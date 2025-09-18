use axum::{
    extract::Extension,
    http::{StatusCode, HeaderMap},
    response::{Json, Html, Response, IntoResponse, Redirect},
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use minijinja::{Environment, context};
use crate::{
    auth::{
        hash_password, verify_password, PasetoManager,
        create_secure_cookie, create_delete_cookie, 
        ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
    },
    config::Config,
    database::{users, DbPool},
    models::{CreateUserRequest, LoginRequest, UserResponse},
    errors::{AppError, Result},
};

fn is_valid_email(email: &str) -> bool {
    email.contains('@') && 
    email.len() > 5 && 
    email.chars().filter(|&c| c == '@').count() == 1 &&
    !email.starts_with('@') && 
    !email.ends_with('@')
}

pub fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

pub fn render_notification(env: &Environment<'static>, message: &str, notification_type: &str) -> std::result::Result<String, AppError> {
    let template = env.get_template("components/notification.html")
        .map_err(|e| AppError::TemplateError(format!("Failed to load notification template: {}", e)))?;
    
    template.render(context! {
        message => message,
        notification_type => notification_type
    }).map_err(|e| AppError::TemplateError(format!("Failed to render notification: {}", e)))
}

pub async fn register(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(env): Extension<Arc<Environment<'static>>>,
    headers: HeaderMap,
    Json(user_req): Json<CreateUserRequest>
) -> Result<Response> {
    if !is_valid_email(&user_req.email) {
        return Err(AppError::invalid_email(&user_req.email));
    }
    
    if user_req.username.len() < 3 || user_req.username.len() > 50 {
        return Err(AppError::validation("Username must be between 3 and 50 characters"));
    }
    
    if user_req.password.len() < 8 {
        return Err(AppError::invalid_password("Password must be at least 8 characters"));
    }

    if let Ok(Some(_)) = users::find_by_email(&pool, &user_req.email).await {
        return Err(AppError::user_exists(&user_req.email));
    }
    
    if let Ok(Some(_)) = users::find_by_username(&pool, &user_req.username).await {
        return Err(AppError::user_exists(&user_req.username));
    }
    
    let password_hash = hash_password(&user_req.password)?;
    
    match users::create_user(&pool, &user_req, &password_hash).await {
        Ok(user) => {
            if is_htmx_request(&headers) {
                let notification_html = render_notification(&env, "Registration successful! Please log in.", "success")?;
                Ok(Html(notification_html).into_response())
            } else {
                let response: UserResponse = user.into();
                Ok((StatusCode::CREATED, Json(response)).into_response())
            }
        },
        Err(e) => {
            Err(AppError::database(format!("Failed to create user: {}", e)))
        }
    }
}

pub async fn login(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(env): Extension<Arc<Environment<'static>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(login_req): Json<LoginRequest>
) -> Result<Response> {
    // Determine if login is email or username based on presence of '@' symbol
    let user = if login_req.login.contains('@') {
        // Login with email
        match users::find_by_email(&pool, &login_req.login).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err(AppError::Unauthorized);
            },
            Err(e) => {
                return Err(AppError::database(format!("Database error during email login: {}", e)));
            }
        }
    } else {
        // Login with username
        match users::find_by_username(&pool, &login_req.login).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err(AppError::Unauthorized);
            },
            Err(e) => {
                return Err(AppError::database(format!("Database error during username login: {}", e)));
            }
        }
    };
    
    let is_valid = verify_password(&login_req.password, &user.password_hash)?;
    
    if is_valid {
        // Create PASETO manager and generate tokens
        let paseto_manager = PasetoManager::new(&config)
            .map_err(|e| AppError::TokenError(format!("Failed to create PASETO manager: {}", e)))?;
        let user_id = user.id.to_string();
        
        let access_token = paseto_manager.generate_access_token(&user_id)
            .map_err(|e| AppError::TokenError(format!("Failed to generate access token: {}", e)))?;
        let refresh_token = paseto_manager.generate_refresh_token(&user_id)
            .map_err(|e| AppError::TokenError(format!("Failed to generate refresh token: {}", e)))?;
        
        // Create secure cookies
        let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &access_token, 15 * 60); // 15 minutes
        let refresh_cookie = create_secure_cookie(REFRESH_TOKEN_COOKIE, &refresh_token, 7 * 24 * 60 * 60); // 7 days
        
        // Add cookies to jar
        let jar = jar.add(access_cookie).add(refresh_cookie);
        
        if is_htmx_request(&headers) {
            // For HTMX requests, redirect to dashboard
            let mut response = Redirect::to("/dashboard").into_response();
            
            // Add cookies to the response
            let headers = response.headers_mut();
            for cookie in jar.iter() {
                if let Ok(header_value) = cookie.to_string().parse() {
                    headers.append("set-cookie", header_value);
                }
            }
            
            Ok(response)
        } else {
            let response: UserResponse = user.into();
            Ok((jar, Json(serde_json::json!({
                "message": "Login successful",
                "user": response,
                "tokens": {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            }))).into_response())
        }
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Refresh access token using refresh token
pub async fn refresh_token(
    Extension(config): Extension<Arc<Config>>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // Get refresh token from cookie
    let refresh_token = jar
        .get(REFRESH_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string())
        .ok_or(AppError::Unauthorized)?;

    // Create PASETO manager and validate refresh token
    let paseto_manager = PasetoManager::new(&config)?;
    let claims = paseto_manager.validate_token(&refresh_token)?;
    
    // Generate new access token
    let new_access_token = paseto_manager.generate_access_token(&claims.sub)?;
    
    // Create new access token cookie
    let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &new_access_token, 15 * 60); // 15 minutes
    let jar = jar.add(access_cookie);
    
    Ok((jar, Json(serde_json::json!({
        "message": "Token refreshed successfully",
        "access_token": new_access_token
    }))))
}

/// Logout user by clearing authentication cookies
pub async fn logout(jar: CookieJar) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // Create delete cookies
    let delete_access = create_delete_cookie(ACCESS_TOKEN_COOKIE);
    let delete_refresh = create_delete_cookie(REFRESH_TOKEN_COOKIE);
    
    // Add delete cookies to jar
    let jar = jar.add(delete_access).add(delete_refresh);
    
    Ok((jar, Json(serde_json::json!({
        "message": "Logged out successfully"
    }))))
}
