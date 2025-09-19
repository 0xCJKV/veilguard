use axum::{
    extract::Extension,
    http::{StatusCode, HeaderMap},
    response::Json,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use std::net::IpAddr;
use std::collections::HashMap;
use crate::{
    auth::{
        hash_password, verify_password, PasetoManager, ses::SessionManager,
    },
    middleware::{
        create_secure_cookie, create_delete_cookie, 
        ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, AuthUser
    },
    config::Config,
    database::{users, DbPool, redis::RedisManager},
    models::{CreateUserRequest, LoginRequest, UserResponse, ses::SecurityLevel},
    errors::{AppError, Result},
};

fn is_valid_email(email: &str) -> bool {
    email.contains('@') && 
    email.len() > 5 && 
    email.chars().filter(|&c| c == '@').count() == 1 &&
    !email.starts_with('@') && 
    !email.ends_with('@')
}

pub async fn register(
    Extension(pool): Extension<Arc<DbPool>>,
    Json(user_req): Json<CreateUserRequest>
) -> Result<(StatusCode, Json<UserResponse>)> {
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
            let response: UserResponse = user.into();
            Ok((StatusCode::CREATED, Json(response)))
        },
        Err(e) => {
            Err(AppError::database(format!("Failed to create user: {}", e)))
        }
    }
}

pub async fn login(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(login_req): Json<LoginRequest>
) -> Result<(CookieJar, Json<serde_json::Value>)> {
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
        // Create PASETO manager
        let paseto_manager = PasetoManager::new(&config)
            .map_err(|e| AppError::TokenError(format!("Failed to create PASETO manager: {}", e)))?;
        
        // Extract request information for session creation
        let ip_address = extract_ip_from_headers(&headers)?;
        let user_agent = extract_user_agent(&headers);
        let device_fingerprint = generate_device_fingerprint(&headers);

        // Create session
        let session = session_manager.create_session(
            user.id.to_string(),
            ip_address,
            user_agent,
            device_fingerprint,
            "password".to_string(),
            SecurityLevel::Standard,
            None,
        ).await?;

        // Generate PASETO tokens with embedded session ID (hybrid approach)
        let access_token = paseto_manager.generate_access_token_with_session(&user.id.to_string(), &session.id)?;
        let refresh_token = paseto_manager.generate_refresh_token_with_session(&user.id.to_string(), &session.id)?;
        
        // Create secure cookies (only two tokens needed)
        let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &access_token, 15 * 60); // 15 minutes
        let refresh_cookie = create_secure_cookie(REFRESH_TOKEN_COOKIE, &refresh_token, 7 * 24 * 60 * 60); // 7 days
        
        // Add cookies to jar
        let jar = jar.add(access_cookie).add(refresh_cookie);
        
        let response: UserResponse = user.into();
        Ok((jar, Json(serde_json::json!({
            "message": "Login successful",
            "user": response,
            "session_id": session.id
        }))))
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

/// Logout user by clearing authentication cookies and revoking session
pub async fn logout(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(paseto_manager): Extension<Arc<PasetoManager>>,
    jar: CookieJar
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // Try to revoke session if access token contains session ID
    if let Some(access_token) = jar.get(ACCESS_TOKEN_COOKIE) {
        if let Ok(claims) = paseto_manager.validate_token(access_token.value()) {
            if let Some(session_id) = claims.get_claim::<String>("sid").unwrap_or(None) {
                let _ = session_manager.revoke_session(&session_id, Some("User logout")).await;
            }
        }
    }
    
    // Create delete cookies
    let delete_access = create_delete_cookie(ACCESS_TOKEN_COOKIE);
    let delete_refresh = create_delete_cookie(REFRESH_TOKEN_COOKIE);
    
    // Add delete cookies to jar
    let jar = jar.add(delete_access).add(delete_refresh);
    
    Ok((jar, Json(serde_json::json!({
        "message": "Logged out successfully"
    }))))
}

/// Extract IP address from request headers
fn extract_ip_from_headers(headers: &HeaderMap) -> Result<IpAddr> {
    // Try X-Forwarded-For first (for proxies)
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }
    
    // Try X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }
    
    // Fallback to localhost
    Ok("127.0.0.1".parse().unwrap())
}

/// Extract user agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}

/// Generate a simple device fingerprint from headers
fn generate_device_fingerprint(headers: &HeaderMap) -> String {
    let user_agent = extract_user_agent(headers);
    let accept_language = headers
        .get("accept-language")
        .and_then(|lang| lang.to_str().ok())
        .unwrap_or("unknown");
    let accept_encoding = headers
        .get("accept-encoding")
        .and_then(|enc| enc.to_str().ok())
        .unwrap_or("unknown");
    
    // Create a simple hash-like fingerprint
    format!("{}:{}:{}", user_agent, accept_language, accept_encoding)
}

/// Get session analytics and security metrics
pub async fn get_analytics(
    Extension(redis_manager): Extension<Arc<RedisManager>>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    // Check if user has admin permissions (you might want to implement proper role checking)
    if !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }

    // Get comprehensive session metrics
    let session_metrics = redis_manager.get_session_metrics().await?;
    
    // Get recent security events
    let recent_events = redis_manager.get_recent_security_events(20).await?;
    
    // Get user activity for the current user
    let user_activity = redis_manager.get_user_activity(&auth_user.user_id, 10).await?;
    
    // Get user session count
    let user_session_count = redis_manager.get_user_session_count(&auth_user.user_id).await?;
    
    let analytics = serde_json::json!({
        "session_metrics": session_metrics,
        "recent_security_events": recent_events,
        "user_activity": user_activity,
        "user_session_count": user_session_count.unwrap_or(0),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    Ok(Json(analytics))
}

/// Get user-specific analytics
pub async fn get_user_analytics(
    Extension(redis_manager): Extension<Arc<RedisManager>>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    // Get user activity
    let user_activity = redis_manager.get_user_activity(&auth_user.user_id, 50).await?;
    
    // Get user session count
    let user_session_count = redis_manager.get_user_session_count(&auth_user.user_id).await?;
    
    // Get session analytics if available
    let session_analytics = if let Some(session_id) = &auth_user.session_id {
        redis_manager.get_session_analytics(session_id).await?
    } else {
        None
    };
    
    let analytics = serde_json::json!({
        "user_id": auth_user.user_id,
        "session_count": user_session_count.unwrap_or(0),
        "session_valid": auth_user.session_valid,
        "recent_activity": user_activity,
        "session_analytics": session_analytics,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    Ok(Json(analytics))
}
