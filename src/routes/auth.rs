use axum::{
    extract::Extension,
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;
use crate::{
    auth::{hash_password, verify_password},
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
    Json(login_req): Json<LoginRequest>
) -> Result<Json<serde_json::Value>> {
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
        let response: UserResponse = user.into();
        Ok(Json(serde_json::json!({
            "message": "Login successful",
            "user": response
        })))
    } else {
        Err(AppError::Unauthorized)
    }
}
