use actix_web::{web, HttpResponse, Result};
use crate::{
    auth::{hash_password, verify_password},
    database::{users, DbPool},
    models::user::{CreateUserRequest, LoginRequest, UserResponse},
    errors::AppError,
};

fn is_valid_email(email: &str) -> bool {
    email.contains('@') && 
    email.len() > 5 && 
    email.chars().filter(|&c| c == '@').count() == 1 &&
    !email.starts_with('@') && 
    !email.ends_with('@')
}

pub async fn register(
    pool: web::Data<DbPool>,
    user_req: web::Json<CreateUserRequest>
) -> Result<HttpResponse> {
    if !is_valid_email(&user_req.email) {
        return Ok(HttpResponse::BadRequest().json("Invalid email format"));
    }
    
    if user_req.username.len() < 3 || user_req.username.len() > 50 {
        return Ok(HttpResponse::BadRequest().json("Username must be between 3 and 50 characters"));
    }
    
    if user_req.password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json("Password must be at least 8 characters"));
    }

    if let Ok(Some(_)) = users::find_by_email(&pool, &user_req.email).await {
        return Ok(HttpResponse::BadRequest().json("Email already registered"));
    }
    
    if let Ok(Some(_)) = users::find_by_username(&pool, &user_req.username).await {
        return Ok(HttpResponse::BadRequest().json("Username already taken"));
    }
    
    let password_hash = hash_password(&user_req.password)
        .map_err(|e| AppError::ValidationError(e.to_string()))?;
    
    match users::create_user(&pool, &user_req, &password_hash).await {
        Ok(user) => {
            let response: UserResponse = user.into();
            Ok(HttpResponse::Created().json(response))
        },
        Err(e) => {
            log::error!("Failed to create user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to create user"))
        }
    }
}

pub async fn login(
    pool: web::Data<DbPool>,
    login_req: web::Json<LoginRequest>
) -> Result<HttpResponse> {
    let user = match users::find_by_email(&pool, &login_req.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json("Invalid credentials"));
        },
        Err(e) => {
            log::error!("Database error during login: {}", e);
            return Ok(HttpResponse::InternalServerError().json("Login failed"));
        }
    };
    
    let is_valid = verify_password(&login_req.password, &user.password_hash)
        .map_err(|e| AppError::ValidationError(e.to_string()))?;
    
    if is_valid {
        let response: UserResponse = user.into();
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Login successful",
            "user": response
        })))
    } else {
        Ok(HttpResponse::Unauthorized().json("Invalid credentials"))
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
    );
}
