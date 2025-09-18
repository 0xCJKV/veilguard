use actix_web::{web, HttpResponse, Result};
use crate::{
    auth::{hash_password, verify_password},
    database::{users, DbPool},
    models::user::{UserResponse, UpdateUserRequest},
    errors::AppError,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

// GET /api/v1/users/{id}
pub async fn get_user(
    pool: web::Data<DbPool>,
    path: web::Path<i32>
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => {
            let response: UserResponse = user.into();
            Ok(HttpResponse::Ok().json(response))
        },
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Database error fetching user {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json("Failed to fetch user"))
        }
    }
}

// GET /api/v1/users
pub async fn list_users(
    pool: web::Data<DbPool>,
    query: web::Query<PaginationQuery>
) -> Result<HttpResponse> {
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10).min(100);
    let offset = (page - 1) * limit;
    
    match users::list_users(&pool, limit, offset).await {
        Ok(user_list) => {
            let responses: Vec<UserResponse> = user_list.into_iter().map(|u| u.into()).collect();
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "users": responses,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "count": responses.len()
                }
            })))
        },
        Err(e) => {
            log::error!("Database error listing users: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to fetch users"))
        }
    }
}

// PUT /api/v1/users/{id}
pub async fn update_user(
    pool: web::Data<DbPool>,
    path: web::Path<i32>,
    update_req: web::Json<UpdateUserRequest>
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    // First, get the current user
    let current_user = match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Database error fetching user {}: {}", user_id, e);
            return Ok(HttpResponse::InternalServerError().json("Failed to fetch user"));
        }
    };
    
    let mut new_password_hash = None;
    
    // Handle password change if requested
    if let (Some(current_pw), Some(new_pw)) = (&update_req.current_password, &update_req.new_password) {
        let is_valid = verify_password(current_pw, &current_user.password_hash)
            .map_err(|e| AppError::ValidationError(e.to_string()))?;
        
        if !is_valid {
            return Ok(HttpResponse::BadRequest().json("Current password is incorrect"));
        }
        
        let new_hash = hash_password(new_pw)
            .map_err(|e| AppError::ValidationError(e.to_string()))?;
        
        new_password_hash = Some(new_hash);
    }
    
    // Validate email format if provided
    if let Some(email) = &update_req.email {
        if !email.contains('@') || email.len() < 5 {
            return Ok(HttpResponse::BadRequest().json("Invalid email format"));
        }
        
        // Check if email is already taken by another user
        if let Ok(Some(existing_user)) = users::find_by_email(&pool, email).await {
            if existing_user.id != user_id {
                return Ok(HttpResponse::BadRequest().json("Email already in use"));
            }
        }
    }
    
    // Validate username if provided
    if let Some(username) = &update_req.username {
        if username.len() < 3 || username.len() > 50 {
            return Ok(HttpResponse::BadRequest().json("Username must be between 3 and 50 characters"));
        }
        
        // Check if username is already taken by another user
        if let Ok(Some(existing_user)) = users::find_by_username(&pool, username).await {
            if existing_user.id != user_id {
                return Ok(HttpResponse::BadRequest().json("Username already taken"));
            }
        }
    }
    
    // Update user in database
    match users::update_user(&pool, user_id, &update_req, new_password_hash.as_deref()).await {
        Ok(Some(updated_user)) => {
            let response: UserResponse = updated_user.into();
            Ok(HttpResponse::Ok().json(response))
        },
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Database error updating user {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json("Failed to update user"))
        }
    }
}

// DELETE /api/v1/users/{id}
pub async fn delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<i32>
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    match users::delete_user(&pool, user_id).await {
        Ok(true) => Ok(HttpResponse::NoContent().finish()),
        Ok(false) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Database error deleting user {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json("Failed to delete user"))
        }
    }
}

// GET /api/v1/users/{id}/profile
pub async fn get_user_profile(
    pool: web::Data<DbPool>,
    path: web::Path<i32>
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => {
            let profile = serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "is_active": user.is_active,
                "profile": {
                    "display_name": user.username,
                    "member_since": user.created_at.format("%Y-%m-%d").to_string(),
                    "last_updated": user.updated_at.format("%Y-%m-%d").to_string()
                }
            });
            
            Ok(HttpResponse::Ok().json(profile))
        },
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Database error fetching user profile {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json("Failed to fetch user profile"))
        }
    }
}

// Configure routes
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("", web::get().to(list_users))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::put().to(update_user))
            .route("/{id}", web::delete().to(delete_user))
            .route("/{id}/profile", web::get().to(get_user_profile))
    );
}
