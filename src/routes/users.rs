use axum::{
    extract::{Extension, Path, Query},
    http::{StatusCode, HeaderMap},
    response::{Json, Html, IntoResponse, Response},
};
use std::sync::Arc;
use minijinja::{Environment, context};
use crate::{
    auth::{AuthUser, hash_password, verify_password},
    database::{users, DbPool},
    models::{UserResponse, UpdateUserRequest},
    errors::{AppError, Result},
    routes::auth::{is_htmx_request, render_notification},
};
use crate::validation::{UserValidator, ValidationResult, sanitize_input};
use serde::Deserialize;

// Helper function to render validation errors for HTMX
fn render_validation_errors(env: &Environment, validation_result: &ValidationResult) -> Result<String> {
    let template = env.get_template("components/validation_errors.html")
        .map_err(|e| AppError::TemplateError(format!("Failed to load validation errors template: {}", e)))?;
    
    let html = template.render(context! {
        errors => validation_result.errors
    }).map_err(|e| AppError::TemplateError(format!("Failed to render validation errors: {}", e)))?;
    
    Ok(html)
}

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

// GET /api/v1/users/{id}
pub async fn get_user(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Path(user_id): Path<i32>
) -> Result<Json<UserResponse>> {
    // Users can only view their own profile, unless they're admin
    let requesting_user_id: i32 = auth_user.user_id.parse()
        .map_err(|_| AppError::TokenError("Invalid user ID in token".to_string()))?;
    
    if requesting_user_id != user_id && !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }

    match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => {
            let response: UserResponse = user.into();
            Ok(Json(response))
        },
        Ok(None) => Err(AppError::user_not_found(user_id)),
        Err(e) => {
            Err(AppError::database(format!("Database error fetching user {}: {}", user_id, e)))
        }
    }
}

// GET /api/v1/users
pub async fn list_users(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Query(query): Query<PaginationQuery>
) -> Result<Json<serde_json::Value>> {
    // Only allow admins to list all users
    if !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10).min(100);
    let offset = (page - 1) * limit;
    
    match users::list_users(&pool, limit, offset).await {
        Ok(user_list) => {
            let responses: Vec<UserResponse> = user_list.into_iter().map(|u| u.into()).collect();
            Ok(Json(serde_json::json!({
                "users": responses,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "count": responses.len()
                }
            })))
        },
        Err(e) => {
            Err(AppError::database(format!("Database error listing users: {}", e)))
        }
    }
}

// PUT /api/v1/users/{id}
pub async fn update_user(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(env): Extension<Arc<Environment<'static>>>,
    headers: HeaderMap,
    Path(user_id): Path<i32>,
    Json(update_req): Json<UpdateUserRequest>
) -> Result<Response> {
    // Users can only update their own profile, unless they're admin
    let requesting_user_id: i32 = auth_user.user_id.parse()
        .map_err(|_| AppError::TokenError("Invalid user ID in token".to_string()))?;
    
    if requesting_user_id != user_id && !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }
    // First, get the current user
    let current_user = match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AppError::user_not_found(user_id)),
        Err(e) => {
            return Err(AppError::database(format!("Database error fetching user {}: {}", user_id, e)));
        }
    };
    
    let mut new_password_hash = None;
    
    // Handle password change if requested
    if let (Some(current_pw), Some(new_pw)) = (&update_req.current_password, &update_req.new_password) {
        let is_valid = verify_password(current_pw, &current_user.password_hash)?;
        
        if !is_valid {
            return Err(AppError::bad_request("Current password is incorrect"));
        }
        
        let new_hash = hash_password(new_pw)?;
        
        new_password_hash = Some(new_hash);
    }
    
    // Comprehensive validation
    let mut validation_result = ValidationResult::new();
    
    // Validate and sanitize email if provided
    if let Some(email) = &update_req.email {
        let sanitized_email = sanitize_input(email);
        let email_validation = UserValidator::validate_email(&sanitized_email);
        validation_result.merge(email_validation);
        
        // Check if email is already taken by another user (only if format is valid)
        if validation_result.is_valid {
            if let Ok(Some(existing_user)) = users::find_by_email(&pool, &sanitized_email).await {
                if existing_user.id != user_id {
                    validation_result.add_error("email", "This email address is already in use", "already_exists");
                }
            }
        }
    }
    
    // Validate and sanitize username if provided
    if let Some(username) = &update_req.username {
        let sanitized_username = sanitize_input(username);
        let username_validation = UserValidator::validate_username(&sanitized_username);
        validation_result.merge(username_validation);
        
        // Check if username is already taken by another user (only if format is valid)
        if validation_result.is_valid {
            if let Ok(Some(existing_user)) = users::find_by_username(&pool, &sanitized_username).await {
                if existing_user.id != user_id {
                    validation_result.add_error("username", "This username is already taken", "already_exists");
                }
            }
        }
    }
    
    // Validate new password if provided
    if let Some(new_password) = &update_req.new_password {
        let password_validation = UserValidator::validate_password(new_password);
        validation_result.merge(password_validation);
    }
    
    // Return validation errors if any
    if !validation_result.is_valid {
        if is_htmx_request(&headers) {
            let validation_html = render_validation_errors(&env, &validation_result)?;
            return Ok(Html(validation_html).into_response());
        } else {
            return Err(validation_result.to_app_error());
        }
    }
    
    // Update user in database
    match users::update_user(&pool, user_id, &update_req, new_password_hash.as_deref()).await {
        Ok(Some(updated_user)) => {
            if is_htmx_request(&headers) {
                // For HTMX requests, return a notification
                let notification_html = render_notification(&env, "Profile updated successfully!", "success")?;
                Ok(Html(notification_html).into_response())
            } else {
                // For regular API requests, return JSON
                let response: UserResponse = updated_user.into();
                Ok(Json(response).into_response())
            }
        },
        Ok(None) => Err(AppError::user_not_found(user_id)),
        Err(e) => {
            Err(AppError::database(format!("Database error updating user {}: {}", user_id, e)))
        }
    }
}

// GET /api/v1/users/{id}/profile-card - Returns updated profile card component
pub async fn get_user_profile_card(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(env): Extension<Arc<Environment<'static>>>,
    Path(user_id): Path<i32>
) -> Result<Response> {
    // Users can only view their own profile, unless they're admin
    let requesting_user_id: i32 = auth_user.user_id.parse()
        .map_err(|_| AppError::TokenError("Invalid user ID in token".to_string()))?;
    
    if requesting_user_id != user_id && !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }

    match users::find_by_id(&pool, user_id).await {
        Ok(Some(user)) => {
            let template = env.get_template("components/user_profile_card.html")
                .map_err(|e| AppError::TemplateError(format!("Failed to load profile card template: {}", e)))?;
            
            let rendered = template.render(context! { user => user })
                .map_err(|e| AppError::TemplateError(format!("Failed to render profile card: {}", e)))?;
            
            Ok(Html(rendered).into_response())
        },
        Ok(None) => Err(AppError::user_not_found(user_id)),
        Err(e) => {
            Err(AppError::database(format!("Database error fetching user {}: {}", user_id, e)))
        }
    }
}

// DELETE /api/v1/users/{id}
pub async fn delete_user(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Path(user_id): Path<i32>
) -> Result<StatusCode> {
    // Only admins can delete users
    if !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }
    match users::delete_user(&pool, user_id).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(AppError::user_not_found(user_id)),
        Err(e) => {
            Err(AppError::database(format!("Database error deleting user {}: {}", user_id, e)))
        }
    }
}

// GET /api/v1/users/{id}/profile
pub async fn get_user_profile(
    Extension(auth_user): Extension<AuthUser>,
    Extension(pool): Extension<Arc<DbPool>>,
    Path(user_id): Path<i32>
) -> Result<Json<serde_json::Value>> {
    // Users can only view their own profile, unless they're admin
    let requesting_user_id: i32 = auth_user.user_id.parse()
        .map_err(|_| AppError::TokenError("Invalid user ID in token".to_string()))?;
    
    if requesting_user_id != user_id && !auth_user.has_role("admin") {
        return Err(AppError::Forbidden);
    }
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
            
            Ok(Json(profile))
        },
        Ok(None) => Err(AppError::user_not_found(user_id)),
        Err(e) => {
            Err(AppError::database(format!("Database error fetching user profile {}: {}", user_id, e)))
        }
    }
}
