use std::fmt;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    // Authentication and password errors
    ArgonError(argon2::Error),
    PasswordHashError(argon2::password_hash::Error),
    
    // Validation errors
    ValidationError(String),
    InvalidEmail(String),
    InvalidPassword(String),
    
    // Database errors
    DatabaseError(String),
    UserNotFound(i32),
    UserAlreadyExists(String),
    
    // Authorization errors
    Unauthorized,
    Forbidden,
    TokenError(String),
    
    // General errors
    InternalServerError(String),
    BadRequest(String),
    NotFound(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Authentication and password errors
            AppError::ArgonError(e) => write!(f, "Argon2 error: {}", e),
            AppError::PasswordHashError(e) => write!(f, "Password hash error: {}", e),
            
            // Validation errors
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::InvalidEmail(email) => write!(f, "Invalid email format: {}", email),
            AppError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            
            // Database errors
            AppError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AppError::UserNotFound(id) => write!(f, "User with ID {} not found", id),
            AppError::UserAlreadyExists(identifier) => write!(f, "User already exists: {}", identifier),
            
            // Authorization errors
            AppError::Unauthorized => write!(f, "Unauthorized access"),
            AppError::Forbidden => write!(f, "Forbidden access"),
            AppError::TokenError(msg) => write!(f, "Token error: {}", msg),
            
            // General errors
            AppError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::NotFound(resource) => write!(f, "Resource not found: {}", resource),
        }
    }
}

impl std::error::Error for AppError {}

// Secure HTTP response implementation
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, user_message) = match &self {
            // Authentication and password errors - don't leak details
            AppError::ArgonError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Argon2 error occurred".to_string(),
                "Internal server error".to_string()
            ),
            AppError::PasswordHashError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password hash error occurred".to_string(), 
                "Internal server error".to_string()
            ),
            
            // Validation errors - safe to show user
            AppError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                msg.clone(),
                msg.clone()
            ),
            AppError::InvalidEmail(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid email format".to_string(),
                "Invalid email format".to_string()
            ),
            AppError::InvalidPassword(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid password format".to_string(),
                "Password does not meet requirements".to_string()
            ),
            
            // Database errors - never leak database details
            AppError::DatabaseError(msg) => {
                // Log the actual error for debugging
                tracing::error!("Database error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database operation failed".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::UserNotFound(_) => (
                StatusCode::NOT_FOUND,
                "User not found".to_string(),
                "User not found".to_string()
            ),
            AppError::UserAlreadyExists(_) => (
                StatusCode::CONFLICT,
                "User already exists".to_string(),
                "User already exists".to_string()
            ),
            
            // Authorization errors
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized access".to_string(),
                "Authentication required".to_string()
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "Forbidden access".to_string(),
                "Access denied".to_string()
            ),
            AppError::TokenError(msg) => {
                // Log the actual error for debugging
                tracing::error!("Token error: {}", msg);
                (
                    StatusCode::UNAUTHORIZED,
                    "Token validation failed".to_string(),
                    "Invalid or expired token".to_string()
                )
            },
            
            // General errors
            AppError::InternalServerError(msg) => {
                // Log the actual error for debugging
                tracing::error!("Internal server error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error occurred".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                msg.clone(),
                msg.clone()
            ),
            AppError::NotFound(resource) => (
                StatusCode::NOT_FOUND,
                format!("{} not found", resource),
                format!("{} not found", resource)
            ),
        };

        // Log all errors for monitoring (with sanitized info)
        tracing::warn!(
            status = %status,
            error = %error_message,
            "API error occurred"
        );

        let body = Json(json!({
            "error": {
                "message": user_message,
                "code": status.as_u16()
            }
        }));

        (status, body).into_response()
    }
}

impl AppError {
    /// Create a validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::ValidationError(msg.into())
    }
    
    /// Create an invalid email error
    pub fn invalid_email(email: impl Into<String>) -> Self {
        Self::InvalidEmail(email.into())
    }
    
    /// Create an invalid password error
    pub fn invalid_password(msg: impl Into<String>) -> Self {
        Self::InvalidPassword(msg.into())
    }
    
    /// Create a database error
    pub fn database(msg: impl Into<String>) -> Self {
        Self::DatabaseError(msg.into())
    }
    
    /// Create a user not found error
    pub fn user_not_found(id: i32) -> Self {
        Self::UserNotFound(id)
    }
    
    /// Create a user already exists error
    pub fn user_exists(identifier: impl Into<String>) -> Self {
        Self::UserAlreadyExists(identifier.into())
    }
    
    /// Create an internal server error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::InternalServerError(msg.into())
    }
    
    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    
    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound(resource.into())
    }
}

// Conversion from database errors
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::NotFound("Resource not found".to_string()),
            _ => Self::DatabaseError(err.to_string()),
        }
    }
}

// Conversion from argon2 errors
impl From<argon2::Error> for AppError {
    fn from(err: argon2::Error) -> Self {
        Self::ArgonError(err)
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        Self::PasswordHashError(err)
    }
}
