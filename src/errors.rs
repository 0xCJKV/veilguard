use actix_web::{HttpResponse, ResponseError};
use std::fmt;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    ArgonError(argon2::Error),
    PasswordHashError(argon2::password_hash::Error),
    ValidationError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppError::ArgonError(e) => write!(f, "Argon2 error: {}", e),
            AppError::PasswordHashError(e) => write!(f, "Password hash error: {}", e),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::ValidationError(_) => HttpResponse::BadRequest().json("Invalid input"),
            _ => HttpResponse::InternalServerError().json("Internal server error"),
        }
    }
}
