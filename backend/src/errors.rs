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
    SecurityViolation(String),
    
    // Session errors
    SessionNotFound(String),
    SessionExpired(String),
    SessionRevoked(String),
    SessionInvalid(String),
    SessionSecurityViolation(String),
    SessionConcurrencyLimitExceeded,
    SessionCreationFailed(String),
    RedisConnectionError(String),
    
    // Security-related errors for consolidated structures
    SecurityConfigError(String),
    RiskAssessmentFailed(String),
    ThreatDetectionError(String),
    BehavioralAnalysisError(String),
    SessionBindingError(String),
    DeviceFingerprintError(String),
    SecurityActionFailed(String),
    
    // Metrics and analytics errors
    MetricsCollectionError(String),
    AnalyticsError(String),
    
    // Configuration errors for unified structures
    ConfigurationError(String),
    ThresholdValidationError(String),
    
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
            AppError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            
            // Session errors
            AppError::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            AppError::SessionExpired(id) => write!(f, "Session expired: {}", id),
            AppError::SessionRevoked(id) => write!(f, "Session revoked: {}", id),
            AppError::SessionInvalid(msg) => write!(f, "Session invalid: {}", msg),
            AppError::SessionSecurityViolation(msg) => write!(f, "Session security violation: {}", msg),
            AppError::SessionConcurrencyLimitExceeded => write!(f, "Session concurrency limit exceeded"),
            AppError::SessionCreationFailed(msg) => write!(f, "Session creation failed: {}", msg),
            AppError::RedisConnectionError(msg) => write!(f, "Redis connection error: {}", msg),
            
            // Security-related errors for consolidated structures
            AppError::SecurityConfigError(msg) => write!(f, "Security configuration error: {}", msg),
            AppError::RiskAssessmentFailed(msg) => write!(f, "Risk assessment failed: {}", msg),
            AppError::ThreatDetectionError(msg) => write!(f, "Threat detection error: {}", msg),
            AppError::BehavioralAnalysisError(msg) => write!(f, "Behavioral analysis error: {}", msg),
            AppError::SessionBindingError(msg) => write!(f, "Session binding error: {}", msg),
            AppError::DeviceFingerprintError(msg) => write!(f, "Device fingerprint error: {}", msg),
            AppError::SecurityActionFailed(msg) => write!(f, "Security action failed: {}", msg),
            
            // Metrics and analytics errors
            AppError::MetricsCollectionError(msg) => write!(f, "Metrics collection error: {}", msg),
            AppError::AnalyticsError(msg) => write!(f, "Analytics error: {}", msg),
            
            // Configuration errors for unified structures
            AppError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            AppError::ThresholdValidationError(msg) => write!(f, "Threshold validation error: {}", msg),
            
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
            AppError::SecurityViolation(msg) => {
                tracing::warn!("Security violation: {}", msg);
                (
                    StatusCode::FORBIDDEN,
                    "Security violation detected".to_string(),
                    "Access denied due to security violation".to_string()
                )
            },
            
            // Session errors
            AppError::SessionNotFound(_) => (
                StatusCode::NOT_FOUND,
                "Session not found".to_string(),
                "Session not found".to_string()
            ),
            AppError::SessionExpired(_) => (
                StatusCode::UNAUTHORIZED,
                "Session expired".to_string(),
                "Session expired".to_string()
            ),
            AppError::SessionRevoked(_) => (
                StatusCode::UNAUTHORIZED,
                "Session revoked".to_string(),
                "Session revoked".to_string()
            ),
            AppError::SessionInvalid(msg) => (
                StatusCode::BAD_REQUEST,
                msg.clone(),
                "Invalid session".to_string()
            ),
            AppError::SessionSecurityViolation(msg) => {
                tracing::warn!("Session security violation: {}", msg);
                (
                    StatusCode::FORBIDDEN,
                    "Session security violation".to_string(),
                    "Access denied due to security violation".to_string()
                )
            },
            AppError::SessionConcurrencyLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Session concurrency limit exceeded".to_string(),
                "Too many active sessions".to_string()
            ),
            AppError::SessionCreationFailed(msg) => {
                tracing::error!("Session creation failed: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Session creation failed".to_string(),
                    "Unable to create session".to_string()
                )
            },
            AppError::RedisConnectionError(msg) => {
                tracing::error!("Redis connection error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Redis connection error".to_string(),
                    "Internal server error".to_string()
                )
            },
            
            // Security-related errors
            AppError::SecurityConfigError(msg) => {
                tracing::error!("Security configuration error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Security configuration error".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::RiskAssessmentFailed(msg) => {
                tracing::warn!("Risk assessment failed: {}", msg);
                (
                    StatusCode::FORBIDDEN,
                    "Risk assessment failed".to_string(),
                    "Access denied due to security risk".to_string()
                )
            },
            AppError::ThreatDetectionError(msg) => {
                tracing::error!("Threat detection error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Threat detection error".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::BehavioralAnalysisError(msg) => {
                tracing::error!("Behavioral analysis error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Behavioral analysis error".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::SessionBindingError(msg) => {
                tracing::warn!("Session binding error: {}", msg);
                (
                    StatusCode::FORBIDDEN,
                    "Session binding error".to_string(),
                    "Session security validation failed".to_string()
                )
            },
            AppError::DeviceFingerprintError(msg) => {
                tracing::warn!("Device fingerprint error: {}", msg);
                (
                    StatusCode::FORBIDDEN,
                    "Device fingerprint error".to_string(),
                    "Device validation failed".to_string()
                )
            },
            AppError::SecurityActionFailed(msg) => {
                tracing::error!("Security action failed: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Security action failed".to_string(),
                    "Security operation failed".to_string()
                )
            },
            
            // Metrics and analytics errors
            AppError::MetricsCollectionError(msg) => {
                tracing::error!("Metrics collection error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Metrics collection error".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::AnalyticsError(msg) => {
                tracing::error!("Analytics error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Analytics error".to_string(),
                    "Internal server error".to_string()
                )
            },
            
            // Configuration errors
            AppError::ConfigurationError(msg) => {
                tracing::error!("Configuration error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Configuration error".to_string(),
                    "Internal server error".to_string()
                )
            },
            AppError::ThresholdValidationError(msg) => {
                tracing::warn!("Threshold validation error: {}", msg);
                (
                    StatusCode::BAD_REQUEST,
                    "Threshold validation error".to_string(),
                    "Invalid threshold configuration".to_string()
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
