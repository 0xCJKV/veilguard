pub mod auth;
pub mod csrf;
pub mod rate;

// Re-export auth middleware components
pub use auth::{
    auth_middleware, AuthUser, 
    create_secure_cookie, create_delete_cookie,
    ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
};

// Re-export CSRF protection components
pub use csrf::{
    csrf_protection_middleware, CsrfProtection, CsrfConfig, CsrfToken,
    create_csrf_protection, get_csrf_token
};

// Re-export rate limiting components
pub use rate::{
    rate_limit_middleware, RateLimitConfig, RateLimitAlgorithm,
    create_rate_limiter, RateLimiter, RateLimitResult
};