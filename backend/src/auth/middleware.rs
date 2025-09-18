use axum::{
    extract::{Extension, Request},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

use crate::{
    auth::{Claims, PasetoManager},
    config::Config,
    errors::AppError,
};

/// Authentication state that gets injected into protected route handlers
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub claims: Claims,
}

impl AuthUser {
    pub fn new(user_id: String, claims: Claims) -> Self {
        Self { user_id, claims }
    }

    /// Get a custom claim from the token
    pub fn get_claim<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, AppError> {
        self.claims.get_claim(key)
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        match self.get_claim::<String>("role") {
            Ok(Some(user_role)) => user_role == role,
            _ => false,
        }
    }

    /// Check if the user has any of the specified permissions
    pub fn has_permission(&self, permission: &str) -> bool {
        match self.get_claim::<Vec<String>>("permissions") {
            Ok(Some(permissions)) => permissions.contains(&permission.to_string()),
            _ => false,
        }
    }
}

/// Cookie names for authentication tokens
pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

/// Authentication middleware that validates PASETO tokens from cookies
pub async fn auth_middleware(
    Extension(config): Extension<Arc<Config>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Create PASETO manager
    let paseto_manager = PasetoManager::new(&config)?;

    // Try to get access token from cookie
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());

    let auth_user = match access_token {
        Some(token) => {
            // Validate the access token
            match paseto_manager.validate_token(&token) {
                Ok(claims) => {
                    let user_id = claims.sub.clone();
                    Some(AuthUser::new(user_id, claims))
                }
                Err(_) => {
                    // Access token is invalid, try refresh token
                    let refresh_token = jar
                        .get(REFRESH_TOKEN_COOKIE)
                        .map(|cookie| cookie.value().to_string());

                    match refresh_token {
                        Some(refresh_token) => {
                            // Validate refresh token
                            match paseto_manager.validate_token(&refresh_token) {
                                Ok(claims) => {
                                    // Refresh token is valid, but we need a new access token
                                    // For now, we'll reject the request and let the client handle refresh
                                    None
                                }
                                Err(_) => None,
                            }
                        }
                        None => None,
                    }
                }
            }
        }
        None => None,
    };

    match auth_user {
        Some(user) => {
            // Insert the authenticated user into request extensions
            request.extensions_mut().insert(user);
            Ok(next.run(request).await)
        }
        None => {
            // No valid authentication found
            Err(AppError::Unauthorized)
        }
    }
}

/// Helper function to create secure cookie attributes
pub fn create_secure_cookie(name: &str, value: &str, max_age_seconds: i64) -> axum_extra::extract::cookie::Cookie<'static> {
    use axum_extra::extract::cookie::{Cookie, SameSite};
    
    Cookie::build((name.to_string(), value.to_string()))
        .http_only(true)
        .secure(true) // Set to false for development over HTTP
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_seconds))
        .path("/")
        .build()
}

/// Helper function to create a cookie for deletion (expires immediately)
pub fn create_delete_cookie(name: &str) -> axum_extra::extract::cookie::Cookie<'static> {
    use axum_extra::extract::cookie::{Cookie, SameSite};
    
    Cookie::build((name.to_string(), "".to_string()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .path("/")
        .build()
}