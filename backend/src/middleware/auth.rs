use axum::{
    extract::{Extension, Request},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use std::net::IpAddr;

use crate::{
    auth::{Claims, PasetoManager, ses::SessionManager},
    config::Config,
    errors::AppError,
};

/// Authentication state that gets injected into protected route handlers
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub claims: Claims,
    pub session_id: Option<String>,
    pub session_valid: bool,
}

impl AuthUser {
    pub fn new(user_id: String, claims: Claims) -> Self {
        Self { 
            user_id, 
            claims, 
            session_id: None, 
            session_valid: false 
        }
    }

    pub fn new_with_session(user_id: String, claims: Claims, session_id: String, session_valid: bool) -> Self {
        Self { 
            user_id, 
            claims, 
            session_id: Some(session_id), 
            session_valid 
        }
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
pub const SESSION_TOKEN_COOKIE: &str = "session_token";

/// Authentication middleware that validates PASETO tokens and sessions from cookies
pub async fn auth_middleware(
    Extension(config): Extension<Arc<Config>>,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Create PASETO manager
    let paseto_manager = PasetoManager::new(&config)?;

    // Extract IP address from request headers
    let ip_address = extract_ip_from_request(&request)?;
    let user_agent = extract_user_agent_from_request(&request);

    // Try to get access token and session token from cookies
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());
    
    let session_token = jar
        .get(SESSION_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());

    let auth_user = match (access_token, session_token) {
        (Some(token), Some(session_token)) => {
            // Validate both PASETO token and session
            match paseto_manager.validate_token(&token) {
                Ok(claims) => {
                    let user_id = claims.sub.clone();
                    
                    // Validate session
                    match session_manager.get_session_by_token(&session_token).await {
                        Ok(Some(session)) => {
                            // Verify session belongs to the same user
                            if session.user_id == user_id {
                                // Validate session with current request context
                                match session_manager.validate_session(&session.id, ip_address, &user_agent).await {
                                    Ok(validation_result) => {
                                        if validation_result.is_valid {
                                            Some(AuthUser::new_with_session(user_id, claims, session.id, true))
                                        } else {
                                            // Session validation failed
                                            None
                                        }
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                // Session doesn't belong to token user
                                None
                            }
                        }
                        Ok(None) => {
                            // Session not found, but PASETO token is valid
                            // Allow access but mark session as invalid
                            Some(AuthUser::new(user_id, claims))
                        }
                        Err(_) => None,
                    }
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
                                Ok(_claims) => {
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
        (Some(token), None) => {
            // Only PASETO token provided, validate it
            match paseto_manager.validate_token(&token) {
                Ok(claims) => {
                    let user_id = claims.sub.clone();
                    Some(AuthUser::new(user_id, claims))
                }
                Err(_) => None,
            }
        }
        (None, Some(_session_token)) => {
            // Only session token provided, not sufficient for authentication
            None
        }
        (None, None) => None,
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

/// Extract IP address from request headers
fn extract_ip_from_request(request: &Request) -> Result<IpAddr, AppError> {
    let headers = request.headers();
    
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
fn extract_user_agent_from_request(request: &Request) -> String {
    request
        .headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}