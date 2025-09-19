use axum::{
    extract::{Extension, Request},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use std::net::IpAddr;

use crate::{
    auth::{Claims, PasetoManager, ses::{SessionManager, SecurityEventType}},
    config::Config,
    database::redis::RedisManager,
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

/// Authentication middleware that validates PASETO tokens and sessions from cookies
pub async fn auth_middleware(
    Extension(config): Extension<Arc<Config>>,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(redis_manager): Extension<Arc<RedisManager>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Create PASETO manager
    let paseto_manager = PasetoManager::new(&config)?;

    // Extract IP address from request headers
    let ip_address = extract_ip_from_request(&request)?;
    let user_agent = extract_user_agent_from_request(&request);

    // Try to get access token from cookies
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());

    // Try to validate access token first
    let auth_user = if let Some(access_token) = &access_token {
        if let Ok(claims) = paseto_manager.validate_token(access_token) {
            // Check if token is blacklisted
            let jti = claims.get_claim::<String>("jti").unwrap_or(None);
            let is_blacklisted = if let Some(ref token_id) = jti {
                redis_manager.is_token_blacklisted(token_id).await.unwrap_or(false)
            } else {
                false
            };

            if is_blacklisted {
                // Log security event for blacklisted token usage
                if let Some(ref token_id) = jti {
                    let _ = redis_manager.add_security_event(
                        &claims.sub,
                        SecurityEventType::BlacklistedTokenUsage,
                        &format!("Attempted use of blacklisted token: {}", token_id),
                        ip_address,
                        &user_agent
                    ).await;
                }
                None
            } else if let Some(session_id) = claims.get_claim::<String>("sid").unwrap_or(None) {
                // Validate session state in Redis
                if let Ok(Some(session)) = session_manager.get_session(&session_id).await {
                    let validation_result = session_manager.validate_session(&session.id, ip_address, &user_agent).await.unwrap_or_else(|_| {
                        use crate::models::ses::{SessionValidationResult, ValidationError};
                        SessionValidationResult {
                            is_valid: false,
                            session: None,
                            validation_errors: vec![ValidationError::SessionNotFound],
                            security_warnings: vec![],
                        }
                    });
                    if session.is_valid() && 
                        session.user_id == claims.sub &&
                        validation_result.is_valid {
                        Some(AuthUser::new_with_session(
                            claims.sub.clone(),
                            claims,
                            session_id,
                            true
                        ))
                    } else {
                        // Token valid but session invalid - still allow access
                        Some(AuthUser::new(claims.sub.clone(), claims))
                    }
                } else {
                    // Token valid but no session - still allow access
                    Some(AuthUser::new(claims.sub.clone(), claims))
                }
            } else {
                // Token valid but no session ID - still allow access
                Some(AuthUser::new(claims.sub.clone(), claims))
            }
        } else {
            // Try refresh token if access token failed
            let refresh_token = jar
                .get(REFRESH_TOKEN_COOKIE)
                .map(|cookie| cookie.value().to_string());
            
            if let Some(refresh_token) = refresh_token {
                if let Ok(claims) = paseto_manager.validate_token(&refresh_token) {
                    // Check if refresh token is blacklisted
                    let jti = claims.get_claim::<String>("jti").unwrap_or(None);
                    let is_blacklisted = if let Some(ref token_id) = jti {
                        redis_manager.is_token_blacklisted(token_id).await.unwrap_or(false)
                    } else {
                        false
                    };

                    if is_blacklisted {
                        // Log security event for blacklisted refresh token usage
                        if let Some(ref token_id) = jti {
                            let _ = redis_manager.add_security_event(
                                &claims.sub,
                                SecurityEventType::BlacklistedTokenUsage,
                                &format!("Attempted use of blacklisted refresh token: {}", token_id),
                                ip_address,
                                &user_agent
                            ).await;
                        }
                        None
                    } else {
                        // Check for session ID in refresh token too
                        let session_id = claims.get_claim::<String>("sid").unwrap_or(None);
                        let session_valid = if let Some(ref sid) = session_id {
                            session_manager.get_session(sid).await
                                .map(|s| s.map(|session| session.is_valid()).unwrap_or(false))
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        
                        Some(AuthUser::new_with_session(claims.sub.clone(), claims, session_id.unwrap_or_default(), session_valid))
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
    } else {
        None
    };

    match auth_user {
        Some(user) => {
            // Log successful authentication analytics
            if let Some(session_id) = &user.session_id {
                let analytics_data = serde_json::json!({
                    "timestamp": chrono::Utc::now().timestamp(),
                    "user_id": user.user_id,
                    "ip_address": ip_address.to_string(),
                    "user_agent": user_agent,
                    "session_valid": user.session_valid,
                    "auth_method": "token"
                });
                
                // Store session analytics
                let _ = redis_manager.store_session_analytics(
                    session_id,
                    &analytics_data.to_string(),
                    86400 // 24 hours TTL for analytics
                ).await;
                
                // Log security event for successful authentication
                let _ = redis_manager.add_security_event(
                    &user.user_id,
                    SecurityEventType::SessionValidated,
                    "Successful token authentication",
                    ip_address,
                    &user_agent
                ).await;
            }
            
            // Insert the authenticated user into request extensions
            request.extensions_mut().insert(user);
            Ok(next.run(request).await)
        }
        None => {
            // Log failed authentication attempt
            let _ = redis_manager.add_security_event(
                "unknown",
                SecurityEventType::AuthenticationFailed,
                "No valid authentication token found",
                ip_address,
                &user_agent
            ).await;
            
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