use axum::{
    extract::{Extension, Request},
    middleware::Next,
    response::Response,
    http::HeaderMap,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use std::net::IpAddr;
use chrono::{Duration, Utc};

use crate::{
    auth::{
        Claims, PasetoManager, 
        ses::{SessionManager, SecurityEventType},
        threat::{ThreatDetectionEngine, ThreatEvaluationResult},
        behavioral::{BehaviorAnalytics, GeoLocation},
        binding::SessionBindingManager,
    },
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
    Extension(threat_engine): Extension<Arc<ThreatDetectionEngine>>,
    Extension(binding_manager): Extension<Arc<SessionBindingManager>>,
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

    let refresh_token = jar
        .get(REFRESH_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());

    // Try to validate access token first
    let (auth_user, mut updated_jar) = if let Some(access_token) = &access_token {
        match paseto_manager.validate_token(access_token) {
            Ok(claims) => {
                // Check if token is blacklisted
                let jti = claims.get_claim::<String>("jti").unwrap_or(None);
                let is_blacklisted = if let Some(ref token_id) = jti {
                    redis_manager.is_token_blacklisted(token_id).await.unwrap_or(false)
                } else {
                    false
                };

                if is_blacklisted {
                    return Err(AppError::TokenError("Token has been revoked".to_string()));
                }

                // Check if token is nearing expiration (within 5 minutes)
                let should_rotate = claims.exp - Utc::now().timestamp() < 300; // 5 minutes

                let mut new_jar = jar.clone();
                let mut rotated_tokens = None;

                if should_rotate && refresh_token.is_some() {
                    // Attempt token rotation
                    match attempt_token_rotation(
                        &paseto_manager,
                        &redis_manager,
                        &refresh_token.unwrap(),
                        &claims.sub,
                        claims.get_claim::<String>("sid").unwrap_or(None).as_deref(),
                    ).await {
                        Ok((new_access_token, new_refresh_token, old_access_jti, old_refresh_jti)) => {
                            // Blacklist old tokens
                            if let Some(old_jti) = &jti {
                                let _ = redis_manager.blacklist_token(old_jti, 3600).await; // 1 hour blacklist
                            }
                            let _ = redis_manager.blacklist_token(&old_refresh_jti, 7 * 24 * 3600).await; // 7 days

                            // Update cookies with new tokens
                            let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &new_access_token, 15 * 60);
                            let refresh_cookie = create_secure_cookie(REFRESH_TOKEN_COOKIE, &new_refresh_token, 7 * 24 * 3600);
                            new_jar = new_jar.add(access_cookie).add(refresh_cookie);

                            // Validate the new token to get updated claims
                            match paseto_manager.validate_token(&new_access_token) {
                                Ok(new_claims) => {
                                    rotated_tokens = Some(new_claims);
                                    
                                    // Log token rotation event
                                    let _ = redis_manager.add_security_event(
                                        &claims.sub,
                                        SecurityEventType::TokenRotated,
                                        "Access token automatically rotated",
                                        ip_address,
                                        &user_agent
                                    ).await;
                                }
                                Err(_) => {
                                    // If new token validation fails, continue with original
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Token rotation failed: {}", e);
                            // Continue with original token
                        }
                    }
                }

                let final_claims = rotated_tokens.unwrap_or(claims);

                // Extract session ID from token if available
                let session_id = final_claims.get_claim::<String>("sid").unwrap_or(None);
                
                // Validate session if session ID is present
                let session_valid = if let Some(ref session_id) = session_id {
                    match session_manager.validate_session(session_id, ip_address, &user_agent).await {
                        Ok(validation_result) => {
                            if !validation_result.is_valid {
                                // Log security event for invalid session using proper audit logging
                                let event = crate::auth::audit::AuditEvent::new(
                                    crate::auth::audit::AuditEventType::SessionRevoked,
                                    ip_address,
                                    Some(user_agent.clone()),
                                    "Session validation failed".to_string(),
                                )
                                .with_user(final_claims.sub.clone())
                                .with_session(session_id.clone())
                                .with_outcome(crate::auth::audit::EventOutcome::Failure)
                                .with_severity(crate::auth::audit::EventSeverity::Medium)
                                .with_metadata("validation_errors".to_string(), format!("{:?}", validation_result.validation_errors))
                                .with_metadata("security_warnings".to_string(), format!("{:?}", validation_result.security_warnings));
                                
                                false
                            } else {
                                // Get session for threat evaluation
                                if let Ok(Some(mut session)) = session_manager.get_session(session_id).await {
                                    // Perform real-time threat evaluation
                                    let user_behavior = BehaviorAnalytics::new(); // TODO: Load from database
                                    let geo_data = GeoLocation {
                                        current_location: (0.0, 0.0), // TODO: Get from IP geolocation service
                                        previous_location: None,
                                        country_code: "US".to_string(),
                                        city: None,
                                        timezone: "UTC".to_string(),
                                        isp: None,
                                        is_vpn_proxy: false,
                                    };

                                    match threat_engine.evaluate_session_threats(&session, &user_behavior, &geo_data).await {
                                        Ok(threat_evaluation) => {
                                            // Execute automated threat response
                                            if let Ok(actions) = threat_engine.execute_threat_response(&mut session, &threat_evaluation).await {
                                                if !actions.is_empty() {
                                                    // Log threat response actions
                                                    let event = crate::auth::audit::AuditEvent::new(
                                                        crate::auth::audit::AuditEventType::SecurityViolation,
                                                        ip_address,
                                                        Some(user_agent.clone()),
                                                        "Threat detected and automated response executed".to_string(),
                                                    )
                                                    .with_user(final_claims.sub.clone())
                                                    .with_session(session_id.clone())
                                                    .with_outcome(crate::auth::audit::EventOutcome::Success)
                                                    .with_severity(crate::auth::audit::EventSeverity::High)
                                                    .with_risk_score(threat_evaluation.risk_score)
                                                    .with_metadata("actions_taken".to_string(), format!("{:?}", actions));

                                                    // Check if session was revoked
                                                    let session_revoked = actions.iter().any(|action| {
                                                        matches!(action, crate::models::security::SecurityAction::SessionRevoked)
                                                    });
                                                     
                                                    if session_revoked {
                                                        return Err(AppError::Unauthorized);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Threat evaluation failed: {}", e);
                                        }
                                    }

                                    // Validate session binding if configured
                                    if let Some(_binding) = binding_manager.get_binding(session_id) {
                                        let device_fingerprint = crate::auth::binding::DeviceFingerprint::from_user_agent(user_agent.clone());
                                        match binding_manager.validate_binding(
                                            session_id,
                                            ip_address,
                                            &device_fingerprint,
                                            None, // TODO: Extract TLS fingerprint
                                        ) {
                                            Ok(validation_result) => {
                                                if !validation_result.is_valid {
                                                    // Log binding validation failure
                                                    let event = crate::auth::audit::AuditEvent::new(
                                                        crate::auth::audit::AuditEventType::SecurityViolation,
                                                        ip_address,
                                                        Some(user_agent.clone()),
                                                        "Session binding validation failed".to_string(),
                                                    )
                                                    .with_user(final_claims.sub.clone())
                                                    .with_session(session_id.clone())
                                                    .with_outcome(crate::auth::audit::EventOutcome::Failure)
                                                    .with_severity(crate::auth::audit::EventSeverity::High)
                                                    .with_metadata("failed_validations".to_string(), validation_result.failed_validations.join(", "));
                                                     
                                                    return Err(AppError::Unauthorized);
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("Session binding validation failed: {}", e);
                                                return Err(AppError::Unauthorized);
                                            }
                                        }
                                    }
                                }
                                true
                            }
                        }
                        Err(_) => false,
                    }
                } else {
                    true // No session ID, just token validation
                };

                (Some(AuthUser::new_with_session(
                    final_claims.sub.clone(),
                    final_claims,
                    session_id.unwrap_or_default(),
                    session_valid,
                )), new_jar)
            }
            Err(_) => {
                // Access token invalid, try refresh token if available
                if let Some(refresh_token) = &refresh_token {
                    match attempt_refresh_token_validation(&paseto_manager, &redis_manager, refresh_token).await {
                        Ok((new_access_token, claims)) => {
                            // Create new access token cookie
                            let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &new_access_token, 15 * 60);
                            let new_jar = jar.clone().add(access_cookie);

                            let session_id = claims.get_claim::<String>("sid").unwrap_or(None);
                            
                            (Some(AuthUser::new_with_session(
                                claims.sub.clone(),
                                claims,
                                session_id.unwrap_or_default(),
                                true, // Assume valid since we just refreshed
                            )), new_jar)
                        }
                        Err(_) => (None, jar.clone())
                    }
                } else {
                    (None, jar.clone())
                }
            }
        }
    } else {
        (None, jar.clone())
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
            
            // If we have updated cookies, we need to add them to the response
            // Check if the jar was modified by comparing cookie counts or using a flag
            let jar_modified = updated_jar.iter().count() != jar.iter().count();
            if jar_modified {
                // Store updated jar in request extensions for response modification
                request.extensions_mut().insert(updated_jar);
            }
            
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

/// Attempt to rotate tokens when access token is nearing expiration
async fn attempt_token_rotation(
    paseto_manager: &PasetoManager,
    redis_manager: &Arc<RedisManager>,
    refresh_token: &str,
    user_id: &str,
    session_id: Option<&str>,
) -> Result<(String, String, String, String), AppError> {
    // Validate refresh token first
    let refresh_claims = paseto_manager.validate_token(refresh_token)?;
    
    // Check if refresh token is blacklisted
    let refresh_jti = refresh_claims.get_claim::<String>("jti").unwrap_or(None);
    if let Some(ref token_id) = refresh_jti {
        if redis_manager.is_token_blacklisted(token_id).await.unwrap_or(false) {
            return Err(AppError::TokenError("Refresh token has been revoked".to_string()));
        }
    }

    // Generate new token pair with rotation tracking
    let (new_access_token, new_refresh_token, access_jti, refresh_jti) = 
        paseto_manager.generate_token_pair_with_rotation(user_id, session_id.unwrap_or(""))?;

    Ok((new_access_token, new_refresh_token, "old_access_jti".to_string(), refresh_jti))
}

/// Attempt to validate refresh token and generate new access token
async fn attempt_refresh_token_validation(
    paseto_manager: &PasetoManager,
    redis_manager: &Arc<RedisManager>,
    refresh_token: &str,
) -> Result<(String, Claims), AppError> {
    // Validate refresh token
    let claims = paseto_manager.validate_token(refresh_token)?;
    
    // Check if refresh token is blacklisted
    let jti = claims.get_claim::<String>("jti").unwrap_or(None);
    if let Some(ref token_id) = jti {
        if redis_manager.is_token_blacklisted(token_id).await.unwrap_or(false) {
            return Err(AppError::TokenError("Refresh token has been revoked".to_string()));
        }
    }

    // Generate new access token
    let session_id = claims.get_claim::<String>("sid").unwrap_or(None);
    let new_access_token = if let Some(session_id) = session_id {
        paseto_manager.generate_access_token_with_session(&claims.sub, &session_id)?
    } else {
        paseto_manager.generate_access_token(&claims.sub)?
    };

    // Validate new token to get claims
    let new_claims = paseto_manager.validate_token(&new_access_token)?;

    Ok((new_access_token, new_claims))
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