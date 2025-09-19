use axum::{
    extract::{Path, Query, Extension},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Utc};

use crate::auth::ses::SessionManager;
use crate::errors::AppError;
use crate::models::ses::{
    Session, CreateSessionRequest, SessionValidationResult, 
    SecurityLevel, ActivityType, SessionActivity
};

/// Session creation response
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub security_level: SecurityLevel,
}

/// Session list response for admin endpoints
#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionSummary>,
    pub total_count: usize,
    pub active_count: usize,
}

/// Session summary for listing
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_ip: IpAddr,
    pub device_name: Option<String>,
    pub security_level: SecurityLevel,
    pub is_active: bool,
    pub is_suspicious: bool,
}

/// Query parameters for session listing
#[derive(Debug, Deserialize)]
pub struct SessionListQuery {
    pub user_id: Option<String>,
    pub active_only: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Session refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshSessionRequest {
    pub extend_duration: Option<u64>, // seconds
}

/// Session revocation request
#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub reason: Option<String>,
    pub revoke_all_user_sessions: Option<bool>,
}

/// Session validation response
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    pub is_valid: bool,
    pub session: Option<SessionSummary>,
    pub warnings: Vec<String>,
}

/// Session analytics response
#[derive(Debug, Serialize)]
pub struct SessionAnalyticsResponse {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub suspicious_sessions: usize,
    pub sessions_by_security_level: HashMap<String, usize>,
    pub recent_activities: Vec<SessionActivity>,
}

/// Create session routes
pub fn create_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        // Public session endpoints
        .route("/sessions", post(create_session))
        .route("/sessions/:session_id", get(get_session))
        .route("/sessions/:session_id/refresh", post(refresh_session))
        .route("/sessions/:session_id/validate", post(validate_session))
        .route("/sessions/:session_id/revoke", delete(revoke_session))
        
        // Admin session endpoints
        .route("/admin/sessions", get(list_sessions))
        .route("/admin/sessions/analytics", get(get_session_analytics))
        .route("/admin/sessions/:session_id", delete(admin_revoke_session))
        .route("/admin/sessions/user/:user_id", get(list_user_sessions))
        .route("/admin/sessions/user/:user_id/revoke", delete(revoke_user_sessions))
        
        // Session activity endpoints
        .route("/sessions/:session_id/activity", get(get_session_activity))
        .route("/admin/sessions/activity", get(get_all_session_activity))
}

/// Create admin session routes
pub fn create_admin_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        // Admin session endpoints
        .route("/admin/sessions", get(list_sessions))
        .route("/admin/sessions/analytics", get(get_session_analytics))
        .route("/admin/sessions/:session_id", delete(admin_revoke_session))
        .route("/admin/sessions/user/:user_id", get(list_user_sessions))
        .route("/admin/sessions/user/:user_id/revoke", delete(revoke_user_sessions))
        .route("/admin/sessions/activity", get(get_all_session_activity))
}

/// Create a new session
pub async fn create_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    // Extract IP address from headers or request
    let ip_address = extract_ip_address(&headers, request.ip_address)?;
    
    // Extract user agent
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Create session through session manager
    let session = session_manager.create_session(
        request.user_id,
        ip_address,
        user_agent,
        request.device_fingerprint,
        request.login_method,
        request.security_level.unwrap_or_default(),
        request.metadata,
    ).await?;

    Ok(Json(SessionResponse {
        session_id: session.id,
        token: session.token,
        expires_at: session.expires_at,
        security_level: session.security_level,
    }))
}

/// Get session details
pub async fn get_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SessionSummary>, AppError> {
    // Validate session access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    
    let session = session_manager.get_session(&session_id).await?
        .ok_or_else(|| AppError::not_found("Session"))?;

    // Check if user can access this session
    if requesting_session.user_id != session.user_id && 
       requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    Ok(Json(session_to_summary(&session)))
}

/// Refresh a session
pub async fn refresh_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RefreshSessionRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    let ip_address = extract_ip_from_headers(&headers)?;
    
    let session = session_manager.refresh_session(
        &session_id,
        ip_address,
        request.extend_duration,
    ).await?;

    Ok(Json(SessionResponse {
        session_id: session.id,
        token: session.token,
        expires_at: session.expires_at,
        security_level: session.security_level,
    }))
}

/// Validate a session
pub async fn validate_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ValidationResponse>, AppError> {
    let ip_address = extract_ip_from_headers(&headers)?;
    let user_agent = extract_user_agent(&headers);
    
    let result = session_manager.validate_session(
        &session_id,
        ip_address,
        &user_agent,
    ).await?;

    Ok(Json(ValidationResponse {
        is_valid: result.is_valid,
        session: result.session.map(|s| session_to_summary(&s)),
        warnings: result.security_warnings.iter()
            .map(|w| format!("{:?}", w))
            .collect(),
    }))
}

/// Revoke a session
pub async fn revoke_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RevokeSessionRequest>,
) -> Result<StatusCode, AppError> {
    // Validate session access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    
    let session = session_manager.get_session(&session_id).await?
        .ok_or_else(|| AppError::not_found("Session"))?;

    // Check if user can revoke this session
    if requesting_session.user_id != session.user_id && 
       requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    if request.revoke_all_user_sessions.unwrap_or(false) {
        session_manager.revoke_user_sessions(&session.user_id, request.reason.as_deref()).await?;
    } else {
        session_manager.revoke_session(&session_id, request.reason.as_deref()).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// List sessions (admin endpoint)
pub async fn list_sessions(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> Result<Json<SessionListResponse>, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    let sessions = session_manager.list_sessions(
        query.user_id.as_deref(),
        query.active_only.unwrap_or(false),
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    ).await?;

    let total_count = sessions.len();
    let active_count = sessions.iter().filter(|s| s.is_valid()).count();

    Ok(Json(SessionListResponse {
        sessions: sessions.into_iter().map(|s| session_to_summary(&s)).collect(),
        total_count,
        active_count,
    }))
}

/// Get session analytics (admin endpoint)
pub async fn get_session_analytics(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    headers: HeaderMap,
) -> Result<Json<SessionAnalyticsResponse>, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    let analytics = session_manager.get_analytics().await?;

    Ok(Json(SessionAnalyticsResponse {
        total_sessions: analytics.total_sessions,
        active_sessions: analytics.active_sessions,
        suspicious_sessions: analytics.suspicious_sessions,
        sessions_by_security_level: analytics.sessions_by_security_level,
        recent_activities: analytics.recent_activities,
    }))
}

/// Admin revoke session
pub async fn admin_revoke_session(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    session_manager.revoke_session(&session_id, Some("Admin revocation")).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List user sessions (admin endpoint)
pub async fn list_user_sessions(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> Result<Json<SessionListResponse>, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    let sessions = session_manager.list_sessions(
        Some(&user_id),
        query.active_only.unwrap_or(false),
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    ).await?;

    let total_count = sessions.len();
    let active_count = sessions.iter().filter(|s| s.is_valid()).count();

    Ok(Json(SessionListResponse {
        sessions: sessions.into_iter().map(|s| session_to_summary(&s)).collect(),
        total_count,
        active_count,
    }))
}

/// Revoke all user sessions (admin endpoint)
pub async fn revoke_user_sessions(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    session_manager.revoke_user_sessions(&user_id, Some("Admin bulk revocation")).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Get session activity
pub async fn get_session_activity(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionActivity>>, AppError> {
    // Validate session access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    
    let session = session_manager.get_session(&session_id).await?
        .ok_or_else(|| AppError::not_found("Session"))?;

    // Check if user can access this session activity
    if requesting_session.user_id != session.user_id && 
       requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    let activities = session_manager.get_session_activity(&session_id).await?;
    Ok(Json(activities))
}

/// Get all session activity (admin endpoint)
pub async fn get_all_session_activity(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> Result<Json<Vec<SessionActivity>>, AppError> {
    // Validate admin access
    let requesting_session = extract_session_from_headers(&session_manager, &headers).await?;
    if requesting_session.security_level < SecurityLevel::Administrative {
        return Err(AppError::Forbidden);
    }

    let activities = session_manager.get_all_activity(
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    ).await?;
    
    Ok(Json(activities))
}

// Helper functions

/// Extract IP address from headers or fallback
fn extract_ip_address(headers: &HeaderMap, fallback: IpAddr) -> Result<IpAddr, AppError> {
    // Try to get real IP from headers (X-Forwarded-For, X-Real-IP, etc.)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    Ok(fallback)
}

/// Extract IP from headers
fn extract_ip_from_headers(headers: &HeaderMap) -> Result<IpAddr, AppError> {
    extract_ip_address(headers, "127.0.0.1".parse().unwrap())
}

/// Extract user agent from headers
fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Extract session from authorization header
async fn extract_session_from_headers(
    session_manager: &Arc<SessionManager>,
    headers: &HeaderMap,
) -> Result<Session, AppError> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized);
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix
    let session = session_manager.get_session_by_token(token).await?
        .ok_or_else(|| AppError::Unauthorized)?;

    if !session.is_valid() {
        return Err(AppError::Unauthorized);
    }

    Ok(session)
}

/// Convert session to summary
fn session_to_summary(session: &Session) -> SessionSummary {
    SessionSummary {
        id: session.id.clone(),
        user_id: session.user_id.clone(),
        created_at: session.created_at,
        last_activity: session.last_activity,
        expires_at: session.expires_at,
        last_ip: session.last_ip,
        device_name: session.device_name.clone(),
        security_level: session.security_level.clone(),
        is_active: session.flags.is_active,
        is_suspicious: session.flags.is_suspicious,
    }
}