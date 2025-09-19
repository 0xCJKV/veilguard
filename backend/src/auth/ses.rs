use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use redis::{AsyncCommands, RedisResult};
use serde::{Serialize, Deserialize};
use serde_json;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::errors::AppError;
use crate::database::redis::RedisManager;
use crate::auth::audit::{AuditManager, AuditEventType, EventOutcome, EventSeverity};
use crate::models::ses::{
    Session, SessionConfig, SessionValidationResult, ValidationError, SecurityWarning,
    SecurityLevel, CreateSessionRequest, SessionFlags, SessionMetadata,
};
use crate::models::security::{
    SessionMetrics, SecurityAction, RiskAssessment, EventSeverity as SecurityEventSeverity,
    SessionActivity, ActivityType,
};
use super::utils::{is_expired, generate_secure_token, default_hash};

/// Session manager with Redis backend and security features
#[derive(Clone)]
pub struct SessionManager {
    redis: redis::Client,
    config: SessionConfig,
    security: Arc<SecurityManager>,
    analytics: Arc<SessionAnalytics>,
    redis_manager: Option<Arc<RedisManager>>,
    audit_manager: Arc<AuditManager>,
}

/// Security manager for session validation and risk assessment
#[derive(Debug)]
pub struct SecurityManager {
    known_ips: RwLock<HashMap<String, Vec<IpAddr>>>,
    known_devices: RwLock<HashMap<String, Vec<String>>>,
    suspicious_ips: RwLock<Vec<IpAddr>>,
    failed_attempts: RwLock<HashMap<String, u32>>,
}

/// Session analytics and monitoring (now using SessionMetrics from models/security.rs)
#[derive(Debug)]
pub struct SessionAnalytics {
    login_attempts: RwLock<HashMap<String, u32>>,
    security_events: RwLock<Vec<SecurityEvent>>,
    session_metrics: RwLock<SessionMetrics>,
}

/// Security event tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub user_id: String,
    pub session_id: Option<String>,
    pub ip_address: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub details: HashMap<String, String>,
}

/// Types of security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    LoginAttempt,
    LoginSuccess,
    LoginFailure,
    AuthenticationFailed,
    SessionCreated,
    SessionRevoked,
    SessionValidated,
    SuspiciousActivity,
    SecurityViolation,
    DeviceChange,
    LocationChange,
    BlacklistedTokenUsage,
    TokenRotated,
}

// Remove duplicate SessionMetrics - now using from models/security.rs

/// Device fingerprinting for security validation
#[derive(Debug, Clone)]
pub struct DeviceFingerprinting {
    pub user_agent: String,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub platform: Option<String>,
    pub plugins: Vec<String>,
    pub canvas_fingerprint: Option<String>,
}

/// Risk assessment result (simplified - using RiskAssessment from models/security.rs for core logic)
#[derive(Debug)]
pub struct SecurityRisk {
    pub risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub recommended_action: RecommendedAction,
}

/// Risk factors for security assessment
#[derive(Debug, Clone)]
pub enum RiskFactor {
    UnknownIpAddress,
    UnknownDevice,
    UnusualLoginTime,
    MultipleFailedAttempts,
    ConcurrentSessions,
    LocationChange,
    SuspiciousUserAgent,
    HighVelocityRequests,
}

/// Recommended security actions
#[derive(Debug)]
pub enum RecommendedAction {
    Allow,
    RequireMfa,
    Block,
    Monitor,
    RequireReauth,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(redis_url: &str, config: SessionConfig) -> Result<Self, AppError> {
        let redis = redis::Client::open(redis_url)
            .map_err(|e| AppError::internal(&format!("Redis connection failed: {}", e)))?;

        Ok(Self {
            redis,
            config,
            security: Arc::new(SecurityManager::new()),
            analytics: Arc::new(SessionAnalytics::new()),
            redis_manager: None,
            audit_manager: Arc::new(AuditManager::new()),
        })
    }

    /// Create a new SessionManager with RedisManager integration
    pub fn new_with_redis_manager(redis_url: &str, config: SessionConfig, redis_manager: Arc<RedisManager>) -> Result<Self, AppError> {
        let redis = redis::Client::open(redis_url)
            .map_err(|e| AppError::internal(&format!("Redis connection failed: {}", e)))?;

        Ok(Self {
            redis,
            config,
            security: Arc::new(SecurityManager::new()),
            analytics: Arc::new(SessionAnalytics::new()),
            redis_manager: Some(redis_manager),
            audit_manager: Arc::new(AuditManager::new()),
        })
    }

    /// Create a new session
    pub async fn create_session(
        &self,
        user_id: String,
        ip_address: IpAddr,
        user_agent: String,
        device_fingerprint: String,
        login_method: String,
        security_level: SecurityLevel,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Session, AppError> {
        // Perform security assessment
        let risk = self.security.assess_risk(
            &user_id,
            ip_address,
            &device_fingerprint,
            &user_agent,
        ).await;

        // Check if we should block this session creation
        match risk.recommended_action {
            RecommendedAction::Block => {
                return Err(AppError::Forbidden);
            }
            RecommendedAction::RequireMfa => {
                // In a real implementation, this would trigger MFA flow
                // For now, we'll create the session but mark it as requiring MFA
            }
            _ => {}
        }

        // Check concurrent session limits
        let concurrent_count = self.count_user_sessions(&user_id).await?;
        if concurrent_count >= self.config.max_concurrent_sessions {
            return Err(AppError::bad_request("Too many concurrent sessions"));
        }

        // Create the session
        let security_level_clone = security_level.clone();
        let mut session = Session::new(
            user_id.clone(),
            ip_address,
            user_agent.clone(),
            device_fingerprint.clone(),
            security_level,
            None, // device_name can be set later
            None, // application can be set later
        );

        // Set metadata
        session.metadata.login_method = login_method.clone();
        session.metadata.risk_score = risk.risk_score;
        session.metadata.concurrent_sessions = concurrent_count + 1;
        
        if let Some(custom_metadata) = metadata {
            session.metadata.custom_data.extend(custom_metadata);
        }

        // Set flags based on risk assessment
        if matches!(risk.recommended_action, RecommendedAction::RequireMfa) {
            session.flags.requires_mfa = true;
        }

        if risk.risk_score > 0.7 {
            session.flags.is_suspicious = true;
        }

        // Store session in Redis
        self.store_session(&session).await?;

        // Record security event
        self.analytics.record_security_event(SecurityEvent {
            event_type: SecurityEventType::SessionCreated,
            user_id: user_id.clone(),
            session_id: Some(session.id.clone()),
            ip_address,
            timestamp: Utc::now(),
            details: HashMap::new(),
        }).await;

        // Update known devices and IPs
        self.security.update_known_device(&user_id, device_fingerprint).await;
        self.security.update_known_ip(&user_id, ip_address).await;

        // Update analytics
        self.analytics.update_session_metrics(&session).await;

        // Log audit event for session creation
        let audit_event = crate::auth::audit::AuditEvent::new(
            AuditEventType::SessionCreated,
            ip_address,
            Some(user_agent.clone()),
            "Session created successfully".to_string(),
        )
        .with_user(user_id.clone())
        .with_session(session.id.clone())
        .with_outcome(EventOutcome::Success)
        .with_severity(EventSeverity::Medium)
        .with_risk_score(risk.risk_score)
        .with_metadata("login_method".to_string(), login_method.clone())
        .with_metadata("security_level".to_string(), format!("{:?}", security_level_clone));
        
        self.audit_manager.log_event(&audit_event).await;

        // Log session creation event using RedisManager if available
         if let Some(redis_manager) = &self.redis_manager {
             let _ = redis_manager.add_security_event(
                  &user_id,
                  SecurityEventType::SessionCreated,
                  &format!("Session created with security level: {:?}", security_level_clone),
                  ip_address,
                  &user_agent
              ).await;

            // Store session analytics
            if let Ok(analytics_data) = serde_json::to_string(&session.metadata) {
                let _ = redis_manager.store_session_analytics(
                    &session.id,
                    &analytics_data,
                    self.config.default_lifetime
                ).await;
            }
        }

        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Result<Option<Session>, AppError> {
        // Use RedisManager if available for enhanced session retrieval
        if let Some(redis_manager) = &self.redis_manager {
            if let Some(session_data) = redis_manager.get_session(session_id).await? {
                let session: Session = serde_json::from_str(&session_data)
                    .map_err(|e| AppError::internal(&format!("Session deserialization failed: {}", e)))?;
                return Ok(Some(session));
            } else {
                return Ok(None);
            }
        }

        // Fallback to direct Redis connection
        let mut conn = self.get_redis_connection().await?;
        let key = format!("session:{}", session_id);
        
        let session_data: Option<String> = conn.get(&key).await
            .map_err(|e| AppError::internal(&format!("Redis get failed: {}", e)))?;

        match session_data {
            Some(data) => {
                let session: Session = serde_json::from_str(&data)
                    .map_err(|e| AppError::internal(&format!("Session deserialization failed: {}", e)))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Get session by token
    pub async fn get_session_by_token(&self, token: &str) -> Result<Option<Session>, AppError> {
        let mut conn = self.get_redis_connection().await?;
        let token_key = format!("token:{}", token);
        
        let session_id: Option<String> = conn.get(&token_key).await
            .map_err(|e| AppError::internal(&format!("Redis get failed: {}", e)))?;

        match session_id {
            Some(id) => self.get_session(&id).await,
            None => Ok(None),
        }
    }

    /// Validate session
    pub async fn validate_session(
        &self,
        session_id: &str,
        ip_address: IpAddr,
        user_agent: &str,
    ) -> Result<SessionValidationResult, AppError> {
        let mut validation_errors = Vec::new();
        let mut security_warnings = Vec::new();

        // Get session
        let session = match self.get_session(session_id).await? {
            Some(s) => s,
            None => {
                validation_errors.push(ValidationError::SessionNotFound);
                return Ok(SessionValidationResult {
                    is_valid: false,
                    session: None,
                    validation_errors,
                    security_warnings,
                });
            }
        };

        // Check if session is expired
        if is_expired(session.expires_at.timestamp() as u64) {
            validation_errors.push(ValidationError::SessionExpired);
        }

        // Check if session is revoked
        if session.flags.is_revoked {
            validation_errors.push(ValidationError::SessionRevoked);
        }

        // Check IP validation if enforced
        if self.config.enforce_ip_validation && session.last_ip != ip_address {
            if session.flags.is_ip_locked {
                validation_errors.push(ValidationError::IpMismatch);
            } else {
                security_warnings.push(SecurityWarning::NewIpAddress);
            }
        }

        // Check device validation if enforced
        if self.config.enforce_device_validation {
            let device_hash = default_hash(user_agent);
            let session_device_hash = default_hash(&session.user_agent);
            
            if device_hash != session_device_hash {
                security_warnings.push(SecurityWarning::NewDevice);
            }
        }

        // Check for suspicious activity
        if session.flags.is_suspicious {
            security_warnings.push(SecurityWarning::HighRiskScore);
        }

        // Perform additional risk assessment
        let risk = self.security.assess_risk(&session.user_id, ip_address, &session.device_fingerprint, user_agent).await;
        
        if risk.risk_score > 0.8 {
            security_warnings.push(SecurityWarning::HighRiskScore);

            // Log security event using RedisManager if available
              if let Some(redis_manager) = &self.redis_manager {
                  let _ = redis_manager.add_security_event(
                      &session.user_id,
                      SecurityEventType::SuspiciousActivity,
                      &format!("High risk activity detected with score: {:.2}", risk.risk_score),
                      ip_address,
                      user_agent
                  ).await;
              }
        }

        // Update session activity if valid
        let is_valid = validation_errors.is_empty() && session.flags.is_active;
        
        if is_valid {
            let mut updated_session = session.clone();
            updated_session.update_activity(ip_address);
            self.store_session(&updated_session).await?;

            // Record session validation event
             if let Some(redis_manager) = &self.redis_manager {
                 let _ = redis_manager.add_security_event(
                     &session.user_id,
                     SecurityEventType::LoginSuccess,
                     "Session validation successful",
                     ip_address,
                     user_agent
                 ).await;
             }
        }

        Ok(SessionValidationResult {
            is_valid,
            session: Some(session),
            validation_errors,
            security_warnings,
        })
    }

    /// Refresh session
    pub async fn refresh_session(
        &self,
        session_id: &str,
        ip_address: IpAddr,
        extend_duration: Option<u64>,
    ) -> Result<Session, AppError> {
        let mut session = self.get_session(session_id).await?
            .ok_or_else(|| AppError::not_found("Session"))?;

        if !session.is_valid() {
            return Err(AppError::Unauthorized);
        }

        // Update activity
        session.update_activity(ip_address);

        // Extend expiry if requested
        if let Some(duration_secs) = extend_duration {
            let duration = Duration::seconds(duration_secs as i64);
            session.extend_expiry(duration);
        } else {
            // Default refresh extends by half the default lifetime
            let duration = Duration::seconds((self.config.default_lifetime / 2) as i64);
            session.extend_expiry(duration);
        }

        // Store updated session
        self.store_session(&session).await?;

        // Record activity
        self.record_session_activity(&session, ActivityType::SessionRefreshed, ip_address).await?;

        Ok(session)
    }

    /// Revoke session
    pub async fn revoke_session(&self, session_id: &str, reason: Option<&str>) -> Result<(), AppError> {
        let mut session = self.get_session(session_id).await?
            .ok_or_else(|| AppError::not_found("Session"))?;

        session.revoke(reason);
        self.store_session(&session).await?;

        // Remove from token index
        let mut conn = self.get_redis_connection().await?;
        let token_key = format!("token:{}", session.token);
        let _: () = conn.del(&token_key).await
            .map_err(|e| AppError::internal(&format!("Redis delete failed: {}", e)))?;

        // Record activity
        self.record_session_activity(&session, ActivityType::SessionRevoked, session.last_ip).await?;

        // Log audit event for session revocation
        let audit_event = crate::auth::audit::AuditEvent::new(
            AuditEventType::SessionRevoked,
            session.last_ip,
            Some(session.user_agent.clone()),
            "Session revoked".to_string(),
        )
        .with_user(session.user_id.clone())
        .with_session(session.id.clone())
        .with_outcome(EventOutcome::Success)
        .with_severity(EventSeverity::Medium)
        .with_metadata("reason".to_string(), reason.unwrap_or("Manual revocation").to_string());
        
        self.audit_manager.log_event(&audit_event).await?;

        Ok(())
    }

    /// Revoke all user sessions
    pub async fn revoke_user_sessions(&self, user_id: &str, reason: Option<&str>) -> Result<(), AppError> {
        let sessions = self.list_sessions(Some(user_id), true, 1000, 0).await?;
        
        for session in sessions {
            self.revoke_session(&session.id, reason).await?;
        }

        Ok(())
    }

    /// List sessions
    pub async fn list_sessions(
        &self,
        user_id: Option<&str>,
        active_only: bool,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Session>, AppError> {
        let mut conn = self.get_redis_connection().await?;
        
        // Get all session keys
        let pattern = match user_id {
            Some(uid) => format!("session:*:user:{}", uid),
            None => "session:*".to_string(),
        };

        let keys: Vec<String> = conn.keys(&pattern).await
            .map_err(|e| AppError::internal(&format!("Redis keys failed: {}", e)))?;

        let mut sessions = Vec::new();
        
        for key in keys.into_iter().skip(offset).take(limit) {
            if let Ok(Some(data)) = conn.get::<_, Option<String>>(&key).await {
                if let Ok(session) = serde_json::from_str::<Session>(&data) {
                    if !active_only || session.is_valid() {
                        sessions.push(session);
                    }
                }
            }
        }

        // Sort by last activity (most recent first)
        sessions.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        Ok(sessions)
    }

    /// Count user sessions
    pub async fn count_user_sessions(&self, user_id: &str) -> Result<u32, AppError> {
        let sessions = self.list_sessions(Some(user_id), true, 1000, 0).await?;
        Ok(sessions.len() as u32)
    }

    /// Get session analytics
    pub async fn get_analytics(&self) -> Result<SessionMetrics, AppError> {
        self.analytics.get_metrics().await
    }

    /// Get session activity
    pub async fn get_session_activity(&self, session_id: &str) -> Result<Vec<SessionActivity>, AppError> {
        let mut conn = self.get_redis_connection().await?;
        let key = format!("activity:{}", session_id);
        
        let activities: Vec<String> = conn.lrange(&key, 0, -1).await
            .map_err(|e| AppError::internal(&format!("Redis lrange failed: {}", e)))?;

        let mut result = Vec::new();
        for activity_data in activities {
            if let Ok(activity) = serde_json::from_str::<SessionActivity>(&activity_data) {
                result.push(activity);
            }
        }

        Ok(result)
    }

    /// Get all activity (admin)
    pub async fn get_all_activity(&self, limit: usize, offset: usize) -> Result<Vec<SessionActivity>, AppError> {
        let mut conn = self.get_redis_connection().await?;
        let keys: Vec<String> = conn.keys("activity:*").await
            .map_err(|e| AppError::internal(&format!("Redis keys failed: {}", e)))?;

        let mut all_activities = Vec::new();
        
        for key in keys {
            let activities: Vec<String> = conn.lrange(&key, 0, -1).await
                .map_err(|e| AppError::internal(&format!("Redis lrange failed: {}", e)))?;

            for activity_data in activities {
                if let Ok(activity) = serde_json::from_str::<SessionActivity>(&activity_data) {
                    all_activities.push(activity);
                }
            }
        }

        // Sort by timestamp (most recent first)
        all_activities.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(all_activities.into_iter().skip(offset).take(limit).collect())
    }

    /// Get recent security events for a user
    pub async fn get_recent_security_events(&self, _user_id: &str, limit_seconds: u64) -> Result<Vec<SecurityEvent>, AppError> {
        if let Some(redis_manager) = &self.redis_manager {
            // Calculate limit based on time window - use a reasonable default
            let limit = std::cmp::min((limit_seconds / 60) as usize, 100); // Rough estimate: 1 event per minute max
            let events_json = redis_manager.get_recent_security_events(limit).await?;
            
            let mut events = Vec::new();
            for event_json in events_json {
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&event_json) {
                    // Filter events within the time window
                    let now = Utc::now();
                    let time_diff = now.signed_duration_since(event.timestamp);
                    if time_diff.num_seconds() <= limit_seconds as i64 {
                        events.push(event);
                    }
                }
            }
            
            Ok(events)
        } else {
            // Fallback to in-memory analytics if no RedisManager
            let analytics = self.analytics.security_events.read().await;
            let now = Utc::now();
            let events: Vec<SecurityEvent> = analytics
                .iter()
                .filter(|event| {
                    let time_diff = now.signed_duration_since(event.timestamp);
                    time_diff.num_seconds() <= limit_seconds as i64
                })
                .cloned()
                .collect();
            Ok(events)
        }
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize, AppError> {
        let mut conn = self.get_redis_connection().await?;
        let keys: Vec<String> = conn.keys("session:*").await
            .map_err(|e| AppError::internal(&format!("Redis keys failed: {}", e)))?;

        let mut cleaned_count = 0;

        for key in keys {
            if let Ok(Some(data)) = conn.get::<_, Option<String>>(&key).await {
                if let Ok(session) = serde_json::from_str::<Session>(&data) {
                    if session.is_expired() {
                        // Delete session
                        let _: () = conn.del(&key).await
                            .map_err(|e| AppError::internal(&format!("Redis delete failed: {}", e)))?;
                        
                        // Delete token index
                        let token_key = format!("token:{}", session.token);
                        let _: () = conn.del(&token_key).await
                            .map_err(|e| AppError::internal(&format!("Redis delete failed: {}", e)))?;
                        
                        cleaned_count += 1;
                    }
                }
            }
        }

        Ok(cleaned_count)
    }

    // Private helper methods

    async fn store_session(&self, session: &Session) -> Result<(), AppError> {
        // Use RedisManager if available for enhanced session storage
        if let Some(redis_manager) = &self.redis_manager {
            let session_data = serde_json::to_string(session)
                .map_err(|e| AppError::internal(&format!("Session serialization failed: {}", e)))?;
            
            // Store session with RedisManager
            redis_manager.set_session(&session.id, &session_data, self.config.default_lifetime).await?;
            
            // Update user session count
            let _ = redis_manager.increment_user_session_count(&session.user_id, self.config.default_lifetime).await;
            
            return Ok(());
        }

        // Fallback to direct Redis connection
        let mut conn = self.get_redis_connection().await?;
        
        let session_data = serde_json::to_string(session)
            .map_err(|e| AppError::internal(&format!("Session serialization failed: {}", e)))?;

        let session_key = format!("session:{}", session.id);
        let token_key = format!("token:{}", session.token);
        
        // Store session data
        let _: () = conn.set_ex(&session_key, &session_data, session.expires_at.timestamp() as u64).await
            .map_err(|e| AppError::internal(&format!("Redis set failed: {}", e)))?;

        // Store token -> session_id mapping
        let _: () = conn.set_ex(&token_key, &session.id, session.expires_at.timestamp() as u64).await
            .map_err(|e| AppError::internal(&format!("Redis set failed: {}", e)))?;

        // Update user session count
        let user_sessions_key = format!("user_sessions:{}", session.user_id);
        let _: () = conn.sadd(&user_sessions_key, &session.id).await
            .map_err(|e| AppError::internal(&format!("Redis sadd failed: {}", e)))?;
        let _: () = conn.expire(&user_sessions_key, self.config.default_lifetime as i64).await
            .map_err(|e| AppError::internal(&format!("Redis expire failed: {}", e)))?;

        Ok(())
    }

    async fn get_redis_connection(&self) -> Result<redis::aio::Connection, AppError> {
        self.redis.get_async_connection().await
            .map_err(|e| AppError::internal(&format!("Redis connection failed: {}", e)))
    }

    async fn record_session_activity(
        &self,
        session: &Session,
        activity_type: ActivityType,
        ip_address: IpAddr,
    ) -> Result<(), AppError> {
        let activity = SessionActivity {
            session_id: session.id.clone(),
            activity_type,
            timestamp: Utc::now(),
            ip_address,
            user_agent: session.user_agent.clone(),
            details: HashMap::new(),
        };

        let mut conn = self.get_redis_connection().await?;
        let key = format!("activity:{}", session.id);
        let activity_data = serde_json::to_string(&activity)
            .map_err(|e| AppError::internal(&format!("Activity serialization failed: {}", e)))?;

        // Store activity (keep last 100 activities per session)
        let _: () = conn.lpush(&key, &activity_data).await
            .map_err(|e| AppError::internal(&format!("Redis lpush failed: {}", e)))?;
        
        let _: () = conn.ltrim(&key, 0, 99).await
            .map_err(|e| AppError::internal(&format!("Redis ltrim failed: {}", e)))?;

        Ok(())
    }
}

// Implementation for SecurityManager, SessionAnalytics, etc.
impl SecurityManager {
    fn new() -> Self {
        Self {
            known_ips: RwLock::new(HashMap::new()),
            known_devices: RwLock::new(HashMap::new()),
            suspicious_ips: RwLock::new(Vec::new()),
            failed_attempts: RwLock::new(HashMap::new()),
        }
    }

    async fn assess_risk(
        &self,
        user_id: &str,
        ip_address: IpAddr,
        device_fingerprint: &str,
        user_agent: &str,
    ) -> SecurityRisk {
        let mut risk_score: f64 = 0.0;
        let mut risk_factors = Vec::new();

        // Check known IPs
        let known_ips = self.known_ips.read().await;
        if let Some(user_ips) = known_ips.get(user_id) {
            if !user_ips.contains(&ip_address) {
                risk_score += 0.3;
                risk_factors.push(RiskFactor::UnknownIpAddress);
            }
        } else {
            risk_score += 0.2;
            risk_factors.push(RiskFactor::UnknownIpAddress);
        }

        // Check known devices
        let known_devices = self.known_devices.read().await;
        if let Some(user_devices) = known_devices.get(user_id) {
            if !user_devices.contains(&device_fingerprint.to_string()) {
                risk_score += 0.2;
                risk_factors.push(RiskFactor::UnknownDevice);
            }
        } else {
            risk_score += 0.1;
            risk_factors.push(RiskFactor::UnknownDevice);
        }

        // Check suspicious IPs
        let suspicious_ips = self.suspicious_ips.read().await;
        if suspicious_ips.contains(&ip_address) {
            risk_score += 0.5;
            risk_factors.push(RiskFactor::SuspiciousUserAgent);
        }

        // Determine recommended action
        let recommended_action = if risk_score >= 0.8 {
            RecommendedAction::Block
        } else if risk_score >= 0.5 {
            RecommendedAction::RequireMfa
        } else if risk_score >= 0.3 {
            RecommendedAction::Monitor
        } else {
            RecommendedAction::Allow
        };

        SecurityRisk {
            risk_score: risk_score.min(1.0),
            risk_factors,
            recommended_action,
        }
    }

    async fn update_known_ip(&self, user_id: &str, ip_address: IpAddr) {
        let mut known_ips = self.known_ips.write().await;
        known_ips.entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(ip_address);
    }

    async fn update_known_device(&self, user_id: &str, device_fingerprint: String) {
        let mut known_devices = self.known_devices.write().await;
        known_devices.entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(device_fingerprint);
    }
}

impl SessionAnalytics {
    fn new() -> Self {
        Self {
            login_attempts: RwLock::new(HashMap::new()),
            security_events: RwLock::new(Vec::new()),
            session_metrics: RwLock::new(SessionMetrics::default()),
        }
    }

    async fn record_security_event(&self, event: SecurityEvent) {
        let mut events = self.security_events.write().await;
        events.push(event);
        
        // Keep only last 1000 events
        if events.len() > 1000 {
            let excess = events.len() - 1000;
            events.drain(0..excess);
        }
    }

    async fn update_session_metrics(&self, session: &Session) {
        let mut metrics = self.session_metrics.write().await;
        metrics.total_sessions += 1;
        
        if session.is_valid() {
            metrics.active_sessions += 1;
        }
        
        if session.flags.is_suspicious {
            metrics.suspicious_sessions += 1;
        }

        // Update sessions by security level using the consolidated structure
        let level_key = format!("{:?}", session.security_level);
        *metrics.sessions_by_security_level.entry(level_key).or_insert(0) += 1;

        // Add recent activity to the consolidated metrics
        let activity = SessionActivity {
            session_id: session.id.clone(),
            activity_type: ActivityType::SessionCreated,
            timestamp: Utc::now(),
            ip_address: session.created_ip,
            user_agent: session.user_agent.clone(),
            details: HashMap::new(),
        };
        
        metrics.recent_activities.push(activity);
        
        // Keep only last 100 activities
        if metrics.recent_activities.len() > 100 {
            metrics.recent_activities.remove(0);
        }
    }

    async fn get_metrics(&self) -> Result<SessionMetrics, AppError> {
        let metrics = self.session_metrics.read().await;
        Ok(metrics.clone())
    }

    /// Update metrics for session validation
    async fn update_validation_metrics(&self, session_id: &str, is_valid: bool) {
        if is_valid {
            // Add validation activity
            let mut metrics = self.session_metrics.write().await;
            let activity = SessionActivity {
                session_id: session_id.to_string(),
                activity_type: ActivityType::SecurityValidation,
                timestamp: Utc::now(),
                ip_address: "0.0.0.0".parse().unwrap(), // Placeholder - should be passed from caller
                user_agent: "Unknown".to_string(),
                details: HashMap::new(),
            };
            
            metrics.recent_activities.push(activity);
            
            // Keep only last 100 activities
            if metrics.recent_activities.len() > 100 {
                metrics.recent_activities.remove(0);
            }
        }
    }

    /// Update metrics for session revocation
    async fn update_revocation_metrics(&self, session_id: &str, reason: Option<&str>) {
        let mut metrics = self.session_metrics.write().await;
        
        // Decrease active sessions count
        if metrics.active_sessions > 0 {
            metrics.active_sessions -= 1;
        }
        
        // Add revocation activity
        let mut details = HashMap::new();
        if let Some(reason) = reason {
            details.insert("reason".to_string(), reason.to_string());
        }
        
        let activity = SessionActivity {
            session_id: session_id.to_string(),
            activity_type: ActivityType::SessionRevoked,
            timestamp: Utc::now(),
            ip_address: "0.0.0.0".parse().unwrap(), // Placeholder
            user_agent: "System".to_string(),
            details,
        };
        
        metrics.recent_activities.push(activity);
        
        // Keep only last 100 activities
        if metrics.recent_activities.len() > 100 {
            metrics.recent_activities.remove(0);
        }
    }
}