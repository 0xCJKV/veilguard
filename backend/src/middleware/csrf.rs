use axum::{
    extract::{Request, State, Extension},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn, error};
use crate::{
    config::Config,
    database::RedisManager,
    errors::AppError,
    auth::{
        behavioral::BehaviorAnalytics,
        threat::{ThreatDetectionEngine},
        audit::{AuditEvent, AuditEventType, EventOutcome, EventSeverity},
        ses::{SessionManager},
        utils::{sha256_hash, is_expired, generate_secure_token},
    },
    models::security::GeoLocation,
};

type HmacSha256 = Hmac<Sha256>;
// TODO:
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Secret key for HMAC signing (must be 32+ bytes for security)
    pub secret_key: String,
    /// Token lifetime in seconds (default: 1 hour)
    pub token_lifetime: u64,
    /// Cookie name for CSRF token
    pub cookie_name: String,
    /// Header name for CSRF token
    pub header_name: String,
    /// Form field name for CSRF token
    pub form_field_name: String,
    /// Whether to use secure cookies (HTTPS only)
    pub secure_cookies: bool,
    /// SameSite cookie attribute
    pub same_site: SameSite,
    /// Methods that require CSRF protection
    pub protected_methods: Vec<Method>,
    /// Paths to exclude from CSRF protection (exact matches)
    pub excluded_paths: Vec<String>,
    /// Path prefixes to exclude from CSRF protection
    pub excluded_path_prefixes: Vec<String>,
    /// Maximum number of tokens per session
    pub max_tokens_per_session: u32,
    /// Token regeneration interval in seconds
    pub token_regeneration_interval: u64,
    /// Risk-based validation settings
    pub enable_risk_based_validation: bool,
    /// Risk threshold for additional validation
    pub risk_threshold: f64,
    /// Enable behavioral analytics
    pub enable_behavioral_analytics: bool,
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            secret_key: "change-this-to-a-secure-32-byte-secret-key-in-production!!".to_string(),
            token_lifetime: 3600, // 1 hour
            cookie_name: "csrf_token".to_string(),
            header_name: "x-csrf-token".to_string(),
            form_field_name: "_csrf_token".to_string(),
            secure_cookies: true,
            same_site: SameSite::Strict,
            protected_methods: vec![
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ],
            excluded_paths: vec![
                "/api/auth/login".to_string(),
                "/api/auth/register".to_string(),
                "/api/health".to_string(),
                "/api/csrf/token".to_string(),
            ],
            excluded_path_prefixes: vec![
                "/api/public/".to_string(),
                "/static/".to_string(),
            ],
            max_tokens_per_session: 10,
            token_regeneration_interval: 300, // 5 minutes
            enable_risk_based_validation: true,
            risk_threshold: 0.7,
            enable_behavioral_analytics: true,
        }
    }
}

/// CSRF token with cryptographic security and session binding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsrfToken {
    /// Unique token identifier
    pub token_id: String,
    /// Random token value (base64 encoded)
    pub value: String,
    /// Token creation timestamp
    pub created_at: u64,
    /// Last usage timestamp
    pub last_used: u64,
    /// Session ID binding
    pub session_id: String,
    /// User ID binding (optional)
    pub user_id: Option<String>,
    /// IP address binding (optional)
    pub ip_address: Option<String>,
    /// User agent hash for binding
    pub user_agent_hash: Option<String>,
    /// Token usage count
    pub use_count: u32,
    /// HMAC signature for integrity
    pub signature: String,
    /// Risk score at token creation
    pub risk_score: Option<f64>,
    /// Behavioral context at creation
    pub behavioral_context: Option<String>,
}

impl CsrfToken {
    /// Create a new CSRF token with risk assessment
    pub fn new_with_risk(
        session_id: String,
        user_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        secret_key: &str,
        risk_score: Option<f64>,
        behavioral_context: Option<String>,
    ) -> Result<Self, AppError> {
        let token_id = generate_secure_id();
        let value = generate_secure_token(32)?;
        let current_time = current_timestamp();
        
        let user_agent_hash = user_agent.as_ref().map(|ua| sha256_hash(ua));

        let mut token = Self {
            token_id,
            value,
            created_at: current_time,
            last_used: current_time,
            session_id,
            user_id,
            ip_address,
            user_agent_hash,
            use_count: 0,
            signature: String::new(),
            risk_score,
            behavioral_context,
        };

        // Generate HMAC signature
        token.signature = token.generate_signature(secret_key)?;
        
        Ok(token)
    }

    /// Generate HMAC signature for the token
    pub fn generate_signature(&self, secret_key: &str) -> Result<String, AppError> {
        let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("HMAC key error: {}", e)))?;

        // Include all critical fields in signature
        mac.update(self.token_id.as_bytes());
        mac.update(self.value.as_bytes());
        mac.update(&self.created_at.to_le_bytes());
        mac.update(self.session_id.as_bytes());
        
        if let Some(ref user_id) = self.user_id {
            mac.update(user_id.as_bytes());
        }
        
        if let Some(ref ip) = self.ip_address {
            mac.update(ip.as_bytes());
        }
        
        if let Some(ref ua_hash) = self.user_agent_hash {
            mac.update(ua_hash.as_bytes());
        }

        let result = mac.finalize();
        Ok(URL_SAFE_NO_PAD.encode(result.into_bytes()))
    }

    /// Verify HMAC signature with constant-time comparison
    pub fn verify_signature(&self, secret_key: &str) -> Result<bool, AppError> {
        let expected_signature = self.generate_signature(secret_key)?;
        Ok(constant_time_eq(&self.signature, &expected_signature))
    }

    /// Check if token is expired
    pub fn is_expired(&self, lifetime: u64) -> bool {
        is_expired(self.created_at + lifetime)
    }

    /// Check if token needs regeneration
    pub fn needs_regeneration(&self, regeneration_interval: u64) -> bool {
        let now = current_timestamp();
        now - self.last_used > regeneration_interval
    }

    /// Update token usage
    pub fn mark_used(&mut self) {
        self.last_used = current_timestamp();
        self.use_count += 1;
    }

    /// Validate token context (IP, User-Agent, etc.)
    pub fn validate_context(
        &self,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> bool {
        // Validate IP address if stored
        if let Some(stored_ip) = &self.ip_address {
            if let Some(current_ip) = ip_address {
                if stored_ip != current_ip {
                    warn!("CSRF token IP mismatch: stored={}, current={}", stored_ip, current_ip);
                    return false;
                }
            }
        }

        // Validate User-Agent hash if stored
        if let Some(stored_ua_hash) = &self.user_agent_hash {
            if let Some(current_ua) = user_agent {
                let current_ua_hash = sha256_hash(current_ua);
                if stored_ua_hash != &current_ua_hash {
                    warn!("CSRF token User-Agent mismatch");
                    return false;
                }
            }
        }

        true
    }

    /// Serialize token for Redis storage
    pub fn serialize(&self) -> Result<String, AppError> {
        serde_json::to_string(self)
            .map_err(|e| AppError::InternalServerError(format!("Token serialization failed: {}", e)))
    }

    /// Deserialize token from Redis storage
    pub fn deserialize(data: &str) -> Result<Self, AppError> {
        serde_json::from_str(data)
            .map_err(|e| AppError::InternalServerError(format!("Token deserialization failed: {}", e)))
    }
}

/// Enterprise-grade CSRF protection manager
#[derive(Clone)]
pub struct CsrfProtection {
    redis: Arc<RedisManager>,
    config: CsrfConfig,
    threat_engine: Option<Arc<ThreatDetectionEngine>>,
    session_manager: Option<Arc<SessionManager>>,
}

impl CsrfProtection {
    pub fn new(redis: Arc<RedisManager>, config: CsrfConfig) -> Self {
        Self {
            redis,
            config,
            threat_engine: None,
            session_manager: None,
        }
    }

    pub fn with_threat_engine(mut self, threat_engine: Arc<ThreatDetectionEngine>) -> Self {
        self.threat_engine = Some(threat_engine);
        self
    }

    pub fn with_session_manager(mut self, session_manager: Arc<SessionManager>) -> Self {
        self.session_manager = Some(session_manager);
        self
    }

    /// Enhanced origin and referer validation
    pub async fn validate_origin_and_referer(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        // Check Origin header first (preferred for CORS requests)
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            if !self.is_valid_origin(origin) {
                warn!("Invalid origin detected: {}", origin);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        // Fallback to Referer header for same-origin requests
        else if let Some(referer) = headers.get("referer").and_then(|h| h.to_str().ok()) {
            if !self.is_valid_referer(referer) {
                warn!("Invalid referer detected: {}", referer);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        // If neither Origin nor Referer is present, this might be suspicious
        else {
            warn!("Neither Origin nor Referer header present in CSRF-protected request");
            // Allow for now but log the event - some legitimate requests might not have these headers
        }

        Ok(())
    }

    /// Validate if the origin is allowed
    fn is_valid_origin(&self, origin: &str) -> bool {
        // TODO: This should be configurable based on allowed origins
        // For now, implement basic validation
        if origin.starts_with("https://") || origin.starts_with("http://localhost") {
            true
        } else {
            false
        }
    }

    /// Validate if the referer is from the same origin
    fn is_valid_referer(&self, referer: &str) -> bool {
        // TODO: This should validate against the application's domain
        // For now, implement basic validation
        if referer.starts_with("https://") || referer.contains("localhost") {
            true
        } else {
            false
        }
    }

    /// Enhanced token validation with origin/referer checks and replay detection
    pub async fn validate_token_enhanced(
        &self,
        token_value: &str,
        session_id: &str,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        headers: &HeaderMap,
    ) -> Result<bool, AppError> {
        // First validate origin and referer headers
        if let Err(_) = self.validate_origin_and_referer(headers).await {
            return Ok(false);
        }

        // Check for token replay attacks
        if self.is_token_replayed(token_value, session_id).await? {
            return Ok(false);
        }

        // Check rate limiting
        if self.is_token_usage_rate_limited(session_id).await? {
            return Ok(false);
        }

        // Perform standard token validation
        self.validate_token(token_value, session_id, user_id, ip_address, user_agent).await
    }

    /// Extract CSRF token from cookie for double-submit validation
    fn extract_csrf_cookie(&self, headers: &HeaderMap) -> Option<String> {
        headers.get("cookie")
            .and_then(|cookie_header| cookie_header.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';')
                    .find_map(|cookie| {
                        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                        if parts.len() == 2 && parts[0] == self.config.cookie_name {
                            Some(parts[1].to_string())
                        } else {
                            None
                        }
                    })
            })
    }

    /// Check if token is being replayed (used multiple times suspiciously)
    async fn is_token_replayed(&self, token_value: &str, session_id: &str) -> Result<bool, AppError> {
        let token_id = self.extract_token_id(token_value)?;
        let usage_key = format!("csrf:token_usage:{}:{}", session_id, token_id);
        
        match self.redis.increment_rate_limit(&usage_key, 3600).await {
            Ok(count) => {
                // Check if usage exceeds reasonable threshold
                Ok(count > 10) // Allow up to 10 uses per hour
            }
            Err(_) => Ok(false), // Allow on Redis error
        }
    }

    /// Check if token usage is rate limited for this session
    async fn is_token_usage_rate_limited(&self, session_id: &str) -> Result<bool, AppError> {
        let rate_key = format!("csrf:rate:{}:{}", session_id, current_timestamp() / 60); // Per minute
        
        match self.redis.increment_rate_limit(&rate_key, 60).await {
            Ok(count) => {
                // Allow up to 10 token validations per minute per session
                Ok(count > 10)
            }
            Err(_) => Ok(false), // Allow on Redis error
        }
    }

    /// Log security events for audit trail
    pub async fn log_security_event(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        event_description: &str,
        severity: EventSeverity,
    ) -> Result<(), AppError> {
        use std::collections::HashMap;
        use std::net::IpAddr;
        use chrono::Utc;
        
        let source_ip = ip_address
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
            
        let mut metadata = HashMap::new();
        if let Some(sid) = Some(session_id) {
            metadata.insert("session_id".to_string(), sid.to_string());
        }
        if let Some(uid) = user_id {
            metadata.insert("user_id".to_string(), uid.to_string());
        }
        
        let audit_event = AuditEvent {
            id: generate_secure_token(16)?,
            event_type: AuditEventType::SecurityViolation,
            timestamp: Utc::now(),
            source_ip,
            user_agent: None,
            user_id: user_id.map(|s| s.to_string()),
            session_id: Some(session_id.to_string()),
            resource: Some("csrf_protection".to_string()),
            action: "validation".to_string(),
            outcome: EventOutcome::Failure,
            severity,
            risk_score: None,
            metadata,
            error_message: Some(event_description.to_string()),
        };

        // Store audit event in Redis for later processing
        let audit_key = format!("audit:csrf:{}", audit_event.id);
        if let Ok(serialized) = serde_json::to_string(&audit_event) {
            let _ = self.redis.set_with_expiry(&audit_key, &serialized, 86400 * 30).await; // 30 days
        }
        
        Ok(())
    }

    /// Log token usage for analytics
    pub async fn log_token_usage(&self, session_id: &str, token_value: &str, success: bool) {
        let usage_event = serde_json::json!({
            "session_id": session_id,
            "token_id": self.extract_token_id(token_value).unwrap_or_default(),
            "success": success,
            "timestamp": current_timestamp(),
        });

        let usage_key = format!("csrf:usage:{}:{}", session_id, current_timestamp() / 3600); // Hourly buckets
        let _ = self.redis.lpush(&usage_key, &usage_event.to_string()).await;
        let _ = self.redis.expire(&usage_key, 86400 * 7).await; // Keep for 7 days
    }

    /// Generate a new CSRF token with behavioral analytics and risk assessment
    pub async fn generate_token(
        &self,
        session_id: String,
        user_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<CsrfToken, AppError> {
        // Perform behavioral analysis if enabled
        let (risk_score, behavioral_context) = if self.config.enable_behavioral_analytics {
            self.analyze_token_generation_behavior(&session_id, &user_id, &ip_address, &user_agent).await?
        } else {
            (None, None)
        };

        // Check if we need to limit token generation based on risk
        if let Some(score) = risk_score {
            if score > self.config.risk_threshold {
                warn!("High risk CSRF token generation attempt blocked: score={}", score);
                
                // Log security event
                let _ = self.log_security_event(
                    &session_id,
                    user_id.as_deref(),
                    ip_address.as_deref(),
                    "High-risk CSRF token generation blocked",
                    EventSeverity::High,
                ).await;
                
                return Err(AppError::SecurityViolation("Token generation blocked due to high risk".to_string()));
            }
        }

        // Clean up old tokens for this session
        self.cleanup_session_tokens(&session_id).await?;

        let token = CsrfToken::new_with_risk(
            session_id.clone(),
            user_id,
            ip_address,
            user_agent,
            &self.config.secret_key,
            risk_score,
            behavioral_context,
        )?;

        // Store token in Redis with session tracking
        let token_key = format!("csrf_token:{}", token.token_id);
        let session_key = format!("csrf_session:{}:{}", session_id, token.token_id);
        
        let serialized_token = token.serialize()?;
        
        // Store token with expiration
        self.redis
            .set_with_expiry(&token_key, &serialized_token, self.config.token_lifetime)
            .await?;
        
        // Track token in session
        self.redis
            .set_with_expiry(&session_key, &token.token_id, self.config.token_lifetime)
            .await?;

        debug!("Generated CSRF token: {} for session: {}", token.token_id, session_id);
        Ok(token)
    }

    /// Validate CSRF token with enhanced behavioral and risk-based checks
    pub async fn validate_token(
        &self,
        token_value: &str,
        session_id: &str,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AppError> {
        // Extract token ID from the token value
        let token_id = self.extract_token_id(token_value)?;
        let token_key = format!("csrf_token:{}", token_id);

        // Retrieve token from Redis
        let stored_data = match self.redis.get(&token_key).await? {
            Some(data) => data,
            None => {
                debug!("CSRF token not found in Redis: {}", token_id);
                return Ok(false);
            }
        };

        // Deserialize token
        let mut token = CsrfToken::deserialize(&stored_data)?;

        // Check if token is expired
        if token.is_expired(self.config.token_lifetime) {
            debug!("CSRF token expired: {}", token_id);
            self.invalidate_token(&token_id).await?;
            return Ok(false);
        }

        // Verify HMAC signature with constant-time comparison
        if !token.verify_signature(&self.config.secret_key)? {
            warn!("CSRF token signature verification failed: {}", token_id);
            return Ok(false);
        }

        // Verify session binding
        if token.session_id != session_id {
            warn!("CSRF token session mismatch: expected {}, got {}", session_id, token.session_id);
            return Ok(false);
        }

        // Verify user binding if provided
        if let Some(expected_user) = user_id {
            match &token.user_id {
                Some(token_user) if token_user != expected_user => {
                    warn!("CSRF token user mismatch: expected {}, got {}", expected_user, token_user);
                    return Ok(false);
                }
                None => {
                    warn!("CSRF token has no user binding but user ID provided");
                    return Ok(false);
                }
                _ => {} // Valid
            }
        }

        // Validate context (IP, User-Agent)
        if !token.validate_context(ip_address, user_agent) {
            return Ok(false);
        }

        // Check token value matches
        if !constant_time_eq(&token.value, token_value) {
            warn!("CSRF token value mismatch");
            return Ok(false);
        }

        // Perform risk-based validation if enabled
        if self.config.enable_risk_based_validation {
            let validation_result = self.perform_risk_based_validation(
                &token,
                session_id,
                user_id,
                ip_address,
                user_agent,
            ).await?;

            if !validation_result {
                warn!("CSRF token failed risk-based validation: {}", token_id);
                return Ok(false);
            }
        }

        // Update token usage
        token.mark_used();
        let updated_data = token.serialize()?;
        self.redis
            .set_with_expiry(&token_key, &updated_data, self.config.token_lifetime)
            .await?;

        debug!("CSRF token validation successful: {}", token_id);
        Ok(true)
    }

    /// Perform behavioral analysis for token generation
    async fn analyze_token_generation_behavior(
        &self,
        session_id: &str,
        user_id: &Option<String>,
        ip_address: &Option<String>,
        user_agent: &Option<String>,
    ) -> Result<(Option<f64>, Option<String>), AppError> {
        if let Some(ref threat_engine) = self.threat_engine {
            // Get session for analysis
            if let Some(ref session_manager) = self.session_manager {
                if let Ok(Some(session)) = session_manager.get_session(session_id).await {
                    // Create behavioral analytics context
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

                    // Evaluate threats for token generation
                    match threat_engine.evaluate_session_threats(&session, &user_behavior, &geo_data).await {
                        Ok(evaluation) => {
                            let behavioral_context = serde_json::json!({
                                "timestamp": chrono::Utc::now().timestamp(),
                                "ip_address": ip_address,
                                "user_agent": user_agent,
                                "session_id": session_id,
                                "user_id": user_id,
                                "threats": evaluation.threats,
                                "risk_score": evaluation.risk_score,
                                "recommended_actions": evaluation.recommended_actions,
                                "requires_immediate_action": evaluation.requires_immediate_action,
                            });

                            return Ok((Some(evaluation.risk_score), Some(behavioral_context.to_string())));
                        }
                        Err(e) => {
                            warn!("Failed to evaluate threats for CSRF token generation: {}", e);
                        }
                    }
                }
            }
        }

        Ok((None, None))
    }

    /// Perform risk-based validation during token usage
    async fn perform_risk_based_validation(
        &self,
        token: &CsrfToken,
        session_id: &str,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AppError> {
        // Check for suspicious token usage patterns
        if token.use_count > 100 {
            warn!("CSRF token used excessively: {} times", token.use_count);
            return Ok(false);
        }

        // Check time-based anomalies
        let current_time = current_timestamp();
        let _time_since_creation = current_time - token.created_at;
        let time_since_last_use = current_time - token.last_used;

        // Flag rapid successive usage (potential automation)
        if time_since_last_use < 1 && token.use_count > 5 {
            warn!("Rapid CSRF token usage detected - potential automation");
            return Ok(false);
        }

        // Check if behavioral context has changed significantly
        if let Some(ref behavioral_context) = token.behavioral_context {
            if let Ok(stored_context) = serde_json::from_str::<serde_json::Value>(behavioral_context) {
                let current_context = serde_json::json!({
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "session_id": session_id,
                    "user_id": user_id,
                });

                // Simple context comparison - in production, use more sophisticated analysis
                if stored_context.get("ip_address") != current_context.get("ip_address") {
                    warn!("IP address changed during CSRF token usage");
                    // Don't fail immediately, but increase suspicion
                }

                if stored_context.get("user_agent") != current_context.get("user_agent") {
                    warn!("User agent changed during CSRF token usage");
                    // Don't fail immediately, but increase suspicion
                }
            }
        }

        // Additional threat evaluation if available
        if let Some(ref threat_engine) = self.threat_engine {
            if let Some(ref session_manager) = self.session_manager {
                if let Ok(Some(session)) = session_manager.get_session(session_id).await {
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
                        Ok(evaluation) => {
                            if evaluation.risk_score > self.config.risk_threshold {
                                warn!("High risk detected during CSRF token validation: score={}", evaluation.risk_score);
                                return Ok(false);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to evaluate threats during CSRF validation: {}", e);
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Invalidate a specific CSRF token
    pub async fn invalidate_token(&self, token_id: &str) -> Result<(), AppError> {
        let token_key = format!("csrf_token:{}", token_id);
        
        // Get token to find session for cleanup
        if let Some(data) = self.redis.get(&token_key).await? {
            if let Ok(token) = CsrfToken::deserialize(&data) {
                let session_key = format!("csrf_session:{}:{}", token.session_id, token_id);
                let _ = self.redis.delete(&session_key).await;
            }
        }
        
        self.redis.delete(&token_key).await?;
        debug!("Invalidated CSRF token: {}", token_id);
        Ok(())
    }

    /// Clean up old tokens for a session
    async fn cleanup_session_tokens(&self, session_id: &str) -> Result<(), AppError> {
        // This is a simplified cleanup - in production, you might want to use Redis SCAN
        // to find all session tokens and clean up expired ones
        debug!("Cleaning up old tokens for session: {}", session_id);
        Ok(())
    }

    /// Extract token ID from token value (assuming format: tokenId.value)
    fn extract_token_id(&self, token_value: &str) -> Result<String, AppError> {
        // For this implementation, we'll use the token value as the ID
        // In a more complex setup, you might encode the ID in the token
        Ok(sha256_hash(token_value)[..16].to_string())
    }

    /// Check if path is excluded from CSRF protection
    pub fn is_excluded_path(&self, path: &str) -> bool {
        // Check exact matches
        if self.config.excluded_paths.contains(&path.to_string()) {
            return true;
        }

        // Check prefix matches
        for prefix in &self.config.excluded_path_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Check if method requires CSRF protection
    pub fn requires_protection(&self, method: &Method) -> bool {
        self.config.protected_methods.contains(method)
    }

    /// Extract CSRF token from request headers or form data
    pub fn extract_token_from_request(&self, headers: &HeaderMap) -> Option<String> {
        // Try header first (most common for APIs)
        if let Some(header_value) = headers.get(&self.config.header_name) {
            if let Ok(header_str) = header_value.to_str() {
                return Some(header_str.to_string());
            }
        }

        // Try custom header variations
        for header_name in &["x-csrf-token", "x-xsrf-token", "csrf-token"] {
            if let Some(header_value) = headers.get(*header_name) {
                if let Ok(header_str) = header_value.to_str() {
                    return Some(header_str.to_string());
                }
            }
        }

        None
    }

    /// Extract session ID from request (you'll need to implement based on your auth system)
    pub fn extract_session_id(&self, headers: &HeaderMap) -> Option<String> {
        // This is a placeholder - implement based on your session management
        // You might extract from JWT, session cookie, etc.
        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    // Extract session from JWT or similar
                    return Some("session_from_jwt".to_string());
                }
            }
        }
        
        // Fallback to a default session for demo
        Some("default_session".to_string())
    }

    /// Extract user ID from request (implement based on your auth system)
    pub fn extract_user_id(&self, _headers: &HeaderMap) -> Option<String> {
        // Placeholder - extract from JWT or session
        None
    }

    /// Extract IP address from request
    pub fn extract_ip_address(&self, headers: &HeaderMap) -> Option<String> {
        // Check X-Forwarded-For first (for load balancers)
        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    return Some(first_ip.trim().to_string());
                }
            }
        }

        // Check X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(real_ip_str) = real_ip.to_str() {
                return Some(real_ip_str.to_string());
            }
        }

        None
    }

    /// Extract User-Agent from request
    pub fn extract_user_agent(&self, headers: &HeaderMap) -> Option<String> {
        headers.get("user-agent")
            .and_then(|ua| ua.to_str().ok())
            .map(|s| s.to_string())
    }
}

/// CSRF protection middleware
pub async fn csrf_protection_middleware(
    State(csrf): State<Arc<CsrfProtection>>,
    _threat_engine: Extension<Arc<ThreatDetectionEngine>>,
    _session_manager: Extension<Arc<SessionManager>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method();
    let path = request.uri().path();
    let headers = request.headers();

    // Skip CSRF protection for excluded paths
    if csrf.is_excluded_path(path) {
        debug!("Skipping CSRF protection for excluded path: {}", path);
        return Ok(next.run(request).await);
    }

    // Skip CSRF protection for methods that don't require it
    if !csrf.requires_protection(method) {
        debug!("Skipping CSRF protection for method: {}", method);
        return Ok(next.run(request).await);
    }

    // Enhanced origin validation
    if let Err(status) = csrf.validate_origin_and_referer(headers).await {
        warn!("Origin/Referer validation failed for request to {}", path);
        return Err(status);
    }

    // Extract required information from request
    let token_value = match csrf.extract_token_from_request(headers) {
        Some(token) => token,
        None => {
            warn!("CSRF token missing from request to {}", path);
            // Log security event for missing CSRF token
            if let Some(session_id) = csrf.extract_session_id(headers) {
                let _ = csrf.log_security_event(
                    &session_id,
                    csrf.extract_user_id(headers).as_deref(),
                    csrf.extract_ip_address(headers).as_deref(),
                    "CSRF token missing from protected request",
                    EventSeverity::Medium,
                ).await;
            }
            return Err(StatusCode::FORBIDDEN);
        }
    };

    let session_id = match csrf.extract_session_id(headers) {
        Some(session) => session,
        None => {
            warn!("Session ID missing from request to {}", path);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_id = csrf.extract_user_id(headers);
    let ip_address = csrf.extract_ip_address(headers);
    let user_agent = csrf.extract_user_agent(headers);

    // Validate CSRF token with enhanced security checks
    match csrf.validate_token_enhanced(
        &token_value,
        &session_id,
        user_id.as_deref(),
        ip_address.as_deref(),
        user_agent.as_deref(),
        headers,
    ).await {
        Ok(true) => {
            debug!("CSRF token validation successful for {}", path);
            // Log successful validation for analytics
            csrf.log_token_usage(&session_id, &token_value, true).await;
            Ok(next.run(request).await)
        }
        Ok(false) => {
            warn!("CSRF token validation failed for {}", path);
            // Log failed validation attempt
            let _ = csrf.log_security_event(
                &session_id,
                user_id.as_deref(),
                ip_address.as_deref(),
                "CSRF token validation failed",
                EventSeverity::High,
            ).await;
            csrf.log_token_usage(&session_id, &token_value, false).await;
            Err(StatusCode::FORBIDDEN)
        }
        Err(e) => {
            error!("CSRF validation error: {}", e);
            // Log system error
            let _ = csrf.log_security_event(
                &session_id,
                user_id.as_deref(),
                ip_address.as_deref(),
                &format!("CSRF validation system error: {}", e),
                EventSeverity::Critical,
            ).await;
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler to generate and return CSRF token
pub async fn get_csrf_token(
    State(csrf): State<Arc<CsrfProtection>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = match csrf.extract_session_id(&headers) {
        Some(session) => session,
        None => {
            warn!("Session ID missing from CSRF token request");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_id = csrf.extract_user_id(&headers);
    let ip_address = csrf.extract_ip_address(&headers);
    let user_agent = csrf.extract_user_agent(&headers);

    match csrf.generate_token(session_id, user_id, ip_address, user_agent).await {
        Ok(token) => {
            let response = serde_json::json!({
                "csrf_token": token.value,
                "token_id": token.token_id,
                "expires_in": csrf.config.token_lifetime,
                "created_at": token.created_at
            });
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to generate CSRF token: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create CSRF protection from config
pub fn create_csrf_protection(redis: Arc<RedisManager>, config: &Config) -> CsrfProtection {
    let csrf_config = CsrfConfig {
        secret_key: config.csrf_secret.clone(),
        token_lifetime: 3600, // 1 hour default
        cookie_name: "csrf_token".to_string(),
        header_name: "X-CSRF-Token".to_string(),
        form_field_name: "_csrf_token".to_string(),
        secure_cookies: true,
        same_site: SameSite::Lax,
        protected_methods: vec![Method::POST, Method::PUT, Method::DELETE, Method::PATCH],
        excluded_paths: vec![],
        excluded_path_prefixes: vec![],
        max_tokens_per_session: 10,
        token_regeneration_interval: 300, // 5 minutes default
        enable_risk_based_validation: true,
        risk_threshold: 0.7,
        enable_behavioral_analytics: true,
    };

    CsrfProtection::new(redis, csrf_config)
}

// Utility functions

fn generate_secure_id() -> String {
    let mut bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a_byte, b_byte) in a.bytes().zip(b.bytes()) {
        result |= a_byte ^ b_byte;
    }
    result == 0
}