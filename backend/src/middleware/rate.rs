use axum::{
    extract::{Request, Extension},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
    Json,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn, error, info};
use crate::{
    auth::{
        threat::ThreatDetectionEngine,
        ses::SessionManager,
        audit::{AuditManager, AuditEvent, AuditEventType, EventOutcome, EventSeverity},
        binding::{SessionBindingManager, DeviceFingerprint},
        behavioral::BehaviorAnalytics,
        utils::{extract_ip_from_headers, get_geolocation_data},
    },
    models::security::{SecurityLevel, SecurityEventType, ThreatType, GeoLocation},
    config::Config,
    database::RedisManager,
    errors::AppError,
};

/// Rate limiting algorithms
#[derive(Debug, Clone)]
pub enum RateLimitAlgorithm {
    /// Fixed window counter
    FixedWindow,
    /// Sliding window log
    SlidingWindow,
    /// Token bucket
    TokenBucket,
    /// Adaptive rate limiting based on user behavior
    Adaptive,
}

/// Rate limit configuration with behavioral analytics
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_seconds: u64,
    pub algorithm: RateLimitAlgorithm,
    pub burst_allowance: Option<u32>,
    pub whitelist_ips: Vec<IpAddr>,
    pub blacklist_ips: Vec<IpAddr>,
    /// Behavioral analytics settings
    pub enable_behavioral_analytics: bool,
    /// Dynamic limits based on security level
    pub requests_per_minute_by_security_level: HashMap<SecurityLevel, u32>,
    /// Penalty multiplier for suspicious users
    pub suspicious_user_penalty: f32,
    /// Bonus multiplier for trusted users
    pub trusted_user_bonus: f32,
    /// Risk threshold for applying penalties
    pub risk_penalty_threshold: f64,
    /// Risk threshold for applying bonuses
    pub risk_bonus_threshold: f64,
    /// Maximum penalty factor
    pub max_penalty_factor: f32,
    /// Maximum bonus factor
    pub max_bonus_factor: f32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut security_level_limits = HashMap::new();
        security_level_limits.insert(SecurityLevel::Low, 200);
        security_level_limits.insert(SecurityLevel::Medium, 100);
        security_level_limits.insert(SecurityLevel::High, 50);
        security_level_limits.insert(SecurityLevel::Critical, 20);

        Self {
            requests_per_window: 100,
            window_seconds: 60,
            algorithm: RateLimitAlgorithm::Adaptive,
            burst_allowance: Some(20),
            whitelist_ips: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            blacklist_ips: vec![],
            enable_behavioral_analytics: true,
            requests_per_minute_by_security_level: security_level_limits,
            suspicious_user_penalty: 0.5,
            trusted_user_bonus: 2.0,
            risk_penalty_threshold: 0.7,
            risk_bonus_threshold: 0.2,
            max_penalty_factor: 0.1,
            max_bonus_factor: 5.0,
        }
    }
}

/// Enhanced rate limiter with behavioral analytics
#[derive(Clone)]
pub struct RateLimiter {
    redis: Arc<RedisManager>,
    config: RateLimitConfig,
    threat_engine: Option<Arc<ThreatDetectionEngine>>,
    session_manager: Option<Arc<SessionManager>>,
    audit_manager: Option<Arc<AuditManager>>,
    binding_manager: Option<Arc<SessionBindingManager>>,
}

impl RateLimiter {
    pub fn new(redis: Arc<RedisManager>, config: RateLimitConfig) -> Self {
        Self { 
            redis, 
            config,
            threat_engine: None,
            session_manager: None,
            audit_manager: None,
            binding_manager: None,
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

    pub fn with_audit_manager(mut self, audit_manager: Arc<AuditManager>) -> Self {
        self.audit_manager = Some(audit_manager);
        self
    }

    pub fn with_binding_manager(mut self, binding_manager: Arc<SessionBindingManager>) -> Self {
        self.binding_manager = Some(binding_manager);
        self
    }

    /// Extract client identifier with enhanced device fingerprinting
    fn extract_client_id(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> String {
        // Priority order for client identification:
        // 1. X-Forwarded-For (for load balancers/proxies)
        // 2. X-Real-IP (for reverse proxies)
        // 3. Direct IP address
        // 4. Device fingerprint + IP combination for enhanced uniqueness

        let actual_ip = if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                // Take the first IP in the chain (original client)
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    let clean_ip = first_ip.trim();
                    clean_ip.parse::<IpAddr>().ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(real_ip_str) = real_ip.to_str() {
                real_ip_str.parse::<IpAddr>().ok()
            } else {
                None
            }
        } else {
            ip
        };

        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");
            
        // Create comprehensive device fingerprint
        let device_fingerprint = DeviceFingerprint::comprehensive(
            user_agent.to_string(),
            headers.get("screen-resolution").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            headers.get("timezone").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            headers.get("accept-language")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').map(|lang| lang.trim().to_string()).collect())
                .unwrap_or_else(Vec::new),
            headers.get("sec-ch-ua-platform").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            headers.get("hardware-concurrency")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            headers.get("device-memory")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            headers.get("webgl-renderer").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            headers.get("canvas-fingerprint").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            headers.get("audio-fingerprint").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
        );
        
        // Generate a more sophisticated client ID using device fingerprint hash
        let fingerprint_hash = self.hash_device_fingerprint(&device_fingerprint);
        
        if let Some(ip_addr) = actual_ip {
            format!("{}:{}", ip_addr, fingerprint_hash)
        } else {
            format!("ua:{}", fingerprint_hash)
        }
    }
    
    /// Hash device fingerprint for client identification
    fn hash_device_fingerprint(&self, fingerprint: &DeviceFingerprint) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.user_agent.as_bytes());
        
        if let Some(ref resolution) = fingerprint.screen_resolution {
            hasher.update(resolution.as_bytes());
        }
        
        if let Some(ref timezone) = fingerprint.timezone {
            hasher.update(timezone.as_bytes());
        }
        
        for lang in &fingerprint.languages {
            hasher.update(lang.as_bytes());
        }
        
        if let Some(ref platform) = fingerprint.platform {
            hasher.update(platform.as_bytes());
        }
        
        if let Some(concurrency) = fingerprint.hardware_concurrency {
            hasher.update(concurrency.to_string().as_bytes());
        }
        
        if let Some(memory) = fingerprint.device_memory {
            hasher.update(memory.to_string().as_bytes());
        }
        
        if let Some(ref webgl) = fingerprint.webgl_renderer {
            hasher.update(webgl.as_bytes());
        }
        
        if let Some(ref canvas) = fingerprint.canvas_fingerprint {
            hasher.update(canvas.as_bytes());
        }
        
        if let Some(ref audio) = fingerprint.audio_fingerprint {
            hasher.update(audio.as_bytes());
        }
        
        let result = hasher.finalize();
        format!("{:x}", &result[..8].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    /// Extract session information for behavioral analysis with binding validation
    async fn extract_session_context(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> Option<(String, String)> {
        if let Some(ref session_manager) = self.session_manager {
            // Try to extract session ID from various sources
            if let Some(session_cookie) = headers.get("cookie") {
                if let Ok(cookie_str) = session_cookie.to_str() {
                    // Parse cookies to find session ID
                    for cookie in cookie_str.split(';') {
                        let cookie = cookie.trim();
                        if cookie.starts_with("session_id=") {
                            let session_id = cookie.strip_prefix("session_id=").unwrap_or("");
                            if let Ok(Some(session)) = session_manager.get_session(session_id).await {
                                // Validate session binding if binding manager is available
                                if let Some(ref binding_manager) = self.binding_manager {
                                    // Extract device fingerprint from headers
                                    let user_agent = headers.get("user-agent")
                                        .and_then(|h| h.to_str().ok())
                                        .unwrap_or("");
                                    
                                    // Validate session binding
                                    let device_fingerprint = DeviceFingerprint::from_user_agent(user_agent.to_string());
                                    match binding_manager.validate_binding(session_id, ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))), &device_fingerprint, None) {
                                        Ok(validation_result) => {
                                            let is_valid = validation_result.is_valid;
                                            if !is_valid {
                                                warn!("Session binding validation failed for session {}", session_id);
                                                // Log security violation
                                                if let Some(ref audit_manager) = self.audit_manager {
                                                    let _ = audit_manager.log_security_violation(
                                                        Some(&session.user_id),
                                                        Some(session_id),
                                                        ip.unwrap_or("127.0.0.1".parse().unwrap()),
                                                        "session_binding_mismatch",
                                                        0.8,
                                                    ).await;
                                                }
                                                return None; // Reject invalid session
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to validate session binding: {}", e);
                                        }
                                    }
                                }
                                
                                return Some((session_id.to_string(), session.user_id));
                            }
                        }
                    }
                }
            }

        }
        None
    }

    /// Calculate dynamic rate limit based on user behavior and risk
    async fn calculate_dynamic_limit(
        &self,
        base_limit: u32,
        session_id: Option<&str>,
        user_id: Option<&str>,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<u32, AppError> {
        if !self.config.enable_behavioral_analytics {
            return Ok(base_limit);
        }

        let mut dynamic_limit = base_limit as f32;

        // Get session and user behavior data
        if let (Some(session_id), Some(user_id)) = (session_id, user_id) {
            if let Some(ref session_manager) = self.session_manager {
                if let Ok(Some(session)) = session_manager.get_session(session_id).await {
                    // Apply security level based limits
                    if let Some(&level_limit) = self.config.requests_per_minute_by_security_level.get(&session.security_level) {
                        dynamic_limit = dynamic_limit.min(level_limit as f32);
                    }

                    // Load behavioral analytics data (simplified approach)
                    let mut user_behavior = BehaviorAnalytics::new();
                    
                    // Get real geolocation data from IP first
                    let geo_data = match self.get_geolocation_data(ip).await {
                        Ok(geo) => geo,
                        Err(e) => {
                            debug!("Failed to get geolocation for IP {:?}: {}", ip, e);
                            GeoLocation {
                                current_location: (0.0, 0.0),
                                previous_location: None,
                                country_code: "US".to_string(),
                                city: Some("Unknown".to_string()),
                                timezone: "UTC".to_string(),
                                isp: None,
                                is_vpn_proxy: false,
                            }
                        }
                    };
                    
                    // Initialize with current session data and geolocation
                    user_behavior.update_with_session(&session, &geo_data);

                    // Perform threat evaluation if available
                    if let Some(ref threat_engine) = self.threat_engine {
                        match threat_engine.evaluate_session_threats(&session, &user_behavior, &geo_data).await {
                            Ok(evaluation) => {
                                // Apply risk-based adjustments
                                if evaluation.risk_score >= self.config.risk_penalty_threshold {
                                    let penalty_factor = (evaluation.risk_score as f32 * self.config.suspicious_user_penalty)
                                        .max(self.config.max_penalty_factor);
                                    dynamic_limit *= penalty_factor;
                                    
                                    info!("Applied rate limit penalty for high-risk user {}: factor={:.2}, new_limit={:.0}", 
                                          user_id, penalty_factor, dynamic_limit);
                                    
                                    // Log rate limit penalty event
                                    if let Some(ref audit_manager) = self.audit_manager {
                                        let event = AuditEvent::new(
                                            AuditEventType::SecurityViolation,
                                            ip.unwrap_or("127.0.0.1".parse().unwrap()),
                                            user_agent.map(|s| s.to_string()),
                                            "rate_limit_penalty_applied".to_string(),
                                        )
                                        .with_user(user_id.to_string())
                                        .with_session(session_id.to_string())
                                        .with_outcome(EventOutcome::Warning)
                                        .with_severity(EventSeverity::Medium)
                                        .with_risk_score(evaluation.risk_score)
                                        .with_metadata("penalty_factor".to_string(), penalty_factor.to_string())
                                        .with_metadata("original_limit".to_string(), base_limit.to_string())
                                        .with_metadata("new_limit".to_string(), dynamic_limit.to_string());
                                        
                                        let _ = audit_manager.log_event(&event).await;
                                    }
                                } else if evaluation.risk_score <= self.config.risk_bonus_threshold {
                                    let bonus_factor = (1.0 + (1.0 - evaluation.risk_score as f32) * (self.config.trusted_user_bonus - 1.0))
                                        .min(self.config.max_bonus_factor);
                                    dynamic_limit *= bonus_factor;
                                    
                                    debug!("Applied rate limit bonus for trusted user {}: factor={:.2}, new_limit={:.0}", 
                                           user_id, bonus_factor, dynamic_limit);
                                }

                                // Check for specific threat indicators and apply targeted penalties
                                for threat in &evaluation.threats {
                                    let (threat_str, penalty_factor) = match threat {
                                        ThreatType::RapidSessionCreation => ("rapid_requests", 0.2),
                                        ThreatType::BehavioralAnomaly => ("automated_behavior", 0.3),
                                        ThreatType::AnomalousLocation => ("suspicious_location", 0.7),
                                        ThreatType::SuspiciousDevice => ("device_fingerprint_mismatch", 0.8),
                                        _ => ("other_threat", 0.9),
                                    };
                                    
                                    dynamic_limit *= penalty_factor;
                                    warn!("Detected {} for user {}, applying rate limit penalty: {:.1}%", 
                                          threat_str, user_id, (1.0 - penalty_factor) * 100.0);
                                    
                                    // Log specific threat detection
                                    if let Some(ref audit_manager) = self.audit_manager {
                                        let event = AuditEvent::new(
                                            AuditEventType::SecurityViolation,
                                            ip.unwrap_or("127.0.0.1".parse().unwrap()),
                                            user_agent.map(|s| s.to_string()),
                                            format!("threat_detected_{}", threat_str),
                                        )
                                        .with_user(user_id.to_string())
                                        .with_session(session_id.to_string())
                                        .with_outcome(EventOutcome::Warning)
                                        .with_severity(EventSeverity::High)
                                        .with_risk_score(evaluation.risk_score)
                                        .with_metadata("threat_type".to_string(), threat_str.to_string())
                                        .with_metadata("penalty_factor".to_string(), penalty_factor.to_string());
                                        
                                        let _ = audit_manager.log_event(&event).await;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to evaluate threats for rate limiting: {}", e);
                            }
                        }
                    }

                    // Enhanced behavioral risk assessment
                    let behavioral_risk = user_behavior.calculate_behavioral_risk(&session, &geo_data);
                    if behavioral_risk > 0.8 {
                        dynamic_limit *= 0.4; // Severe penalty for high behavioral risk
                        warn!("Applied severe rate limit penalty for high behavioral risk: user={}, risk={:.2}", 
                              user_id, behavioral_risk);
                    } else if behavioral_risk > 0.6 {
                        dynamic_limit *= 0.7; // Moderate penalty
                        info!("Applied moderate rate limit penalty for elevated behavioral risk: user={}, risk={:.2}", 
                              user_id, behavioral_risk);
                    }

                    // Check recent security events with more granular analysis
                    let recent_violations = session_manager.get_recent_security_events(user_id, 300).await // Last 5 minutes
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|event| matches!(event.event_type, SecurityEventType::SecurityViolation))
                        .count();

                    if recent_violations > 0 {
                        let violation_penalty = 0.5_f32.powi(recent_violations as i32);
                        dynamic_limit *= violation_penalty;
                        warn!("Applied rate limit penalty for recent security violations: user={}, violations={}, penalty={:.2}", 
                              user_id, recent_violations, violation_penalty);
                        
                        // Log cumulative violation penalty
                        if let Some(ref audit_manager) = self.audit_manager {
                            let event = AuditEvent::new(
                                AuditEventType::SecurityViolation,
                                ip.unwrap_or("127.0.0.1".parse().unwrap()),
                                user_agent.map(|s| s.to_string()),
                                "cumulative_violation_penalty".to_string(),
                            )
                            .with_user(user_id.to_string())
                            .with_session(session_id.to_string())
                            .with_outcome(EventOutcome::Warning)
                            .with_severity(EventSeverity::High)
                            .with_metadata("violation_count".to_string(), recent_violations.to_string())
                            .with_metadata("penalty_factor".to_string(), violation_penalty.to_string());
                            
                            let _ = audit_manager.log_event(&event).await;
                        }
                    }

                    // Get geolocation data for behavioral analytics
                    let geo_data = self.get_geolocation_data(ip).await.unwrap_or_else(|_| {
                        GeoLocation {
                            current_location: (0.0, 0.0),
                            previous_location: None,
                            country_code: "US".to_string(),
                            city: Some("Unknown".to_string()),
                            timezone: "UTC".to_string(),
                            isp: Some("Unknown ISP".to_string()),
                            is_vpn_proxy: false,
                        }
                    });

                    // Update behavioral analytics with current request
                    user_behavior.update_with_session(&session, &geo_data);
                }
            }
        }

        // Ensure minimum limit and reasonable maximum
        let final_limit = (dynamic_limit.max(1.0) as u32).min(base_limit * 10); // Cap at 10x base limit
        
        if final_limit != base_limit {
            debug!("Dynamic rate limit calculated: base={}, final={}, user={:?}", 
                   base_limit, final_limit, user_id);
        }

        Ok(final_limit)
    }

    /// Get geolocation data from IP address using shared utility
    async fn get_geolocation_data(&self, ip: Option<IpAddr>) -> Result<GeoLocation, AppError> {
        get_geolocation_data(ip).await
    }

    /// Check if IP is whitelisted TODO:
    fn is_whitelisted(&self, ip: Option<IpAddr>) -> bool {
        if let Some(ip_addr) = ip {
            self.config.whitelist_ips.contains(&ip_addr)
        } else {
            false
        }
    }

    /// Check if IP is blacklisted TODO:
    fn is_blacklisted(&self, ip: Option<IpAddr>) -> bool {
        if let Some(ip_addr) = ip {
            self.config.blacklist_ips.contains(&ip_addr)
        } else {
            false
        }
    }

    /// Fixed window rate limiting with dynamic limits
    async fn check_fixed_window(&self, client_id: &str, dynamic_limit: u32) -> Result<RateLimitResult, AppError> {
        let window_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() / self.config.window_seconds * self.config.window_seconds;
        
        let key = format!("rate_limit:{}:{}", client_id, window_start);
        
        let current_count = self.redis
            .increment_rate_limit(&key, self.config.window_seconds)
            .await?;

        let remaining = if current_count <= dynamic_limit as i64 {
            dynamic_limit as i64 - current_count
        } else {
            0
        };

        let reset_time = window_start + self.config.window_seconds;
        let allowed = current_count <= dynamic_limit as i64;

        Ok(RateLimitResult {
            allowed,
            limit: dynamic_limit,
            remaining: remaining.max(0) as u32,
            reset_time,
            retry_after: if allowed { None } else { Some(reset_time - SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) },
        })
    }

    /// Sliding window rate limiting with dynamic limits
    async fn check_sliding_window(&self, client_id: &str, dynamic_limit: u32) -> Result<RateLimitResult, AppError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let _window_start = now - self.config.window_seconds;
        
        // Use a sorted set to track request timestamps
        let key = format!("rate_limit_sliding:{}", client_id);
        
        // Remove old entries and count current requests
        // This is a simplified implementation - in production, you'd use Lua scripts for atomicity
        let current_count = self.redis
            .increment_rate_limit(&format!("{}:{}", key, now), self.config.window_seconds)
            .await?;

        let remaining = if current_count <= dynamic_limit as i64 {
            dynamic_limit as i64 - current_count
        } else {
            0
        };

        let allowed = current_count <= dynamic_limit as i64;
        let reset_time = now + self.config.window_seconds;

        Ok(RateLimitResult {
            allowed,
            limit: dynamic_limit,
            remaining: remaining.max(0) as u32,
            reset_time,
            retry_after: if allowed { None } else { Some(self.config.window_seconds) },
        })
    }

    /// Token bucket rate limiting with dynamic limits
    async fn check_token_bucket(&self, client_id: &str, dynamic_limit: u32) -> Result<RateLimitResult, AppError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = format!("token_bucket:{}", client_id);
        let last_refill_key = format!("token_bucket_refill:{}", client_id);
        
        // Get current tokens and last refill time
        let current_tokens = self.redis.get(&bucket_key).await?
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(dynamic_limit);
            
        let last_refill = self.redis.get(&last_refill_key).await?
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(now);

        // Calculate tokens to add based on time elapsed
        let time_elapsed = now - last_refill;
        let tokens_to_add = (time_elapsed * dynamic_limit as u64) / self.config.window_seconds;
        let new_tokens = (current_tokens + tokens_to_add as u32).min(
            dynamic_limit + self.config.burst_allowance.unwrap_or(0)
        );

        let allowed = new_tokens > 0;
        let tokens_after = if allowed { new_tokens - 1 } else { new_tokens };

        // Update Redis
        if tokens_to_add > 0 || allowed {
            self.redis.set_with_expiry(&bucket_key, &tokens_after.to_string(), self.config.window_seconds * 2).await?;
            self.redis.set_with_expiry(&last_refill_key, &now.to_string(), self.config.window_seconds * 2).await?;
        }

        let retry_after = if allowed { 
            None 
        } else { 
            Some(self.config.window_seconds / dynamic_limit as u64) 
        };

        Ok(RateLimitResult {
            allowed,
            limit: dynamic_limit,
            remaining: tokens_after,
            reset_time: now + self.config.window_seconds,
            retry_after,
        })
    }

    /// Adaptive rate limiting that combines multiple algorithms based on behavior
    async fn check_adaptive(&self, client_id: &str, dynamic_limit: u32, session_context: Option<(String, String)>) -> Result<RateLimitResult, AppError> {
        // For high-risk users or sessions, use more restrictive sliding window
        // For trusted users, use more permissive token bucket
        
        let use_strict_algorithm = if let Some((session_id, _user_id)) = session_context {
            if let Some(ref threat_engine) = self.threat_engine {
                if let Some(ref session_manager) = self.session_manager {
                    if let Ok(Some(session)) = session_manager.get_session(&session_id).await {
                        let user_behavior = BehaviorAnalytics::new(); // TODO: Load from database
                        let geo_data = GeoLocation {
                            current_location: (0.0, 0.0),
                            previous_location: None,
                            country_code: "US".to_string(),
                            city: None,
                            timezone: "UTC".to_string(),
                            isp: None,
                            is_vpn_proxy: false,
                        };

                        match threat_engine.evaluate_session_threats(&session, &user_behavior, &geo_data).await {
                            Ok(evaluation) => evaluation.risk_score > 0.5,
                            Err(_) => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if use_strict_algorithm {
            debug!("Using strict sliding window algorithm for high-risk client: {}", client_id);
            self.check_sliding_window(client_id, dynamic_limit).await
        } else {
            debug!("Using permissive token bucket algorithm for trusted client: {}", client_id);
            self.check_token_bucket(client_id, dynamic_limit).await
        }
    }

    /// Check rate limit using configured algorithm with behavioral analytics
    pub async fn check_rate_limit(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> Result<RateLimitResult, AppError> {
        // Check blacklist first with enhanced threat response
        if self.is_blacklisted(ip) {
            warn!("Blocked request from blacklisted IP: {:?}", ip);
            
            // Enhanced threat detection for blacklisted IPs
            if let Some(ref threat_engine) = self.threat_engine {
                if let Some(actual_ip) = ip {
                    let _ = threat_engine.update_ip_threat_data(
                        actual_ip,
                        false,
                        None,
                        headers.get("user-agent").and_then(|ua| ua.to_str().ok()).unwrap_or("unknown").to_string(),
                    ).await;
                }
            }
            
            // Log security event
            if let Some(ref audit_manager) = self.audit_manager {
                let audit_event = crate::auth::audit::AuditEvent::new(
                    crate::auth::audit::AuditEventType::SecurityViolation,
                    ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                    headers.get("user-agent").and_then(|ua| ua.to_str().ok()).map(|s| s.to_string()),
                    "blacklist_block".to_string(),
                )
                .with_outcome(crate::auth::audit::EventOutcome::Failure)
                .with_severity(crate::auth::audit::EventSeverity::High)
                .with_error("Request blocked from blacklisted IP".to_string());
                
                let _ = audit_manager.log_event(&audit_event).await;
            }
            
            return Ok(RateLimitResult {
                allowed: false,
                limit: 0,
                remaining: 0,
                reset_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600, // 1 hour
                retry_after: Some(3600),
            });
        }

        // Skip rate limiting for whitelisted IPs with audit logging
        if self.is_whitelisted(ip) {
            debug!("Allowing whitelisted IP: {:?}", ip);
            
            // Log whitelisted access for audit trail
            if let Some(ref audit_manager) = self.audit_manager {
                let audit_event = crate::auth::audit::AuditEvent::new(
                    crate::auth::audit::AuditEventType::DataAccess,
                    ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                    headers.get("user-agent").and_then(|ua| ua.to_str().ok()).map(|s| s.to_string()),
                    "whitelist_bypass".to_string(),
                )
                .with_outcome(crate::auth::audit::EventOutcome::Success)
                .with_severity(crate::auth::audit::EventSeverity::Low)
                .with_metadata("bypass_reason".to_string(), "whitelisted_ip".to_string());
                
                let _ = audit_manager.log_event(&audit_event).await;
            }
            
            return Ok(RateLimitResult {
                allowed: true,
                limit: u32::MAX,
                remaining: u32::MAX,
                reset_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + self.config.window_seconds,
                retry_after: None,
            });
        }

        let client_id = self.extract_client_id(&headers, ip);
        let session_context = self.extract_session_context(headers, ip).await;
        let user_agent = headers.get("user-agent").and_then(|ua| ua.to_str().ok());
        
        debug!("Rate limiting check for client: {}, session: {:?}", client_id, session_context);

        // Calculate dynamic limit based on user behavior
        let dynamic_limit = self.calculate_dynamic_limit(
            self.config.requests_per_window,
            session_context.as_ref().map(|(s, _)| s.as_str()),
            session_context.as_ref().map(|(_, u)| u.as_str()),
            ip,
            user_agent,
        ).await?;

        let result = match self.config.algorithm {
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window(&client_id, dynamic_limit).await?,
            RateLimitAlgorithm::SlidingWindow => self.check_sliding_window(&client_id, dynamic_limit).await?,
            RateLimitAlgorithm::TokenBucket => self.check_token_bucket(&client_id, dynamic_limit).await?,
            RateLimitAlgorithm::Adaptive => self.check_adaptive(&client_id, dynamic_limit, session_context.clone()).await?,
        };

        // Enhanced threat detection and response for rate limit violations
        if !result.allowed {
            warn!("Rate limit exceeded for client: {}, IP: {:?}, limit: {}", client_id, ip, dynamic_limit);
            
            // Comprehensive audit logging
            if let Some(ref audit_manager) = self.audit_manager {
                let audit_event = crate::auth::audit::AuditEvent::new(
                    crate::auth::audit::AuditEventType::SecurityViolation,
                    ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                    user_agent.map(|s| s.to_string()),
                    "rate_limit_exceeded".to_string(),
                )
                .with_user(session_context.as_ref().map(|(_, u)| u.clone()).unwrap_or_else(|| "unknown".to_string()))
                .with_session(session_context.as_ref().map(|(s, _)| s.clone()).unwrap_or_else(|| "unknown".to_string()))
                .with_outcome(crate::auth::audit::EventOutcome::Failure)
                .with_severity(crate::auth::audit::EventSeverity::Medium)
                .with_error(format!("Rate limit exceeded: {}/{} requests", result.limit - result.remaining, result.limit))
                .with_metadata("client_id".to_string(), client_id.clone())
                .with_metadata("algorithm".to_string(), format!("{:?}", self.config.algorithm))
                .with_metadata("dynamic_limit".to_string(), dynamic_limit.to_string())
                .with_metadata("remaining".to_string(), result.remaining.to_string());
                
                let _ = audit_manager.log_event(&audit_event).await;
            }

            // Enhanced threat detection integration
            if let Some(ref threat_engine) = self.threat_engine {
                if let Some(actual_ip) = ip {
                    // Update IP threat data for rate limiting violations
                    let _ = threat_engine.update_ip_threat_data(
                        actual_ip,
                        false, // Rate limit violation is a failed attempt
                        None,  // Country data would come from geolocation
                        user_agent.unwrap_or("unknown").to_string(),
                    ).await;

                    // Check if IP should be blocked due to repeated violations
                    if let Ok(is_blocked) = threat_engine.is_ip_blocked(actual_ip).await {
                        if is_blocked {
                            warn!("IP {:?} is now blocked due to threat detection", actual_ip);
                        }
                    }
                }

                // Check if user should be locked due to repeated violations
                if let Some((_, user_id)) = &session_context {
                    if let Ok(is_locked) = threat_engine.is_user_locked(user_id).await {
                        if is_locked {
                            warn!("User {} is now locked due to threat detection", user_id);
                        }
                    }
                }
            }

            // Log security event for session manager
            if let Some((_, user_id)) = &session_context {
                let _ = self.redis.add_security_event(
                    user_id,
                    SecurityEventType::SecurityViolation,
                    "Rate limit exceeded",
                    ip.unwrap_or("127.0.0.1".parse().unwrap()),
                    &user_agent.unwrap_or_default()
                ).await;
            }
        } else {
            // Log successful rate limit checks for audit trail
            if let Some(ref audit_manager) = self.audit_manager {
                let audit_event = crate::auth::audit::AuditEvent::new(
                    crate::auth::audit::AuditEventType::DataAccess,
                    ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                    user_agent.map(|s| s.to_string()),
                    "rate_limit_check_passed".to_string(),
                )
                .with_user(session_context.as_ref().map(|(_, u)| u.clone()).unwrap_or_else(|| "anonymous".to_string()))
                .with_session(session_context.as_ref().map(|(s, _)| s.clone()).unwrap_or_else(|| "none".to_string()))
                .with_outcome(crate::auth::audit::EventOutcome::Success)
                .with_severity(crate::auth::audit::EventSeverity::Low)
                .with_metadata("requests_remaining".to_string(), result.remaining.to_string())
                .with_metadata("limit".to_string(), result.limit.to_string());
                
                let _ = audit_manager.log_event(&audit_event).await;
            }
        }

        Ok(result)
    }
}

/// Rate limit check result
#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: u64,
    pub retry_after: Option<u64>,
}

/// Enhanced rate limiting middleware with behavioral analytics
pub async fn rate_limit_middleware(
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();
    
    // Extract IP from connection info or headers
    let ip = extract_ip_from_request(&request);
    
    match rate_limiter.check_rate_limit(headers, ip).await {
        Ok(result) => {
            if result.allowed {
                let mut response = next.run(request).await;
                
                // Add rate limit headers
                let response_headers = response.headers_mut();
                response_headers.insert("X-RateLimit-Limit", result.limit.to_string().parse().unwrap());
                response_headers.insert("X-RateLimit-Remaining", result.remaining.to_string().parse().unwrap());
                response_headers.insert("X-RateLimit-Reset", result.reset_time.to_string().parse().unwrap());
                
                Ok(response)
            } else {
                warn!("Rate limit exceeded for IP: {:?}", ip);
                
                let body = serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": result.retry_after
                });
                
                let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", result.limit.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers.insert("X-RateLimit-Reset", result.reset_time.to_string().parse().unwrap());
                
                if let Some(retry_after) = result.retry_after {
                    headers.insert("Retry-After", retry_after.to_string().parse().unwrap());
                }
                
                Ok(response)
            }
        }
        Err(e) => {
            error!("Rate limiting error: {}", e);
            // Fail open - allow request if rate limiting is down
            Ok(next.run(request).await)
        }
    }
}

/// Extract IP address from request
/// Extract IP address from request using shared utility
fn extract_ip_from_request(request: &Request) -> Option<IpAddr> {
    // Try to extract from connection info first
    if let Some(connect_info) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return Some(connect_info.ip());
    }

    // Fallback to headers using shared utility
    extract_ip_from_headers(request.headers()).ok()
}

/// Create enhanced rate limiter from config with behavioral analytics
pub fn create_rate_limiter(redis: Arc<RedisManager>, config: &Config) -> RateLimiter {
    let mut security_level_limits = HashMap::new();
    security_level_limits.insert(SecurityLevel::Low, config.rate_limit_requests * 2);
    security_level_limits.insert(SecurityLevel::Medium, config.rate_limit_requests);
    security_level_limits.insert(SecurityLevel::High, config.rate_limit_requests / 2);
    security_level_limits.insert(SecurityLevel::Critical, config.rate_limit_requests / 5);

    let rate_config = RateLimitConfig {
        requests_per_window: config.rate_limit_requests,
        window_seconds: config.rate_limit_window_seconds,
        algorithm: RateLimitAlgorithm::Adaptive,
        burst_allowance: Some(config.rate_limit_requests / 5), // 20% burst allowance
        whitelist_ips: vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
        ],
        blacklist_ips: vec![], // Can be loaded from database or config
        enable_behavioral_analytics: true,
        requests_per_minute_by_security_level: security_level_limits,
        suspicious_user_penalty: 0.3,
        trusted_user_bonus: 2.5,
        risk_penalty_threshold: 0.6,
        risk_bonus_threshold: 0.3,
        max_penalty_factor: 0.1,
        max_bonus_factor: 4.0,
    };
    
    RateLimiter::new(redis, rate_config)
}