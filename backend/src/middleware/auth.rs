use axum::{
    extract::{Request, Extension},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, SameSite as CookieSameSite};
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use time::Duration;
use tracing::{error, info};
use crate::{
    auth::{
        audit::{AuditManager, AuditEvent, AuditEventType, EventOutcome, EventSeverity},
        behavioral::BehaviorAnalytics,
        binding::{SessionBindingManager, DeviceFingerprint},
        ses::{SessionManager, SecurityManager},
        threat::ThreatDetectionEngine,
        utils::{
            is_expired, extract_ip_from_headers,
            extract_user_agent, get_geolocation_data, is_suspicious_location_change
        },
        PasetoManager,
    },
    config::Config,
    database::RedisManager,
    errors::AppError,
    models::{
        security::{SecurityLevel, ThreatType, ThreatEvaluationResult, GeoLocation},
        user::User,
        ses::Session,
    },
};

/// Enhanced authentication configuration with comprehensive security settings
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Token lifetime in seconds (default: 1 hour)
    pub token_lifetime: u64,
    /// Refresh token lifetime in seconds (default: 30 days)
    pub refresh_token_lifetime: u64,
    /// Session timeout in seconds (default: 24 hours)
    pub session_timeout: u64,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
    /// Enable automatic token rotation
    pub enable_token_rotation: bool,
    /// Token rotation interval in seconds
    pub token_rotation_interval: u64,
    /// Enable risk-based authentication
    pub enable_risk_based_auth: bool,
    /// Risk threshold for additional authentication
    pub risk_threshold: f64,
    /// Enable behavioral analytics
    pub enable_behavioral_analytics: bool,
    /// Enable session binding validation
    pub enable_session_binding: bool,
    /// Enable geolocation validation
    pub enable_geolocation_validation: bool,
    /// Maximum allowed location distance in km
    pub max_location_distance: f64,
    /// Enable device fingerprinting
    pub enable_device_fingerprinting: bool,
    /// Require MFA for high-risk sessions
    pub require_mfa_for_high_risk: bool,
    /// MFA requirement threshold
    pub mfa_risk_threshold: f64,
    /// Authentication rate limits by security level
    pub auth_rate_limits: HashMap<SecurityLevel, u32>,
    /// Failed attempt lockout threshold
    pub failed_attempt_threshold: u32,
    /// Lockout duration in seconds
    pub lockout_duration: u64,
    /// Enable progressive delays for failed attempts
    pub enable_progressive_delays: bool,
    /// Paths that require authentication
    pub protected_paths: Vec<String>,
    /// Path prefixes that require authentication
    pub protected_path_prefixes: Vec<String>,
    /// Paths to exclude from authentication
    pub excluded_paths: Vec<String>,
    /// Path prefixes to exclude from authentication
    pub excluded_path_prefixes: Vec<String>,
    /// Cookie settings
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,
    /// Header name for bearer token
    pub bearer_header_name: String,
    /// Enable audit logging
    pub enable_audit_logging: bool,
    /// Audit log level
    pub audit_log_level: EventSeverity,
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let mut auth_rate_limits = HashMap::new();
        auth_rate_limits.insert(SecurityLevel::Low, 100);
        auth_rate_limits.insert(SecurityLevel::Medium, 50);
        auth_rate_limits.insert(SecurityLevel::High, 20);
        auth_rate_limits.insert(SecurityLevel::Critical, 10);

        Self {
            token_lifetime: 3600, // 1 hour
            refresh_token_lifetime: 2592000, // 30 days
            session_timeout: 86400, // 24 hours
            max_concurrent_sessions: 5,
            enable_token_rotation: true,
            token_rotation_interval: 1800, // 30 minutes
            enable_risk_based_auth: true,
            risk_threshold: 0.7,
            enable_behavioral_analytics: true,
            enable_session_binding: true,
            enable_geolocation_validation: true,
            max_location_distance: 100.0, // 100 km
            enable_device_fingerprinting: true,
            require_mfa_for_high_risk: true,
            mfa_risk_threshold: 0.8,
            auth_rate_limits,
            failed_attempt_threshold: 5,
            lockout_duration: 900, // 15 minutes
            enable_progressive_delays: true,
            protected_paths: vec![
                "/api/user/".to_string(),
                "/api/admin/".to_string(),
                "/api/secure/".to_string(),
            ],
            protected_path_prefixes: vec![
                "/api/user/".to_string(),
                "/api/admin/".to_string(),
                "/dashboard/".to_string(),
            ],
            excluded_paths: vec![
                "/api/auth/login".to_string(),
                "/api/auth/register".to_string(),
                "/api/auth/refresh".to_string(),
                "/api/health".to_string(),
                "/api/public/".to_string(),
            ],
            excluded_path_prefixes: vec![
                "/api/public/".to_string(),
                "/static/".to_string(),
                "/assets/".to_string(),
            ],
            cookie_name: "auth_token".to_string(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: SameSite::Strict,
            bearer_header_name: "authorization".to_string(),
            enable_audit_logging: true,
            audit_log_level: EventSeverity::Low,
        }
    }
}

/// Enhanced authentication result with comprehensive security context
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: User,
    pub session: Session,
    pub risk_score: f64,
    pub requires_mfa: bool,
    pub behavioral_context: Option<String>,
    pub threat_evaluation: Option<ThreatEvaluationResult>,
    pub device_fingerprint: Option<DeviceFingerprint>,
    pub geolocation: Option<GeoLocation>,
}

/// Enhanced authentication user with comprehensive security context
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,  // Added missing user_id field
    pub user: User,
    pub session: Session,
    pub risk_score: f64,
    pub security_level: SecurityLevel,
    pub requires_mfa: bool,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<DeviceFingerprint>,
    pub geolocation: Option<GeoLocation>,
    pub behavioral_context: Option<String>,
    pub threat_indicators: Vec<ThreatType>,
}

impl AuthUser {
    /// Create AuthUser from authentication result
    pub fn from_auth_result(
        result: AuthResult,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Self {
        let risk_score = result.risk_score;
        let security_level = Self::calculate_security_level(risk_score);
        let threat_indicators = result.threat_evaluation
            .as_ref()
            .map(|eval| eval.threats.clone())
            .unwrap_or_default();

        Self {
            user_id: result.user.id.to_string(),  // Convert i32 to String
            user: result.user,
            session: result.session,
            risk_score,
            security_level,
            requires_mfa: result.requires_mfa,
            last_activity: Utc::now(),
            ip_address,
            user_agent,
            device_fingerprint: result.device_fingerprint,
            geolocation: result.geolocation,
            behavioral_context: result.behavioral_context,
            threat_indicators,
        }
    }

    /// Calculate security level based on risk score
    fn calculate_security_level(risk_score: f64) -> SecurityLevel {
        match risk_score {
            score if score >= 0.8 => SecurityLevel::Critical,
            score if score >= 0.6 => SecurityLevel::High,
            score if score >= 0.4 => SecurityLevel::Medium,
            _ => SecurityLevel::Low,
        }
    }

    /// Check if user requires additional authentication
    pub fn requires_additional_auth(&self) -> bool {
        self.requires_mfa || self.risk_score > 0.7
    }

    /// Get user permissions based on roles and security level
    pub fn get_permissions(&self) -> Vec<String> {
        // For now, return basic permissions since User doesn't have roles field
        let mut permissions = vec!["read".to_string()];
        
        // Add security-level based permissions
        match self.security_level {
            SecurityLevel::Critical => permissions.push("restricted_access".to_string()),
            SecurityLevel::High => permissions.push("monitored_access".to_string()),
            SecurityLevel::Medium => permissions.push("write".to_string()),
            SecurityLevel::Low => {
                permissions.push("write".to_string());
                permissions.push("modify".to_string());
            }
        }
        permissions
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        // For now, implement basic role checking based on user properties
        match role {
            "admin" => self.user.is_active && self.security_level != SecurityLevel::Critical,
            "user" => self.user.is_active,
            "read" => true,
            "write" => self.user.is_active && self.security_level != SecurityLevel::Critical,
            _ => false,
        }
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if session is expired based on timeout
    pub fn is_session_expired(&self, timeout: u64) -> bool {
        let now = Utc::now();
        let elapsed = now.signed_duration_since(self.last_activity);
        elapsed.num_seconds() as u64 > timeout
    }
}

/// Enhanced authentication middleware with comprehensive security features
#[derive(Clone)]
pub struct AuthMiddleware {
    redis: Arc<RedisManager>,
    config: AuthConfig,
    session_manager: Option<Arc<SessionManager>>,
    security_manager: Option<Arc<SecurityManager>>,
    threat_engine: Option<Arc<ThreatDetectionEngine>>,
    audit_manager: Option<Arc<AuditManager>>,
    binding_manager: Option<Arc<SessionBindingManager>>,
    paseto_manager: Option<Arc<PasetoManager>>,
}

impl AuthMiddleware {
    /// Create new authentication middleware
    pub fn new(redis: Arc<RedisManager>, config: AuthConfig) -> Self {
        Self {
            redis,
            config,
            session_manager: None,
            security_manager: None,
            threat_engine: None,
            audit_manager: None,
            binding_manager: None,
            paseto_manager: None,
        }
    }

    /// Add session manager with builder pattern
    pub fn with_session_manager(mut self, session_manager: Arc<SessionManager>) -> Self {
        self.session_manager = Some(session_manager);
        self
    }

    /// Add security manager with builder pattern
    pub fn with_security_manager(mut self, security_manager: Arc<SecurityManager>) -> Self {
        self.security_manager = Some(security_manager);
        self
    }

    /// Add threat detection engine with builder pattern
    pub fn with_threat_engine(mut self, threat_engine: Arc<ThreatDetectionEngine>) -> Self {
        self.threat_engine = Some(threat_engine);
        self
    }

    /// Add audit manager with builder pattern
    pub fn with_audit_manager(mut self, audit_manager: Arc<AuditManager>) -> Self {
        self.audit_manager = Some(audit_manager);
        self
    }

    /// Add session binding manager with builder pattern
    pub fn with_paseto_manager(mut self, paseto_manager: Arc<PasetoManager>) -> Self {
        self.paseto_manager = Some(paseto_manager);
        self
    }

    /// Add session binding manager with builder pattern
    pub fn with_binding_manager(mut self, binding_manager: Arc<SessionBindingManager>) -> Self {
        self.binding_manager = Some(binding_manager);
        self
    }

    /// Enhanced authentication with comprehensive security validation
    pub async fn authenticate_request(
        &self,
        headers: &HeaderMap,
        path: &str,
        method: &str,
    ) -> Result<Option<AuthUser>, AppError> {
        // Check if path requires authentication
        if !self.requires_authentication(path) {
            return Ok(None);
        }

        // Extract authentication token
        let token = self.extract_token(headers)
            .ok_or_else(|| AppError::Unauthorized)?;

        // Extract request context
        let ip_address = self.extract_ip_from_request(headers);
        let user_agent = self.extract_user_agent_from_request(headers);

        // Validate token and get session
        let session = self.validate_token_and_get_session(&token).await?;

        // Perform comprehensive security validation
        let auth_result = self.perform_security_validation(
            &session,
            ip_address,
            user_agent.as_deref(),
            headers,
        ).await?;

        // Check for additional authentication requirements
        if auth_result.requires_mfa {
            return Err(AppError::Unauthorized);
        }

        // Create AuthUser from result
        let auth_user = AuthUser::from_auth_result(auth_result, ip_address, user_agent);

        // Log authentication event
        self.log_authentication_event(&auth_user, "authentication_success", EventOutcome::Success).await?;

        // Attempt token rotation if enabled
        if self.config.enable_token_rotation {
            self.attempt_token_rotation(&session, &auth_user).await?;
        }

        Ok(Some(auth_user))
    }

    /// Perform comprehensive security validation
    async fn perform_security_validation(
        &self,
        session: &Session,
        ip_address: Option<IpAddr>,
        user_agent: Option<&str>,
        headers: &HeaderMap,
    ) -> Result<AuthResult, AppError> {
        let mut risk_score: f64 = 0.0;
        let mut requires_mfa = false;
        let mut behavioral_context = None;
        let mut threat_evaluation = None;
        let mut device_fingerprint = None;
        let mut geolocation = None;

        // Get user information
        let user = self.get_user_by_id(&session.user_id).await?;

        // Validate session binding if enabled
        if self.config.enable_session_binding {
            if let Some(ref binding_manager) = self.binding_manager {
                let fingerprint = self.extract_device_fingerprint(headers, user_agent);
                let validation_result = binding_manager.validate_binding(
                    &session.id,
                    ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
                    &fingerprint,
                    None,
                )?;

                if !validation_result.is_valid {
                    self.log_security_violation(
                        &session.user_id,
                        &session.id,
                        ip_address,
                        "session_binding_mismatch",
                        0.9,
                    ).await?;
                    return Err(AppError::Unauthorized);
                }

                device_fingerprint = Some(fingerprint);
            }
        }

        // Perform behavioral analytics if enabled
        if self.config.enable_behavioral_analytics {
            let mut behavior_analytics = BehaviorAnalytics::new();
            
            // Get geolocation data using shared utility
            if let Some(ip) = ip_address {
                geolocation = get_geolocation_data(Some(ip)).await.ok();
                if let Some(ref geo) = geolocation {
                    behavior_analytics.update_with_session(session, geo);
                    
                    // Validate location if enabled using enhanced logic
                    if self.config.enable_geolocation_validation {
                        if let Some(prev_location) = geo.previous_location {
                            let time_diff_hours = (chrono::Utc::now().timestamp() - session.created_at.timestamp()) as f64 / 3600.0;
                            if is_suspicious_location_change(
                                prev_location,
                                geo.current_location,
                                time_diff_hours,
                                self.config.max_location_distance,
                            ) {
                                risk_score += 0.3;
                            }
                        }
                    }
                }
            }

            behavioral_context = Some(serde_json::to_string(&behavior_analytics)
                .unwrap_or_default());
        }

        // Perform threat evaluation if available
        if let Some(ref threat_engine) = self.threat_engine {
            if let (Some(geo), Some(behavior)) = (&geolocation, &behavioral_context) {
                let behavior_analytics: BehaviorAnalytics = serde_json::from_str(behavior)
                    .unwrap_or_else(|_| BehaviorAnalytics::new());
                
                let evaluation = threat_engine.evaluate_session_threats(
                    session,
                    &behavior_analytics,
                    geo,
                ).await?;

                risk_score = risk_score.max(evaluation.risk_score);
                threat_evaluation = Some(evaluation);
            }
        }

        // Determine MFA requirement
        if self.config.require_mfa_for_high_risk && risk_score >= self.config.mfa_risk_threshold {
            requires_mfa = true;
        }

        // Check if risk exceeds threshold
        if risk_score >= self.config.risk_threshold {
            self.log_security_violation(
                &session.user_id,
                &session.id,
                ip_address,
                "high_risk_session",
                risk_score,
            ).await?;
        }

        Ok(AuthResult {
            user,
            session: session.clone(),
            risk_score,
            requires_mfa,
            behavioral_context,
            threat_evaluation,
            device_fingerprint,
            geolocation,
        })
    }

    /// Validate token and retrieve session
    async fn validate_token_and_get_session(&self, token: &str) -> Result<Session, AppError> {
        // First check if token is expired using utility function
        if is_expired(token.parse::<u64>().unwrap_or(0)) {
            return Err(AppError::Unauthorized);
        }

        // Get session from Redis or session manager
        if let Some(session_manager) = &self.session_manager {
            match session_manager.get_session_by_token(token).await {
                Ok(Some(session)) => {
                    if session.flags.is_active && !session.is_expired() {
                        Ok(session)
                    } else {
                        Err(AppError::SessionExpired("Session has expired or is inactive".to_string()))
                    }
                }
                Ok(None) => Err(AppError::Unauthorized),
                Err(_) => Err(AppError::Unauthorized),
            }
        } else {
            Err(AppError::InternalServerError("Session manager not configured".to_string()))
        }
    }

    /// Get user by ID from database
    async fn get_user_by_id(&self, user_id: &str) -> Result<User, AppError> {
        // This would typically query the database
        // For now, return a placeholder error
        Err(AppError::not_found("User"))
    }

    /// Extract device fingerprint from request
    fn extract_device_fingerprint(&self, headers: &HeaderMap, user_agent: Option<&str>) -> DeviceFingerprint {
        DeviceFingerprint::from_user_agent(
            user_agent.unwrap_or("unknown").to_string()
        )
    }

    /// Log security violation
    async fn log_security_violation(
        &self,
        user_id: &str,
        session_id: &str,
        ip_address: Option<IpAddr>,
        violation_type: &str,
        risk_score: f64,
    ) -> Result<(), AppError> {
        if let Some(ref audit_manager) = self.audit_manager {
            let event = AuditEvent::new(
                AuditEventType::SecurityViolation,
                ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
                None,
                violation_type.to_string(),
            )
            .with_user(user_id.to_string())
            .with_session(session_id.to_string())
            .with_outcome(EventOutcome::Failure)
            .with_severity(EventSeverity::High)
            .with_risk_score(risk_score);

            audit_manager.log_event(&event).await?;
        }
        Ok(())
    }

    /// Log authentication event
    async fn log_authentication_event(
        &self,
        auth_user: &AuthUser,
        event_type: &str,
        outcome: EventOutcome,
    ) -> Result<(), AppError> {
        if let Some(ref audit_manager) = self.audit_manager {
            let event = AuditEvent::new(
                AuditEventType::Authentication,
                auth_user.ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
                auth_user.user_agent.clone(),
                event_type.to_string(),
            )
            .with_user(auth_user.user.id.to_string())
            .with_session(auth_user.session.id.clone())
            .with_outcome(outcome)
            .with_severity(EventSeverity::Low)
            .with_risk_score(auth_user.risk_score);

            audit_manager.log_event(&event).await?;
        }
        Ok(())
    }

    /// Attempt token rotation
    async fn attempt_token_rotation(&self, session: &Session, auth_user: &AuthUser) -> Result<(), AppError> {
        if let Some(ref session_manager) = self.session_manager {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| AppError::internal(&format!("System time error: {}", e)))?
                .as_secs();
            let last_rotation = session.created_at.timestamp() as u64;
            
            if now - last_rotation >= self.config.token_rotation_interval {
                // Generate new token pair using PASETO manager
                if let Some(ref paseto_manager) = self.paseto_manager {
                    let (new_access_token, new_refresh_token, access_jti, refresh_jti): (String, String, String, String) = 
                        paseto_manager.generate_token_pair_with_rotation(&auth_user.user.id.to_string(), &session.id)?;
                    
                    // Update session with new token using refresh_session
                    let mut updated_session = session_manager.refresh_session(&session.id, session.last_ip, None).await?;
                    updated_session.token = new_access_token;
                    
                    info!("Token rotated for user {} session {}", auth_user.user.id, session.id);
                }
            }
        }
        Ok(())
    }

    /// Check if path requires authentication
    fn requires_authentication(&self, path: &str) -> bool {
        // Check excluded paths first
        for excluded_path in &self.config.excluded_paths {
            if path == excluded_path {
                return false;
            }
        }

        // Check excluded path prefixes
        for prefix in &self.config.excluded_path_prefixes {
            if path.starts_with(prefix) {
                return false;
            }
        }

        // Check protected paths
        for protected_path in &self.config.protected_paths {
            if path == protected_path {
                return true;
            }
        }

        // Check protected path prefixes
        for prefix in &self.config.protected_path_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }

        // Default to requiring authentication for API paths
        path.starts_with("/api/") && !path.starts_with("/api/public/")
    }

    /// Extract authentication token from request
    fn extract_token(&self, headers: &HeaderMap) -> Option<String> {
        // Try Authorization header first
        if let Some(auth_header) = headers.get(&self.config.bearer_header_name) {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    return Some(auth_str.strip_prefix("Bearer ").unwrap().to_string());
                }
            }
        }

        // Try cookie
        if let Some(cookie_header) = headers.get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(token) = cookie.strip_prefix(&format!("{}=", self.config.cookie_name)) {
                        return Some(token.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract IP address from request headers using shared utility
    fn extract_ip_from_request(&self, headers: &HeaderMap) -> Option<IpAddr> {
        extract_ip_from_headers(headers).ok()
    }

    /// Extract User-Agent from request headers using shared utility
    fn extract_user_agent_from_request(&self, headers: &HeaderMap) -> Option<String> {
        Some(extract_user_agent(headers))
    }
}

/// Enhanced authentication middleware function
pub async fn auth_middleware(
    Extension(auth): Extension<Arc<AuthMiddleware>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();
    let path = request.uri().path();
    let method = request.method().as_str();

    match auth.authenticate_request(&headers, path, method).await {
        Ok(Some(auth_user)) => {
            // Add authenticated user to request extensions
            request.extensions_mut().insert(auth_user);
            Ok(next.run(request).await)
        }
        Ok(None) => {
            // Path doesn't require authentication
            Ok(next.run(request).await)
        }
        Err(e) => {
            error!("Authentication failed: {}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Create authentication middleware with comprehensive configuration
pub fn create_auth_middleware(
    redis: Arc<RedisManager>,
    _config: &Config, // TODO
    session_manager: Arc<SessionManager>,
    security_manager: Arc<SecurityManager>,
    threat_engine: Arc<ThreatDetectionEngine>,
    audit_manager: Arc<AuditManager>,
    binding_manager: Arc<SessionBindingManager>,
) -> AuthMiddleware {
    let auth_config = AuthConfig::default(); // You might want to load this from config

    AuthMiddleware::new(redis, auth_config)
        .with_session_manager(session_manager)
        .with_security_manager(security_manager)
        .with_threat_engine(threat_engine)
        // Remove the broken code at the end of the file
        .with_audit_manager(audit_manager)
        .with_binding_manager(binding_manager)
}

// Cookie constants
pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

/// Creates a secure HTTP-only cookie with the specified name, value, and max age
pub fn create_secure_cookie(name: &str, value: &str, max_age_seconds: i64) -> Cookie<'static> {
    Cookie::build((name.to_string(), value.to_string()))
        .http_only(true)
        .secure(true)
        .same_site(CookieSameSite::Strict)
        .max_age(Duration::seconds(max_age_seconds))
        .path("/")
        .build()
}

/// Creates a cookie that will delete an existing cookie by setting it to expire immediately
pub fn create_delete_cookie(name: &str) -> Cookie<'static> {
    Cookie::build((name.to_string(), "".to_string()))
        .http_only(true)
        .secure(true)
        .same_site(CookieSameSite::Strict)
        .max_age(Duration::seconds(0))
        .path("/")
        .build()
}