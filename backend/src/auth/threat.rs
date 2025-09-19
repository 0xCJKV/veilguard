use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::errors::AppError;
use crate::models::ses::{Session};
use crate::models::security::{
    SecurityConfig, SecurityAction, RiskAssessment, ThreatData, EventSeverity, SecurityLevel
};
use crate::auth::behavioral::{BehaviorAnalytics, GeoLocation};
use crate::auth::audit::{AuditEvent, AuditEventType, EventOutcome, AuditManager};

/// Real-time threat detection engine
pub struct ThreatDetectionEngine {
    /// Configuration for threat response (now using SecurityConfig from models/security.rs)
    pub config: SecurityConfig,
    /// Audit manager for logging security events
    pub audit_manager: Arc<AuditManager>,
    /// Active threat tracking
    pub active_threats: Arc<RwLock<HashMap<String, ActiveThreat>>>,
    /// IP-based threat tracking
    pub ip_threats: Arc<RwLock<HashMap<IpAddr, IpThreatData>>>,
    /// User-based threat tracking (now using ThreatData from models/security.rs)
    pub user_threats: Arc<RwLock<HashMap<String, ThreatData>>>,
}

/// Active threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveThreat {
    /// Threat ID
    pub id: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Risk score
    pub risk_score: f64,
    /// First detected timestamp
    pub first_detected: DateTime<Utc>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
    /// Source IP address
    pub source_ip: IpAddr,
    /// User ID if known
    pub user_id: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Threat details
    pub details: HashMap<String, String>,
    /// Actions taken (now using SecurityAction from models/security.rs)
    pub actions_taken: Vec<SecurityAction>,
}

/// Types of security threats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    BruteForceAttack,
    CredentialStuffing,
    SessionHijacking,
    AnomalousLocation,
    SuspiciousDevice,
    RapidSessionCreation,
    PrivilegeEscalation,
    TokenAbuse,
    ConcurrentSessionAnomaly,
    BehavioralAnomaly,
}

/// IP-based threat tracking data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpThreatData {
    /// Failed login attempts
    pub failed_attempts: u32,
    /// Successful logins
    pub successful_logins: u32,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Countries associated with this IP
    pub countries: Vec<String>,
    /// User agents seen from this IP
    pub user_agents: Vec<String>,
    /// Whether this IP is blocked
    pub is_blocked: bool,
    /// Block expiration if applicable
    pub block_expires: Option<DateTime<Utc>>,
    /// Risk score for this IP
    pub risk_score: f64,
}

// Remove duplicate UserThreatData - now using ThreatData from models/security.rs

/// Threat evaluation result
#[derive(Debug)]
pub struct ThreatEvaluationResult {
    /// Overall risk score
    pub risk_score: f64,
    /// Detected threats
    pub threats: Vec<ThreatType>,
    /// Recommended actions (now using SecurityAction from models/security.rs)
    pub recommended_actions: Vec<SecurityAction>,
    /// Whether immediate action is required
    pub requires_immediate_action: bool,
}

impl ThreatDetectionEngine {
    /// Create a new threat detection engine
    pub fn new(config: SecurityConfig, audit_manager: Arc<AuditManager>) -> Self {
        Self {
            config,
            audit_manager,
            active_threats: Arc::new(RwLock::new(HashMap::new())),
            ip_threats: Arc::new(RwLock::new(HashMap::new())),
            user_threats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Evaluate threats for a session
    pub async fn evaluate_session_threats(
        &self,
        session: &Session,
        user_behavior: &BehaviorAnalytics,
        geo_data: &GeoLocation,
    ) -> Result<ThreatEvaluationResult, AppError> {
        let mut threats = Vec::new();
        let mut risk_score: f64 = 0.0;

        // Check for brute force attacks
        if let Some(_threat) = self.detect_brute_force(session.created_ip).await? {
            threats.push(ThreatType::BruteForceAttack);
            risk_score += 0.8;
        }

        // Check for anomalous location
        if self.is_anomalous_location(session, geo_data).await? {
            threats.push(ThreatType::AnomalousLocation);
            risk_score += 0.6;
        }

        // Check for suspicious device
        if self.is_suspicious_device(session, user_behavior).await? {
            threats.push(ThreatType::SuspiciousDevice);
            risk_score += 0.5;
        }

        // Check for rapid session creation
        if self.detect_rapid_session_creation(&session.user_id).await? {
            threats.push(ThreatType::RapidSessionCreation);
            risk_score += 0.7;
        }

        // Check for concurrent session anomalies
        if self.detect_concurrent_session_anomaly(session).await? {
            threats.push(ThreatType::ConcurrentSessionAnomaly);
            risk_score += 0.4;
        }

        // Normalize risk score
        risk_score = risk_score.min(1.0);

        let recommended_actions = self.determine_actions(risk_score, &threats).await;
        let requires_immediate_action = risk_score > self.config.risk_thresholds.auto_revoke_threshold;

        Ok(ThreatEvaluationResult {
            risk_score,
            threats,
            recommended_actions,
            requires_immediate_action,
        })
    }

    /// Execute threat response actions
    pub async fn execute_threat_response(
        &self,
        session: &mut Session,
        evaluation: &ThreatEvaluationResult,
    ) -> Result<Vec<SecurityAction>, AppError> {
        let mut executed_actions = Vec::new();

        for action in &evaluation.recommended_actions {
            match action {
                SecurityAction::SessionRevoked => {
                    session.revoke(Some("Security threat detected"));
                    executed_actions.push(SecurityAction::SessionRevoked);
                }
                SecurityAction::MfaRequired => {
                    // Set MFA requirement flag
                    executed_actions.push(SecurityAction::MfaRequired);
                }
                SecurityAction::SecurityNotification => {
                    self.send_security_notification(session, evaluation).await?;
                    executed_actions.push(SecurityAction::SecurityNotification);
                }
                SecurityAction::AccountLocked => {
                    self.lock_user_account(&session.user_id, Duration::hours(24)).await?;
                    executed_actions.push(SecurityAction::AccountLocked);
                }
                SecurityAction::IpBlocked => {
                    self.block_ip(session.created_ip, Duration::hours(1)).await?;
                    executed_actions.push(SecurityAction::IpBlocked);
                }
                SecurityAction::AdditionalVerificationRequired => {
                    executed_actions.push(SecurityAction::AdditionalVerificationRequired);
                }
                SecurityAction::DeviceBlocked => {
                    // Block the device (implementation would depend on device tracking system)
                    executed_actions.push(SecurityAction::DeviceBlocked);
                }
                SecurityAction::PasswordResetRequired => {
                    // Force password reset (implementation would depend on user management system)
                    executed_actions.push(SecurityAction::PasswordResetRequired);
                }
                SecurityAction::ContactSupport => {
                    // Notify user to contact support
                    executed_actions.push(SecurityAction::ContactSupport);
                }
                SecurityAction::MonitorActivity => {
                    // Enable enhanced monitoring for this session/user
                    executed_actions.push(SecurityAction::MonitorActivity);
                }
            }
        }

        Ok(executed_actions)
    }

    /// Detect brute force attacks from an IP
    async fn detect_brute_force(&self, ip: IpAddr) -> Result<Option<ActiveThreat>, AppError> {
        let ip_threats = self.ip_threats.read().await;
        
        if let Some(ip_data) = ip_threats.get(&ip) {
            if ip_data.failed_attempts >= self.config.threat_config.max_failed_attempts {
                let threat = ActiveThreat {
                    id: format!("brute_force_{}", ip),
                    threat_type: ThreatType::BruteForceAttack,
                    risk_score: 0.9,
                    first_detected: ip_data.first_seen,
                    last_updated: Utc::now(),
                    source_ip: ip,
                    user_id: None,
                    session_id: None,
                    details: HashMap::from([
                        ("failed_attempts".to_string(), ip_data.failed_attempts.to_string()),
                        ("countries".to_string(), ip_data.countries.join(", ")),
                    ]),
                    actions_taken: Vec::new(),
                };
                return Ok(Some(threat));
            }
        }
        
        Ok(None)
    }

    /// Check if location is anomalous
    async fn is_anomalous_location(
        &self,
        _session: &Session,
        geo_data: &GeoLocation,
    ) -> Result<bool, AppError> {
        // Simple heuristic: VPN/proxy usage is considered anomalous
        Ok(geo_data.is_vpn_proxy)
    }

    /// Check if device is suspicious
    async fn is_suspicious_device(
        &self,
        session: &Session,
        user_behavior: &BehaviorAnalytics,
    ) -> Result<bool, AppError> {
        // Check if device fingerprint is known
        Ok(!user_behavior.profile.typical_devices.contains(&session.device_fingerprint))
    }

    /// Detect rapid session creation
    async fn detect_rapid_session_creation(&self, user_id: &str) -> Result<bool, AppError> {
        let user_threats = self.user_threats.read().await;
        
        if let Some(threat_data) = user_threats.get(user_id) {
            if let Some(user_info) = threat_data.user_threats.get(user_id) {
                // Check if there are too many concurrent sessions
                return Ok(user_info.concurrent_sessions > 5);
            }
        }
        
        Ok(false)
    }

    /// Detect concurrent session anomalies
    async fn detect_concurrent_session_anomaly(&self, session: &Session) -> Result<bool, AppError> {
        let user_threats = self.user_threats.read().await;
        
        if let Some(threat_data) = user_threats.get(&session.user_id) {
            if let Some(user_info) = threat_data.user_threats.get(&session.user_id) {
                // Check for too many concurrent sessions
                return Ok(user_info.concurrent_sessions > 10);
            }
        }
        
        Ok(false)
    }

    /// Determine appropriate actions based on risk score and threats
    async fn determine_actions(
        &self,
        risk_score: f64,
        threats: &[ThreatType],
    ) -> Vec<SecurityAction> {
        let mut actions = Vec::new();

        if risk_score >= self.config.risk_thresholds.auto_revoke_threshold {
            actions.push(SecurityAction::SessionRevoked);
            actions.push(SecurityAction::SecurityNotification);
        } else if risk_score >= self.config.risk_thresholds.mfa_challenge_threshold {
            actions.push(SecurityAction::MfaRequired);
            actions.push(SecurityAction::SecurityNotification);
        } else if risk_score >= self.config.risk_thresholds.notification_threshold {
            actions.push(SecurityAction::SecurityNotification);
        }

        // Specific actions for specific threats
        for threat in threats {
            match threat {
                ThreatType::BruteForceAttack => {
                    actions.push(SecurityAction::IpBlocked);
                }
                ThreatType::RapidSessionCreation => {
                    actions.push(SecurityAction::AccountLocked);
                }
                ThreatType::SuspiciousDevice => {
                    actions.push(SecurityAction::AdditionalVerificationRequired);
                }
                _ => {}
            }
        }

        // Remove duplicates
        actions.sort();
        actions.dedup();
        actions
    }

    /// Block an IP address
    async fn block_ip(&self, ip: IpAddr, duration: Duration) -> Result<(), AppError> {
        let mut ip_threats = self.ip_threats.write().await;
        
        let ip_data = ip_threats.entry(ip).or_insert_with(|| IpThreatData {
            failed_attempts: 0,
            successful_logins: 0,
            first_seen: Utc::now(),
            last_activity: Utc::now(),
            countries: Vec::new(),
            user_agents: Vec::new(),
            is_blocked: false,
            block_expires: None,
            risk_score: 0.0,
        });
        
        ip_data.is_blocked = true;
        ip_data.block_expires = Some(Utc::now() + duration);
        
        // Log the action
        let audit_event = AuditEvent::new(
            AuditEventType::SecurityViolation,
            ip,
            Some("system".to_string()),
            format!("IP {} blocked for {} seconds", ip, duration.num_seconds()),
        )
        .with_outcome(EventOutcome::Success)
        .with_severity(crate::auth::audit::EventSeverity::High);
        
        self.audit_manager.log_event(&audit_event).await?;
        Ok(())
    }

    /// Lock a user account
    async fn lock_user_account(&self, user_id: &str, duration: Duration) -> Result<(), AppError> {
        let mut user_threats = self.user_threats.write().await;
        
        let user_data = user_threats.entry(user_id.to_string()).or_insert_with(|| ThreatData {
            ip_threats: HashMap::new(),
            user_threats: HashMap::new(),
            global_stats: Default::default(),
            last_updated: Utc::now(),
        });
        
        // Update the user threat info within the ThreatData
        let user_info = user_data.user_threats.entry(user_id.to_string()).or_insert_with(|| crate::models::security::UserThreatInfo {
            failed_attempts: 0,
            concurrent_sessions: 0,
            last_successful_login: None,
            recent_ips: Vec::new(),
            recent_locations: Vec::new(),
            is_locked: false,
            lock_expires: None,
            risk_score: 0.0,
            behavioral_profile: None,
        });
        
        user_info.is_locked = true;
        user_info.lock_expires = Some(Utc::now() + duration);
        user_data.last_updated = Utc::now();
        
        // Log the action
        let audit_event = AuditEvent::new(
            AuditEventType::AccountLocked,
            "127.0.0.1".parse().unwrap(), // Default IP for system actions
            None,
            format!("User account locked for {} seconds", duration.num_seconds()),
        )
        .with_user(user_id.to_string())
        .with_outcome(EventOutcome::Success)
        .with_severity(crate::auth::audit::EventSeverity::High);
        
        self.audit_manager.log_event(&audit_event).await?;
        Ok(())
    }

    /// Send security notification
    async fn send_security_notification(
        &self,
        session: &Session,
        evaluation: &ThreatEvaluationResult,
    ) -> Result<(), AppError> {
        // Log security notification
        let audit_event = AuditEvent::new(
            AuditEventType::SystemEvent,
            session.created_ip,
            Some(session.user_agent.clone()),
            format!("Security notification sent - Risk: {:.2}, Threats: {:?}", 
                   evaluation.risk_score, evaluation.threats),
        )
        .with_user(session.user_id.clone())
        .with_outcome(EventOutcome::Success)
        .with_severity(crate::auth::audit::EventSeverity::Medium);
        
        self.audit_manager.log_event(&audit_event).await?;
        Ok(())
    }

    /// Update IP threat data
    pub async fn update_ip_threat_data(
        &self,
        ip: IpAddr,
        success: bool,
        country: Option<String>,
        user_agent: String,
    ) -> Result<(), AppError> {
        let mut ip_threats = self.ip_threats.write().await;
        
        let ip_data = ip_threats.entry(ip).or_insert_with(|| IpThreatData {
            failed_attempts: 0,
            successful_logins: 0,
            first_seen: Utc::now(),
            last_activity: Utc::now(),
            countries: Vec::new(),
            user_agents: Vec::new(),
            is_blocked: false,
            block_expires: None,
            risk_score: 0.0,
        });
        
        ip_data.last_activity = Utc::now();
        
        if success {
            ip_data.successful_logins += 1;
            // Reset failed attempts on successful login
            ip_data.failed_attempts = 0;
        } else {
            ip_data.failed_attempts += 1;
        }
        
        if let Some(country) = country {
            if !ip_data.countries.contains(&country) {
                ip_data.countries.push(country);
            }
        }
        
        if !ip_data.user_agents.contains(&user_agent) {
            ip_data.user_agents.push(user_agent);
        }
        
        // Calculate risk score based on failed attempts and other factors
        ip_data.risk_score = (ip_data.failed_attempts as f64 / self.config.threat_config.max_failed_attempts as f64)
            .min(1.0);
        
        Ok(())
    }

    /// Check if IP is blocked
    pub async fn is_ip_blocked(&self, ip: IpAddr) -> Result<bool, AppError> {
        let ip_threats = self.ip_threats.read().await;
        
        if let Some(ip_data) = ip_threats.get(&ip) {
            if ip_data.is_blocked {
                if let Some(expires) = ip_data.block_expires {
                    return Ok(Utc::now() < expires);
                }
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Check if user is locked
    pub async fn is_user_locked(&self, user_id: &str) -> Result<bool, AppError> {
        let user_threats = self.user_threats.read().await;
        
        if let Some(threat_data) = user_threats.get(user_id) {
            if let Some(user_info) = threat_data.user_threats.get(user_id) {
                if user_info.is_locked {
                    if let Some(expires) = user_info.lock_expires {
                        return Ok(Utc::now() < expires);
                    }
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
}
