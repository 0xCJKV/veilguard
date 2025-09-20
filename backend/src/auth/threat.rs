use chrono::{Utc, Duration};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::errors::AppError;
use crate::models::ses::{Session};
use crate::models::security::{
    SecurityConfig, SecurityAction, RiskAssessment, ThreatData, SecurityLevel, GeoLocation,
    ThreatType, ActiveThreat, ThreatEvaluationResult, IpThreatData, RiskFactor, RiskFactorType
};
use crate::auth::behavioral::{BehaviorAnalytics};
use crate::auth::audit::{AuditEvent, AuditEventType, EventOutcome, AuditManager};

/// Real-time threat detection engine
pub struct ThreatDetectionEngine {
    /// Configuration for threat response (now using SecurityConfig from models/security.rs)
    pub config: SecurityConfig,
    /// Audit manager for logging security events
    pub audit_manager: Arc<AuditManager>,
    /// Active threat tracking (now using ActiveThreat from models/security.rs)
    pub active_threats: Arc<RwLock<HashMap<String, ActiveThreat>>>,
    /// IP-based threat tracking (now using IpThreatData from models/security.rs)
    pub ip_threats: Arc<RwLock<HashMap<IpAddr, IpThreatData>>>,
    /// User-based threat tracking (now using ThreatData from models/security.rs)
    pub user_threats: Arc<RwLock<HashMap<String, ThreatData>>>,
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
        let mut risk_assessment = RiskAssessment::new(0.0);

        // Check for brute force attacks
        if let Some(_threat) = self.detect_brute_force(session.created_ip).await? {
            threats.push(ThreatType::BruteForceAttack);
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::MultipleFailedAttempts,
                0.8,
                "Multiple failed login attempts detected from IP".to_string(),
                SecurityLevel::High,
            ));
        }

        // Check for anomalous location
        if self.is_anomalous_location(session, geo_data).await? {
            threats.push(ThreatType::AnomalousLocation);
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::AnomalousLocation,
                0.6,
                "Login from unusual geographic location".to_string(),
                SecurityLevel::High,
            ));
        }

        // Check for suspicious device
        if self.is_suspicious_device(session, user_behavior).await? {
            threats.push(ThreatType::SuspiciousDevice);
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::UnknownDevice,
                0.5,
                "Login from unrecognized device".to_string(),
                SecurityLevel::High,
            ));
        }

        // Check for rapid session creation
        if self.detect_rapid_session_creation(&session.user_id).await? {
            threats.push(ThreatType::RapidSessionCreation);
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::HighVelocityRequests,
                0.7,
                "Rapid session creation detected".to_string(),
                SecurityLevel::High,
            ));
        }

        // Check for concurrent session anomalies
        if self.detect_concurrent_session_anomaly(session).await? {
            threats.push(ThreatType::ConcurrentSessionAnomaly);
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::ConcurrentSessions,
                0.4,
                "Unusual number of concurrent sessions".to_string(),
                SecurityLevel::High,
            ));
        }

        // Check for VPN/Proxy usage
        if geo_data.is_vpn_proxy {
            risk_assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::VpnProxyUsage,
                0.3,
                "VPN or proxy usage detected".to_string(),
                SecurityLevel::Low,
            ));
        }

        // Calculate final risk score
        risk_assessment.calculate_risk_score();
        let risk_score = risk_assessment.risk_score;

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
            if ip_data.base.failed_attempts >= self.config.threat_config.max_failed_attempts {
                let threat = ActiveThreat {
                    id: format!("brute_force_{}", ip),
                    threat_type: ThreatType::BruteForceAttack,
                    risk_score: 0.9,
                    first_detected: ip_data.base.first_seen,
                    last_updated: Utc::now(),
                    source_ip: ip,
                    user_id: None,
                    session_id: None,
                    details: HashMap::from([
                        ("failed_attempts".to_string(), ip_data.base.failed_attempts.to_string()),
                        ("countries".to_string(), ip_data.base.countries.join(", ")),
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

        // Determine security level based on risk score
        let security_level = self.determine_security_level(risk_score);

        // Apply actions based on security level
        match security_level {
            SecurityLevel::Critical => {
                actions.push(SecurityAction::SessionRevoked);
                actions.push(SecurityAction::AccountLocked);
                actions.push(SecurityAction::SecurityNotification);
                actions.push(SecurityAction::ContactSupport);
            }
            SecurityLevel::High => {
                actions.push(SecurityAction::SessionRevoked);
                actions.push(SecurityAction::SecurityNotification);
                actions.push(SecurityAction::AdditionalVerificationRequired);
            }
            SecurityLevel::Medium => {
                actions.push(SecurityAction::MfaRequired);
                actions.push(SecurityAction::SecurityNotification);
                actions.push(SecurityAction::MonitorActivity);
            }
            SecurityLevel::Low => {
                actions.push(SecurityAction::SecurityNotification);
            }
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
                    actions.push(SecurityAction::DeviceBlocked);
                    actions.push(SecurityAction::AdditionalVerificationRequired);
                }
                ThreatType::AnomalousLocation => {
                    actions.push(SecurityAction::AdditionalVerificationRequired);
                }
                ThreatType::ConcurrentSessionAnomaly => {
                    actions.push(SecurityAction::MonitorActivity);
                }
                ThreatType::CredentialStuffing => {
                    actions.push(SecurityAction::IpBlocked);
                    actions.push(SecurityAction::PasswordResetRequired);
                }
                ThreatType::SessionHijacking => {
                    actions.push(SecurityAction::SessionRevoked);
                    actions.push(SecurityAction::ContactSupport);
                }
                ThreatType::PrivilegeEscalation => {
                    actions.push(SecurityAction::SessionRevoked);
                    actions.push(SecurityAction::AccountLocked);
                    actions.push(SecurityAction::ContactSupport);
                }
                ThreatType::TokenAbuse => {
                    actions.push(SecurityAction::SessionRevoked);
                    actions.push(SecurityAction::AdditionalVerificationRequired);
                }
                ThreatType::BehavioralAnomaly => {
                    actions.push(SecurityAction::MonitorActivity);
                    actions.push(SecurityAction::AdditionalVerificationRequired);
                }
            }
        }

        // Remove duplicates
        actions.sort();
        actions.dedup();
        actions
    }

    /// Determine security level based on risk score
    fn determine_security_level(&self, risk_score: f64) -> SecurityLevel {
        if risk_score >= 0.9 {
            SecurityLevel::Critical
        } else if risk_score >= 0.7 {
            SecurityLevel::High
        } else if risk_score >= 0.4 {
            SecurityLevel::Medium
        } else {
            SecurityLevel::Low
        }
    }

    /// Block an IP address
    async fn block_ip(&self, ip: IpAddr, duration: Duration) -> Result<(), AppError> {
        let mut ip_threats = self.ip_threats.write().await;
        
        let ip_data = ip_threats.entry(ip).or_insert_with(|| IpThreatData {
            base: crate::models::security::IpThreatInfo {
                failed_attempts: 0,
                successful_logins: 0,
                first_seen: Utc::now(),
                last_activity: Utc::now(),
                countries: Vec::new(),
                user_agents: Vec::new(),
                is_blocked: false,
                block_expires: None,
                risk_score: 0.0,
                threat_intel: None,
            },
            first_flagged: Utc::now(),
            last_updated: Utc::now(),
        });
        
        ip_data.base.is_blocked = true;
        ip_data.base.block_expires = Some(Utc::now() + duration);
        
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
            base: crate::models::security::IpThreatInfo {
                failed_attempts: 0,
                successful_logins: 0,
                first_seen: Utc::now(),
                last_activity: Utc::now(),
                countries: Vec::new(),
                user_agents: Vec::new(),
                is_blocked: false,
                block_expires: None,
                risk_score: 0.0,
                threat_intel: None,
            },
            first_flagged: Utc::now(),
            last_updated: Utc::now(),
        });
        
        ip_data.base.last_activity = Utc::now();
        ip_data.last_updated = Utc::now();
        
        if success {
            ip_data.base.successful_logins += 1;
            // Reset failed attempts on successful login
            ip_data.base.failed_attempts = 0;
        } else {
            ip_data.base.failed_attempts += 1;
        }
        
        if let Some(country) = country {
            if !ip_data.base.countries.contains(&country) {
                ip_data.base.countries.push(country);
            }
        }
        
        if !ip_data.base.user_agents.contains(&user_agent) {
            ip_data.base.user_agents.push(user_agent);
        }
        
        // Calculate risk score based on failed attempts and other factors
        ip_data.base.risk_score = (ip_data.base.failed_attempts as f64 / self.config.threat_config.max_failed_attempts as f64)
            .min(1.0);
        
        Ok(())
    }

    /// Check if IP is blocked
    pub async fn is_ip_blocked(&self, ip: IpAddr) -> Result<bool, AppError> {
        let ip_threats = self.ip_threats.read().await;
        
        if let Some(ip_data) = ip_threats.get(&ip) {
            if ip_data.base.is_blocked {
                if let Some(expires) = ip_data.base.block_expires {
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
