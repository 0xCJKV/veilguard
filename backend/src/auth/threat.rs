use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::errors::AppError;
use crate::models::ses::{Session, SecurityLevel};
use crate::auth::behavioral::{BehaviorAnalytics, GeoLocation, ThreatAction, ThreatResponse};
use crate::auth::audit::{AuditEvent, AuditEventType, EventOutcome, EventSeverity, AuditManager};

/// Real-time threat detection engine
pub struct ThreatDetectionEngine {
    /// Configuration for threat response
    pub config: ThreatResponse,
    /// Audit manager for logging security events
    pub audit_manager: Arc<AuditManager>,
    /// Active threat tracking
    pub active_threats: Arc<RwLock<HashMap<String, ActiveThreat>>>,
    /// IP-based threat tracking
    pub ip_threats: Arc<RwLock<HashMap<IpAddr, IpThreatData>>>,
    /// User-based threat tracking
    pub user_threats: Arc<RwLock<HashMap<String, UserThreatData>>>,
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
    /// Actions taken
    pub actions_taken: Vec<ThreatAction>,
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

/// User-based threat tracking data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserThreatData {
    /// Failed login attempts
    pub failed_attempts: u32,
    /// Concurrent sessions count
    pub concurrent_sessions: u32,
    /// Last successful login
    pub last_successful_login: Option<DateTime<Utc>>,
    /// Recent IP addresses
    pub recent_ips: Vec<IpAddr>,
    /// Recent locations
    pub recent_locations: Vec<String>,
    /// Account locked status
    pub is_locked: bool,
    /// Lock expiration if applicable
    pub lock_expires: Option<DateTime<Utc>>,
    /// Risk score for this user
    pub risk_score: f64,
}

/// Threat evaluation result
#[derive(Debug)]
pub struct ThreatEvaluationResult {
    /// Overall risk score
    pub risk_score: f64,
    /// Detected threats
    pub threats: Vec<ThreatType>,
    /// Recommended actions
    pub recommended_actions: Vec<ThreatAction>,
    /// Whether immediate action is required
    pub requires_immediate_action: bool,
}

impl ThreatDetectionEngine {
    /// Create a new threat detection engine
    pub fn new(config: ThreatResponse, audit_manager: Arc<AuditManager>) -> Self {
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
        let mut recommended_actions = Vec::new();
        let mut risk_score = session.calculate_enhanced_risk_score(user_behavior, geo_data);

        // Check for brute force attacks
        if let Some(brute_force_threat) = self.detect_brute_force(session.created_ip).await? {
            threats.push(ThreatType::BruteForceAttack);
            risk_score += 0.3;
            recommended_actions.push(ThreatAction::IpBlocked);
        }

        // Check for anomalous location
        if geo_data.is_vpn_proxy || self.is_anomalous_location(session, geo_data).await? {
            threats.push(ThreatType::AnomalousLocation);
            risk_score += 0.2;
            recommended_actions.push(ThreatAction::AdditionalVerificationRequired);
        }

        // Check for suspicious device
        if self.is_suspicious_device(session, user_behavior).await? {
            threats.push(ThreatType::SuspiciousDevice);
            risk_score += 0.15;
            recommended_actions.push(ThreatAction::DeviceBlocked);
        }

        // Check for rapid session creation
        if self.detect_rapid_session_creation(&session.user_id).await? {
            threats.push(ThreatType::RapidSessionCreation);
            risk_score += 0.25;
            recommended_actions.push(ThreatAction::AccountLocked);
        }

        // Check for concurrent session anomalies
        if self.detect_concurrent_session_anomaly(session).await? {
            threats.push(ThreatType::ConcurrentSessionAnomaly);
            risk_score += 0.2;
            recommended_actions.push(ThreatAction::MfaRequired);
        }

        // Determine final actions based on risk score
        let final_actions = self.determine_actions(risk_score, &threats).await;

        let requires_immediate_action = risk_score >= self.config.auto_revoke_threshold
            || threats.contains(&ThreatType::BruteForceAttack)
            || threats.contains(&ThreatType::CredentialStuffing);

        Ok(ThreatEvaluationResult {
            risk_score: risk_score.min(1.0),
            threats,
            recommended_actions: final_actions,
            requires_immediate_action,
        })
    }

    /// Execute threat response actions
    pub async fn execute_threat_response(
        &self,
        session: &mut Session,
        evaluation: &ThreatEvaluationResult,
    ) -> Result<Vec<ThreatAction>, AppError> {
        let mut executed_actions = Vec::new();

        for action in &evaluation.recommended_actions {
            match action {
                ThreatAction::SessionRevoked => {
                    session.revoke(Some("High risk score detected"));
                    executed_actions.push(ThreatAction::SessionRevoked);
                    
                    // Log audit event
                    let audit_event = AuditEvent::new(
                        AuditEventType::SessionRevoked,
                        session.created_ip,
                        Some(session.user_agent.clone()),
                        "threat-detection".to_string(),
                    )
                    .with_user(session.user_id.clone())
                    .with_session(session.id.clone())
                    .with_risk_score(evaluation.risk_score)
                    .with_severity(EventSeverity::High)
                    .with_metadata("reason".to_string(), "threat_detected".to_string());

                    self.audit_manager.log_event(&audit_event).await?;
                }
                ThreatAction::MfaRequired => {
                    session.flags.requires_mfa = true;
                    executed_actions.push(ThreatAction::MfaRequired);
                }
                ThreatAction::IpBlocked => {
                    self.block_ip(session.created_ip, Duration::hours(1)).await?;
                    executed_actions.push(ThreatAction::IpBlocked);
                }
                ThreatAction::AccountLocked => {
                    self.lock_user_account(&session.user_id, Duration::minutes(15)).await?;
                    executed_actions.push(ThreatAction::AccountLocked);
                }
                ThreatAction::SecurityNotification => {
                    self.send_security_notification(session, evaluation).await?;
                    executed_actions.push(ThreatAction::SecurityNotification);
                }
                _ => {
                    // Other actions would be implemented here
                }
            }
        }

        Ok(executed_actions)
    }

    /// Detect brute force attacks from an IP
    async fn detect_brute_force(&self, ip: IpAddr) -> Result<Option<ActiveThreat>, AppError> {
        let ip_threats = self.ip_threats.read().await;
        
        if let Some(ip_data) = ip_threats.get(&ip) {
            let time_window = Utc::now() - Duration::minutes(5);
            
            if ip_data.last_activity > time_window && ip_data.failed_attempts > 10 {
                return Ok(Some(ActiveThreat {
                    id: uuid::Uuid::new_v4().to_string(),
                    threat_type: ThreatType::BruteForceAttack,
                    risk_score: 0.8,
                    first_detected: ip_data.first_seen,
                    last_updated: Utc::now(),
                    source_ip: ip,
                    user_id: None,
                    session_id: None,
                    details: HashMap::from([
                        ("failed_attempts".to_string(), ip_data.failed_attempts.to_string()),
                        ("time_window".to_string(), "5_minutes".to_string()),
                    ]),
                    actions_taken: Vec::new(),
                }));
            }
        }

        Ok(None)
    }

    /// Check if location is anomalous for the user
    async fn is_anomalous_location(
        &self,
        _session: &Session,
        geo_data: &GeoLocation,
    ) -> Result<bool, AppError> {
        // Implementation would check against user's typical locations
        // For now, simple heuristic based on VPN/proxy detection
        Ok(geo_data.is_vpn_proxy)
    }

    /// Check if device is suspicious
    async fn is_suspicious_device(
        &self,
        session: &Session,
        user_behavior: &BehaviorAnalytics,
    ) -> Result<bool, AppError> {
        // Check if device fingerprint is in typical devices
        Ok(!user_behavior.typical_devices.contains(&session.device_fingerprint))
    }

    /// Detect rapid session creation
    async fn detect_rapid_session_creation(&self, user_id: &str) -> Result<bool, AppError> {
        let user_threats = self.user_threats.read().await;
        
        if let Some(user_data) = user_threats.get(user_id) {
            // Check if more than 5 sessions created in last 5 minutes
            return Ok(user_data.concurrent_sessions > 5);
        }

        Ok(false)
    }

    /// Detect concurrent session anomalies
    async fn detect_concurrent_session_anomaly(&self, session: &Session) -> Result<bool, AppError> {
        // Check if concurrent sessions exceed normal patterns
        let max_allowed = match session.security_level {
            SecurityLevel::Administrative => 2,
            SecurityLevel::High => 3,
            SecurityLevel::Standard => 5,
            SecurityLevel::Low => 10,
            SecurityLevel::Critical => 1, // Most restrictive for critical security level
        };

        Ok(session.metadata.concurrent_sessions > max_allowed)
    }

    /// Determine actions based on risk score and threats
    async fn determine_actions(
        &self,
        risk_score: f64,
        threats: &[ThreatType],
    ) -> Vec<ThreatAction> {
        let mut actions = Vec::new();

        if risk_score >= self.config.auto_revoke_threshold {
            actions.push(ThreatAction::SessionRevoked);
        } else if risk_score >= self.config.mfa_challenge_threshold {
            actions.push(ThreatAction::MfaRequired);
        }

        if risk_score >= self.config.notification_threshold {
            actions.push(ThreatAction::SecurityNotification);
        }

        // Specific threat-based actions
        for threat in threats {
            match threat {
                ThreatType::BruteForceAttack => {
                    actions.push(ThreatAction::IpBlocked);
                }
                ThreatType::RapidSessionCreation => {
                    actions.push(ThreatAction::AccountLocked);
                }
                ThreatType::SuspiciousDevice => {
                    actions.push(ThreatAction::DeviceBlocked);
                }
                _ => {}
            }
        }

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
        ip_data.risk_score = 1.0;

        Ok(())
    }

    /// Lock a user account
    async fn lock_user_account(&self, user_id: &str, duration: Duration) -> Result<(), AppError> {
        let mut user_threats = self.user_threats.write().await;
        
        let user_data = user_threats.entry(user_id.to_string()).or_insert_with(|| UserThreatData {
            failed_attempts: 0,
            concurrent_sessions: 0,
            last_successful_login: None,
            recent_ips: Vec::new(),
            recent_locations: Vec::new(),
            is_locked: false,
            lock_expires: None,
            risk_score: 0.0,
        });

        user_data.is_locked = true;
        user_data.lock_expires = Some(Utc::now() + duration);
        user_data.risk_score = 0.8;

        Ok(())
    }

    /// Send security notification
    async fn send_security_notification(
        &self,
        session: &Session,
        evaluation: &ThreatEvaluationResult,
    ) -> Result<(), AppError> {
        // Implementation would send notifications via email, SMS, etc.
        println!(
            "SECURITY NOTIFICATION: High risk session detected for user {} from IP {} with risk score {}",
            session.user_id, session.created_ip, evaluation.risk_score
        );
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
            ip_data.failed_attempts = 0; // Reset on successful login
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

        // Calculate risk score based on failed attempts
        ip_data.risk_score = (ip_data.failed_attempts as f64 / 20.0).min(1.0);

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

    /// Check if user account is locked
    pub async fn is_user_locked(&self, user_id: &str) -> Result<bool, AppError> {
        let user_threats = self.user_threats.read().await;
        
        if let Some(user_data) = user_threats.get(user_id) {
            if user_data.is_locked {
                if let Some(expires) = user_data.lock_expires {
                    return Ok(Utc::now() < expires);
                }
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::models::ses::{SessionMetadata, SessionFlags};

    #[tokio::test]
    async fn test_threat_detection() {
        let audit_manager = Arc::new(AuditManager::new());
        let engine = ThreatDetectionEngine::new(ThreatResponse::default(), audit_manager);

        // Test IP blocking
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        engine.update_ip_threat_data(ip, false, Some("US".to_string()), "test-agent".to_string()).await.unwrap();
        
        // Simulate multiple failed attempts
        for _ in 0..15 {
            engine.update_ip_threat_data(ip, false, Some("US".to_string()), "test-agent".to_string()).await.unwrap();
        }

        let brute_force = engine.detect_brute_force(ip).await.unwrap();
        assert!(brute_force.is_some());
    }

    #[tokio::test]
    async fn test_ip_blocking() {
        let audit_manager = Arc::new(AuditManager::new());
        let engine = ThreatDetectionEngine::new(ThreatResponse::default(), audit_manager);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // IP should not be blocked initially
        assert!(!engine.is_ip_blocked(ip).await.unwrap());

        // Block the IP
        engine.block_ip(ip, Duration::minutes(5)).await.unwrap();

        // IP should now be blocked
        assert!(engine.is_ip_blocked(ip).await.unwrap());
    }
}