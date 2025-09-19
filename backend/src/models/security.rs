use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Unified session metrics for analytics across all auth modules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionMetrics {
    /// Total number of sessions
    pub total_sessions: usize,
    /// Currently active sessions
    pub active_sessions: usize,
    /// Sessions flagged as suspicious
    pub suspicious_sessions: usize,
    /// Sessions grouped by security level
    pub sessions_by_security_level: HashMap<String, usize>,
    /// Recent session activities
    pub recent_activities: Vec<SessionActivity>,
    /// Failed login attempts
    pub failed_attempts: u32,
    /// Concurrent sessions count
    pub concurrent_sessions: u32,
    /// Average session duration in seconds
    pub average_session_duration: u64,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Session activity for tracking and analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionActivity {
    /// Session ID
    pub session_id: String,
    /// Activity type
    pub activity_type: ActivityType,
    /// Timestamp of activity
    pub timestamp: DateTime<Utc>,
    /// IP address
    pub ip_address: IpAddr,
    /// User agent
    pub user_agent: String,
    /// Additional details
    pub details: HashMap<String, String>,
}

/// Types of session activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityType {
    SessionCreated,
    SessionRefreshed,
    SessionRevoked,
    SecurityValidation,
    SuspiciousActivity,
    PrivilegeEscalation,
    LocationChange,
    DeviceChange,
    LoginAttempt,
    LogoutEvent,
}

/// Unified security configuration for all auth modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Risk score thresholds
    pub risk_thresholds: RiskThresholds,
    /// Session binding configuration
    pub binding_config: BindingConfig,
    /// Threat detection configuration
    pub threat_config: ThreatConfig,
    /// Audit configuration
    pub audit_config: AuditConfig,
    /// Behavioral analysis configuration
    pub behavioral_config: BehavioralConfig,
}

/// Risk score thresholds for various security actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Risk score threshold for automatic session revocation
    pub auto_revoke_threshold: f64,
    /// Risk score threshold for MFA challenge
    pub mfa_challenge_threshold: f64,
    /// Risk score threshold for security notifications
    pub notification_threshold: f64,
    /// Risk score threshold for additional verification
    pub verification_threshold: f64,
    /// Risk score threshold for account locking
    pub lock_threshold: f64,
}

/// Configuration for session binding security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingConfig {
    /// Whether to enforce IP binding
    pub enforce_ip_binding: bool,
    /// Whether to enforce device binding
    pub enforce_device_binding: bool,
    /// Whether to enforce TLS binding
    pub enforce_tls_binding: bool,
    /// Maximum allowed IP changes
    pub max_ip_changes: u32,
    /// Time window for IP change tracking (in minutes)
    pub ip_change_window: i64,
    /// Whether to allow mobile IP changes
    pub allow_mobile_ip_changes: bool,
}

/// Configuration for threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatConfig {
    /// Maximum allowed failed attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in seconds
    pub lockout_duration: u64,
    /// Enable brute force detection
    pub enable_brute_force_detection: bool,
    /// Enable anomalous location detection
    pub enable_location_detection: bool,
    /// Enable device fingerprinting
    pub enable_device_fingerprinting: bool,
    /// Enable behavioral analysis
    pub enable_behavioral_analysis: bool,
}

/// Configuration for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    /// Log file path
    pub log_file_path: String,
    /// Maximum log file size in bytes
    pub max_file_size: u64,
    /// Number of log files to retain
    pub max_files: u32,
    /// Whether to log successful events
    pub log_success: bool,
    /// Whether to log failed events
    pub log_failures: bool,
    /// Minimum severity level to log
    pub min_severity: EventSeverity,
}

/// Configuration for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Enable login pattern analysis
    pub enable_login_patterns: bool,
    /// Enable location tracking
    pub enable_location_tracking: bool,
    /// Enable device tracking
    pub enable_device_tracking: bool,
    /// Number of days to retain behavioral data
    pub retention_days: u32,
    /// Minimum data points required for analysis
    pub min_data_points: u32,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security levels for sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub enum SecurityLevel {
    /// Low security - basic authentication
    Low,
    /// Standard security - normal user operations
    Standard,
    /// High security - sensitive operations
    High,
    /// Critical security - highest level operations
    Critical,
    /// Administrative - admin operations
    Administrative,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Standard
    }
}

/// Security event tracking for sessions
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

/// Unified risk assessment structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk score (0.0 to 1.0)
    pub risk_score: f64,
    /// Individual risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Confidence level of assessment
    pub confidence: f64,
    /// Timestamp of assessment
    pub assessed_at: DateTime<Utc>,
    /// Recommended actions
    pub recommended_actions: Vec<SecurityAction>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Individual risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Type of risk factor
    pub factor_type: RiskFactorType,
    /// Weight of this factor (0.0 to 1.0)
    pub weight: f64,
    /// Description of the risk
    pub description: String,
    /// Severity level
    pub severity: EventSeverity,
}

/// Types of risk factors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskFactorType {
    UnknownIpAddress,
    UnknownDevice,
    UnusualLoginTime,
    MultipleFailedAttempts,
    ConcurrentSessions,
    LocationChange,
    SuspiciousUserAgent,
    HighVelocityRequests,
    AnomalousLocation,
    VpnProxyUsage,
    DeviceFingerprinting,
    BehavioralAnomaly,
    ThreatIntelligence,
}

/// Security actions that can be taken
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum SecurityAction {
    SessionRevoked,
    MfaRequired,
    SecurityNotification,
    AccountLocked,
    IpBlocked,
    DeviceBlocked,
    AdditionalVerificationRequired,
    PasswordResetRequired,
    ContactSupport,
    MonitorActivity,
}

/// Unified threat data for tracking across IP addresses and users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatData {
    /// IP-based threat information
    pub ip_threats: HashMap<IpAddr, IpThreatInfo>,
    /// User-based threat information
    pub user_threats: HashMap<String, UserThreatInfo>,
    /// Global threat statistics
    pub global_stats: ThreatStatistics,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// IP-based threat tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpThreatInfo {
    /// Failed login attempts from this IP
    pub failed_attempts: u32,
    /// Successful logins from this IP
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
    /// Threat intelligence data
    pub threat_intel: Option<ThreatIntelligence>,
}

/// User-based threat tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserThreatInfo {
    /// Failed login attempts for this user
    pub failed_attempts: u32,
    /// Concurrent sessions count
    pub concurrent_sessions: u32,
    /// Last successful login
    pub last_successful_login: Option<DateTime<Utc>>,
    /// Recent IP addresses used
    pub recent_ips: Vec<IpAddr>,
    /// Recent locations
    pub recent_locations: Vec<String>,
    /// Account locked status
    pub is_locked: bool,
    /// Lock expiration if applicable
    pub lock_expires: Option<DateTime<Utc>>,
    /// Risk score for this user
    pub risk_score: f64,
    /// Behavioral profile
    pub behavioral_profile: Option<BehavioralProfile>,
}

/// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// Whether IP is known malicious
    pub is_malicious: bool,
    /// Threat categories
    pub categories: Vec<String>,
    /// Confidence score
    pub confidence: f64,
    /// Source of intelligence
    pub source: String,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

/// Behavioral profile for users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    /// Typical login hours (0-23)
    pub typical_login_hours: Vec<u8>,
    /// Frequently used IP addresses
    pub frequent_locations: Vec<IpAddr>,
    /// Average session duration in seconds
    pub average_session_duration: u64,
    /// Typical user agents
    pub typical_user_agents: Vec<String>,
    /// Typical devices
    pub typical_devices: Vec<String>,
    /// Geographic locations (country codes)
    pub typical_countries: Vec<String>,
    /// Time zones typically used
    pub typical_timezones: Vec<String>,
    /// Login frequency patterns (day of week)
    pub login_patterns: HashMap<u8, u32>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Global threat statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatStatistics {
    /// Total threats detected
    pub total_threats: u64,
    /// Active threats
    pub active_threats: u64,
    /// Blocked IPs count
    pub blocked_ips: u64,
    /// Locked accounts count
    pub locked_accounts: u64,
    /// Threats by type
    pub threats_by_type: HashMap<String, u64>,
    /// Last 24 hours statistics
    pub last_24h_stats: DailyStats,
}

/// Daily threat statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DailyStats {
    /// Failed login attempts
    pub failed_logins: u64,
    /// Successful logins
    pub successful_logins: u64,
    /// New threats detected
    pub new_threats: u64,
    /// Actions taken
    pub actions_taken: u64,
}

/// Default implementations
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            risk_thresholds: RiskThresholds::default(),
            binding_config: BindingConfig::default(),
            threat_config: ThreatConfig::default(),
            audit_config: AuditConfig::default(),
            behavioral_config: BehavioralConfig::default(),
        }
    }
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            auto_revoke_threshold: 0.8,
            mfa_challenge_threshold: 0.6,
            notification_threshold: 0.4,
            verification_threshold: 0.5,
            lock_threshold: 0.9,
        }
    }
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            enforce_ip_binding: true,
            enforce_device_binding: true,
            enforce_tls_binding: false,
            max_ip_changes: 3,
            ip_change_window: 60,
            allow_mobile_ip_changes: true,
        }
    }
}

impl Default for ThreatConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: 900, // 15 minutes
            enable_brute_force_detection: true,
            enable_location_detection: true,
            enable_device_fingerprinting: true,
            enable_behavioral_analysis: true,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file_path: "logs/audit.log".to_string(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            log_success: true,
            log_failures: true,
            min_severity: EventSeverity::Low,
        }
    }
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            enable_login_patterns: true,
            enable_location_tracking: true,
            enable_device_tracking: true,
            retention_days: 90,
            min_data_points: 5,
        }
    }
}

impl RiskAssessment {
    /// Create a new risk assessment
    pub fn new(risk_score: f64) -> Self {
        Self {
            risk_score,
            risk_factors: Vec::new(),
            confidence: 1.0,
            assessed_at: Utc::now(),
            recommended_actions: Vec::new(),
            context: HashMap::new(),
        }
    }

    /// Add a risk factor to the assessment
    pub fn add_risk_factor(&mut self, factor: RiskFactor) {
        self.risk_factors.push(factor);
    }

    /// Add a recommended action
    pub fn add_action(&mut self, action: SecurityAction) {
        if !self.recommended_actions.contains(&action) {
            self.recommended_actions.push(action);
        }
    }

    /// Calculate overall risk score based on factors
    pub fn calculate_risk_score(&mut self) {
        if self.risk_factors.is_empty() {
            self.risk_score = 0.0;
            return;
        }

        let total_weight: f64 = self.risk_factors.iter().map(|f| f.weight).sum();
        if total_weight > 0.0 {
            self.risk_score = self.risk_factors.iter()
                .map(|f| f.weight)
                .sum::<f64>() / total_weight;
        }

        // Ensure risk score is between 0.0 and 1.0
        self.risk_score = self.risk_score.clamp(0.0, 1.0);
    }
}

impl RiskFactor {
    /// Create a new risk factor
    pub fn new(factor_type: RiskFactorType, weight: f64, description: String, severity: EventSeverity) -> Self {
        Self {
            factor_type,
            weight: weight.clamp(0.0, 1.0),
            description,
            severity,
        }
    }
}