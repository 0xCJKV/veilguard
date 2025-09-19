use chrono::{DateTime, Utc, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::errors::AppError;

/// Session data structure with comprehensive security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Session token for authentication
    pub token: String,
    /// User ID associated with this session
    pub user_id: String,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Session expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// IP address when session was created
    pub created_ip: IpAddr,
    /// Last known IP address
    pub last_ip: IpAddr,
    /// Device fingerprint for security validation
    pub device_fingerprint: String,
    /// User agent string
    pub user_agent: String,
    /// Device name (optional)
    pub device_name: Option<String>,
    /// Application identifier (optional)
    pub application: Option<String>,
    /// Session security level
    pub security_level: SecurityLevel,
    /// Session metadata
    pub metadata: SessionMetadata,
    /// Session flags for various states
    pub flags: SessionFlags,
}

/// Security levels for sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum SecurityLevel {
    /// Low security - basic authentication
    Low,
    /// Standard security - normal user operations
    Standard,
    /// High security - sensitive operations
    High,
    /// Administrative - admin operations
    Administrative,
}

/// Session metadata containing additional security information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Login method used (password, oauth, etc.)
    pub login_method: String,
    /// Whether MFA was verified
    pub mfa_verified: bool,
    /// Risk score calculated for this session
    pub risk_score: f64,
    /// Number of concurrent sessions for this user
    pub concurrent_sessions: u32,
    /// Number of failed login attempts
    pub failed_attempts: u32,
    /// Last password change timestamp
    pub last_password_change: Option<DateTime<Utc>>,
    /// User permissions for this session
    pub permissions: Vec<String>,
    /// Custom metadata
    pub custom_data: HashMap<String, String>,
}

/// Session state flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFlags {
    /// Whether the session is currently active
    pub is_active: bool,
    /// Whether the session has expired
    pub is_expired: bool,
    /// Whether the session has been revoked
    pub is_revoked: bool,
    /// Whether the session is flagged as suspicious
    pub is_suspicious: bool,
    /// Whether the session requires MFA verification
    pub requires_mfa: bool,
    /// Whether the session has elevated privileges
    pub has_elevated_privileges: bool,
    /// Whether concurrent session limits apply
    pub is_concurrent_limited: bool,
    /// Whether the session is locked to specific IP
    pub is_ip_locked: bool,
}

/// Request for creating a new session
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub user_id: String,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub login_method: String,
    pub security_level: Option<SecurityLevel>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Result of session validation
#[derive(Debug)]
pub struct SessionValidationResult {
    pub is_valid: bool,
    pub session: Option<Session>,
    pub validation_errors: Vec<ValidationError>,
    pub security_warnings: Vec<SecurityWarning>,
}

/// Session validation errors
#[derive(Debug, Clone)]
pub enum ValidationError {
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    InvalidToken,
    IpMismatch,
    DeviceMismatch,
    SecurityLevelInsufficient,
    ConcurrentSessionLimitExceeded,
    SuspiciousActivity,
}

/// Security warnings for sessions
#[derive(Debug, Clone)]
pub enum SecurityWarning {
    NewIpAddress,
    NewDevice,
    UnusualActivity,
    HighRiskScore,
    ConcurrentSessionDetected,
    LocationChange,
    TimeZoneChange,
}

/// Session activity tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionActivity {
    pub session_id: String,
    pub activity_type: ActivityType,
    pub timestamp: DateTime<Utc>,
    pub ip_address: IpAddr,
    pub user_agent: String,
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
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Default session lifetime in seconds
    pub default_lifetime: u64,
    /// Maximum session lifetime in seconds
    pub max_lifetime: u64,
    /// Refresh threshold in seconds
    pub refresh_threshold: u64,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
    /// Whether to enforce IP validation
    pub enforce_ip_validation: bool,
    /// Whether to enforce device validation
    pub enforce_device_validation: bool,
    /// Whether to enable suspicious activity detection
    pub enable_suspicious_detection: bool,
    /// Cleanup interval in seconds
    pub cleanup_interval: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_lifetime: 3600,        // 1 hour
            max_lifetime: 86400,           // 24 hours
            refresh_threshold: 1800,       // 30 minutes
            max_concurrent_sessions: 5,
            enforce_ip_validation: true,
            enforce_device_validation: true,
            enable_suspicious_detection: true,
            cleanup_interval: 300,         // 5 minutes
        }
    }
}

impl Session {
    /// Create a new session
    pub fn new(
        user_id: String,
        ip_address: IpAddr,
        user_agent: String,
        device_fingerprint: String,
        security_level: SecurityLevel,
        device_name: Option<String>,
        application: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let id = uuid::Uuid::new_v4().to_string();
        let token = Self::generate_secure_token();
        
        // Set expiration based on security level
        let expires_at = match security_level {
            SecurityLevel::Low => now + chrono::Duration::hours(24),
            SecurityLevel::Standard => now + chrono::Duration::hours(8),
            SecurityLevel::High => now + chrono::Duration::hours(2),
            SecurityLevel::Administrative => now + chrono::Duration::hours(1),
        };

        Self {
            id,
            token,
            user_id,
            created_at: now,
            last_activity: now,
            expires_at,
            created_ip: ip_address,
            last_ip: ip_address,
            device_fingerprint,
            user_agent,
            device_name,
            application,
            security_level,
            metadata: SessionMetadata::default(),
            flags: SessionFlags::default(),
        }
    }

    /// Generate a secure session token
    fn generate_secure_token() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..64)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is valid
    pub fn is_valid(&self) -> bool {
        self.flags.is_active && !self.is_expired() && !self.flags.is_revoked
    }

    /// Update session activity
    pub fn update_activity(&mut self, ip_address: IpAddr) {
        self.last_activity = Utc::now();
        self.last_ip = ip_address;
    }

    /// Mark session as suspicious
    pub fn mark_suspicious(&mut self, reason: &str) {
        self.flags.is_suspicious = true;
        self.metadata.custom_data.insert("suspicious_reason".to_string(), reason.to_string());
    }

    /// Revoke the session
    pub fn revoke(&mut self, reason: Option<&str>) {
        self.flags.is_revoked = true;
        self.flags.is_active = false;
        if let Some(reason) = reason {
            self.metadata.custom_data.insert("revoke_reason".to_string(), reason.to_string());
        }
    }

    /// Extend session expiry
    pub fn extend_expiry(&mut self, duration: chrono::Duration) {
        if !self.flags.is_revoked {
            self.expires_at = self.expires_at + duration;
        }
    }

    /// Calculate risk score based on known patterns
    pub fn calculate_risk_score(&self, known_ips: &[IpAddr], known_devices: &[String]) -> f64 {
        let mut risk_score = 0.0;

        // IP address risk
        if !known_ips.contains(&self.last_ip) {
            risk_score += 0.3;
        }

        // Device fingerprint risk
        if !known_devices.contains(&self.device_fingerprint) {
            risk_score += 0.2;
        }

        // Time-based risk (unusual hours)
        let hour = self.created_at.hour();
        if hour < 6 || hour > 22 {
            risk_score += 0.1;
        }

        // Failed attempts risk
        if self.metadata.failed_attempts > 0 {
            risk_score += (self.metadata.failed_attempts as f64) * 0.1;
        }

        // Concurrent sessions risk
        if self.metadata.concurrent_sessions > 3 {
            risk_score += 0.2;
        }

        // Cap at 1.0
        risk_score.min(1.0)
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Standard
    }
}

impl Default for SessionMetadata {
    fn default() -> Self {
        Self {
            login_method: "password".to_string(),
            mfa_verified: false,
            risk_score: 0.0,
            concurrent_sessions: 1,
            failed_attempts: 0,
            last_password_change: None,
            permissions: Vec::new(),
            custom_data: HashMap::new(),
        }
    }
}

impl Default for SessionFlags {
    fn default() -> Self {
        Self {
            is_active: true,
            is_expired: false,
            is_revoked: false,
            is_suspicious: false,
            requires_mfa: false,
            has_elevated_privileges: false,
            is_concurrent_limited: false,
            is_ip_locked: false,
        }
    }
}

// Conversion implementations for error handling
impl From<ValidationError> for AppError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::SessionNotFound => AppError::not_found("Session"),
            ValidationError::SessionExpired => AppError::Unauthorized,
            ValidationError::SessionRevoked => AppError::Unauthorized,
            ValidationError::InvalidToken => AppError::Unauthorized,
            ValidationError::IpMismatch => AppError::Forbidden,
            ValidationError::DeviceMismatch => AppError::Forbidden,
            ValidationError::SecurityLevelInsufficient => AppError::Forbidden,
            ValidationError::ConcurrentSessionLimitExceeded => AppError::bad_request("Too many concurrent sessions"),
            ValidationError::SuspiciousActivity => AppError::Forbidden,
        }
    }
}