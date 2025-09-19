use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use crate::errors::AppError;

/// Audit event for security logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// Event type
    pub event_type: AuditEventType,
    /// Timestamp when event occurred
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub source_ip: IpAddr,
    /// User agent string
    pub user_agent: Option<String>,
    /// User ID if applicable
    pub user_id: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Resource accessed
    pub resource: Option<String>,
    /// Action performed
    pub action: String,
    /// Event outcome
    pub outcome: EventOutcome,
    /// Event severity
    pub severity: EventSeverity,
    /// Risk score associated with event
    pub risk_score: Option<f64>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Error message if applicable
    pub error_message: Option<String>,
}

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    SessionCreated,
    SessionRevoked,
    SessionExpired,
    PasswordChanged,
    AccountLocked,
    AccountUnlocked,
    SecurityViolation,
    DataAccess,
    ConfigurationChange,
    SystemEvent,
}

/// Event outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventOutcome {
    Success,
    Failure,
    Warning,
    Error,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    /// Log file path
    pub log_file_path: PathBuf,
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

/// File-based audit logger
pub struct FileAuditLogger {
    /// Configuration
    pub config: AuditConfig,
}

/// Main audit manager
pub struct AuditManager {
    /// File logger
    pub logger: FileAuditLogger,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file_path: PathBuf::from("logs/audit.log"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            log_success: true,
            log_failures: true,
            min_severity: EventSeverity::Low,
        }
    }
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: AuditEventType,
        source_ip: IpAddr,
        user_agent: Option<String>,
        action: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            source_ip,
            user_agent,
            user_id: None,
            session_id: None,
            resource: None,
            action,
            outcome: EventOutcome::Success,
            severity: EventSeverity::Medium,
            risk_score: None,
            metadata: HashMap::new(),
            error_message: None,
        }
    }

    /// Set user ID
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set resource
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set outcome
    pub fn with_outcome(mut self, outcome: EventOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set risk score
    pub fn with_risk_score(mut self, risk_score: f64) -> Self {
        self.risk_score = Some(risk_score);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set error message
    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.outcome = EventOutcome::Error;
        self
    }
}

impl FileAuditLogger {
    /// Create a new file audit logger
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    /// Log an audit event
    pub async fn log(&self, event: &AuditEvent) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if we should log this event based on severity
        if !self.should_log_severity(&event.severity) {
            return Ok(());
        }

        // Check if we should log based on outcome
        if !self.should_log_outcome(&event.outcome) {
            return Ok(());
        }

        // Serialize event to JSON
        let log_entry = serde_json::to_string(event)
            .map_err(|e| AppError::InternalServerError(format!("Failed to serialize audit event: {}", e)))?;

        // Append to file (simplified - in production would handle rotation, etc.)
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_file_path)
            .await
            .map_err(|e| AppError::InternalServerError(format!("Failed to open audit log file: {}", e)))?;
            
        file.write_all(format!("{}\n", log_entry).as_bytes())
            .await
            .map_err(|e| AppError::InternalServerError(format!("Failed to write audit log: {}", e)))?;

        Ok(())
    }

    /// Check if we should log based on severity
    fn should_log_severity(&self, severity: &EventSeverity) -> bool {
        match (&self.config.min_severity, severity) {
            (EventSeverity::Low, _) => true,
            (EventSeverity::Medium, EventSeverity::Low) => false,
            (EventSeverity::Medium, _) => true,
            (EventSeverity::High, EventSeverity::Low | EventSeverity::Medium) => false,
            (EventSeverity::High, _) => true,
            (EventSeverity::Critical, EventSeverity::Critical) => true,
            (EventSeverity::Critical, _) => false,
        }
    }

    /// Check if we should log based on outcome
    fn should_log_outcome(&self, outcome: &EventOutcome) -> bool {
        match outcome {
            EventOutcome::Success => self.config.log_success,
            EventOutcome::Failure | EventOutcome::Error => self.config.log_failures,
            EventOutcome::Warning => true, // Always log warnings
        }
    }
}

impl AuditManager {
    /// Create a new audit manager
    pub fn new() -> Self {
        let config = AuditConfig::default();
        let logger = FileAuditLogger::new(config);
        Self { logger }
    }

    /// Create audit manager with custom config
    pub fn with_config(config: AuditConfig) -> Self {
        let logger = FileAuditLogger::new(config);
        Self { logger }
    }

    /// Log an audit event
    pub async fn log_event(&self, event: &AuditEvent) -> Result<(), AppError> {
        self.logger.log(event).await
    }

    /// Log authentication event
    pub async fn log_authentication(
        &self,
        user_id: &str,
        source_ip: IpAddr,
        user_agent: Option<String>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<(), AppError> {
        let mut event = AuditEvent::new(
            AuditEventType::Authentication,
            source_ip,
            user_agent,
            "login".to_string(),
        )
        .with_user(user_id.to_string());

        if success {
            event = event.with_outcome(EventOutcome::Success);
        } else {
            event = event.with_outcome(EventOutcome::Failure);
            if let Some(error) = error_message {
                event = event.with_error(error);
            }
        }

        self.log_event(&event).await
    }

    /// Log session event
    pub async fn log_session_event(
        &self,
        event_type: AuditEventType,
        session_id: &str,
        user_id: &str,
        source_ip: IpAddr,
        action: &str,
    ) -> Result<(), AppError> {
        let event = AuditEvent::new(
            event_type,
            source_ip,
            None,
            action.to_string(),
        )
        .with_user(user_id.to_string())
        .with_session(session_id.to_string());

        self.log_event(&event).await
    }

    /// Log security violation
    pub async fn log_security_violation(
        &self,
        user_id: Option<&str>,
        session_id: Option<&str>,
        source_ip: IpAddr,
        violation_type: &str,
        risk_score: f64,
    ) -> Result<(), AppError> {
        let mut event = AuditEvent::new(
            AuditEventType::SecurityViolation,
            source_ip,
            None,
            violation_type.to_string(),
        )
        .with_severity(EventSeverity::High)
        .with_risk_score(risk_score);

        if let Some(uid) = user_id {
            event = event.with_user(uid.to_string());
        }

        if let Some(sid) = session_id {
            event = event.with_session(sid.to_string());
        }

        self.log_event(&event).await
    }
}
