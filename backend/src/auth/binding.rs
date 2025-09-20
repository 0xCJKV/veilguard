use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use crate::errors::AppError;
use crate::models::ses::Session;
use crate::models::security::{SecurityConfig, SecurityAction};
use super::utils::{sha256_hash_multiple};

/// Session binding manager for cryptographic session security
pub struct SessionBindingManager {
    /// Binding configuration (now using SecurityConfig from models/security.rs)
    pub config: SecurityConfig,
    /// Active session bindings (protected by mutex for interior mutability)
    pub bindings: Mutex<HashMap<String, CryptographicSessionBinding>>,
}

// Remove duplicate BindingConfig - now using SecurityConfig from models/security.rs

/// Cryptographic session binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicSessionBinding {
    /// Session ID
    pub session_id: String,
    /// User ID
    pub user_id: String,
    /// Bound IP address
    pub bound_ip: IpAddr,
    /// Device fingerprint hash
    pub device_fingerprint_hash: String,
    /// TLS fingerprint
    pub tls_fingerprint: Option<String>,
    /// Browser fingerprint
    pub browser_fingerprint: String,
    /// Cryptographic binding token
    pub binding_token: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last validation timestamp
    pub last_validated: DateTime<Utc>,
    /// IP change history
    pub ip_changes: Vec<IpChange>,
    /// Validation failures
    pub validation_failures: u32,
    /// Whether binding is compromised
    pub is_compromised: bool,
}

/// IP address change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpChange {
    /// Previous IP address
    pub from_ip: IpAddr,
    /// New IP address
    pub to_ip: IpAddr,
    /// Change timestamp
    pub changed_at: DateTime<Utc>,
    /// Reason for change
    pub reason: String,
    /// Whether change was validated
    pub validated: bool,
}

/// Device fingerprint components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// User agent string
    pub user_agent: String,
    /// Screen resolution
    pub screen_resolution: Option<String>,
    /// Timezone
    pub timezone: Option<String>,
    /// Language preferences
    pub languages: Vec<String>,
    /// Platform information
    pub platform: Option<String>,
    /// Hardware concurrency
    pub hardware_concurrency: Option<u32>,
    /// Device memory
    pub device_memory: Option<f64>,
    /// WebGL renderer
    pub webgl_renderer: Option<String>,
    /// Canvas fingerprint
    pub canvas_fingerprint: Option<String>,
    /// Audio fingerprint
    pub audio_fingerprint: Option<String>,
}

/// TLS fingerprint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprint {
    /// TLS version
    pub version: String,
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    /// TLS extensions
    pub extensions: Vec<String>,
    /// Certificate chain hash
    pub cert_chain_hash: Option<String>,
}

/// Binding validation result
#[derive(Debug)]
pub struct BindingValidationResult {
    /// Whether binding is valid
    pub is_valid: bool,
    /// Validation score (0.0 to 1.0)
    pub validation_score: f64,
    /// List of failed validations
    pub failed_validations: Vec<String>,
    /// Risk factors identified
    pub risk_factors: Vec<String>,
    /// Recommended actions (now using SecurityAction from models/security.rs)
    pub recommended_actions: Vec<SecurityAction>,
}

impl SessionBindingManager {
    /// Create a new session binding manager
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            bindings: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new cryptographic session binding
    pub fn create_binding(
        &self,
        session: &Session,
        device_fingerprint: &DeviceFingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
    ) -> Result<CryptographicSessionBinding, AppError> {
        let device_hash = self.hash_device_fingerprint(device_fingerprint)?;
        let tls_hash = if let Some(tls) = tls_fingerprint {
            Some(self.hash_tls_fingerprint(tls)?)
        } else {
            None
        };
        let browser_fingerprint = self.generate_browser_fingerprint(device_fingerprint)?;
        let binding_token = self.generate_binding_token(session, &device_hash)?;

        let binding = CryptographicSessionBinding {
            session_id: session.id.clone(),
            user_id: session.user_id.clone(),
            bound_ip: session.created_ip,
            device_fingerprint_hash: device_hash,
            tls_fingerprint: tls_hash,
            browser_fingerprint,
            binding_token,
            created_at: Utc::now(),
            last_validated: Utc::now(),
            ip_changes: Vec::new(),
            validation_failures: 0,
            is_compromised: false,
        };

        let mut bindings = self.bindings.lock().unwrap();
        bindings.insert(session.id.clone(), binding.clone());

        Ok(binding)
    }

    /// Validate an existing session binding
    pub fn validate_binding(
        &self,
        session_id: &str,
        current_ip: IpAddr,
        device_fingerprint: &DeviceFingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
    ) -> Result<BindingValidationResult, AppError> {
        let mut bindings = self.bindings.lock().unwrap();
        
        let binding = match bindings.get_mut(session_id) {
            Some(b) => b,
            None => {
                return Ok(BindingValidationResult {
                    is_valid: false,
                    validation_score: 0.0,
                    failed_validations: vec!["No binding found".to_string()],
                    risk_factors: vec!["Missing session binding".to_string()],
                    recommended_actions: vec![SecurityAction::SessionRevoked],
                });
            }
        };

        let mut validation_score = 1.0;
        let mut failed_validations = Vec::new();
        let mut risk_factors = Vec::new();
        let mut recommended_actions = Vec::new();

        // Validate IP binding
        if current_ip != binding.bound_ip {
            if self.validate_ip_change(binding, current_ip)? {
                // IP change is allowed, update binding
                binding.ip_changes.push(IpChange {
                    from_ip: binding.bound_ip,
                    to_ip: current_ip,
                    changed_at: Utc::now(),
                    reason: "Network change detected".to_string(),
                    validated: true,
                });
                binding.bound_ip = current_ip;
                validation_score -= 0.1; // Small penalty for IP change
                risk_factors.push("IP address changed".to_string());
            } else {
                validation_score -= 0.4;
                failed_validations.push("IP binding validation failed".to_string());
                risk_factors.push("Unauthorized IP change".to_string());
                recommended_actions.push(SecurityAction::AdditionalVerificationRequired);
            }
        }

        // Validate device fingerprint
        let current_device_hash = self.hash_device_fingerprint(device_fingerprint)?;
        if current_device_hash != binding.device_fingerprint_hash {
            validation_score -= 0.5;
            failed_validations.push("Device fingerprint mismatch".to_string());
            risk_factors.push("Device fingerprint changed".to_string());
            recommended_actions.push(SecurityAction::MfaRequired);
        }

        // Validate TLS fingerprint if available
        if let Some(tls) = tls_fingerprint {
            let current_tls_hash = self.hash_tls_fingerprint(tls)?;
            if let Some(ref bound_tls) = binding.tls_fingerprint {
                if current_tls_hash != *bound_tls {
                    validation_score -= 0.3;
                    failed_validations.push("TLS fingerprint mismatch".to_string());
                    risk_factors.push("TLS configuration changed".to_string());
                }
            }
        }

        // Check for too many validation failures
        if binding.validation_failures > self.config.threat_config.max_failed_attempts {
            validation_score = 0.0;
            failed_validations.push("Too many validation failures".to_string());
            risk_factors.push("Repeated validation failures".to_string());
            recommended_actions.push(SecurityAction::SessionRevoked);
        }

        // Update binding state
        binding.last_validated = Utc::now();
        if validation_score < 0.5 {
            binding.validation_failures += 1;
        } else {
            binding.validation_failures = 0; // Reset on successful validation
        }

        // Determine if binding is compromised
        if validation_score < 0.3 || binding.validation_failures > self.config.threat_config.max_failed_attempts {
            binding.is_compromised = true;
            recommended_actions.push(SecurityAction::SessionRevoked);
        }

        // Add security notifications for high-risk situations
        if validation_score < 0.6 {
            recommended_actions.push(SecurityAction::SecurityNotification);
        }

        // Remove duplicates from recommended actions
        recommended_actions.sort();
        recommended_actions.dedup();

        Ok(BindingValidationResult {
            is_valid: validation_score >= 0.5 && !binding.is_compromised,
            validation_score,
            failed_validations,
            risk_factors,
            recommended_actions,
        })
    }

    /// Validate IP change for static configurations
    fn validate_ip_change_static(&self, binding: &CryptographicSessionBinding, _new_ip: IpAddr) -> Result<bool, AppError> {
        // For static IP binding, no changes are allowed
        if binding.ip_changes.len() >= self.config.threat_config.max_failed_attempts as usize {
            return Ok(false);
        }

        // Check if too many IP changes in short time window
        let recent_changes = binding.ip_changes.iter()
            .filter(|change| {
                let minutes_ago = Utc::now() - chrono::Duration::minutes(60);
                change.changed_at > minutes_ago
            })
            .count();

        Ok(recent_changes < 3)
    }

    /// Validate IP change with more flexible rules
    fn validate_ip_change(&self, binding: &CryptographicSessionBinding, _new_ip: IpAddr) -> Result<bool, AppError> {
        // Allow reasonable number of IP changes
        if binding.ip_changes.len() >= 10 {
            return Ok(false);
        }

        // Check rate limiting - max 3 changes per hour
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let recent_changes = binding.ip_changes.iter()
            .filter(|change| change.changed_at > one_hour_ago)
            .count();

        Ok(recent_changes < 3)
    }

    /// Generate a cryptographic binding token
    fn generate_binding_token(&self, session: &Session, device_hash: &str) -> Result<String, AppError> {
        let token_data = &[
            &session.id,
            &session.user_id,
            &session.created_ip.to_string(),
            device_hash,
            &session.created_at.timestamp().to_string(),
        ];
        
        let token = sha256_hash_multiple(token_data);
        Ok(format!("bind_{}", &token[..32]))
    }

    /// Hash device fingerprint for secure storage
    fn hash_device_fingerprint(&self, fingerprint: &DeviceFingerprint) -> Result<String, AppError> {
        let fingerprint_data = &[
            &fingerprint.user_agent,
            fingerprint.screen_resolution.as_deref().unwrap_or(""),
            fingerprint.timezone.as_deref().unwrap_or(""),
            &fingerprint.languages.join(","),
            fingerprint.platform.as_deref().unwrap_or(""),
            &fingerprint.hardware_concurrency.unwrap_or(0).to_string(),
            &fingerprint.device_memory.unwrap_or(0.0).to_string(),
            fingerprint.webgl_renderer.as_deref().unwrap_or(""),
            fingerprint.canvas_fingerprint.as_deref().unwrap_or(""),
            fingerprint.audio_fingerprint.as_deref().unwrap_or(""),
        ];
        
        Ok(sha256_hash_multiple(fingerprint_data))
    }

    /// Hash TLS fingerprint
    fn hash_tls_fingerprint(&self, fingerprint: &TlsFingerprint) -> Result<String, AppError> {
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.version.as_bytes());
        
        for cipher in &fingerprint.cipher_suites {
            hasher.update(cipher.as_bytes());
        }
        
        for ext in &fingerprint.extensions {
            hasher.update(ext.as_bytes());
        }
        
        if let Some(ref cert_hash) = fingerprint.cert_chain_hash {
            hasher.update(cert_hash.as_bytes());
        }
        
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Generate browser fingerprint from device components
    fn generate_browser_fingerprint(&self, device: &DeviceFingerprint) -> Result<String, AppError> {
        // Collect all components for hashing
        let mut components = vec![device.user_agent.as_str()];
        
        // Add optional components if they exist
        if let Some(ref resolution) = device.screen_resolution {
            components.push(resolution);
        }
        
        if let Some(ref canvas) = device.canvas_fingerprint {
            components.push(canvas);
        }
        
        if let Some(ref webgl) = device.webgl_renderer {
            components.push(webgl);
        }
        
        // Use the utility function for consistent hashing
        let hash = sha256_hash_multiple(&components);
        Ok(hash[..16].to_string()) // Shorter fingerprint for browser
    }

    /// Get binding for a session
    pub fn get_binding(&self, session_id: &str) -> Option<CryptographicSessionBinding> {
        let bindings = self.bindings.lock().unwrap();
        bindings.get(session_id).cloned()
    }

    /// Remove binding for a session
    pub fn remove_binding(&self, session_id: &str) -> Option<CryptographicSessionBinding> {
        let mut bindings = self.bindings.lock().unwrap();
        bindings.remove(session_id)
    }

    /// Mark a binding as compromised
    pub fn mark_compromised(&self, session_id: &str) -> Result<(), AppError> {
        let mut bindings = self.bindings.lock().unwrap();
        if let Some(binding) = bindings.get_mut(session_id) {
            binding.is_compromised = true;
        }
        Ok(())
    }

    /// Get all bindings for a user
    pub fn get_user_bindings(&self, user_id: &str) -> Vec<CryptographicSessionBinding> {
        let bindings = self.bindings.lock().unwrap();
        bindings.values()
            .filter(|binding| binding.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Clean up expired bindings
    pub fn cleanup_expired_bindings(&self, max_age_hours: i64) {
        let mut bindings = self.bindings.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);
        bindings.retain(|_, binding| binding.created_at > cutoff);
    }
}

impl DeviceFingerprint {
    /// Create a basic device fingerprint from user agent
    pub fn from_user_agent(user_agent: String) -> Self {
        Self {
            user_agent,
            screen_resolution: None,
            timezone: None,
            languages: Vec::new(),
            platform: None,
            hardware_concurrency: None,
            device_memory: None,
            webgl_renderer: None,
            canvas_fingerprint: None,
            audio_fingerprint: None,
        }
    }

    /// Create a comprehensive device fingerprint
    pub fn comprehensive(
        user_agent: String,
        screen_resolution: Option<String>,
        timezone: Option<String>,
        languages: Vec<String>,
        platform: Option<String>,
        hardware_concurrency: Option<u32>,
        device_memory: Option<f64>,
        webgl_renderer: Option<String>,
        canvas_fingerprint: Option<String>,
        audio_fingerprint: Option<String>,
    ) -> Self {
        Self {
            user_agent,
            screen_resolution,
            timezone,
            languages,
            platform,
            hardware_concurrency,
            device_memory,
            webgl_renderer,
            canvas_fingerprint,
            audio_fingerprint,
        }
    }
}
