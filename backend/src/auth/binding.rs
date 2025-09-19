use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use crate::errors::AppError;
use crate::models::ses::Session;

/// Session binding manager for cryptographic session security
pub struct SessionBindingManager {
    /// Binding configuration
    pub config: BindingConfig,
    /// Active session bindings (protected by mutex for interior mutability)
    pub bindings: Mutex<HashMap<String, CryptographicSessionBinding>>,
}

/// Configuration for session binding
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
    /// Extensions
    pub extensions: Vec<String>,
    /// Certificate chain hash
    pub cert_chain_hash: Option<String>,
}

/// Session binding validation result
#[derive(Debug)]
pub struct BindingValidationResult {
    /// Whether binding is valid
    pub is_valid: bool,
    /// Validation score (0.0 to 1.0)
    pub validation_score: f64,
    /// Failed validations
    pub failed_validations: Vec<String>,
    /// Risk factors detected
    pub risk_factors: Vec<String>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            enforce_ip_binding: true,
            enforce_device_binding: true,
            enforce_tls_binding: false,
            max_ip_changes: 3,
            ip_change_window: 60, // 1 hour
            allow_mobile_ip_changes: true,
        }
    }
}

impl SessionBindingManager {
    /// Create a new session binding manager
    pub fn new(config: BindingConfig) -> Self {
        Self {
            config,
            bindings: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session binding
    pub fn create_binding(
        &self,
        session: &Session,
        device_fingerprint: &DeviceFingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
    ) -> Result<CryptographicSessionBinding, AppError> {
        let device_hash = self.hash_device_fingerprint(device_fingerprint)?;
        let browser_fingerprint = self.generate_browser_fingerprint(device_fingerprint)?;
        let binding_token = self.generate_binding_token(session, &device_hash)?;
        
        let tls_fp = tls_fingerprint.map(|fp| self.hash_tls_fingerprint(fp)).transpose()?;

        let binding = CryptographicSessionBinding {
            session_id: session.id.clone(),
            user_id: session.user_id.clone(),
            bound_ip: session.created_ip,
            device_fingerprint_hash: device_hash,
            tls_fingerprint: tls_fp,
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

    /// Validate session binding
    pub fn validate_binding(
        &self,
        session_id: &str,
        current_ip: IpAddr,
        device_fingerprint: &DeviceFingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
    ) -> Result<BindingValidationResult, AppError> {
        // First, get the binding and check if it's compromised
        let binding = {
            let bindings = self.bindings.lock().unwrap();
            bindings.get(session_id).cloned()
        };
        
        let binding = binding.ok_or_else(|| AppError::NotFound("Session binding not found".to_string()))?;

        if binding.is_compromised {
            return Ok(BindingValidationResult {
                is_valid: false,
                validation_score: 0.0,
                failed_validations: vec!["Session binding is compromised".to_string()],
                risk_factors: vec!["Compromised binding".to_string()],
                recommended_actions: vec!["Revoke session immediately".to_string()],
            });
        }

        let mut validation_score = 1.0;
        let mut failed_validations = Vec::new();
        let mut risk_factors = Vec::new();
        let mut recommended_actions = Vec::new();
        let mut needs_ip_update = false;
        let mut new_ip_change: Option<IpChange> = None;

        // Validate IP binding
        if self.config.enforce_ip_binding {
            if current_ip != binding.bound_ip {
                let ip_change_valid = self.validate_ip_change_static(&binding, current_ip)?;
                if !ip_change_valid {
                    validation_score -= 0.4;
                    failed_validations.push("IP address validation failed".to_string());
                    risk_factors.push("Unexpected IP change".to_string());
                    recommended_actions.push("Require additional authentication".to_string());
                } else {
                    // Prepare IP change record
                    new_ip_change = Some(IpChange {
                        from_ip: binding.bound_ip,
                        to_ip: current_ip,
                        changed_at: Utc::now(),
                        reason: "Valid IP change detected".to_string(),
                        validated: true,
                    });
                    needs_ip_update = true;
                    validation_score -= 0.1; // Minor penalty for IP change
                }
            }
        }

        // Validate device fingerprint
        if self.config.enforce_device_binding {
            let current_device_hash = self.hash_device_fingerprint(device_fingerprint)?;
            if current_device_hash != binding.device_fingerprint_hash {
                validation_score -= 0.5;
                failed_validations.push("Device fingerprint validation failed".to_string());
                risk_factors.push("Device fingerprint mismatch".to_string());
                recommended_actions.push("Revoke session".to_string());
            }
        }

        // Validate TLS fingerprint
        if self.config.enforce_tls_binding {
            if let Some(tls_fp) = tls_fingerprint {
                let current_tls_hash = self.hash_tls_fingerprint(tls_fp)?;
                if Some(current_tls_hash) != binding.tls_fingerprint {
                    validation_score -= 0.3;
                    failed_validations.push("TLS fingerprint validation failed".to_string());
                    risk_factors.push("TLS fingerprint mismatch".to_string());
                    recommended_actions.push("Require MFA".to_string());
                }
            }
        }

        // Now update the binding with mutable access
        {
            let mut bindings = self.bindings.lock().unwrap();
            let binding = bindings.get_mut(session_id).unwrap(); // Safe because we checked above
            
            // Update binding validation status
            binding.last_validated = Utc::now();
            
            // Apply IP changes if needed
            if needs_ip_update {
                if let Some(ip_change) = new_ip_change {
                    binding.ip_changes.push(ip_change);
                    binding.bound_ip = current_ip;
                }
            }
            
            let is_valid = validation_score >= 0.6;
            if !is_valid {
                binding.validation_failures += 1;
                
                // Mark as compromised if too many failures
                if binding.validation_failures >= 3 {
                    binding.is_compromised = true;
                    recommended_actions.push("Session binding compromised - revoke immediately".to_string());
                }
            } else {
                binding.validation_failures = 0; // Reset on successful validation
            }
        }

        let is_valid = validation_score >= 0.6;
        Ok(BindingValidationResult {
            is_valid,
            validation_score,
            failed_validations,
            risk_factors,
            recommended_actions,
        })
    }

    /// Validate IP address change
    fn validate_ip_change_static(&self, binding: &CryptographicSessionBinding, _new_ip: IpAddr) -> Result<bool, AppError> {
        // Check if too many IP changes in the time window
        let window_start = Utc::now() - chrono::Duration::hours(self.config.ip_change_window);
        let recent_changes = binding.ip_changes.iter()
            .filter(|change| change.changed_at > window_start)
            .count();

        if recent_changes >= self.config.max_ip_changes as usize {
            return Ok(false);
        }

        // For mobile devices, allow more IP changes
        if self.config.allow_mobile_ip_changes {
            // Simple heuristic: if user agent contains mobile indicators
            // In a real implementation, you'd have more sophisticated detection
            return Ok(true);
        }

        Ok(true)
    }

    fn validate_ip_change(&self, binding: &CryptographicSessionBinding, _new_ip: IpAddr) -> Result<bool, AppError> {
        // Check if too many IP changes in the time window
        let window_start = Utc::now() - chrono::Duration::minutes(self.config.ip_change_window);
        let recent_changes = binding.ip_changes.iter()
            .filter(|change| change.changed_at > window_start)
            .count();

        if recent_changes >= self.config.max_ip_changes as usize {
            return Ok(false);
        }

        // Additional validation logic could include:
        // - Geolocation checks
        // - ISP validation
        // - Mobile network detection
        
        Ok(true)
    }

    /// Generate cryptographic binding token
    fn generate_binding_token(&self, session: &Session, device_hash: &str) -> Result<String, AppError> {
        let mut hasher = Sha256::new();
        hasher.update(session.id.as_bytes());
        hasher.update(session.user_id.as_bytes());
        hasher.update(device_hash.as_bytes());
        hasher.update(session.created_ip.to_string().as_bytes());
        hasher.update(session.created_at.timestamp().to_string().as_bytes());
        
        // Add some entropy
        hasher.update(uuid::Uuid::new_v4().to_string().as_bytes());
        
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Hash device fingerprint
    fn hash_device_fingerprint(&self, fingerprint: &DeviceFingerprint) -> Result<String, AppError> {
        let mut hasher = Sha256::new();
        
        hasher.update(fingerprint.user_agent.as_bytes());
        
        if let Some(resolution) = &fingerprint.screen_resolution {
            hasher.update(resolution.as_bytes());
        }
        
        if let Some(timezone) = &fingerprint.timezone {
            hasher.update(timezone.as_bytes());
        }
        
        for lang in &fingerprint.languages {
            hasher.update(lang.as_bytes());
        }
        
        if let Some(platform) = &fingerprint.platform {
            hasher.update(platform.as_bytes());
        }
        
        if let Some(concurrency) = fingerprint.hardware_concurrency {
            hasher.update(concurrency.to_string().as_bytes());
        }
        
        if let Some(memory) = fingerprint.device_memory {
            hasher.update(memory.to_string().as_bytes());
        }
        
        if let Some(webgl) = &fingerprint.webgl_renderer {
            hasher.update(webgl.as_bytes());
        }
        
        if let Some(canvas) = &fingerprint.canvas_fingerprint {
            hasher.update(canvas.as_bytes());
        }
        
        if let Some(audio) = &fingerprint.audio_fingerprint {
            hasher.update(audio.as_bytes());
        }
        
        Ok(format!("{:x}", hasher.finalize()))
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
        
        if let Some(cert_hash) = &fingerprint.cert_chain_hash {
            hasher.update(cert_hash.as_bytes());
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Generate browser fingerprint
    fn generate_browser_fingerprint(&self, device: &DeviceFingerprint) -> Result<String, AppError> {
        let mut hasher = Sha256::new();
        
        // Use a subset of device fingerprint for browser identification
        hasher.update(device.user_agent.as_bytes());
        
        if let Some(canvas) = &device.canvas_fingerprint {
            hasher.update(canvas.as_bytes());
        }
        
        if let Some(webgl) = &device.webgl_renderer {
            hasher.update(webgl.as_bytes());
        }
        
        for lang in &device.languages {
            hasher.update(lang.as_bytes());
        }
        
        Ok(format!("{:x}", hasher.finalize())[..16].to_string())
    }

    /// Get binding for session
    pub fn get_binding(&self, session_id: &str) -> Option<CryptographicSessionBinding> {
        let bindings = self.bindings.lock().unwrap();
        bindings.get(session_id).cloned()
    }

    /// Remove binding
    pub fn remove_binding(&self, session_id: &str) -> Option<CryptographicSessionBinding> {
        let mut bindings = self.bindings.lock().unwrap();
        bindings.remove(session_id)
    }

    /// Mark binding as compromised
    pub fn mark_compromised(&self, session_id: &str) -> Result<(), AppError> {
        let mut bindings = self.bindings.lock().unwrap();
        if let Some(binding) = bindings.get_mut(session_id) {
            binding.is_compromised = true;
            Ok(())
        } else {
            Err(AppError::NotFound("Session binding not found".to_string()))
        }
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
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);
        
        let mut bindings = self.bindings.lock().unwrap();
        bindings.retain(|_, binding| {
            binding.last_validated > cutoff && !binding.is_compromised
        });
    }
}

impl DeviceFingerprint {
    /// Create a basic device fingerprint from user agent
    pub fn from_user_agent(user_agent: String) -> Self {
        Self {
            user_agent,
            screen_resolution: None,
            timezone: None,
            languages: vec!["en-US".to_string()],
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
