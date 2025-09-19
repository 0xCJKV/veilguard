use chrono::{DateTime, Utc, Duration, Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::errors::AppError;
use crate::models::ses::{Session, SecurityLevel};

/// Behavioral analytics data for risk-based authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalytics {
    /// User's typical login hours (0-23)
    pub typical_login_hours: Vec<u8>,
    /// Frequently used IP addresses
    pub frequent_locations: Vec<IpAddr>,
    /// Average session duration in seconds
    pub average_session_duration: u64,
    /// Typical user agents used by this user
    pub typical_user_agents: Vec<String>,
    /// Typical devices used by this user
    pub typical_devices: Vec<String>,
    /// Geographic locations (country codes)
    pub typical_countries: Vec<String>,
    /// Time zones typically used
    pub typical_timezones: Vec<String>,
    /// Login frequency patterns (day of week)
    pub login_patterns: HashMap<u8, u32>, // 0=Sunday, 6=Saturday
    /// Failed login attempt patterns
    pub failed_attempt_patterns: Vec<FailedAttemptPattern>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Geographic location data for enhanced risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Current location coordinates
    pub current_location: (f64, f64), // (latitude, longitude)
    /// Previous location coordinates
    pub previous_location: Option<(f64, f64)>,
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,
    /// City name
    pub city: Option<String>,
    /// Time zone
    pub timezone: String,
    /// ISP information
    pub isp: Option<String>,
    /// Whether this is a known VPN/proxy
    pub is_vpn_proxy: bool,
}

/// Failed login attempt pattern for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAttemptPattern {
    /// Timestamp of failed attempt
    pub timestamp: DateTime<Utc>,
    /// IP address of failed attempt
    pub ip_address: IpAddr,
    /// User agent of failed attempt
    pub user_agent: String,
    /// Type of failure
    pub failure_type: FailureType,
}

/// Types of authentication failures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureType {
    InvalidPassword,
    InvalidUsername,
    AccountLocked,
    MfaFailed,
    SuspiciousActivity,
    RateLimited,
}

/// Threat response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    /// Risk score threshold for automatic session revocation
    pub auto_revoke_threshold: f64,
    /// Risk score threshold for MFA challenge
    pub mfa_challenge_threshold: f64,
    /// Risk score threshold for security notifications
    pub notification_threshold: f64,
    /// Maximum allowed failed attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in seconds
    pub lockout_duration: u64,
}

/// Actions that can be taken in response to threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatAction {
    SessionRevoked,
    MfaRequired,
    SecurityNotification,
    AccountLocked,
    IpBlocked,
    DeviceBlocked,
    AdditionalVerificationRequired,
}

/// Session binding for cryptographic session security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBinding {
    /// Hashed IP address for binding verification
    pub ip_hash: String,
    /// Hashed user agent for binding verification
    pub user_agent_hash: String,
    /// TLS fingerprint if available
    pub tls_fingerprint: Option<String>,
    /// Device fingerprint hash
    pub device_fingerprint_hash: String,
    /// Binding creation timestamp
    pub created_at: DateTime<Utc>,
}

impl BehaviorAnalytics {
    /// Create new behavioral analytics with default values
    pub fn new() -> Self {
        Self {
            typical_login_hours: Vec::new(),
            frequent_locations: Vec::new(),
            average_session_duration: 0,
            typical_user_agents: Vec::new(),
            typical_devices: Vec::new(),
            typical_countries: Vec::new(),
            typical_timezones: Vec::new(),
            login_patterns: HashMap::new(),
            failed_attempt_patterns: Vec::new(),
            last_updated: Utc::now(),
        }
    }

    /// Update behavioral analytics with new session data
    pub fn update_with_session(&mut self, session: &Session, geo_data: &GeoLocation) {
        let login_hour = session.created_at.hour() as u8;
        let day_of_week = session.created_at.weekday().num_days_from_sunday() as u8;

        // Update typical login hours
        if !self.typical_login_hours.contains(&login_hour) {
            self.typical_login_hours.push(login_hour);
        }

        // Update frequent locations
        if !self.frequent_locations.contains(&session.created_ip) {
            self.frequent_locations.push(session.created_ip);
        }

        // Update typical user agents
        if !self.typical_user_agents.contains(&session.user_agent) {
            self.typical_user_agents.push(session.user_agent.clone());
        }

        // Update typical devices
        if !self.typical_devices.contains(&session.device_fingerprint) {
            self.typical_devices.push(session.device_fingerprint.clone());
        }

        // Update typical countries
        if !self.typical_countries.contains(&geo_data.country_code) {
            self.typical_countries.push(geo_data.country_code.clone());
        }

        // Update typical timezones
        if !self.typical_timezones.contains(&geo_data.timezone) {
            self.typical_timezones.push(geo_data.timezone.clone());
        }

        // Update login patterns
        *self.login_patterns.entry(day_of_week).or_insert(0) += 1;

        // Keep only recent failed attempts (last 30 days)
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        self.failed_attempt_patterns.retain(|pattern| pattern.timestamp > thirty_days_ago);

        self.last_updated = Utc::now();
    }

    /// Add a failed login attempt to the pattern analysis
    pub fn add_failed_attempt(&mut self, ip: IpAddr, user_agent: String, failure_type: FailureType) {
        let pattern = FailedAttemptPattern {
            timestamp: Utc::now(),
            ip_address: ip,
            user_agent,
            failure_type,
        };
        
        self.failed_attempt_patterns.push(pattern);
        
        // Keep only last 100 failed attempts
        if self.failed_attempt_patterns.len() > 100 {
            self.failed_attempt_patterns.remove(0);
        }
        
        self.last_updated = Utc::now();
    }
}

impl Session {
    /// Calculate enhanced risk score using behavioral analytics
    pub fn calculate_enhanced_risk_score(
        &self,
        user_behavior: &BehaviorAnalytics,
        geo_data: &GeoLocation,
    ) -> f64 {
        let mut risk_score = self.calculate_risk_score(
            &user_behavior.frequent_locations,
            &user_behavior.typical_devices,
        );

        // Time-based behavioral analysis
        let current_hour = self.created_at.hour() as u8;
        if !user_behavior.typical_login_hours.contains(&current_hour) {
            risk_score += 0.2;
        }

        // Geographic anomaly detection
        if let Some(previous_location) = geo_data.previous_location {
            let distance = calculate_distance(geo_data.current_location, previous_location);
            if distance > 500.0 {
                // 500km threshold for suspicious travel
                risk_score += 0.3;
            }
        }

        // Country-based risk assessment
        if !user_behavior.typical_countries.contains(&geo_data.country_code) {
            risk_score += 0.25;
        }

        // VPN/Proxy detection
        if geo_data.is_vpn_proxy {
            risk_score += 0.15;
        }

        // User agent analysis
        if !user_behavior.typical_user_agents.contains(&self.user_agent) {
            risk_score += 0.1;
        }

        // Failed attempt pattern analysis
        let recent_failures = user_behavior.failed_attempt_patterns.iter()
            .filter(|pattern| {
                let time_diff = Utc::now() - pattern.timestamp;
                time_diff.num_hours() < 24
            })
            .count();

        if recent_failures > 5 {
            risk_score += 0.2;
        }

        // Day of week pattern analysis
        let day_of_week = self.created_at.weekday().num_days_from_sunday() as u8;
        let typical_logins_this_day = user_behavior.login_patterns.get(&day_of_week).unwrap_or(&0);
        if *typical_logins_this_day == 0 {
            risk_score += 0.1;
        }

        risk_score.min(1.0)
    }
}

impl SessionBinding {
    /// Create session binding with cryptographic hashes
    pub fn create_binding(
        ip: IpAddr,
        user_agent: &str,
        device_fingerprint: &str,
        tls_fingerprint: Option<String>,
    ) -> Self {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(ip.to_string().as_bytes());
        let ip_hash = format!("{:x}", hasher.finalize_reset());

        hasher.update(user_agent.as_bytes());
        let user_agent_hash = format!("{:x}", hasher.finalize_reset());

        hasher.update(device_fingerprint.as_bytes());
        let device_fingerprint_hash = format!("{:x}", hasher.finalize());

        Self {
            ip_hash,
            user_agent_hash,
            tls_fingerprint,
            device_fingerprint_hash,
            created_at: Utc::now(),
        }
    }

    /// Verify session binding against current request
    pub fn verify_binding(
        &self,
        current_ip: IpAddr,
        current_user_agent: &str,
        current_device_fingerprint: &str,
    ) -> bool {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Verify IP hash
        hasher.update(current_ip.to_string().as_bytes());
        let current_ip_hash = format!("{:x}", hasher.finalize_reset());
        if current_ip_hash != self.ip_hash {
            return false;
        }

        // Verify user agent hash
        hasher.update(current_user_agent.as_bytes());
        let current_user_agent_hash = format!("{:x}", hasher.finalize_reset());
        if current_user_agent_hash != self.user_agent_hash {
            return false;
        }

        // Verify device fingerprint hash
        hasher.update(current_device_fingerprint.as_bytes());
        let current_device_hash = format!("{:x}", hasher.finalize());
        if current_device_hash != self.device_fingerprint_hash {
            return false;
        }

        true
    }
}

impl Default for ThreatResponse {
    fn default() -> Self {
        Self {
            auto_revoke_threshold: 0.8,
            mfa_challenge_threshold: 0.6,
            notification_threshold: 0.4,
            max_failed_attempts: 5,
            lockout_duration: 900, // 15 minutes
        }
    }
}

/// Calculate distance between two geographic coordinates in kilometers
pub fn calculate_distance(coord1: (f64, f64), coord2: (f64, f64)) -> f64 {
    let (lat1, lon1) = coord1;
    let (lat2, lon2) = coord2;
    
    let r = 6371.0; // Earth's radius in kilometers
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    
    let a = (d_lat / 2.0).sin().powi(2) +
        lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    
    r * c
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_distance_calculation() {
        // Distance between New York and Los Angeles (approximately 3944 km)
        let ny = (40.7128, -74.0060);
        let la = (34.0522, -118.2437);
        let distance = calculate_distance(ny, la);
        
        assert!((distance - 3944.0).abs() < 100.0); // Allow 100km tolerance
    }

    #[test]
    fn test_session_binding() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_agent = "Mozilla/5.0 Test";
        let device_fp = "test-device-fingerprint";
        
        let binding = SessionBinding::create_binding(ip, user_agent, device_fp, None);
        
        // Should verify successfully with same data
        assert!(binding.verify_binding(ip, user_agent, device_fp));
        
        // Should fail with different data
        let different_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        assert!(!binding.verify_binding(different_ip, user_agent, device_fp));
    }

    #[test]
    fn test_behavior_analytics_update() {
        let mut analytics = BehaviorAnalytics::new();
        let session = Session::new(
            "user123".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "Mozilla/5.0 Test".to_string(),
            "device-fp".to_string(),
            SecurityLevel::Standard,
            None,
            None,
        );
        let geo_data = GeoLocation {
            current_location: (40.7128, -74.0060),
            previous_location: None,
            country_code: "US".to_string(),
            city: Some("New York".to_string()),
            timezone: "America/New_York".to_string(),
            isp: None,
            is_vpn_proxy: false,
        };
        
        analytics.update_with_session(&session, &geo_data);
        
        assert!(analytics.typical_countries.contains(&"US".to_string()));
        assert!(analytics.typical_timezones.contains(&"America/New_York".to_string()));
    }
}