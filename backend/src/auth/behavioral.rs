use chrono::{DateTime, Utc, Duration, Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::errors::AppError;
use crate::models::ses::{Session};
use crate::models::security::{
    RiskAssessment, RiskFactor, RiskFactorType, SecurityAction, EventSeverity,
    BehavioralProfile, SessionMetrics, ActivityType, SecurityLevel
};
use super::utils::{calculate_distance, calculate_travel_velocity};

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

// Remove duplicate ThreatResponse - now using SecurityConfig from models/security.rs
// Remove duplicate ThreatAction - now using SecurityAction from models/security.rs
// Remove duplicate SessionBinding - this should be in binding.rs only

/// Behavioral analytics data for risk-based authentication
/// Now uses BehavioralProfile from models/security.rs internally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalytics {
    /// Internal behavioral profile
    pub profile: BehavioralProfile,
    /// Failed login attempt patterns
    pub failed_attempt_patterns: Vec<FailedAttemptPattern>,
}

impl BehaviorAnalytics {
    /// Create new behavioral analytics with default values
    pub fn new() -> Self {
        Self {
            profile: BehavioralProfile {
                typical_login_hours: Vec::new(),
                frequent_locations: Vec::new(),
                average_session_duration: 0,
                typical_user_agents: Vec::new(),
                typical_devices: Vec::new(),
                typical_countries: Vec::new(),
                typical_timezones: Vec::new(),
                login_patterns: HashMap::new(),
                last_updated: Utc::now(),
            },
            failed_attempt_patterns: Vec::new(),
        }
    }

    /// Update behavioral analytics with new session data
    pub fn update_with_session(&mut self, session: &Session, geo_data: &GeoLocation) {
        let login_hour = session.created_at.hour() as u8;
        let day_of_week = session.created_at.weekday().num_days_from_sunday() as u8;

        // Update typical login hours
        if !self.profile.typical_login_hours.contains(&login_hour) {
            self.profile.typical_login_hours.push(login_hour);
        }

        // Update frequent locations
        if !self.profile.frequent_locations.contains(&session.created_ip) {
            self.profile.frequent_locations.push(session.created_ip);
        }

        // Update typical user agents
        if !self.profile.typical_user_agents.contains(&session.user_agent) {
            self.profile.typical_user_agents.push(session.user_agent.clone());
        }

        // Update typical devices
        if !self.profile.typical_devices.contains(&session.device_fingerprint) {
            self.profile.typical_devices.push(session.device_fingerprint.clone());
        }

        // Update typical countries
        if !self.profile.typical_countries.contains(&geo_data.country_code) {
            self.profile.typical_countries.push(geo_data.country_code.clone());
        }

        // Update typical timezones
        if !self.profile.typical_timezones.contains(&geo_data.timezone) {
            self.profile.typical_timezones.push(geo_data.timezone.clone());
        }

        // Update login patterns
        *self.profile.login_patterns.entry(day_of_week).or_insert(0) += 1;

        // Keep only recent failed attempts (last 30 days)
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        self.failed_attempt_patterns.retain(|pattern| pattern.timestamp > thirty_days_ago);

        self.profile.last_updated = Utc::now();
    }

    /// Calculate behavioral risk score based on current session vs historical patterns
    pub fn calculate_behavioral_risk(&self, session: &Session, geo_data: &GeoLocation) -> f64 {
        let mut risk_score = 0.0;
        let mut factors = 0;

        // Check login hour patterns
        let current_hour = session.created_at.hour() as u8;
        if !self.profile.typical_login_hours.is_empty() && !self.profile.typical_login_hours.contains(&current_hour) {
            risk_score += 0.2;
        }
        factors += 1;

        // Check IP address patterns
        if !self.profile.frequent_locations.is_empty() && !self.profile.frequent_locations.contains(&session.created_ip) {
            risk_score += 0.3;
        }
        factors += 1;

        // Check user agent patterns
        if !self.profile.typical_user_agents.is_empty() && !self.profile.typical_user_agents.contains(&session.user_agent) {
            risk_score += 0.15;
        }
        factors += 1;

        // Check device patterns
        if !self.profile.typical_devices.is_empty() && !self.profile.typical_devices.contains(&session.device_fingerprint) {
            risk_score += 0.25;
        }
        factors += 1;

        // Check country patterns
        if !self.profile.typical_countries.is_empty() && !self.profile.typical_countries.contains(&geo_data.country_code) {
            risk_score += 0.2;
        }
        factors += 1;

        // Check timezone patterns
        if !self.profile.typical_timezones.is_empty() && !self.profile.typical_timezones.contains(&geo_data.timezone) {
            risk_score += 0.1;
        }
        factors += 1;

        if factors > 0 {
            risk_score / factors as f64
        } else {
            0.0
        }
    }

    /// Generate a comprehensive risk assessment
    pub fn generate_risk_assessment(&self, session: &Session, geo_data: &GeoLocation) -> RiskAssessment {
        let behavioral_risk = self.calculate_behavioral_risk(session, geo_data);
        let mut assessment = RiskAssessment::new(behavioral_risk);

        // Add specific risk factors based on behavioral analysis
        let current_hour = session.created_at.hour() as u8;
        if !self.profile.typical_login_hours.is_empty() && !self.profile.typical_login_hours.contains(&current_hour) {
            assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::UnusualLoginTime,
                0.2,
                format!("Login at unusual hour: {}", current_hour),
                EventSeverity::Medium,
            ));
        }

        if !self.profile.frequent_locations.is_empty() && !self.profile.frequent_locations.contains(&session.created_ip) {
            assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::UnknownIpAddress,
                0.3,
                format!("Unknown IP address: {}", session.created_ip),
                EventSeverity::High,
            ));
        }

        if !self.profile.typical_devices.is_empty() && !self.profile.typical_devices.contains(&session.device_fingerprint) {
            assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::UnknownDevice,
                0.25,
                "Unknown device fingerprint".to_string(),
                EventSeverity::High,
            ));
        }

        if geo_data.is_vpn_proxy {
            assessment.add_risk_factor(RiskFactor::new(
                RiskFactorType::VpnProxyUsage,
                0.4,
                "VPN/Proxy usage detected".to_string(),
                EventSeverity::High,
            ));
        }

        // Add recommended actions based on risk level
        if behavioral_risk > 0.7 {
            assessment.add_action(SecurityAction::SessionRevoked);
            assessment.add_action(SecurityAction::SecurityNotification);
        } else if behavioral_risk > 0.5 {
            assessment.add_action(SecurityAction::MfaRequired);
            assessment.add_action(SecurityAction::SecurityNotification);
        } else if behavioral_risk > 0.3 {
            assessment.add_action(SecurityAction::AdditionalVerificationRequired);
        }

        assessment
    }

    /// Record a failed login attempt
    pub fn record_failed_attempt(&mut self, ip: IpAddr, user_agent: String, failure_type: FailureType) {
        let pattern = FailedAttemptPattern {
            timestamp: Utc::now(),
            ip_address: ip,
            user_agent,
            failure_type,
        };
        self.failed_attempt_patterns.push(pattern);

        // Keep only recent attempts (last 30 days)
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        self.failed_attempt_patterns.retain(|p| p.timestamp > thirty_days_ago);
    }

    /// Get recent failed attempts count
    pub fn get_recent_failed_attempts(&self, hours: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::hours(hours);
        self.failed_attempt_patterns.iter()
            .filter(|p| p.timestamp > cutoff)
            .count()
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
            &user_behavior.profile.frequent_locations,
            &user_behavior.profile.typical_devices,
        );

        // Time-based behavioral analysis
        let current_hour = self.created_at.hour() as u8;
        if !user_behavior.profile.typical_login_hours.contains(&current_hour) {
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
        if !user_behavior.profile.typical_countries.contains(&geo_data.country_code) {
            risk_score += 0.25;
        }

        // VPN/Proxy detection
        if geo_data.is_vpn_proxy {
            risk_score += 0.15;
        }

        // User agent analysis
        if !user_behavior.profile.typical_user_agents.contains(&self.user_agent) {
            risk_score += 0.1;
        }

        // Failed attempt pattern analysis
        let recent_failures = user_behavior.failed_attempt_patterns.iter()
            .filter(|pattern| {
                let time_diff = Utc::now() - pattern.timestamp;
                time_diff.num_hours() < 24 // Last 24 hours
            })
            .count();

        if recent_failures > 3 {
            risk_score += 0.2;
        }

        // Day of week pattern analysis
        let day_of_week = self.created_at.weekday().num_days_from_sunday() as u8;
        let typical_logins_this_day = user_behavior.profile.login_patterns.get(&day_of_week).unwrap_or(&0);
        if *typical_logins_this_day == 0 {
            risk_score += 0.1;
        }

        risk_score.min(1.0)
    }
}
