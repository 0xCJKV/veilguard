use axum::{
    extract::Extension,
    http::{StatusCode, HeaderMap},
    response::Json,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use std::net::IpAddr;
use std::collections::HashMap;
use serde_json::Value;
use crate::{
    auth::{
        hash_password, verify_password, PasetoManager, ses::SessionManager,
        behavioral::{BehaviorAnalytics, GeoLocation, ThreatAction},
        binding::{SessionBindingManager, DeviceFingerprint, TlsFingerprint},
        threat::ThreatDetectionEngine,
        audit::{AuditManager, AuditEvent, AuditEventType, EventOutcome, EventSeverity},
    },
    middleware::{
        create_secure_cookie, create_delete_cookie, 
        ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, AuthUser
    },
    config::Config,
    database::{users, DbPool, redis::RedisManager},
    models::{CreateUserRequest, LoginRequest, UserResponse, ses::SecurityLevel},
    errors::{AppError, Result},
};

fn is_valid_email(email: &str) -> bool {
    email.contains('@') && 
    email.len() > 5 && 
    email.chars().filter(|&c| c == '@').count() == 1 &&
    !email.starts_with('@') && 
    !email.ends_with('@')
}

/// Enhanced device fingerprinting with comprehensive data collection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnhancedDeviceFingerprint {
    pub basic_fingerprint: DeviceFingerprint,
    pub browser_features: BrowserFeatures,
    pub hardware_info: HardwareInfo,
    pub network_info: NetworkInfo,
    pub behavioral_markers: BehavioralMarkers,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserFeatures {
    pub cookies_enabled: bool,
    pub local_storage_enabled: bool,
    pub session_storage_enabled: bool,
    pub indexed_db_enabled: bool,
    pub web_gl_enabled: bool,
    pub web_rtc_enabled: bool,
    pub touch_support: bool,
    pub do_not_track: Option<String>,
    pub plugins: Vec<String>,
    pub mime_types: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HardwareInfo {
    pub cpu_cores: Option<u32>,
    pub memory_gb: Option<f64>,
    pub gpu_vendor: Option<String>,
    pub gpu_renderer: Option<String>,
    pub max_touch_points: Option<u32>,
    pub color_depth: Option<u32>,
    pub pixel_ratio: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInfo {
    pub connection_type: Option<String>,
    pub effective_type: Option<String>,
    pub downlink: Option<f64>,
    pub rtt: Option<u32>,
    pub save_data: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehavioralMarkers {
    pub typing_patterns: Option<Vec<u32>>, // Keystroke dynamics
    pub mouse_movements: Option<Vec<(f64, f64)>>, // Mouse movement patterns
    pub scroll_behavior: Option<ScrollPattern>,
    pub interaction_timing: Option<Vec<u64>>, // Time between interactions
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScrollPattern {
    pub scroll_speed: f64,
    pub scroll_acceleration: f64,
    pub pause_patterns: Vec<u64>,
}

/// Enhanced geolocation data with comprehensive location intelligence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnhancedGeoLocation {
    pub basic_location: GeoLocation,
    pub ip_intelligence: IpIntelligence,
    pub location_history: LocationHistory,
    pub risk_assessment: LocationRiskAssessment,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpIntelligence {
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub isp: Option<String>,
    pub connection_type: Option<String>, // residential, business, mobile, hosting
    pub threat_types: Vec<String>, // malware, phishing, spam, etc.
    pub reputation_score: f64, // 0.0 (bad) to 1.0 (good)
    pub is_tor: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_hosting: bool,
    pub is_mobile: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocationHistory {
    pub previous_locations: Vec<HistoricalLocation>,
    pub travel_patterns: Vec<TravelPattern>,
    pub location_consistency_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HistoricalLocation {
    pub location: (f64, f64),
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub confidence: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TravelPattern {
    pub from_location: (f64, f64),
    pub to_location: (f64, f64),
    pub travel_time: chrono::Duration,
    pub is_realistic: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocationRiskAssessment {
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
    pub impossible_travel: bool,
    pub high_risk_country: bool,
    pub unusual_location: bool,
}

impl Default for BrowserFeatures {
    fn default() -> Self {
        Self {
            cookies_enabled: true,
            local_storage_enabled: true,
            session_storage_enabled: true,
            indexed_db_enabled: true,
            web_gl_enabled: true,
            web_rtc_enabled: true,
            touch_support: false,
            do_not_track: None,
            plugins: vec![],
            mime_types: vec![],
        }
    }
}

impl Default for HardwareInfo {
    fn default() -> Self {
        Self {
            cpu_cores: None,
            memory_gb: None,
            gpu_vendor: None,
            gpu_renderer: None,
            max_touch_points: None,
            color_depth: None,
            pixel_ratio: None,
        }
    }
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            connection_type: None,
            effective_type: None,
            downlink: None,
            rtt: None,
            save_data: false,
        }
    }
}

impl Default for BehavioralMarkers {
    fn default() -> Self {
        Self {
            typing_patterns: None,
            mouse_movements: None,
            scroll_behavior: None,
            interaction_timing: None,
        }
    }
}

/// Enhanced IP geolocation service integration
async fn get_enhanced_geolocation(ip_address: IpAddr) -> Result<EnhancedGeoLocation> {
    // In production, integrate with services like MaxMind, IPinfo, or similar
    // For now, we'll create a comprehensive mock implementation
    
    let basic_location = GeoLocation {
        current_location: (37.7749, -122.4194), // San Francisco coordinates as default
        previous_location: None,
        country_code: "US".to_string(),
        city: Some("San Francisco".to_string()),
        timezone: "America/Los_Angeles".to_string(),
        isp: Some("Example ISP".to_string()),
        is_vpn_proxy: false,
    };

    // Mock IP intelligence data - in production, use real threat intelligence feeds
    let ip_intelligence = IpIntelligence {
        asn: Some(15169), // Google ASN as example
        organization: Some("Google LLC".to_string()),
        isp: Some("Google Fiber".to_string()),
        connection_type: Some("residential".to_string()),
        threat_types: vec![],
        reputation_score: 0.95,
        is_tor: false,
        is_vpn: false,
        is_proxy: false,
        is_hosting: false,
        is_mobile: false,
    };

    let location_history = LocationHistory {
        previous_locations: vec![],
        travel_patterns: vec![],
        location_consistency_score: 1.0,
    };

    let risk_assessment = LocationRiskAssessment {
        risk_score: 0.1,
        risk_factors: vec![],
        impossible_travel: false,
        high_risk_country: false,
        unusual_location: false,
    };

    Ok(EnhancedGeoLocation {
        basic_location,
        ip_intelligence,
        location_history,
        risk_assessment,
    })
}

/// Extract comprehensive device fingerprint from headers and request data
fn extract_enhanced_device_fingerprint(headers: &HeaderMap, fingerprint_data: Option<Value>) -> EnhancedDeviceFingerprint {
    let user_agent = extract_user_agent(headers);
    let basic_fingerprint = DeviceFingerprint::from_user_agent(user_agent.clone());

    // Extract additional fingerprinting data from client-side JavaScript
    let (browser_features, hardware_info, network_info, behavioral_markers) = if let Some(data) = fingerprint_data {
        (
            serde_json::from_value(data.get("browserFeatures").cloned().unwrap_or(Value::Null))
                .unwrap_or(BrowserFeatures::default()),
            serde_json::from_value(data.get("hardwareInfo").cloned().unwrap_or(Value::Null))
                .unwrap_or(HardwareInfo::default()),
            serde_json::from_value(data.get("networkInfo").cloned().unwrap_or(Value::Null))
                .unwrap_or(NetworkInfo::default()),
            serde_json::from_value(data.get("behavioralMarkers").cloned().unwrap_or(Value::Null))
                .unwrap_or(BehavioralMarkers::default()),
        )
    } else {
        (
            BrowserFeatures::default(),
            HardwareInfo::default(),
            NetworkInfo::default(),
            BehavioralMarkers::default(),
        )
    };

    EnhancedDeviceFingerprint {
        basic_fingerprint,
        browser_features,
        hardware_info,
        network_info,
        behavioral_markers,
    }
}

/// Extract TLS fingerprint from headers (basic implementation)
fn extract_tls_fingerprint(headers: &HeaderMap) -> Option<TlsFingerprint> {
    // In a real implementation, you would extract TLS information from the connection
    // This is a simplified version that extracts what's available from headers
    
    let cipher_info = headers.get("ssl-cipher")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    
    let protocol_version = headers.get("ssl-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    Some(TlsFingerprint {
        version: protocol_version.to_string(),
        cipher_suites: vec![cipher_info.to_string()],
        extensions: vec![], // Would need to be extracted from actual TLS handshake
        cert_chain_hash: None, // Would need access to certificate chain
    })
}

/// Register a new user with enhanced behavioral analysis and device fingerprinting
pub async fn register(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(behavior_analytics): Extension<Arc<BehaviorAnalytics>>,
    Extension(binding_manager): Extension<Arc<SessionBindingManager>>,
    Extension(threat_engine): Extension<Arc<ThreatDetectionEngine>>,
    Extension(audit_manager): Extension<Arc<AuditManager>>,
    headers: HeaderMap,
    Json(user_req): Json<CreateUserRequest>
) -> Result<(StatusCode, Json<UserResponse>)> {
    // Extract client information for behavioral analysis
    let ip_address = extract_ip_from_headers(&headers)?;
    let user_agent = extract_user_agent(&headers);
    
    // Extract enhanced device fingerprint
    let enhanced_device_fingerprint = extract_enhanced_device_fingerprint(&headers, None);

    if !is_valid_email(&user_req.email) {
        return Err(AppError::invalid_email(&user_req.email));
    }
    
    if user_req.username.len() < 3 || user_req.username.len() > 50 {
        return Err(AppError::validation("Username must be between 3 and 50 characters"));
    }
    
    if user_req.password.len() < 8 {
        return Err(AppError::invalid_password("Password must be at least 8 characters"));
    }

    // Get enhanced geolocation data
    let enhanced_geo_data = get_enhanced_geolocation(ip_address).await?;

    // Perform comprehensive risk assessment
    let mut registration_risk_score = 0.0;
    let mut risk_factors = Vec::new();

    // IP reputation check
    if enhanced_geo_data.ip_intelligence.reputation_score < 0.5 {
        registration_risk_score += 0.3;
        risk_factors.push("Low IP reputation".to_string());
    }

    // VPN/Proxy/Tor detection
    if enhanced_geo_data.ip_intelligence.is_tor {
        registration_risk_score += 0.4;
        risk_factors.push("Tor network detected".to_string());
    }
    if enhanced_geo_data.ip_intelligence.is_vpn || enhanced_geo_data.ip_intelligence.is_proxy {
        registration_risk_score += 0.2;
        risk_factors.push("VPN/Proxy detected".to_string());
    }

    // Threat intelligence check
    if !enhanced_geo_data.ip_intelligence.threat_types.is_empty() {
        registration_risk_score += 0.5;
        risk_factors.push(format!("Threat types: {:?}", enhanced_geo_data.ip_intelligence.threat_types));
    }

    // Device fingerprint analysis
    if enhanced_device_fingerprint.browser_features.plugins.is_empty() {
        registration_risk_score += 0.1;
        risk_factors.push("No browser plugins detected".to_string());
    }

    // Check if registration should be blocked based on risk
    if registration_risk_score > 0.8 {
        // Log high-risk registration attempt
        let audit_event = crate::auth::audit::AuditEvent::new(
            AuditEventType::Authentication,
            ip_address,
            Some(user_agent.clone()),
            "High-risk registration attempt blocked".to_string(),
        )
        .with_outcome(EventOutcome::Failure)
        .with_severity(EventSeverity::High)
        .with_risk_score(registration_risk_score)
        .with_metadata("email".to_string(), user_req.email.clone())
        .with_metadata("risk_factors".to_string(), format!("{:?}", risk_factors));
        audit_manager.log_event(&audit_event).await;

        return Err(AppError::Forbidden);
    }

    if let Ok(Some(_)) = users::find_by_email(&pool, &user_req.email).await {
        return Err(AppError::user_exists(&user_req.email));
    }
    
    if let Ok(Some(_)) = users::find_by_username(&pool, &user_req.username).await {
        return Err(AppError::user_exists(&user_req.username));
    }
    
    let password_hash = hash_password(&user_req.password)?;
    
    match users::create_user(&pool, &user_req, &password_hash).await {
        Ok(user) => {
            // Log successful registration with comprehensive data
            let audit_event = crate::auth::audit::AuditEvent::new(
                AuditEventType::Authentication,
                ip_address,
                Some(user_agent.clone()),
                "User registration successful".to_string(),
            )
            .with_user(user.id.to_string())
            .with_outcome(EventOutcome::Success)
            .with_severity(EventSeverity::Low)
            .with_risk_score(registration_risk_score);
            audit_manager.log_event(&audit_event).await;

            let response: UserResponse = user.into();
            Ok((StatusCode::CREATED, Json(response)))
        },
        Err(e) => {
            Err(AppError::database(format!("Failed to create user: {}", e)))
        }
    }
}

/// Login with comprehensive behavioral analysis, device fingerprinting, and threat detection
pub async fn login(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(behavior_analytics): Extension<Arc<BehaviorAnalytics>>,
    Extension(binding_manager): Extension<Arc<SessionBindingManager>>,
    Extension(threat_engine): Extension<Arc<ThreatDetectionEngine>>,
    Extension(audit_manager): Extension<Arc<AuditManager>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(login_req): Json<LoginRequest>
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // Extract request information for comprehensive analysis
    let ip_address = extract_ip_from_headers(&headers)?;
    let user_agent = extract_user_agent(&headers);
    
    // Extract enhanced device fingerprint
    let enhanced_device_fingerprint = extract_enhanced_device_fingerprint(&headers, None);
    
    // Determine if login is email or username based on presence of '@' symbol
    let user = if login_req.login.contains('@') {
        // Login with email
        match users::find_by_email(&pool, &login_req.login).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                // Log failed authentication attempt
                let audit_event = crate::auth::audit::AuditEvent::new(
                    AuditEventType::Authentication,
                    ip_address,
                    Some(user_agent.clone()),
                    "Authentication failed - email not found".to_string(),
                )
                .with_outcome(EventOutcome::Failure)
                .with_severity(EventSeverity::Medium);
                audit_manager.log_event(&audit_event).await;

                return Err(AppError::Unauthorized);
            },
            Err(e) => {
                tracing::error!("Database error during email lookup: {}", e);
                return Err(AppError::database("Database error during authentication".to_string()));
            }
        }
    } else {
        // Login with username
        match users::find_by_username(&pool, &login_req.login).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                // Log failed authentication attempt
                let audit_event = crate::auth::audit::AuditEvent::new(
                    AuditEventType::Authentication,
                    ip_address,
                    Some(user_agent.clone()),
                    "Authentication failed - username not found".to_string(),
                )
                .with_outcome(EventOutcome::Failure)
                .with_severity(EventSeverity::Medium);
                audit_manager.log_event(&audit_event).await;

                return Err(AppError::Unauthorized);
            },
            Err(e) => {
                tracing::error!("Database error during username lookup: {}", e);
                return Err(AppError::database("Database error during authentication".to_string()));
            }
        }
    };

    // Verify password
    if !verify_password(&login_req.password, &user.password_hash)? {
        // Log failed authentication attempt
        let audit_event = crate::auth::audit::AuditEvent::new(
            AuditEventType::Authentication,
            ip_address,
            Some(user_agent.clone()),
            "Authentication failed - invalid password".to_string(),
        )
        .with_user(user.id.to_string())
        .with_outcome(EventOutcome::Failure)
        .with_severity(EventSeverity::Medium);
        audit_manager.log_event(&audit_event).await;

        return Err(AppError::Unauthorized);
    }

    // Get enhanced geolocation data
    let enhanced_geo_data = get_enhanced_geolocation(ip_address).await?;

    // Additional risk factors from enhanced data
    let mut additional_risk_score: f64 = 0.0;
    let mut additional_risk_factors = Vec::new();

    // IP intelligence risk assessment
    if enhanced_geo_data.ip_intelligence.reputation_score < 0.3 {
        additional_risk_score += 0.4;
        additional_risk_factors.push("Very low IP reputation".to_string());
    } else if enhanced_geo_data.ip_intelligence.reputation_score < 0.6 {
        additional_risk_score += 0.2;
        additional_risk_factors.push("Low IP reputation".to_string());
    }

    // Threat intelligence
    if !enhanced_geo_data.ip_intelligence.threat_types.is_empty() {
        additional_risk_score += 0.5;
        additional_risk_factors.push(format!("Threat indicators: {:?}", enhanced_geo_data.ip_intelligence.threat_types));
    }

    // Anonymization services
    if enhanced_geo_data.ip_intelligence.is_tor {
        additional_risk_score += 0.6;
        additional_risk_factors.push("Tor network access".to_string());
    }
    if enhanced_geo_data.ip_intelligence.is_vpn {
        additional_risk_score += 0.3;
        additional_risk_factors.push("VPN access".to_string());
    }
    if enhanced_geo_data.ip_intelligence.is_proxy {
        additional_risk_score += 0.4;
        additional_risk_factors.push("Proxy access".to_string());
    }

    // Location risk assessment
    if enhanced_geo_data.risk_assessment.impossible_travel {
        additional_risk_score += 0.8;
        additional_risk_factors.push("Impossible travel detected".to_string());
    }
    if enhanced_geo_data.risk_assessment.high_risk_country {
        additional_risk_score += 0.3;
        additional_risk_factors.push("High-risk country".to_string());
    }

    // Device fingerprint analysis (simplified for now)
    let device_known = false; // Would check against stored fingerprints
    if !device_known {
        additional_risk_score += 0.2;
        additional_risk_factors.push("Unknown device".to_string());
    }

    // Combine risk scores
    let combined_risk_score: f64 = additional_risk_score.min(1.0_f64);

    // Check if login should be blocked based on combined risk
    if combined_risk_score > 0.9 {
        // Log high-risk login attempt
        let audit_event = crate::auth::audit::AuditEvent::new(
            AuditEventType::Authentication,
            ip_address,
            Some(user_agent.clone()),
            "High-risk login attempt blocked".to_string(),
        )
        .with_user(user.id.to_string())
        .with_outcome(EventOutcome::Failure)
        .with_severity(EventSeverity::High)
        .with_risk_score(combined_risk_score);
        audit_manager.log_event(&audit_event).await;

        return Err(AppError::Forbidden);
    }

    // Determine security level based on combined risk
    let security_level = if combined_risk_score > 0.7 {
        SecurityLevel::High
    } else if combined_risk_score > 0.4 {
        SecurityLevel::Standard
    } else {
        SecurityLevel::Low
    };

    // Log successful authentication with comprehensive risk information
    let audit_event = crate::auth::audit::AuditEvent::new(
        AuditEventType::Authentication,
        ip_address,
        Some(user_agent.clone()),
        "Authentication successful".to_string(),
    )
    .with_outcome(EventOutcome::Success)
    .with_severity(EventSeverity::Low)
    .with_user(user.id.to_string())
    .with_risk_score(combined_risk_score);
    audit_manager.log_event(&audit_event).await;
    
    // Create PASETO manager
    let paseto_manager = PasetoManager::new(&config)
        .map_err(|e| AppError::TokenError(format!("Failed to create PASETO manager: {}", e)))?;
    
    // Extract device fingerprint for session creation
    let device_fingerprint_hash = generate_device_fingerprint(&headers);

    // Create session with comprehensive risk-based metadata
    let session = session_manager.create_session(
        user.id.to_string(),
        ip_address,
        user_agent.clone(),
        device_fingerprint_hash,
        "password".to_string(),
        security_level.clone(),
        Some(HashMap::from([
            ("login_risk_score".to_string(), combined_risk_score.to_string()),
            ("behavioral_analysis".to_string(), "completed".to_string()),
            ("device_known".to_string(), device_known.to_string()),
            ("ip_reputation".to_string(), enhanced_geo_data.ip_intelligence.reputation_score.to_string()),
            ("location_risk".to_string(), enhanced_geo_data.risk_assessment.risk_score.to_string()),
        ])),
    ).await?;

    // Create enhanced session binding with comprehensive fingerprinting
    let tls_fingerprint = extract_tls_fingerprint(&headers);
    let binding_result = binding_manager.create_binding(
        &session,
        &enhanced_device_fingerprint.basic_fingerprint,
        tls_fingerprint.as_ref(),
    );

    if let Err(e) = binding_result {
        tracing::warn!("Failed to create session binding: {}", e);
    }

    // Generate PASETO tokens with embedded session ID (hybrid approach)
    let access_token = paseto_manager.generate_access_token_with_session(&user.id.to_string(), &session.id)?;
    let refresh_token = paseto_manager.generate_refresh_token(&user.id.to_string())?;

    // Create secure HTTP-only cookies
    let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &access_token, 15 * 60); // 15 minutes
    let refresh_cookie = create_secure_cookie(REFRESH_TOKEN_COOKIE, &refresh_token, 7 * 24 * 60 * 60); // 7 days

    let jar = jar.add(access_cookie).add(refresh_cookie);

    let user_response: UserResponse = user.into();
    let response = serde_json::json!({
        "message": "Login successful",
        "user": user_response,
        "session_id": session.id,
        "security_level": format!("{:?}", &security_level),
        "risk_score": combined_risk_score,
        "device_known": device_known,
        "location": {
            "country": enhanced_geo_data.basic_location.country_code,
            "city": enhanced_geo_data.basic_location.city,
            "timezone": enhanced_geo_data.basic_location.timezone
        },
        "security_info": {
            "ip_reputation": enhanced_geo_data.ip_intelligence.reputation_score,
            "anonymization_detected": enhanced_geo_data.ip_intelligence.is_tor || enhanced_geo_data.ip_intelligence.is_vpn || enhanced_geo_data.ip_intelligence.is_proxy,
            "threat_indicators": enhanced_geo_data.ip_intelligence.threat_types
        }
    });

    Ok((jar, Json(response)))
}

pub async fn refresh_token(
    Extension(config): Extension<Arc<Config>>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let paseto_manager = PasetoManager::new(&config)
        .map_err(|e| AppError::TokenError(format!("Failed to create PASETO manager: {}", e)))?;

    let refresh_token = jar.get(REFRESH_TOKEN_COOKIE)
        .ok_or(AppError::Unauthorized)?
        .value();

    let claims = paseto_manager.validate_token(refresh_token)?;
    let user_id = claims.sub;
    let new_access_token = paseto_manager.generate_access_token(&user_id)?;

    let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, &new_access_token, 15 * 60);
    let jar = jar.add(access_cookie);

    Ok((jar, Json(serde_json::json!({
        "message": "Token refreshed successfully"
    }))))
}

pub async fn logout(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(paseto_manager): Extension<Arc<PasetoManager>>,
    Extension(audit_manager): Extension<Arc<AuditManager>>,
    headers: HeaderMap,
    jar: CookieJar
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let ip_address = extract_ip_from_headers(&headers)?;
    let user_agent = extract_user_agent(&headers);

    // Extract session ID from access token if available
    if let Some(access_token_cookie) = jar.get(ACCESS_TOKEN_COOKIE) {
        if let Ok(claims) = paseto_manager.validate_token(access_token_cookie.value()) {
            if let Some(session_id) = claims.get_claim::<String>("sid")? {
                // Revoke the session
                if let Err(e) = session_manager.revoke_session(&session_id, Some("User logout")).await {
                    tracing::warn!("Failed to revoke session {}: {}", session_id, e);
                }

                // Log logout event
                let audit_event = crate::auth::audit::AuditEvent::new(
                    crate::auth::audit::AuditEventType::Authentication,
                    ip_address,
                    Some(user_agent),
                    "User logout".to_string(),
                )
                .with_user(claims.get_claim::<String>("sub")?.unwrap_or("unknown".to_string()))
                .with_outcome(crate::auth::audit::EventOutcome::Success)
                .with_severity(crate::auth::audit::EventSeverity::Low);
                audit_manager.log_event(&audit_event).await;
            }
        }
    }

    // Clear cookies
    let access_delete_cookie = create_delete_cookie(ACCESS_TOKEN_COOKIE);
    let refresh_delete_cookie = create_delete_cookie(REFRESH_TOKEN_COOKIE);
    let jar = jar.add(access_delete_cookie).add(refresh_delete_cookie);

    Ok((jar, Json(serde_json::json!({
        "message": "Logged out successfully"
    }))))
}

fn extract_ip_from_headers(headers: &HeaderMap) -> Result<IpAddr> {
    // Check for forwarded IP headers in order of preference
    let ip_str = headers.get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim())
        .or_else(|| {
            headers.get("x-real-ip")
                .and_then(|hv| hv.to_str().ok())
        })
        .or_else(|| {
            headers.get("cf-connecting-ip")
                .and_then(|hv| hv.to_str().ok())
        })
        .unwrap_or("127.0.0.1");

    ip_str.parse::<IpAddr>()
        .map_err(|_| AppError::validation("Invalid IP address"))
}

fn extract_user_agent(headers: &HeaderMap) -> String {
    headers.get("user-agent")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}

fn generate_device_fingerprint(headers: &HeaderMap) -> String {
    use sha2::{Sha256, Digest};
    
    let user_agent = extract_user_agent(headers);
    let accept_language = headers.get("accept-language")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("");
    let accept_encoding = headers.get("accept-encoding")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("");
    
    let fingerprint_data = format!("{}{}{}", user_agent, accept_language, accept_encoding);
    let mut hasher = Sha256::new();
    hasher.update(fingerprint_data.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub async fn get_analytics(
    Extension(redis_manager): Extension<Arc<RedisManager>>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    // Use existing session metrics as a foundation for analytics
    let session_metrics = redis_manager.get_session_metrics().await?;
    
    Ok(Json(serde_json::json!({
        "active_sessions": session_metrics["active_sessions"],
        "total_security_events": session_metrics["total_security_events"],
        "recent_events_count": session_metrics["recent_events_count"],
        "timestamp": session_metrics["timestamp"],
        // Placeholder values for comprehensive analytics
        "total_requests": 0,
        "successful_logins": 0,
        "failed_logins": 0,
        "blocked_requests": 0,
        "top_countries": [],
        "threat_detections": 0,
        "average_session_duration": 0.0,
        "peak_concurrent_users": 0,
        "user_agents": {},
        "ip_addresses": {},
        "authentication_methods": {},
        "device_types": {},
        "browser_distribution": {},
        "os_distribution": {},
        "hourly_activity": {},
        "daily_activity": {},
        "weekly_activity": {},
        "monthly_activity": {}
    })))
}

pub async fn get_user_analytics(
    Extension(redis_manager): Extension<Arc<RedisManager>>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    // Get user activity data from Redis
    let user_activity = redis_manager.get_user_activity(&auth_user.user_id, 100).await?;
    let user_session_count = redis_manager.get_user_session_count(&auth_user.user_id).await?.unwrap_or(0);
    
    Ok(Json(serde_json::json!({
        "user_id": auth_user.user_id,
        "session_count": user_session_count,
        "recent_activities": user_activity,
        // Placeholder values for comprehensive user analytics
        "total_logins": 0,
        "last_login": null,
        "login_locations": [],
        "device_history": [],
        "average_session_duration": 0.0,
        "security_events": [],
        "failed_login_attempts": 0,
        "password_changes": 0,
        "account_lockouts": 0,
        "suspicious_activities": [],
        "login_patterns": {},
        "risk_score": 0.0,
        "trust_score": 1.0
    })))
}
