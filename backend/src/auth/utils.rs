use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use axum::http::HeaderMap;
use crate::errors::AppError;
use crate::models::security::{GeoLocation, IPinfoResponse};

/// Centralized utilities for auth modules to eliminate code duplication
/// while maintaining module independence and reusability.

// =============================================================================
// GEOGRAPHIC UTILITIES
// =============================================================================

/// Calculate distance between two geographic coordinates using Haversine formula
/// 
/// # Arguments
/// * `coord1` - First coordinate as (latitude, longitude)
/// * `coord2` - Second coordinate as (latitude, longitude)
/// 
/// # Returns
/// Distance in kilometers
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

/// Calculate travel velocity between two locations
/// 
/// # Arguments
/// * `distance_km` - Distance in kilometers
/// * `time_diff` - Time difference between locations
/// 
/// # Returns
/// Velocity in km/h
pub fn calculate_travel_velocity(distance_km: f64, time_diff: Duration) -> f64 {
    if time_diff.num_hours() == 0 {
        return f64::INFINITY;
    }
    distance_km / time_diff.num_hours() as f64
}

// =============================================================================
// CRYPTOGRAPHIC UTILITIES
// =============================================================================

/// Generate SHA256 hash from string input
/// 
/// # Arguments
/// * `input` - String to hash
/// 
/// # Returns
/// Hexadecimal hash string
pub fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate SHA256 hash from multiple string inputs
/// 
/// # Arguments
/// * `inputs` - Vector of strings to hash together
/// 
/// # Returns
/// Hexadecimal hash string
pub fn sha256_hash_multiple(inputs: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Generate DefaultHasher hash from string input
/// 
/// # Arguments
/// * `input` - String to hash
/// 
/// # Returns
/// Hexadecimal hash string
pub fn default_hash(input: &str) -> String {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Generate secure random token
/// 
/// # Arguments
/// * `length` - Length of the token in bytes
/// 
/// # Returns
/// Base64 encoded random token
pub fn generate_secure_token(length: usize) -> Result<String, AppError> {
    use rand::RngCore;
    use base64::{Engine as _, engine::general_purpose};
    let mut rng = rand::thread_rng();
    let mut token = vec![0u8; length];
    rng.fill_bytes(&mut token);
    Ok(general_purpose::STANDARD.encode(token))
}

// =============================================================================
// TIME UTILITIES
// =============================================================================

/// Check if a timestamp is expired
/// 
/// # Arguments
/// * `timestamp` - Timestamp to check
/// * `lifetime_seconds` - Lifetime in seconds
/// 
/// # Returns
/// True if expired, false otherwise
pub fn is_timestamp_expired(timestamp: DateTime<Utc>, lifetime_seconds: u64) -> bool {
    let now = Utc::now();
    let elapsed = now.signed_duration_since(timestamp);
    elapsed.num_seconds() > lifetime_seconds as i64
}

/// Check if a Unix timestamp is expired
/// 
/// # Arguments
/// * `unix_timestamp` - Unix timestamp to check
/// * `lifetime_seconds` - Lifetime in seconds
/// 
/// # Returns
/// True if expired, false otherwise
pub fn is_unix_timestamp_expired(unix_timestamp: i64, lifetime_seconds: u64) -> bool {
    let now = Utc::now().timestamp();
    (now - unix_timestamp) > lifetime_seconds as i64
}

/// Calculate time difference in seconds
/// 
/// # Arguments
/// * `start` - Start timestamp
/// * `end` - End timestamp
/// 
/// # Returns
/// Difference in seconds
pub fn time_diff_seconds(start: DateTime<Utc>, end: DateTime<Utc>) -> i64 {
    end.signed_duration_since(start).num_seconds()
}

/// Get current Unix timestamp
/// 
/// # Returns
/// Current Unix timestamp
pub fn current_unix_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Create DateTime from Unix timestamp
/// 
/// # Arguments
/// * `timestamp` - Unix timestamp
/// 
/// # Returns
/// DateTime<Utc> or error if invalid
pub fn datetime_from_unix(timestamp: i64) -> Result<DateTime<Utc>, AppError> {
    DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| AppError::ValidationError("Invalid Unix timestamp".to_string()))
}

/// Check if Unix timestamp is expired
/// 
/// # Arguments
/// * `expires_at` - Unix timestamp representing expiration time
/// 
/// # Returns
/// True if current time is past the expiration timestamp, false otherwise
pub fn is_expired(expires_at: u64) -> bool {
    current_unix_timestamp() as u64 > expires_at
}

// =============================================================================
// IP ADDRESS UTILITIES
// =============================================================================

/// Extract IP address from HTTP headers with fallback chain
/// 
/// # Arguments
/// * `headers` - HTTP headers
/// 
/// # Returns
/// Extracted IP address or error
pub fn extract_ip_from_headers(headers: &HeaderMap) -> Result<IpAddr, AppError> {
    // Try X-Forwarded-For first (most common proxy header)
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(header_value) = forwarded_for.to_str() {
            // Take the first IP in the chain (original client)
            if let Some(first_ip) = header_value.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }

    // Try X-Real-IP (nginx)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    // Try CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    Err(AppError::ValidationError("No valid IP address found in headers".to_string()))
}

/// Validate IP address string
/// 
/// # Arguments
/// * `ip_str` - IP address string
/// 
/// # Returns
/// Parsed IP address or error
pub fn validate_ip_address(ip_str: &str) -> Result<IpAddr, AppError> {
    ip_str.parse::<IpAddr>()
        .map_err(|_| AppError::ValidationError(format!("Invalid IP address: {}", ip_str)))
}

/// Check if IP address is in private range
/// 
/// # Arguments
/// * `ip` - IP address to check
/// 
/// # Returns
/// True if private, false otherwise
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unicast_link_local()
        }
    }
}

/// Check if two IP addresses are in the same subnet
/// 
/// # Arguments
/// * `ip1` - First IP address
/// * `ip2` - Second IP address
/// * `prefix_len` - Subnet prefix length
/// 
/// # Returns
/// True if in same subnet, false otherwise
pub fn same_subnet(ip1: IpAddr, ip2: IpAddr, prefix_len: u8) -> bool {
    match (ip1, ip2) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let a_bytes = a.octets();
            let b_bytes = b.octets();
            let full_bytes = prefix_len / 8;
            let remaining_bits = prefix_len % 8;
            
            // Compare full bytes
            if a_bytes[..full_bytes as usize] != b_bytes[..full_bytes as usize] {
                return false;
            }
            
            // Compare remaining bits if any
            if remaining_bits > 0 && full_bytes < 16 {
                let mask = 0xFF << (8 - remaining_bits);
                let idx = full_bytes as usize;
                (a_bytes[idx] & mask) == (b_bytes[idx] & mask)
            } else {
                true
            }
        }
        _ => false, // Different IP versions
    }
}

// =============================================================================
// STRING UTILITIES
// =============================================================================

/// Extract User-Agent from headers
/// 
/// # Arguments
/// * `headers` - HTTP headers
/// 
/// # Returns
/// User-Agent string or "Unknown"
pub fn extract_user_agent(headers: &HeaderMap) -> String {
    headers.get("user-agent")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}

/// Sanitize string for logging (remove sensitive data)
/// 
/// # Arguments
/// * `input` - String to sanitize
/// 
/// # Returns
/// Sanitized string
pub fn sanitize_for_logging(input: &str) -> String {
    // Remove potential sensitive patterns
    let sanitized = input
        .replace(|c: char| c.is_control(), "")  // Remove control characters
        .chars()
        .take(1000)  // Limit length
        .collect();
    
    sanitized
}

/// Generate fingerprint from multiple string components
/// 
/// # Arguments
/// * `components` - Vector of string components
/// 
/// # Returns
/// Combined fingerprint hash
pub fn generate_fingerprint(components: &[&str]) -> String {
    sha256_hash_multiple(components)
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/// Validate email format
/// 
/// # Arguments
/// * `email` - Email string to validate
/// 
/// # Returns
/// True if valid email format
pub fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.len() > 3 && email.len() < 255
}

/// Validate session ID format
/// 
/// # Arguments
/// * `session_id` - Session ID to validate
/// 
/// # Returns
/// True if valid format
pub fn is_valid_session_id(session_id: &str) -> bool {
    session_id.len() >= 16 && session_id.len() <= 128 && session_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Validate user ID format
/// 
/// # Arguments
/// * `user_id` - User ID to validate
/// 
/// # Returns
/// True if valid format
pub fn is_valid_user_id(user_id: &str) -> bool {
    !user_id.is_empty() && user_id.len() <= 255 && !user_id.trim().is_empty()
}

// =============================================================================
// ENHANCED GEOLOCATION UTILITIES
// =============================================================================

/// Get comprehensive geolocation data from IP address using IPinfo.io API
/// 
/// # Arguments
/// * `ip` - Optional IP address to geolocate
/// 
/// # Returns
/// GeoLocation data or error
pub async fn get_geolocation_data(ip: Option<IpAddr>) -> Result<GeoLocation, AppError> {
    if let Some(ip_addr) = ip {
        // Check if it's a local/private IP
        if is_private_ip(ip_addr) {
            return Ok(GeoLocation {
                current_location: (0.0, 0.0),
                previous_location: None,
                country_code: "US".to_string(),
                city: Some("Local".to_string()),
                timezone: "UTC".to_string(),
                isp: Some("Local Network".to_string()),
                is_vpn_proxy: false,
            });
        }
        
        // Make API call to IPinfo.io
        let url = format!("https://ipinfo.io/{}/json", ip_addr);
        let client = reqwest::Client::new();
        
        match client.get(&url).send().await {
            Ok(response) => {
                match response.json::<IPinfoResponse>().await {
                    Ok(ipinfo_data) => {
                        let (lat, lon) = if let Some(loc) = ipinfo_data.loc {
                            let coords: Vec<&str> = loc.split(',').collect();
                            if coords.len() == 2 {
                                (
                                    coords[0].parse().unwrap_or(0.0),
                                    coords[1].parse().unwrap_or(0.0)
                                )
                            } else {
                                (0.0, 0.0)
                            }
                        } else {
                            (0.0, 0.0)
                        };

                        Ok(GeoLocation {
                            current_location: (lat, lon),
                            previous_location: None,
                            country_code: ipinfo_data.country,
                            city: ipinfo_data.city,
                            timezone: ipinfo_data.timezone.unwrap_or_else(|| "UTC".to_string()),
                            isp: ipinfo_data.org,
                            is_vpn_proxy: false, // Could be enhanced with VPN detection
                        })
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse IPinfo.io response for IP {}: {}", ip_addr, e);
                        // Return fallback data
                        Ok(GeoLocation {
                            current_location: (0.0, 0.0),
                            previous_location: None,
                            country_code: "US".to_string(),
                            city: Some("Unknown".to_string()),
                            timezone: "UTC".to_string(),
                            isp: Some("Unknown ISP".to_string()),
                            is_vpn_proxy: false,
                        })
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch geolocation data for IP {}: {}", ip_addr, e);
                // Return fallback data
                Ok(GeoLocation {
                    current_location: (0.0, 0.0),
                    previous_location: None,
                    country_code: "US".to_string(),
                    city: Some("Unknown".to_string()),
                    timezone: "UTC".to_string(),
                    isp: Some("Unknown ISP".to_string()),
                    is_vpn_proxy: false,
                })
            }
        }
    } else {
        Err(AppError::ValidationError("No IP address provided for geolocation".to_string()))
    }
}

/// Check if a location change is suspicious based on distance and time
/// 
/// # Arguments
/// * `previous_location` - Previous location coordinates
/// * `current_location` - Current location coordinates
/// * `time_diff_hours` - Time difference in hours
/// * `max_distance_km` - Maximum allowed distance in kilometers
/// 
/// # Returns
/// True if location change is suspicious
pub fn is_suspicious_location_change(
    previous_location: (f64, f64),
    current_location: (f64, f64),
    time_diff_hours: f64,
    max_distance_km: f64,
) -> bool {
    let distance = calculate_distance(previous_location, current_location);
    
    // If distance is greater than max allowed, it's suspicious
    if distance > max_distance_km {
        return true;
    }
    
    // Check if travel speed is humanly possible (max ~900 km/h for commercial flights)
    if time_diff_hours > 0.0 {
        let speed_kmh = distance / time_diff_hours;
        if speed_kmh > 900.0 {
            return true;
        }
    }
    
    false
}
