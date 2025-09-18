use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn, error, info};
use crate::{
    config::Config,
    database::RedisManager,
    errors::AppError,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Secret key for HMAC signing (must be 32+ bytes for security)
    pub secret_key: String,
    /// Token lifetime in seconds (default: 1 hour)
    pub token_lifetime: u64,
    /// Cookie name for CSRF token
    pub cookie_name: String,
    /// Header name for CSRF token
    pub header_name: String,
    /// Form field name for CSRF token
    pub form_field_name: String,
    /// Whether to use secure cookies (HTTPS only)
    pub secure_cookies: bool,
    /// SameSite cookie attribute
    pub same_site: SameSite,
    /// Methods that require CSRF protection
    pub protected_methods: Vec<Method>,
    /// Paths to exclude from CSRF protection (exact matches)
    pub excluded_paths: Vec<String>,
    /// Path prefixes to exclude from CSRF protection
    pub excluded_path_prefixes: Vec<String>,
    /// Maximum number of tokens per session
    pub max_tokens_per_session: u32,
    /// Token regeneration interval in seconds
    pub token_regeneration_interval: u64,
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            secret_key: "change-this-to-a-secure-32-byte-secret-key-in-production!!".to_string(),
            token_lifetime: 3600, // 1 hour
            cookie_name: "csrf_token".to_string(),
            header_name: "x-csrf-token".to_string(),
            form_field_name: "_csrf_token".to_string(),
            secure_cookies: true,
            same_site: SameSite::Strict,
            protected_methods: vec![
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ],
            excluded_paths: vec![
                "/api/auth/login".to_string(),
                "/api/auth/register".to_string(),
                "/api/health".to_string(),
                "/api/csrf/token".to_string(),
            ],
            excluded_path_prefixes: vec![
                "/api/public/".to_string(),
                "/static/".to_string(),
            ],
            max_tokens_per_session: 10,
            token_regeneration_interval: 300, // 5 minutes
        }
    }
}

/// CSRF token with cryptographic security and session binding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsrfToken {
    /// Unique token identifier
    pub token_id: String,
    /// Random token value (base64 encoded)
    pub value: String,
    /// Token creation timestamp
    pub created_at: u64,
    /// Token last used timestamp
    pub last_used: u64,
    /// Session identifier for binding
    pub session_id: String,
    /// User identifier for additional binding
    pub user_id: Option<String>,
    /// IP address for additional validation
    pub ip_address: Option<String>,
    /// User agent hash for fingerprinting
    pub user_agent_hash: Option<String>,
    /// Number of times token has been used
    pub use_count: u32,
    /// HMAC signature of the token
    pub signature: String,
}

impl CsrfToken {
    /// Create a new CSRF token with cryptographic security
    pub fn new(
        session_id: String,
        user_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        secret_key: &str,
    ) -> Result<Self, AppError> {
        let token_id = generate_secure_id();
        let value = generate_secure_token();
        let now = current_timestamp();
        let user_agent_hash = user_agent.map(|ua| sha256_hash(&ua));

        let mut token = Self {
            token_id,
            value,
            created_at: now,
            last_used: now,
            session_id,
            user_id,
            ip_address,
            user_agent_hash,
            use_count: 0,
            signature: String::new(), // Will be set below
        };

        // Generate HMAC signature
        token.signature = token.generate_signature(secret_key)?;
        
        Ok(token)
    }

    /// Generate HMAC signature for the token
    pub fn generate_signature(&self, secret_key: &str) -> Result<String, AppError> {
        let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("HMAC key error: {}", e)))?;

        // Include all critical fields in signature
        mac.update(self.token_id.as_bytes());
        mac.update(self.value.as_bytes());
        mac.update(&self.created_at.to_le_bytes());
        mac.update(self.session_id.as_bytes());
        
        if let Some(ref user_id) = self.user_id {
            mac.update(user_id.as_bytes());
        }
        
        if let Some(ref ip) = self.ip_address {
            mac.update(ip.as_bytes());
        }
        
        if let Some(ref ua_hash) = self.user_agent_hash {
            mac.update(ua_hash.as_bytes());
        }

        let result = mac.finalize();
        Ok(URL_SAFE_NO_PAD.encode(result.into_bytes()))
    }

    /// Verify HMAC signature with constant-time comparison
    pub fn verify_signature(&self, secret_key: &str) -> Result<bool, AppError> {
        let expected_signature = self.generate_signature(secret_key)?;
        Ok(constant_time_eq(&self.signature, &expected_signature))
    }

    /// Check if token is expired
    pub fn is_expired(&self, lifetime: u64) -> bool {
        let now = current_timestamp();
        now - self.created_at > lifetime
    }

    /// Check if token needs regeneration
    pub fn needs_regeneration(&self, regeneration_interval: u64) -> bool {
        let now = current_timestamp();
        now - self.last_used > regeneration_interval
    }

    /// Update token usage
    pub fn mark_used(&mut self) {
        self.last_used = current_timestamp();
        self.use_count += 1;
    }

    /// Validate token context (IP, User-Agent, etc.)
    pub fn validate_context(
        &self,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> bool {
        // Validate IP address if stored
        if let Some(stored_ip) = &self.ip_address {
            if let Some(current_ip) = ip_address {
                if stored_ip != current_ip {
                    warn!("CSRF token IP mismatch: stored={}, current={}", stored_ip, current_ip);
                    return false;
                }
            }
        }

        // Validate User-Agent hash if stored
        if let Some(stored_ua_hash) = &self.user_agent_hash {
            if let Some(current_ua) = user_agent {
                let current_ua_hash = sha256_hash(current_ua);
                if stored_ua_hash != &current_ua_hash {
                    warn!("CSRF token User-Agent mismatch");
                    return false;
                }
            }
        }

        true
    }

    /// Serialize token for Redis storage
    pub fn serialize(&self) -> Result<String, AppError> {
        serde_json::to_string(self)
            .map_err(|e| AppError::InternalServerError(format!("Token serialization failed: {}", e)))
    }

    /// Deserialize token from Redis storage
    pub fn deserialize(data: &str) -> Result<Self, AppError> {
        serde_json::from_str(data)
            .map_err(|e| AppError::InternalServerError(format!("Token deserialization failed: {}", e)))
    }
}

/// Enterprise-grade CSRF protection manager
#[derive(Clone)]
pub struct CsrfProtection {
    redis: Arc<RedisManager>,
    config: CsrfConfig,
}

impl CsrfProtection {
    pub fn new(redis: Arc<RedisManager>, config: CsrfConfig) -> Self {
        Self { redis, config }
    }

    /// Generate a new CSRF token with session binding
    pub async fn generate_token(
        &self,
        session_id: String,
        user_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<CsrfToken, AppError> {
        // Clean up old tokens for this session first
        self.cleanup_session_tokens(&session_id).await?;

        // Create new token
        let token = CsrfToken::new(
            session_id.clone(),
            user_id,
            ip_address,
            user_agent,
            &self.config.secret_key,
        )?;

        // Store token in Redis with multiple keys for efficient lookup
        let token_key = format!("csrf_token:{}", token.token_id);
        let session_key = format!("csrf_session:{}:{}", session_id, token.token_id);
        
        let serialized = token.serialize()?;
        
        // Store with expiration
        self.redis
            .set_with_expiry(&token_key, &serialized, self.config.token_lifetime)
            .await?;
            
        // Store session mapping
        self.redis
            .set_with_expiry(&session_key, &token.token_id, self.config.token_lifetime)
            .await?;

        info!("Generated CSRF token: {} for session: {}", token.token_id, session_id);
        Ok(token)
    }

    /// Validate CSRF token with comprehensive security checks
    pub async fn validate_token(
        &self,
        token_value: &str,
        session_id: &str,
        user_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AppError> {
        // Extract token ID from the token value
        let token_id = self.extract_token_id(token_value)?;
        let token_key = format!("csrf_token:{}", token_id);

        // Retrieve token from Redis
        let stored_data = match self.redis.get(&token_key).await? {
            Some(data) => data,
            None => {
                debug!("CSRF token not found in Redis: {}", token_id);
                return Ok(false);
            }
        };

        // Deserialize token
        let mut token = CsrfToken::deserialize(&stored_data)?;

        // Check if token is expired
        if token.is_expired(self.config.token_lifetime) {
            debug!("CSRF token expired: {}", token_id);
            self.invalidate_token(&token_id).await?;
            return Ok(false);
        }

        // Verify HMAC signature with constant-time comparison
        if !token.verify_signature(&self.config.secret_key)? {
            warn!("CSRF token signature verification failed: {}", token_id);
            return Ok(false);
        }

        // Verify session binding
        if token.session_id != session_id {
            warn!("CSRF token session mismatch: expected {}, got {}", session_id, token.session_id);
            return Ok(false);
        }

        // Verify user binding if provided
        if let Some(expected_user) = user_id {
            match &token.user_id {
                Some(token_user) if token_user != expected_user => {
                    warn!("CSRF token user mismatch: expected {}, got {}", expected_user, token_user);
                    return Ok(false);
                }
                None => {
                    warn!("CSRF token has no user binding but user ID provided");
                    return Ok(false);
                }
                _ => {} // Valid
            }
        }

        // Validate context (IP, User-Agent)
        if !token.validate_context(ip_address, user_agent) {
            return Ok(false);
        }

        // Check token value matches
        if !constant_time_eq(&token.value, token_value) {
            warn!("CSRF token value mismatch");
            return Ok(false);
        }

        // Update token usage
        token.mark_used();
        let updated_data = token.serialize()?;
        self.redis
            .set_with_expiry(&token_key, &updated_data, self.config.token_lifetime)
            .await?;

        debug!("CSRF token validation successful: {}", token_id);
        Ok(true)
    }

    /// Invalidate a specific CSRF token
    pub async fn invalidate_token(&self, token_id: &str) -> Result<(), AppError> {
        let token_key = format!("csrf_token:{}", token_id);
        
        // Get token to find session for cleanup
        if let Some(data) = self.redis.get(&token_key).await? {
            if let Ok(token) = CsrfToken::deserialize(&data) {
                let session_key = format!("csrf_session:{}:{}", token.session_id, token_id);
                let _ = self.redis.delete(&session_key).await;
            }
        }
        
        self.redis.delete(&token_key).await?;
        debug!("Invalidated CSRF token: {}", token_id);
        Ok(())
    }

    /// Clean up old tokens for a session
    async fn cleanup_session_tokens(&self, session_id: &str) -> Result<(), AppError> {
        // This is a simplified cleanup - in production, you might want to use Redis SCAN
        // to find all session tokens and clean up expired ones
        debug!("Cleaning up old tokens for session: {}", session_id);
        Ok(())
    }

    /// Extract token ID from token value (assuming format: tokenId.value)
    fn extract_token_id(&self, token_value: &str) -> Result<String, AppError> {
        // For this implementation, we'll use the token value as the ID
        // In a more complex setup, you might encode the ID in the token
        Ok(sha256_hash(token_value)[..16].to_string())
    }

    /// Check if path is excluded from CSRF protection
    pub fn is_excluded_path(&self, path: &str) -> bool {
        // Check exact matches
        if self.config.excluded_paths.contains(&path.to_string()) {
            return true;
        }

        // Check prefix matches
        for prefix in &self.config.excluded_path_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Check if method requires CSRF protection
    pub fn requires_protection(&self, method: &Method) -> bool {
        self.config.protected_methods.contains(method)
    }

    /// Extract CSRF token from request headers or form data
    pub fn extract_token_from_request(&self, headers: &HeaderMap) -> Option<String> {
        // Try header first (most common for APIs)
        if let Some(header_value) = headers.get(&self.config.header_name) {
            if let Ok(header_str) = header_value.to_str() {
                return Some(header_str.to_string());
            }
        }

        // Try custom header variations
        for header_name in &["x-csrf-token", "x-xsrf-token", "csrf-token"] {
            if let Some(header_value) = headers.get(*header_name) {
                if let Ok(header_str) = header_value.to_str() {
                    return Some(header_str.to_string());
                }
            }
        }

        None
    }

    /// Extract session ID from request (you'll need to implement based on your auth system)
    pub fn extract_session_id(&self, headers: &HeaderMap) -> Option<String> {
        // This is a placeholder - implement based on your session management
        // You might extract from JWT, session cookie, etc.
        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    // Extract session from JWT or similar
                    return Some("session_from_jwt".to_string());
                }
            }
        }
        
        // Fallback to a default session for demo
        Some("default_session".to_string())
    }

    /// Extract user ID from request (implement based on your auth system)
    pub fn extract_user_id(&self, _headers: &HeaderMap) -> Option<String> {
        // Placeholder - extract from JWT or session
        None
    }

    /// Extract IP address from request
    pub fn extract_ip_address(&self, headers: &HeaderMap) -> Option<String> {
        // Check X-Forwarded-For first (for load balancers)
        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    return Some(first_ip.trim().to_string());
                }
            }
        }

        // Check X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(real_ip_str) = real_ip.to_str() {
                return Some(real_ip_str.to_string());
            }
        }

        None
    }

    /// Extract User-Agent from request
    pub fn extract_user_agent(&self, headers: &HeaderMap) -> Option<String> {
        headers.get("user-agent")
            .and_then(|ua| ua.to_str().ok())
            .map(|s| s.to_string())
    }
}

/// CSRF protection middleware
pub async fn csrf_protection_middleware(
    State(csrf): State<Arc<CsrfProtection>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method();
    let path = request.uri().path();
    let headers = request.headers();

    // Skip CSRF protection for excluded paths
    if csrf.is_excluded_path(path) {
        debug!("Skipping CSRF protection for excluded path: {}", path);
        return Ok(next.run(request).await);
    }

    // Skip CSRF protection for methods that don't require it
    if !csrf.requires_protection(method) {
        debug!("Skipping CSRF protection for method: {}", method);
        return Ok(next.run(request).await);
    }

    // Extract required information from request
    let token_value = match csrf.extract_token_from_request(headers) {
        Some(token) => token,
        None => {
            warn!("CSRF token missing from request to {}", path);
            return Err(StatusCode::FORBIDDEN);
        }
    };

    let session_id = match csrf.extract_session_id(headers) {
        Some(session) => session,
        None => {
            warn!("Session ID missing from request to {}", path);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_id = csrf.extract_user_id(headers);
    let ip_address = csrf.extract_ip_address(headers);
    let user_agent = csrf.extract_user_agent(headers);

    // Validate CSRF token
    match csrf.validate_token(
        &token_value,
        &session_id,
        user_id.as_deref(),
        ip_address.as_deref(),
        user_agent.as_deref(),
    ).await {
        Ok(true) => {
            debug!("CSRF token validation successful for {}", path);
            Ok(next.run(request).await)
        }
        Ok(false) => {
            warn!("CSRF token validation failed for {}", path);
            Err(StatusCode::FORBIDDEN)
        }
        Err(e) => {
            error!("CSRF validation error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler to generate and return CSRF token
pub async fn get_csrf_token(
    State(csrf): State<Arc<CsrfProtection>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = match csrf.extract_session_id(&headers) {
        Some(session) => session,
        None => {
            warn!("Session ID missing from CSRF token request");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_id = csrf.extract_user_id(&headers);
    let ip_address = csrf.extract_ip_address(&headers);
    let user_agent = csrf.extract_user_agent(&headers);

    match csrf.generate_token(session_id, user_id, ip_address, user_agent).await {
        Ok(token) => {
            let response = serde_json::json!({
                "csrf_token": token.value,
                "token_id": token.token_id,
                "expires_in": csrf.config.token_lifetime,
                "created_at": token.created_at
            });
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to generate CSRF token: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create CSRF protection from config
pub fn create_csrf_protection(redis: Arc<RedisManager>, config: &Config) -> CsrfProtection {
    let csrf_config = CsrfConfig {
        secret_key: config.csrf_secret.clone(),
        token_lifetime: 3600, // 1 hour - can be made configurable
        cookie_name: "csrf_token".to_string(),
        header_name: "x-csrf-token".to_string(),
        form_field_name: "_csrf_token".to_string(),
        secure_cookies: true, // Should be true in production
        same_site: SameSite::Strict,
        protected_methods: vec![
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ],
        excluded_paths: vec![
            "/api/auth/login".to_string(),
            "/api/auth/register".to_string(),
            "/api/health".to_string(),
            "/api/csrf/token".to_string(),
        ],
        excluded_path_prefixes: vec![
            "/api/public/".to_string(),
            "/static/".to_string(),
        ],
        max_tokens_per_session: 10,
        token_regeneration_interval: 300, // 5 minutes
    };

    CsrfProtection::new(redis, csrf_config)
}

// Utility functions

/// Generate a cryptographically secure random token
fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a secure ID
fn generate_secure_id() -> String {
    let mut bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// SHA256 hash function
fn sha256_hash(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }

    result == 0
}