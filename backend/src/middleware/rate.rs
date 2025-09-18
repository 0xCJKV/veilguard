use axum::{
    extract::{Request, Extension},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
    Json,
};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn, error};
use crate::{
    config::Config,
    database::RedisManager,
    errors::AppError,
};

/// Rate limiting algorithms
#[derive(Debug, Clone)]
pub enum RateLimitAlgorithm {
    /// Fixed window counter
    FixedWindow,
    /// Sliding window log
    SlidingWindow,
    /// Token bucket
    TokenBucket,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_seconds: u64,
    pub algorithm: RateLimitAlgorithm,
    pub burst_allowance: Option<u32>,
    pub whitelist_ips: Vec<IpAddr>,
    pub blacklist_ips: Vec<IpAddr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window_seconds: 60,
            algorithm: RateLimitAlgorithm::FixedWindow,
            burst_allowance: Some(20),
            whitelist_ips: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            blacklist_ips: vec![],
        }
    }
}

/// Rate limiter with Redis backend
#[derive(Clone)]
pub struct RateLimiter {
    redis: Arc<RedisManager>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(redis: Arc<RedisManager>, config: RateLimitConfig) -> Self {
        Self { redis, config }
    }

    /// Extract client identifier from request
    fn extract_client_id(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> String {
        // Priority order for client identification:
        // 1. X-Forwarded-For (for load balancers/proxies)
        // 2. X-Real-IP (for reverse proxies)
        // 3. Direct IP address
        // 4. User-Agent + IP combination for additional uniqueness

        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                // Take the first IP in the chain (original client)
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    let clean_ip = first_ip.trim();
                    if let Ok(parsed_ip) = clean_ip.parse::<IpAddr>() {
                        return format!("ip:{}", parsed_ip);
                    }
                }
            }
        }

        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(real_ip_str) = real_ip.to_str() {
                if let Ok(parsed_ip) = real_ip_str.parse::<IpAddr>() {
                    return format!("ip:{}", parsed_ip);
                }
            }
        }

        if let Some(ip_addr) = ip {
            return format!("ip:{}", ip_addr);
        }

        // Fallback: use User-Agent hash if no IP available
        if let Some(user_agent) = headers.get("user-agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                return format!("ua:{}", sha256_hash(ua_str));
            }
        }

        // Ultimate fallback
        "unknown".to_string()
    }

    /// Check if IP is whitelisted
    fn is_whitelisted(&self, ip: Option<IpAddr>) -> bool {
        if let Some(ip_addr) = ip {
            self.config.whitelist_ips.contains(&ip_addr)
        } else {
            false
        }
    }

    /// Check if IP is blacklisted
    fn is_blacklisted(&self, ip: Option<IpAddr>) -> bool {
        if let Some(ip_addr) = ip {
            self.config.blacklist_ips.contains(&ip_addr)
        } else {
            false
        }
    }

    /// Fixed window rate limiting
    async fn check_fixed_window(&self, client_id: &str) -> Result<RateLimitResult, AppError> {
        let window_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() / self.config.window_seconds * self.config.window_seconds;
        
        let key = format!("rate_limit:{}:{}", client_id, window_start);
        
        let current_count = self.redis
            .increment_rate_limit(&key, self.config.window_seconds)
            .await?;

        let remaining = if current_count <= self.config.requests_per_window as i64 {
            self.config.requests_per_window as i64 - current_count
        } else {
            0
        };

        let reset_time = window_start + self.config.window_seconds;
        let allowed = current_count <= self.config.requests_per_window as i64;

        Ok(RateLimitResult {
            allowed,
            limit: self.config.requests_per_window,
            remaining: remaining.max(0) as u32,
            reset_time,
            retry_after: if allowed { None } else { Some(reset_time - SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) },
        })
    }

    /// Sliding window rate limiting (more accurate but more expensive)
    async fn check_sliding_window(&self, client_id: &str) -> Result<RateLimitResult, AppError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let _window_start = now - self.config.window_seconds;
        
        // Use a sorted set to track request timestamps
        let key = format!("rate_limit_sliding:{}", client_id);
        
        // Remove old entries and count current requests
        // This is a simplified implementation - in production, you'd use Lua scripts for atomicity
        let current_count = self.redis
            .increment_rate_limit(&format!("{}:{}", key, now), self.config.window_seconds)
            .await?;

        let remaining = if current_count <= self.config.requests_per_window as i64 {
            self.config.requests_per_window as i64 - current_count
        } else {
            0
        };

        let allowed = current_count <= self.config.requests_per_window as i64;
        let reset_time = now + self.config.window_seconds;

        Ok(RateLimitResult {
            allowed,
            limit: self.config.requests_per_window,
            remaining: remaining.max(0) as u32,
            reset_time,
            retry_after: if allowed { None } else { Some(self.config.window_seconds) },
        })
    }

    /// Token bucket rate limiting (allows bursts)
    async fn check_token_bucket(&self, client_id: &str) -> Result<RateLimitResult, AppError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = format!("token_bucket:{}", client_id);
        let last_refill_key = format!("token_bucket_refill:{}", client_id);
        
        // Get current tokens and last refill time
        let current_tokens = self.redis.get(&bucket_key).await?
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(self.config.requests_per_window);
            
        let last_refill = self.redis.get(&last_refill_key).await?
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(now);

        // Calculate tokens to add based on time elapsed
        let time_elapsed = now - last_refill;
        let tokens_to_add = (time_elapsed * self.config.requests_per_window as u64) / self.config.window_seconds;
        let new_tokens = (current_tokens + tokens_to_add as u32).min(
            self.config.requests_per_window + self.config.burst_allowance.unwrap_or(0)
        );

        let allowed = new_tokens > 0;
        let tokens_after = if allowed { new_tokens - 1 } else { new_tokens };

        // Update Redis
        if tokens_to_add > 0 || allowed {
            self.redis.set_with_expiry(&bucket_key, &tokens_after.to_string(), self.config.window_seconds * 2).await?;
            self.redis.set_with_expiry(&last_refill_key, &now.to_string(), self.config.window_seconds * 2).await?;
        }

        let retry_after = if allowed { 
            None 
        } else { 
            Some(self.config.window_seconds / self.config.requests_per_window as u64) 
        };

        Ok(RateLimitResult {
            allowed,
            limit: self.config.requests_per_window,
            remaining: tokens_after,
            reset_time: now + self.config.window_seconds,
            retry_after,
        })
    }

    /// Check rate limit using configured algorithm
    pub async fn check_rate_limit(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> Result<RateLimitResult, AppError> {
        // Check blacklist first
        if self.is_blacklisted(ip) {
            warn!("Blocked request from blacklisted IP: {:?}", ip);
            return Ok(RateLimitResult {
                allowed: false,
                limit: 0,
                remaining: 0,
                reset_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600, // 1 hour
                retry_after: Some(3600),
            });
        }

        // Skip rate limiting for whitelisted IPs
        if self.is_whitelisted(ip) {
            debug!("Allowing whitelisted IP: {:?}", ip);
            return Ok(RateLimitResult {
                allowed: true,
                limit: u32::MAX,
                remaining: u32::MAX,
                reset_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + self.config.window_seconds,
                retry_after: None,
            });
        }

        let client_id = self.extract_client_id(headers, ip);
        debug!("Rate limiting check for client: {}", client_id);

        match self.config.algorithm {
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window(&client_id).await,
            RateLimitAlgorithm::SlidingWindow => self.check_sliding_window(&client_id).await,
            RateLimitAlgorithm::TokenBucket => self.check_token_bucket(&client_id).await,
        }
    }
}

/// Rate limit check result
#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: u64,
    pub retry_after: Option<u64>,
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();
    
    // Extract IP from connection info or headers
    let ip = extract_ip_from_request(&request);
    
    match rate_limiter.check_rate_limit(headers, ip).await {
        Ok(result) => {
            if result.allowed {
                let mut response = next.run(request).await;
                
                // Add rate limit headers
                let response_headers = response.headers_mut();
                response_headers.insert("X-RateLimit-Limit", result.limit.to_string().parse().unwrap());
                response_headers.insert("X-RateLimit-Remaining", result.remaining.to_string().parse().unwrap());
                response_headers.insert("X-RateLimit-Reset", result.reset_time.to_string().parse().unwrap());
                
                Ok(response)
            } else {
                warn!("Rate limit exceeded for IP: {:?}", ip);
                
                let body = serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": result.retry_after
                });
                
                let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", result.limit.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers.insert("X-RateLimit-Reset", result.reset_time.to_string().parse().unwrap());
                
                if let Some(retry_after) = result.retry_after {
                    headers.insert("Retry-After", retry_after.to_string().parse().unwrap());
                }
                
                Ok(response)
            }
        }
        Err(e) => {
            error!("Rate limiting error: {}", e);
            // Fail open - allow request if rate limiting is down
            Ok(next.run(request).await)
        }
    }
}

/// Extract IP address from request
fn extract_ip_from_request(request: &Request) -> Option<IpAddr> {
    // Try to get IP from connection info first
    if let Some(connect_info) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return Some(connect_info.ip());
    }
    
    // Fallback to headers
    let headers = request.headers();
    
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    
    None
}

/// Simple SHA256 hash function for User-Agent
fn sha256_hash(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Create rate limiter from config
pub fn create_rate_limiter(redis: Arc<RedisManager>, config: &Config) -> RateLimiter {
    let rate_config = RateLimitConfig {
        requests_per_window: config.rate_limit_requests,
        window_seconds: config.rate_limit_window_seconds,
        algorithm: RateLimitAlgorithm::FixedWindow, // Can be made configurable
        burst_allowance: Some(config.rate_limit_requests / 5), // 20% burst allowance
        whitelist_ips: vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
        ],
        blacklist_ips: vec![], // Can be loaded from database or config
    };
    
    RateLimiter::new(redis, rate_config)
}