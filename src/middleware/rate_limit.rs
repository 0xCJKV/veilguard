use axum::{
    extract::{Request, State, ConnectInfo},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use crate::errors::AppError;

#[derive(Clone, Debug)]
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: u64,
    pub last_request: u64,
}

impl RateLimitEntry {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            count: 1,
            window_start: now,
            last_request: now,
        }
    }
    
    pub fn increment(&mut self, window_size: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Reset window if expired
        if now - self.window_start >= window_size {
            self.count = 1;
            self.window_start = now;
            self.last_request = now;
            return true;
        }
        
        self.count += 1;
        self.last_request = now;
        true
    }
    
    pub fn is_within_limit(&self, max_requests: u32) -> bool {
        self.count <= max_requests
    }
    
    pub fn time_until_reset(&self, window_size: u64) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let window_end = self.window_start + window_size;
        if now >= window_end {
            0
        } else {
            window_end - now
        }
    }
}

#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_size: u64, // in seconds
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60, // 60 requests per minute
            window_size: 60,  // 1 minute window
        }
    }
}

#[derive(Clone)]
pub struct RateLimitStore {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    config: RateLimitConfig,
}

impl RateLimitStore {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    pub async fn check_rate_limit(&self, key: &str) -> std::result::Result<(), AppError> {
        let mut entries = self.entries.write().await;
        
        // Clean up old entries periodically
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        entries.retain(|_, entry| {
            now - entry.last_request < self.config.window_size * 2
        });
        
        let entry = entries.entry(key.to_string()).or_insert_with(RateLimitEntry::new);
        
        if !entry.is_within_limit(self.config.max_requests) {
            let time_until_reset = entry.time_until_reset(self.config.window_size);
            return Err(AppError::bad_request(&format!(
                "Rate limit exceeded. {} requests made. Try again in {} seconds.",
                entry.count, time_until_reset
            )));
        }
        
        entry.increment(self.config.window_size);
        
        if !entry.is_within_limit(self.config.max_requests) {
            let time_until_reset = entry.time_until_reset(self.config.window_size);
            Err(AppError::bad_request(&format!(
                "Rate limit exceeded. {} requests made. Try again in {} seconds.",
                entry.count, time_until_reset
            )))
        } else {
            Ok(())
        }
    }
}

pub async fn rate_limit_middleware(
    State(rate_limiter): State<RateLimitStore>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    // Use IP address as the rate limit key
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    
    // Check rate limit
    match rate_limiter.check_rate_limit(&client_ip).await {
        Ok(()) => Ok(next.run(request).await),
        Err(app_error) => {
            let mut response = Response::new(app_error.to_string().into());
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            
            // Add rate limit headers
            response.headers_mut().insert(
                "X-RateLimit-Limit",
                rate_limiter.config.max_requests.to_string().parse().unwrap(),
            );
            response.headers_mut().insert(
                "X-RateLimit-Remaining",
                "0".parse().unwrap(),
            );
            
            Ok(response)
        }
    }
}