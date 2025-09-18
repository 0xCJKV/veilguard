use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{thread_rng, Rng};
use crate::errors::{AppError, Result};

#[derive(Clone)]
pub struct CsrfToken {
    pub token: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl CsrfToken {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let token = generate_csrf_token();
        
        Self {
            token,
            created_at: now,
            expires_at: now + 3600, // 1 hour expiry
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now < self.expires_at
    }
}

#[derive(Clone)]
pub struct CsrfStore {
    tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,
}

impl CsrfStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn generate_token(&self, session_id: &str) -> String {
        let token = CsrfToken::new();
        let token_value = token.token.clone();
        
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.to_string(), token);
        
        // Clean up expired tokens
        tokens.retain(|_, token| token.is_valid());
        
        token_value
    }
    
    pub async fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let tokens = self.tokens.read().await;
        
        if let Some(stored_token) = tokens.get(session_id) {
            stored_token.is_valid() && stored_token.token == token
        } else {
            false
        }
    }
    
    pub async fn remove_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
    }
}

fn generate_csrf_token() -> String {
    use rand::RngCore;
    let mut rng = thread_rng();
    let mut token = [0u8; 32];
    rng.fill_bytes(&mut token);
    // Simple hex encoding instead of base64 to avoid dependency issues
    token.iter().map(|b| format!("{:02x}", b)).collect()
}

pub async fn csrf_middleware(
    State(csrf_store): State<CsrfStore>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    // Skip CSRF protection for GET, HEAD, OPTIONS requests
    if matches!(request.method(), &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(next.run(request).await);
    }
    
    // Get session ID from headers or generate one
    let session_id = headers
        .get("x-session-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");
    
    // For state-changing requests, validate CSRF token
    let csrf_token = headers
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok());
    
    if let Some(token) = csrf_token {
        if !csrf_store.validate_token(session_id, token).await {
            return Err(AppError::bad_request("Invalid CSRF token"));
        }
    } else {
        return Err(AppError::bad_request("Missing CSRF token"));
    }
    
    Ok(next.run(request).await)
}

// Helper function to get CSRF token for templates
pub async fn get_csrf_token(csrf_store: &CsrfStore, session_id: &str) -> String {
    csrf_store.generate_token(session_id).await
}