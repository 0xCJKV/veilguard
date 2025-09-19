use chrono::{Duration, Utc};
use rusty_paseto::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::config::Config;
use crate::errors::AppError;
use super::utils::{is_expired, generate_secure_token};

/// Standard JWT-like claims structure for PASETO tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Create new claims with standard fields
    pub fn new(
        subject: String,
        issuer: String,
        audience: String,
        expires_in: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + expires_in;
        
        Self {
            sub: subject,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            nbf: now.timestamp(),
            iss: issuer,
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            custom: HashMap::new(),
        }
    }



    /// Get a custom claim
    pub fn get_claim<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, AppError> {
        match self.custom.get(key) {
            Some(value) => {
                let result = serde_json::from_value(value.clone())
                    .map_err(|e| AppError::TokenError(format!("Failed to deserialize claim: {}", e)))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        is_expired(self.exp as u64)
    }

    /// Check if the token is valid (not before time)
    pub fn is_valid_time(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.nbf && now <= self.exp
    }

    /// Validate the token against expected issuer and audience
    pub fn validate(&self, expected_issuer: &str, expected_audience: &str) -> Result<(), AppError> {
        if self.is_expired() {
            return Err(AppError::TokenError("Token has expired".to_string()));
        }

        if !self.is_valid_time() {
            return Err(AppError::TokenError("Token is not yet valid".to_string()));
        }

        if self.iss != expected_issuer {
            return Err(AppError::TokenError("Invalid token issuer".to_string()));
        }

        if self.aud != expected_audience {
            return Err(AppError::TokenError("Invalid token audience".to_string()));
        }

        Ok(())
    }
}

/// PASETO token manager for secure token operations
pub struct PasetoManager {
    key: PasetoSymmetricKey<V4, Local>,
    default_issuer: String,
    default_audience: String,
}

impl PasetoManager {
    /// Create a new PASETO manager from configuration
    pub fn new(config: &Config) -> Result<Self, AppError> {
        // Decode the base64 key or use it directly if it's 32 bytes
        let key_bytes = if config.paseto_key.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(config.paseto_key.as_bytes());
            key
        } else {
            // Try to decode as base64
            use base64::{Engine as _, engine::general_purpose};
            let decoded = general_purpose::STANDARD.decode(&config.paseto_key)
                .map_err(|_| AppError::TokenError("Invalid base64 key".to_string()))?;
            
            if decoded.len() != 32 {
                return Err(AppError::TokenError("Key must be exactly 32 bytes".to_string()));
            }
            
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            key
        };

        let key = Key::<32>::from(key_bytes);
        let paseto_key = PasetoSymmetricKey::<V4, Local>::from(key);

        Ok(Self {
            key: paseto_key,
            default_issuer: "veilguard".to_string(),
            default_audience: "veilguard-api".to_string(),
        })
    }

    /// Generate a new access token with standard expiration (15 minutes)
    pub fn generate_access_token(&self, user_id: &str) -> Result<String, AppError> {
        let claims = Claims::new(
            user_id.to_string(),
            self.default_issuer.clone(),
            self.default_audience.clone(),
            Duration::minutes(15),
        );

        self.generate_token(&claims)
    }

    /// Generate a new refresh token with extended expiration (7 days)
    pub fn generate_refresh_token(&self, user_id: &str) -> Result<String, AppError> {
        let claims = Claims::new(
            user_id.to_string(),
            self.default_issuer.clone(),
            format!("{}-refresh", self.default_audience),
            Duration::days(7),
        );

        self.generate_token(&claims)
    }

    /// Generate a new access token with embedded session ID
    pub fn generate_access_token_with_session(&self, user_id: &str, session_id: &str) -> Result<String, AppError> {
        let mut claims = Claims::new(
            user_id.to_string(),
            self.default_issuer.clone(),
            self.default_audience.clone(),
            Duration::minutes(15),
        );

        // Add session ID to custom claims
        claims.custom.insert("sid".to_string(), serde_json::Value::String(session_id.to_string()));

        self.generate_token(&claims)
    }

    /// Generate a new refresh token with embedded session ID
    pub fn generate_refresh_token_with_session(&self, user_id: &str, session_id: &str) -> Result<String, AppError> {
        let mut claims = Claims::new(
            user_id.to_string(),
            self.default_issuer.clone(),
            format!("{}-refresh", self.default_audience),
            Duration::days(7),
        );

        // Add session ID to custom claims
        claims.custom.insert("sid".to_string(), serde_json::Value::String(session_id.to_string()));

        self.generate_token(&claims)
    }

    /// Generate a custom token with specific claims and expiration
    // pub fn generate_custom_token(
    //     &self,
    //     user_id: &str,
    //     expires_in: Duration,
    //     custom_claims: HashMap<String, serde_json::Value>,
    // ) -> Result<String, AppError> {
    //     let mut claims = Claims::new(
    //         user_id.to_string(),
    //         self.default_issuer.clone(),
    //         self.default_audience.clone(),
    //         expires_in,
    //     );

    //     claims.custom = custom_claims;
    //     self.generate_token(&claims)
    // }

    /// Generate a token from claims
    fn generate_token(&self, claims: &Claims) -> Result<String, AppError> {
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| AppError::TokenError(format!("Failed to serialize claims: {}", e)))?;

        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(CustomClaim::try_from(("data", claims_json.as_str()))
                .map_err(|e| AppError::TokenError(format!("Failed to create claim: {}", e)))?)
            .build(&self.key)
            .map_err(|e| AppError::TokenError(format!("Failed to build token: {}", e)))?;

        Ok(token)
    }

    /// Validate and parse a token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        let mut parser = PasetoParser::<V4, Local>::default();
        
        let parsed_token = parser
            .parse(token, &self.key)
            .map_err(|e| AppError::TokenError(format!("Failed to parse token: {}", e)))?;

        // Extract claims from the data field
        let data_claim = parsed_token.get("data")
            .ok_or_else(|| AppError::TokenError("Token has no data claim".to_string()))?;

        let claims_str = data_claim.as_str()
            .ok_or_else(|| AppError::TokenError("Data claim is not a string".to_string()))?;

        let claims: Claims = serde_json::from_str(claims_str)
            .map_err(|e| AppError::TokenError(format!("Failed to deserialize claims: {}", e)))?;
        
        // Validate the claims
        claims.validate(&self.default_issuer, &self.default_audience)
            .or_else(|_| {
                // Try refresh token audience
                claims.validate(&self.default_issuer, &format!("{}-refresh", self.default_audience))
            })?;

        Ok(claims)
    }

    /// Extract user ID from token without full validation (for utility purposes)
    pub fn extract_user_id(&self, token: &str) -> Result<String, AppError> {
        let claims = self.validate_token(token)?;
        Ok(claims.sub)
    }

    /// Check if token is expired
    pub fn is_token_expired(&self, token: &str) -> bool {
        match self.validate_token(token) {
            Ok(claims) => claims.is_expired(),
            Err(_) => true,
        }
    }

    /// Rotate access token (generate new token and return both old and new JTIs)
    pub fn rotate_access_token(&self, user_id: &str, session_id: Option<&str>) -> Result<(String, String, String), AppError> {
        let new_token = if let Some(session_id) = session_id {
            self.generate_access_token_with_session(user_id, session_id)?
        } else {
            self.generate_access_token(user_id)?
        };

        // Extract JTI from new token
        let new_claims = self.validate_token(&new_token)?;
        let new_jti = new_claims.jti.clone();

        // Generate a unique old JTI for tracking (in real scenario, this would be from the old token)
        let old_jti = uuid::Uuid::new_v4().to_string();

        Ok((new_token, old_jti, new_jti))
    }

    /// Rotate refresh token (generate new token and return both old and new JTIs)
    pub fn rotate_refresh_token(&self, user_id: &str, session_id: Option<&str>) -> Result<(String, String, String), AppError> {
        let new_token = if let Some(session_id) = session_id {
            self.generate_refresh_token_with_session(user_id, session_id)?
        } else {
            self.generate_refresh_token(user_id)?
        };

        // Extract JTI from new token
        let new_claims = self.validate_token(&new_token)?;
        let new_jti = new_claims.jti.clone();

        // Generate a unique old JTI for tracking (in real scenario, this would be from the old token)
        let old_jti = uuid::Uuid::new_v4().to_string();

        Ok((new_token, old_jti, new_jti))
    }

    /// Extract JTI from token
    pub fn extract_jti(&self, token: &str) -> Result<String, AppError> {
        let claims = self.validate_token(token)?;
        Ok(claims.jti)
    }

    /// Extract session ID from token
    pub fn extract_session_id(&self, token: &str) -> Result<Option<String>, AppError> {
        let claims = self.validate_token(token)?;
        Ok(claims.get_claim::<String>("session_id")?)
    }

    /// Generate token pair (access + refresh) with rotation tracking
    pub fn generate_token_pair_with_rotation(&self, user_id: &str, session_id: &str) -> Result<(String, String, String, String), AppError> {
        let access_token = self.generate_access_token_with_session(user_id, session_id)?;
        let refresh_token = self.generate_refresh_token_with_session(user_id, session_id)?;

        let access_claims = self.validate_token(&access_token)?;
        let refresh_claims = self.validate_token(&refresh_token)?;

        Ok((access_token, refresh_token, access_claims.jti, refresh_claims.jti))
    }

}
