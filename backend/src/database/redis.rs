use redis::{
    aio::ConnectionManager,
    Client, RedisResult, AsyncCommands,
};
use std::sync::Arc;
use std::net::IpAddr;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use chrono::Utc;
use serde_json;
use crate::{config::Config, errors::AppError, models::security::SecurityEventType};

/// Enterprise-grade Redis connection manager with connection pooling and health checks
#[derive(Clone)]
pub struct RedisManager {
    connection_manager: Arc<RwLock<ConnectionManager>>,
    client: Client,
}

impl RedisManager {
    /// Create a new Redis manager with connection pooling
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        info!("Initializing Redis connection to: {}", 
              config.redis_url.chars().map(|c| if c.is_ascii_digit() && c != ':' { '*' } else { c }).collect::<String>());

        let client = Client::open(config.redis_url.as_str())
            .map_err(|e| {
                error!("Failed to create Redis client: {}", e);
                AppError::DatabaseError(format!("Redis client creation failed: {}", e))
            })?;

        let connection_manager = ConnectionManager::new(client.clone())
            .await
            .map_err(|e| {
                error!("Failed to create Redis connection manager: {}", e);
                AppError::DatabaseError(format!("Redis connection failed: {}", e))
            })?;

        info!("Redis connection established successfully");

        Ok(Self {
            connection_manager: Arc::new(RwLock::new(connection_manager)),
            client,
        })
    }

    /// Health check for Redis connection
    #[allow(dead_code)]
    pub async fn health_check(&self) -> Result<(), AppError> {
        let mut conn = self.connection_manager.write().await;
        
        match redis::cmd("PING").query_async::<String>(&mut *conn).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Redis health check failed: {}", e);
                Err(AppError::DatabaseError(format!("Redis health check failed: {}", e)))
            }
        }
    }

    /// Reconnect to Redis if connection is lost
    pub async fn reconnect(&self) -> Result<(), AppError> {
        warn!("Attempting to reconnect to Redis...");
        
        let new_connection = ConnectionManager::new(self.client.clone())
            .await
            .map_err(|e| {
                error!("Failed to reconnect to Redis: {}", e);
                AppError::DatabaseError(format!("Redis reconnection failed: {}", e))
            })?;

        let mut conn = self.connection_manager.write().await;
        *conn = new_connection;
        
        info!("Redis reconnection successful");
        Ok(())
    }

    /// Execute Redis command with automatic retry on connection failure
    async fn execute_with_retry<F, T>(&self, operation: F) -> Result<T, AppError>
    where
        F: Fn(&mut ConnectionManager) -> std::pin::Pin<Box<dyn std::future::Future<Output = RedisResult<T>> + Send + '_>> + Send + Sync,
        T: Send,
    {
        let mut conn = self.connection_manager.write().await;
        
        match operation(&mut *conn).await {
            Ok(result) => Ok(result),
            Err(e) => {
                warn!("Redis operation failed, attempting reconnect: {}", e);
                drop(conn); // Release the lock before reconnecting
                
                self.reconnect().await?;
                
                let mut conn = self.connection_manager.write().await;
                operation(&mut *conn).await.map_err(|e| {
                    error!("Redis operation failed after reconnect: {}", e);
                    AppError::DatabaseError(format!("Redis operation failed: {}", e))
                })
            }
        }
    }
}

/// Rate limiting operations
impl RedisManager {
    /// Increment rate limit counter for a key with expiration
    pub async fn increment_rate_limit(&self, key: &str, window_seconds: u64) -> Result<i64, AppError> {
        self.execute_with_retry(|conn| {
            let key = key.to_string();
            Box::pin(async move {
                let count: i64 = conn.incr(&key, 1).await?;
                if count == 1 {
                    let _: bool = conn.expire(&key, window_seconds as i64).await?;
                }
                Ok(count)
            })
        }).await
    }

    /// Get current rate limit count for a key
    #[allow(dead_code)]
    pub async fn get_rate_limit(&self, key: &str) -> Result<Option<i64>, AppError> {
        self.execute_with_retry(|conn| {
            let key = key.to_string();
            Box::pin(async move {
                let count: Option<i64> = conn.get(&key).await?;
                Ok(count)
            })
        }).await
    }

    /// Get TTL for rate limit key
    #[allow(dead_code)]
    pub async fn get_rate_limit_ttl(&self, key: &str) -> Result<i64, AppError> {
        self.execute_with_retry(|conn| {
            let key = key.to_string();
            Box::pin(async move {
                let ttl: i64 = conn.ttl(&key).await?;
                Ok(ttl)
            })
        }).await
    }
}

/// Session management operations
impl RedisManager {
    /// Set session data with TTL
    #[allow(dead_code)]
    pub async fn set_session(&self, session_id: &str, data: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("session:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let data = data.to_string();
            Box::pin(async move {
                conn.set_ex(&key, &data, ttl_seconds).await
            })
        }).await
    }

    /// Get session data
    #[allow(dead_code)]
    pub async fn get_session(&self, session_id: &str) -> Result<Option<String>, AppError> {
        let key = format!("session:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let data: Option<String> = conn.get(&key).await?;
                Ok(data)
            })
        }).await
    }

    /// Delete session
    #[allow(dead_code)]
    pub async fn delete_session(&self, session_id: &str) -> Result<(), AppError> {
        let key = format!("session:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let _: () = conn.del(&key).await?;
                Ok(())
            })
        }).await
    }

    /// Extend session TTL
    #[allow(dead_code)]
    pub async fn extend_session(&self, session_id: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("session:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let _result: bool = conn.expire(&key, ttl_seconds as i64).await?;
                Ok(())
            })
        }).await
    }

    /// Blacklist a token (for token rotation and revocation)
    pub async fn blacklist_token(&self, token_jti: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("blacklist:{}", token_jti);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                conn.set_ex(&key, "revoked", ttl_seconds).await
            })
        }).await
    }

    /// Check if a token is blacklisted
    pub async fn is_token_blacklisted(&self, token_jti: &str) -> Result<bool, AppError> {
        let key = format!("blacklist:{}", token_jti);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let exists: bool = conn.exists(&key).await?;
                Ok(exists)
            })
        }).await
    }

    /// Store token rotation mapping (old token -> new token)
    pub async fn store_token_rotation(&self, old_jti: &str, new_jti: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("rotation:{}", old_jti);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let new_jti = new_jti.to_string();
            Box::pin(async move {
                conn.set_ex(&key, &new_jti, ttl_seconds).await
            })
        }).await
    }

    /// Get rotated token JTI
    pub async fn get_rotated_token(&self, old_jti: &str) -> Result<Option<String>, AppError> {
        let key = format!("rotation:{}", old_jti);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let new_jti: Option<String> = conn.get(&key).await?;
                Ok(new_jti)
            })
        }).await
    }

    /// Store session analytics data
    pub async fn store_session_analytics(&self, session_id: &str, analytics_data: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("analytics:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let analytics_data = analytics_data.to_string();
            Box::pin(async move {
                conn.set_ex(&key, &analytics_data, ttl_seconds).await
            })
        }).await
    }

    /// Get session analytics data
    pub async fn get_session_analytics(&self, session_id: &str) -> Result<Option<String>, AppError> {
        let key = format!("analytics:{}", session_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let data: Option<String> = conn.get(&key).await?;
                Ok(data)
            })
        }).await
    }

    /// Store security event
    pub async fn store_security_event(&self, event_id: &str, event_data: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("security_event:{}", event_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let event_data = event_data.to_string();
            Box::pin(async move {
                conn.set_ex(&key, &event_data, ttl_seconds).await
            })
        }).await
    }

    /// Add to security events list (for analytics)
    pub async fn add_to_security_events_list(&self, event_data: &str, max_events: usize) -> Result<(), AppError> {
        self.execute_with_retry(|conn| {
            let event_data = event_data.to_string();
            Box::pin(async move {
                // Add to list and trim to max size
                let _: i64 = conn.lpush("security_events", &event_data).await?;
                let _: () = conn.ltrim("security_events", 0, max_events as isize - 1).await?;
                Ok(())
            })
        }).await
    }

    /// Get recent security events
    pub async fn get_recent_security_events(&self, limit: usize) -> Result<Vec<String>, AppError> {
        self.execute_with_retry(|conn| {
            Box::pin(async move {
                let events: Vec<String> = conn.lrange("security_events", 0, limit as isize - 1).await?;
                Ok(events)
            })
        }).await
    }

    /// Store user session count
    pub async fn set_user_session_count(&self, user_id: &str, count: u32, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("user_sessions:{}", user_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                conn.set_ex(&key, count, ttl_seconds).await
            })
        }).await
    }

    /// Get user session count
    pub async fn get_user_session_count(&self, user_id: &str) -> Result<Option<u32>, AppError> {
        let key = format!("user_sessions:{}", user_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let count: Option<u32> = conn.get(&key).await?;
                Ok(count)
            })
        }).await
    }

    /// Increment user session count
    pub async fn increment_user_session_count(&self, user_id: &str, ttl_seconds: u64) -> Result<u32, AppError> {
        let key = format!("user_sessions:{}", user_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let count: u32 = conn.incr(&key, 1).await?;
                if count == 1 {
                    let _: bool = conn.expire(&key, ttl_seconds as i64).await?;
                }
                Ok(count)
            })
        }).await
    }

    /// Decrement user session count
    pub async fn decrement_user_session_count(&self, user_id: &str) -> Result<u32, AppError> {
        let key = format!("user_sessions:{}", user_id);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let count: i32 = conn.decr(&key, 1).await?;
                Ok(count.max(0) as u32)
            })
        }).await
    }

    /// Add a security event with comprehensive logging
    pub async fn add_security_event(
        &self,
        user_id: &str,
        event_type: SecurityEventType,
        details: &str,
        ip_address: IpAddr,
        user_agent: &str,
    ) -> Result<(), AppError> {
        let event_data = serde_json::json!({
            "user_id": user_id,
            "event_type": format!("{:?}", event_type),
            "details": details,
            "ip_address": ip_address.to_string(),
            "user_agent": user_agent,
            "timestamp": Utc::now().to_rfc3339()
        });

        let event_str = serde_json::to_string(&event_data)
            .map_err(|e| AppError::InternalServerError(format!("Failed to serialize security event: {}", e)))?;

        // Store individual event
        let event_id = format!("security_event:{}:{}", user_id, Utc::now().timestamp_millis());
        self.store_security_event(&event_id, &event_str, 86400 * 30).await?; // 30 days

        // Add to global events list
        self.add_to_security_events_list(&event_str, 1000).await?;

        Ok(())
    }
}

/// CSRF token operations
impl RedisManager {
    /// Store CSRF token with expiration
    pub async fn set_csrf_token(&self, token: &str, user_id: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("csrf:{}", token);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let user_id = user_id.to_string();
            Box::pin(async move {
                conn.set_ex(&key, &user_id, ttl_seconds).await
            })
        }).await
    }

    /// Validate and consume CSRF token (one-time use)
    pub async fn validate_and_consume_csrf_token(&self, token: &str) -> Result<Option<String>, AppError> {
        let key = format!("csrf:{}", token);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                // Use GETDEL to atomically get and delete the token
                let user_id: Option<String> = conn.get_del(&key).await?;
                Ok(user_id)
            })
        }).await
    }

    /// Check if CSRF token exists without consuming it
    pub async fn check_csrf_token(&self, token: &str) -> Result<Option<String>, AppError> {
        let key = format!("csrf:{}", token);
        
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let user_id: Option<String> = conn.get(&key).await?;
                Ok(user_id)
            })
        }).await
    }
}

/// Utility operations
impl RedisManager {
    /// Set a key-value pair with expiration
    pub async fn set_with_expiry(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = key.to_string();
        let value = value.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let value = value.clone();
            Box::pin(async move {
                conn.set_ex(key, value, ttl_seconds).await
            })
        }).await
    }

    /// Get a value by key
    pub async fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let value: Option<String> = conn.get(key).await?;
                Ok(value)
            })
        }).await
    }

    /// Delete a key
    pub async fn delete(&self, key: &str) -> Result<bool, AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let deleted: i64 = conn.del(key).await?;
                Ok(deleted > 0)
            })
        }).await
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> Result<bool, AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let exists: bool = conn.exists(key).await?;
                Ok(exists)
            })
        }).await
    }

    /// Get comprehensive session metrics
    pub async fn get_session_metrics(&self) -> Result<serde_json::Value, AppError> {
        let active_sessions = self.count_active_sessions().await?;
        let total_events = self.count_security_events().await?;
        let recent_events = self.get_recent_security_events(10).await?;
        
        let metrics = serde_json::json!({
            "active_sessions": active_sessions,
            "total_security_events": total_events,
            "recent_events_count": recent_events.len(),
            "timestamp": Utc::now().to_rfc3339()
        });
        
        Ok(metrics)
    }

    /// Count active sessions across all users
    pub async fn count_active_sessions(&self) -> Result<u32, AppError> {
        self.execute_with_retry(|conn| {
            Box::pin(async move {
                let pattern = "session:*";
                let keys: Vec<String> = conn.keys(pattern).await?;
                Ok(keys.len() as u32)
            })
        }).await
    }

    /// Count total security events
    pub async fn count_security_events(&self) -> Result<u32, AppError> {
        self.execute_with_retry(|conn| {
            Box::pin(async move {
                let count: i64 = conn.llen("security_events").await?;
                Ok(count as u32)
            })
        }).await
    }

    /// Store user activity for analytics
    pub async fn store_user_activity(&self, user_id: &str, activity_data: &str, ttl_seconds: u64) -> Result<(), AppError> {
        let key = format!("user_activity:{}", user_id);
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let activity_data = activity_data.to_string();
            Box::pin(async move {
                let _: () = conn.lpush(&key, &activity_data).await?;
                let _: () = conn.ltrim(&key, 0, 99).await?; // Keep last 100 activities
                let _: bool = conn.expire(&key, ttl_seconds as i64).await?;
                Ok(())
            })
        }).await
    }

    /// Get user activity history
    pub async fn get_user_activity(&self, user_id: &str, limit: usize) -> Result<Vec<String>, AppError> {
        let key = format!("user_activity:{}", user_id);
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let activities: Vec<String> = conn.lrange(&key, 0, limit as isize - 1).await?;
                Ok(activities)
            })
        }).await
    }

    /// Get keys matching a pattern
    pub async fn keys(&self, pattern: &str) -> Result<Vec<String>, AppError> {
        let pattern = pattern.to_string();
        self.execute_with_retry(|conn| {
            let pattern = pattern.clone();
            Box::pin(async move {
                let keys: Vec<String> = conn.keys(pattern).await?;
                Ok(keys)
            })
        }).await
    }

    /// Delete a key (alias for delete method)
    pub async fn del(&self, key: &str) -> Result<(), AppError> {
        self.delete(key).await?;
        Ok(())
    }

    /// Set expiration time for a key
    pub async fn expire(&self, key: &str, ttl_seconds: u64) -> Result<bool, AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let result: bool = conn.expire(key, ttl_seconds as i64).await?;
                Ok(result)
            })
        }).await
    }

    /// Set a key-value pair with optional expiration
    pub async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> Result<(), AppError> {
        match ttl_seconds {
            Some(ttl) => self.set_with_expiry(key, value, ttl).await,
            None => {
                let key = key.to_string();
                let value = value.to_string();
                self.execute_with_retry(|conn| {
                    let key = key.clone();
                    let value = value.clone();
                    Box::pin(async move {
                        conn.set(key, value).await
                    })
                }).await
            }
        }
    }

    /// Push element to the left of a list
    pub async fn lpush(&self, key: &str, value: &str) -> Result<(), AppError> {
        let key = key.to_string();
        let value = value.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            let value = value.clone();
            Box::pin(async move {
                let _: i64 = conn.lpush(key, value).await?;
                Ok(())
            })
        }).await
    }

    /// Trim a list to keep only elements in the specified range
    pub async fn ltrim(&self, key: &str, start: isize, stop: isize) -> Result<(), AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let _: () = conn.ltrim(key, start, stop).await?;
                Ok(())
            })
        }).await
    }

    /// Get a range of elements from a list
    pub async fn lrange(&self, key: &str, start: isize, stop: isize) -> Result<Vec<String>, AppError> {
        let key = key.to_string();
        self.execute_with_retry(|conn| {
            let key = key.clone();
            Box::pin(async move {
                let values: Vec<String> = conn.lrange(key, start, stop).await?;
                Ok(values)
            })
        }).await
    }
}