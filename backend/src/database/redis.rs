use redis::{
    aio::ConnectionManager,
    Client, RedisResult, AsyncCommands,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use crate::{config::Config, errors::AppError};

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
}