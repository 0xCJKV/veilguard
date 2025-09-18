use dotenvy::dotenv;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub paseto_key: String,
    pub host: String,
    pub port: u16,
    pub log_level: String, 
}

impl Config {
    pub fn from_env() -> Self {
        dotenv().ok();
        
        Self {
            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set"),
            paseto_key: env::var("PASETO_KEY")
                .expect("PASETO_KEY must be set"),
            host: env::var("HOST")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("PORT must be a valid number"),
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
        }
    }

    // Smart RUST_LOG construction for Axum and tracing
    pub fn rust_log(&self) -> String {
        match self.log_level.to_lowercase().as_str() {
            "trace" => "trace,axum=trace,tower=trace,hyper=trace,veilguard=trace".to_string(),
            "debug" => "debug,axum=debug,tower=debug,hyper=debug,veilguard=debug".to_string(),
            "info" => "info,axum=info,tower=info,hyper=info,veilguard=info".to_string(),
            "warn" => "warn,axum=warn,tower=warn,hyper=warn,veilguard=warn".to_string(),
            "error" => "error,axum=error,tower=error,hyper=error,veilguard=error".to_string(),
            _ => "info,axum=info,tower=info,hyper=info,veilguard=info".to_string(), // fallback
        }
    }
}
