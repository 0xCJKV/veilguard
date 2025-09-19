mod auth;
mod config;
mod database; 
mod errors;
mod middleware;
mod models;
mod routes;

use axum::{
    extract::Extension,
    routing::{get, post, put, delete},
    Router,
};
use middleware::{
    auth_middleware, rate_limit_middleware,
    csrf::{create_csrf_protection, get_csrf_token},
    create_rate_limiter
};
use config::Config;
use env_logger::Env;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    env_logger::init_from_env(Env::default().default_filter_or(&config.rust_log()));
    let bind_address = format!("{}:{}", config.host, config.port);

    let db_pool = match database::create_pool(&config).await {
        Ok(pool) => {
            println!("✅ Database pool created successfully");
            Arc::new(pool)
        },
        Err(e) => {
            eprintln!("❌ Failed to create database pool: {}", e);
            eprintln!("Check your DATABASE_URL: {}", config.database_url);
            std::process::exit(1);
        }
    };

    // Initialize Redis manager
    let redis_manager = match database::RedisManager::new(&config).await {
        Ok(redis) => {
            println!("✅ Redis connection established successfully");
            Arc::new(redis)
        },
        Err(e) => {
            eprintln!("❌ Failed to connect to Redis: {}", e);
            eprintln!("Check your REDIS_URL: {}", config.redis_url);
            std::process::exit(1);
        }
    };

    // Create CSRF protection
    let csrf_protection = Arc::new(create_csrf_protection(redis_manager.clone(), &config));
    
    // Create rate limiter
    let rate_limiter = Arc::new(create_rate_limiter(redis_manager.clone(), &config));
    
    // Initialize session manager with RedisManager integration
    let session_config = models::ses::SessionConfig::default();
    let session_manager = match auth::ses::SessionManager::new_with_redis_manager(&config.redis_url, session_config, redis_manager.clone()) {
        Ok(manager) => {
            println!("✅ Session manager initialized successfully with Redis integration");
            Arc::new(manager)
        },
        Err(e) => {
            eprintln!("❌ Failed to initialize session manager: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("🚀 Starting server at http://{}", bind_address);

    // Build the application with routes and middleware
    let app = Router::new()
        .nest("/api/v1", api_routes(csrf_protection.clone(), session_manager.clone()))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(Extension(db_pool))
                .layer(Extension(Arc::new(config)))
                .layer(Extension(redis_manager))
                .layer(Extension(csrf_protection.clone()))
                .layer(Extension(rate_limiter))
                .layer(Extension(session_manager))
        )
        .with_state(csrf_protection);

    // Create the listener
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ Failed to bind to {}: {}", bind_address, e);
            std::process::exit(1);
        });

    // Start the server
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ Server error: {}", e);
            std::process::exit(1);
        });
}

fn api_routes(csrf_protection: Arc<middleware::csrf::CsrfProtection>, session_manager: Arc<auth::ses::SessionManager>) -> Router<Arc<middleware::csrf::CsrfProtection>> {
    // Create user routes with the correct state type and auth middleware
    let protected_routes = user_routes(csrf_protection.clone())
        .layer(Extension(session_manager.clone()))
        .layer(axum::middleware::from_fn(auth_middleware));

    // Create session routes with auth middleware and session manager extension
    let session_routes = routes::ses::create_routes::<Arc<middleware::csrf::CsrfProtection>>()
        .layer(Extension(session_manager.clone()))
        .layer(axum::middleware::from_fn(auth_middleware));

    // Create admin session routes with auth middleware and session manager extension
    let admin_session_routes = routes::ses::create_admin_routes::<Arc<middleware::csrf::CsrfProtection>>()
        .layer(Extension(session_manager.clone()))
        .layer(axum::middleware::from_fn(auth_middleware));

    // Create auth routes with rate limiting and session manager
    let auth_routes = Router::new()
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/refresh", post(routes::auth::refresh_token))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/analytics", get(routes::auth::get_analytics))
        .route("/auth/user-analytics", get(routes::auth::get_user_analytics))
        .layer(Extension(session_manager.clone()))
        .layer(axum::middleware::from_fn(rate_limit_middleware));

    Router::new()
        // CSRF token endpoint (public)
        .route("/csrf/token", get(get_csrf_token))
        // Auth routes (public with rate limiting)
        .merge(auth_routes)
        // User routes (protected with auth and CSRF)
        .nest("/users", protected_routes)
        // Session routes (protected with auth)
        .nest("/sessions", session_routes)
        // Admin session routes (protected with auth)
        .nest("/admin/sessions", admin_session_routes)
        .with_state(csrf_protection)
}

// Updated function to accept and return the correct state type
fn user_routes(csrf_protection: Arc<middleware::csrf::CsrfProtection>) -> Router<Arc<middleware::csrf::CsrfProtection>> {
    Router::new()
        .route("/", get(routes::users::list_users))
        .route("/{id}", get(routes::users::get_user))
        .route("/{id}", put(routes::users::update_user))
        .route("/{id}", delete(routes::users::delete_user))
        .route("/{id}/profile", get(routes::users::get_user_profile))
        .with_state(csrf_protection)
}
