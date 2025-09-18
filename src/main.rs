mod auth;
mod config;
mod database; 
mod errors;
mod models;
mod routes;

use axum::{
    extract::Extension,
    routing::{get, post, put, delete},
    Router,
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
    
    println!("🚀 Starting server at http://{}", bind_address);

    // Build the application with routes and middleware
    let app = Router::new()
        .nest("/api/v1", api_routes())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(Extension(db_pool))
        );

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

fn api_routes() -> Router {
    Router::new()
        // Auth routes
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
        // User routes
        .route("/users", get(routes::users::list_users))
        .route("/users/{id}", get(routes::users::get_user))
        .route("/users/{id}", put(routes::users::update_user))
        .route("/users/{id}", delete(routes::users::delete_user))
        .route("/users/{id}/profile", get(routes::users::get_user_profile))
}
