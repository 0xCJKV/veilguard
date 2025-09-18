mod auth;
mod config;
mod database; 
mod errors;
mod models;
mod routes;
mod validation;

use axum::{
    extract::Extension,
    http::StatusCode,
    routing::{get, post, put, delete},
    Router,
};
use auth::auth_middleware;
use chrono;
use config::Config;
use env_logger::Env;
use minijinja::{Environment, path_loader};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    services::ServeDir,
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
    
    // Create MiniJinja environment
    let minijinja_env = Arc::new(create_minijinja_env());
    
    println!("🚀 Starting server at http://{}", bind_address);

    // Build the application with routes and middleware
    let app = Router::new()
        .nest("/api/v1", api_routes())
        .merge(web_routes())
        .nest_service("/static", ServeDir::new("static"))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(Extension(db_pool))
                .layer(Extension(Arc::new(config)))
                .layer(Extension(minijinja_env))
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
        // Auth routes (public)
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/refresh", post(routes::auth::refresh_token))
        .route("/auth/logout", post(routes::auth::logout))
        // User routes (protected)
        .nest("/users", user_routes().layer(axum::middleware::from_fn(auth_middleware)))
}

fn user_routes() -> Router {
    Router::new()
        .route("/", get(routes::users::list_users))
        .route("/{id}", get(routes::users::get_user))
        .route("/{id}", put(routes::users::update_user))
        .route("/{id}", delete(routes::users::delete_user))
        .route("/{id}/profile", get(routes::users::get_user_profile))
        .route("/{id}/profile-card", get(routes::users::get_user_profile_card))
}

fn web_routes() -> Router {
    let protected_routes = Router::new()
        .route("/dashboard", get(routes::web::dashboard_page))
        .layer(axum::middleware::from_fn(auth::auth_middleware));
    
    let public_routes = Router::new()
        .route("/", get(routes::web::landing_page))
        .route("/login", get(routes::web::login_page))
        .route("/register", get(routes::web::register_page))
        .route("/favicon.ico", get(|| async { StatusCode::NOT_FOUND }))
        .merge(protected_routes)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(axum::middleware::from_fn(auth::optional_auth_middleware));
    
    public_routes
}

fn create_minijinja_env() -> Environment<'static> {
    let mut env = Environment::new();
    env.set_loader(path_loader("templates"));
    
    // Add date filter for formatting dates
    env.add_filter("date", |value: String| -> Result<String, minijinja::Error> {
        // Parse the datetime string and format it nicely
        match chrono::NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%S%.f") {
            Ok(dt) => Ok(dt.format("%B %d, %Y at %I:%M %p").to_string()),
            Err(_) => {
                // Fallback: try parsing without microseconds
                match chrono::NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%S") {
                    Ok(dt) => Ok(dt.format("%B %d, %Y at %I:%M %p").to_string()),
                    Err(_) => Ok(value), // Return original if parsing fails
                }
            }
        }
    });
    
    env
}
