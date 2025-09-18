mod auth;
mod config;
mod database; 
mod errors;
mod models;
mod routes;

use actix_web::{web, App, HttpServer, middleware::Logger};
use config::Config;
use env_logger::Env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    
    let config = Config::from_env();
    let bind_address = format!("{}:{}", config.host, config.port);

    let db_pool = match database::create_pool(&config).await {
        Ok(pool) => {
            println!("✅ Database pool created successfully");
            pool
        },
        Err(e) => {
            eprintln!("❌ Failed to create database pool: {}", e);
            eprintln!("Check your DATABASE_URL: {}", config.database_url);
            std::process::exit(1);
        }
    };
    
    println!("🚀 Starting server at http://{}", bind_address);
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(Logger::default())
            .service(
                web::scope("/api/v1")
                    .configure(routes::auth::config)
                    .configure(routes::users::config)
            )
    })
    .bind(&bind_address)?
    .run()
    .await
}