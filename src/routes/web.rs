use axum::{
    extract::{Extension, Request},
    response::{Html, IntoResponse},
    http::StatusCode,
};
use minijinja::{context, Environment};
use std::sync::Arc;
use chrono;

use crate::auth::AuthUser;
use crate::models::user::User;

pub async fn landing_page(
    Extension(env): Extension<Arc<Environment<'static>>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<impl IntoResponse, StatusCode> {
    let template = env.get_template("landing.html").unwrap();
    let rendered = template.render(context! {
        user => auth_user.map(|Extension(u)| u.user_id),
    }).unwrap();
    Ok(Html(rendered))
}

pub async fn login_page(
    Extension(env): Extension<Arc<Environment<'static>>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<impl IntoResponse, StatusCode> {
    let template = env.get_template("auth.html").unwrap();
    let rendered = template.render(context! {
        is_register => false,
        user => auth_user.map(|Extension(u)| u.user_id),
    }).unwrap();
    Ok(Html(rendered))
}

pub async fn register_page(
    Extension(env): Extension<Arc<Environment<'static>>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<impl IntoResponse, StatusCode> {
    let template = env.get_template("auth.html").unwrap();
    let rendered = template.render(context! {
        is_register => true,
        user => auth_user.map(|Extension(u)| u.user_id),
    }).unwrap();
    Ok(Html(rendered))
}

pub async fn dashboard_page(
    Extension(env): Extension<Arc<Environment<'static>>>,
    Extension(auth_user): Extension<AuthUser>,
    Extension(db): Extension<Arc<sqlx::PgPool>>,
) -> Result<impl IntoResponse, StatusCode> {
    // Parse user ID from string to i32
    let user_id: i32 = match auth_user.user_id.parse() {
        Ok(id) => id,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Fetch user data from database
    let user = match sqlx::query!(
        "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(db.as_ref())
    .await
    {
        Ok(row) => User {
            id: row.id,
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            created_at: row.created_at.unwrap_or_else(|| chrono::Utc::now().naive_utc()),
            updated_at: row.updated_at.unwrap_or_else(|| chrono::Utc::now().naive_utc()),
            is_active: row.is_active.unwrap_or(true),
        },
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let template = env.get_template("dashboard.html").unwrap();
    let rendered = template.render(context! {
        user => user,
    }).unwrap();
    
    Ok(Html(rendered))
}