use sqlx::{Pool, Postgres, PgPool};
use crate::config::Config;

pub type DbPool = Pool<Postgres>;

pub async fn create_pool(config: &Config) -> Result<DbPool, sqlx::Error> {
    PgPool::connect(&config.database_url).await
}

pub mod users {
    use super::*;
    use crate::models::user::{User, CreateUserRequest, UpdateUserRequest};
    use chrono::Utc;

    pub async fn create_user(
        pool: &DbPool,
        req: &CreateUserRequest,
        password_hash: &str,
    ) -> Result<User, sqlx::Error> {
        let now = Utc::now().naive_utc();
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, email, password_hash, created_at, updated_at, is_active)
            VALUES ($1, $2, $3, $4, $4, true)
            RETURNING id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!"
            "#,
            req.username,
            req.email,
            password_hash,
            now
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_email(pool: &DbPool, email: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!" 
               FROM users WHERE email = $1 AND is_active = true"#,
            email
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_username(pool: &DbPool, username: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!" 
               FROM users WHERE username = $1 AND is_active = true"#,
            username
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_id(pool: &DbPool, id: i32) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!" 
               FROM users WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn list_users(pool: &DbPool, limit: i64, offset: i64) -> Result<Vec<User>, sqlx::Error> {
        let users = sqlx::query_as!(
            User,
            r#"SELECT id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!" 
               FROM users WHERE is_active = true 
               ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            limit,
            offset
        )
        .fetch_all(pool)
        .await?;

        Ok(users)
    }

    pub async fn update_user(
        pool: &DbPool,
        id: i32,
        req: &UpdateUserRequest,
        new_password_hash: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let now = Utc::now().naive_utc();
        
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users 
            SET username = COALESCE($2, username),
                email = COALESCE($3, email),
                password_hash = COALESCE($4, password_hash),
                is_active = COALESCE($5, is_active),
                updated_at = $6
            WHERE id = $1
            RETURNING id, username, email, password_hash, 
                     created_at as "created_at!", 
                     updated_at as "updated_at!", 
                     is_active as "is_active!"
            "#,
            id,
            req.username.as_ref(),
            req.email.as_ref(),
            new_password_hash,
            req.is_active,
            now
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    // Soft-delete a user account
    // pub async fn delete_user(pool: &DbPool, id: i32) -> Result<bool, sqlx::Error> {
    //     let now = Utc::now().naive_utc();
    //     let result = sqlx::query!(
    //         "UPDATE users SET is_active = false, updated_at = $2 WHERE id = $1",
    //         id,
    //         now
    //     )
    //     .execute(pool)
    //     .await?;

    //     Ok(result.rows_affected() > 0)
    // }

    // Hard-delete a user account
    pub async fn delete_user(pool: &DbPool, id: i32) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            "DELETE FROM users WHERE id = $1",
            id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
