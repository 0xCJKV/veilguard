use gloo::net::http::{Request, Response};
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::types::{User, CreateUserRequest, LoginRequest, UpdateUserRequest};

const API_BASE: &str = "http://127.0.0.1:8080/api/v1";

#[derive(Debug, Clone)]
pub enum ApiError {
    NetworkError(String),
    ServerError(String),
    ValidationError(String),
    Unauthorized,
    NotFound,
}

impl From<gloo::net::Error> for ApiError {
    fn from(error: gloo::net::Error) -> Self {
        ApiError::NetworkError(error.to_string())
    }
}

pub struct ApiService;

impl ApiService {
    pub async fn register(user_data: CreateUserRequest) -> Result<User, ApiError> {
        let response = Request::post(&format!("{}/auth/register", API_BASE))
            .header("Content-Type", "application/json")
            .json(&user_data)?
            .send()
            .await?;

        Self::handle_response(response).await
    }

    pub async fn login(login_data: LoginRequest) -> Result<serde_json::Value, ApiError> {
        let response = Request::post(&format!("{}/auth/login", API_BASE))
            .header("Content-Type", "application/json")
            .json(&login_data)?
            .send()
            .await?;

        Self::handle_response(response).await
    }

    pub async fn logout() -> Result<(), ApiError> {
        let response = Request::post(&format!("{}/auth/logout", API_BASE))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if response.ok() {
            Ok(())
        } else {
            Err(ApiError::ServerError("Logout failed".to_string()))
        }
    }

    pub async fn get_user(user_id: i32) -> Result<User, ApiError> {
        let response = Request::get(&format!("{}/users/{}", API_BASE, user_id))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        Self::handle_response(response).await
    }

    pub async fn update_user(user_id: i32, update_data: UpdateUserRequest) -> Result<User, ApiError> {
        let response = Request::put(&format!("{}/users/{}", API_BASE, user_id))
            .header("Content-Type", "application/json")
            .json(&update_data)?
            .send()
            .await?;

        Self::handle_response(response).await
    }

    pub async fn list_users(page: Option<i64>, limit: Option<i64>) -> Result<serde_json::Value, ApiError> {
        let mut url = format!("{}/users", API_BASE);
        let mut params = Vec::new();
        
        if let Some(p) = page {
            params.push(format!("page={}", p));
        }
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = Request::get(&url)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        Self::handle_response(response).await
    }

    async fn handle_response<T>(response: Response) -> Result<T, ApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        
        match status {
            200..=299 => {
                let data: T = response.json().await?;
                Ok(data)
            }
            401 => Err(ApiError::Unauthorized),
            404 => Err(ApiError::NotFound),
            400..=499 => {
                let error_text = response.text().await.unwrap_or_else(|_| "Client error".to_string());
                Err(ApiError::ValidationError(error_text))
            }
            500..=599 => {
                let error_text = response.text().await.unwrap_or_else(|_| "Server error".to_string());
                Err(ApiError::ServerError(error_text))
            }
            _ => Err(ApiError::NetworkError(format!("Unexpected status: {}", status))),
        }
    }
}