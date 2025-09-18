use yew::prelude::*;
use yew_router::prelude::*;
use web_sys::HtmlInputElement;
use wasm_bindgen_futures::spawn_local;

use crate::Route;
use crate::services::{ApiService, AuthService};
use crate::types::LoginRequest;

#[function_component(Login)]
pub fn login() -> Html {
    let navigator = use_navigator().unwrap();
    let login_input = use_node_ref();
    let password_input = use_node_ref();
    let error_message = use_state(|| None::<String>);
    let is_loading = use_state(|| false);

    let onsubmit = {
        let login_input = login_input.clone();
        let password_input = password_input.clone();
        let error_message = error_message.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            
            let login_input = login_input.cast::<HtmlInputElement>().unwrap();
            let password_input = password_input.cast::<HtmlInputElement>().unwrap();
            
            let login_value = login_input.value();
            let password_value = password_input.value();
            
            if login_value.is_empty() || password_value.is_empty() {
                error_message.set(Some("Please fill in all fields".to_string()));
                return;
            }

            let login_request = LoginRequest {
                login: login_value,
                password: password_value,
            };

            let error_message = error_message.clone();
            let is_loading = is_loading.clone();
            let navigator = navigator.clone();

            is_loading.set(true);
            error_message.set(None);

            spawn_local(async move {
                match ApiService::login(login_request).await {
                    Ok(response) => {
                        // Parse the response to extract token and user data
                        if let Some(tokens) = response.get("tokens") {
                            if let Some(access_token) = tokens.get("access_token").and_then(|t| t.as_str()) {
                                if let Some(user_data) = response.get("user") {
                                    if let Ok(user) = serde_json::from_value(user_data.clone()) {
                                        AuthService::set_auth_data(access_token.to_string(), user);
                                        navigator.push(&Route::Dashboard);
                                        return;
                                    }
                                }
                            }
                        }
                        error_message.set(Some("Invalid response format".to_string()));
                    }
                    Err(api_error) => {
                        let error_msg = match api_error {
                            crate::services::api::ApiError::Unauthorized => "Invalid credentials".to_string(),
                            crate::services::api::ApiError::ValidationError(msg) => msg,
                            crate::services::api::ApiError::NetworkError(msg) => format!("Network error: {}", msg),
                            crate::services::api::ApiError::ServerError(msg) => format!("Server error: {}", msg),
                            _ => "Login failed".to_string(),
                        };
                        error_message.set(Some(error_msg));
                    }
                }
                is_loading.set(false);
            });
        })
    };

    html! {
        <div class="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
            <h2 class="text-2xl font-bold text-center text-gray-900 mb-6">{"Sign In"}</h2>
            
            if let Some(error) = (*error_message).as_ref() {
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    {error}
                </div>
            }
            
            <form {onsubmit}>
                <div class="mb-4">
                    <label for="login" class="block text-sm font-medium text-gray-700 mb-2">
                        {"Username or Email"}
                    </label>
                    <input
                        ref={login_input}
                        type="text"
                        id="login"
                        name="login"
                        required=true
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter your username or email"
                    />
                </div>
                
                <div class="mb-6">
                    <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                        {"Password"}
                    </label>
                    <input
                        ref={password_input}
                        type="password"
                        id="password"
                        name="password"
                        required=true
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter your password"
                    />
                </div>
                
                <button
                    type="submit"
                    disabled={*is_loading}
                    class="w-full bg-blue-500 hover:bg-blue-700 disabled:bg-blue-300 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                    if *is_loading {
                        {"Signing In..."}
                    } else {
                        {"Sign In"}
                    }
                </button>
            </form>
            
            <div class="text-center mt-4">
                <p class="text-sm text-gray-600">
                    {"Don't have an account? "}
                    <Link<Route> to={Route::Register} classes="text-blue-500 hover:text-blue-700">
                        {"Sign up"}
                    </Link<Route>>
                </p>
            </div>
        </div>
    }
}