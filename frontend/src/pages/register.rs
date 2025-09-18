use yew::prelude::*;
use yew_router::prelude::*;
use web_sys::HtmlInputElement;
use wasm_bindgen_futures::spawn_local;

use crate::Route;
use crate::services::ApiService;
use crate::types::CreateUserRequest;
use crate::utils::validation::{is_valid_email, is_valid_username, is_strong_password};

#[function_component(Register)]
pub fn register() -> Html {
    let navigator = use_navigator().unwrap();
    let username_input = use_node_ref();
    let email_input = use_node_ref();
    let password_input = use_node_ref();
    let confirm_password_input = use_node_ref();
    let error_message = use_state(|| None::<String>);
    let success_message = use_state(|| None::<String>);
    let is_loading = use_state(|| false);

    let onsubmit = {
        let username_input = username_input.clone();
        let email_input = email_input.clone();
        let password_input = password_input.clone();
        let confirm_password_input = confirm_password_input.clone();
        let error_message = error_message.clone();
        let success_message = success_message.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            
            let username_input = username_input.cast::<HtmlInputElement>().unwrap();
            let email_input = email_input.cast::<HtmlInputElement>().unwrap();
            let password_input = password_input.cast::<HtmlInputElement>().unwrap();
            let confirm_password_input = confirm_password_input.cast::<HtmlInputElement>().unwrap();
            
            let username = username_input.value();
            let email = email_input.value();
            let password = password_input.value();
            let confirm_password = confirm_password_input.value();
            
            // Client-side validation
            if username.is_empty() || email.is_empty() || password.is_empty() || confirm_password.is_empty() {
                error_message.set(Some("Please fill in all fields".to_string()));
                return;
            }

            if !is_valid_username(&username) {
                error_message.set(Some("Username must be 3-30 characters, alphanumeric and underscores only".to_string()));
                return;
            }

            if !is_valid_email(&email) {
                error_message.set(Some("Please enter a valid email address".to_string()));
                return;
            }

            if password != confirm_password {
                error_message.set(Some("Passwords do not match".to_string()));
                return;
            }

            if !is_strong_password(&password) {
                error_message.set(Some("Password must be at least 8 characters with uppercase, lowercase, and number".to_string()));
                return;
            }

            let user_request = CreateUserRequest {
                username,
                email,
                password,
            };

            let error_message = error_message.clone();
            let success_message = success_message.clone();
            let is_loading = is_loading.clone();
            let navigator = navigator.clone();

            is_loading.set(true);
            error_message.set(None);
            success_message.set(None);

            spawn_local(async move {
                match ApiService::register(user_request).await {
                    Ok(_user) => {
                        success_message.set(Some("Registration successful! Please log in.".to_string()));
                        // Redirect to login page after a short delay
                        gloo::timers::callback::Timeout::new(2000, move || {
                            navigator.push(&Route::Login);
                        }).forget();
                    }
                    Err(api_error) => {
                        let error_msg = match api_error {
                            crate::services::api::ApiError::ValidationError(msg) => msg,
                            crate::services::api::ApiError::NetworkError(msg) => format!("Network error: {}", msg),
                            crate::services::api::ApiError::ServerError(msg) => format!("Server error: {}", msg),
                            _ => "Registration failed".to_string(),
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
            <h2 class="text-2xl font-bold text-center text-gray-900 mb-6">{"Create Account"}</h2>
            
            if let Some(error) = (*error_message).as_ref() {
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    {error}
                </div>
            }
            
            if let Some(success) = (*success_message).as_ref() {
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
                    {success}
                </div>
            }
            
            <form {onsubmit}>
                <div class="mb-4">
                    <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
                        {"Username"}
                    </label>
                    <input
                        ref={username_input}
                        type="text"
                        id="username"
                        name="username"
                        required=true
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Choose a username"
                    />
                </div>
                
                <div class="mb-4">
                    <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
                        {"Email"}
                    </label>
                    <input
                        ref={email_input}
                        type="email"
                        id="email"
                        name="email"
                        required=true
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter your email"
                    />
                </div>
                
                <div class="mb-4">
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
                        placeholder="Create a password (min 8 characters)"
                    />
                </div>
                
                <div class="mb-6">
                    <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">
                        {"Confirm Password"}
                    </label>
                    <input
                        ref={confirm_password_input}
                        type="password"
                        id="confirm_password"
                        name="confirm_password"
                        required=true
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Confirm your password"
                    />
                </div>
                
                <button
                    type="submit"
                    disabled={*is_loading}
                    class="w-full bg-blue-500 hover:bg-blue-700 disabled:bg-blue-300 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                    if *is_loading {
                        {"Creating Account..."}
                    } else {
                        {"Create Account"}
                    }
                </button>
            </form>
            
            <div class="text-center mt-4">
                <p class="text-sm text-gray-600">
                    {"Already have an account? "}
                    <Link<Route> to={Route::Login} classes="text-blue-500 hover:text-blue-700">
                        {"Sign in"}
                    </Link<Route>>
                </p>
            </div>
        </div>
    }
}