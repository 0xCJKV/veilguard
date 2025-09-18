use yew::prelude::*;
use yew_router::prelude::*;
use web_sys::{HtmlFormElement, HtmlInputElement};
use wasm_bindgen_futures::spawn_local;

use crate::components::Layout;
use crate::services::{ApiService, AuthService};
use crate::types::{User, UpdateUserRequest, ChangePasswordRequest};
use crate::contexts::AuthContext;
use crate::router::Route;
use crate::utils::validation::{is_valid_email, is_valid_username, is_strong_password, sanitize_input};

#[function_component(Profile)]
pub fn profile() -> Html {
    let navigator = use_navigator().unwrap();
    let current_user = use_state(|| AuthService::get_user_data());
    let username_input = use_node_ref();
    let email_input = use_node_ref();
    let current_password_input = use_node_ref();
    let new_password_input = use_node_ref();
    let confirm_password_input = use_node_ref();
    let error_message = use_state(|| None::<String>);
    let success_message = use_state(|| None::<String>);
    let is_loading = use_state(|| false);

    // Redirect if not authenticated and set initial form values
    {
        let navigator = navigator.clone();
        let username_input = username_input.clone();
        let email_input = email_input.clone();
        let current_user = current_user.clone();
        
        use_effect_with((), move |_| {
            if !AuthService::is_authenticated() {
                navigator.push(&Route::Login);
            } else if let Some(user) = current_user.as_ref() {
                // Set initial form values
                if let Some(username_element) = username_input.cast::<HtmlInputElement>() {
                    username_element.set_value(&user.username);
                }
                if let Some(email_element) = email_input.cast::<HtmlInputElement>() {
                    email_element.set_value(&user.email);
                }
            }
            || ()
        });
    }

    let onsubmit = {
        let username_input = username_input.clone();
        let email_input = email_input.clone();
        let current_password_input = current_password_input.clone();
        let new_password_input = new_password_input.clone();
        let confirm_password_input = confirm_password_input.clone();
        let error_message = error_message.clone();
        let success_message = success_message.clone();
        let is_loading = is_loading.clone();
        let current_user = current_user.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            
            let username_input = username_input.cast::<HtmlInputElement>().unwrap();
            let email_input = email_input.cast::<HtmlInputElement>().unwrap();
            let current_password_input = current_password_input.cast::<HtmlInputElement>().unwrap();
            let new_password_input = new_password_input.cast::<HtmlInputElement>().unwrap();
            let confirm_password_input = confirm_password_input.cast::<HtmlInputElement>().unwrap();
            
            let username = username_input.value();
            let email = email_input.value();
            let current_password = current_password_input.value();
            let new_password = new_password_input.value();
            let confirm_password = confirm_password_input.value();

            if let Some(user) = current_user.as_ref() {
                // Validation
                if username.is_empty() || email.is_empty() {
                    error_message.set(Some("Username and email are required".to_string()));
                    return;
                }

                if !is_valid_username(&username) {
                    error_message.set(Some("Please enter a valid username".to_string()));
                    return;
                }

                if !is_valid_email(&email) {
                    error_message.set(Some("Please enter a valid email address".to_string()));
                    return;
                }

                // Password validation if changing password
                if !new_password.is_empty() {
                    if current_password.is_empty() {
                        error_message.set(Some("Current password is required to change password".to_string()));
                        return;
                    }

                    if new_password != confirm_password {
                        error_message.set(Some("New passwords do not match".to_string()));
                        return;
                    }

                    if !is_strong_password(&new_password) {
                        error_message.set(Some("New password must be at least 8 characters with uppercase, lowercase, and number".to_string()));
                        return;
                    }
                }

                let update_request = UpdateUserRequest {
                    username: if username != user.username { Some(username) } else { None },
                    email: if email != user.email { Some(email) } else { None },
                    current_password: if !current_password.is_empty() { Some(current_password) } else { None },
                    new_password: if !new_password.is_empty() { Some(new_password) } else { None },
                    is_active: None,
                };

                let user_id = user.id;
                let error_message = error_message.clone();
                let success_message = success_message.clone();
                let is_loading = is_loading.clone();
                let current_user = current_user.clone();

                is_loading.set(true);
                error_message.set(None);
                success_message.set(None);

                spawn_local(async move {
                    match ApiService::update_user(user_id, update_request).await {
                        Ok(updated_user) => {
                            // Update local user data
                            AuthService::set_auth_data(
                                AuthService::get_token().unwrap_or_default(),
                                updated_user.clone()
                            );
                            current_user.set(Some(updated_user));
                            success_message.set(Some("Profile updated successfully!".to_string()));
                            
                            // Clear password fields
                            current_password_input.set_value("");
                            new_password_input.set_value("");
                            confirm_password_input.set_value("");
                        }
                        Err(api_error) => {
                            let error_msg = match api_error {
                                crate::services::api::ApiError::Unauthorized => "Invalid current password".to_string(),
                                crate::services::api::ApiError::ValidationError(msg) => msg,
                                crate::services::api::ApiError::NetworkError(msg) => format!("Network error: {}", msg),
                                crate::services::api::ApiError::ServerError(msg) => format!("Server error: {}", msg),
                                _ => "Update failed".to_string(),
                            };
                            error_message.set(Some(error_msg));
                        }
                    }
                    is_loading.set(false);
                });
            }
        })
    };

    if let Some(user) = current_user.as_ref() {
        html! {
            <div class="max-w-2xl mx-auto">
                <h1 class="text-3xl font-bold text-gray-900 mb-6">{"Profile Settings"}</h1>
                
                <div class="bg-white rounded-lg shadow-md p-6">
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
                        <div class="grid md:grid-cols-2 gap-6 mb-6">
                            <div>
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
                                />
                            </div>
                            
                            <div>
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
                                />
                            </div>
                        </div>
                        
                        <div class="border-t pt-6 mb-6">
                            <h3 class="text-lg font-medium text-gray-900 mb-4">{"Change Password"}</h3>
                            <p class="text-sm text-gray-600 mb-4">{"Leave blank to keep current password"}</p>
                            
                            <div class="space-y-4">
                                <div>
                                    <label for="current_password" class="block text-sm font-medium text-gray-700 mb-2">
                                        {"Current Password"}
                                    </label>
                                    <input
                                        ref={current_password_input}
                                        type="password"
                                        id="current_password"
                                        name="current_password"
                                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        placeholder="Enter current password"
                                    />
                                </div>
                                
                                <div class="grid md:grid-cols-2 gap-4">
                                    <div>
                                        <label for="new_password" class="block text-sm font-medium text-gray-700 mb-2">
                                            {"New Password"}
                                        </label>
                                        <input
                                            ref={new_password_input}
                                            type="password"
                                            id="new_password"
                                            name="new_password"
                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                            placeholder="Enter new password"
                                        />
                                    </div>
                                    
                                    <div>
                                        <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">
                                            {"Confirm New Password"}
                                        </label>
                                        <input
                                            ref={confirm_password_input}
                                            type="password"
                                            id="confirm_password"
                                            name="confirm_password"
                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                            placeholder="Confirm new password"
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="flex justify-between items-center">
                            <Link<Route> to={Route::Dashboard} classes="text-gray-600 hover:text-gray-900">
                                {"← Back to Dashboard"}
                            </Link<Route>>
                            
                            <button
                                type="submit"
                                disabled={*is_loading}
                                class="bg-blue-500 hover:bg-blue-700 disabled:bg-blue-300 text-white font-bold py-2 px-6 rounded focus:outline-none focus:shadow-outline"
                            >
                                if *is_loading {
                                    {"Updating..."}
                                } else {
                                    {"Update Profile"}
                                }
                            </button>
                        </div>
                    </form>
                </div>
                
                <div class="mt-6 bg-gray-50 rounded-lg p-4">
                    <h3 class="text-sm font-medium text-gray-700 mb-2">{"Account Information"}</h3>
                    <div class="text-sm text-gray-600 space-y-1">
                        <p>{"Account created: "}{user.created_at.format("%B %d, %Y").to_string()}</p>
                        <p>{"Last updated: "}{user.updated_at.format("%B %d, %Y").to_string()}</p>
                        <p>{"Status: "}<span class={if user.is_active { "text-green-600" } else { "text-red-600" }}>
                            {if user.is_active { "Active" } else { "Inactive" }}
                        </span></p>
                    </div>
                </div>
            </div>
        }
    } else {
        html! {
            <div class="text-center">
                <p>{"Loading profile..."}</p>
            </div>
        }
    }
}