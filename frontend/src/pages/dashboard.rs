use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::Route;
use crate::services::{ApiService, AuthService};
use crate::types::User;

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    let navigator = use_navigator().unwrap();
    let users = use_state(|| Vec::<User>::new());
    let is_loading = use_state(|| true);
    let error_message = use_state(|| None::<String>);
    let current_user = AuthService::get_user_data();

    // Redirect if not authenticated
    {
        let navigator = navigator.clone();
        use_effect_with((), move |_| {
            if !AuthService::is_authenticated() {
                navigator.push(&Route::Login);
            }
            || ()
        });
    }

    // Load users on component mount
    {
        let users = users.clone();
        let is_loading = is_loading.clone();
        let error_message = error_message.clone();

        use_effect_with((), move |_| {
            spawn_local(async move {
                match ApiService::list_users(Some(1), Some(10)).await {
                    Ok(response) => {
                        // Parse the response to extract users array
                        if let Some(users_data) = response.get("users") {
                            if let Ok(users_list) = serde_json::from_value::<Vec<User>>(users_data.clone()) {
                                users.set(users_list);
                            }
                        }
                    }
                    Err(api_error) => {
                        let error_msg = match api_error {
                            crate::services::api::ApiError::Unauthorized => "Unauthorized access".to_string(),
                            crate::services::api::ApiError::NetworkError(msg) => format!("Network error: {}", msg),
                            crate::services::api::ApiError::ServerError(msg) => format!("Server error: {}", msg),
                            _ => "Failed to load users".to_string(),
                        };
                        error_message.set(Some(error_msg));
                    }
                }
                is_loading.set(false);
            });
            || ()
        });
    }

    if let Some(user) = current_user {
        html! {
            <div>
                <div class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900 mb-2">
                        {format!("Welcome back, {}!", user.username)}
                    </h1>
                    <p class="text-gray-600">{"Manage your account and view system information"}</p>
                </div>

                <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-2">{"Account Status"}</h3>
                        <p class="text-2xl font-bold text-green-600">
                            {if user.is_active { "Active" } else { "Inactive" }}
                        </p>
                        <p class="text-sm text-gray-500">{"Your account is in good standing"}</p>
                    </div>

                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-2">{"Member Since"}</h3>
                        <p class="text-2xl font-bold text-blue-600">
                            {user.created_at.format("%B %Y").to_string()}
                        </p>
                        <p class="text-sm text-gray-500">{"Account creation date"}</p>
                    </div>

                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-2">{"Quick Actions"}</h3>
                        <Link<Route> to={Route::Profile} classes="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                            {"Edit Profile"}
                        </Link<Route>>
                    </div>
                </div>

                <div class="bg-white rounded-lg shadow-md p-6">
                    <h2 class="text-xl font-bold mb-4">{"Recent Users"}</h2>
                    
                    if let Some(error) = (*error_message).as_ref() {
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                            {error}
                        </div>
                    }
                    
                    if *is_loading {
                        <div class="text-center py-4">
                            <p class="text-gray-600">{"Loading users..."}</p>
                        </div>
                    } else if users.is_empty() {
                        <div class="text-center py-4">
                            <p class="text-gray-600">{"No users found"}</p>
                        </div>
                    } else {
                        <div class="overflow-x-auto">
                            <table class="min-w-full table-auto">
                                <thead>
                                    <tr class="bg-gray-50">
                                        <th class="px-4 py-2 text-left">{"Username"}</th>
                                        <th class="px-4 py-2 text-left">{"Email"}</th>
                                        <th class="px-4 py-2 text-left">{"Status"}</th>
                                        <th class="px-4 py-2 text-left">{"Joined"}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    { for users.iter().map(|user| html! {
                                        <tr class="border-b">
                                            <td class="px-4 py-2">{&user.username}</td>
                                            <td class="px-4 py-2">{&user.email}</td>
                                            <td class="px-4 py-2">
                                                <span class={if user.is_active { "text-green-600" } else { "text-red-600" }}>
                                                    {if user.is_active { "Active" } else { "Inactive" }}
                                                </span>
                                            </td>
                                            <td class="px-4 py-2">{user.created_at.format("%Y-%m-%d").to_string()}</td>
                                        </tr>
                                    }) }
                                </tbody>
                            </table>
                        </div>
                    }
                </div>
            </div>
        }
    } else {
        html! {
            <div class="text-center">
                <p>{"Loading..."}</p>
            </div>
        }
    }
}