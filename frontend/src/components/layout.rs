use yew::prelude::*;
use yew_router::prelude::*;
use crate::types::AuthState;
use crate::services::AuthService;
use crate::router::Route;

#[derive(Properties, PartialEq)]
pub struct LayoutProps {
    pub children: Children,
}

#[function_component(Layout)]
pub fn layout(props: &LayoutProps) -> Html {
    let auth_state = use_state(|| AuthService::get_auth_state());
    let navigator = use_navigator().unwrap();

    let logout_callback = {
        let auth_state = auth_state.clone();
        let navigator = navigator.clone();
        Callback::from(move |_| {
            AuthService::logout();
            auth_state.set(AuthService::get_auth_state());
            navigator.push(&Route::Home);
        })
    };

    html! {
        <div class="min-h-screen bg-gray-50">
            <nav class="bg-white shadow-lg">
                <div class="max-w-7xl mx-auto px-4">
                    <div class="flex justify-between h-16">
                        <div class="flex items-center">
                            <Link<Route> to={Route::Home} classes="text-xl font-bold text-gray-800">
                                {"VeilGuard"}
                            </Link<Route>>
                        </div>
                        
                        <div class="flex items-center space-x-4">
                            if auth_state.is_authenticated {
                                <Link<Route> to={Route::Dashboard} classes="text-gray-600 hover:text-gray-900">
                                    {"Dashboard"}
                                </Link<Route>>
                                <Link<Route> to={Route::Profile} classes="text-gray-600 hover:text-gray-900">
                                    {"Profile"}
                                </Link<Route>>
                                <button 
                                    onclick={logout_callback}
                                    class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
                                >
                                    {"Logout"}
                                </button>
                            } else {
                                <Link<Route> to={Route::Login} classes="text-gray-600 hover:text-gray-900">
                                    {"Login"}
                                </Link<Route>>
                                <Link<Route> to={Route::Register} classes="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                                    {"Register"}
                                </Link<Route>>
                            }
                        </div>
                    </div>
                </div>
            </nav>
            
            <main class="max-w-7xl mx-auto py-6 px-4">
                { for props.children.iter() }
            </main>
            
            <footer class="bg-gray-800 text-white py-8 mt-auto">
                <div class="max-w-7xl mx-auto px-4 text-center">
                    <p>{"© 2024 VeilGuard. Built with Yew and Rust."}</p>
                </div>
            </footer>
        </div>
    }
}