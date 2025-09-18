use yew::prelude::*;
use yew_router::prelude::*;

use crate::Route;
use crate::services::AuthService;

#[function_component(Home)]
pub fn home() -> Html {
    let is_authenticated = AuthService::is_authenticated();

    html! {
        <div class="text-center">
            <div class="max-w-4xl mx-auto">
                <h1 class="text-4xl font-bold text-gray-900 mb-6">
                    {"Welcome to VeilGuard"}
                </h1>
                
                <p class="text-xl text-gray-600 mb-8">
                    {"A secure user management system built with Rust, Yew, and WebAssembly"}
                </p>
                
                <div class="grid md:grid-cols-3 gap-8 mb-12">
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-3">{"🔒 Secure Authentication"}</h3>
                        <p class="text-gray-600">{"Advanced security with JWT tokens and password hashing"}</p>
                    </div>
                    
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-3">{"⚡ Fast Performance"}</h3>
                        <p class="text-gray-600">{"Built with Rust and WebAssembly for optimal speed"}</p>
                    </div>
                    
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h3 class="text-lg font-semibold mb-3">{"🎨 Modern UI"}</h3>
                        <p class="text-gray-600">{"Clean, responsive interface with Tailwind CSS"}</p>
                    </div>
                </div>
                
                if !is_authenticated {
                    <div class="space-x-4">
                        <Link<Route> to={Route::Register} classes="bg-blue-500 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg text-lg">
                            {"Get Started"}
                        </Link<Route>>
                        
                        <Link<Route> to={Route::Login} classes="bg-gray-500 hover:bg-gray-700 text-white font-bold py-3 px-6 rounded-lg text-lg">
                            {"Sign In"}
                        </Link<Route>>
                    </div>
                } else {
                    <div>
                        <Link<Route> to={Route::Dashboard} classes="bg-green-500 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg text-lg">
                            {"Go to Dashboard"}
                        </Link<Route>>
                    </div>
                }
            </div>
        </div>
    }
}