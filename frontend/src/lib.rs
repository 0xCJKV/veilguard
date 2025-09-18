use yew::prelude::*;
use yew_router::prelude::*;

mod components;
mod contexts;
mod pages;
mod router;
mod services;
mod types;
mod utils;
use components::Layout;
use router::{Route, switch};
use contexts::AuthProvider;

#[function_component(App)]
fn app() -> Html {
    html! {
        <AuthProvider>
            <BrowserRouter>
                <Layout>
                    <Switch<Route> render={switch} />
                </Layout>
            </BrowserRouter>
        </AuthProvider>
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    log::info!("VeilGuard Frontend starting...");
    yew::Renderer::<App>::new().render();
}