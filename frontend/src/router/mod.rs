use yew::prelude::*;
use yew_router::prelude::*;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/login")]
    Login,
    #[at("/register")]
    Register,
    #[at("/dashboard")]
    Dashboard,
    #[at("/profile")]
    Profile,
    #[not_found]
    #[at("/404")]
    NotFound,
}

pub fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <crate::pages::Home /> },
        Route::Login => html! { <crate::pages::Login /> },
        Route::Register => html! { <crate::pages::Register /> },
        Route::Dashboard => html! { <crate::pages::Dashboard /> },
        Route::Profile => html! { <crate::pages::Profile /> },
        Route::NotFound => html! { <h1>{ "404 - Page Not Found" }</h1> },
    }
}