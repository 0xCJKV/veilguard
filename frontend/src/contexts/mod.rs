use yew::prelude::*;
use crate::types::{User, AuthState};

#[derive(Debug, Clone, PartialEq)]
pub enum AuthAction {
    Login(User),
    Logout,
    UpdateUser(User),
}

pub type AuthContext = UseReducerHandle<AuthState>;

impl Reducible for AuthState {
    type Action = AuthAction;

    fn reduce(self: std::rc::Rc<Self>, action: Self::Action) -> std::rc::Rc<Self> {
        match action {
            AuthAction::Login(user) => {
                std::rc::Rc::new(AuthState {
                    is_authenticated: true,
                    user: Some(user),
                    token: self.token.clone(),
                })
            }
            AuthAction::Logout => {
                std::rc::Rc::new(AuthState {
                    is_authenticated: false,
                    user: None,
                    token: None,
                })
            }
            AuthAction::UpdateUser(user) => {
                std::rc::Rc::new(AuthState {
                    is_authenticated: self.is_authenticated,
                    user: Some(user),
                    token: self.token.clone(),
                })
            }
        }
    }
}

#[derive(Properties, Debug, PartialEq)]
pub struct AuthProviderProps {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(AuthProvider)]
pub fn auth_provider(props: &AuthProviderProps) -> Html {
    let auth_state = use_reducer(|| crate::services::AuthService::get_auth_state());

    html! {
        <ContextProvider<AuthContext> context={auth_state}>
            {props.children.clone()}
        </ContextProvider<AuthContext>>
    }
}