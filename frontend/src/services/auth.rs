use gloo::storage::{LocalStorage, Storage};
use yew::prelude::*;

use crate::types::{AuthState, User};

const AUTH_TOKEN_KEY: &str = "veilguard_auth_token";
const USER_DATA_KEY: &str = "veilguard_user_data";

pub struct AuthService;

impl AuthService {
    pub fn get_auth_state() -> AuthState {
        let token = Self::get_token();
        let user = Self::get_user_data();
        
        AuthState {
            is_authenticated: token.is_some() && user.is_some(),
            user,
            token,
        }
    }

    pub fn set_auth_data(token: String, user: User) {
        let _ = LocalStorage::set(AUTH_TOKEN_KEY, &token);
        let _ = LocalStorage::set(USER_DATA_KEY, &user);
    }

    pub fn clear_auth_data() {
        LocalStorage::delete(AUTH_TOKEN_KEY);
        LocalStorage::delete(USER_DATA_KEY);
    }

    pub fn logout() {
        Self::clear_auth_data();
    }

    pub fn get_token() -> Option<String> {
        LocalStorage::get(AUTH_TOKEN_KEY).ok()
    }

    pub fn get_user_data() -> Option<User> {
        LocalStorage::get(USER_DATA_KEY).ok()
    }

    pub fn is_authenticated() -> bool {
        Self::get_token().is_some() && Self::get_user_data().is_some()
    }
}