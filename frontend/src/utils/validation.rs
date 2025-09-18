use regex::Regex;

pub fn is_valid_email(email: &str) -> bool {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    email_regex.is_match(email)
}

pub fn is_valid_username(username: &str) -> bool {
    // Username should be 3-30 characters, alphanumeric and underscores only
    let username_regex = Regex::new(r"^[a-zA-Z0-9_]{3,30}$").unwrap();
    username_regex.is_match(username)
}

pub fn is_strong_password(password: &str) -> bool {
    // At least 8 characters, contains uppercase, lowercase, number
    if password.len() < 8 {
        return false;
    }
    
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    
    has_upper && has_lower && has_digit
}

pub fn sanitize_input(input: &str) -> String {
    // Basic HTML entity encoding for XSS prevention
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('/', "&#x2F;")
}