use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::errors::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub message: String,
    pub error_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: HashMap<String, ValidationError>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: HashMap::new(),
        }
    }

    pub fn add_error(&mut self, field: &str, message: &str, error_type: &str) {
        self.is_valid = false;
        self.errors.insert(
            field.to_string(),
            ValidationError {
                message: message.to_string(),
                error_type: error_type.to_string(),
            },
        );
    }

    pub fn merge(&mut self, other: ValidationResult) {
        if !other.is_valid {
            self.is_valid = false;
            for (field, error) in other.errors {
                self.errors.insert(field, error);
            }
        }
    }

    pub fn to_app_error(&self) -> AppError {
        if self.errors.is_empty() {
            return AppError::validation("Unknown validation error");
        }
        
        let messages: Vec<String> = self.errors.iter()
            .map(|(_, error)| error.message.clone())
            .collect();
        AppError::validation(&messages.join(", "))
    }
}

pub struct UserValidator;

impl UserValidator {
    pub fn validate_username(username: &str) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Length validation
        if username.is_empty() {
            result.add_error("username", "Username is required", "required");
            return result;
        }
        
        if username.len() < 3 {
            result.add_error("username", "Username must be at least 3 characters long", "min_length");
        }
        
        if username.len() > 50 {
            result.add_error("username", "Username must not exceed 50 characters", "max_length");
        }
        
        // Character validation - only alphanumeric and underscores
        let username_regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
        if !username_regex.is_match(username) {
            result.add_error("username", "Username can only contain letters, numbers, and underscores", "invalid_format");
        }
        
        // Reserved usernames
        let reserved = ["admin", "root", "system", "api", "www", "mail", "ftp"];
        if reserved.contains(&username.to_lowercase().as_str()) {
            result.add_error("username", "This username is reserved and cannot be used", "reserved");
        }
        
        result
    }
    
    pub fn validate_email(email: &str) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        if email.is_empty() {
            result.add_error("email", "Email is required", "required");
            return result;
        }
        
        // Basic email format validation
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if !email_regex.is_match(email) {
            result.add_error("email", "Please enter a valid email address", "invalid_format");
        }
        
        // Length validation
        if email.len() > 254 {
            result.add_error("email", "Email address is too long", "max_length");
        }
        
        // Domain validation
        if let Some(domain) = email.split('@').nth(1) {
            if domain.len() > 253 {
                result.add_error("email", "Email domain is too long", "invalid_domain");
            }
        }
        
        result
    }
    
    pub fn validate_password(password: &str) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        if password.is_empty() {
            result.add_error("password", "Password is required", "required");
            return result;
        }
        
        // Length validation
        if password.len() < 8 {
            result.add_error("password", "Password must be at least 8 characters long", "min_length");
        }
        
        if password.len() > 128 {
            result.add_error("password", "Password must not exceed 128 characters", "max_length");
        }
        
        // Complexity validation
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        if !has_lowercase {
            result.add_error("password", "Password must contain at least one lowercase letter", "missing_lowercase");
        }
        
        if !has_uppercase {
            result.add_error("password", "Password must contain at least one uppercase letter", "missing_uppercase");
        }
        
        if !has_digit {
            result.add_error("password", "Password must contain at least one number", "missing_digit");
        }
        
        if !has_special {
            result.add_error("password", "Password must contain at least one special character", "missing_special");
        }
        
        // Common password check
        let common_passwords = [
            "password", "123456", "123456789", "qwerty", "abc123", 
            "password123", "admin", "letmein", "welcome", "monkey"
        ];
        
        if common_passwords.contains(&password.to_lowercase().as_str()) {
            result.add_error("password", "This password is too common. Please choose a more secure password", "common_password");
        }
        
        result
    }
    
    pub fn validate_password_confirmation(password: &str, confirmation: &str) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        if password != confirmation {
            result.add_error("password_confirmation", "Passwords do not match", "mismatch");
        }
        
        result
    }
}

pub fn sanitize_input(input: &str) -> String {
    // Remove potentially dangerous characters and trim whitespace
    input
        .trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect::<String>()
        .replace('\0', "") // Remove null bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        // Valid username
        let result = UserValidator::validate_username("valid_user123");
        assert!(result.is_valid);
        
        // Too short
        let result = UserValidator::validate_username("ab");
        assert!(!result.is_valid);
        assert_eq!(result.errors.values().next().unwrap().error_type, "min_length");
        
        // Invalid characters
        let result = UserValidator::validate_username("user@name");
        assert!(!result.is_valid);
        assert_eq!(result.errors.values().next().unwrap().error_type, "invalid_format");
        
        // Reserved username
        let result = UserValidator::validate_username("admin");
        assert!(!result.is_valid);
        assert_eq!(result.errors.values().next().unwrap().error_type, "reserved");
    }

    #[test]
    fn test_email_validation() {
        // Valid email
        let result = UserValidator::validate_email("user@example.com");
        assert!(result.is_valid);
        
        // Invalid format
        let result = UserValidator::validate_email("invalid-email");
        assert!(!result.is_valid);
        assert_eq!(result.errors.values().next().unwrap().error_type, "invalid_format");
    }

    #[test]
    fn test_password_validation() {
        // Valid password
        let result = UserValidator::validate_password("SecurePass123!");
        assert!(result.is_valid);
        
        // Too short
        let result = UserValidator::validate_password("short");
        assert!(!result.is_valid);
        
        // Missing complexity
        let result = UserValidator::validate_password("alllowercase");
        assert!(!result.is_valid);
        assert!(result.errors.values().any(|e| e.error_type == "missing_uppercase"));
    }
}