use secrecy::{Secret, ExposeSecret};
use serde::{Deserialize, Serialize};
use validator::{ValidationErrors, ValidationError};
use regex;

// Payload for user registration
#[derive(Debug, Deserialize, Clone)] // Remove Validate derive
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: Secret<String>, // Use Secret for password
}

// Implement manual validation for RegisterPayload
impl RegisterPayload {
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        
        // Validate username length
        if self.username.len() < 3 {
            let error = ValidationError::new("length");
            errors.add("username", error);
        }
        
        // Validate email format with a simple regex check
        let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if !email_regex.is_match(&self.email) {
            let error = ValidationError::new("email");
            errors.add("email", error);
        }
        
        // Validate password length
        if self.password.expose_secret().len() < 8 {
            let error = ValidationError::new("length");
            errors.add("password", error);
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// Payload for user login (using either username or email)
#[derive(Debug, Deserialize, Clone)]
pub struct LoginPayload {
    // Can be either username or email
    pub identifier: String,
    pub password: Secret<String>, // Use Secret for password
}

// Response for successful login/registration
#[derive(Debug, Serialize, Clone)]
pub struct AuthResponse {
    pub user_id: uuid::Uuid,
    pub username: String,
    // Add other relevant fields if needed, e.g., email
    pub email: String,
}
