use secrecy::{SecretString, ExposeSecret};
use serde::{Deserialize, Serialize};
use validator::{ValidationErrors, ValidationError};
use regex;

// Payload for user registration
#[derive(Debug, Deserialize, Clone)] // Remove Validate derive
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: SecretString, // Corrected: Was Secret<String>
    pub recovery_phrase: Option<SecretString>, // Corrected: Was Option<Secret<String>>
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
    pub password: SecretString, // Corrected: Was Secret<String>
}

// Response for successful login/registration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthResponse {
    pub user_id: uuid::Uuid,
    pub username: String,
    // Add other relevant fields if needed, e.g., email
    pub email: String,
}

// Payload for changing password
#[derive(Debug, Deserialize, Clone)]
pub struct ChangePasswordPayload {
    pub current_password: SecretString, // Corrected: Was Secret<String>
    pub new_password: SecretString, // Corrected: Was Secret<String>
}

impl ChangePasswordPayload {
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        // Validate new_password length
        if self.new_password.expose_secret().len() < 8 {
            let mut error = ValidationError::new("length");
            error.add_param("min".into(), &8);
            errors.add("new_password", error);
        }

        // Potentially add other password complexity rules here in the future

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// Payload for password recovery
#[derive(Debug, Deserialize, Clone)]
pub struct RecoverPasswordPayload {
    pub identifier: String, // Can be username or email
    pub recovery_phrase: SecretString, // Corrected: Was Secret<String>
    pub new_password: SecretString, // Corrected: Was Secret<String>
}

impl RecoverPasswordPayload {
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        // Validate identifier (basic non-empty check, more specific checks can be added if needed)
        if self.identifier.trim().is_empty() {
            let mut error = ValidationError::new("identifier_empty");
            error.message = Some("Identifier cannot be empty.".into());
            errors.add("identifier", error);
        }

        // Validate recovery_phrase (basic non-empty check)
        if self.recovery_phrase.expose_secret().trim().is_empty() {
            let mut error = ValidationError::new("recovery_phrase_empty");
            error.message = Some("Recovery phrase cannot be empty.".into());
            errors.add("recovery_phrase", error);
        }

        // Validate new_password length
        if self.new_password.expose_secret().len() < 8 {
            let mut error = ValidationError::new("length");
            error.add_param("min".into(), &8);
            error.message = Some("New password must be at least 8 characters long.".into());
            errors.add("new_password", error);
        }

        // Potentially add other password complexity rules here in the future

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
