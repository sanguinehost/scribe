use regex;
use secrecy::{ExposeSecret, SecretString};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use validator::{ValidationError, ValidationErrors};

// Payload for user registration
#[derive(Deserialize, Clone)] // Remove Validate derive, Remove Debug
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: SecretString,          // Corrected: Was Secret<String>
    pub recovery_phrase: Option<String>, // Corrected: Was Option<Secret<String>>
}

impl std::fmt::Debug for RegisterPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterPayload")
            .field("username", &self.username)
            .field("email", &"[REDACTED]")
            .field("password", &self.password) // SecretString handles its own redaction
            .field(
                "recovery_phrase",
                &self.recovery_phrase.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// Implement manual validation for RegisterPayload
impl RegisterPayload {
    /// Validates the registration payload fields
    ///
    /// # Errors
    /// Returns `ValidationErrors` if:
    /// - Username is less than 3 characters
    /// - Email format is invalid
    /// - Password is less than 8 characters
    ///
    /// # Panics
    /// Panics if the email regex pattern fails to compile
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        // Validate username length
        if self.username.len() < 3 {
            let error = ValidationError::new("length");
            errors.add("username", error);
        }

        // Validate email format with a simple regex check
        let email_regex =
            regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
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
#[derive(Debug, Deserialize, Clone)] // Removed Serialize derive
pub struct LoginPayload {
    // Can be either username or email
    pub identifier: String,
    pub password: SecretString, // Corrected: Was Secret<String>
}

impl serde::Serialize for LoginPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("LoginPayload", 2)?;
        state.serialize_field("identifier", &self.identifier)?;
        state.serialize_field("password", self.password.expose_secret())?;
        state.end()
    }
}

// Response for successful login/registration
#[derive(Serialize, Deserialize, Clone)] // Removed Debug
pub struct AuthResponse {
    pub user_id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub role: String,                 // Added role field
    pub recovery_key: Option<String>, // Added recovery key field
    pub default_persona_id: Option<uuid::Uuid>,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("email", &"[REDACTED]")
            .field("role", &self.role)
            .field(
                "recovery_key",
                &self.recovery_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("default_persona_id", &self.default_persona_id)
            .finish()
    }
}

// Payload for changing password
#[derive(Debug, Deserialize, Clone)]
pub struct ChangePasswordPayload {
    pub current_password: SecretString, // Corrected: Was Secret<String>
    pub new_password: SecretString,     // Corrected: Was Secret<String>
}

impl ChangePasswordPayload {
    /// Validates the change password payload fields
    ///
    /// # Errors
    /// Returns `ValidationErrors` if the new password is less than 8 characters
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
    pub identifier: String,            // Can be username or email
    pub recovery_phrase: SecretString, // Corrected: Was Secret<String>
    pub new_password: SecretString,    // Corrected: Was Secret<String>
}

impl RecoverPasswordPayload {
    /// Validates the password recovery payload fields
    ///
    /// # Errors
    /// Returns `ValidationErrors` if:
    /// - Identifier is empty or whitespace only
    /// - Recovery phrase is empty or whitespace only
    /// - New password is less than 8 characters
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
