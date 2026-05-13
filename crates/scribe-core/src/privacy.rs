use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use crate::types::{SO2Rotor, ThermodynamicTelemetry};

/// Compositional Auth Rotor
/// Used for Adjoint Verification of gradient updates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompositionalAuthRotor(pub SO2Rotor);

/// Adjoint Verification Pass
/// Protects the HNA from "Thermodynamic Hijacking".
pub trait AdjointVerifier {
    /// Performs an Adjoint Verification pass on a telemetry update.
    /// Returns true if the projected Free Energy surprise is within safe bounds.
    fn verify_adjoint(&self, telemetry: &ThermodynamicTelemetry, threshold: f32) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedString {
    content: String,
    redaction_type: RedactionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedactionType {
    Content,      // User-generated content
    SystemPrompt, // System prompts
    PersonalInfo, // Email, username, etc.
    Credentials,  // Passwords, tokens, etc.
}

impl SanitizedString {
    pub fn content<S: Into<String>>(content: S) -> Self {
        Self {
            content: content.into(),
            redaction_type: RedactionType::Content,
        }
    }

    pub fn system_prompt<S: Into<String>>(content: S) -> Self {
        Self {
            content: content.into(),
            redaction_type: RedactionType::SystemPrompt,
        }
    }

    pub fn personal_info<S: Into<String>>(content: S) -> Self {
        Self {
            content: content.into(),
            redaction_type: RedactionType::PersonalInfo,
        }
    }

    pub fn credentials<S: Into<String>>(content: S) -> Self {
        Self {
            content: content.into(),
            redaction_type: RedactionType::Credentials,
        }
    }

    pub fn expose(&self) -> &str {
        &self.content
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

impl fmt::Display for SanitizedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.redaction_type {
            RedactionType::Content => write!(f, "<content-redacted:{}-chars>", self.len()),
            RedactionType::SystemPrompt => {
                write!(f, "<system-prompt-redacted:{}-chars>", self.len())
            }
            RedactionType::PersonalInfo => write!(f, "<personal-info-redacted>"),
            RedactionType::Credentials => write!(f, "<credentials-redacted>"),
        }
    }
}

pub fn sanitize_personal_info<S: Into<String>>(content: S) -> SanitizedString {
    SanitizedString::personal_info(content)
}

/// Check if a string looks like a UUID
pub fn is_uuid_pattern(s: &str) -> bool {
    s.len() == 36
        && s.chars().filter(|&c| c == '-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Check if a string looks like an email
pub fn is_email_pattern(s: &str) -> bool {
    s.contains('@') && s.contains('.') && s.len() > 5
}

/// Utility for sanitizing JSON values in logs
pub fn sanitize_json_value(value: &Value) -> Value {
    match value {
        Value::String(s) => {
            if is_uuid_pattern(s) {
                Value::String("<uuid-redacted>".to_string())
            } else if is_email_pattern(s) {
                Value::String("<email-redacted>".to_string())
            } else if s.len() > 100 {
                // Redact long strings that might be content
                Value::String(format!("<content-redacted:{}-chars>", s.len()))
            } else {
                value.clone()
            }
        }
        Value::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (key, val) in obj {
                let sanitized_key = key.clone();

                let sanitized_val = if key.to_lowercase().contains("password")
                    || key.to_lowercase().contains("token")
                    || key.to_lowercase().contains("key")
                {
                    Value::String("<credentials-redacted>".to_string())
                } else {
                    sanitize_json_value(val)
                };

                new_obj.insert(sanitized_key, sanitized_val);
            }
            Value::Object(new_obj)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sanitize_json_value).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_sanitized_string_obfuscation(raw_str in "\\PC*") {
            let sanitized = SanitizedString::personal_info(&raw_str);
            // OWASP Sensitive Data Exposure test
            // The Display formatting MUST NOT contain the raw string (unless the string is empty or we are specifically checking length, but here the format string is static)
            let display_output = format!("{}", sanitized);
            assert_eq!(display_output, "<personal-info-redacted>");
            
            // Expose should return the original
            assert_eq!(sanitized.expose(), raw_str);
        }

        #[test]
        fn test_content_redaction_length(raw_str in "\\PC*") {
            let sanitized = SanitizedString::content(&raw_str);
            let display_output = format!("{}", sanitized);
            assert_eq!(display_output, format!("<content-redacted:{}-chars>", raw_str.len()));
        }
    }
}
