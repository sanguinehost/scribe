use serde::{Deserialize, Serialize};
use std::fmt;

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
