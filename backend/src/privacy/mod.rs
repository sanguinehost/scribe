use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

pub mod examples;
pub mod logging;
pub mod middleware;

/// Configuration for privacy settings
#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    /// Salt for hashing user identifiers (should be loaded from environment)
    pub hash_salt: String,
    /// Whether to enable content redaction in logs
    pub redact_content: bool,
    /// Maximum length of content snippets to show in logs (0 = full redaction)
    pub max_content_preview: usize,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            hash_salt: std::env::var("PRIVACY_HASH_SALT")
                .unwrap_or_else(|_| "default-salt-change-in-production".to_string()),
            redact_content: true,
            max_content_preview: 0, // Full redaction by default
        }
    }
}

/// One-way hashed identifier for privacy-safe logging
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObfuscatedId {
    hash: String,
    id_type: String,
}

impl ObfuscatedId {
    /// Create an obfuscated ID from a UUID with a specific salt and type
    pub fn new(uuid: Uuid, salt: &str, id_type: &str) -> Self {
        let input = format!("{}{}{}", uuid, salt, id_type);
        let hash = blake3::hash(input.as_bytes());
        let hash_str = hash.to_hex()[..16].to_string(); // Use first 16 chars for brevity

        Self {
            hash: hash_str,
            id_type: id_type.to_string(),
        }
    }

    /// Create from user ID
    pub fn user_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "user")
    }

    /// Create from session ID  
    pub fn session_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "session")
    }

    /// Create from character ID
    pub fn character_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "character")
    }

    /// Create from persona ID
    pub fn persona_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "persona")
    }

    /// Create from chronicle ID
    pub fn chronicle_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "chronicle")
    }

    /// Create from lorebook ID
    pub fn lorebook_id(uuid: Uuid, salt: &str) -> Self {
        Self::new(uuid, salt, "lorebook")
    }
}

impl fmt::Display for ObfuscatedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.id_type, self.hash)
    }
}

/// Wrapper for sensitive string content that should be redacted in logs
#[derive(Debug, Clone)]
pub struct SanitizedString {
    content: String,
    redaction_type: RedactionType,
}

#[derive(Debug, Clone)]
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

    /// Get the raw content (for business logic, not logging)
    pub fn expose(&self) -> &str {
        &self.content
    }

    /// Get length for logging purposes
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Check if empty
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

/// Request-scoped context for privacy mappings
#[derive(Debug, Default, Clone)]
pub struct PrivacyContext {
    config: PrivacyConfig,
    request_id: String,
}

impl PrivacyContext {
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            request_id: nanoid::nanoid!(8), // Generate 8-char request ID
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn obfuscate_user_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::user_id(uuid, &self.config.hash_salt)
    }

    pub fn obfuscate_session_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::session_id(uuid, &self.config.hash_salt)
    }

    pub fn obfuscate_character_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::character_id(uuid, &self.config.hash_salt)
    }

    pub fn obfuscate_persona_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::persona_id(uuid, &self.config.hash_salt)
    }

    pub fn obfuscate_chronicle_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::chronicle_id(uuid, &self.config.hash_salt)
    }

    pub fn obfuscate_lorebook_id(&self, uuid: Uuid) -> ObfuscatedId {
        ObfuscatedId::lorebook_id(uuid, &self.config.hash_salt)
    }

    pub fn sanitize_content<S: Into<String>>(&self, content: S) -> SanitizedString {
        SanitizedString::content(content)
    }
}

/// Wrapper types for privacy-safe logging
#[derive(Debug, Clone)]
pub struct LoggableUserId(pub Uuid, pub String);

impl LoggableUserId {
    pub fn new(uuid: Uuid, salt: &str) -> Self {
        Self(uuid, salt.to_string())
    }
}

impl fmt::Display for LoggableUserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let obfuscated = ObfuscatedId::user_id(self.0, &self.1);
        write!(f, "{}", obfuscated)
    }
}

#[derive(Debug, Clone)]
pub struct LoggableSessionId(pub Uuid, pub String);

impl LoggableSessionId {
    pub fn new(uuid: Uuid, salt: &str) -> Self {
        Self(uuid, salt.to_string())
    }
}

impl fmt::Display for LoggableSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let obfuscated = ObfuscatedId::session_id(self.0, &self.1);
        write!(f, "{}", obfuscated)
    }
}

#[derive(Debug, Clone)]
pub struct LoggableCharacterId(pub Uuid, pub String);

impl LoggableCharacterId {
    pub fn new(uuid: Uuid, salt: &str) -> Self {
        Self(uuid, salt.to_string())
    }
}

impl fmt::Display for LoggableCharacterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let obfuscated = ObfuscatedId::character_id(self.0, &self.1);
        write!(f, "{}", obfuscated)
    }
}

#[derive(Debug, Clone)]
pub struct LoggablePersonaId(pub Uuid, pub String);

impl LoggablePersonaId {
    pub fn new(uuid: Uuid, salt: &str) -> Self {
        Self(uuid, salt.to_string())
    }
}

impl fmt::Display for LoggablePersonaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let obfuscated = ObfuscatedId::persona_id(self.0, &self.1);
        write!(f, "{}", obfuscated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscated_id_consistency() {
        let uuid = Uuid::new_v4();
        let salt = "test-salt";

        let id1 = ObfuscatedId::user_id(uuid, salt);
        let id2 = ObfuscatedId::user_id(uuid, salt);

        assert_eq!(
            id1, id2,
            "Same UUID and salt should produce same obfuscated ID"
        );

        let id3 = ObfuscatedId::user_id(uuid, "different-salt");
        assert_ne!(
            id1, id3,
            "Different salt should produce different obfuscated ID"
        );

        let different_uuid = Uuid::new_v4();
        let id4 = ObfuscatedId::user_id(different_uuid, salt);
        assert_ne!(
            id1, id4,
            "Different UUID should produce different obfuscated ID"
        );
    }

    #[test]
    fn test_obfuscated_id_display() {
        let uuid = Uuid::new_v4();
        let salt = "test-salt";

        let user_id = ObfuscatedId::user_id(uuid, salt);
        let session_id = ObfuscatedId::session_id(uuid, salt);

        assert!(user_id.to_string().starts_with("user#"));
        assert!(session_id.to_string().starts_with("session#"));
        assert_ne!(user_id.to_string(), session_id.to_string());
    }

    #[test]
    fn test_sanitized_string_redaction() {
        let content = "This is sensitive user content";
        let sanitized = SanitizedString::content(content);

        assert_eq!(sanitized.expose(), content);
        assert_eq!(sanitized.len(), content.len());
        assert!(sanitized.to_string().contains("<content-redacted:"));
        assert!(
            sanitized
                .to_string()
                .contains(&format!("{}-chars>", content.len()))
        );
    }
}
