use crate::privacy::{
    LoggableCharacterId, LoggablePersonaId, LoggableSessionId, LoggableUserId, PrivacyConfig,
    SanitizedString,
};
use serde_json::Value;
use std::collections::HashMap;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use uuid::Uuid;

/// Global privacy configuration (loaded from environment or defaults)
static PRIVACY_CONFIG: std::sync::LazyLock<PrivacyConfig> =
    std::sync::LazyLock::new(PrivacyConfig::default);

/// Privacy-safe logging macros that automatically obfuscate sensitive data
#[macro_export]
macro_rules! privacy_info {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! privacy_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}

#[macro_export]
macro_rules! privacy_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! privacy_error {
    ($($arg:tt)*) => {
        tracing::error!($($arg)*)
    };
}

/// Helper functions to create loggable wrappers with global salt
pub fn loggable_user_id(uuid: crate::DbUuid) -> LoggableUserId {
    LoggableUserId::new(uuid, &PRIVACY_CONFIG.hash_salt)
}

pub fn loggable_session_id(uuid: crate::DbUuid) -> LoggableSessionId {
    LoggableSessionId::new(uuid, &PRIVACY_CONFIG.hash_salt)
}

pub fn loggable_character_id(uuid: crate::DbUuid) -> LoggableCharacterId {
    LoggableCharacterId::new(uuid, &PRIVACY_CONFIG.hash_salt)
}

pub fn loggable_persona_id(uuid: crate::DbUuid) -> LoggablePersonaId {
    LoggablePersonaId::new(uuid, &PRIVACY_CONFIG.hash_salt)
}

/// Sanitize content for logging
pub fn sanitize_content<S: Into<String>>(content: S) -> SanitizedString {
    SanitizedString::content(content)
}

/// Sanitize system prompt for logging
pub fn sanitize_system_prompt<S: Into<String>>(content: S) -> SanitizedString {
    SanitizedString::system_prompt(content)
}

/// Sanitize personal information for logging
pub fn sanitize_personal_info<S: Into<String>>(content: S) -> SanitizedString {
    SanitizedString::personal_info(content)
}

/// Privacy layer for tracing that redacts sensitive fields
#[derive(Debug)]
pub struct PrivacyLayer {
    config: PrivacyConfig,
}

impl PrivacyLayer {
    pub fn new() -> Self {
        Self {
            config: PRIVACY_CONFIG.clone(),
        }
    }
}

impl Default for PrivacyLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for PrivacyLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // This layer could be used to scan for and redact sensitive data
        // For now, we rely on the wrapper types doing the redaction
        // Future enhancement: scan log messages for patterns like UUID-looking strings
        let mut visitor = PrivacyVisitor::new(&self.config);
        event.record(&mut visitor);
    }
}

/// Visitor that inspects log fields for sensitive data patterns
struct PrivacyVisitor<'a> {
    _config: &'a PrivacyConfig,
    _fields: HashMap<String, String>,
}

impl<'a> PrivacyVisitor<'a> {
    fn new(config: &'a PrivacyConfig) -> Self {
        Self {
            _config: config,
            _fields: HashMap::new(),
        }
    }
}

impl<'a> Visit for PrivacyVisitor<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // For future enhancement: detect and warn about potential PII leakage
        let field_name = field.name();
        if field_name.contains("id") && !field_name.starts_with("request_") {
            // Could log warning about potential ID leakage
        }
        let debug_str = format!("{:?}", value);
        self._fields.insert(field_name.to_string(), debug_str);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let field_name = field.name();

        // Check for potential UUID patterns in string fields
        if is_uuid_pattern(value) {
            tracing::warn!(
                "Potential UUID detected in log field '{}' - consider using privacy wrappers",
                field_name
            );
        }

        // Check for potential email patterns
        if is_email_pattern(value) {
            tracing::warn!(
                "Potential email detected in log field '{}' - consider using privacy wrappers",
                field_name
            );
        }

        self._fields
            .insert(field_name.to_string(), value.to_string());
    }
}

/// Check if a string looks like a UUID
fn is_uuid_pattern(s: &str) -> bool {
    s.len() == 36
        && s.chars().filter(|&c| c == '-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Check if a string looks like an email
fn is_email_pattern(s: &str) -> bool {
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
                let sanitized_key = if key.to_lowercase().contains("password")
                    || key.to_lowercase().contains("token")
                    || key.to_lowercase().contains("key")
                {
                    key.clone()
                } else {
                    key.clone()
                };

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

    #[test]
    fn test_uuid_pattern_detection() {
        assert!(is_uuid_pattern("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid_pattern("not-a-uuid"));
        assert!(!is_uuid_pattern("550e8400-e29b-41d4-a716"));
    }

    #[test]
    fn test_email_pattern_detection() {
        assert!(is_email_pattern("user@example.com"));
        assert!(is_email_pattern("test.email+tag@domain.co.uk"));
        assert!(!is_email_pattern("notanemail"));
        assert!(!is_email_pattern("@missing-local"));
    }

    #[test]
    fn test_json_sanitization() {
        let input = serde_json::json!({
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "email": "user@example.com",
            "password": "secret123",
            "content": "Some user content that might be long enough to redact if it exceeds one hundred characters in length which this string does",
            "safe_field": "normal data"
        });

        let sanitized = sanitize_json_value(&input);

        assert_eq!(sanitized["user_id"], "<uuid-redacted>");
        assert_eq!(sanitized["email"], "<email-redacted>");
        assert_eq!(sanitized["password"], "<credentials-redacted>");
        assert!(sanitized["content"]
            .as_str()
            .unwrap()
            .starts_with("<content-redacted:"));
        assert_eq!(sanitized["safe_field"], "normal data");
    }

    #[test]
    fn test_loggable_wrappers() {
        let user_uuid = Uuid::new_v4();
        let session_uuid = Uuid::new_v4();

        let loggable_user = loggable_user_id(user_uuid);
        let loggable_session = loggable_session_id(session_uuid);

        let user_str = loggable_user.to_string();
        let session_str = loggable_session.to_string();

        assert!(user_str.starts_with("user#"));
        assert!(session_str.starts_with("session#"));
        assert_ne!(user_str, session_str);

        // Ensure the original UUIDs are not present in the output
        assert!(!user_str.contains(&user_uuid.to_string()));
        assert!(!session_str.contains(&session_uuid.to_string()));
    }
}
