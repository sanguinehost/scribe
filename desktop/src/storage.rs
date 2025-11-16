//! Unified token storage types for Tauri ↔ Frontend communication
//!
//! This module defines the canonical token storage format used across the
//! Rust (Tauri) and TypeScript (Frontend) boundary. The `StoredTokens` type
//! uses explicit serde camelCase serialization to match TypeScript conventions.

use serde::{Deserialize, Serialize};

/// Unified token storage type for secure token persistence
///
/// CRITICAL: Uses `#[serde(rename_all = "camelCase")]` to ensure TypeScript
/// compatibility. JavaScript sends `{ accessToken, refreshToken, expiresAt }`
/// and Rust fields are `{ access_token, refresh_token, expires_at }`.
///
/// This eliminates the "invalid args accessToken" error caused by snake_case/camelCase mismatch.
///
/// IMPORTANT: `expires_at` is an absolute Unix timestamp (milliseconds since epoch)
/// indicating when the access token expires. This prevents expiry calculation bugs
/// when tokens are loaded from storage after app restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTokens {
    /// JWT access token (short-lived, typically 15 minutes)
    pub access_token: String,

    /// JWT refresh token (long-lived, used to obtain new access tokens)
    pub refresh_token: String,

    /// Unix timestamp in milliseconds when access token expires
    /// This is an ABSOLUTE timestamp, not a duration
    pub expires_at: i64,
}

impl StoredTokens {
    /// Create a new StoredTokens instance
    ///
    /// # Arguments
    /// * `access_token` - JWT access token string
    /// * `refresh_token` - JWT refresh token string
    /// * `expires_at` - Unix timestamp in milliseconds when token expires
    pub fn new(access_token: String, refresh_token: String, expires_at: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_tokens_serialization() {
        let tokens = StoredTokens::new(
            "access_test_token".to_string(),
            "refresh_test_token".to_string(),
            1704067200000, // Example timestamp (milliseconds)
        );

        // Serialize to JSON (what TypeScript receives)
        let json = serde_json::to_string(&tokens).unwrap();
        println!("Serialized JSON: {}", json);

        // Verify camelCase format (TypeScript convention)
        assert!(json.contains("\"accessToken\""), "Should serialize to camelCase");
        assert!(json.contains("\"refreshToken\""), "Should serialize to camelCase");
        assert!(json.contains("\"expiresAt\""), "Should serialize to camelCase");

        // Verify no snake_case (Rust convention should be hidden)
        assert!(!json.contains("\"access_token\""), "Should not expose snake_case");
        assert!(!json.contains("\"refresh_token\""), "Should not expose snake_case");
        assert!(!json.contains("\"expires_at\""), "Should not expose snake_case");
    }

    #[test]
    fn test_stored_tokens_deserialization() {
        // TypeScript sends this format (camelCase)
        let json = r#"{
            "accessToken": "access_from_js",
            "refreshToken": "refresh_from_js",
            "expiresAt": 1704067200000
        }"#;

        let tokens: StoredTokens = serde_json::from_str(json).unwrap();

        // Verify Rust fields populated correctly
        assert_eq!(tokens.access_token, "access_from_js");
        assert_eq!(tokens.refresh_token, "refresh_from_js");
        assert_eq!(tokens.expires_at, 1704067200000);
    }

    #[test]
    fn test_stored_tokens_roundtrip() {
        let original = StoredTokens::new(
            "test_access".to_string(),
            "test_refresh".to_string(),
            1704067200000,
        );

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let roundtrip: StoredTokens = serde_json::from_str(&json).unwrap();

        // Verify data preserved
        assert_eq!(roundtrip.access_token, original.access_token);
        assert_eq!(roundtrip.refresh_token, original.refresh_token);
        assert_eq!(roundtrip.expires_at, original.expires_at);
    }
}
