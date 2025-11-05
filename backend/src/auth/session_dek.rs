use crate::auth::token_auth::UnifiedAuth;
use crate::errors::AppError;
use crate::privacy::logging::loggable_user_id;
use crate::AppState;
use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::HeaderName, request::Parts},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use tracing::{debug, warn};

/// Represents the session's Data Encryption Key (DEK).
/// This struct is intended to be used as an Axum request extractor.
pub struct SessionDek(pub SecretBox<Vec<u8>>); // Reverted to Vec<u8>

// Manual Clone implementation since Vec<u8> doesn't implement CloneableSecret
impl Clone for SessionDek {
    fn clone(&self) -> Self {
        // We expose the secret, clone the vector, and wrap it in a new SecretBox
        let dek_bytes = self.0.expose_secret().clone();
        Self(SecretBox::new(Box::new(dek_bytes)))
    }
}

impl SessionDek {
    /// Creates a new `SessionDek` from raw bytes.
    #[must_use]
    pub fn new(dek_bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(dek_bytes)))
    }

    /// Access the inner DEK bytes
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret() // Single expose
    }

    // These constants and methods are no longer needed since we don't store DEK in the session
    // They have been removed as part of the security fix
}

impl fmt::Debug for SessionDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionDek")
            .field("dek", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for SessionDek
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        const DEK_HEADER: HeaderName = HeaderName::from_static("x-scribe-dek");

        debug!("SessionDek extractor: Attempting to retrieve DEK.");

        // Extract UnifiedAuth to determine auth method and get user for session-based auth
        let auth = UnifiedAuth::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized("Authentication required".to_string()))?;

        if !auth.is_authenticated() {
            warn!("SessionDek: No authenticated user in UnifiedAuth");
            return Err(AppError::Unauthorized(
                "No authenticated user found".to_string(),
            ));
        }

        // Handle token-based authentication (desktop client)
        if auth.is_token_auth {
            debug!(
                "Auth method is token-based. Looking for DEK in '{}' header.",
                DEK_HEADER.as_str()
            );
            let header_value = parts.headers.get(&DEK_HEADER).ok_or_else(|| {
                warn!(
                    "SessionDek extractor: '{}' header missing for token auth.",
                    DEK_HEADER.as_str()
                );
                AppError::DekMissing
            })?;

            let b64_dek = header_value.to_str().map_err(|_| {
                warn!(
                    "SessionDek extractor: '{}' header contains invalid UTF-8 characters.",
                    DEK_HEADER.as_str()
                );
                AppError::DekInvalid("Header contains invalid characters".to_string())
            })?;

            let dek_bytes = STANDARD.decode(b64_dek).map_err(|e| {
                warn!(
                    "SessionDek extractor: Failed to base64-decode DEK from header: {}",
                    e
                );
                AppError::DekInvalid("Failed to decode DEK".to_string())
            })?;

            debug!("SessionDek extractor: Successfully retrieved and decoded DEK from header.");
            return Ok(SessionDek::new(dek_bytes));
        }

        // Handle session-based authentication (web client)
        debug!("Auth method is session-based. Looking for DEK in user session object.");
        let user = auth.user().unwrap(); // Safe to unwrap due to is_authenticated() check above
        let user_id = user.id;

        user.dek.as_ref().map_or_else(
            || {
                warn!(
                    user_id = %loggable_user_id(user_id),
                    "SessionDek extractor: DEK not found in user session object. User may need to log in again."
                );
                Err(AppError::DekMissing)
            },
            |dek_wrapper| {
                debug!(
                    user_id = %loggable_user_id(user_id),
                    "SessionDek extractor: Successfully retrieved DEK from user session object"
                );
                let dek_bytes_vec = dek_wrapper.expose_secret_bytes().to_vec();
                Ok(SessionDek::new(dek_bytes_vec))
            },
        )
    }
}

// REMOVED Test functions that use Session:
// test_session_dek_valid_case, test_session_dek_none_case, test_session_dek_base64_decode_error,
// test_session_dek_no_session, test_session_no_user, test_session_no_cookie

// These tests used the old tower_sessions approach and are no longer relevant
