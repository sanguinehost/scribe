use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts};
use axum_login::AuthSession;
use secrecy::{ExposeSecret, SecretBox}; // Removed SecretVec
use std::fmt;
use tracing::{debug, error, warn};

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
    /// Creates a new SessionDek from raw bytes.
    pub fn new(dek_bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(dek_bytes)))
    }

    /// Access the inner DEK bytes
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
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Added detailed logging for test_get_unauthorized debugging
        tracing::warn!(target: "auth_debug", "SessionDek::from_request_parts called. Parts URI: {:?}", parts.uri);

        debug!("SessionDek extractor: Attempting to retrieve DEK from user object.");

        // Extract the AuthSession to get the authenticated user
        let auth_session: AuthSession<AuthBackend> = AuthSession::from_request_parts(parts, state)
            .await
            .map_err(|err| {
                error!("SessionDek: Failed to extract AuthSession: {:?}", err);
                AppError::Unauthorized("Failed to extract auth session".to_string())
            })?;

        // Get the authenticated user
        let user = auth_session.user.ok_or_else(|| {
            tracing::warn!(target: "auth_debug", "SessionDek: No authenticated user in AuthSession");
            AppError::Unauthorized("No authenticated user found".to_string())
        })?;

        let user_id = user.id;
        tracing::warn!(target: "auth_debug", "SessionDek: Found authenticated user with ID: {}", user_id);

        // The AuthBackend's get_user method populates the DEK from cache
        // So if the user has a DEK, it should be present in the user object
        match user.dek {
            Some(dek_wrapper) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Found DEK in user object for user_id: {}", user_id);
                debug!(
                    "SessionDek extractor: Successfully retrieved DEK from user object for user_id: {}",
                    user_id
                );

                // Convert SerializableSecretDek to SessionDek
                let dek_bytes_vec = dek_wrapper.expose_secret_bytes().to_vec();
                Ok(SessionDek(SecretBox::new(Box::new(dek_bytes_vec))))
            }
            None => {
                tracing::warn!(target: "auth_debug", "SessionDek: DEK not found in user object for user_id: {}", user_id);
                warn!(
                    user_id = %user_id,
                    "SessionDek extractor: DEK not found in user object. User may need to log in again."
                );

                Err(AppError::Unauthorized(
                    "DEK not found. Please log in again.".to_string(),
                ))
            }
        }
    }
}

// REMOVED Test functions that use Session:
// test_session_dek_valid_case, test_session_dek_none_case, test_session_dek_base64_decode_error,
// test_session_dek_no_session, test_session_no_user, test_session_no_cookie

// These tests used the old tower_sessions approach and are no longer relevant
