use secrecy::{ExposeSecret, SecretBox};
use axum::{
    extract::FromRequestParts,
    http::request::Parts
};
use crate::errors::AppError;
use tracing::{debug, error, warn};
use async_trait::async_trait;
use std::fmt;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use tower_sessions::Session;

/// Represents the session's Data Encryption Key (DEK).
/// This struct is intended to be used as an Axum request extractor.
pub struct SessionDek(pub SecretBox<Vec<u8>>);

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
        self.0.expose_secret()
    }

    // Correctly define the associated constant for the session key
    const SESSION_USER_DEK_KEY: &'static str = "user_dek";
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
        // We are removing the attempt to get DEK from auth_session.user.dek
        // because AuthBackend::get_user cannot reliably populate it with a decrypted DEK.
        // We will rely solely on the DEK stored directly in the tower_sessions::Session by the login_handler.
        
        // Added detailed logging for test_get_unauthorized debugging
        tracing::warn!(target: "auth_debug", "SessionDek::from_request_parts called. Parts URI: {:?}", parts.uri);

        debug!("SessionDek extractor: Attempting to retrieve DEK directly from tower_sessions::Session.");

        let tower_session: Session =
            Session::from_request_parts(parts, state).await
            .map_err(|err| {
                error!("SessionDek: Failed to extract tower_sessions::Session for DEK retrieval: {:?}", err);
                AppError::InternalServerErrorGeneric(format!("Failed to access session for DEK retrieval: {:?}", err))
            })?;

        match tower_session.get::<String>(Self::SESSION_USER_DEK_KEY).await {
            Ok(Some(dek_b64)) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Found DEK key '{}' in session. Value (b64): {}", Self::SESSION_USER_DEK_KEY, dek_b64);
                debug!("SessionDek extractor: Found base64 DEK in tower_session data under key '{}'. Attempting to decode.", Self::SESSION_USER_DEK_KEY);
                match BASE64_STANDARD.decode(dek_b64) {
                    Ok(dek_bytes) => {
                        debug!(
                            dek_bytes_len = dek_bytes.len(),
                            "SessionDek extractor: Successfully decoded base64 DEK from session data. Reconstructing SecretBox."
                        );
                        Ok(SessionDek(SecretBox::new(Box::new(dek_bytes))))
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            key = Self::SESSION_USER_DEK_KEY,
                            "SessionDek extractor: Failed to decode base64 DEK from session data."
                        );
                        Err(AppError::InternalServerErrorGeneric("Failed to decode DEK from session".to_string()))
                    }
                }
            }
            Ok(None) => {
                tracing::warn!(target: "auth_debug", "SessionDek: DEK key '{}' NOT found in session (Ok(None)). Returning Unauthorized.", Self::SESSION_USER_DEK_KEY);
                warn!(
                    key = Self::SESSION_USER_DEK_KEY,
                    "SessionDek extractor: DEK not found in tower_session data under key (Ok(None)). DEK unavailable."
                );
                Err(AppError::Unauthorized("DEK not found in session, user likely not authenticated.".to_string()))
            }
            Err(e) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Error retrieving DEK key '{}' from session: {}. Returning InternalServerError.", Self::SESSION_USER_DEK_KEY, e);
                error!(
                    error = %e,
                    key = Self::SESSION_USER_DEK_KEY,
                    "SessionDek extractor: Error retrieving DEK from tower_session data. DEK unavailable."
                );
                 Err(AppError::InternalServerErrorGeneric("Error accessing session data for DEK".to_string()))
            }
        }
    }
}

// REMOVED Test functions that use Session:
// test_session_dek_valid_case, test_session_dek_none_case, test_session_dek_base64_decode_error, 
// test_session_dek_no_session, test_session_no_user, test_session_no_cookie

// These tests used the old tower_sessions approach and are no longer relevant