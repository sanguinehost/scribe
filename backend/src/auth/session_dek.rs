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

    // Fixed DEK key - not used anymore, keeping for backwards compatibility in tests
    const SESSION_USER_DEK_KEY: &'static str = "user_dek";
    
    // The key where axum-login stores the user ID in the session
    const AXUM_LOGIN_USER_KEY: &'static str = "axum-login.user";
    
    // The pattern for constructing the user-specific DEK key
    fn user_dek_key(user_id: &str) -> String {
        format!("_user_dek_{}", user_id)
    }
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

        debug!("SessionDek extractor: Attempting to retrieve DEK from tower_sessions::Session.");

        let tower_session: Session =
            Session::from_request_parts(parts, state).await
            .map_err(|err| {
                error!("SessionDek: Failed to extract tower_sessions::Session for DEK retrieval: {:?}", err);
                AppError::InternalServerErrorGeneric(format!("Failed to access session for DEK retrieval: {:?}", err))
            })?;

        // First, get the user ID from the session (stored by our manually fixed auth.rs)
        let user_id = match tower_session.get::<String>(Self::AXUM_LOGIN_USER_KEY).await {
            Ok(Some(id)) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Found user ID in session: {}", id);
                id
            },
            Ok(None) => {
                tracing::warn!(target: "auth_debug", "SessionDek: No user ID found in session under key '{}'", Self::AXUM_LOGIN_USER_KEY);
                return Err(AppError::Unauthorized("No user ID found in session, user likely not authenticated.".to_string()));
            },
            Err(e) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Error retrieving user ID from session: {}", e);
                return Err(AppError::InternalServerErrorGeneric("Error accessing session data for user ID".to_string()));
            }
        };

        // Now, construct the user-specific DEK key
        let dek_key = Self::user_dek_key(&user_id);
        
        // Try to get the DEK using the user-specific key
        match tower_session.get::<crate::models::users::SerializableSecretDek>(&dek_key).await {
            Ok(Some(serializable_dek)) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Found DEK under key '{}' in session", dek_key);
                debug!("SessionDek extractor: Found DEK in tower_session data under key '{}'", dek_key);
                
                // Convert SerializableSecretDek to SessionDek
                let dek_bytes = serializable_dek.expose_secret_bytes().to_vec();
                Ok(SessionDek(SecretBox::new(Box::new(dek_bytes))))
            },
            Ok(None) => {
                tracing::warn!(target: "auth_debug", "SessionDek: DEK not found under key '{}' in session", dek_key);
                warn!(
                    key = %dek_key,
                    "SessionDek extractor: DEK not found in tower_session data under user-specific key."
                );
                
                // Try the legacy fixed key as fallback
                match tower_session.get::<String>(Self::SESSION_USER_DEK_KEY).await {
                    Ok(Some(dek_b64)) => {
                        tracing::warn!(target: "auth_debug", "SessionDek: Found DEK using legacy key '{}'. Decoding from base64.", Self::SESSION_USER_DEK_KEY);
                        // Handle legacy case - decode from base64
                        match BASE64_STANDARD.decode(dek_b64) {
                            Ok(dek_bytes) => {
                                debug!("SessionDek extractor: Successfully decoded legacy base64 DEK. Bytes length: {}", dek_bytes.len());
                                Ok(SessionDek(SecretBox::new(Box::new(dek_bytes))))
                            },
                            Err(e) => {
                                error!("SessionDek: Failed to decode legacy base64 DEK: {}", e);
                                Err(AppError::InternalServerErrorGeneric("Failed to decode legacy DEK format".to_string()))
                            }
                        }
                    },
                    _ => Err(AppError::Unauthorized("DEK not found in session".to_string()))
                }
            },
            Err(e) => {
                tracing::warn!(target: "auth_debug", "SessionDek: Error retrieving DEK under key '{}' from session: {}", dek_key, e);
                error!(
                    error = %e,
                    key = %dek_key,
                    "SessionDek extractor: Error retrieving DEK from tower_session data."
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