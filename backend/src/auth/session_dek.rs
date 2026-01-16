use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::privacy::logging::loggable_user_id;
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{header::HeaderName, request::Parts},
};
use axum_login::AuthSession;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use tracing::{error, info, warn};

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
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        const DEK_HEADER: HeaderName = HeaderName::from_static("x-scribe-dek");

        info!(
            "SessionDek extractor: Attempting to retrieve DEK. Headers: {:?}",
            parts.headers.keys().collect::<Vec<_>>()
        );

        // Step 1: Check for X-Scribe-Dek header (JWT desktop mode)
        if let Some(dek_header) = parts.headers.get(&DEK_HEADER) {
            info!(
                "SessionDek extractor: Found {} header (JWT desktop mode)",
                DEK_HEADER.as_str()
            );

            let dek_b64 = dek_header.to_str().map_err(|e| {
                warn!(
                    "SessionDek extractor: {} header contains invalid UTF-8: {}",
                    DEK_HEADER.as_str(),
                    e
                );
                AppError::BadRequest("DEK header contains invalid UTF-8 characters".to_string())
            })?;

            let dek_bytes = STANDARD.decode(dek_b64).map_err(|e| {
                warn!(
                    "SessionDek extractor: Failed to base64-decode DEK from header: {}",
                    e
                );
                AppError::BadRequest("Failed to decode DEK from header".to_string())
            })?;

            info!(
                "SessionDek extractor: Successfully retrieved and decoded DEK from {} header (length: {} bytes)",
                DEK_HEADER.as_str(),
                dek_bytes.len()
            );
            return Ok(SessionDek::new(dek_bytes));
        }

        // Step 2: Fallback to cookie session (web mode)
        info!("SessionDek extractor: No DEK header found, falling back to cookie session");

        // Extract the AuthSession to get the authenticated user
        let auth_session: AuthSession<AuthBackend> = AuthSession::from_request_parts(parts, state)
            .await
            .map_err(|err| {
                error!("SessionDek: Failed to extract AuthSession: {:?}", err);
                AppError::Unauthorized("Failed to extract auth session".to_string())
            })?;

        // Get the authenticated user
        let user = auth_session.user.ok_or_else(|| {
            warn!("SessionDek: No authenticated user in AuthSession");
            AppError::Unauthorized("No authenticated user found".to_string())
        })?;

        let user_id = user.id;
        info!(
            "SessionDek extractor: Found authenticated user with ID: {}",
            loggable_user_id(user_id)
        );

        // The AuthBackend's get_user method populates the DEK from cache
        // So if the user has a DEK, it should be present in the user object
        user.dek.map_or_else(
            || {
                warn!(
                    user_id = %loggable_user_id(user_id),
                    "SessionDek extractor: DEK not found in user session object. User may need to log in again."
                );
                Err(AppError::DekMissing)
            },
            |dek_wrapper| {
                info!(
                    user_id = %loggable_user_id(user_id),
                    "SessionDek extractor: Successfully retrieved DEK from user session object"
                );

                // Convert SerializableSecretDek to SessionDek
                let dek_bytes_vec = dek_wrapper.expose_secret_bytes().to_vec();
                Ok(Self(SecretBox::new(Box::new(dek_bytes_vec))))
            },
        )
    }
}

// REMOVED Test functions that use Session:
// test_session_dek_valid_case, test_session_dek_none_case, test_session_dek_base64_decode_error,
// test_session_dek_no_session, test_session_no_user, test_session_no_cookie

// These tests used the old tower_sessions approach and are no longer relevant
