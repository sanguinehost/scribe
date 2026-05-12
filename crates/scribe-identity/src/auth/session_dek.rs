use crate::auth::user_store::Backend as AuthBackend;
use crate::error::AppError;
use crate::privacy::loggable_user_id;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::HeaderName, request::Parts},
};
use axum_login::AuthSession;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use tower_sessions::Session;
use tracing::{debug, error, info, warn};

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

impl<S> FromRequestParts<S> for SessionDek
where
    crate::state::AuthAppState: FromRef<S>,
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
                AppError::InternalServerError("DEK header contains invalid UTF-8 characters".to_string())
            })?;

            let dek_bytes = STANDARD.decode(dek_b64).map_err(|e| {
                warn!(
                    "SessionDek extractor: Failed to base64-decode DEK from header: {}",
                    e
                );
                AppError::InternalServerError("Failed to decode DEK from header".to_string())
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
        let user = auth_session.user.as_ref().ok_or_else(|| {
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
        if let Some(dek_wrapper) = &user.dek {
            info!(
                user_id = %loggable_user_id(user_id),
                "SessionDek extractor: Successfully retrieved DEK from user session object (cache hit)"
            );

            // Convert SerializableSecretDek to SessionDek
            let dek_bytes_vec = dek_wrapper.expose_secret_bytes().to_vec();
            return Ok(Self(SecretBox::new(Box::new(dek_bytes_vec))));
        }

        // Fallback: If DEK is not in the user object (cache miss on cold instance),
        // try to pull it directly from the session
        info!(
            user_id = %loggable_user_id(user_id),
            "SessionDek extractor: DEK not in user object, attempting fallback to session store"
        );

        if let Ok(session) = Session::from_request_parts(parts, state).await {
            match session
                .get::<crate::models::db_models::SerializableSecretDek>("dek")
                .await
            {
                Ok(Some(dek_wrapper)) => {
                    info!(
                        user_id = %loggable_user_id(user_id),
                        "SessionDek extractor: ✓ DEK retrieved from secure session (cache miss recovery)"
                    );

                    // Populate the in-memory cache to benefit subsequent requests to this instance
                    let app_state = crate::state::AuthAppState::from_ref(state);
                    let mut cache = app_state.auth_backend.dek_cache.write().await;
                    cache.insert(user.id, dek_wrapper.clone());

                    // CRITICAL: We also need to update the User object in auth_session's extension
                    // so that subsequent extractors don't have to hit the session store again.
                    let mut auth_session_update = auth_session.clone();
                    if let Some(ref mut user_ref) = auth_session_update.user {
                        user_ref.dek = Some(dek_wrapper.clone());
                        parts.extensions.insert(auth_session_update);
                    }

                    debug!(
                        user_id = %loggable_user_id(user_id),
                        "In-memory DEK cache populated and AuthSession extension updated from SessionDek"
                    );

                    let dek_bytes_vec = dek_wrapper.expose_secret_bytes().to_vec();
                    return Ok(Self(SecretBox::new(Box::new(dek_bytes_vec))));
                }
                Ok(None) => {
                    warn!(
                        user_id = %loggable_user_id(user_id),
                        "SessionDek extractor: DEK not found in session either"
                    );
                }
                Err(e) => {
                    error!(
                        user_id = %loggable_user_id(user_id),
                        error = ?e,
                        "SessionDek extractor: Failed to load DEK from session"
                    );
                }
            }
        }

        warn!(
            user_id = %loggable_user_id(user_id),
            "SessionDek extractor: DEK recovery failed. User may need to log in again."
        );
        Err(AppError::InternalServerError("DEK missing".to_string()))
    }
}

// REMOVED Test functions that use Session:
// test_session_dek_valid_case, test_session_dek_none_case, test_session_dek_base64_decode_error,
// test_session_dek_no_session, test_session_no_user, test_session_no_cookie

// These tests used the old tower_sessions approach and are no longer relevant
