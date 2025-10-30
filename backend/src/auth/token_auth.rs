use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use axum_login::{AuthSession, AuthnBackend, AuthzBackend};
use tower_sessions::Session;
use tracing::{debug, error, instrument, warn};

use crate::auth::{AuthError, TokenService, UserCryptoFields};
use crate::db::unified_types::DbId;
use crate::errors::AppError;
use crate::models::users::{UserRole as Role, User};
use crate::state::AppState;

/// Type alias for our specific authentication session using either cookies or tokens
pub type UnifiedAuthSession = AuthSession<crate::auth::AuthBackend>;

/// Extractor that supports both cookie-based and token-based authentication
/// This allows the same endpoints to work for both web (cookies) and desktop (tokens)
pub struct UnifiedAuth {
    pub session: UnifiedAuthSession,
    pub is_token_auth: bool,
}

impl UnifiedAuth {
    /// Check if the user is authenticated (either via cookie or token)
    pub fn is_authenticated(&self) -> bool {
        self.session.user.is_some()
    }

    /// Get the authenticated user
    pub fn user(&self) -> Option<&User> {
        self.session.user.as_ref()
    }

    /// Get the user ID if authenticated
    pub fn user_id(&self) -> Option<&DbId> {
        self.session.user.as_ref().map(|u| &u.id)
    }

    /// Get the user's role if authenticated
    pub fn role(&self) -> Option<&Role> {
        self.session.user.as_ref().map(|u| &u.role)
    }

    /// Login a user (only works for cookie-based auth)
    pub async fn login(&mut self, user: &User) -> Result<(), axum_login::Error<crate::auth::AuthBackend>>
    where
        crate::auth::AuthBackend: AuthnBackend<User = User>,
    {
        if self.is_token_auth {
            warn!("Attempted to login via token auth - this is not supported");
            return Err(axum_login::Error::Backend(AuthError::WrongCredentials));
        }
        self.session.login(user).await
    }

    /// Logout the user (only works for cookie-based auth)
    pub async fn logout(&mut self) -> Result<(), axum_login::Error<crate::auth::AuthBackend>>
    where
        crate::auth::AuthBackend: AuthnBackend,
    {
        if self.is_token_auth {
            warn!("Attempted to logout via token auth - tokens should be discarded client-side");
            return Ok(()); // Silently succeed for tokens
        }
        self.session.logout().await.map(|_| ())
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UnifiedAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    #[instrument(skip_all, name = "unified_auth_extract")]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // First, check for Bearer token in Authorization header
        if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    debug!("Found Bearer token in Authorization header");

                    // Get the app state to access token service
                    let app_state = AppState::from_ref(state);

                    // Get the token service from app state
                    let token_service = match app_state.token_service.as_ref() {
                        Some(service) => service,
                        None => {
                            error!("Token service not initialized");
                            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Token service unavailable")
                                .into_response());
                        }
                    };

                    // Validate the token
                    match token_service.validate_token(token) {
                        Ok(claims) => {
                            debug!(?claims.sub, "Token validated successfully");

                            // Load the user from the database
                            let pool = app_state.pool.clone();
                            let user_id = claims.sub.clone();

                            let user = match crate::db::with_conn(&pool, move |conn| {
                                crate::auth::get_user(conn, user_id)
                                    .map_err(AppError::from)
                            }).await {
                                Ok(user) => user,
                                Err(e) => {
                                    error!(?e, "Failed to load user for token auth");
                                    return Err((StatusCode::UNAUTHORIZED, "Invalid token")
                                        .into_response());
                                }
                            };

                            // Create a minimal session for token auth
                            // Note: This bypasses the normal session flow but maintains compatibility
                            let mut auth_session = UnifiedAuthSession::from_request_parts(parts, state)
                                .await
                                .map_err(|_| {
                                    (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create auth session")
                                        .into_response()
                                })?;

                            // Set the user in the session (in-memory only, not persisted)
                            auth_session.user = Some(user);

                            return Ok(UnifiedAuth {
                                session: auth_session,
                                is_token_auth: true,
                            });
                        }
                        Err(e) => {
                            debug!(?e, "Token validation failed");
                            // Fall through to cookie auth
                        }
                    }
                }
            }
        }

        // Fall back to cookie-based authentication
        debug!("Falling back to cookie-based authentication");
        let auth_session = UnifiedAuthSession::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                error!(?e, "Failed to extract auth session");
                (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
            })?;

        Ok(UnifiedAuth {
            session: auth_session,
            is_token_auth: false,
        })
    }
}

// Re-export for convenience
pub use UnifiedAuth as CurrentAuth;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_auth_methods() {
        let auth = UnifiedAuth {
            session: UnifiedAuthSession {
                user: None,
                backend: std::marker::PhantomData,
                _session_data_type: std::marker::PhantomData,
            },
            is_token_auth: false,
        };

        assert!(!auth.is_authenticated());
        assert!(auth.user().is_none());
        assert!(auth.user_id().is_none());
        assert!(auth.role().is_none());
    }
}