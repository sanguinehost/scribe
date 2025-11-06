use crate::{auth::user_store::Backend as AuthBackend, errors::AppError, models::users::User};
use axum_login::AuthSession;
use tracing::error;

/// Helper to get user or return error
pub fn get_user_from_session(auth_session: &AuthSession<AuthBackend>) -> Result<User, AppError> {
    auth_session.user.clone().ok_or_else(|| {
        error!("User not authenticated for lorebook operation.");
        AppError::Unauthorized("User not authenticated".to_string())
    })
}
