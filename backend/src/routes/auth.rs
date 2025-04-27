use crate::auth::{AuthError, create_user};
use crate::errors::AppError;
use crate::models::users::UserCredentials;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_login::{AuthSession, AuthUser};
use secrecy::{/* ExposeSecret, */ Secret};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};

use crate::auth::user_store::Backend as AuthBackend;
type CurrentAuthSession = AuthSession<AuthBackend>;

#[instrument(skip(state, credentials), err)]
pub async fn register_handler(
    State(state): State<AppState>,
    Json(credentials): Json<UserCredentials>,
) -> Result<impl IntoResponse, AppError> {
    info!(username = %credentials.username, "Register handler entered");

    let pool = state.pool.clone();
    let username = credentials.username.clone();
    let password = credentials.password.clone();

    // Hash the password asynchronously
    let password_hash = crate::auth::hash_password(password).await?;

    debug!(username = %username, "Attempting to get DB connection from pool for registration...");
    match pool.get().await {
        Ok(conn) => {
            debug!(username = %username, "Got DB connection. Calling interact for create_user...");
            let user_result = conn
                .interact(move |conn| create_user(conn, username, Secret::new(password_hash)))
                .await;

            match user_result {
                Ok(inner_result) => {
                    debug!(username = %credentials.username, "Interact for create_user completed.");
                    match inner_result {
                        Ok(user) => {
                            info!(username = %user.username, user_id = %user.id, "User registration successful.");
                            Ok((StatusCode::CREATED, Json(user)).into_response())
                        }
                        Err(AuthError::UsernameTaken) => {
                            warn!(username = %credentials.username, "Registration failed: Username taken.");
                            Err(AppError::UsernameTaken)
                        }
                        Err(AuthError::HashingError) => {
                            error!(username = %credentials.username, "Registration failed: Password hashing error.");
                            Err(AppError::InternalServerError(
                                "Password hashing failed during registration".to_string(),
                            ))
                        }
                        Err(AuthError::DatabaseError(e)) => {
                            error!(username = %credentials.username, error = ?e, "Registration failed: Database error.");
                            Err(AppError::DatabaseQueryError(e))
                        }
                        Err(e) => {
                            error!(username = %credentials.username, error = ?e, "Registration failed: Unknown AuthError.");
                            Err(AppError::InternalServerError(
                                "An unexpected authentication error occurred.".to_string(),
                            ))
                        }
                    }
                }
                Err(interact_err) => {
                    error!(username = %credentials.username, error = ?interact_err, "Interact error during user creation");
                    Err(AppError::InternalServerError(interact_err.to_string()))
                }
            }
        }
        Err(pool_err) => {
            error!(username = %credentials.username, error = ?pool_err, "Failed to get DB connection for registration");
            Err(AppError::DbPoolError(pool_err.to_string()))
        }
    }
}

#[instrument(skip(auth_session, credentials), err)]
pub async fn login_handler(
    mut auth_session: CurrentAuthSession,
    Json(credentials): Json<UserCredentials>,
) -> Result<Response, AppError> {
    let username = credentials.username.clone();
    info!(%username, "Attempting login");

    info!("Calling auth_session.authenticate...");
    tracing::debug!(username=%username, ">>> BEFORE auth_session.authenticate().await");
    match auth_session.authenticate(credentials).await {
        Ok(Some(user)) => {
            let user_id = user.id; // Capture for logging
            let username = user.username.clone(); // Capture for logging
            info!(%username, %user_id, "Authentication successful, attempting explicit login...");
            if let Err(e) = auth_session.login(&user).await {
                error!(error = ?e, %username, %user_id, "Explicit auth_session.login failed after successful authentication");
                return Err(AppError::InternalServerError(format!(
                    "Session login failed: {}",
                    e
                )));
            }
            info!(%username, %user_id, "Explicit auth_session.login successful");
            Ok((StatusCode::OK, Json(user)).into_response())
        }
        Ok(None) => Err(AppError::Unauthorized(
            "Invalid username or password".to_string(),
        )),
        Err(e) => Err(AppError::InternalServerError(format!(
            "An unexpected authentication error occurred: {}",
            e
        ))),
    }
}

#[instrument(skip(auth_session), err)]
pub async fn logout_handler(mut auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    info!("Logout handler entered.");
    if let Some(user) = &auth_session.user {
        info!(user_id = %user.id(), username = %user.username, "Attempting to log out user.");
    } else {
        debug!("Logout called, but no user session found in request.");
    }

    debug!("Calling auth_session.logout().await...");
    if let Err(e) = auth_session.logout().await {
        error!(error = ?e, "Failed to destroy session during logout via auth_session.logout()");
        return Err(AppError::InternalServerError(format!(
            "Failed to clear session during logout: {}",
            e
        )));
    }
    info!("Logout process completed (session cleared if existed).");

    Ok((
        StatusCode::OK,
        Json(json!({ "message": "Logout successful" })),
    )
        .into_response())
}

#[instrument(skip(auth_session), err)]
pub async fn me_handler(auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    info!("Me handler entered.");
    match auth_session.user {
        Some(user) => {
            info!(username = %user.username, user_id = %user.id, "Returning current user data for /me endpoint.");
            Ok(Json(user).into_response())
        }
        None => {
            info!("No authenticated user found in session for /me endpoint.");
            Err(AppError::Unauthorized("Not logged in".to_string()))
        }
    }
}
