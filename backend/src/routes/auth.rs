use crate::auth::{create_user, AuthError};
use crate::errors::AppError;
use crate::models::users::UserCredentials;
use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Json};
use axum::http::StatusCode;
use axum_login::{AuthSession, AuthUser, AuthnBackend};
use serde_json::json;
use tracing::{debug, error, info, instrument};
use anyhow::anyhow;

type CurrentAuthSession = AuthSession<AppState>;

#[instrument(skip(state, credentials), err)]
pub async fn register_handler(
    State(state): State<AppState>,
    Json(credentials): Json<UserCredentials>,
) -> Result<impl IntoResponse, AppError> {
    info!(username = %credentials.username, "Registering user");

    let pool = state.pool.clone();
    let username = credentials.username.clone();
    let password = credentials.password.clone();

    match pool.get().await {
        Ok(conn) => {
            let user_result = conn.interact(move |conn| create_user(conn, username, password)).await;

            match user_result {
                Ok(inner_result) => {
                    match inner_result {
                        Ok(user) => {
                            info!(username = %user.username, user_id = %user.id, "User registered successfully");
                            Ok((StatusCode::CREATED, Json(user)).into_response())
                        }
                        Err(AuthError::UsernameTaken) => Err(AppError::UsernameTaken),
                        Err(AuthError::HashingError) => Err(AppError::InternalServerError(anyhow::anyhow!("Password hashing failed during registration"))),
                        Err(AuthError::DatabaseError(e)) => Err(AppError::DatabaseError(e)),
                        Err(e) => {
                            error!("Unknown AuthError during registration: {:?}", e);
                            Err(AppError::InternalServerError(anyhow!("An unexpected authentication error occurred.")))
                        }
                    }
                }
                Err(interact_err) => {
                    error!("Interact error during user creation: {}", interact_err);
                    Err(AppError::InternalServerError(anyhow!(interact_err.to_string())))
                }
            }
        }
        Err(pool_err) => {
            error!("Failed to get DB connection for registration: {}", pool_err);
            Err(AppError::DbPoolError(pool_err))
        }
    }
}

#[instrument(skip(state, auth_session, credentials), err)]
pub async fn login_handler(
    State(state): State<AppState>,
    mut auth_session: CurrentAuthSession,
    Json(credentials): Json<UserCredentials>,
) -> Result<Response, AppError> {
    let username = credentials.username.clone();
    info!(%username, "Attempting login");

    match state.authenticate(credentials).await {
        Ok(Some(user)) => {
            let user_id = user.id;
            let username = user.username.clone();
            if let Err(e) = auth_session.login(&user).await {
                error!(error = ?e, "Failed to log user in after authentication");
                return Err(AppError::InternalServerError(anyhow::anyhow!(
                    "Session login failed: {}",
                    e
                )));
            }
            info!(%username, %user_id, "Login successful");
            Ok((StatusCode::OK, Json(user)).into_response())
        }
        Ok(None) => {
            info!(%username, "Login failed: Invalid credentials");
            Err(AppError::InvalidCredentials)
        }
        Err(e) => {
            error!(%username, error = ?e, "Login failed: Authentication error");
            Err(e)
        }
    }
}

#[instrument(skip(auth_session), err)]
pub async fn logout_handler(mut auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    if let Some(user) = auth_session.user.clone() {
        info!(user_id = %user.id(), "Logging out user");
    } else {
        debug!("Logout called, but no user session found");
    }

    if auth_session.logout().await.is_err() {
        error!("Failed to destroy session during logout");
    }

    Ok((StatusCode::OK, Json(json!({ "message": "Logout successful" }))).into_response())
}

#[instrument(skip(auth_session), err)]
pub async fn me_handler(auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    match auth_session.user {
        Some(user) => {
            info!(username = %user.username, user_id = %user.id, "Returning current user data");
            Ok(Json(user).into_response())
        }
        None => {
            info!("No authenticated user found in session");
            Err(AppError::Unauthorized)
        }
    }
} 