use crate::auth::{AuthError, create_user};
use crate::errors::AppError;
use crate::models::auth::{AuthResponse, LoginPayload, RegisterPayload}; // Updated imports
use crate::state::AppState;
use axum::Json;
// Removed: use validator::Validate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_login::{AuthSession, AuthUser};
use secrecy::{/* ExposeSecret, */ Secret};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};

use crate::auth::user_store::Backend as AuthBackend;
type CurrentAuthSession = AuthSession<AuthBackend>;

use crate::schema::sessions;
use crate::schema::users::{self}; // Import users table (dsl::* is unused)
use crate::models::users::User; // Added model import
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper}; // Added RunQueryDsl and SelectableHelper
use axum::{
    extract::Path,
};
// Removed: use axum_login::tower_sessions::Session;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use axum::Router;
use axum::routing::{post, get, delete};

#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionWithUserResponse {
    pub session: SessionResponse,
    pub user: AuthResponse, // Renamed UserResponse to AuthResponse
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[instrument(skip(state, payload), err)]
pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterPayload>, // Use RegisterPayload
) -> Result<impl IntoResponse, AppError> {
    info!(username = %payload.username, email = %payload.email, "Register handler entered");

    // Validate the payload
    if let Err(validation_errors) = payload.validate() {
        error!(errors = ?validation_errors, "Registration payload validation failed.");
        return Err(AppError::ValidationError(validation_errors.to_string()));
    }

    let pool = state.pool.clone();
    let reg_username = payload.username.clone(); // Renamed to avoid shadowing schema item
    let reg_email = payload.email.clone(); // Renamed to avoid shadowing schema item
    let password = payload.password.clone();

    // Hash the password asynchronously
    let pwd_hash = crate::auth::hash_password(password).await?;

    debug!(username = %reg_username, email = %reg_email, "Attempting to get DB connection from pool for registration..."); // Use renamed vars
    match pool.get().await {
        Ok(conn) => {
            debug!(username = %reg_username, email = %reg_email, "Got DB connection. Calling interact for create_user..."); // Use renamed vars
            // Pass email to create_user
            let user_result = conn
                .interact(move |conn| create_user(conn, reg_username, reg_email, Secret::new(pwd_hash))) // Use renamed vars
                .await;

            match user_result {
                Ok(inner_result) => {
                    debug!(username = %payload.username, email = %payload.email, "Interact for create_user completed.");
                    match inner_result {
                        Ok(user) => {
                            info!(username = %user.username, email = %user.email, user_id = %user.id, "User registration successful.");
                            // Use AuthResponse for success
                            let response = AuthResponse {
                                user_id: user.id,
                                username: user.username,
                                email: user.email,
                            };
                            Ok((StatusCode::CREATED, Json(response)).into_response())
                        }
                        Err(AuthError::UsernameTaken) => {
                            warn!(username = %payload.username, "Registration failed: Username taken.");
                            Err(AppError::UsernameTaken)
                        }
                        Err(AuthError::EmailTaken) => { // Handle EmailTaken error
                            warn!(email = %payload.email, "Registration failed: Email taken.");
                            Err(AppError::EmailTaken)
                        }
                        Err(AuthError::HashingError) => {
                            error!(username = %payload.username, email = %payload.email, "Registration failed: Password hashing error.");
                            Err(AppError::InternalServerError(
                                "Password hashing failed during registration".to_string(),
                            ))
                        }
                        Err(AuthError::DatabaseError(e)) => {
                            error!(username = %payload.username, email = %payload.email, error = ?e, "Registration failed: Database error.");
                            Err(AppError::DatabaseQueryError(e))
                        }
                        Err(e) => {
                            error!(username = %payload.username, email = %payload.email, error = ?e, "Registration failed: Unknown AuthError.");
                            Err(AppError::InternalServerError(
                                "An unexpected authentication error occurred.".to_string(),
                            ))
                        }
                    }
                }
                Err(interact_err) => {
                    error!(username = %payload.username, email = %payload.email, error = ?interact_err, "Interact error during user creation");
                    Err(AppError::InternalServerError(interact_err.to_string()))
                }
            }
        }
        Err(pool_err) => {
            error!(username = %payload.username, email = %payload.email, error = ?pool_err, "Failed to get DB connection for registration");
            Err(AppError::DbPoolError(pool_err.to_string()))
        }
    }
}

#[instrument(skip(auth_session, payload), err)]
pub async fn login_handler(
    mut auth_session: CurrentAuthSession,
    Json(payload): Json<LoginPayload>, // Use LoginPayload
) -> Result<Response, AppError> {
    let identifier = payload.identifier.clone();
    info!(%identifier, "Attempting login");

    // The `authenticate` method in `AuthBackend` will handle
    // checking both username and email.
    info!("Calling auth_session.authenticate...");
    tracing::debug!(identifier=%identifier, ">>> BEFORE auth_session.authenticate().await");
    match auth_session.authenticate(payload).await { // Pass the LoginPayload
        Ok(Some(user)) => {
            let user_id = user.id; // Capture for logging
            let login_username = user.username.clone(); // Renamed to avoid shadowing
            let login_email = user.email.clone(); // Renamed to avoid shadowing
            info!(username = %login_username, email = %login_email, %user_id, "Authentication successful, attempting explicit login..."); // Use renamed vars
            if let Err(e) = auth_session.login(&user).await {
                error!(error = ?e, username = %login_username, email = %login_email, %user_id, "Explicit auth_session.login failed after successful authentication"); // Use renamed vars
                return Err(AppError::InternalServerError(format!(
                    "Session login failed: {}",
                    e
                )));
            }
            info!(username = %login_username, email = %login_email, %user_id, "Explicit auth_session.login successful"); // Use renamed vars
            // Use AuthResponse for success
            let response = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
            };
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        Ok(None) => Err(AppError::Unauthorized(
            "Invalid identifier or password".to_string(), // Updated error message
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
            info!(username = %user.username, email = %user.email, user_id = %user.id, "Returning current user data for /me endpoint.");
            // Use AuthResponse for consistency
            let response = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
            };
            Ok(Json(response).into_response())
        }
        None => {
            info!("No authenticated user found in session for /me endpoint.");
            Err(AppError::Unauthorized("Not logged in".to_string()))
        }
    }
}

/// Create a new session
pub async fn create_session_handler(
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();
    
    // Insert the session into the database
    let session = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(sessions::table)
                .values((
                    sessions::id.eq(payload.id),
                    sessions::expires.eq(payload.expires_at),
                    sessions::session.eq(format!("{{\"userId\":\"{}\"}}", payload.user_id)),
                ))
                .returning((sessions::id, sessions::expires))
                .get_result::<(String, Option<chrono::DateTime<chrono::Utc>>)>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;

    let session_response = SessionResponse {
        id: session.0,
        user_id: payload.user_id,
        expires_at: session.1.unwrap_or_else(chrono::Utc::now),
    };

    Ok((StatusCode::CREATED, Json(session_response)))
}

/// Get session with user details
pub async fn get_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();
    
    // Get the session from the database
    let session = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let session_result = sessions::table
                .filter(sessions::id.eq(&session_id))
                .first::<(String, Option<chrono::DateTime<chrono::Utc>>, String)>(conn)
                .map_err(|e| {
                    if let diesel::result::Error::NotFound = e {
                        AppError::NotFound(format!("Session not found: {}", session_id))
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })?;

            // Extract user ID from session JSON
            let session_json: serde_json::Value = serde_json::from_str(&session_result.2)
                .map_err(|e| AppError::BadRequest(format!("Invalid session data: {}", e)))?;
            
            let user_id = session_json["userId"].as_str()
                .ok_or_else(|| AppError::BadRequest("Invalid session data: missing userId".to_string()))?;
            
            let user_id = Uuid::parse_str(user_id)
                .map_err(|e| AppError::BadRequest(format!("Invalid user ID in session: {}", e)))?;
            
            // Get the user
            let user = users::table // Use imported users::table
                .filter(users::id.eq(user_id)) // Use imported users::id
                .select(User::as_select()) // Use SelectableHelper trait
                .first::<User>(conn)
                .map_err(|e| {
                    if let diesel::result::Error::NotFound = e {
                        AppError::NotFound(format!("User not found: {}", user_id))
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })?;

            Ok::<_, AppError>((session_result, user)) // Add explicit type annotation for error
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    let (session_data, user) = session;
    
    let session_response = SessionResponse {
        id: session_data.0,
        user_id: user.id,
        expires_at: session_data.1.unwrap_or_else(chrono::Utc::now),
    };

    let user_response = AuthResponse { // Renamed UserResponse to AuthResponse
        user_id: user.id, // Renamed id to user_id
        username: user.username,
        email: user.email,
    };
    
    let response = SessionWithUserResponse {
        session: session_response,
        user: user_response,
    };
    
    Ok(Json(response))
}

/// Extend session expiration
pub async fn extend_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();
    
    // Update the session expiration
    let new_expiry = chrono::Utc::now() + chrono::Duration::days(30);
    
    let session = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::update(sessions::table)
                .filter(sessions::id.eq(session_id))
                .set(sessions::expires.eq(new_expiry))
                .returning((sessions::id, sessions::expires, sessions::session))
                .get_result::<(String, Option<chrono::DateTime<chrono::Utc>>, String)>(conn)
                .map_err(|e| {
                    if let diesel::result::Error::NotFound = e {
                        AppError::NotFound("Session not found".to_string())
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    // Extract user ID from session JSON
    let session_json: serde_json::Value = serde_json::from_str(&session.2)
        .map_err(|e| AppError::BadRequest(format!("Invalid session data: {}", e)))?;
    
    let user_id = session_json["userId"].as_str()
        .ok_or_else(|| AppError::BadRequest("Invalid session data: missing userId".to_string()))?;
    
    let user_id = Uuid::parse_str(user_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid user ID in session: {}", e)))?;
    
    let session_response = SessionResponse {
        id: session.0,
        user_id,
        expires_at: session.1.unwrap_or_else(chrono::Utc::now),
    };
    
    Ok(Json(session_response))
}

/// Delete a session
pub async fn delete_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();
    
    pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(sessions::table)
                .filter(sessions::id.eq(session_id))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    Ok(StatusCode::NO_CONTENT)
}

/// Delete all sessions for a user
pub async fn delete_user_sessions_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();
    
    // Find all sessions for this user and delete them
    // This is a bit tricky since the userId is stored in the JSON session data
    pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            // Get all sessions
            let all_sessions = sessions::table
                .select((sessions::id, sessions::session))
                .load::<(String, String)>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Filter sessions belonging to the user
            let user_session_ids: Vec<String> = all_sessions
                .into_iter()
                .filter_map(|(session_db_id, session_data): (String, String)| { // Renamed id to session_db_id
                    // Try to parse the session JSON
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&session_data) {
                        // Extract the userId if it exists
                        if let Some(session_user_id) = json["userId"].as_str() {
                            // Check if it matches our target userId
                            if let Ok(parsed_id) = Uuid::parse_str(session_user_id) {
                                if parsed_id == user_id {
                                    return Some(session_db_id); // Return renamed variable
                                }
                            }
                        }
                    }
                    None
                })
                .collect();
            
            // Delete the matching sessions
            if !user_session_ids.is_empty() {
                diesel::delete(sessions::table)
                    .filter(sessions::id.eq_any(user_session_ids))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            }

            Ok::<(), AppError>(())
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    Ok(StatusCode::NO_CONTENT)
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/me", get(me_handler))
        .route("/session", post(create_session_handler))
        .route("/session/{id}", get(get_session_handler).delete(delete_session_handler))
        .route("/session/{id}/extend", post(extend_session_handler))
        .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
}
