use crate::auth::{self, AuthError, recover_user_password_with_phrase}; // Added recover_user_password_with_phrase
use crate::errors::AppError;
use crate::models::auth::{
    AuthResponse, ChangePasswordPayload, LoginPayload, RecoverPasswordPayload, RegisterPayload,
}; // Added RecoverPasswordPayload
use crate::models::email_verification::VerifyEmailPayload;
use crate::state::{AppState, DbPool}; // Added DbPool import
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_login::{AuthSession, AuthUser};
// use secrecy::{ExposeSecret, Secret}; // Commenting out as they are unused now
// Added back for DEK length logging
use axum::Router;
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};
// use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64}; // Add Base64 import - Removed unused
// For session DEK handling
use crate::auth::session_store::offset_to_utc;
use tower_sessions::Session; // Import tower_sessions::Session // Added for time conversion

use crate::auth::user_store::Backend as AuthBackend;
type CurrentAuthSession = AuthSession<AuthBackend>;

use crate::models::users::User; // Removed UserDbQuery
use crate::schema::sessions;
// use crate::schema::users::{self}; // Import users table (dsl::* is unused) - Removed self
use axum::extract::Path;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl}; // Removed SelectableHelper
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionWithUserResponse {
    pub session: SessionResponse,
    pub user: AuthResponse,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String, // This is the session_id from tower_sessions
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// New response structure for successful login
#[derive(Debug, Serialize)]
pub struct LoginSuccessResponse {
    pub user: AuthResponse,
    pub session_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/verify-email", post(verify_email_handler))
        .route("/logout", post(logout_handler))
        .route("/me", get(me_handler))
        .route("/change-password", post(change_password_handler))
        .route("/recover-password", post(recover_password_handler))
        .route("/session", post(create_session_handler))
        .route("/session/current", get(get_session_handler))
        .route("/session/{id}", delete(delete_session_handler))
        .route("/session/{id}/extend", post(extend_session_handler))
        .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
}

#[instrument(skip(state, payload), err)]
pub async fn verify_email_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailPayload>,
) -> Result<Response, AppError> {
    info!("Email verification handler entered");

    let pool = state.pool.clone();
    let token = payload.token;

    let verification_result = pool
        .get()
        .await
        .map_err(AppError::from)?
        .interact(move |conn| auth::verify_email(conn, &token))
        .await
        .map_err(AppError::from)?;

    match verification_result {
        Ok(_) => {
            info!("Email verification successful.");
            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Email verified successfully. You can now log in." })),
            )
                .into_response())
        }
        Err(AuthError::InvalidVerificationToken) => {
            warn!("Email verification failed: Invalid or expired token.");
            Err(AppError::BadRequest(
                "The verification link is invalid or has expired.".to_string(),
            ))
        }
        Err(e) => {
            error!(error = ?e, "Email verification failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric(
                "An unexpected error occurred during email verification.".to_string(),
            ))
        }
    }
}

/// Handles user registration with username, email, and password.
///
/// # Errors
///
/// Returns `AppError::ValidationError` if payload validation fails,
/// `AppError::UsernameTaken` if the username is already registered,
/// `AppError::EmailTaken` if the email is already registered,
/// `AppError::InternalServerErrorGeneric` if password hashing fails,
/// `AppError::DatabaseQueryError` if database operations fail,
/// `AppError::DbPoolError` if database connection cannot be obtained.
#[instrument(skip(state, payload), err)]
pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterPayload>, // Use RegisterPayload
) -> Result<impl IntoResponse, AppError> {
    info!("Register handler entered");

    // Validate the payload
    if let Err(validation_errors) = payload.validate() {
        warn!("Register DTO validation failed: {:?}", validation_errors);
        return Err(AppError::ValidationError(validation_errors));
    }

    let pool = state.pool.clone();
    let reg_username = payload.username.clone(); // Renamed to avoid shadowing schema item
    let reg_email = payload.email.clone(); // Renamed to avoid shadowing schema item

    debug!("Attempting to create user with email verification...");
    // Use the new create_user_with_verification function
    let user_result = crate::auth::create_user_with_verification(
        &pool,
        payload,
        state.email_service.clone(),
    )
    .await;

    match user_result {
        Ok(user) => {
            debug!("User creation with email verification completed.");
            info!(user_id = %user.id, "User registration successful.");
            // Use AuthResponse for success
            // The created user has the recovery phrase that was used
            let response = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
                role: format!("{:?}", user.role),
                recovery_key: user.recovery_phrase.clone(), // Get recovery phrase from the returned user
                default_persona_id: user.default_persona_id,
            };
            Ok((StatusCode::CREATED, Json(response)).into_response())
        }
        Err(AuthError::UsernameTaken) => {
            warn!("Registration failed: Username {} taken.", reg_username);
            Err(AppError::UsernameTaken)
        }
        Err(AuthError::EmailTaken) => {
            // Handle EmailTaken error
            warn!("Registration failed: Email {} taken.", reg_email);
            Err(AppError::EmailTaken)
        }
        Err(AuthError::HashingError) => {
            error!("Registration failed: Password hashing error.");
            Err(AppError::InternalServerErrorGeneric(
                "Password hashing failed during registration".to_string(),
            ))
        }
        Err(AuthError::DatabaseError(e)) => {
            error!(error = ?e, "Registration failed: Database error.");
            Err(AppError::DatabaseQueryError(e))
        }
        Err(e) => {
            error!(error = ?e, "Registration failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric(
                "An unexpected authentication error occurred.".to_string(),
            ))
        }
    }
}

#[instrument(skip(auth_session, payload), err)]
pub async fn login_handler(
    State(state): State<AppState>, // Added AppState
    mut auth_session: CurrentAuthSession,
    session: Session,                  // tower_sessions session, extracted directly
    Json(payload): Json<LoginPayload>, // Use LoginPayload
) -> Result<Response, AppError> {
    info!("Attempting login");

    // Use axum-login's authenticate method which will call our AuthBackend::authenticate
    // This ensures the DEK is properly cached
    match auth_session.authenticate(payload).await {
        Ok(Some(user)) => {
            let user_id = user.id;
            info!(%user_id, "Authentication successful via AuthBackend.");

            // SECURITY: The DEK is now cached in AuthBackend, NOT stored in the session
            // The user object returned from authenticate has dek=None to prevent session storage

            // Serialize the user object to see what's going into the session
            match serde_json::to_string(&user) {
                Ok(user_json) => {
                    // Note: user_json might still contain PII if User's Serialize impl includes it.
                    // This change only removes the direct `username` field from this specific log line.
                    debug!(%user_id, user_json = %user_json, "User object serialized before login");
                }
                Err(e) => {
                    error!(%user_id, error = ?e, "Failed to serialize user for debugging");
                }
            }

            // Log the session ID BEFORE auth_session.login
            debug!(session_id = ?session.id(), user_id = %user_id, "Session ID BEFORE axum-login.login() call");

            // Debugging: User returned from authenticate should have dek=None
            if user.dek.is_some() {
                error!(%user_id, "SECURITY WARNING: User.dek should be None after authenticate but it's present!");
            } else {
                debug!(%user_id, "User.dek is correctly None after authenticate (DEK is cached in AuthBackend)");
            }

            // Invalidate the session before logging in to prevent session fixation
            if let Err(e) = auth_session.logout().await {
                error!(%user_id, error = ?e, "Failed to destroy existing session during login: {:?}", e);
                return Err(AppError::InternalServerErrorGeneric(format!(
                    "Failed to clear existing session during login: {e}"
                )));
            }

            // Now we need to explicitly log the user in
            if let Err(e) = auth_session.login(&user).await {
                error!(%user_id, error = ?e, "Failed to log in user after successful authentication");
                return Err(AppError::InternalServerErrorGeneric(
                    "Failed to establish session after authentication".to_string(),
                ));
            }
            info!(user_id = %user_id, "Login successful via authenticate");

            // Log the session ID AFTER auth_session.login
            debug!(session_id = ?session.id(), user_id = %user_id, "Session ID AFTER axum-login.login() call");

            // Rotate session ID to prevent session fixation attacks
            if let Err(e) = session.cycle_id().await {
                error!(%user_id, error = ?e, "Failed to rotate session ID after login: {:?}", e);
                return Err(AppError::InternalServerErrorGeneric(format!(
                    "Failed to rotate session ID after login: {e}"
                )));
            }
            debug!(session_id = ?session.id(), user_id = %user_id, "Session ID rotated successfully after login");

            // Try to explicitly save the session (this might be redundant, but useful for debugging)
            match session.save().await {
                Ok(()) => {
                    debug!(session_id = ?session.id(), user_id = %user_id, "Explicitly called session.save() successfully");
                }
                Err(e) => {
                    error!(session_id = ?session.id(), user_id = %user_id, error = ?e, "Explicit session.save() call failed: {:?}", e);
                }
            }

            // Debugging: Log DEK presence after login call (from auth_session.user)
            if let Some(ref user_after_login) = auth_session.user {
                if let Some(ref _wrapped_dek_after_login) = user_after_login.dek {
                    // _wrapped_dek_after_login as it's not used in the error
                    error!(%user_id, "SECURITY WARNING: User.dek is UNEXPECTEDLY PRESENT in auth_session.user AFTER login. DEK should be None and cached server-side.");
                } else {
                    debug!(%user_id, "User.dek is None in auth_session.user AFTER login (expected, as DEK is cached server-side).");
                }
            } else {
                error!(%user_id, "auth_session.user is NONE after login.");
            }

            // SECURITY FIX: We no longer store the DEK in the session.
            // The following block for checking "axum-login.user" key immediately after login has been removed.
            // This check is unreliable as the session instance in the handler may not be synchronously updated.
            // Session persistence is handled by middleware and verified by integration tests.

            // SECURITY FIX: We no longer store the DEK in the session.
            // The DEK is now only stored in the server-side AuthBackend cache.
            // This comment block replaces the code that previously stored the DEK in the session.

            // Get session ID and expiry from tower_sessions::Session
            let session_id_str = session.id().map_or_else(
                || {
                    error!(user_id = %user.id, "Failed to get session ID after login for response");
                    // Fallback or handle error appropriately, though this should ideally not happen
                    // For now, let's use a placeholder or consider this a critical error.
                    // However, axum-login should have ensured a session exists.
                    // If this fails, the cookie setting itself might be problematic.
                    // For now, we'll proceed, but this indicates an issue if it occurs.
                    "error_retrieving_session_id".to_string()
                },
                |id| id.0.to_string(), // tower_sessions::SessionId is OwnedSessionId(SessionId(i128))
            );

            let expires_at_utc = offset_to_utc(Some(session.expiry_date())).ok_or_else(|| {
                error!(user_id = %user.id, session_id = %session_id_str, "Failed to convert session expiry to UTC for login response");
                AppError::InternalServerErrorGeneric("Failed to process session expiry for login response.".to_string())
            })?;

            let login_success_response = LoginSuccessResponse {
                user: AuthResponse {
                    user_id: user.id,
                    username: user.username.clone(),
                    email: user.email.clone(),
                    role: format!("{:?}", user.role),
                    recovery_key: None, // Login response doesn't include recovery key
                    default_persona_id: user.default_persona_id,
                },
                session_id: session_id_str,
                expires_at: expires_at_utc,
            };
            Ok((StatusCode::OK, Json(login_success_response)).into_response())
        }
        Ok(None) => {
            // Authentication failed - wrong credentials
            warn!("Login failed: Wrong credentials.");
            Err(AppError::Unauthorized(
                "Invalid identifier or password".to_string(),
            ))
        }
        Err(e) => {
            error!(error = ?e, "Login failed due to authentication error.");
            // axum_login::Error wraps our AuthError
            match e {
                axum_login::Error::Backend(auth_err) => {
                    // Extract our AuthError from the axum_login wrapper
                    match auth_err {
                        AuthError::WrongCredentials | AuthError::UserNotFound => {
                            warn!("Login failed: Wrong credentials.");
                            Err(AppError::Unauthorized(
                                "Invalid identifier or password".to_string(),
                            ))
                        }
                        AuthError::AccountLocked => {
                            warn!("Login failed: Account locked.");
                            Err(AppError::Unauthorized(
                                "Your account is locked. Please contact an administrator."
                                    .to_string(),
                            ))
                        }
                        AuthError::AccountPendingVerification => {
                            warn!("Login failed: Account pending verification.");
                            Err(AppError::Forbidden(
                                "Your account is pending email verification.".to_string(),
                            ))
                        }
                        AuthError::HashingError => Err(AppError::PasswordProcessingError),
                        AuthError::CryptoOperationFailed(_) => {
                            Err(AppError::InternalServerErrorGeneric(
                                "Encryption error during login.".to_string(),
                            ))
                        }
                        AuthError::DatabaseError(db_err) => {
                            Err(AppError::DatabaseQueryError(db_err))
                        }
                        AuthError::PoolError(pool_err) => {
                            Err(AppError::DbPoolError(pool_err.to_string()))
                        }
                        AuthError::InteractError(int_err) => {
                            Err(AppError::InternalServerErrorGeneric(int_err))
                        }
                        AuthError::UsernameTaken => {
                            warn!("Login failed: Username taken (shouldn't happen during login).");
                            Err(AppError::InternalServerErrorGeneric(
                                "Unexpected error during login.".to_string(),
                            ))
                        }
                        AuthError::EmailTaken => {
                            warn!("Login failed: Email taken (shouldn't happen during login).");
                            Err(AppError::InternalServerErrorGeneric(
                                "Unexpected error during login.".to_string(),
                            ))
                        }
                        AuthError::RecoveryNotSetup => {
                            warn!(
                                "Login failed: Recovery not setup (shouldn't happen during login)."
                            );
                            Err(AppError::InternalServerErrorGeneric(
                                "Unexpected error during login.".to_string(),
                            ))
                        }
                        AuthError::InvalidRecoveryPhrase => {
                            warn!(
                                "Login failed: Invalid recovery phrase (shouldn't happen during login)."
                            );
                            Err(AppError::InternalServerErrorGeneric(
                                "Unexpected error during login.".to_string(),
                            ))
                        }
                        AuthError::SessionDeletionError(msg) => {
                            error!("Login failed: Session deletion error: {}", msg);
                            Err(AppError::SessionError(format!("Session error: {msg}")))
                        }
                        AuthError::InvalidVerificationToken => {
                            // This error should not occur during login
                            error!("Login failed: InvalidVerificationToken encountered during login flow.");
                            Err(AppError::InternalServerErrorGeneric(
                                "Unexpected authentication error.".to_string(),
                            ))
                        }
                    }
                }
                axum_login::Error::Session(session_err) => {
                    error!("Session error during login: {:?}", session_err);
                    Err(AppError::SessionError(format!(
                        "Session error: {session_err}"
                    )))
                }
            }
        }
    }
}

#[instrument(skip(auth_session, state), err)]
pub async fn logout_handler(
    State(state): State<AppState>,
    mut auth_session: CurrentAuthSession,
) -> Result<Response, AppError> {
    info!("Logout handler entered.");

    // Remove DEK from cache before logging out
    if let Some(user) = &auth_session.user {
        let user_id = user.id();
        info!(user_id = %user_id, "Attempting to log out user.");

        // Remove the DEK from the AuthBackend cache
        state.auth_backend.remove_dek_from_cache(&user_id).await;
        info!(user_id = %user_id, "DEK removed from cache during logout");
    } else {
        debug!("Logout called, but no user session found in request.");
    }

    debug!("Calling auth_session.logout().await...");
    if let Err(e) = auth_session.logout().await {
        error!(error = ?e, "Failed to destroy session during logout via auth_session.logout(): {:?}", e);
        return Err(AppError::InternalServerErrorGeneric(format!(
            "Failed to clear session during logout: {e}"
        )));
    }
    info!("Logout process completed (session cleared if existed).");

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[instrument(skip(auth_session), err)]
pub async fn me_handler(auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    info!("Me handler entered.");
    if let Some(user) = auth_session.user {
        info!(user_id = %user.id, "Returning current user data for /me endpoint.");
        // Use AuthResponse for consistency
        let response = AuthResponse {
            user_id: user.id,
            username: user.username,
            email: user.email,
            role: format!("{:?}", user.role),
            recovery_key: None, // /me endpoint doesn't return recovery key
            default_persona_id: user.default_persona_id,
        };
        Ok(Json(response).into_response())
    } else {
        info!("No authenticated user found in session for /me endpoint.");
        Err(AppError::Unauthorized("Not logged in".to_string()))
    }
}

/// Create a new session
///
/// # Errors
/// Returns `AppError` if database operations fail or session creation fails
pub async fn create_session_handler(
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();

    // Insert the session into the database
    let session = pool
        .get()
        .await
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let session_response = SessionResponse {
        id: session.0,
        user_id: payload.user_id,
        expires_at: session.1.unwrap_or_else(chrono::Utc::now),
    };

    Ok((StatusCode::CREATED, Json(session_response)))
}

/// Get current session details if a valid session exists
#[instrument(skip_all, err)] // Skip all to avoid issues with AppState and Session not being Debug
pub async fn get_session_handler(
    State(_state): State<AppState>, // _state might be needed if we fetch more user details not in AuthUser
    auth_session: CurrentAuthSession,
    session: tower_sessions::Session, // tower_sessions::Session to get session ID and expiry
) -> Result<impl IntoResponse, AppError> {
    info!("Get current session handler entered");

    if let Some(user) = auth_session.user {
        let user_id = user.id;
        info!(%user_id, "Valid session found. Returning user and session details.");

        // The session ID from tower_sessions::Session is an i128, convert to string.
        let session_actual_id_str = if let Some(id) = session.id() {
            id.0.to_string()
        } else {
            // This case should ideally not happen if auth_session.user is Some,
            // as it implies an active session object without an ID.
            error!(
                "Critical: tower_sessions::Session present but session.id() is None in get_session_handler"
            );
            return Err(AppError::InternalServerErrorGeneric(
                "Failed to retrieve session ID from active session".to_string(),
            ));
        };

        // The expiry date from tower_sessions::Session is time::OffsetDateTime.
        let session_expiry_offset = session.expiry_date();

        // Convert time::OffsetDateTime to chrono::DateTime<Utc> for the response model.
        // The offset_to_utc helper is available in crate::auth::session_store.
        let expires_at_utc = offset_to_utc(Some(session_expiry_offset)).ok_or_else(|| {
            error!(session_id = %session_actual_id_str, "Failed to convert session expiry to UTC");
            AppError::InternalServerErrorGeneric("Failed to process session expiry.".to_string())
        })?;

        let user_response = AuthResponse {
            user_id: user.id,
            username: user.username.clone(), // Assuming User struct has these fields and they are cloneable
            email: user.email.clone(),
            role: format!("{:?}", user.role), // Assuming role is an enum
            recovery_key: None, // Session response doesn't typically include recovery key
            default_persona_id: user.default_persona_id,
        };

        let session_data_response = SessionResponse {
            id: session_actual_id_str, // Use the actual session ID from tower_sessions
            user_id,
            expires_at: expires_at_utc,
        };

        let response = SessionWithUserResponse {
            session: session_data_response,
            user: user_response,
        };
        Ok((StatusCode::OK, Json(response)).into_response())
    } else {
        info!("No active session found.");
        // This error should be handled by AppError's IntoResponse to return a JSON error
        Err(AppError::Unauthorized(
            "No active session. Please log in.".to_string(),
        ))
    }
}

/// Extend session expiration
///
/// # Errors
/// Returns `AppError` if database operations fail or session extension fails
pub async fn extend_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();

    // Update the session expiration
    let new_expiry = chrono::Utc::now() + chrono::Duration::days(30);

    let session = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::update(sessions::table)
                .filter(sessions::id.eq(session_id))
                .set(sessions::expires.eq(new_expiry))
                .returning((sessions::id, sessions::expires, sessions::session))
                .get_result::<(String, Option<chrono::DateTime<chrono::Utc>>, String)>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::NotFound("Session not found".to_string())
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Extract user ID from session JSON
    let session_json: serde_json::Value = serde_json::from_str(&session.2)
        .map_err(|e| AppError::BadRequest(format!("Invalid session data: {e}")))?;

    let user_id = session_json["userId"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Invalid session data: missing userId".to_string()))?;

    let user_id = Uuid::parse_str(user_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid user ID in session: {e}")))?;

    let session_response = SessionResponse {
        id: session.0,
        user_id,
        expires_at: session.1.unwrap_or_else(chrono::Utc::now),
    };

    Ok(Json(session_response))
}

/// Delete a session
///
/// # Errors
/// Returns `AppError` if database operations fail or session deletion fails
pub async fn delete_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();

    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(sessions::table)
                .filter(sessions::id.eq(session_id))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete all sessions for a user
///
/// # Errors
/// Returns `AppError` if database operations fail or session deletion fails
pub async fn delete_user_sessions_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();

    // Find all sessions for this user and delete them
    // This is a bit tricky since the userId is stored in the JSON session data
    pool.get()
        .await
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
                .filter_map(|(session_db_id, session_data): (String, String)| {
                    // Renamed id to session_db_id
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    Ok(StatusCode::NO_CONTENT)
}

#[allow(dead_code)]
#[instrument(skip(pool, auth_session), err)]
async fn get_current_user_handler(
    State(pool): State<DbPool>,
    auth_session: AuthSession<AuthBackend>,
) -> Result<Json<User>, AppError> {
    let user_id = auth_session.user.as_ref().map_or_else(
        || {
            warn!("Attempt to get current user without active session");
            Err(AppError::Unauthorized("No active session".to_string()))
        },
        |user| Ok(user.id),
    )?;

    info!(%user_id, "Fetching current user details from database using auth::get_user");

    let user = pool
        .get()
        .await
        .map_err(AppError::from)?
        .interact(move |conn| {
            // Call the refactored function from auth module
            crate::auth::get_user(conn, user_id)
        })
        .await
        .map_err(AppError::from)??; // Double ?? handles InteractError from pool and then AuthError from get_user via AppError::from

    Ok(Json(user))
}

#[instrument(skip(state, auth_session, payload), err)]
pub async fn change_password_handler(
    State(state): State<AppState>,
    mut auth_session: CurrentAuthSession,
    Json(payload): Json<ChangePasswordPayload>,
) -> Result<Response, AppError> {
    info!("Change password handler entered");

    // 1. Ensure user is authenticated
    let Some(authenticated_user) = auth_session.user.clone() else {
        warn!("Change password attempt by unauthenticated user.");
        return Err(AppError::Unauthorized("Not logged in".to_string()));
    };
    info!(user_id = %authenticated_user.id, "User is authenticated. Proceeding with password change.");

    // 2. Validate payload
    if let Err(validation_errors) = payload.validate() {
        warn!("Update DTO validation failed: {:?}", validation_errors);
        return Err(AppError::ValidationError(validation_errors));
    }

    // 3. Fetch full current user details from DB (needed for salts, encrypted DEK)
    // We need a fresh copy to ensure we have the latest kek_salt and encrypted_dek.
    debug!(user_id = %authenticated_user.id, "Fetching full user details from DB for password change.");
    let current_db_user = state
        .pool
        .get()
        .await
        .map_err(AppError::from)?
        .interact(move |conn| crate::auth::get_user(conn, authenticated_user.id))
        .await
        .map_err(AppError::from)??; // Double ?? for InteractError then AuthError

    // 4. Call the core password change logic
    debug!(user_id = %current_db_user.id, "Calling auth::change_user_password function.");
    // Use the shared auth_backend from AppState
    match auth::change_user_password(
        &state.auth_backend,
        current_db_user.id,
        current_db_user, // Pass the full user object fetched from DB
        payload.current_password,
        payload.new_password,
    )
    .await
    {
        Ok(()) => {
            info!(user_id = %authenticated_user.id, "Password changed successfully in core logic.");
            // 5. Session Invalidation (Recommended - TODO)
            // For now, we will log out the current session as a minimal step.
            // A more robust solution would invalidate *all other* sessions.
            warn!(user_id = %authenticated_user.id, "TODO: Implement full session invalidation for other active sessions.");
            if let Err(e) = auth_session.logout().await {
                error!(user_id = %authenticated_user.id, error = ?e, "Failed to log out current session after password change.");
                // Non-critical error, proceed with success response for password change itself.
            } else {
                info!(user_id = %authenticated_user.id, "Current session logged out after password change.");
            }

            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Password changed successfully. Please log in again." })),
            )
                .into_response())
        }
        Err(AuthError::WrongCredentials) => {
            warn!(user_id = %authenticated_user.id, "Password change failed: Incorrect current password.");
            Err(AppError::Unauthorized(
                "Incorrect current password".to_string(),
            ))
        }
        Err(AuthError::HashingError) => {
            error!(user_id = %authenticated_user.id, "Password change failed: Hashing error.");
            Err(AppError::PasswordProcessingError)
        }
        Err(AuthError::CryptoOperationFailed(e)) => {
            error!(user_id = %authenticated_user.id, error = ?e, "Password change failed: Cryptographic operation error.");
            Err(AppError::InternalServerErrorGeneric(
                "Encryption error during password change.".to_string(),
            ))
        }
        Err(AuthError::UserNotFound) => {
            // Should not happen if user is authenticated and fetched
            error!(user_id = %authenticated_user.id, "Password change failed: User not found during update (unexpected).");
            Err(AppError::InternalServerErrorGeneric(
                "User consistency error.".to_string(),
            ))
        }
        Err(e) => {
            error!(user_id = %authenticated_user.id, error = ?e, "Password change failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric(
                "An unexpected error occurred during password change.".to_string(),
            ))
        }
    }
}

#[instrument(skip(state, payload), err)]
pub async fn recover_password_handler(
    State(state): State<AppState>,
    Json(payload): Json<RecoverPasswordPayload>,
) -> Result<Response, AppError> {
    info!("Password recovery handler entered");

    // 1. Validate payload
    if let Err(validation_errors) = payload.validate() {
        error!(errors = ?validation_errors, "Password recovery payload validation failed.");
        return Err(AppError::ValidationError(validation_errors));
    }

    // 2. Call the core password recovery logic
    debug!("Calling auth::recover_user_password_with_phrase function.");
    // Use the shared auth_backend from AppState
    let result = recover_user_password_with_phrase(
        &state.auth_backend,
        &state.pool,
        payload.identifier.clone(),
        payload.recovery_phrase,
        payload.new_password,
    )
    .await;

    match result {
        Ok(user_id) => {
            info!(%user_id, "Password recovered successfully in core logic.");

            warn!(%user_id, "Attempting to invalidate all sessions for user after password recovery.");
            if let Err(e) = auth::delete_all_sessions_for_user(&state.pool, user_id).await {
                error!(%user_id, error = ?e, "Failed to invalidate all sessions for user after password recovery. This is non-critical but should be investigated.");
            } else {
                info!(%user_id, "Successfully invalidated all sessions for user after password recovery.");
            }

            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Password recovered successfully. You can now log in with your new password." })),
            )
                .into_response())
        }
        Err(AuthError::UserNotFound) => {
            warn!("Password recovery failed: User not found for identifier.");
            Err(AppError::UserNotFound)
        }
        Err(AuthError::RecoveryNotSetup) => {
            warn!("Password recovery failed: Recovery not set up for this user.");
            Err(AppError::BadRequest(
                "Password recovery is not enabled for this account.".to_string(),
            ))
        }
        Err(AuthError::InvalidRecoveryPhrase) => {
            warn!("Password recovery failed: Invalid recovery phrase.");
            Err(AppError::Unauthorized(
                "Invalid recovery phrase.".to_string(),
            ))
        }
        Err(AuthError::HashingError) => {
            error!("Password recovery failed: Hashing error.");
            Err(AppError::PasswordProcessingError)
        }
        Err(AuthError::CryptoOperationFailed(e)) => {
            error!(error = ?e, "Password recovery failed: Cryptographic operation error.");
            Err(AppError::InternalServerErrorGeneric(
                "Encryption error during password recovery.".to_string(),
            ))
        }
        Err(e) => {
            error!(error = ?e, "Password recovery failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric(
                "An unexpected error occurred during password recovery.".to_string(),
            ))
        }
    }
}
