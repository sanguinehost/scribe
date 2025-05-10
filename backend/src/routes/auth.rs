use crate::auth::{self, AuthError, create_user, recover_user_password_with_phrase}; // Added recover_user_password_with_phrase
use crate::errors::AppError;
use crate::models::auth::{AuthResponse, LoginPayload, RegisterPayload, ChangePasswordPayload, RecoverPasswordPayload}; // Added RecoverPasswordPayload
use crate::state::{AppState, DbPool}; // Added DbPool import
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_login::{AuthSession, AuthUser};
// use secrecy::{ExposeSecret, Secret}; // Commenting out as they are unused now
use secrecy::ExposeSecret; // Added for DEK handling
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};
use base64::Engine; // Added for base64 encoding

use crate::auth::user_store::Backend as AuthBackend;
type CurrentAuthSession = AuthSession<AuthBackend>;

use crate::auth::SESSION_DEK_KEY; // Use the centrally defined key

use crate::schema::sessions;
use crate::schema::users::{self}; // Import users table (dsl::* is unused)
use crate::models::users::{User, UserDbQuery}; // Added UserDbQuery, consolidated User import
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper}; // Added SelectableHelper back
use axum::{
    extract::Path,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use axum::Router;
use axum::routing::{post, get, delete};
 // For session DEK handling
use tower_sessions::Session; // Import tower_sessions::Session

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
    let plaintext_password = payload.password.clone(); // Keep original Secret for KEK derivation

    // Hash the password asynchronously for storage
    // Clone the secret to pass to hash_password, original plaintext_password is moved to create_user
    let pwd_hash = crate::auth::hash_password(plaintext_password.clone()).await?;

    debug!(username = %reg_username, email = %reg_email, "Attempting to get DB connection from pool for registration..."); // Use renamed vars
    match pool.get().await {
        Ok(conn) => {
            debug!(username = %reg_username, email = %reg_email, "Got DB connection. Calling interact for create_user..."); // Use renamed vars
            // Pass the original payload and pwd_hash to create_user
            let user_result = conn
                .interact(move |conn_inner| create_user(conn_inner, payload, pwd_hash)) // Pass payload and pwd_hash
                .await;

            match user_result {
                Ok(inner_result) => {
                    debug!(username = %reg_username, email = %reg_email, "Interact for create_user completed.");
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
                            warn!(username = %reg_username, "Registration failed: Username taken.");
                            Err(AppError::UsernameTaken)
                        }
                        Err(AuthError::EmailTaken) => { // Handle EmailTaken error
                            warn!(email = %reg_email, "Registration failed: Email taken.");
                            Err(AppError::EmailTaken)
                        }
                        Err(AuthError::HashingError) => {
                            error!(username = %reg_username, email = %reg_email, "Registration failed: Password hashing error.");
                            Err(AppError::InternalServerErrorGeneric(
                                "Password hashing failed during registration".to_string(),
                            ))
                        }
                        Err(AuthError::DatabaseError(e)) => {
                            error!(username = %reg_username, email = %reg_email, error = ?e, "Registration failed: Database error.");
                            Err(AppError::DatabaseQueryError(e))
                        }
                        Err(e) => {
                            error!(username = %reg_username, email = %reg_email, error = ?e, "Registration failed: Unknown AuthError.");
                            Err(AppError::InternalServerErrorGeneric(
                                "An unexpected authentication error occurred.".to_string(),
                            ))
                        }
                    }
                }
                Err(interact_err) => {
                    error!(username = %reg_username, email = %reg_email, error = ?interact_err, "Interact error during user creation");
                    Err(AppError::InternalServerErrorGeneric(interact_err.to_string()))
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
    State(state): State<AppState>, // Added AppState
    mut auth_session: CurrentAuthSession,
    session: Session,             // tower_sessions session, extracted directly
    Json(payload): Json<LoginPayload>, // Use LoginPayload
) -> Result<Response, AppError> {
    let identifier_for_log = payload.identifier.clone();
    info!(identifier = %identifier_for_log, "Attempting login");

    // Directly call verify_credentials to get User and DEK
    let verification_result = state.pool.get().await
        .map_err(|e| {
            error!("Failed to get DB connection for login: {:?}", e);
            AppError::DbPoolError(e.to_string())
        })?
        .interact(move |conn| {
            // Clone password for the closure. Identifier is String, so it's cloned by value.
            auth::verify_credentials(conn, &payload.identifier, payload.password)
        })
        .await
        .map_err(|e| { // InteractError
            error!(identifier = %identifier_for_log, "Interact error during credential verification: {:?}", e);
            AppError::InternalServerErrorGeneric(format!("Credential verification process failed: {}", e))
        })?;

    match verification_result {
        Ok((user, maybe_dek)) => {
            let user_id = user.id;
            let login_username = user.username.clone();
            let login_email = user.email.clone();
            info!(username = %login_username, email = %login_email, %user_id, "Credential verification successful.");

            if let Some(dek) = maybe_dek {
                debug!(username = %login_username, %user_id, "DEK present, encoding and storing in session.");
                let dek_bytes = dek.expose_secret();
                let dek_base64 = base64::engine::general_purpose::STANDARD.encode(dek_bytes);
                
                // Store the DEK in the session using the directly extracted tower_sessions::Session
                match session.insert(SESSION_DEK_KEY, dek_base64).await {
                    Ok(_) => debug!("DEK stored in session successfully after login."),
                    Err(e) => {
                        error!("Failed to store DEK in session after login: {:?}", e);
                        // This might be a critical error, depending on application requirements.
                        // For now, we log it and proceed with the login response.
                        // Consider returning an error if DEK storage is mandatory for a valid session.
                    }
                }
            } else {
                info!(username = %login_username, %user_id, "No DEK present for this user or login type.");
            }

            // Proceed with axum-login's session login
            info!(username = %login_username, email = %login_email, %user_id, "Attempting explicit axum-login session.login...");
            if let Err(e) = auth_session.login(&user).await {
                error!(error = ?e, username = %login_username, email = %login_email, %user_id, "Explicit auth_session.login failed after successful credential verification");
                return Err(AppError::InternalServerErrorGeneric(format!(
                    "Session login failed: {}",
                    e
                )));
            }
            info!(username = %login_username, email = %login_email, %user_id, "Explicit auth_session.login successful");
            
            let response_data = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
            };
            Ok((StatusCode::OK, Json(response_data)).into_response())
        }
        Err(AuthError::WrongCredentials) => {
            warn!(identifier = %identifier_for_log, "Login failed: Wrong credentials.");
            Err(AppError::Unauthorized("Invalid identifier or password".to_string()))
        }
        Err(e) => {
            error!(identifier = %identifier_for_log, error = ?e, "Login failed due to an unexpected authentication error.");
            // Map other AuthErrors to appropriate AppErrors or a generic internal server error
            match e {
                AuthError::UserNotFound => Err(AppError::UserNotFound), // Should be caught by WrongCredentials generally
                AuthError::HashingError => Err(AppError::PasswordProcessingError), // Use new specific variant
                AuthError::CryptoOperationFailed(_) => Err(AppError::InternalServerErrorGeneric("Encryption error during login.".to_string())),
                AuthError::DatabaseError(db_err) => Err(AppError::DatabaseQueryError(db_err)),
                AuthError::PoolError(pool_err) => Err(AppError::DbPoolError(pool_err.to_string())),
                AuthError::InteractError(int_err) => Err(AppError::InternalServerErrorGeneric(int_err.to_string())),
                _ => Err(AppError::InternalServerErrorGeneric(format!("An unexpected auth error occurred: {}", e))),
            }
        }
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
        return Err(AppError::InternalServerErrorGeneric(format!(
            "Failed to clear session during logout: {}",
            e
        )));
    }
    info!("Logout process completed (session cleared if existed).");

    Ok(StatusCode::NO_CONTENT.into_response())
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    let session_response = SessionResponse {
        id: session.0,
        user_id: payload.user_id,
        expires_at: session.1.unwrap_or_else(chrono::Utc::now),
    };

    Ok((StatusCode::CREATED, Json(session_response)))
}

/// Get session with user details
#[instrument(skip(state), err)]
pub async fn get_session_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    info!(%session_id, "Get session handler entered");
    let pool = state.pool.clone();

    #[derive(Deserialize, Debug)]
    struct StoredSessionData {
        user_id: Uuid,
    }

    let session_id_for_closure = session_id.clone(); // Clone for the closure
    let session_info_result = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            sessions::table
                .filter(sessions::id.eq(&session_id_for_closure)) 
                .select((sessions::id, sessions::session, sessions::expires))
                .first::<(String, String, Option<chrono::DateTime<chrono::Utc>>)>(conn)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Interact error fetching session: {}", e)))?;

    match session_info_result {
        Ok((retrieved_session_id, session_json_string, expires_at_opt)) => {
            // Deserialize the session string to get user_id
            let stored_data: StoredSessionData = match serde_json::from_str(&session_json_string) {
                Ok(data) => data,
                Err(e) => {
                    error!(%retrieved_session_id, error = ?e, "Failed to deserialize session JSON string");
                    return Err(AppError::InternalServerErrorGeneric(format!("Invalid session data format: {}", e)));
                }
            };
            let user_id = stored_data.user_id;
            
            let expires_at = match expires_at_opt {
                Some(dt) => dt,
                None => {
                    // This case should ideally not happen if sessions always have an expiry.
                    // If they can be non-expiring, this needs different handling.
                    // For now, error out or use a default past time if that makes sense.
                    error!(%retrieved_session_id, "Session found but has no expiration time in DB.");
                    return Err(AppError::InternalServerErrorGeneric("Session has no expiration time.".to_string()));
                }
            };

            debug!(%retrieved_session_id, %user_id, %expires_at, "Session found and parsed. Fetching user details.");
            
            let user_details_result = pool // Re-acquire pool for the second interact
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?
                .interact(move |conn_user_fetch| { // Renamed conn to avoid conflict in some tracing
                    users::table
                        .filter(users::id.eq(user_id))
                        .select(UserDbQuery::as_select()) 
                        .first::<UserDbQuery>(conn_user_fetch)      
                        .map(User::from)                
                })
                .await
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Interact error fetching user for session: {}", e)))?;

            match user_details_result {
                Ok(user) => {
                    let user_response = AuthResponse {
                        user_id: user.id,
                        username: user.username.clone(), // Clone if User.username is String
                        email: user.email.clone(),       // Clone if User.email is String
                    };
                    let response = SessionWithUserResponse {
                        session: SessionResponse { 
                            id: retrieved_session_id, // Use the ID retrieved from DB
                            user_id, 
                            expires_at 
                        },
                        user: user_response,
                    };
                    Ok((StatusCode::OK, Json(response)).into_response())
                }
                Err(diesel::result::Error::NotFound) => {
                    error!(%user_id, "User not found for session, but session exists.");
                    Err(AppError::UserNotFound)
                }
                Err(e) => {
                    error!(%user_id, error = ?e, "Database error fetching user for session.");
                    // Convert diesel::result::Error to AppError properly
                    // This could be diesel::result::Error or deadpool_diesel::PoolError if interact fails
                    // The map_err above for interact handles pool errors. This is likely a diesel error.
                    Err(AppError::DatabaseQueryError(e.to_string()))
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            warn!(%session_id, "Session not found.");
            Err(AppError::SessionNotFound)
        }
        Err(e) => {
            error!(%session_id, error = ?e, "Database error fetching session details.");
            Err(AppError::DatabaseQueryError(e.to_string()))
        }
    }
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    Ok(StatusCode::NO_CONTENT)
}

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
        .get().await.map_err(AppError::from)? 
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
    let authenticated_user = match auth_session.user.clone() {
        Some(u) => u,
        None => {
            warn!("Change password attempt by unauthenticated user.");
            return Err(AppError::Unauthorized("Not logged in".to_string()));
        }
    };
    info!(user_id = %authenticated_user.id, username = %authenticated_user.username, "User is authenticated. Proceeding with password change.");

    // 2. Validate payload
    if let Err(validation_errors) = payload.validate() {
        error!(user_id = %authenticated_user.id, errors = ?validation_errors, "Change password payload validation failed.");
        return Err(AppError::ValidationError(validation_errors.to_string()));
    }

    // 3. Fetch full current user details from DB (needed for salts, encrypted DEK)
    // We need a fresh copy to ensure we have the latest kek_salt and encrypted_dek.
    debug!(user_id = %authenticated_user.id, "Fetching full user details from DB for password change.");
    let current_db_user = state.pool.get().await.map_err(AppError::from)?
        .interact(move |conn| crate::auth::get_user(conn, authenticated_user.id))
        .await
        .map_err(AppError::from)??; // Double ?? for InteractError then AuthError

    // 4. Call the core password change logic
    debug!(user_id = %current_db_user.id, "Calling auth::change_user_password function.");
    let auth_backend = crate::auth::user_store::Backend::new(state.pool.clone());
    match auth::change_user_password(
        &auth_backend,
        current_db_user.id,
        current_db_user, // Pass the full user object fetched from DB
        payload.current_password,
        payload.new_password,
    ).await {
        Ok(_) => {
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

            Ok((StatusCode::OK, Json(json!({ "message": "Password changed successfully. Please log in again." }))).into_response())
        }
        Err(AuthError::WrongCredentials) => {
            warn!(user_id = %authenticated_user.id, "Password change failed: Incorrect current password.");
            Err(AppError::Unauthorized("Incorrect current password".to_string()))
        }
        Err(AuthError::HashingError) => {
            error!(user_id = %authenticated_user.id, "Password change failed: Hashing error.");
            Err(AppError::PasswordProcessingError)
        }
        Err(AuthError::CryptoOperationFailed(e)) => {
            error!(user_id = %authenticated_user.id, error = ?e, "Password change failed: Cryptographic operation error.");
            Err(AppError::InternalServerErrorGeneric("Encryption error during password change.".to_string()))
        }
        Err(AuthError::UserNotFound) => { // Should not happen if user is authenticated and fetched
            error!(user_id = %authenticated_user.id, "Password change failed: User not found during update (unexpected).");
            Err(AppError::InternalServerErrorGeneric("User consistency error.".to_string()))
        }
        Err(e) => {
            error!(user_id = %authenticated_user.id, error = ?e, "Password change failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric("An unexpected error occurred during password change.".to_string()))
        }
    }
}

#[instrument(skip(state, payload), err)]
pub async fn recover_password_handler(
    State(state): State<AppState>,
    Json(payload): Json<RecoverPasswordPayload>,
) -> Result<Response, AppError> {
    info!(identifier = %payload.identifier, "Password recovery handler entered");

    // 1. Validate payload
    if let Err(validation_errors) = payload.validate() {
        error!(identifier = %payload.identifier, errors = ?validation_errors, "Password recovery payload validation failed.");
        return Err(AppError::ValidationError(validation_errors.to_string()));
    }

    // 2. Call the core password recovery logic
    debug!(identifier = %payload.identifier, "Calling auth::recover_user_password_with_phrase function.");
    let auth_backend = crate::auth::user_store::Backend::new(state.pool.clone());
    match recover_user_password_with_phrase(
        &auth_backend,
        &state.pool,
        payload.identifier.clone(),
        payload.recovery_phrase,
        payload.new_password,
    )
    .await
    {
        Ok(user_id) => {
            info!(identifier = %payload.identifier, %user_id, "Password recovered successfully in core logic.");

            // 3. Session Invalidation for all user's sessions
            // This is crucial after a password recovery.
            // We can reuse or adapt the logic from delete_user_sessions_handler,
            // but it needs to be called here.
            // For now, we'll call a helper that might be similar to delete_user_sessions_handler's core.
            // This assumes `delete_all_sessions_for_user` exists or will be created in `auth` module.
            // It's important this doesn't rely on an active session for *this* request.
            warn!(%user_id, "Attempting to invalidate all sessions for user after password recovery.");
            match auth::delete_all_sessions_for_user(&state.pool, user_id).await {
                Ok(_) => {
                    info!(%user_id, "Successfully invalidated all sessions for user after password recovery.");
                }
                Err(e) => {
                    // Log the error but don't fail the entire recovery process,
                    // as password has been reset. This is a cleanup step.
                    error!(%user_id, error = ?e, "Failed to invalidate all sessions for user after password recovery. This is non-critical for the recovery itself but should be investigated.");
                }
            }

            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Password recovered successfully. You can now log in with your new password." })),
            )
                .into_response())
        }
        Err(AuthError::UserNotFound) => {
            warn!(identifier = %payload.identifier, "Password recovery failed: User not found.");
            Err(AppError::UserNotFound)
        }
        Err(AuthError::RecoveryNotSetup) => {
            warn!(identifier = %payload.identifier, "Password recovery failed: Recovery not set up for this user.");
            Err(AppError::BadRequest("Password recovery is not enabled for this account.".to_string()))
        }
        Err(AuthError::InvalidRecoveryPhrase) => {
            warn!(identifier = %payload.identifier, "Password recovery failed: Invalid recovery phrase.");
            Err(AppError::Unauthorized("Invalid recovery phrase.".to_string()))
        }
        Err(AuthError::HashingError) => {
            error!(identifier = %payload.identifier, "Password recovery failed: Hashing error.");
            Err(AppError::PasswordProcessingError)
        }
        Err(AuthError::CryptoOperationFailed(e)) => {
            error!(identifier = %payload.identifier, error = ?e, "Password recovery failed: Cryptographic operation error.");
            Err(AppError::InternalServerErrorGeneric(
                "Encryption error during password recovery.".to_string(),
            ))
        }
        Err(e) => {
            error!(identifier = %payload.identifier, error = ?e, "Password recovery failed: Unknown AuthError.");
            Err(AppError::InternalServerErrorGeneric(
                "An unexpected error occurred during password recovery.".to_string(),
            ))
        }
    }
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/me", get(me_handler))
        .route("/change-password", post(change_password_handler))
        .route("/recover-password", post(recover_password_handler)) // New route
        .route("/session", post(create_session_handler))
        .route("/session/{id}", get(get_session_handler).delete(delete_session_handler))
        .route("/session/{id}/extend", post(extend_session_handler))
        .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
}
