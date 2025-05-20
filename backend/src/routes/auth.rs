use crate::auth::{self, AuthError, create_user, recover_user_password_with_phrase}; // Added recover_user_password_with_phrase
use crate::errors::AppError;
use crate::models::auth::{
    AuthResponse, ChangePasswordPayload, LoginPayload, RecoverPasswordPayload, RegisterPayload,
}; // Added RecoverPasswordPayload
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
use tower_sessions::Session; // Import tower_sessions::Session

use crate::auth::user_store::Backend as AuthBackend;
type CurrentAuthSession = AuthSession<AuthBackend>;

use crate::models::users::{SerializableSecretDek, User, UserDbQuery}; // Added SerializableSecretDek
use crate::schema::sessions;
use crate::schema::users::{self}; // Import users table (dsl::* is unused)
use axum::extract::Path;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper}; // Added SelectableHelper back
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
    pub user: AuthResponse, // Renamed UserResponse to AuthResponse
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
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
        .route(
            "/session/{id}",
            get(get_session_handler).delete(delete_session_handler),
        )
        .route("/session/{id}/extend", post(extend_session_handler))
        .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
}

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
    let plaintext_password = payload.password.clone(); // Keep original Secret for KEK derivation

    // Hash the password asynchronously for storage
    // Clone the secret to pass to hash_password, original plaintext_password is moved to create_user
    let _pwd_hash = crate::auth::hash_password(plaintext_password.clone()).await?;

    debug!("Attempting to get DB connection from pool for registration...");
    match pool.get().await {
        Ok(conn) => {
            debug!("Got DB connection. Calling interact for create_user...");
            // Pass the original payload to create_user
            let user_result = conn
                .interact(move |conn_inner| {
                    // Create a new Runtime for the blocking task
                    let rt = tokio::runtime::Runtime::new()
                        .expect("Failed to create runtime in register handler");

                    // Use the runtime to block on the async create_user call
                    rt.block_on(create_user(conn_inner, payload))
                })
                .await;

            match user_result {
                Ok(inner_result) => {
                    debug!("Interact for create_user completed.");
                    match inner_result {
                        Ok(user) => {
                            info!(user_id = %user.id, "User registration successful.");
                            // Use AuthResponse for success
                            // The created user has the recovery phrase that was used
                            let response = AuthResponse {
                                user_id: user.id,
                                username: user.username,
                                email: user.email,
                                role: format!("{:?}", user.role),
                                recovery_key: user.recovery_phrase.clone(), // Get recovery phrase from the returned user
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
                Err(interact_err) => {
                    error!(error = ?interact_err, "Interact error during user creation");
                    Err(AppError::InternalServerErrorGeneric(
                        interact_err.to_string(),
                    ))
                }
            }
        }
        Err(pool_err) => {
            error!(error = ?pool_err, "Failed to get DB connection for registration");
            Err(AppError::DbPoolError(pool_err.to_string()))
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

    // Directly call verify_credentials to get User and DEK
    let verification_result = state
        .pool
        .get()
        .await
        .map_err(|e| {
            error!("Failed to get DB connection for login: {:?}", e);
            AppError::DbPoolError(e.to_string())
        })?
        .interact(move |conn| {
            // Clone password for the closure. Identifier is String, so it's cloned by value.
            auth::verify_credentials(conn, &payload.identifier, payload.password)
        })
        .await
        .map_err(|e| {
            error!("Interact error during credential verification: {:?}", e);
            AppError::InternalServerErrorGeneric(format!(
                "Credential verification process failed: {}",
                e
            ))
        })?;

    debug!("Credential verification successful");

    match verification_result {
        Ok((mut user, maybe_dek_secret_box)) => {
            let user_id = user.id;
            // let login_username = user.username.clone(); // PII
            // let login_email = user.email.clone(); // PII
            info!(%user_id, "Credential verification successful.");

            // Set the DEK on the user object
            let _dek_bytes_for_session = if let Some(dek_secret_box) = maybe_dek_secret_box {
                user.dek = Some(SerializableSecretDek(dek_secret_box)); // Wrap in SerializableSecretDek
                debug!(%user_id, "DEK successfully set on user object before login.");

                // Get the raw bytes for storing directly in the session
                // Access inner SecretBox then expose_secret, or use helper
                let dek_bytes = user.dek.as_ref().unwrap().expose_secret_bytes().to_vec();
                Some(dek_bytes)
            } else {
                info!(%user_id, "No DEK present for this user or login type.");
                None
            };

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

            // Debugging: Log DEK presence before login call
            if let Some(ref wrapped_dek) = user.dek {
                info!(%user_id, "User.dek is PRESENT before auth_session.login() call. Length: {}", wrapped_dek.expose_secret_bytes().len());
            } else {
                warn!(%user_id, "User.dek is MISSING before auth_session.login() call.");
            }

            // Proceed with axum-login's session login
            info!(user_id = %user_id, "Attempting explicit axum-login session.login...");
            auth_session.login(&user).await.map_err(|e| {
                error!(user_id = %user_id, "axum-login session.login() failed: {}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Login process failed for user {}: {}",
                    user_id, e
                ))
            })?;

            // MANUAL FIX: Explicitly insert axum-login.user key with user.id as a string since axum-login.login() appears to not be doing it
            session
                .insert("axum-login.user", user.id.to_string())
                .await
                .map_err(|e| {
                    error!(
                        user_id = %user.id,
                        "Failed to manually insert axum-login.user key into session: {}",
                        e
                    );
                    AppError::SessionError(format!("Failed to store user ID in session: {}", e))
                })?;

            // --- Log session data immediately after axum_session.login() ---
            let axum_login_user_key_after_login = session.get::<String>("axum-login.user").await;
            let dek_session_key_str_after_login = format!("_user_dek_{}", user.id); // Reconstruct for logging
            let our_dek_after_login = session
                .get::<SerializableSecretDek>(&dek_session_key_str_after_login)
                .await;
            info!(
                user_id = %user.id,
                session_id = ?session.id(),
                axum_login_user_key_val = ?axum_login_user_key_after_login,
                our_dek_key_val = ?our_dek_after_login,
                "Session data immediately AFTER auth_session.login() (specific keys)"
            );
            // --- End log ---

            info!(user_id = %user.id, "Explicit auth_session.login successful");

            // Log the session ID AFTER auth_session.login
            debug!(session_id = ?session.id(), user_id = %user_id, "Session ID AFTER axum-login.login() call");

            // Try to explicitly save the session (this might be redundant, but useful for debugging)
            match session.save().await {
                Ok(_) => {
                    debug!(session_id = ?session.id(), user_id = %user_id, "Explicitly called session.save() successfully")
                }
                Err(e) => {
                    error!(session_id = ?session.id(), user_id = %user_id, error = ?e, "Explicit session.save() call failed: {:?}", e)
                }
            }

            // Debugging: Log DEK presence after login call (from auth_session.user)
            if let Some(ref user_after_login) = auth_session.user {
                if let Some(ref wrapped_dek_after_login) = user_after_login.dek {
                    info!(%user_id, "User.dek is PRESENT in auth_session.user AFTER login. Length: {}", wrapped_dek_after_login.expose_secret_bytes().len());
                } else {
                    error!(%user_id, "User.dek is MISSING in auth_session.user AFTER login.");
                }
            } else {
                error!(%user_id, "auth_session.user is NONE after login.");
            }

            // Log the state of the tower_sessions::Session AFTER axum-login has done its work.
            match session.get::<String>("axum-login.user").await {
                Ok(Some(user_session_data_str)) => {
                    debug!(session_id = ?session.id(), user_id = %user_id, "Raw 'axum-login.user' data (as string) after login: {}", user_session_data_str);
                }
                Ok(None) => {
                    warn!(session_id = ?session.id(), user_id = %user_id, "'axum-login.user' key not found in session after login.");
                }
                Err(e) => {
                    // This error means the key was found but couldn't be deserialized into String,
                    // or some other session store error occurred.
                    error!(session_id = ?session.id(), user_id = %user_id, "Error trying to get/deserialize 'axum-login.user' as String from session after login: {:?}. This might indicate the data is not stored as a simple string (e.g., it might be binary).", e);
                }
            }

            // Store the DEK directly in the session.
            if let Some(dek_secret_box) = user.dek {
                info!(user_id = %user.id, "User.dek is PRESENT in auth_session.user AFTER login. Length: {}", dek_secret_box.expose_secret_bytes().len());

                // Use a user-specific key format matching the SessionDek extractor's expectations
                let user_specific_dek_key = format!("_user_dek_{}", user.id);

                // Store the DEK directly - SerializableSecretDek already implements Serialize/Deserialize correctly
                session
                    .insert(&user_specific_dek_key, dek_secret_box) // Use the SerializableSecretDek directly
                    .await
                    .map_err(|e| {
                        error!(
                            user_id = %user.id,
                            "Failed to store DEK in session: {}",
                            e
                        );
                        AppError::SessionError(format!("Failed to store DEK in session: {}", e))
                    })?;

                // --- Log session data immediately after our DEK insert ---
                let axum_login_user_key_val = session.get::<String>("axum-login.user").await;
                let our_dek_key_val = session
                    .get::<SerializableSecretDek>(&user_specific_dek_key)
                    .await;
                info!(
                    user_id = %user.id,
                    session_id = ?session.id(),
                    axum_login_user_key_val = ?axum_login_user_key_val,
                    our_dek_key_val = ?our_dek_key_val,
                    "Session data immediately AFTER our custom DEK insert (specific keys)"
                );
                // --- End log ---

                info!(user_id = %user.id, "Successfully stored DEK directly in session");
            } else {
                warn!(user_id = %user.id, "User has no DEK in database. New account?");
            }

            let response_data = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
                role: format!("{:?}", user.role),
                recovery_key: None, // Login response doesn't include recovery key
            };
            Ok((StatusCode::OK, Json(response_data)).into_response())
        }
        Err(AuthError::WrongCredentials) => {
            warn!("Login failed: Wrong credentials.");
            Err(AppError::Unauthorized(
                "Invalid identifier or password".to_string(),
            ))
        }
        Err(AuthError::AccountLocked) => {
            warn!("Login failed: Account locked.");
            Err(AppError::Unauthorized(
                "Your account is locked. Please contact an administrator.".to_string(),
            ))
        }
        Err(e) => {
            error!(error = ?e, "Login failed due to an unexpected authentication error.");
            // Map other AuthErrors to appropriate AppErrors or a generic internal server error
            match e {
                AuthError::UserNotFound => Err(AppError::Unauthorized(
                    "Invalid identifier or password".to_string(),
                )), // Treat as wrong credentials
                AuthError::HashingError => Err(AppError::PasswordProcessingError), // Use new specific variant
                AuthError::CryptoOperationFailed(_) => Err(AppError::InternalServerErrorGeneric(
                    "Encryption error during login.".to_string(),
                )),
                AuthError::DatabaseError(db_err) => Err(AppError::DatabaseQueryError(db_err)),
                AuthError::PoolError(pool_err) => Err(AppError::DbPoolError(pool_err.to_string())),
                AuthError::InteractError(int_err) => {
                    Err(AppError::InternalServerErrorGeneric(int_err.to_string()))
                }
                _ => Err(AppError::InternalServerErrorGeneric(format!(
                    "An unexpected auth error occurred: {}",
                    e
                ))),
            }
        }
    }
}

#[instrument(skip(auth_session), err)]
pub async fn logout_handler(mut auth_session: CurrentAuthSession) -> Result<Response, AppError> {
    info!("Logout handler entered.");
    if let Some(user) = &auth_session.user {
        info!(user_id = %user.id(), "Attempting to log out user.");
    } else {
        debug!("Logout called, but no user session found in request.");
    }

    debug!("Calling auth_session.logout().await...");
    if let Err(e) = auth_session.logout().await {
        error!(error = ?e, "Failed to destroy session during logout via auth_session.logout(): {:?}", e);
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
            info!(user_id = %user.id, "Returning current user data for /me endpoint.");
            // Use AuthResponse for consistency
            let response = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
                role: format!("{:?}", user.role),
                recovery_key: None, // /me endpoint doesn't return recovery key
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
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Interact error fetching session: {}", e))
        })?;

    match session_info_result {
        Ok((retrieved_session_id, session_json_string, expires_at_opt)) => {
            // Deserialize the session string to get user_id
            let stored_data: StoredSessionData = match serde_json::from_str(&session_json_string) {
                Ok(data) => data,
                Err(e) => {
                    error!(%retrieved_session_id, error = ?e, "Failed to deserialize session JSON string");
                    return Err(AppError::InternalServerErrorGeneric(format!(
                        "Invalid session data format: {}",
                        e
                    )));
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
                    return Err(AppError::InternalServerErrorGeneric(
                        "Session has no expiration time.".to_string(),
                    ));
                }
            };

            debug!(%retrieved_session_id, %user_id, %expires_at, "Session found and parsed. Fetching user details.");

            let user_details_result = pool // Re-acquire pool for the second interact
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?
                .interact(move |conn_user_fetch| {
                    // Renamed conn to avoid conflict in some tracing
                    users::table
                        .filter(users::id.eq(user_id))
                        .select(UserDbQuery::as_select())
                        .first::<UserDbQuery>(conn_user_fetch)
                        .map(User::from)
                })
                .await
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!(
                        "Interact error fetching user for session: {}",
                        e
                    ))
                })?;

            match user_details_result {
                Ok(user) => {
                    let user_response = AuthResponse {
                        user_id: user.id,
                        username: user.username.clone(), // Clone if User.username is String
                        email: user.email.clone(),       // Clone if User.email is String
                        role: format!("{:?}", user.role),
                        recovery_key: None, // Session response doesn't include recovery key
                    };
                    let response = SessionWithUserResponse {
                        session: SessionResponse {
                            id: retrieved_session_id, // Use the ID retrieved from DB
                            user_id,
                            expires_at,
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
                    if let diesel::result::Error::NotFound = e {
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
        .map_err(|e| AppError::BadRequest(format!("Invalid session data: {}", e)))?;

    let user_id = session_json["userId"]
        .as_str()
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
    let authenticated_user = match auth_session.user.clone() {
        Some(u) => u,
        None => {
            warn!("Change password attempt by unauthenticated user.");
            return Err(AppError::Unauthorized("Not logged in".to_string()));
        }
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
    let auth_backend = crate::auth::user_store::Backend::new(state.pool.clone());
    match auth::change_user_password(
        &auth_backend,
        current_db_user.id,
        current_db_user, // Pass the full user object fetched from DB
        payload.current_password,
        payload.new_password,
    )
    .await
    {
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
    let auth_backend = crate::auth::user_store::Backend::new(state.pool.clone());
    match recover_user_password_with_phrase(
        &auth_backend,
        &state.pool,
        payload.identifier.clone(), // identifier is still needed for the function call
        payload.recovery_phrase,
        payload.new_password,
    )
    .await
    {
        Ok(user_id) => {
            info!(%user_id, "Password recovered successfully in core logic.");

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


