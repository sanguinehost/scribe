use crate::auth::{self, recover_user_password_with_phrase, AuthError}; // Added recover_user_password_with_phrase
use crate::db::DbId;
use crate::errors::AppError;
use crate::logging::security_events::SecurityEvent;
use crate::metrics::SECURITY_METRICS;
use crate::models::auth::{
    AuthResponse, ChangePasswordPayload, LoginPayload, RecoverPasswordPayload, RegisterPayload,
}; // Added RecoverPasswordPayload
use crate::models::email_verification::VerifyEmailPayload;
use crate::privacy::ip_anonymization::extract_and_anonymize_ip;
use crate::privacy::logging::loggable_user_id;
use crate::state::{AppState, DbPool}; // Added DbPool import
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Json;
use axum::Router;
use axum_login::{AuthSession, AuthUser, AuthnBackend};
#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};
// For session DEK handling
use crate::auth::session_store::offset_to_utc;
use tower_sessions::Session; // Import tower_sessions::Session // Added for time conversion

use crate::auth::session_dek::SessionDek;
use crate::auth::token_auth::UnifiedAuth;
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
    pub user_id: crate::db::DbId,
    pub expires_at: crate::DbTimestamp,
}

#[derive(Debug, Serialize)]
pub struct SessionWithUserResponse {
    pub session: SessionResponse,
    pub user: AuthResponse,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String, // This is the session_id from tower_sessions
    pub user_id: crate::db::DbId,
    pub expires_at: crate::DbTimestamp,
}

// New response structure for successful login
#[derive(Debug, Serialize)]
pub struct LoginSuccessResponse {
    pub user: AuthResponse,
    pub session_id: String,
    pub expires_at: crate::DbTimestamp,
}

// Desktop-specific request/response types (feature-gated)
#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[derive(Debug, Serialize)]
pub struct DesktopConfigResponse {
    pub setup_complete: bool,
    pub auth_mode: String,       // "quick_start" | "account"
    pub deployment_mode: String, // "local" | "remote"
}

#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[derive(Debug, Deserialize)]
pub struct DesktopSetupPayload {
    pub auth_mode: String, // "quick_start" | "account"
}

#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[derive(Debug, Deserialize)]
pub struct DesktopUpgradeAccountPayload {
    pub username: String,
    pub password: SecretString,
}

pub fn auth_routes() -> Router<AppState> {
    #[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
    {
        Router::new()
            .route("/register", post(register_handler))
            .route("/login", post(login_handler))
            .route("/verify-email", post(verify_email_handler))
            .route("/logout", post(logout_handler))
            .route("/invalidate-session", post(invalidate_session_handler))
            .route("/me", get(me_handler))
            .route("/change-password", post(change_password_handler))
            .route("/recover-password", post(recover_password_handler))
            .route("/session", post(create_session_handler))
            .route("/session/current", get(get_session_handler))
            .route("/session/{id}", delete(delete_session_handler))
            .route("/session/{id}/extend", post(extend_session_handler))
            .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
            // Desktop-specific routes
            .route("/desktop/config", get(get_desktop_config_handler))
            .route("/desktop/setup", post(desktop_setup_handler))
            .route("/desktop/auto-login", get(desktop_auto_login_handler))
            .route(
                "/desktop/upgrade-account",
                post(desktop_upgrade_account_handler),
            )
            // Token-based authentication endpoints
            .route("/token/login", post(token_login_handler))
            .route("/token/refresh", post(token_refresh_handler))
            .route("/token/logout", post(token_logout_handler))
    }

    #[cfg(any(not(feature = "desktop"), feature = "postgres-backend"))]
    {
        Router::new()
            .route("/register", post(register_handler))
            .route("/login", post(login_handler))
            .route("/verify-email", post(verify_email_handler))
            .route("/logout", post(logout_handler))
            .route("/invalidate-session", post(invalidate_session_handler))
            .route("/me", get(me_handler))
            .route("/change-password", post(change_password_handler))
            .route("/recover-password", post(recover_password_handler))
            .route("/session", post(create_session_handler))
            .route("/session/current", get(get_session_handler))
            .route("/session/{id}", delete(delete_session_handler))
            .route("/session/{id}/extend", post(extend_session_handler))
            .route("/user/{id}/sessions", delete(delete_user_sessions_handler))
            // Token-based authentication endpoints (available for all backends)
            .route("/token/login", post(token_login_handler))
            .route("/token/refresh", post(token_refresh_handler))
            .route("/token/logout", post(token_logout_handler))
    }
}

#[instrument(skip(state, payload), err)]
pub async fn verify_email_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailPayload>,
) -> Result<Response, AppError> {
    info!("Email verification handler entered");

    let pool = state.pool.clone();
    let token = payload.token;

    match crate::db::with_conn(&pool, move |conn| {
        auth::verify_email(conn, &token).map_err(AppError::from)
    })
    .await
    {
        Ok(_user) => {
            info!("Email verification successful.");
            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Email verified successfully. You can now log in." })),
            )
                .into_response())
        }
        Err(AppError::BadRequest(_)) => {
            warn!("Email verification failed: Invalid or expired token.");
            Err(AppError::BadRequest(
                "The verification link is invalid or has expired.".to_string(),
            ))
        }
        Err(e) => {
            error!(error = ?e, "Email verification failed");
            Err(e)
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
    let user_result =
        crate::auth::create_user_with_verification(&pool, payload, state.email_service.clone())
            .await;

    match user_result {
        Ok(user) => {
            debug!("User creation with email verification completed.");
            info!(user_id = %loggable_user_id(user.id), "User registration successful.");
            // Use AuthResponse for success
            // The created user has the recovery phrase that was used
            let response = AuthResponse {
                user_id: user.id,
                username: user.username,
                email: Some(user.email),
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
    headers: axum::http::HeaderMap,    // For IP extraction
    Json(payload): Json<LoginPayload>, // Use LoginPayload
) -> Result<Response, AppError> {
    // SECURITY MONITORING: Extract client IP for auth tracking
    let client_ip = extract_and_anonymize_ip(&headers);

    info!(client_ip = %client_ip, "Attempting login");

    // Use axum-login's authenticate method which will call our AuthBackend::authenticate
    // This ensures the DEK is properly cached
    match auth_session.authenticate(payload).await {
        Ok(Some(user)) => {
            let user_id = user.id;
            info!(%user_id, "Authentication successful via AuthBackend.");

            // SECURITY: The DEK is cached in AuthBackend AND persisted in the secure session
            // for multi-instance stability. It is encrypted with the session private key.

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

            // Debugging: User returned from authenticate should have dek populated
            if user.dek.is_none() {
                warn!(%user_id, "DEK was not available/decryptable during login - re-auth might be needed later");
            } else {
                debug!(%user_id, "User.dek is present after authenticate");
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

            // Persist the DEK in the session for multi-instance stability
            if let Some(ref dek) = user.dek {
                if let Err(e) = session.insert("dek", dek).await {
                    error!(%user_id, error = ?e, "Failed to persist DEK in session tracker");
                } else {
                    debug!(%user_id, "DEK persisted in secure session");
                }
            }

            info!(user_id = %user_id, "Login successful via authenticate");

            // SECURITY MONITORING: Record successful authentication
            let user_hash = loggable_user_id(user_id);
            SECURITY_METRICS.record_auth_success(&user_hash.to_string(), &client_ip);

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

            // SECURITY NOTE: The DEK is stored in a separate session key "dek"
            // and is also cached in the server-side AuthBackend.

            // Get session ID and expiry from tower_sessions::Session
            let session_id_str = session.id().map_or_else(
                || {
                    error!(user_id = %loggable_user_id(user.id), "Failed to get session ID after login for response");
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
                error!(user_id = %loggable_user_id(user.id), session_id = %session_id_str, "Failed to convert session expiry to UTC for login response");
                AppError::InternalServerErrorGeneric("Failed to process session expiry for login response.".to_string())
            })?;

            let login_success_response = LoginSuccessResponse {
                user: AuthResponse {
                    user_id: user.id,
                    username: user.username.clone(),
                    email: Some(user.email.clone()),
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
            warn!(client_ip = %client_ip, "Login failed: Wrong credentials.");

            // SECURITY MONITORING: Record authentication failure
            // Use "unknown" for user hash since we don't know the user ID on failed login
            SECURITY_METRICS.record_auth_failure("unknown", &client_ip);

            // Log security event for potential credential stuffing detection
            let security_event = SecurityEvent::AuthFailure {
                timestamp: chrono::Utc::now().into(),
                user_hash: "unknown".to_string(),
                ip_address: client_ip.clone(),
                failure_reason: "wrong_credentials".to_string(),
                attempt_count: 1,
            };

            if let Ok(json) = security_event.to_json() {
                tracing::warn!(event_type = "security_event", severity = "P2", "{}", json);
            }

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
                            warn!(client_ip = %client_ip, "Login failed: Wrong credentials.");

                            // SECURITY MONITORING: Record authentication failure
                            SECURITY_METRICS.record_auth_failure("unknown", &client_ip);

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
                        #[cfg(feature = "postgres-backend")]
                        AuthError::PoolError(pool_err) => {
                            Err(AppError::DbPoolError(pool_err.to_string()))
                        }
                        #[cfg(feature = "sqlite-backend")]
                        AuthError::PoolErrorSqlite(pool_err) => {
                            Err(AppError::DbPoolError(pool_err))
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
                            error!(
                                "Login failed: InvalidVerificationToken encountered during login flow."
                            );
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
    session: Session,
) -> Result<Response, AppError> {
    info!("Logout handler entered.");

    // Remove DEK from cache before logging out
    if let Some(user) = &auth_session.user {
        let user_id = user.id();
        info!(user_id = %user_id, "Attempting to log out user.");

        // Remove the DEK from the AuthBackend cache
        state.auth_backend.remove_dek_from_cache(&user_id).await;

        // Remove DEK from the session
        let _ = session
            .remove::<crate::models::users::SerializableSecretDek>("dek")
            .await;

        info!(user_id = %user_id, "DEK removed from cache and session during logout");
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

/// Explicitly invalidate session cookies by sending Set-Cookie headers with expired dates.
/// This endpoint is called by the frontend to ensure HttpOnly cookies are properly cleared.
///
/// # Errors
/// Returns `AppError` only if critical configuration is missing or invalid.
#[instrument(skip(state), err)]
pub async fn invalidate_session_handler(
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    info!("Invalidate session handler entered.");

    // Build Set-Cookie header to delete the session cookie
    // The cookie name used by tower-sessions is "id" by default
    let cookie_name = "id";
    let mut cookie_value = format!(
        "{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax",
        cookie_name
    );

    // Add Secure flag if configured
    if state.config.session_cookie_secure {
        cookie_value.push_str("; Secure");
    }

    // Add Domain if configured (critical for production environments)
    if let Some(ref domain) = state.config.cookie_domain {
        cookie_value.push_str(&format!("; Domain={}", domain));
        info!(domain = %domain, "Setting cookie deletion with domain");
    } else {
        info!("No cookie domain configured, using default cookie scope");
    }

    debug!(cookie_header = %cookie_value, "Sending Set-Cookie header to invalidate session");

    // Build response with Set-Cookie header
    use axum::http::header;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        cookie_value.parse().map_err(|e| {
            error!(error = ?e, "Failed to parse cookie header value");
            AppError::InternalServerErrorGeneric(
                "Failed to construct cookie deletion header".to_string(),
            )
        })?,
    );

    info!("Session cookie invalidation headers sent successfully");
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

#[instrument(skip(auth), err)]
pub async fn me_handler(auth: UnifiedAuth) -> Result<Response, AppError> {
    info!("Me handler entered.");
    if let Some(user) = auth.user().cloned() {
        info!(user_id = %loggable_user_id(user.id), "Returning current user data for /me endpoint.");
        // Use AuthResponse for consistency
        let response = AuthResponse {
            user_id: user.id,
            username: user.username,
            email: Some(user.email),
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
    auth: UnifiedAuth,
    _dek: SessionDek,
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify user is authenticated
    let user = auth.user().cloned().ok_or_else(|| {
        error!("User not authenticated in create_session_handler");
        AppError::Unauthorized("User not authenticated".to_string())
    })?;

    // Verify the session is being created for the authenticated user
    if user.id != payload.user_id {
        error!(
            "User {:?} attempted to create session for different user {:?}",
            user.id, payload.user_id
        );
        return Err(AppError::Unauthorized(
            "Cannot create session for another user".to_string(),
        ));
    }

    let pool = state.pool.clone();

    // Insert the session into the database
    let session = crate::db::with_conn(&pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::insert_into(sessions::table)
                .values((
                    sessions::id.eq(&payload.id),
                    sessions::expires.eq(payload.expires_at),
                    sessions::session.eq(format!("{{\"userId\":\"{}\"}}", payload.user_id)),
                ))
                .returning((sessions::id, sessions::expires))
                .get_result::<(String, Option<crate::DbTimestamp>)>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING, so we insert and query back
            diesel::insert_into(sessions::table)
                .values((
                    sessions::id.eq(&payload.id),
                    sessions::expires.eq(payload.expires_at),
                    sessions::session.eq(format!("{{\"userId\":\"{}\"}}", payload.user_id)),
                ))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            sessions::table
                .filter(sessions::id.eq(payload.id))
                .select((sessions::id, sessions::expires))
                .first::<(String, Option<crate::DbTimestamp>)>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }
    })
    .await?;

    let session_response = SessionResponse {
        id: session.0,
        user_id: payload.user_id,
        expires_at: session.1.unwrap_or_else(crate::db::DbTimestamp::now),
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
            email: Some(user.email.clone()),
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
    let new_expiry: crate::DbTimestamp = (chrono::Utc::now() + chrono::Duration::days(30)).into();

    let session = crate::db::with_conn(&pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::update(sessions::table)
                .filter(sessions::id.eq(&session_id))
                .set(sessions::expires.eq(new_expiry))
                .returning((sessions::id, sessions::expires, sessions::session))
                .get_result::<(String, Option<crate::DbTimestamp>, String)>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::NotFound("Session not found".to_string())
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING on UPDATE, so we update and query back
            diesel::update(sessions::table)
                .filter(sessions::id.eq(&session_id))
                .set(sessions::expires.eq(new_expiry))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            sessions::table
                .filter(sessions::id.eq(session_id))
                .select((sessions::id, sessions::expires, sessions::session))
                .first::<(String, Option<crate::DbTimestamp>, String)>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::NotFound("Session not found".to_string())
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }
    })
    .await?;

    // Extract user ID from session JSON
    let session_json: crate::DbJson = serde_json::from_str(&session.2)
        .map_err(|e| AppError::BadRequest(format!("Invalid session data: {e}")))?;

    let user_id = session_json["userId"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Invalid session data: missing userId".to_string()))?;

    let user_id = DbId::parse_str(user_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid user ID in session: {e}")))?;

    let session_response = SessionResponse {
        id: session.0,
        user_id,
        expires_at: session.1.unwrap_or_else(crate::db::DbTimestamp::now),
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

    crate::db::with_conn(&pool, move |conn| {
        diesel::delete(sessions::table)
            .filter(sessions::id.eq(session_id))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete all sessions for a user
///
/// # Errors
/// Returns `AppError` if database operations fail or session deletion fails
pub async fn delete_user_sessions_handler(
    State(state): State<AppState>,
    Path(user_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let pool = state.pool.clone();

    // Find all sessions for this user and delete them
    // This is a bit tricky since the userId is stored in the JSON session data
    crate::db::with_conn(&pool, move |conn| {
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
                if let Ok(json) = serde_json::from_str::<crate::DbJson>(&session_data) {
                    // Extract the userId if it exists
                    if let Some(session_user_id) = json["userId"].as_str() {
                        // Check if it matches our target userId
                        if let Ok(parsed_id) = DbId::parse_str(session_user_id) {
                            let parsed_id: crate::db::DbId = parsed_id;
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
    .await?;

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

    let user = crate::db::with_conn(&pool, move |conn| {
        // Call the refactored function from auth module
        crate::auth::get_user(conn, user_id).map_err(AppError::from)
    })
    .await?;

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
    let current_db_user = crate::db::with_conn(&state.pool, move |conn| {
        crate::auth::get_user(conn, authenticated_user.id).map_err(AppError::from)
    })
    .await?;

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

// Desktop-specific handlers (feature-gated)
#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[instrument(err)]
pub async fn get_desktop_config_handler() -> Result<Response, AppError> {
    info!("Desktop config handler entered");

    let config = crate::desktop::load_desktop_config()?;

    let response = DesktopConfigResponse {
        setup_complete: config.setup_complete,
        auth_mode: match config.auth_mode {
            Some(crate::desktop::AuthMode::QuickStart) => "quick_start".to_string(),
            Some(crate::desktop::AuthMode::Account) => "account".to_string(),
            None => "not_set".to_string(),
        },
        deployment_mode: match config.deployment_mode {
            crate::desktop::DeploymentMode::Local => "local".to_string(),
            crate::desktop::DeploymentMode::Remote => "remote".to_string(),
        },
    };

    Ok(Json(response).into_response())
}

#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[instrument(skip(state, auth_session, session, payload), err)]
pub async fn desktop_setup_handler(
    State(state): State<AppState>,
    mut auth_session: CurrentAuthSession,
    session: Session,
    Json(payload): Json<DesktopSetupPayload>,
) -> Result<Response, AppError> {
    info!("🔧 Desktop setup handler entered");
    info!("📝 Requested auth_mode: {}", payload.auth_mode);

    // Parse auth mode
    let auth_mode = match payload.auth_mode.as_str() {
        "quick_start" => {
            info!("✅ Parsed auth_mode: QuickStart");
            crate::desktop::AuthMode::QuickStart
        }
        "account" => {
            info!("✅ Parsed auth_mode: Account");
            crate::desktop::AuthMode::Account
        }
        _ => {
            error!("❌ Invalid auth_mode received: {}", payload.auth_mode);
            return Err(AppError::BadRequest(
                "Invalid auth_mode. Must be 'quick_start' or 'account'".to_string(),
            ));
        }
    };

    // Save auth mode to config
    info!("💾 Saving auth_mode to desktop config...");
    if let Err(e) = crate::desktop::set_auth_mode(auth_mode) {
        error!("❌ Failed to save auth_mode: {:?}", e);
        return Err(e);
    }
    info!("✅ Auth mode saved successfully");

    info!("💾 Marking setup as complete...");
    if let Err(e) = crate::desktop::mark_setup_complete() {
        error!("❌ Failed to mark setup complete: {:?}", e);
        return Err(e);
    }
    info!("✅ Setup marked as complete");

    info!("🎉 Desktop setup complete with mode: {:?}", auth_mode);

    // If Quick Start mode, create default user and auto-login
    if matches!(auth_mode, crate::desktop::AuthMode::QuickStart) {
        info!("👤 Quick Start mode selected - creating default user and auto-logging in");

        // Ensure default user exists
        // Get a connection using the pool helper (handles async/sync difference)
        info!("🔌 Getting database connection...");
        let mut conn = match crate::db::get_conn(&state.pool).await {
            Ok(c) => {
                info!("✅ Database connection acquired");
                c
            }
            Err(e) => {
                error!("❌ Failed to get database connection: {:?}", e);
                return Err(e);
            }
        };

        info!("🏭 Creating/loading default user...");
        let user = match crate::desktop::ensure_default_user_exists(&mut *conn).await {
            Ok(u) => {
                info!(
                    "✅ Default user ready: id={}, username={}",
                    u.id, u.username
                );
                u
            }
            Err(e) => {
                error!("❌ Failed to create/load default user: {:?}", e);
                return Err(e);
            }
        };

        info!("🔐 Establishing session for user {}...", user.id);

        // Log the user in
        if let Err(e) = auth_session.login(&user).await {
            error!("❌ Failed to log in default user {}: {:?}", user.id, e);
            return Err(AppError::InternalServerErrorGeneric(format!(
                "Failed to establish session for default user: {}",
                e
            )));
        }
        info!("✅ Session established successfully");

        // Rotate session ID to prevent session fixation
        info!("🔄 Rotating session ID...");
        if let Err(e) = session.cycle_id().await {
            error!(
                "❌ Failed to rotate session ID for user {}: {:?}",
                user.id, e
            );
            return Err(AppError::InternalServerErrorGeneric(format!(
                "Failed to rotate session ID: {}",
                e
            )));
        }
        info!("✅ Session ID rotated");

        info!("🎉 Default user auto-login successful for user {}", user.id);

        // Get session details for response
        let session_id_str = session.id().map_or_else(
            || "error_retrieving_session_id".to_string(),
            |id| id.0.to_string(),
        );

        let expires_at_utc = offset_to_utc(Some(session.expiry_date())).ok_or_else(|| {
            AppError::InternalServerErrorGeneric("Failed to process session expiry".to_string())
        })?;

        let response = LoginSuccessResponse {
            user: AuthResponse {
                user_id: user.id,
                username: user.username,
                email: Some(user.email),
                role: format!("{:?}", user.role),
                recovery_key: None,
                default_persona_id: user.default_persona_id,
            },
            session_id: session_id_str,
            expires_at: expires_at_utc,
        };

        Ok((StatusCode::OK, Json(response)).into_response())
    } else {
        // Account mode - setup complete, user will need to register/login
        Ok((
            StatusCode::OK,
            Json(json!({
                "message": "Setup complete. Please create an account to continue.",
                "setup_complete": true
            })),
        )
            .into_response())
    }
}

#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[instrument(skip(state), err)]
pub async fn desktop_auto_login_handler(
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    info!("Desktop auto-login handler entered");

    // Check if Quick Start mode is enabled
    let auth_mode = crate::desktop::get_auth_mode()?;
    if !matches!(auth_mode, Some(crate::desktop::AuthMode::QuickStart)) {
        return Err(AppError::Forbidden(
            "Auto-login is only available in Quick Start mode".to_string(),
        ));
    }

    // Get or create default user
    let pool = state.pool.clone();
    // Attempt to load user from config ID first
    let user_from_config = if let Some(id) = crate::desktop::get_default_user_id()? {
        debug!(?id, "Found default user ID in config, verifying existence");
        let pool_clone = pool.clone();
        crate::db::with_conn(&pool_clone, move |conn| {
            crate::auth::get_user(conn, id).map(Some).or_else(|e| {
                if matches!(e, AuthError::UserNotFound) {
                    Ok(None)
                } else {
                    Err(AppError::from(e))
                }
            })
        })
        .await?
    } else {
        None
    };

    let user = if let Some(u) = user_from_config {
        u
    } else {
        info!("No valid default user ID in config, checking if 'quickstart_user' exists by name");
        let pool_clone = pool.clone();
        let existing_user_opt = crate::db::with_conn(&pool_clone, move |conn| {
            crate::auth::get_user_by_username(conn, "quickstart_user")
                .map(Some)
                .or_else(|e| {
                    if matches!(e, AuthError::UserNotFound) {
                        Ok(None)
                    } else {
                        Err(AppError::from(e))
                    }
                })
        })
        .await?;

        if let Some(u) = existing_user_opt {
            info!(?u.id, "Found existing quickstart_user, updating config");
            crate::desktop::set_default_user_id(u.id)?;
            u
        } else {
            info!("No quickstart_user found in database, creating new user");
            // Create default user
            let user_db = crate::auth::user_store::create_user_in_db(
                &pool,
                "quickstart_user",
                "default_password_12345",
                "quickstart@localhost",
                None,
            )
            .await
            .map_err(|e| {
                error!("Failed to create default user: {}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to create default user: {}",
                    e
                ))
            })?;

            // Save user ID to config
            let user_id = user_db.id;
            crate::desktop::set_default_user_id(user_id)?;
            info!(
                ?user_id,
                "Created and saved default user for Quick Start mode"
            );

            // Load the newly created user
            let pool_clone = pool.clone();
            crate::db::with_conn(&pool_clone, move |conn| {
                crate::auth::get_user(conn, user_id).map_err(AppError::from)
            })
            .await?
        }
    };

    debug!(user_id = %loggable_user_id(user.id), "Using default user for auto-login");

    // For desktop mode, generate JWT tokens directly (no session-based auth needed)
    // Get the token service
    let token_service = state.token_service.as_ref().ok_or_else(|| {
        error!("Token service not available for desktop auto-login");
        AppError::InternalServerErrorGeneric("Token authentication not configured".to_string())
    })?;

    // Generate token pair for the user
    let token_pair = token_service.generate_token_pair(user.id).map_err(|e| {
        error!(user_id = %loggable_user_id(user.id), error = ?e, "Failed to generate token pair for auto-login");
        AppError::InternalServerErrorGeneric("Token generation failed".to_string())
    })?;

    // Get or generate DEK for Quick Start mode
    // IMPORTANT: DEK must be persisted to decrypt data across sessions
    let dek_b64 = match crate::desktop::get_quick_start_dek()? {
        Some(existing_dek) => {
            info!(user_id = %loggable_user_id(user.id), "Using existing persisted DEK for Quick Start mode");
            existing_dek
        }
        None => {
            info!(user_id = %loggable_user_id(user.id), "No persisted DEK found, generating new one");
            // Generate new DEK
            let dek_secret = crate::crypto::generate_dek().map_err(|e| {
                error!(user_id = %loggable_user_id(user.id), error = ?e, "Failed to generate DEK for Quick Start mode");
                AppError::InternalServerErrorGeneric("DEK generation failed".to_string())
            })?;

            // Base64-encode the DEK for transmission
            let dek_bytes = dek_secret.expose_secret();
            let new_dek_b64 = BASE64.encode(dek_bytes);

            // Persist the DEK for future auto-logins
            crate::desktop::set_quick_start_dek(new_dek_b64.clone())?;
            info!(user_id = %loggable_user_id(user.id), "Generated and persisted new DEK for Quick Start mode");

            new_dek_b64
        }
    };

    // Return JWT token response with DEK
    let response = TokenLoginResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        expires_in: token_pair.expires_in,
        user: AuthResponse {
            user_id: user.id,
            username: user.username.clone(),
            email: Some(user.email.clone()),
            role: format!("{:?}", user.role),
            recovery_key: None,
            default_persona_id: user.default_persona_id,
        },
        dek: Some(dek_b64),
    };

    info!(user_id = %loggable_user_id(user.id), "Auto-login JWT tokens generated successfully with DEK");
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(all(feature = "desktop", not(feature = "postgres-backend")))]
#[instrument(skip(state, auth_session, payload), err)]
pub async fn desktop_upgrade_account_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<DesktopUpgradeAccountPayload>,
) -> Result<Response, AppError> {
    info!("Desktop upgrade account handler entered");

    // Ensure user is authenticated
    let authenticated_user = auth_session.user.ok_or_else(|| {
        AppError::Unauthorized("Must be logged in to upgrade account".to_string())
    })?;

    // Check if Quick Start mode is active
    let auth_mode = crate::desktop::get_auth_mode()?;
    if !matches!(auth_mode, Some(crate::desktop::AuthMode::QuickStart)) {
        return Err(AppError::BadRequest(
            "Account upgrade is only available in Quick Start mode".to_string(),
        ));
    }

    info!(user_id = %authenticated_user.id, "Upgrading Quick Start user to full account");

    // Hash the new password
    let password_hash = crate::auth::hash_password(payload.password)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to hash password during account upgrade");
            AppError::PasswordProcessingError
        })?;

    // Update the user's credentials in the database
    let pool = state.pool.clone();
    let user_id = authenticated_user.id;
    let new_username = payload.username.clone();

    crate::db::with_conn(&pool, move |conn| {
        use crate::schema::users;
        use diesel::prelude::*;

        diesel::update(users::table.find(user_id))
            .set((
                users::username.eq(new_username),
                users::password_hash.eq(password_hash.as_str()),
            ))
            .execute(conn)
            .map_err(|e| {
                error!(error = ?e, "Failed to update user credentials during upgrade");
                AppError::DatabaseQueryError(e.to_string())
            })
    })
    .await?;

    // Switch to Account mode
    crate::desktop::set_auth_mode(crate::desktop::AuthMode::Account)?;

    info!(user_id = %authenticated_user.id, "Account upgrade successful, switched to Account mode");

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Account upgraded successfully. Please log in with your new credentials.",
            "auth_mode": "account"
        })),
    )
        .into_response())
}

// ========================= TOKEN AUTHENTICATION ENDPOINTS =========================
// These endpoints provide JWT token-based authentication for the desktop application
// They work alongside the existing cookie-based auth for web clients

/// Request payload for token-based login
#[derive(Debug, Deserialize)]
pub struct TokenLoginRequest {
    pub identifier: String, // Username or email
    pub password: SecretString,
}

/// Response payload for successful token login
#[derive(Debug, Serialize)]
pub struct TokenLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64, // seconds until access token expires
    pub user: AuthResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dek: Option<String>, // Base64-encoded DEK for Quick Start mode
}

/// Request payload for token refresh
#[derive(Debug, Deserialize)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

/// Response payload for successful token refresh
#[derive(Debug, Serialize)]
pub struct TokenRefreshResponse {
    pub access_token: String,
    pub expires_in: i64, // seconds until access token expires
}

/// Token-based login handler for desktop application
/// This endpoint exchanges credentials for a JWT token pair (access + refresh)
#[instrument(skip(state, payload), err)]
pub async fn token_login_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<TokenLoginRequest>,
) -> Result<Response, AppError> {
    let client_ip = extract_and_anonymize_ip(&headers);
    info!(client_ip = %client_ip, "Attempting token-based login");

    // Get the token service
    let token_service = state.token_service.as_ref().ok_or_else(|| {
        error!("Token service not available");
        AppError::InternalServerErrorGeneric("Token authentication not configured".to_string())
    })?;

    // Convert TokenLoginRequest to LoginPayload for authentication
    let login_payload = LoginPayload {
        identifier: payload.identifier.clone(),
        password: payload.password,
    };

    // Authenticate the user using the existing auth backend
    let _pool = state.pool.clone();
    let auth_backend = state.auth_backend.clone();

    // Use the authenticate method from AuthBackend
    match auth_backend.authenticate(login_payload).await {
        Ok(Some(user)) => {
            let user_id = user.id;
            info!(%user_id, "Token authentication successful");

            // Generate a session ID for this token session
            let _session_id = Uuid::new_v4().to_string();

            // Generate token pair
            let token_pair = token_service.generate_token_pair(user_id).map_err(|e| {
                error!(%user_id, error = ?e, "Failed to generate token pair");
                AppError::InternalServerErrorGeneric("Token generation failed".to_string())
            })?;

            // Record successful authentication
            let user_hash = loggable_user_id(user_id);
            SECURITY_METRICS.record_auth_success(&user_hash.to_string(), &client_ip);

            let response = TokenLoginResponse {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                expires_in: token_pair.expires_in,
                user: AuthResponse {
                    user_id: user.id,
                    username: user.username,
                    email: Some(user.email),
                    role: format!("{:?}", user.role),
                    recovery_key: None,
                    default_persona_id: user.default_persona_id,
                },
                dek: None, // DEK only included for desktop Quick Start mode
            };

            Ok((StatusCode::OK, Json(response)).into_response())
        }
        Ok(None) => {
            warn!(client_ip = %client_ip, "Token login failed: Wrong credentials");
            SECURITY_METRICS.record_auth_failure("unknown", &client_ip);
            Err(AppError::Unauthorized(
                "Invalid identifier or password".to_string(),
            ))
        }
        Err(auth_err) => {
            error!(error = ?auth_err, "Token login failed due to authentication error");
            // The error is already AuthError directly, not wrapped
            match auth_err {
                AuthError::WrongCredentials | AuthError::UserNotFound => {
                    warn!(client_ip = %client_ip, "Token login failed: Wrong credentials");
                    SECURITY_METRICS.record_auth_failure("unknown", &client_ip);
                    Err(AppError::Unauthorized(
                        "Invalid identifier or password".to_string(),
                    ))
                }
                AuthError::AccountLocked => Err(AppError::Unauthorized(
                    "Your account is locked. Please contact an administrator.".to_string(),
                )),
                AuthError::AccountPendingVerification => Err(AppError::Forbidden(
                    "Your account is pending email verification.".to_string(),
                )),
                _ => Err(AppError::InternalServerErrorGeneric(
                    "Authentication error".to_string(),
                )),
            }
        }
    }
}

/// Token refresh handler for desktop application
/// This endpoint exchanges a valid refresh token for a new access token
#[instrument(skip(state, payload), err)]
pub async fn token_refresh_handler(
    State(state): State<AppState>,
    Json(payload): Json<TokenRefreshRequest>,
) -> Result<Response, AppError> {
    info!("Attempting token refresh");

    // Get the token service
    let token_service = state.token_service.as_ref().ok_or_else(|| {
        error!("Token service not available");
        AppError::InternalServerErrorGeneric("Token authentication not configured".to_string())
    })?;

    // Refresh the access token
    let new_access_token = token_service
        .refresh_access_token(&payload.refresh_token)
        .map_err(|e| {
            warn!(error = ?e, "Token refresh failed");
            e
        })?;

    // Get token duration from service (15 minutes by default)
    let expires_in = 15 * 60; // 15 minutes in seconds

    let response = TokenRefreshResponse {
        access_token: new_access_token,
        expires_in,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Token logout handler (informational only)
/// Since JWTs are stateless, this endpoint simply confirms logout
/// The client should discard the tokens locally
#[instrument(skip(_state), err)]
pub async fn token_logout_handler(State(_state): State<AppState>) -> Result<Response, AppError> {
    info!("Token logout requested");

    // For stateless JWT tokens, logout is handled client-side
    // This endpoint exists for API completeness and logging
    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Logout successful. Please discard your tokens."
        })),
    )
        .into_response())
}
