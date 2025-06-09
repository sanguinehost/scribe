#![allow(clippy::items_after_statements)]
use axum::{
    Json,
    Router,
    extract::{Path, State},      // Added Path
    http::{Request, StatusCode}, // Added Request
    middleware::{self, Next},    // Added middleware, Next
    response::{IntoResponse, Response},
    routing::{delete, get, put},
};
use serde::Serialize; // Removed Deserialize as SetDefaultPersonaRequest is removed
use tracing::debug;
use uuid::Uuid; // Added for logging

use crate::{
    // auth::AuthSession, // Replaced by axum_login::AuthSession
    // models::{user_personas::UserPersona, users::User}, // UserPersona is unused
    auth::user_store::Backend as AuthBackend, // Import the backend
    errors::AppError,
    models::{user_settings::UpdateUserSettingsRequest, users::User},
    services::{
        user_persona_service::UserPersonaService, user_settings_service::UserSettingsService,
    },
    state::AppState,
};
use axum_login::AuthSession; // Correct import for AuthSession

// SetDefaultPersonaRequest struct removed as persona_id is now from path

#[derive(Serialize, Debug)]
pub struct DefaultPersonaResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub default_persona_id: Option<Uuid>,
}

impl From<User> for DefaultPersonaResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            default_persona_id: user.default_persona_id,
        }
    }
}

async fn user_settings_logging_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    debug!("Request to user_settings_routes: {}", path);
    next.run(request).await
}

pub fn user_settings_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(get_user_settings_handler))
        .route("/", put(update_user_settings_handler))
        .route("/", delete(delete_user_settings_handler))
        .route(
            "/set_default_persona/:persona_id",
            put(set_default_persona_handler),
        ) // Changed path to be more explicit and distinct
        .route(
            "/clear_default_persona",
            delete(clear_default_persona_handler),
        ) // Changed path for consistency and explicitness and distinctness
        .layer(middleware::from_fn(user_settings_logging_middleware)) // Add logging middleware
        .with_state(state)
}

#[axum::debug_handler]
async fn get_user_settings_handler(
    auth_session: AuthSession<AuthBackend>,
    State(app_state): State<AppState>,
) -> Result<Response, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %user.id, "Getting user settings");

    let settings =
        UserSettingsService::get_user_settings(&app_state.pool, user.id, &app_state.config).await?;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

#[axum::debug_handler]
async fn update_user_settings_handler(
    auth_session: AuthSession<AuthBackend>,
    State(app_state): State<AppState>,
    Json(update_request): Json<UpdateUserSettingsRequest>,
) -> Result<Response, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %user.id, "Updating user settings");

    let updated_settings = UserSettingsService::update_user_settings(
        &app_state.pool,
        user.id,
        update_request,
        &app_state.config,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated_settings)).into_response())
}

#[axum::debug_handler]
async fn delete_user_settings_handler(
    auth_session: AuthSession<AuthBackend>,
    State(app_state): State<AppState>,
) -> Result<Response, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %user.id, "Deleting user settings (reset to defaults)");

    UserSettingsService::delete_user_settings(&app_state.pool, user.id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[axum::debug_handler]
async fn set_default_persona_handler(
    auth_session: AuthSession<AuthBackend>,
    State(app_state): State<AppState>,
    Path(persona_id): Path<Uuid>, // Changed from Json(payload)
) -> Result<Response, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;
    debug!(user_id = %user.id, %persona_id, "Attempting to set default persona");

    // Verify the user owns the persona
    let persona_lookup_result = UserPersonaService::get_user_persona_by_id_and_user_id(
        &app_state.pool,
        persona_id, // Use persona_id from path
        user.id,
    )
    .await;

    debug!(
        ?persona_lookup_result,
        "Result of get_user_persona_by_id_and_user_id"
    );

    persona_lookup_result?.ok_or_else(|| {
        AppError::NotFound(format!(
            "Persona with ID {persona_id} not found for this user."
        ))
    })?;

    let updated_user = UserPersonaService::set_default_persona(
        &app_state.pool,
        user.id,
        Some(persona_id), // Use persona_id from path
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(DefaultPersonaResponse::from(updated_user)),
    )
        .into_response())
}

#[axum::debug_handler]
async fn clear_default_persona_handler(
    auth_session: AuthSession<AuthBackend>,
    State(app_state): State<AppState>,
) -> Result<Response, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    UserPersonaService::set_default_persona(&app_state.pool, user.id, None).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// TODO: Add tests for these handlers in a new file backend/tests/user_settings_api_tests.rs
// TODO: Add set_default_persona to UserPersonaService
// TODO: Modify GET /api/auth/me to include default_persona_id
