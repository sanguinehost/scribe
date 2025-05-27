use axum::{
    Json,
    Router,
    extract::{Path, State},      // Added Path
    http::{Request, StatusCode}, // Added Request
    middleware::{self, Next},    // Added middleware, Next
    response::{IntoResponse, Response},
    routing::{delete, put},
};
use serde::Serialize; // Removed Deserialize as SetDefaultPersonaRequest is removed
use tracing::debug;
use uuid::Uuid; // Added for logging

use crate::{
    // auth::AuthSession, // Replaced by axum_login::AuthSession
    // models::{user_personas::UserPersona, users::User}, // UserPersona is unused
    auth::user_store::Backend as AuthBackend, // Import the backend
    errors::AppError,
    models::users::User,
    services::user_persona_service::UserPersonaService,
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
        DefaultPersonaResponse {
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
            "Persona with ID {} not found for this user.",
            persona_id
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
