use crate::privacy::logging::loggable_user_id;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, put},
    Json, Router,
};
use serde::Deserialize;
use tracing::debug;

use crate::{
    auth::token_auth::UnifiedAuth, errors::AppError,
    models::template_preferences::UpdateTemplatePreferenceRequest,
    services::TemplatePreferenceService, state::AppState,
};

#[derive(Deserialize)]
struct CharacterIdQuery {
    character_id: Option<crate::db::DbId>,
}

/// Logging middleware for template preferences routes
async fn template_preferences_logging_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    debug!(
        method = %req.method(),
        uri = %req.uri(),
        "Template preferences route accessed"
    );
    Ok(next.run(req).await)
}

/// Router for template preferences endpoints
pub fn template_preferences_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(get_template_preferences_handler))
        .route("/", put(update_template_preferences_handler))
        .route("/", delete(delete_template_preferences_handler))
        .layer(middleware::from_fn(template_preferences_logging_middleware))
        .with_state(state)
}

/// GET /api/template-preferences?character_id=:id
/// Gets template preferences for the authenticated user and optional character
#[axum::debug_handler]
async fn get_template_preferences_handler(
    auth: UnifiedAuth,
    State(app_state): State<AppState>,
    Query(query): Query<CharacterIdQuery>,
) -> Result<Response, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %loggable_user_id(user.id), ?query.character_id, "Getting template preferences");

    let preferences = TemplatePreferenceService::get_template_preferences(
        &app_state.pool,
        user.id,
        query.character_id,
    )
    .await?;

    Ok((StatusCode::OK, Json(preferences)).into_response())
}

/// PUT /api/template-preferences?character_id=:id
/// Updates template preferences for the authenticated user and optional character
#[axum::debug_handler]
async fn update_template_preferences_handler(
    auth: UnifiedAuth,
    State(app_state): State<AppState>,
    Query(query): Query<CharacterIdQuery>,
    Json(update_request): Json<UpdateTemplatePreferenceRequest>,
) -> Result<Response, AppError> {
    debug!("=== UPDATE HANDLER ENTERED ===");

    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %loggable_user_id(user.id), ?query.character_id, ?update_request, "Updating template preferences");

    let updated_preferences = TemplatePreferenceService::update_template_preferences(
        &app_state.pool,
        user.id,
        query.character_id,
        update_request,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated_preferences)).into_response())
}

/// DELETE /api/template-preferences?character_id=:id
/// Deletes template preferences for the authenticated user and optional character
#[axum::debug_handler]
async fn delete_template_preferences_handler(
    auth: UnifiedAuth,
    State(app_state): State<AppState>,
    Query(query): Query<CharacterIdQuery>,
) -> Result<Response, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;

    debug!(user_id = %loggable_user_id(user.id), ?query.character_id, "Deleting template preferences");

    TemplatePreferenceService::delete_template_preferences(
        &app_state.pool,
        user.id,
        query.character_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
