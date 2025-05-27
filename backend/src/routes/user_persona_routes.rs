// backend/src/routes/user_persona_routes.rs

use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::models::user_personas::{
    CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient,
};
use crate::services::encryption_service::EncryptionService;
use crate::services::user_persona_service::UserPersonaService;
use crate::state::AppState;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_login::AuthSession;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

// Type alias for the auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn user_personas_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/",
            post(create_user_persona_handler).get(list_user_personas_handler),
        )
        .route(
            "/:persona_id",
            get(get_user_persona_handler) // GET a specific persona
                .put(update_user_persona_handler) // UPDATE a specific persona
                .delete(delete_user_persona_handler), // DELETE a specific persona
        )
        .with_state(state)
}

#[instrument(skip(state, auth_session, dek, payload), err)]
async fn create_user_persona_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Json(payload): Json<CreateUserPersonaDto>,
) -> Result<(StatusCode, Json<UserPersonaDataForClient>), AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    let enc_service = Arc::new(EncryptionService::new());
    let user_persona_service = UserPersonaService::new(state.pool.clone(), enc_service);

    let created_persona = user_persona_service
        .create_user_persona(&user, &dek.0, payload)
        .await?;

    Ok((StatusCode::CREATED, Json(created_persona)))
}

#[instrument(skip(state, auth_session, dek), err)]
async fn list_user_personas_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
) -> Result<Json<Vec<UserPersonaDataForClient>>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    let enc_service = Arc::new(EncryptionService::new());
    let user_persona_service = UserPersonaService::new(state.pool.clone(), enc_service);

    let personas = user_persona_service
        .list_user_personas(&user, &dek.0)
        .await?;

    Ok(Json(personas))
}

#[instrument(skip(state, auth_session, dek), err)]
async fn get_user_persona_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Path(persona_id): Path<Uuid>,
) -> Result<Json<UserPersonaDataForClient>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    let enc_service = Arc::new(EncryptionService::new());
    let user_persona_service = UserPersonaService::new(state.pool.clone(), enc_service);

    let persona = user_persona_service
        .get_user_persona(&user, Some(&dek.0), persona_id)
        .await?;

    Ok(Json(persona))
}

#[instrument(skip(state, auth_session, dek, payload), err)]
async fn update_user_persona_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Path(persona_id): Path<Uuid>,
    Json(payload): Json<UpdateUserPersonaDto>,
) -> Result<Json<UserPersonaDataForClient>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    let enc_service = Arc::new(EncryptionService::new());
    let user_persona_service = UserPersonaService::new(state.pool.clone(), enc_service);

    let updated_persona = user_persona_service
        .update_user_persona(&user, &dek.0, persona_id, payload)
        .await?;

    Ok(Json(updated_persona))
}

#[instrument(skip(state, auth_session), err)]
async fn delete_user_persona_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(persona_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Note: UserPersonaService::delete_user_persona does not require EncryptionService or DEK
    // as it only verifies ownership and deletes.
    let enc_service = Arc::new(EncryptionService::new()); // Still needed for service instantiation
    let user_persona_service = UserPersonaService::new(state.pool.clone(), enc_service);

    user_persona_service
        .delete_user_persona(&user, persona_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
