use crate::{
    errors::AppError,
    models::lorebook_dtos::{
        AssociateLorebookToChatPayload, CreateLorebookEntryPayload, CreateLorebookPayload,
        UpdateLorebookEntryPayload, UpdateLorebookPayload,
    },
    services::LorebookService,
    AppState,
    auth::user_store::Backend as AuthBackend, // Import AuthBackend
    auth::session_dek::SessionDek, // Import SessionDek
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use axum_login::AuthSession;
use axum_macros::debug_handler;
use tracing::instrument; // Keep instrument
use uuid::Uuid;
use validator::Validate; // For validating payloads

pub fn lorebook_routes() -> Router<AppState> {
    Router::new()
        .route("/lorebooks", post(create_lorebook_handler))
        .route("/lorebooks", get(list_lorebooks_handler))
        .route("/lorebooks/:lorebook_id", get(get_lorebook_handler))
        .route("/lorebooks/:lorebook_id", put(update_lorebook_handler))
        .route(
            "/lorebooks/:lorebook_id",
            delete(delete_lorebook_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/entries",
            post(create_lorebook_entry_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/entries",
            get(list_lorebook_entries_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/entries/:entry_id",
            get(get_lorebook_entry_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/entries/:entry_id",
            put(update_lorebook_entry_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/entries/:entry_id",
            delete(delete_lorebook_entry_handler),
        )
        .route(
            "/chats/:chat_session_id/lorebooks",
            post(associate_lorebook_to_chat_handler),
        )
        .route(
            "/chats/:chat_session_id/lorebooks",
            get(list_chat_lorebook_associations_handler),
        )
        .route(
            "/chats/:chat_session_id/lorebooks/:lorebook_id",
            delete(disassociate_lorebook_from_chat_handler),
        )
}

// --- Lorebook Handlers ---
#[debug_handler]
#[instrument(skip(state, auth_session, payload))]
async fn create_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Json(payload): Json<CreateLorebookPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone()); // Already passing Arc
    let lorebook = lorebook_service
        .create_lorebook(&auth_session, payload)
        .await?;
    Ok((StatusCode::CREATED, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn list_lorebooks_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let lorebooks = lorebook_service.list_lorebooks(&auth_session).await?;
    Ok((StatusCode::OK, Json(lorebooks)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn get_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path(lorebook_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let lorebook = lorebook_service
        .get_lorebook(&auth_session, lorebook_id)
        .await?;
    Ok((StatusCode::OK, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, payload))]
async fn update_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path(lorebook_id): Path<Uuid>,
    Json(payload): Json<UpdateLorebookPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let lorebook = lorebook_service
        .update_lorebook(&auth_session, lorebook_id, payload)
        .await?;
    Ok((StatusCode::OK, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn delete_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path(lorebook_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    lorebook_service
        .delete_lorebook(&auth_session, lorebook_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Lorebook Entry Handlers ---
#[debug_handler]
#[instrument(skip(state, auth_session, payload, dek))]
async fn create_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek, // Add SessionDek extractor
    Path(lorebook_id): Path<Uuid>,
    Json(payload): Json<CreateLorebookEntryPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let entry = lorebook_service
        .create_lorebook_entry(&auth_session, lorebook_id, payload, Some(&dek.0))
        .await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn list_lorebook_entries_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek, // Add SessionDek extractor
    Path(lorebook_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let entries = lorebook_service
        .list_lorebook_entries(&auth_session, lorebook_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entries)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn get_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek, // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let entry = lorebook_service
        .get_lorebook_entry(&auth_session, lorebook_id, entry_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, payload, dek))]
async fn update_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek, // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateLorebookEntryPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let entry = lorebook_service
        .update_lorebook_entry(&auth_session, lorebook_id, entry_id, payload, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn delete_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path((lorebook_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    lorebook_service
        .delete_lorebook_entry(&auth_session, lorebook_id, entry_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Chat Session Lorebook Association Handlers ---
#[debug_handler]
#[instrument(skip(state, auth_session, payload))]
async fn associate_lorebook_to_chat_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path(chat_session_id): Path<Uuid>,
    Json(payload): Json<AssociateLorebookToChatPayload>,
) -> Result<impl IntoResponse, AppError> {
    // payload.validate()?; // Validation removed from DTO for this field
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let association = lorebook_service
        .associate_lorebook_to_chat(&auth_session, chat_session_id, payload)
        .await?;
    Ok((StatusCode::CREATED, Json(association)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn list_chat_lorebook_associations_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path(chat_session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    let associations = lorebook_service
        .list_chat_lorebook_associations(&auth_session, chat_session_id)
        .await?;
    Ok((StatusCode::OK, Json(associations)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn disassociate_lorebook_from_chat_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path((chat_session_id, lorebook_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(state.pool.clone(), state.encryption_service.clone());
    lorebook_service
        .disassociate_lorebook_from_chat(&auth_session, chat_session_id, lorebook_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}