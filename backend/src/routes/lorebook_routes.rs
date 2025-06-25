#![allow(clippy::items_after_statements)]
use crate::{
    AppState,
    auth::session_dek::SessionDek,            // Import SessionDek
    auth::user_store::Backend as AuthBackend, // Import AuthBackend
    errors::AppError,
    models::lorebook_dtos::{
        AssociateLorebookToChatPayload, CharacterLorebookOverrideResponse,
        ChatLorebookAssociationsResponse, CreateLorebookEntryPayload, CreateLorebookPayload,
        ExportFormat, SetCharacterLorebookOverridePayload, UpdateLorebookEntryPayload,
        UpdateLorebookPayload,
    },
    services::LorebookService,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use axum_login::AuthSession;
use axum_macros::debug_handler;
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument; // Keep instrument
use uuid::Uuid;
use validator::Validate; // For validating payloads


pub fn lorebook_routes() -> Router<AppState> {
    Router::new()
        .route("/lorebooks", post(create_lorebook_handler))
        .route("/lorebooks", get(list_lorebooks_handler))
        .route("/lorebooks/import", post(import_lorebook_handler))
        .route("/lorebooks/:lorebook_id", get(get_lorebook_handler))
        .route("/lorebooks/:lorebook_id", put(update_lorebook_handler))
        .route("/lorebooks/:lorebook_id", delete(delete_lorebook_handler))
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
        .route(
            "/lorebooks/:lorebook_id/fetch/associated_chats", // Made path more distinct
            get(list_associated_chat_sessions_for_lorebook_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/export",
            get(export_lorebook_handler),
        )
        // Character lorebook override routes
        .route(
            "/chats/:chat_session_id/lorebooks/:lorebook_id/override",
            put(set_character_lorebook_override_handler),
        )
        .route(
            "/chats/:chat_session_id/lorebooks/:lorebook_id/override",
            delete(remove_character_lorebook_override_handler),
        )
        .route(
            "/chats/:chat_session_id/lorebook-overrides",
            get(get_character_lorebook_overrides_handler),
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    ); // Added qdrant service
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
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
    dek: SessionDek,                        // Add SessionDek extractor
    Path(lorebook_id): Path<Uuid>,
    Json(payload): Json<CreateLorebookEntryPayload>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(
        "create_lorebook_entry_handler called for lorebook_id: {}, payload: {:?}",
        lorebook_id,
        payload
    );
    payload.validate()?;
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let entry = lorebook_service
        .create_lorebook_entry(
            &auth_session,
            lorebook_id,
            payload,
            Some(&dek.0),
            state.clone().into(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn list_lorebook_entries_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek,                        // Add SessionDek extractor
    Path(lorebook_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let entries = lorebook_service
        .list_lorebook_entries_with_content(&auth_session, lorebook_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entries)))
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn get_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    dek: SessionDek,                        // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
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
    dek: SessionDek,                        // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateLorebookEntryPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let entry = lorebook_service
        .update_lorebook_entry(
            &auth_session,
            lorebook_id,
            entry_id,
            payload,
            Some(&dek.0),
            state.clone().into(),
        )
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
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    lorebook_service
        .delete_lorebook_entry(&auth_session, lorebook_id, entry_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Chat Session Lorebook Association Handlers ---
#[debug_handler]
#[instrument(skip(state, auth_session, payload, dek))]
async fn associate_lorebook_to_chat_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    dek: SessionDek, // Add SessionDek extractor
    Path(chat_session_id): Path<Uuid>,
    Json(payload): Json<AssociateLorebookToChatPayload>,
) -> Result<impl IntoResponse, AppError> {
    // payload.validate()?; // Validation removed from DTO for this field
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let association = lorebook_service
        .associate_lorebook_to_chat(
            &auth_session,
            chat_session_id,
            payload,
            Some(&dek.0),
            state.clone().into(),
        )
        .await?;
    Ok((StatusCode::OK, Json(association)))
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn list_chat_lorebook_associations_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(chat_session_id): Path<Uuid>,
    Query(params): Query<LorebookAssociationsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    if params.include_source {
        let enhanced_associations = lorebook_service
            .list_enhanced_chat_lorebook_associations(&auth_session, chat_session_id)
            .await?;
        Ok((
            StatusCode::OK,
            Json(ChatLorebookAssociationsResponse::Enhanced(
                enhanced_associations,
            )),
        ))
    } else {
        let associations = lorebook_service
            .list_chat_lorebook_associations(&auth_session, chat_session_id)
            .await?;
        Ok((
            StatusCode::OK,
            Json(ChatLorebookAssociationsResponse::Basic(associations)),
        ))
    }
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn disassociate_lorebook_from_chat_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>, // Changed to AuthBackend
    Path((chat_session_id, lorebook_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    lorebook_service
        .disassociate_lorebook_from_chat(&auth_session, chat_session_id, lorebook_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn list_associated_chat_sessions_for_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    dek: SessionDek, // Add SessionDek extractor
    Path(lorebook_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let chat_sessions = lorebook_service
        .list_associated_chat_sessions_for_lorebook(&auth_session, lorebook_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(chat_sessions)))
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    #[serde(default = "default_export_format")]
    format: ExportFormat,
}

#[derive(Debug, Deserialize)]
struct LorebookAssociationsQuery {
    #[serde(default)]
    include_source: bool,
}

fn default_export_format() -> ExportFormat {
    ExportFormat::SillyTavernFull
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek))]
async fn export_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    dek: SessionDek,
    Path(lorebook_id): Path<Uuid>,
    Query(params): Query<ExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    let response: Result<axum::response::Response, AppError> = match params.format {
        ExportFormat::ScribeMinimal => {
            let exported = lorebook_service
                .export_lorebook_minimal(&auth_session, Some(&dek.0), lorebook_id)
                .await?;
            Ok((StatusCode::OK, Json(exported)).into_response())
        }
        ExportFormat::SillyTavernFull => {
            let exported = lorebook_service
                .export_lorebook(&auth_session, Some(&dek.0), lorebook_id)
                .await?;
            Ok((StatusCode::OK, Json(exported)).into_response())
        }
    };
    response
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportFormat {
    ScribeMinimal,
    SillyTavernFull,
}

#[derive(Debug, Deserialize)]
struct ImportQuery {
    #[serde(default = "default_import_format")]
    format: ImportFormat,
}

fn default_import_format() -> ImportFormat {
    ImportFormat::SillyTavernFull
}

#[debug_handler]
#[instrument(skip(state, auth_session, dek, payload, params))]
async fn import_lorebook_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    dek: SessionDek,
    Query(params): Query<ImportQuery>,
    Json(payload): Json<serde_json::Value>, // Accept generic JSON for dynamic deserialization
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    let response: Result<axum::response::Response, AppError> = match params.format {
        ImportFormat::ScribeMinimal => {
            let scribe_payload: crate::models::lorebook_dtos::ScribeMinimalLorebook =
                serde_json::from_value(payload).map_err(|e| {
                    AppError::BadRequest(format!("Invalid Scribe Minimal payload: {}", e))
                })?;

            // No validation needed for ScribeMinimalLorebook as it's a simple DTO

            let imported_lorebook = lorebook_service
                .import_lorebook_from_scribe_minimal(
                    &auth_session,
                    Some(&dek.0),
                    scribe_payload,
                    state.clone().into(),
                )
                .await?;
            Ok((StatusCode::CREATED, Json(imported_lorebook)).into_response())
        }
        ImportFormat::SillyTavernFull => {
            // Try to detect the format dynamically
            // If "entries" is an array, it's actually a Scribe format
            // If "entries" is an object with string keys, it's SillyTavern format

            if let Some(entries) = payload.get("entries") {
                if entries.is_array() {
                    // This is actually a Scribe format, not SillyTavern
                    let scribe_payload: crate::models::lorebook_dtos::ScribeMinimalLorebook =
                        serde_json::from_value(payload).map_err(|e| {
                            AppError::BadRequest(format!("Invalid lorebook format: {}", e))
                        })?;

                    let imported_lorebook = lorebook_service
                        .import_lorebook_from_scribe_minimal(
                            &auth_session,
                            Some(&dek.0),
                            scribe_payload,
                            state.clone().into(),
                        )
                        .await?;
                    Ok((StatusCode::CREATED, Json(imported_lorebook)).into_response())
                } else if entries.is_object() {
                    // This is SillyTavern format
                    let sillytavern_import_payload: crate::models::lorebook_dtos::SillyTavernImportPayload =
                        serde_json::from_value(payload)
                            .map_err(|e| AppError::BadRequest(format!("Invalid SillyTavern Full payload: {}", e)))?;

                    // Construct LorebookUploadPayload from SillyTavernImportPayload
                    let lorebook_name = sillytavern_import_payload
                        .name
                        .unwrap_or_else(|| "Imported Lorebook".to_string());
                    let lorebook_description = sillytavern_import_payload.description;
                    let lorebook_is_public = sillytavern_import_payload.is_public.unwrap_or(false); // Default to false

                    let lorebook_upload_payload =
                        crate::models::lorebook_dtos::LorebookUploadPayload {
                            name: lorebook_name,
                            description: lorebook_description,
                            is_public: lorebook_is_public,
                            entries: sillytavern_import_payload.entries,
                        };

                    lorebook_upload_payload.validate()?; // Validate the constructed payload

                    let imported_lorebook = lorebook_service
                        .import_lorebook(
                            &auth_session,
                            Some(&dek.0),
                            lorebook_upload_payload,
                            Arc::new(state.clone()),
                        )
                        .await?;
                    Ok((StatusCode::CREATED, Json(imported_lorebook)).into_response())
                } else {
                    Err(AppError::BadRequest(
                        "Invalid entries field: must be either an array or object".to_string(),
                    ))
                }
            } else {
                Err(AppError::BadRequest(
                    "Missing entries field in lorebook data".to_string(),
                ))
            }
        }
    };
    response
}

// --- Character Lorebook Override Handlers ---

#[debug_handler]
#[instrument(skip(state, auth_session, payload))]
async fn set_character_lorebook_override_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path((chat_session_id, lorebook_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<SetCharacterLorebookOverridePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    lorebook_service
        .set_character_lorebook_override(
            &auth_session,
            chat_session_id,
            lorebook_id,
            payload.action,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn remove_character_lorebook_override_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path((chat_session_id, lorebook_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    lorebook_service
        .remove_character_lorebook_override(&auth_session, chat_session_id, lorebook_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth_session))]
async fn get_character_lorebook_overrides_handler(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(chat_session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    let overrides = lorebook_service
        .get_character_lorebook_overrides(&auth_session, chat_session_id)
        .await?;

    // Convert model to response DTO
    let response: Vec<CharacterLorebookOverrideResponse> = overrides
        .into_iter()
        .map(|override_model| CharacterLorebookOverrideResponse {
            id: override_model.id,
            chat_session_id: override_model.chat_session_id,
            lorebook_id: override_model.lorebook_id,
            user_id: override_model.user_id,
            action: override_model.action,
            created_at: override_model.created_at,
            updated_at: override_model.updated_at,
        })
        .collect();

    Ok((StatusCode::OK, Json(response)))
}

