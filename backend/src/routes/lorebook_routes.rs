#![allow(clippy::items_after_statements)]
use crate::{
    auth::session_dek::SessionDek, // Import SessionDek
    auth::token_auth::UnifiedAuth, // Import UnifiedAuth
    db::DbId,
    errors::AppError,
    middleware::rate_limit::ai_lorebook_rate_limit_middleware, // Import AI rate limiter
    models::lorebook_dtos::{
        AnalyzeLorebookResponse, AssociateLorebookToChatPayload, CharacterLorebookOverrideResponse,
        ChatLorebookAssociationsResponse, CreateLorebookEntryPayload, CreateLorebookPayload,
        ExportFormat, ExtractLorebookEntriesFromChatPayload, GenerateLorebookEntriesPayload,
        GenerateLorebookEntriesResponse, GeneratedEntryPreview, LorebookAnalysis,
        SetCharacterLorebookOverridePayload, UpdateLorebookEntryPayload, UpdateLorebookPayload,
    },
    services::LorebookService,
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use axum_macros::debug_handler;
use secrecy::ExposeSecret; // For exposing SessionDek secret
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument; // Keep instrument
use validator::Validate; // For validating payloads

pub fn lorebook_routes() -> Router<AppState> {
    // Create a separate router for AI routes with rate limiting
    let ai_routes = Router::new()
        .route(
            "/lorebooks/:lorebook_id/ai/generate",
            post(ai_generate_entries_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/ai/analyze",
            post(ai_analyze_lorebook_handler),
        )
        .route(
            "/lorebooks/:lorebook_id/extract-from-chat",
            post(extract_from_chat_handler),
        )
        .layer(middleware::from_fn(ai_lorebook_rate_limit_middleware));

    // Main router with all lorebook routes
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
        // Merge AI routes with rate limiting
        .merge(ai_routes)
}

// --- Lorebook Handlers ---
#[debug_handler]
#[instrument(skip(state, auth, payload))]
async fn create_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Json(payload): Json<CreateLorebookPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    ); // Added qdrant service
    let lorebook = lorebook_service
        .create_lorebook(&auth.session, payload)
        .await?;
    Ok((StatusCode::CREATED, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn list_lorebooks_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let lorebooks = lorebook_service.list_lorebooks(&auth.session).await?;
    Ok((StatusCode::OK, Json(lorebooks)))
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn get_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Path(lorebook_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let lorebook = lorebook_service
        .get_lorebook(&auth.session, lorebook_id)
        .await?;
    Ok((StatusCode::OK, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth, payload))]
async fn update_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Path(lorebook_id): Path<crate::db::DbId>,
    Json(payload): Json<UpdateLorebookPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let lorebook = lorebook_service
        .update_lorebook(&auth.session, lorebook_id, payload)
        .await?;
    Ok((StatusCode::OK, Json(lorebook)))
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn delete_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Path(lorebook_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    lorebook_service
        .delete_lorebook(&auth.session, lorebook_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Lorebook Entry Handlers ---
#[debug_handler]
#[instrument(skip(state, auth, payload, dek))]
async fn create_lorebook_entry_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    dek: SessionDek,   // Add SessionDek extractor
    Path(lorebook_id): Path<crate::db::DbId>,
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
            &auth.session,
            lorebook_id,
            payload,
            Some(&dek.0),
            state.clone().into(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth, dek))]
async fn list_lorebook_entries_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    dek: SessionDek,   // Add SessionDek extractor
    Path(lorebook_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let entries = lorebook_service
        .list_lorebook_entries_with_content(&auth.session, lorebook_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entries)))
}

#[debug_handler]
#[instrument(skip(state, auth, dek))]
async fn get_lorebook_entry_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    dek: SessionDek,   // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(crate::db::DbId, crate::db::DbId)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let entry = lorebook_service
        .get_lorebook_entry(&auth.session, lorebook_id, entry_id, Some(&dek.0))
        .await?;
    Ok((StatusCode::OK, Json(entry)))
}

#[debug_handler]
#[instrument(skip(state, auth, payload, dek))]
async fn update_lorebook_entry_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    dek: SessionDek,   // Add SessionDek extractor
    Path((lorebook_id, entry_id)): Path<(crate::db::DbId, crate::db::DbId)>,
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
            &auth.session,
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
#[instrument(skip(state, auth))]
async fn delete_lorebook_entry_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Path((lorebook_id, entry_id)): Path<(crate::db::DbId, crate::db::DbId)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    lorebook_service
        .delete_lorebook_entry(&auth.session, lorebook_id, entry_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Chat Session Lorebook Association Handlers ---
#[debug_handler]
#[instrument(skip(state, auth, payload, dek))]
async fn associate_lorebook_to_chat_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek, // Add SessionDek extractor
    Path(chat_session_id): Path<crate::db::DbId>,
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
            &auth.session,
            chat_session_id,
            payload,
            Some(&dek.0),
            state.clone().into(),
        )
        .await?;
    Ok((StatusCode::OK, Json(association)))
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn list_chat_lorebook_associations_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(chat_session_id): Path<crate::db::DbId>,
    Query(params): Query<LorebookAssociationsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    if params.include_source {
        let enhanced_associations = lorebook_service
            .list_enhanced_chat_lorebook_associations(&auth.session, chat_session_id)
            .await?;
        Ok((
            StatusCode::OK,
            Json(ChatLorebookAssociationsResponse::Enhanced(
                enhanced_associations,
            )),
        ))
    } else {
        let associations = lorebook_service
            .list_chat_lorebook_associations(&auth.session, chat_session_id)
            .await?;
        Ok((
            StatusCode::OK,
            Json(ChatLorebookAssociationsResponse::Basic(associations)),
        ))
    }
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn disassociate_lorebook_from_chat_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth, // Changed to AuthBackend
    Path((chat_session_id, lorebook_id)): Path<(crate::db::DbId, crate::db::DbId)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    lorebook_service
        .disassociate_lorebook_from_chat(&auth.session, chat_session_id, lorebook_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth, dek))]
async fn list_associated_chat_sessions_for_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek, // Add SessionDek extractor
    Path(lorebook_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    let chat_sessions = lorebook_service
        .list_associated_chat_sessions_for_lorebook(&auth.session, lorebook_id, Some(&dek.0))
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
#[instrument(skip(state, auth, dek))]
async fn export_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek,
    Path(lorebook_id): Path<crate::db::DbId>,
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
                .export_lorebook_minimal(&auth.session, Some(&dek.0), lorebook_id)
                .await?;
            Ok((StatusCode::OK, Json(exported)).into_response())
        }
        ExportFormat::SillyTavernFull => {
            let exported = lorebook_service
                .export_lorebook(&auth.session, Some(&dek.0), lorebook_id)
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
#[instrument(skip(state, auth, dek, payload, params))]
async fn import_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek,
    Query(params): Query<ImportQuery>,
    Json(payload): Json<crate::DbJson>, // Accept generic JSON for dynamic deserialization
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    let response: Result<axum::response::Response, AppError> = match params.format {
        ImportFormat::ScribeMinimal => {
            let scribe_payload: crate::models::lorebook_dtos::ScribeMinimalLorebook =
                serde_json::from_value(payload.0.clone()).map_err(|e| {
                    AppError::BadRequest(format!("Invalid Scribe Minimal payload: {}", e))
                })?;

            // No validation needed for ScribeMinimalLorebook as it's a simple DTO

            let imported_lorebook = lorebook_service
                .import_lorebook_from_scribe_minimal(
                    &auth.session,
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
                        serde_json::from_value(payload.0.clone()).map_err(|e| {
                            AppError::BadRequest(format!("Invalid lorebook format: {}", e))
                        })?;

                    let imported_lorebook = lorebook_service
                        .import_lorebook_from_scribe_minimal(
                            &auth.session,
                            Some(&dek.0),
                            scribe_payload,
                            state.clone().into(),
                        )
                        .await?;
                    Ok((StatusCode::CREATED, Json(imported_lorebook)).into_response())
                } else if entries.is_object() {
                    // This is SillyTavern format
                    let sillytavern_import_payload: crate::models::lorebook_dtos::SillyTavernImportPayload =
                        serde_json::from_value(payload.0.clone())
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
                            &auth.session,
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
#[instrument(skip(state, auth, payload))]
async fn set_character_lorebook_override_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path((chat_session_id, lorebook_id)): Path<(crate::db::DbId, crate::db::DbId)>,
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
            &auth.session,
            chat_session_id,
            lorebook_id,
            payload.action,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn remove_character_lorebook_override_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path((chat_session_id, lorebook_id)): Path<(crate::db::DbId, crate::db::DbId)>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    lorebook_service
        .remove_character_lorebook_override(&auth.session, chat_session_id, lorebook_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
#[instrument(skip(state, auth))]
async fn get_character_lorebook_overrides_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(chat_session_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    let overrides = lorebook_service
        .get_character_lorebook_overrides(&auth.session, chat_session_id)
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

// --- AI-Powered Lorebook Handlers ---

#[debug_handler]
#[instrument(skip(state, auth, dek, payload))]
async fn ai_generate_entries_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek,
    Path(lorebook_id): Path<crate::db::DbId>,
    Json(payload): Json<GenerateLorebookEntriesPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // Get user from auth session
    let user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;
    let user_id = user.id;

    // Security logging: Track AI generation requests
    let is_suspicious = payload.count > 15; // Flag requests for many entries
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        theme = %payload.theme,
        count = payload.count,
        has_context = payload.context.is_some(),
        suspicious = is_suspicious,
        "AI lorebook generation request initiated"
    );

    if is_suspicious {
        tracing::warn!(
            user_id = %user_id,
            lorebook_id = %lorebook_id,
            count = payload.count,
            "Suspicious AI generation request: unusually high entry count"
        );
    }

    // Access tool via registry
    let narrative_service = state
        .narrative_intelligence_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerErrorGeneric("Narrative service not available".to_string())
        })?;

    let registry = narrative_service.get_tool_registry();
    let batch_tool = registry
        .get_tool("create_batch_lorebook_entries")
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get tool from registry: {}", e))
        })?;

    // Build tool parameters
    let session_dek_hex = hex::encode(dek.0.expose_secret());
    let tool_params = serde_json::json!({
        "user_id": user_id.to_string(),
        "lorebook_id": lorebook_id.to_string(),
        "session_dek": session_dek_hex,
        "theme": payload.theme,
        "count": payload.count,
        "context": payload.context,
    });

    // Execute tool - it returns Value directly, not String
    let result_json = batch_tool.execute(&tool_params).await.map_err(|e| {
        AppError::InternalServerErrorGeneric(format!("Tool execution failed: {}", e))
    })?;

    // Extract and log token usage for cost tracking
    if let Some(token_usage) = result_json.get("token_usage") {
        let prompt_tokens = token_usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completion_tokens = token_usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_tokens = token_usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        tracing::info!(
            user_id = %user_id,
            lorebook_id = %lorebook_id,
            theme = %payload.theme,
            count = payload.count,
            prompt_tokens = prompt_tokens,
            completion_tokens = completion_tokens,
            total_tokens = total_tokens,
            "AI lorebook batch generation token usage"
        );
    }

    // Extract entries from result (tool returns "created_entries")
    let entries_generated = result_json
        .get("entries_created")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let entries: Vec<GeneratedEntryPreview> = result_json
        .get("created_entries")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    // Tool returns "entry_id" and "title"
                    let id = entry
                        .get("entry_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| DbId::parse_str(s).ok())?;
                    let entry_title = entry
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;
                    // Keys are not included in the tool output
                    let keys_text = None;

                    Some(GeneratedEntryPreview {
                        id: id.into(),
                        entry_title,
                        keys_text,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let message = result_json
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Entries generated successfully")
        .to_string();

    let response = GenerateLorebookEntriesResponse {
        success: true,
        entries_generated,
        entries,
        message,
    };

    // Security logging: Track successful completion
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        entries_generated = entries_generated,
        "AI lorebook generation request completed successfully"
    );

    Ok((StatusCode::OK, Json(response)))
}

#[debug_handler]
#[instrument(skip(state, auth, dek))]
async fn ai_analyze_lorebook_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek,
    Path(lorebook_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    // Get user from auth session
    let user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;
    let user_id = user.id;

    // Security logging: Track AI analysis requests
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        "AI lorebook analysis request initiated"
    );

    // Access tool via registry
    let narrative_service = state
        .narrative_intelligence_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerErrorGeneric("Narrative service not available".to_string())
        })?;

    let registry = narrative_service.get_tool_registry();
    let analysis_tool = registry.get_tool("analyze_lorebook").map_err(|e| {
        AppError::InternalServerErrorGeneric(format!("Failed to get tool from registry: {}", e))
    })?;

    // Build tool parameters
    let session_dek_hex = hex::encode(dek.0.expose_secret());
    let tool_params = serde_json::json!({
        "user_id": user_id.to_string(),
        "lorebook_id": lorebook_id.to_string(),
        "session_dek": session_dek_hex,
    });

    // Execute tool - it returns Value directly, not String
    let result_json = analysis_tool.execute(&tool_params).await.map_err(|e| {
        AppError::InternalServerErrorGeneric(format!("Tool execution failed: {}", e))
    })?;

    // Extract and log token usage for cost tracking
    if let Some(token_usage) = result_json.get("token_usage") {
        let prompt_tokens = token_usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completion_tokens = token_usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_tokens = token_usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        tracing::info!(
            user_id = %user_id,
            lorebook_id = %lorebook_id,
            prompt_tokens = prompt_tokens,
            completion_tokens = completion_tokens,
            total_tokens = total_tokens,
            "AI lorebook analysis token usage"
        );
    }

    // Extract analysis from result - tool returns analysis nested under "analysis" key
    let entries_analyzed = result_json
        .get("entries_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let analysis_obj = result_json
        .get("analysis")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            AppError::InternalServerErrorGeneric(
                "Missing analysis object in tool result".to_string(),
            )
        })?;

    let gaps = analysis_obj
        .get("gaps")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let consistency_issues = analysis_obj
        .get("consistency_issues")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let improvement_suggestions = analysis_obj
        .get("improvement_suggestions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let recommended_themes = analysis_obj
        .get("recommended_themes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let analysis = LorebookAnalysis {
        gaps,
        consistency_issues,
        improvement_suggestions,
        recommended_themes,
    };

    let response = AnalyzeLorebookResponse {
        success: true,
        entries_analyzed,
        analysis,
    };

    // Security logging: Track successful completion
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        entries_analyzed = entries_analyzed,
        "AI lorebook analysis request completed successfully"
    );

    Ok((StatusCode::OK, Json(response)))
}

#[debug_handler]
#[instrument(skip(state, auth, dek, payload))]
async fn extract_from_chat_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    dek: SessionDek,
    Path(lorebook_id): Path<crate::db::DbId>,
    Json(payload): Json<ExtractLorebookEntriesFromChatPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // Get user from auth session
    let user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("User not authenticated".to_string()))?;
    let user_id = user.id;

    // Security logging: Track extraction requests
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        chat_session_id = %payload.chat_session_id,
        start_index = ?payload.start_message_index,
        end_index = ?payload.end_message_index,
        "Lorebook extraction from chat request initiated"
    );

    // Create lorebook service
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );

    // Call extraction service method
    let result = lorebook_service
        .extract_entries_from_chat(user_id, lorebook_id, payload, &dek.0)
        .await?;

    // Security logging: Track successful completion
    tracing::info!(
        user_id = %user_id,
        lorebook_id = %lorebook_id,
        entries_extracted = result.entries_extracted,
        "Lorebook extraction from chat completed successfully"
    );

    Ok((StatusCode::OK, Json(result)))
}
