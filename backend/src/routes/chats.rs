use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::auth::token_auth::UnifiedAuth;
use crate::crypto; // Added crypto for encryption/decryption
use crate::db::DbId;
use crate::db::DbPool; // Added PgPool import
use crate::errors::AppError;
use crate::models::chat_override::CharacterOverrideDto; // Added for override handler
use crate::models::chats::{
    Chat, // Replaced ChatListQuery/ChatSessionQuery
    // ChatSettingsResponse, // Not used directly in this file anymore
    CreateChatRequest,    // Now available
    CreateMessageRequest, // Now available
    Message,
    MessageResponse, // Now available
    MessageRole,
    SelectVariantRequest, // Added for variant selection
    UpdateChatSettingsRequest,
    UpdateChatVisibilityRequest, // Now available
    Vote,                        // Now available
    VoteRequest,                 // Now available
};
use crate::models::usage::ChatTokenUsage;
use crate::models::users::User; // Added User import
use crate::privacy::logging::loggable_user_id;
use crate::schema::{
    agent_context_analysis, chat_messages, chat_sessions, chronicle_events, message_variants,
};
use axum::{
    extract::{Path, Query, State}, // Added Query
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Router,
};
use secrecy::ExposeSecret; // Added for expose_secret method
use secrecy::SecretBox; // Ensure SecretBox is imported
                        // Removed incorrect ValidatedJson import
use crate::services::chat;
use crate::services::chat::generation::{self, StreamAiParams}; // Added generation imports
use crate::state::AppState;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole}; // Added genai imports
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn}; // Added for logging
use tracing::{error, info};
// ExposeSecret already imported above
#[cfg(feature = "sqlite-backend")]
use crate::db::pool_helpers::{SqliteInteractExt, SqlitePoolExt};
use serde::{Deserialize, Serialize}; // Added Deserialize
use validator::Validate; // Remove unused Deserialize // Added for cursor-based pagination

// Shorthand for auth session

pub fn chat_routes() -> Router<crate::state::AppState> {
    tracing::debug!("chat_routes: entering chat_routes function");
    let mut router = Router::new()
        .route("/", get(get_chats_handler)) // Keep GET / for listing
        .route("/create_session", post(create_chat_handler)) // More distinct path for POST
        .route("/fetch/:id", get(get_chat_by_id_handler))
        .route("/remove/:id", delete(delete_chat_handler))
        .route(
            "/:id/deletion-analysis",
            get(get_chat_deletion_analysis_handler),
        )
        .route(
            "/by-character/:character_id",
            get(get_chats_by_character_handler),
        ) // NEW: Get chats by character
        .route("/:id/messages", {
            tracing::debug!(
                "chat_routes: mapping /:id/messages to get_messages_by_chat_id_handler"
            );
            get(get_messages_by_chat_id_handler).post(create_message_handler)
        })
        .route("/:id/visibility", put(update_chat_visibility_handler))
        .route(
            "/:id/settings",
            get(get_chat_settings_handler).put(update_chat_settings_handler),
        )
        .route(
            "/messages/:id",
            get(get_message_by_id_handler).delete(delete_message_handler),
        )
        .route(
            "/messages/:id/select-variant",
            post(select_message_variant_handler),
        )
        .route(
            "/messages/:id/trailing",
            delete(delete_trailing_messages_handler),
        )
        .route(
            "/:id/character/overrides",
            post(set_chat_character_override_handler),
        )
        .route("/:id/token-usage", get(get_chat_token_usage_handler));

    // Postgres-only routes (voting feature not yet implemented for SQLite)
    #[cfg(feature = "postgres-backend")]
    {
        router = router
            .route("/messages/:id/vote", post(vote_message_handler))
            .route("/:id/votes", get(get_votes_by_chat_id_handler));
    }

    router
}

/// Sets character overrides for a chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Session does not exist or access is denied
/// - Character override validation fails
/// - Database operation fails
pub async fn set_chat_character_override_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek,                         // Added SessionDek extractor
    Path(session_id): Path<crate::db::DbId>, // Renamed id to session_id for clarity
    Json(payload): Json<CharacterOverrideDto>,
) -> Result<impl IntoResponse, AppError> {
    #[derive(Serialize)]
    struct OverrideResponse {
        message: String,
        session_id: crate::db::DbId,
        field_name: String,
        new_value: String,
        // Include original fields for compatibility with existing tests
        id: crate::db::DbId,
        chat_session_id: crate::db::DbId,
        original_character_id: crate::db::DbId,
        overridden_value: Vec<u8>,
        overridden_value_nonce: Option<Vec<u8>>,
        created_at: crate::DbTimestamp,
        updated_at: crate::DbTimestamp,
    }

    // Validate the payload first
    payload.validate()?;

    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    tracing::info!(target: "scribe_backend::routes::chats", %session_id, user_id = %loggable_user_id(user.id), field_name = %payload.field_name, "Attempting to set chat character override");

    // The user.dek from auth_session might not be the raw SecretBox<Vec<u8>> needed by the service.
    // The SessionDek extractor provides the correct SecretBox<Vec<u8>>.
    let override_db_response = chat::overrides::set_character_override(
        &state.pool,
        user.id,
        session_id,
        payload.clone(), // Clone payload for use in client response
        Some(&dek.0),    // Pass the SecretBox from SessionDek
    )
    .await?;

    let client_response = OverrideResponse {
        message: format!(
            "Override for '{}' applied successfully.",
            override_db_response.field_name
        ),
        session_id: override_db_response.chat_session_id,
        field_name: override_db_response.field_name.clone(),
        new_value: payload.value, // Use the unencrypted value from the request

        // Include original fields
        id: override_db_response.id,
        chat_session_id: override_db_response.chat_session_id,
        original_character_id: override_db_response.original_character_id,
        overridden_value: override_db_response.overridden_value,
        overridden_value_nonce: Some(override_db_response.overridden_value_nonce),
        created_at: override_db_response.created_at,
        updated_at: override_db_response.updated_at,
    };

    Ok((StatusCode::OK, Json(client_response)))
}

/// Retrieves chat sessions for a specific character for the current user.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Character access is denied
/// - Database operation fails
pub async fn get_chats_by_character_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek,
    Path(character_id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chats = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user.id))
            .filter(chat_sessions::character_id.eq(character_id))
            .order_by(chat_sessions::created_at.desc())
            .select(Chat::as_select())
            .load::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Decrypt the titles for client display
    let mut decrypted_chats = Vec::new();
    for chat in chats {
        let client_chat = chat.into_decrypted_for_client(Some(&dek.0))?;
        decrypted_chats.push(client_chat);
    }

    Ok(Json(decrypted_chats))
}

// Get all chats for current user
/// Retrieves all chat sessions for the current user.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Database operation fails
/// - Decryption fails
pub async fn get_chats_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor for decryption
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chats = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user.id))
            .order_by(chat_sessions::created_at.desc())
            .select(Chat::as_select())
            .load::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Decrypt the titles for client display
    let mut decrypted_chats = Vec::new();
    for chat in chats {
        let client_chat = chat.into_decrypted_for_client(Some(&dek.0))?;
        decrypted_chats.push(client_chat);
    }

    Ok(Json(decrypted_chats))
}

// Create a new chat
/// Creates a new chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Validation fails
/// - Database operation fails
/// - Encryption fails
pub async fn create_chat_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor for encryption
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_start = std::time::Instant::now();

    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    // Use the SessionDek which provides the user's DEK
    let user_dek_arc = Some(Arc::new(SecretBox::new(Box::new(
        dek.0.expose_secret().clone(),
    ))));

    info!(
        %user.id,
        character_id=%payload.character_id,
        lorebook_ids=?payload.lorebook_ids,
        has_title = payload.title.is_some(),
        has_custom_persona = payload.active_custom_persona_id.is_some(),
        "create_chat_handler: Creating chat session"
    );

    let app_state = Arc::new(state.clone());
    let chat = chat::session_management::create_session_and_maybe_first_message(
        app_state,
        user.id,
        Some(payload.character_id),
        crate::models::chats::ChatMode::Character,
        payload.active_custom_persona_id, // active_custom_persona_id
        payload.lorebook_ids.clone(),     // lorebook_ids
        user_dek_arc,
    )
    .await
    .map_err(|e| {
        error!(
            user_id = %user.id,
            character_id = %payload.character_id,
            error = ?e,
            error_msg = %e,
            elapsed_ms = request_start.elapsed().as_millis(),
            "create_chat_handler: Service call failed"
        );
        e
    })?;

    // Generate a custom title if provided (default title is set by the service)
    if let Some(ref title) = payload.title {
        if !title.trim().is_empty() {
            let pool = state.pool.clone();
            let session_id = chat.id;
            let custom_title = title.clone();

            // Encrypt the title using the DEK from the SessionDek extractor
            let dek_for_title_encryption = &dek.0; // dek is SessionDek, dek.0 is SecretBox<Vec<u8>>
            match crypto::encrypt_gcm(custom_title.as_bytes(), dek_for_title_encryption) {
                Ok((ciphertext, nonce)) => {
                    // Update with encrypted title
                    crate::db::with_conn(&pool, move |conn| {
                        diesel::update(chat_sessions::table.find(session_id))
                            .set((
                                chat_sessions::title_ciphertext.eq(Some(ciphertext)),
                                chat_sessions::title_nonce.eq(Some(nonce)),
                            ))
                            .execute(conn)
                            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
                    })
                    .await
                    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
                }
                Err(e) => {
                    error!(error = ?e, "Failed to encrypt chat title");
                    return Err(AppError::EncryptionError(
                        "Failed to encrypt title".to_string(),
                    ));
                }
            }
        }
    }

    // Add detailed logging for debugging the chat session after creation
    info!(
        message = "Chat session created in handler",
        chat_id = %chat.id,
        character_id = ?chat.character_id,
        user_id = %chat.user_id,
        system_prompt_present = chat.system_prompt_ciphertext.is_some(), // Avoid logging potentially large/sensitive prompt
        title_present = chat.title_ciphertext.is_some(), // Also avoid logging title directly
        elapsed_ms = request_start.elapsed().as_millis(),
        // Removed full 'chat = ?chat' to avoid logging all fields, including encrypted ones
        "create_chat_handler: Success - returning 201 Created"
    );

    // Return the fully configured Chat struct
    Ok((StatusCode::CREATED, Json(chat)))
}

// Get a chat by ID
/// Retrieves a specific chat session by ID.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
pub async fn get_chat_by_id_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(AppError::from) // Use From trait to handle NotFound correctly
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Ensure the user owns this chat or it's public
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }

    // Return the full Chat struct directly
    Ok(Json(chat))
}

/// Get deletion analysis for a chat (chronicle info)
/// Returns analysis information to help user make informed deletion decisions
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
pub async fn get_chat_deletion_analysis_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // First verify the user owns this chat
    let pool = state.pool.clone();
    let _chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .filter(chat_sessions::user_id.eq(user.id)) // Ensure ownership
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Chat not found or access denied: {e}"))
            })
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Get chronicle analysis if this chat has one
    let chronicle_service =
        crate::services::ChronicleService::new(state.pool.clone(), state.ai_client.clone());
    let chronicle_analysis = chronicle_service
        .get_chat_deletion_analysis(user.id, id)
        .await?;

    let response = ChatDeletionAnalysisResponse {
        has_chronicle: chronicle_analysis.is_some(),
        chronicle: chronicle_analysis.map(|analysis| ChronicleAnalysisDto {
            id: analysis.id,
            name: analysis.name,
            total_events: analysis.total_events,
            events_from_this_chat: analysis.events_from_this_chat,
            other_chats_using_chronicle: analysis.other_chats_using_chronicle,
            can_delete_chronicle: analysis.can_delete_chronicle,
        }),
    };

    Ok(Json(response))
}

// Delete a chat
/// Deletes a chat session by ID.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
pub async fn delete_chat_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
    Query(params): Query<DeleteChatQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user owns the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .filter(chat_sessions::user_id.eq(user.id)) // Ensure ownership
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Chat not found or access denied: {e}"))
            })
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    let chronicle_service =
        crate::services::ChronicleService::new(state.pool.clone(), state.ai_client.clone());

    // Handle chronicle deletion based on the requested strategy
    if let Some(chronicle_id) = chat.player_chronicle_id {
        info!(
            chat_id = %id,
            chronicle_id = %chronicle_id,
            chronicle_action = %params.chronicle_action,
            "Processing chat deletion with chronicle strategy"
        );

        match params.chronicle_action.as_str() {
            "delete_chronicle" => {
                info!("Strategy: Delete entire chronicle and all events");

                // Clean up ALL chronicle event embeddings (not just from this chat)
                if let Err(e) = state
                    .embedding_pipeline_service
                    .delete_chronicle_events_by_chronicle_id(
                        Arc::new(state.clone()),
                        chronicle_id,
                        user.id,
                    )
                    .await
                {
                    error!(
                        chronicle_id = %chronicle_id,
                        error = %e,
                        "Failed to clean up chronicle embeddings, but will proceed with deletion"
                    );
                }

                // Delete the entire chronicle (will cascade to all events)
                chronicle_service
                    .delete_chronicle_completely(user.id, chronicle_id)
                    .await?;

                info!("Chronicle {} deleted completely", chronicle_id);
            }

            "disassociate" => {
                info!("Strategy: Disassociate chronicle events from chat (preserve events)");

                // First disassociate events from the chat (set chat_session_id to NULL)
                let disassociated_count = chronicle_service
                    .disassociate_events_from_chat(user.id, id)
                    .await?;

                info!(
                    "Disassociated {} events from chat {}",
                    disassociated_count, id
                );

                // Note: We don't clean up embeddings because events are preserved
            }

            "delete_events" | _ => {
                info!("Strategy: Delete only events created by this chat (default)");

                // Clean up embeddings for events from this specific chat
                match chronicle_service
                    .get_events_for_chat_session(user.id, id)
                    .await
                {
                    Ok(events) => {
                        info!(
                            "Found {} chronicle events from this chat to clean up",
                            events.len()
                        );

                        for event in events {
                            if let Err(e) = state
                                .embedding_pipeline_service
                                .delete_chronicle_event_chunks(
                                    Arc::new(state.clone()),
                                    event.id,
                                    user.id,
                                )
                                .await
                            {
                                error!(
                                    event_id = %event.id,
                                    error = %e,
                                    "Failed to clean up embeddings for chronicle event, continuing with deletion"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            chat_id = %id,
                            error = %e,
                            "Failed to retrieve chronicle events for cleanup, continuing with deletion"
                        );
                    }
                }
                // Events will be cascade-deleted when chat is deleted due to foreign key constraint
            }
        }
    }

    // Delete the chat (messages and other associated data will cascade)
    crate::db::with_conn(&pool, move |conn| {
        diesel::delete(chat_sessions::table.filter(chat_sessions::id.eq(id)))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    info!(
        "Successfully deleted chat session {} with strategy '{}'",
        id, params.chronicle_action
    );
    Ok(StatusCode::NO_CONTENT)
}

// Query parameters for fetching messages
#[derive(Debug, Deserialize)]
pub struct GetMessagesQueryParams {
    #[serde(default = "default_message_limit")]
    pub limit: i64,
    pub cursor: Option<crate::DbTimestamp>, // Timestamp of the last message from previous batch
}

fn default_message_limit() -> i64 {
    20
}

// Response structure for paginated messages
#[derive(Debug, Serialize)]
pub struct PaginatedMessagesResponse {
    pub messages: Vec<MessageResponse>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<crate::DbTimestamp>,
}

/// Helper function to validate and parse the chat ID
///
/// # Errors
///
/// Returns `AppError::BadRequest` if the provided string is not a valid UUID format
fn parse_chat_id(id: &str) -> Result<crate::db::DbId, AppError> {
    DbId::parse_str(id)
        .map(Into::into)
        .map_err(|_| AppError::BadRequest("Invalid UUID format in path".to_string()))
}

/// Helper function to get authenticated user
fn get_authenticated_user(auth: UnifiedAuth) -> Result<User, AppError> {
    auth.user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))
}

/// Helper function to fetch chat session and verify ownership
async fn fetch_and_verify_chat_ownership(
    pool: DbPool,
    chat_id: crate::db::DbId,
    user_id: crate::db::DbId,
) -> Result<Chat, AppError> {
    crate::db::with_conn(&pool, move |conn| {
        fetch_chat_with_ownership_check(conn, chat_id, user_id)
    })
    .await
    .map_err(|e| {
        tracing::error!("Failed to verify chat ownership: {}", e);
        AppError::DbInteractError(e.to_string())
    })
}

/// Database operation to fetch chat and check ownership
fn fetch_chat_with_ownership_check(
    conn: &mut crate::DbConnection,
    chat_id: crate::db::DbId,
    user_id: crate::db::DbId,
) -> Result<Chat, AppError> {
    tracing::debug!("Fetching chat for id={}", chat_id);

    let chat = chat_sessions::table
        .filter(chat_sessions::id.eq(chat_id))
        .select(Chat::as_select())
        .first::<Chat>(conn)
        .map_err(|e| {
            if e == diesel::result::Error::NotFound {
                tracing::warn!("Chat with id {} not found", chat_id);
                AppError::NotFound(format!("Chat session with id {chat_id} not found"))
            } else {
                tracing::error!("Database error fetching chat: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            }
        })?;

    // Verify ownership
    if chat.user_id != user_id {
        tracing::warn!(
            "User {} attempted to access chat {} owned by {}",
            user_id,
            chat_id,
            chat.user_id
        );
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }

    tracing::debug!(
        "Successfully verified chat ownership for user {}",
        loggable_user_id(user_id)
    );
    Ok(chat)
}

/// Helper function to fetch messages for a chat session with pagination
async fn fetch_paginated_chat_messages(
    pool: DbPool,
    chat_id: crate::db::DbId,
    limit: i64,
    cursor: Option<crate::DbTimestamp>,
) -> Result<Vec<Message>, AppError> {
    crate::db::with_conn(&pool, move |conn| {
            tracing::debug!(
                "Fetching paginated messages for session_id = {}, limit = {}, cursor = {:?}",
                chat_id,
                limit,
                cursor
            );
            let mut query = chat_messages::table
                .filter(chat_messages::session_id.eq(chat_id))
                .filter(chat_messages::superseded_at.is_null()) // Only get active (non-superseded) messages
                .order_by(chat_messages::created_at.desc()) // Order by descending for reverse pagination
                .limit(limit)
                .into_boxed(); // Use into_boxed to allow dynamic query building

            if let Some(cursor_timestamp) = cursor {
                #[cfg(feature = "sqlite-backend")]
                {
                    // SQLite stores timestamps as strings (often with space separator), but cursor is RFC3339 (T separator).
                    // We must normalize both to ensure correct lexicographical comparison.
                    // We bind as Text because DbTimestamp's ToSql for SQLite produces an ISO string.
                    use diesel::dsl::sql;
                    use diesel::sql_types::{Bool, Text};
                    query = query.filter(
                        sql::<Bool>("datetime(created_at) < datetime(")
                            .bind::<Text, _>(cursor_timestamp.to_string())
                            .sql(")"),
                    );
                }

                #[cfg(feature = "postgres-backend")]
                {
                    query = query.filter(chat_messages::created_at.lt(cursor_timestamp));
                }
            }

            let result = query.select(Message::as_select()).load(conn);

            match &result {
                Ok(messages) => {
                    tracing::info!(
                        "📥 Found {} paginated messages for chat {}",
                        messages.len(),
                        chat_id
                    );
                    for msg in messages {
                        tracing::info!(
                            "📋 Message: id={}, type={}, variant_count={}, current_variant_index={}, status={}",
                            msg.id,
                            msg.message_type,
                            msg.variant_count,
                            msg.current_variant_index,
                            msg.status
                        );
                    }
                }
                Err(e) => tracing::error!("Error fetching paginated messages: {}", e),
            }

            result.map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| {
        tracing::error!("Join error in paginated messages query: {}", e);
        AppError::InternalServerErrorGeneric(e.to_string())
    })
}

/// Helper function to get the default variant content for a message (variant index 0)
#[allow(dead_code)]
async fn get_default_variant_content(
    pool: DbPool,
    message_id: crate::db::DbId,
    user_id: crate::db::DbId,
    dek: &crate::auth::session_dek::SessionDek,
) -> Result<Option<String>, AppError> {
    use crate::models::chats::MessageVariant;
    use crate::schema::message_variants;
    use diesel::OptionalExtension; // Add this import for .optional()

    let variant_opt = crate::db::with_conn(&pool, move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .filter(message_variants::variant_index.eq(0)) // Always get variant 0 (original)
            .first::<MessageVariant>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if let Some(variant) = variant_opt {
        // Decrypt the variant content
        let content = variant.decrypt_content(&dek.0)?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

/// Helper function to decrypt and transform messages for client response with variant support
async fn process_messages_for_response(
    messages_db: Vec<Message>,
    dek: &crate::auth::session_dek::SessionDek,
    pool: DbPool,
    user_id: crate::db::DbId,
    character_name: Option<&str>,
    user_persona_name: Option<&str>,
) -> Result<Vec<MessageResponse>, AppError> {
    tracing::info!("🔄 Processing {} messages for response", messages_db.len());
    let mut responses = Vec::new();

    for msg_db in messages_db {
        tracing::info!(
            "🔄 Processing message: id={}, type={}, variant_count={}, current_variant_index={}",
            msg_db.id,
            msg_db.message_type,
            msg_db.variant_count,
            msg_db.current_variant_index
        );
        // Get content based on the current variant index, not always variant 0
        let content = if msg_db.current_variant_index == 0 {
            // Index 0 means original message content
            tracing::info!("📄 Using original content for message {}", msg_db.id);
            let decrypted_client_message =
                msg_db.clone().into_decrypted_for_client(Some(&dek.0))?;
            decrypted_client_message.content
        } else {
            // Get the specific variant content based on current_variant_index
            tracing::info!(
                "🎯 Getting variant {} content for message {}",
                msg_db.current_variant_index,
                msg_db.id
            );
            match get_variant_content_by_index(
                pool.clone(),
                msg_db.id,
                msg_db.current_variant_index,
                user_id,
                dek,
            )
            .await?
            {
                Some(variant_content) => {
                    tracing::info!("✅ Found variant content for message {}", msg_db.id);
                    variant_content
                }
                None => {
                    // Fallback to original message content if variant not found
                    tracing::warn!(
                        "⚠️ Variant {} not found for message {}, falling back to original",
                        msg_db.current_variant_index,
                        msg_db.id
                    );
                    let decrypted_client_message =
                        msg_db.clone().into_decrypted_for_client(Some(&dek.0))?;
                    decrypted_client_message.content
                }
            }
        };

        // Parts are created inline with template substitution below
        let response_attachments = msg_db.attachments.unwrap_or_else(|| json!([]).into());

        let response_role = msg_db
            .role
            .unwrap_or_else(|| msg_db.message_type.to_string());

        // For raw_prompt, still decrypt from the original message
        let raw_prompt = match (&msg_db.raw_prompt_ciphertext, &msg_db.raw_prompt_nonce) {
            (Some(ciphertext), Some(nonce)) if !ciphertext.is_empty() && !nonce.is_empty() => {
                crate::crypto::decrypt_gcm(ciphertext, nonce, &dek.0)
                    .ok()
                    .and_then(|secret_bytes| {
                        String::from_utf8(secret_bytes.expose_secret().clone()).ok()
                    })
            }
            _ => None,
        };

        let message_response = MessageResponse {
            id: msg_db.id,
            session_id: msg_db.session_id,
            message_type: msg_db.message_type,
            role: response_role,
            content: crate::prompt_builder::replace_template_variables(&content, character_name, user_persona_name),
            parts: json!([{"text": crate::prompt_builder::replace_template_variables(&content, character_name, user_persona_name)}]).into(),
            attachments: response_attachments,
            created_at: msg_db.created_at,
            raw_prompt,
            prompt_tokens: msg_db.prompt_tokens,
            completion_tokens: msg_db.completion_tokens,
            model_name: Some(msg_db.model_name),
            status: msg_db.status,
            error_message: msg_db.error_message,
            variant_count: msg_db.variant_count,
            current_variant_index: msg_db.current_variant_index,
            is_variant: msg_db.variant_count > 0, // True if this message has variants
            parent_message_id: None,              // TODO: Add parent_message_id to Message struct
            variants: None,                       // TODO: Load actual variants
        };

        tracing::info!(
            "📤 Sending message response: id={}, variant_count={}, current_variant_index={}, is_variant={}",
            message_response.id,
            message_response.variant_count,
            message_response.current_variant_index,
            message_response.is_variant
        );

        responses.push(message_response);
    }

    Ok(responses)
}

/// Retrieves all messages for a specific chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
/// - Decryption fails
/// Retrieves paginated messages for a specific chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
/// - Decryption fails
pub async fn get_messages_by_chat_id_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // ADDED SessionDek extractor
    Path(id): Path<String>,
    Query(params): Query<GetMessagesQueryParams>, // Added query parameters
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(
        "get_messages_by_chat_id_handler: id = {}, limit = {}, cursor = {:?}",
        id,
        params.limit,
        params.cursor
    );

    // Parse and validate input
    let chat_id = parse_chat_id(&id)?;
    let user = get_authenticated_user(auth)?;

    tracing::debug!(
        "Parsed chat_id = {}, user_id = {}",
        chat_id,
        loggable_user_id(user.id)
    );

    // Fetch chat session and verify ownership
    let chat = fetch_and_verify_chat_ownership(state.pool.clone(), chat_id, user.id).await?;

    // Fetch character name for template substitution (if character_id exists)
    let character_name: Option<String> = if let Some(char_id) = chat.character_id {
        crate::db::with_conn(&state.pool, move |conn| {
            use crate::schema::characters;
            characters::table
                .filter(characters::id.eq(char_id))
                .select(characters::name)
                .first::<String>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };

    // Fetch persona name for template substitution
    // Priority: 1) chat's active_custom_persona_id, 2) user's default_persona_id
    let effective_persona_id: Option<crate::db::DbId> = if chat.active_custom_persona_id.is_some() {
        chat.active_custom_persona_id
    } else {
        // Fall back to user's default persona
        user.default_persona_id
    };

    let user_persona_name: Option<String> = if let Some(persona_id) = effective_persona_id {
        crate::db::with_conn(&state.pool, move |conn| {
            use crate::schema::user_personas;
            user_personas::table
                .filter(user_personas::id.eq(persona_id))
                .select(user_personas::name)
                .first::<String>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };

    // Fetch paginated messages for the chat
    let messages_db =
        fetch_paginated_chat_messages(state.pool.clone(), chat_id, params.limit, params.cursor)
            .await?;

    // Decrypt and transform messages for response with variant support + template substitution
    let mut responses = process_messages_for_response(
        messages_db,
        &dek,
        state.pool.clone(),
        user.id,
        character_name.as_deref(),
        user_persona_name.as_deref(),
    )
    .await?;

    // Determine the next cursor
    let next_cursor = responses.last().map(|msg| msg.created_at);

    // Reverse the order of messages to be chronological for the frontend
    responses.reverse();

    Ok(Json(PaginatedMessagesResponse {
        messages: responses,
        next_cursor,
    }))
}

pub async fn create_message_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor
    Path(chat_id): Path<crate::db::DbId>,
    Json(payload): Json<CreateMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Parse the role into enum for validation
    let message_role_enum = match payload.role.to_lowercase().as_str() {
        "user" => MessageRole::User,
        "assistant" => MessageRole::Assistant,
        "system" => MessageRole::System,
        _ => {
            return Err(AppError::BadRequest(format!(
                "Invalid role: {}",
                payload.role
            )));
        }
    };

    // Fetch chat session and verify ownership
    let chat = fetch_and_verify_chat_ownership(state.pool.clone(), chat_id, user.id).await?;
    let game_master_mode_enabled = chat.game_master_mode_enabled;

    let user_id = user.id;
    let user_dek_arc = Some(Arc::new(SecretBox::new(Box::new(
        dek.0.expose_secret().clone(),
    ))));

    // Note: CreateMessageRequest doesn't have validation - basic validation happens in role parsing above

    // Track daily usage for user messages (this happens synchronously, before token tracking)
    #[cfg(feature = "payment")]
    if message_role_enum == MessageRole::User {
        use crate::services::payment::SoftLimitService;

        let soft_limit_service = SoftLimitService::new(state.config.clone());
        let pool = state.pool.clone();
        let user_id_for_daily_tracking = user_id;

        let _daily_usage_result = crate::db::with_conn(&pool, move |conn| {
            soft_limit_service.record_usage(conn, user_id_for_daily_tracking, "manual_message", 0)
        })
        .await;

        match _daily_usage_result {
            Ok(_) => {
                debug!(
                    user_id = %user_id_for_daily_tracking,
                    chat_id = %chat_id,
                    "Successfully incremented daily usage for user message"
                );
            }
            Err(e) => {
                warn!(
                    user_id = %user_id_for_daily_tracking,
                    chat_id = %chat_id,
                    error = %e,
                    "Failed to increment daily usage for user message, but proceeding"
                );
            }
        }
    }

    // Create the message using the save_message function
    let app_state = Arc::new(state.clone());
    let saved_db_message = crate::services::chat::message_handling::save_message(
        crate::services::chat::message_handling::SaveMessageParams {
            state: app_state.clone(),
            session_id: chat_id,
            user_id,
            message_type_enum: message_role_enum,
            content: &payload.content,
            role_str: Some(payload.role.clone()),
            parts: payload.parts.clone().map(Into::into),
            attachments: payload.attachments.clone().map(Into::into),
            user_dek_secret_box: user_dek_arc.clone(),
            model_name: chat.model_name.clone(),
            raw_prompt_debug: None,
            status: crate::models::chats::MessageStatus::Completed,
            error_message: None,
            variant_of: None,
            charge_credits: false, // Manual message creation is not charged
            credits_cost_override: None, // Let save_message calculate from tokens
        },
    )
    .await?;

    // Track token usage for payment/quota tracking (for manually created user messages)
    #[cfg(feature = "payment")]
    if message_role_enum == MessageRole::User && saved_db_message.prompt_tokens.unwrap_or(0) > 0 {
        use crate::services::encryption_service::EncryptionService;
        use crate::services::payment::UsageTrackingService;

        let usage_tracking_service =
            UsageTrackingService::new((*state.config).clone(), EncryptionService::new());

        let user_id_for_payment = user_id;
        let tokens_used = saved_db_message.prompt_tokens.unwrap_or(0);
        let model_name_for_tracking = chat.model_name.clone();

        // Get a database connection for the usage tracking
        match crate::db::get_conn(&state.pool).await {
            Ok(conn) => {
                let subscription_id = None; // TODO: Get from user's subscription if needed
                let mut model_usage = std::collections::HashMap::new();
                model_usage.insert(model_name_for_tracking, tokens_used);

                let metadata = Some(
                    crate::services::payment::usage_tracking_service::UsageMetadata {
                        model_usage,
                        feature_usage: std::collections::HashMap::new(),
                        request_count: 1,
                        last_activity: crate::DbTimestamp::now(),
                    },
                );

                // Use interact to call the async track_usage method
                let track_result = conn
                    .interact(move |conn| {
                        usage_tracking_service.track_usage_sync(
                            conn,
                            user_id_for_payment,
                            subscription_id,
                            tokens_used,
                            metadata,
                        )
                    })
                    .await;

                match track_result {
                    Ok(Ok(_)) => {
                        debug!(
                            chat_id = %chat_id,
                            tokens_used = tokens_used,
                            "Successfully tracked token usage for manually created user message"
                        );
                    }
                    Ok(Err(e)) => {
                        warn!(
                            chat_id = %chat_id,
                            error = %e,
                            "Failed to track token usage for manually created user message"
                        );
                    }
                    Err(e) => {
                        warn!(
                            chat_id = %chat_id,
                            error = %e,
                            "Database interaction failed for token usage tracking"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    chat_id = %chat_id,
                    error = %e,
                    "Failed to get database connection for token usage tracking"
                );
            }
        }
    }

    // Convert DbChatMessage to ChatMessageForClient to get decrypted content
    // saved_db_message is a ChatMessage. We need to construct a Message to call into_decrypted_for_client.
    let message_for_decryption = Message {
        id: saved_db_message.id,
        session_id: saved_db_message.session_id,
        message_type: saved_db_message.message_type,
        content: saved_db_message.content, // This is Vec<u8>
        content_nonce: saved_db_message.content_nonce,
        rag_embedding_id: None,
        created_at: saved_db_message.created_at,
        updated_at: saved_db_message.created_at, // For a new message, updated_at is same as created_at
        user_id: saved_db_message.user_id,
        role: Some(payload.role.clone()), // From the request payload
        parts: payload.parts.clone(),     // From the request payload
        attachments: payload.attachments.clone(), // From the request payload
        prompt_tokens: saved_db_message.prompt_tokens,
        completion_tokens: saved_db_message.completion_tokens,
        raw_prompt_ciphertext: saved_db_message.raw_prompt_ciphertext,
        raw_prompt_nonce: saved_db_message.raw_prompt_nonce,
        model_name: saved_db_message.model_name.clone(),
        status: saved_db_message.status.clone(),
        error_message: saved_db_message.error_message.clone(),
        superseded_at: saved_db_message.superseded_at,
        variant_count: saved_db_message.variant_count,
        current_variant_index: saved_db_message.current_variant_index,
        credits_charged: saved_db_message.credits_charged,
        credits_cost: saved_db_message.credits_cost,
        actual_cost: saved_db_message.actual_cost,
        modified_cost: saved_db_message.modified_cost,
        credit_cost: saved_db_message.credit_cost,
        actual_charge: saved_db_message.actual_charge,
    };
    let client_message =
        message_for_decryption.into_decrypted_for_client(user_dek_arc.as_deref())?;

    // Use client_message.content (String) for parts if payload.parts is None
    let response_parts = payload
        .parts
        .unwrap_or_else(|| json!([{"text": client_message.content.clone()}]).into());
    let response_attachments = payload.attachments.unwrap_or_else(|| json!([]).into());

    // --- Trigger AI Response Generation (Background Task) ---
    // Only trigger if the user sent the message (system messages don't trigger AI)
    if message_role_enum == MessageRole::User {
        let state_for_gen = app_state.clone();
        let session_id_for_gen = chat_id;
        let user_id_for_gen = user_id;
        let user_dek_for_gen = user_dek_arc.clone();
        let user_message_content_for_gen = payload.content.clone();

        tokio::spawn(async move {
            info!(chat_id = %session_id_for_gen, "Spawning background task for AI response generation");

            // 1. Fetch session data and history
            let session_data_result = generation::get_session_data_for_generation(
                state_for_gen.clone(),
                user_id_for_gen,
                session_id_for_gen,
                user_message_content_for_gen.clone(),
                user_dek_for_gen.clone(),
                None, // No frontend history provided in this endpoint
            )
            .await;

            match session_data_result {
                Ok(data) => {
                    let (
                        managed_recent_history,
                        system_prompt,
                        _active_lorebook_ids,
                        _session_character_id,
                        _raw_character_system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        seed,
                        model_name,
                        model_provider,
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                        _user_db_message_to_save, // We already saved the message
                        _actual_recent_history_tokens,
                        _rag_context_items,
                        _history_management_strategy,
                        _history_management_limit,
                        _user_persona_name,
                        player_chronicle_id,
                        agent_mode,
                        game_master_mode_enabled,
                    ) = data;

                    // 2. Convert history to GenAiChatMessage
                    let mut incoming_genai_messages = Vec::new();

                    // Add history
                    if let Some(dek_arc) = &user_dek_for_gen {
                        for msg in managed_recent_history {
                            let role = match msg.message_type {
                                crate::services::chat::types::MessageRole::User => ChatRole::User,
                                crate::services::chat::types::MessageRole::Assistant => {
                                    ChatRole::Assistant
                                }
                                crate::services::chat::types::MessageRole::System => {
                                    ChatRole::System
                                }
                            };

                            match msg.decrypt_content_field(&dek_arc) {
                                Ok(content) => {
                                    incoming_genai_messages.push(GenAiChatMessage {
                                        role,
                                        content: genai::chat::MessageContent::Text(content),
                                        options: None,
                                    });
                                }
                                Err(e) => {
                                    error!(message_id = %msg.id, error = %e, "Failed to decrypt message for history, skipping");
                                }
                            }
                        }
                    }

                    // Add the current user message
                    let last_msg_content =
                        incoming_genai_messages
                            .last()
                            .and_then(|m| match &m.content {
                                genai::chat::MessageContent::Text(t) => Some(t.clone()),
                                _ => None,
                            });

                    if last_msg_content.as_deref() != Some(&user_message_content_for_gen) {
                        incoming_genai_messages.push(GenAiChatMessage {
                            role: ChatRole::User,
                            content: genai::chat::MessageContent::Text(
                                user_message_content_for_gen,
                            ),
                            options: None,
                        });
                    }

                    // 3. Prepare params
                    if let Some(dek_arc) = user_dek_for_gen {
                        let params = StreamAiParams {
                            state: state_for_gen,
                            session_id: session_id_for_gen,
                            user_id: user_id_for_gen,
                            incoming_genai_messages,
                            system_prompt,
                            temperature,
                            max_output_tokens,
                            frequency_penalty,
                            presence_penalty,
                            top_k,
                            top_p,
                            stop_sequences: None, // TODO: Fetch from settings if needed
                            seed,
                            model_name,
                            model_provider,
                            gemini_thinking_budget,
                            gemini_enable_code_execution,
                            request_thinking: false, // Default to false for now
                            user_dek: dek_arc,
                            character_name: None,
                            player_chronicle_id,
                            variant_of: None,
                            charge_credits: true, // Charge for AI response
                            game_master_mode_enabled: game_master_mode_enabled.unwrap_or(false),
                        };

                        // 4. Stream response
                        if let Err(e) =
                            generation::stream_ai_response_and_save_message(params).await
                        {
                            error!(chat_id = %session_id_for_gen, error = %e, "Failed to stream AI response");
                        }
                    } else {
                        error!(chat_id = %session_id_for_gen, "User DEK missing for AI generation");
                    }
                }
                Err(e) => {
                    error!(chat_id = %session_id_for_gen, error = %e, "Failed to get session data for generation");
                }
            }
        });
    }

    let response = MessageResponse {
        id: client_message.id,
        session_id: client_message.session_id, // Renamed from chat_id
        message_type: client_message.message_type,
        role: payload.role, // Keep original role string from request for response consistency with frontend expectations
        content: client_message.content,
        parts: response_parts,
        attachments: response_attachments,
        created_at: client_message.created_at,
        raw_prompt: client_message.raw_prompt,
        prompt_tokens: saved_db_message.prompt_tokens,
        completion_tokens: saved_db_message.completion_tokens,
        model_name: Some(saved_db_message.model_name),
        status: saved_db_message.status,
        error_message: saved_db_message.error_message,
        variant_count: saved_db_message.variant_count,
        current_variant_index: saved_db_message.current_variant_index,
        is_variant: saved_db_message.variant_count > 0,
        parent_message_id: None, // TODO: Add parent_message_id to ChatMessage struct
        variants: None,          // TODO: Load actual variants
    };

    Ok((StatusCode::CREATED, Json(response)))
}

// Get a message by ID
/// Retrieves a specific message by ID.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Message not found or access denied
/// - Database operation fails
pub async fn get_message_by_id_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let message_db: Message = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(id))
            .first::<Message>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(message_db.session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden("Access denied to message".to_string()));
    }

    let decrypted_content_string = if message_db.content.is_empty() {
        String::new()
    } else {
        let nonce_bytes_ref = message_db.content_nonce.as_deref().ok_or_else(|| {
            tracing::error!(
                "Message ID {} content nonce is missing. Cannot decrypt.",
                message_db.id
            );
            AppError::DecryptionError("Nonce missing for content decryption".to_string())
        })?;

        if nonce_bytes_ref.is_empty() {
            tracing::error!(
                "Message ID {} content nonce is present but empty. Cannot decrypt.",
                message_db.id
            );
            return Err(AppError::DecryptionError(
                "Nonce is empty for content decryption".to_string(),
            ));
        }

        crypto::decrypt_gcm(&message_db.content, nonce_bytes_ref, &dek.0)
            .map_err(|e| {
                tracing::error!(
                    "Failed to decrypt message content for get_message_by_id {}: {}",
                    message_db.id,
                    e
                );
                AppError::DecryptionError(format!(
                    "Failed to decrypt content for message {}: {}",
                    message_db.id, e
                ))
            })
            .and_then(|secret_bytes| {
                String::from_utf8(secret_bytes.expose_secret().clone()).map_err(|e| {
                    tracing::error!(
                        "UTF-8 conversion error for decrypted message {}: {}",
                        message_db.id,
                        e
                    );
                    AppError::DecryptionError(format!(
                        "UTF-8 conversion error for message {}: {}",
                        message_db.id, e
                    ))
                })
            })?
    };

    let response_parts = message_db
        .parts
        .unwrap_or_else(|| json!([{"text": decrypted_content_string}]).into());

    // Decrypt raw prompt if available
    let decrypted_raw_prompt = match (
        &message_db.raw_prompt_ciphertext,
        &message_db.raw_prompt_nonce,
    ) {
        (Some(ciphertext), Some(nonce)) if !ciphertext.is_empty() && !nonce.is_empty() => {
            crypto::decrypt_gcm(ciphertext, nonce, &dek.0)
                .map_err(|e| {
                    tracing::error!(
                        "Failed to decrypt raw prompt for message {}: {}",
                        message_db.id,
                        e
                    );
                    AppError::DecryptionError(format!(
                        "Failed to decrypt raw prompt for message {}: {}",
                        message_db.id, e
                    ))
                })
                .and_then(|secret_bytes| {
                    String::from_utf8(secret_bytes.expose_secret().clone()).map_err(|e| {
                        tracing::error!(
                            "UTF-8 conversion error for decrypted raw prompt {}: {}",
                            message_db.id,
                            e
                        );
                        AppError::DecryptionError(format!(
                            "UTF-8 conversion error for raw prompt {}: {}",
                            message_db.id, e
                        ))
                    })
                })
                .ok() // Convert Result to Option, ignoring errors for raw prompt
        }
        _ => None, // No raw prompt stored or empty/missing fields
    };

    // If this is a variant (index > 0), try to fetch the raw prompt from the variant itself
    #[cfg(feature = "sqlite-backend")]
    let decrypted_raw_prompt = if message_db.current_variant_index > 0 {
        let pool = state.pool.clone();
        let msg_id = message_db.id;
        let var_idx = message_db.current_variant_index;
        // Clone the secret key for the closure
        use secrecy::ExposeSecret;
        let dek_bytes = dek.0.expose_secret().clone();
        let dek_box = SecretBox::new(Box::new(dek_bytes));

        let variant_raw_prompt_res = crate::db::with_conn(&pool, move |conn| {
            use crate::models::chats::MessageVariant;

            let variant_opt = message_variants::table
                .filter(message_variants::parent_message_id.eq(msg_id))
                .filter(message_variants::variant_index.eq(var_idx))
                .first::<MessageVariant>(conn)
                .optional()
                .map_err(AppError::from)?;

            Ok::<_, AppError>(variant_opt)
        })
        .await;

        match variant_raw_prompt_res {
            Ok(Some(variant)) => {
                match (&variant.raw_prompt_ciphertext, &variant.raw_prompt_nonce) {
                    (Some(ciphertext), Some(nonce))
                        if !ciphertext.is_empty() && !nonce.is_empty() =>
                    {
                        crypto::decrypt_gcm(ciphertext, nonce, &dek_box)
                            .map_err(|e| {
                                tracing::error!("Failed to decrypt variant raw prompt: {}", e);
                                AppError::DecryptionError(e.to_string())
                            })
                            .and_then(|secret_bytes| {
                                String::from_utf8(secret_bytes.expose_secret().clone()).map_err(
                                    |e| {
                                        tracing::error!("UTF-8 error variant raw prompt: {}", e);
                                        AppError::DecryptionError(e.to_string())
                                    },
                                )
                            })
                            .ok()
                    }
                    _ => decrypted_raw_prompt,
                }
            }
            Ok(None) => decrypted_raw_prompt,
            Err(e) => {
                tracing::warn!("Failed to fetch variant for raw prompt: {}", e);
                decrypted_raw_prompt
            }
        }
    } else {
        decrypted_raw_prompt
    };

    let response = MessageResponse {
        id: message_db.id,
        session_id: message_db.session_id,
        message_type: message_db.message_type,
        role: message_db
            .role
            .unwrap_or_else(|| message_db.message_type.to_string()),
        content: decrypted_content_string,
        parts: response_parts,
        attachments: message_db.attachments.unwrap_or_else(|| json!([]).into()),
        created_at: message_db.created_at,
        raw_prompt: decrypted_raw_prompt,
        prompt_tokens: message_db.prompt_tokens,
        completion_tokens: message_db.completion_tokens,
        model_name: Some(message_db.model_name),
        status: message_db.status,
        error_message: message_db.error_message,
        variant_count: message_db.variant_count,
        current_variant_index: message_db.current_variant_index,
        is_variant: false,
        parent_message_id: None,
        variants: None,
    };

    Ok(Json(response))
}

// Vote on a message
/// Records a vote for a message.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Message not found or access denied
/// - Database operation fails
#[cfg(feature = "postgres-backend")]
pub async fn vote_message_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
    Json(payload): Json<VoteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to find its chat ID
    let message = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(id))
            .first::<Message>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Check if user has access to the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(message.session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden("Access denied to vote".to_string()));
    }

    let is_upvoted = payload.type_ == "up";

    // Insert or update the vote
    crate::db::with_conn(&pool, move |conn| {
        diesel::insert_into(crate::schema::old_votes::table) // Use old_votes
            .values((
                crate::schema::old_votes::dsl::chat_id.eq(message.session_id), // Use old_votes::dsl
                crate::schema::old_votes::dsl::message_id.eq(id),              // Use old_votes::dsl
                crate::schema::old_votes::dsl::is_upvoted.eq(is_upvoted),      // Use old_votes::dsl
            ))
            .on_conflict((
                crate::schema::old_votes::dsl::chat_id,
                crate::schema::old_votes::dsl::message_id,
            )) // Use old_votes::dsl
            .do_update()
            .set(crate::schema::old_votes::dsl::is_upvoted.eq(is_upvoted)) // Use old_votes::dsl
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    Ok(StatusCode::OK)
}

// Get votes for a chat
/// Retrieves all votes for messages in a chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
#[cfg(feature = "postgres-backend")]
pub async fn get_votes_by_chat_id_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user has access to the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden("Access denied to votes".to_string()));
    }

    // Get all votes for the chat
    let votes = crate::db::with_conn(&pool, move |conn| {
        crate::schema::old_votes::table // Use old_votes
            .filter(crate::schema::old_votes::dsl::chat_id.eq(id)) // Use old_votes::dsl
            .load::<(crate::db::DbId, crate::db::DbId, bool)>(conn)
            .map(|rows| {
                rows.into_iter()
                    .map(|(chat_id, message_id, is_upvoted)| Vote {
                        chat_id,
                        message_id,
                        is_upvoted,
                    })
                    .collect::<Vec<Vote>>()
            })
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    Ok(Json(votes))
}

// Delete messages after a certain point in a chat
/// Deletes trailing messages from a chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
pub async fn delete_trailing_messages_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to find its timestamp and chat ID
    let message = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(id))
            .first::<Message>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Check if user owns the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(message.session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to delete messages".to_string(),
        ));
    }

    // Get all messages to delete
    let chat_id = message.session_id;
    let timestamp = message.created_at;

    let message_ids = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::session_id.eq(chat_id))
            .filter(chat_messages::created_at.ge(timestamp))
            .select(chat_messages::id)
            .load::<crate::db::DbId>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if !message_ids.is_empty() {
        // Clone message_ids for different operations
        let message_ids_clone_for_messages = message_ids.clone();
        let message_ids_clone_for_embeddings = message_ids.clone();
        let message_ids_clone_for_variants = message_ids.clone();

        // Fix for SQLite foreign key constraint:
        // chronicle_events references message_variants(id) but might not have ON DELETE CASCADE.
        // We must manually set message_variant_id to NULL for any events referencing variants of these messages
        // before we delete the messages (which cascades to variants).
        #[cfg(feature = "sqlite-backend")]
        let variant_ids: Vec<String> = {
            let message_ids_strings: Vec<String> = message_ids_clone_for_variants
                .iter()
                .map(|id| id.to_string())
                .collect();
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::message_variants::dsl as mv_dsl;
                mv_dsl::message_variants
                    .filter(mv_dsl::parent_message_id.eq_any(message_ids_strings))
                    .select(mv_dsl::id)
                    .load::<String>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        };

        #[cfg(feature = "postgres-backend")]
        let variant_ids: Vec<uuid::Uuid> = {
            let message_uuids: Vec<uuid::Uuid> = message_ids_clone_for_variants
                .iter()
                .map(|&id| id.into())
                .collect();
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::message_variants::dsl as mv_dsl;
                mv_dsl::message_variants
                    .filter(mv_dsl::parent_message_id.eq_any(message_uuids))
                    .select(mv_dsl::id)
                    .load::<uuid::Uuid>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        };

        if !variant_ids.is_empty() {
            tracing::info!(
                "Cleaning up {} variants referenced in chronicle events before trailing message deletion",
                variant_ids.len()
            );
            #[cfg(feature = "sqlite-backend")]
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::chronicle_events::dsl as ce_dsl;
                diesel::update(
                    ce_dsl::chronicle_events.filter(ce_dsl::message_variant_id.eq_any(variant_ids)),
                )
                .set(ce_dsl::message_variant_id.eq(None::<String>))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

            #[cfg(feature = "postgres-backend")]
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::chronicle_events::dsl as ce_dsl;
                diesel::update(
                    ce_dsl::chronicle_events.filter(ce_dsl::message_variant_id.eq_any(variant_ids)),
                )
                .set(ce_dsl::message_variant_id.eq(None::<uuid::Uuid>))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
        }

        // Fix for SQLite foreign key constraint:
        // agent_context_analysis references chat_messages(id) via assistant_message_id but might not have ON DELETE CASCADE.
        // We must manually delete these analysis records before deleting the messages.
        #[cfg(feature = "sqlite-backend")]
        {
            let message_ids_strings: Vec<String> = message_ids_clone_for_variants
                .iter()
                .map(|id| id.to_string())
                .collect();
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::agent_context_analysis::dsl as aca_dsl;
                diesel::delete(
                    aca_dsl::agent_context_analysis
                        .filter(aca_dsl::assistant_message_id.eq_any(message_ids_strings)),
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
        }

        #[cfg(feature = "postgres-backend")]
        {
            let message_uuids: Vec<uuid::Uuid> = message_ids.iter().map(|&id| id.into()).collect();
            crate::db::with_conn(&pool, move |conn| {
                use crate::schema::agent_context_analysis::dsl as aca_dsl;
                diesel::delete(
                    aca_dsl::agent_context_analysis
                        .filter(aca_dsl::assistant_message_id.eq_any(message_uuids)),
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
        }

        // Delete associated votes first (PostgreSQL only - old_votes table)
        #[cfg(feature = "postgres-backend")]
        {
            crate::db::with_conn(&pool, move |conn| {
                // This closure moves the original message_ids
                let message_uuids: Vec<uuid::Uuid> =
                    message_ids.iter().map(|&id| id.into()).collect();
                diesel::delete(crate::schema::old_votes::table) // Use old_votes
                    .filter(crate::schema::old_votes::dsl::chat_id.eq(chat_id)) // Use old_votes::dsl
                    .filter(crate::schema::old_votes::dsl::message_id.eq_any(message_uuids)) // Use converted UUIDs
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
        }

        // Delete embeddings from Qdrant
        if let Err(e) = state
            .embedding_pipeline_service
            .delete_message_chunks(
                Arc::new(state.clone()),
                message_ids_clone_for_embeddings,
                user.id,
            )
            .await
        {
            // Log error but don't fail the whole operation
            tracing::warn!("Failed to delete message embeddings from Qdrant: {}", e);
        }

        // Now delete the messages from the database
        crate::db::with_conn(&pool, move |conn| {
            // This closure moves the clone
            #[cfg(feature = "postgres-backend")]
            {
                let message_uuids: Vec<uuid::Uuid> = message_ids_clone_for_messages
                    .iter()
                    .map(|&id| id.into())
                    .collect();
                diesel::delete(chat_messages::table)
                    .filter(chat_messages::session_id.eq(chat_id))
                    .filter(chat_messages::id.eq_any(message_uuids))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            }

            #[cfg(feature = "sqlite-backend")]
            {
                let message_strings: Vec<String> = message_ids_clone_for_messages
                    .iter()
                    .map(|id| id.to_string())
                    .collect();
                diesel::delete(chat_messages::table)
                    .filter(chat_messages::session_id.eq(chat_id))
                    .filter(chat_messages::id.eq_any(message_strings))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            }
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a single message by ID.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Message not found or access denied
/// - Database operation fails
pub async fn delete_message_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to verify ownership
    let message = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(id))
            .first::<Message>(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => {
                    AppError::NotFound("Message not found".to_string())
                }
                _ => AppError::DatabaseQueryError(e.to_string()),
            })
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    // Check if user owns the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(message.session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to delete message".to_string(),
        ));
    }

    let message_id = message.id;
    let chat_id = message.session_id;

    // Delete associated votes first (PostgreSQL only - old_votes table)
    #[cfg(feature = "postgres-backend")]
    {
        crate::db::with_conn(&pool, move |conn| {
            diesel::delete(
                crate::schema::old_votes::table
                    .filter(crate::schema::old_votes::dsl::chat_id.eq(chat_id))
                    .filter(crate::schema::old_votes::dsl::message_id.eq(message_id)),
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    }

    // Fix for SQLite foreign key constraint:
    // chronicle_events references message_variants(id) but might not have ON DELETE CASCADE.
    // We must manually set message_variant_id to NULL for any events referencing variants of this message
    // before we delete the message (which cascades to variants).
    #[cfg(feature = "sqlite-backend")]
    let variant_ids: Vec<String> = {
        let message_id_str = message_id.to_string();
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::message_variants::dsl as mv_dsl;
            mv_dsl::message_variants
                .filter(mv_dsl::parent_message_id.eq(message_id_str))
                .select(mv_dsl::id)
                .load::<String>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
    };

    #[cfg(feature = "postgres-backend")]
    let variant_ids: Vec<uuid::Uuid> = {
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::message_variants::dsl as mv_dsl;
            mv_dsl::message_variants
                .filter(mv_dsl::parent_message_id.eq(message_id))
                .select(mv_dsl::id)
                .load::<uuid::Uuid>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
    };

    if !variant_ids.is_empty() {
        tracing::info!(
            "Cleaning up {} variants referenced in chronicle events before message deletion",
            variant_ids.len()
        );
        #[cfg(feature = "sqlite-backend")]
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::chronicle_events::dsl as ce_dsl;
            diesel::update(
                ce_dsl::chronicle_events.filter(ce_dsl::message_variant_id.eq_any(variant_ids)),
            )
            .set(ce_dsl::message_variant_id.eq(None::<String>))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

        #[cfg(feature = "postgres-backend")]
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::chronicle_events::dsl as ce_dsl;
            diesel::update(
                ce_dsl::chronicle_events.filter(ce_dsl::message_variant_id.eq_any(variant_ids)),
            )
            .set(ce_dsl::message_variant_id.eq(None::<uuid::Uuid>))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    }

    // Fix for SQLite foreign key constraint:
    // agent_context_analysis references chat_messages(id) via assistant_message_id but might not have ON DELETE CASCADE.
    // We must manually delete these analysis records before deleting the message.
    #[cfg(feature = "sqlite-backend")]
    {
        let message_id_str = message_id.to_string();
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::agent_context_analysis::dsl as aca_dsl;
            diesel::delete(
                aca_dsl::agent_context_analysis
                    .filter(aca_dsl::assistant_message_id.eq(message_id_str)),
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    }

    #[cfg(feature = "postgres-backend")]
    {
        crate::db::with_conn(&pool, move |conn| {
            use crate::schema::agent_context_analysis::dsl as aca_dsl;
            diesel::delete(
                aca_dsl::agent_context_analysis
                    .filter(aca_dsl::assistant_message_id.eq(message_id)),
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    }

    // Delete embeddings from Qdrant
    if let Err(e) = state
        .embedding_pipeline_service
        .delete_message_chunks(Arc::new(state.clone()), vec![message_id], user.id)
        .await
    {
        // Log error but don't fail the whole operation
        tracing::warn!("Failed to delete message embeddings from Qdrant: {}", e);
    }

    // Delete the message from PostgreSQL
    crate::db::with_conn(&pool, move |conn| {
        diesel::delete(chat_messages::table.filter(chat_messages::id.eq(message_id)))
            .execute(conn)
            .map_err(|e| {
                tracing::error!("Failed to delete message from DB: {:?}", e);
                AppError::DatabaseQueryError(e.to_string())
            })
    })
    .await
    .map_err(|e| {
        tracing::error!("Failed to delete message (outer error): {:?}", e);
        AppError::InternalServerErrorGeneric(e.to_string())
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// Update chat visibility
/// Updates the visibility of a chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
pub async fn update_chat_visibility_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
    Json(payload): Json<UpdateChatVisibilityRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user owns the chat
    let chat = crate::db::with_conn(&pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to update chat visibility".to_string(),
        ));
    }

    // Ensure visibility is one of the allowed values
    if payload.visibility != "public" && payload.visibility != "private" {
        return Err(AppError::BadRequest(
            "Visibility must be 'public' or 'private'".to_string(),
        ));
    }

    // Update the chat visibility
    crate::db::with_conn(&pool, move |conn| {
        diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(id)))
            .set(chat_sessions::visibility.eq(payload.visibility))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

    Ok(StatusCode::OK)
}

/// Retrieves chat settings for a specific session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
/// - Decryption fails
pub async fn get_chat_settings_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek,                 // Added SessionDek extractor
    Path(id): Path<crate::db::DbId>, // This is session_id
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Call the service function to get chat settings
    // The service function handles ownership check and constructing the response
    let chat_settings_response = chat::settings::get_session_settings(
        &state.pool,
        user.id,
        id,           // session_id
        Some(&dek.0), // Pass the DEK for decryption
    )
    .await?;

    info!(session_id = %id, user_id = %user.id,
          response_system_prompt_is_some = chat_settings_response.system_prompt.is_some(),
          response_system_prompt_len = chat_settings_response.system_prompt.as_ref().map(|s| s.len()).unwrap_or(0),
          "get_chat_settings_handler: Returning response to client");

    Ok(Json(chat_settings_response))
}

/// Updates chat settings for a specific session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Validation fails
/// - Database operation fails
/// - Encryption fails
pub async fn update_chat_settings_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor
    Path(id): Path<crate::db::DbId>,
    crate::extractors::JsonExtractor(payload): crate::extractors::JsonExtractor<
        UpdateChatSettingsRequest,
    >,
) -> Result<impl IntoResponse, AppError> {
    // Manually validate the payload
    payload.validate()?; // Ensure validator is imported and used

    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let user_id = user.id; // Clone user_id for use in service call

    // Use the service function which handles encryption and ownership checks
    let response = chat::settings::update_session_settings(
        &state.pool,
        user_id,
        id,
        payload,
        Some(&dek.0), // Pass the DEK from SessionDek
    )
    .await?;

    Ok((StatusCode::OK, Json(response)))
}

// DTOs for deletion analysis
#[derive(Debug, Serialize)]
pub struct ChronicleAnalysisDto {
    pub id: crate::db::DbId,
    pub name: String,
    pub total_events: i32,
    pub events_from_this_chat: i32,
    pub other_chats_using_chronicle: i32,
    pub can_delete_chronicle: bool,
}

#[derive(Debug, Serialize)]
pub struct ChatDeletionAnalysisResponse {
    pub has_chronicle: bool,
    pub chronicle: Option<ChronicleAnalysisDto>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteChatQueryParams {
    #[serde(default = "default_chronicle_action")]
    pub chronicle_action: String, // "delete_chronicle" | "disassociate" | "delete_events"
}

fn default_chronicle_action() -> String {
    "delete_events".to_string()
}

/// Get token usage statistics for a specific chat session
#[axum::debug_handler]
async fn get_chat_token_usage_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(id): Path<crate::db::DbId>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(chat_id = %id, "Getting chat token usage statistics");

    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Fetch the chat session to verify ownership and get token statistics
    let user_id = user.id;
    let chat = crate::db::with_conn(&state.pool, move |conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => {
                    AppError::NotFound("Chat not found or access denied".to_string())
                }
                _ => {
                    tracing::error!("Database error querying chat: {}", e);
                    AppError::DatabaseQueryError("Failed to query chat".to_string())
                }
            })
    })
    .await?;

    let total_tokens = chat.total_prompt_tokens + chat.total_completion_tokens;
    let estimated_cost_dollars = chat.estimated_cost_cents as f64 / 100.0;

    // Get model_name from most recent message
    let model_name_query = crate::db::with_conn(&state.pool, move |conn| {
        chat_messages::table
            .select(chat_messages::model_name)
            .filter(chat_messages::session_id.eq(id))
            .order_by(chat_messages::created_at.desc())
            .first::<String>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await?;

    let model_name = model_name_query.unwrap_or_else(|| "unknown".to_string());

    let token_usage = ChatTokenUsage {
        chat_id: id,
        total_prompt_tokens: chat.total_prompt_tokens,
        total_completion_tokens: chat.total_completion_tokens,
        total_tokens,
        estimated_cost_cents: chat.estimated_cost_cents,
        estimated_cost_dollars,
        tokens_counted_at: chat.tokens_counted_at,
        model_name,
    };

    Ok((StatusCode::OK, Json(token_usage)))
}

/// Select a variant for a message
/// Updates the current_variant_index and returns the message with new content
pub async fn select_message_variant_handler(
    auth: UnifiedAuth,
    State(state): State<AppState>,
    Path(message_id): Path<crate::db::DbId>,
    dek: SessionDek, // Added SessionDek extractor
    Json(payload): Json<SelectVariantRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    let pool = state.pool.clone();

    // Verify the message exists and user has access
    let message_db = crate::db::with_conn(&pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(message_id))
            .filter(chat_messages::user_id.eq(user.id))
            .first::<Message>(conn)
            .optional()
            .map_err(Into::into)
    })
    .await?
    .ok_or_else(|| AppError::NotFound("Message not found".to_string()))?;

    // Validate variant index
    if payload.variant_index < 0 || payload.variant_index >= message_db.variant_count {
        return Err(AppError::BadRequest(format!(
            "Invalid variant index: {}. Message has {} variants (0-{})",
            payload.variant_index,
            message_db.variant_count,
            message_db.variant_count - 1
        )));
    }

    // Update the current_variant_index in the database
    let pool_clone = pool.clone();
    let updated_message =
        crate::db::with_conn(&pool_clone, move |conn| -> Result<Message, AppError> {
            diesel::update(chat_messages::table.filter(chat_messages::id.eq(message_id)))
                .set(chat_messages::current_variant_index.eq(payload.variant_index))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Get the updated message
            chat_messages::table
                .filter(chat_messages::id.eq(message_id))
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?;

    // Get the content for the selected variant
    let content = if payload.variant_index == 0 {
        // Variant 0 means use original message content
        let client_message = updated_message
            .clone()
            .into_decrypted_for_client(Some(&dek.0))?;
        client_message.content
    } else {
        // Get content from the variants table
        get_variant_content_by_index(
            pool.clone(),
            message_id,
            payload.variant_index,
            user.id,
            &dek,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Variant not found".to_string()))?
    };

    // Return the updated message response
    let response = MessageResponse {
        id: updated_message.id,
        session_id: updated_message.session_id,
        message_type: updated_message.message_type,
        role: updated_message
            .role
            .unwrap_or_else(|| updated_message.message_type.to_string()),
        content,
        parts: updated_message.parts.unwrap_or_else(|| json!([]).into()),
        attachments: updated_message
            .attachments
            .unwrap_or_else(|| json!([]).into()),
        created_at: updated_message.created_at,
        raw_prompt: None, // Don't expose raw prompts in variant selection
        prompt_tokens: updated_message.prompt_tokens,
        completion_tokens: updated_message.completion_tokens,
        model_name: Some(updated_message.model_name),
        status: updated_message.status,
        error_message: updated_message.error_message,
        variant_count: updated_message.variant_count,
        current_variant_index: updated_message.current_variant_index,
        is_variant: false,
        parent_message_id: None,
        variants: None,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Helper function to get variant content by index
async fn get_variant_content_by_index(
    pool: DbPool,
    message_id: crate::db::DbId,
    variant_index: i32,
    user_id: crate::db::DbId,
    dek: &SessionDek,
) -> Result<Option<String>, AppError> {
    use crate::schema::message_variants;

    let dek_ref = &dek.0;
    let variant_opt = crate::db::with_conn(&pool, move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .filter(message_variants::variant_index.eq(variant_index))
            .first::<crate::models::chats::MessageVariant>(conn)
            .optional()
            .map_err(Into::into)
    })
    .await?;

    if let Some(variant) = variant_opt {
        let content = variant.decrypt_content(dek_ref)?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}
