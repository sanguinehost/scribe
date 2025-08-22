use crate::PgPool; // Added PgPool import
use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::auth::user_store::Backend as AuthBackend;
use crate::crypto; // Added crypto for encryption/decryption
use crate::errors::AppError;
use crate::models::chat_override::CharacterOverrideDto; // Added for override handler
use crate::models::chats::{
    Chat,
    // ChatSettingsResponse, // Not used directly in this file anymore
    CreateChatRequest,    // Now available
    CreateMessageRequest, // Now available
    Message,
    MessageResponse, // Now available
    MessageRole,
    UpdateChatSettingsRequest,
    UpdateChatVisibilityRequest, // Now available
    Vote,                        // Now available
    VoteRequest,                 // Now available
};
use crate::models::users::User; // Added User import
use crate::schema::{chat_messages, chat_sessions};
use axum::{
    Router,
    extract::{Path, Query, State}, // Added Query
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
};
use axum_login::AuthSession;
use secrecy::ExposeSecret; // Added for expose_secret method
use secrecy::SecretBox; // Ensure SecretBox is imported
// Removed incorrect ValidatedJson import
use crate::services::chat;
use crate::state::AppState;
use diesel::{ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl, SelectableHelper};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};
// ExposeSecret already imported above
use serde::{Deserialize, Serialize}; // Added Deserialize
use uuid::Uuid;
use validator::Validate; // Remove unused Deserialize
use chrono::{DateTime, Utc}; // Added for cursor-based pagination

// Shorthand for auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn chat_routes() -> Router<crate::state::AppState> {
    tracing::debug!("chat_routes: entering chat_routes function");
    Router::new()
        .route("/", get(get_chats_handler)) // Keep GET / for listing
        .route("/create_session", post(create_chat_handler)) // More distinct path for POST
        .route("/fetch/:id", get(get_chat_by_id_handler))
        .route("/remove/:id", delete(delete_chat_handler))
        .route("/:id/deletion-analysis", get(get_chat_deletion_analysis_handler))
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
        .route("/messages/:id", get(get_message_by_id_handler).delete(delete_message_handler))
        .route("/messages/:id/vote", post(vote_message_handler))
        .route(
            "/messages/:id/trailing",
            delete(delete_trailing_messages_handler),
        )
        .route("/:id/votes", get(get_votes_by_chat_id_handler))
        .route(
            "/:id/character/overrides",
            post(set_chat_character_override_handler),
        )
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek,              // Added SessionDek extractor
    Path(session_id): Path<Uuid>, // Renamed id to session_id for clarity
    Json(payload): Json<CharacterOverrideDto>,
) -> Result<impl IntoResponse, AppError> {
    #[derive(Serialize)]
    struct OverrideResponse {
        message: String,
        session_id: Uuid,
        field_name: String,
        new_value: String,
        // Include original fields for compatibility with existing tests
        id: Uuid,
        chat_session_id: Uuid,
        original_character_id: Uuid,
        overridden_value: Vec<u8>,
        overridden_value_nonce: Option<Vec<u8>>,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    // Validate the payload first
    payload.validate()?;

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    tracing::info!(target: "scribe_backend::routes::chats", %session_id, user_id = %user.id, field_name = %payload.field_name, "Attempting to set chat character override");

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek,
    Path(character_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chats = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::user_id.eq(user.id))
                .filter(chat_sessions::character_id.eq(character_id))
                .order_by(chat_sessions::created_at.desc())
                .select(Chat::as_select())
                .load::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor for decryption
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chats = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::user_id.eq(user.id))
                .order_by(chat_sessions::created_at.desc())
                .select(Chat::as_select()) // Added select
                .load::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor for encryption
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    // Use the SessionDek which provides the user's DEK
    let user_dek_arc = Some(Arc::new(SecretBox::new(Box::new(
        dek.0.expose_secret().clone(),
    ))));

    info!(%user.id, character_id=%payload.character_id, lorebook_ids=?payload.lorebook_ids, "Creating chat session");

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
    .await?;

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
                    pool.get()
                        .await
                        .map_err(|e| AppError::DbPoolError(e.to_string()))?
                        .interact(move |conn| {
                            diesel::update(chat_sessions::table.find(session_id))
                                .set((
                                    chat_sessions::title_ciphertext.eq(Some(ciphertext)),
                                    chat_sessions::title_nonce.eq(Some(nonce)),
                                ))
                                .execute(conn)
                                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
                        })
                        .await
                        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
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
        title_present = chat.title_ciphertext.is_some() // Also avoid logging title directly
        // Removed full 'chat = ?chat' to avoid logging all fields, including encrypted ones
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(AppError::from) // Use From trait to handle NotFound correctly
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // First verify the user owns this chat
    let pool = state.pool.clone();
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .filter(chat_sessions::user_id.eq(user.id)) // Ensure ownership
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(format!("Chat not found or access denied: {e}")))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Get chronicle analysis if this chat has one
    let chronicle_service = crate::services::ChronicleService::new(state.pool.clone());
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<DeleteChatQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user owns the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .filter(chat_sessions::user_id.eq(user.id)) // Ensure ownership
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(format!("Chat not found or access denied: {e}")))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let chronicle_service = crate::services::ChronicleService::new(state.pool.clone());

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
                    .delete_chronicle_events_by_chronicle_id(Arc::new(state.clone()), chronicle_id, user.id)
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
                
                info!("Disassociated {} events from chat {}", disassociated_count, id);
                
                // Note: We don't clean up embeddings because events are preserved
            }

            "delete_events" | _ => {
                info!("Strategy: Delete only events created by this chat (default)");
                
                // Clean up embeddings for events from this specific chat
                match chronicle_service.get_events_for_chat_session(user.id, id).await {
                    Ok(events) => {
                        info!("Found {} chronicle events from this chat to clean up", events.len());
                        
                        for event in events {
                            if let Err(e) = state
                                .embedding_pipeline_service
                                .delete_chronicle_event_chunks(Arc::new(state.clone()), event.id, user.id)
                                .await
                            {
                                error!(
                                    event_id = %event.id,
                                    error = %e,
                                    "Failed to clean up embeddings for chronicle event, continuing with deletion"
                                );
                            }
                        }
                    },
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
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(chat_sessions::table.filter(chat_sessions::id.eq(id)))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    info!("Successfully deleted chat session {} with strategy '{}'", id, params.chronicle_action);
    Ok(StatusCode::NO_CONTENT)
}

// Query parameters for fetching messages
#[derive(Debug, Deserialize)]
pub struct GetMessagesQueryParams {
    #[serde(default = "default_message_limit")]
    pub limit: i64,
    pub cursor: Option<DateTime<Utc>>, // Timestamp of the last message from previous batch
}

fn default_message_limit() -> i64 {
    20
}

// Response structure for paginated messages
#[derive(Debug, Serialize)]
pub struct PaginatedMessagesResponse {
    pub messages: Vec<MessageResponse>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<DateTime<Utc>>,
}

/// Helper function to validate and parse the chat ID
///
/// # Errors
///
/// Returns `AppError::BadRequest` if the provided string is not a valid UUID format
fn parse_chat_id(id: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(id).map_err(|_| AppError::BadRequest("Invalid UUID format in path".to_string()))
}

/// Helper function to get authenticated user
fn get_authenticated_user(auth_session: CurrentAuthSession) -> Result<User, AppError> {
    auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))
}

/// Helper function to fetch chat session and verify ownership
async fn fetch_and_verify_chat_ownership(
    pool: PgPool,
    chat_id: Uuid,
    user_id: Uuid,
) -> Result<Chat, AppError> {
    pool.get()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get connection from pool: {}", e);
            AppError::DbPoolError(e.to_string())
        })?
        .interact(move |conn| fetch_chat_with_ownership_check(conn, chat_id, user_id))
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
}

/// Database operation to fetch chat and check ownership
fn fetch_chat_with_ownership_check(
    conn: &mut PgConnection,
    chat_id: Uuid,
    user_id: Uuid,
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

    tracing::debug!("Successfully verified chat ownership for user {}", user_id);
    Ok(chat)
}

/// Helper function to fetch messages for a chat session with pagination
async fn fetch_paginated_chat_messages(
    pool: PgPool,
    chat_id: Uuid,
    limit: i64,
    cursor: Option<DateTime<Utc>>,
) -> Result<Vec<Message>, AppError> {
    pool.get()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get connection from pool for paginated messages query: {}",
                e
            );
            AppError::DbPoolError(e.to_string())
        })?
        .interact(move |conn| {
            tracing::debug!(
                "Fetching paginated messages for session_id = {}, limit = {}, cursor = {:?}",
                chat_id,
                limit,
                cursor
            );
            let mut query = chat_messages::table
                .filter(chat_messages::session_id.eq(chat_id))
                .filter(chat_messages::superseded_at.is_null()) // Only get active (non-superseded) messages
                .filter(chat_messages::status.eq("completed")) // Only get completed messages
                .order_by(chat_messages::created_at.desc()) // Order by descending for reverse pagination
                .limit(limit)
                .select(Message::as_select())
                .into_boxed(); // Use into_boxed to allow dynamic query building

            if let Some(cursor_timestamp) = cursor {
                query = query.filter(chat_messages::created_at.lt(cursor_timestamp));
            }

            let result = query.load::<Message>(conn);

            match &result {
                Ok(messages) => {
                    tracing::debug!(
                        "Found {} paginated messages for chat {}",
                        messages.len(),
                        chat_id
                    )
                }
                Err(e) => tracing::error!("Error fetching paginated messages: {}", e),
            }

            result.map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| {
            tracing::error!("Join error in paginated messages query: {}", e);
            AppError::InternalServerErrorGeneric(e.to_string())
        })?
}

/// Helper function to get the default variant content for a message (variant index 0)
async fn get_default_variant_content(
    pool: PgPool,
    message_id: Uuid,
    user_id: Uuid,
    dek: &crate::auth::session_dek::SessionDek,
) -> Result<Option<String>, AppError> {
    use crate::schema::message_variants;
    use crate::models::chats::MessageVariant;
    use diesel::OptionalExtension; // Add this import for .optional()

    let conn = pool.get().await?;
    
    let variant_opt = conn
        .interact(move |conn| {
            message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .filter(message_variants::user_id.eq(user_id))
                .filter(message_variants::variant_index.eq(0)) // Always get variant 0 (original)
                .select(MessageVariant::as_select())
                .first::<MessageVariant>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    pool: PgPool,
    user_id: Uuid,
) -> Result<Vec<MessageResponse>, AppError> {
    let mut responses = Vec::new();

    for msg_db in messages_db {
        // First try to get variant 0 content, fall back to original message content
        let content = match get_default_variant_content(pool.clone(), msg_db.id, user_id, dek).await? {
            Some(variant_content) => variant_content,
            None => {
                // No variants exist, use original message content
                let decrypted_client_message = msg_db.clone().into_decrypted_for_client(Some(&dek.0))?;
                decrypted_client_message.content
            }
        };

        // Update parts to use the variant content or original content
        let response_parts = msg_db
            .parts
            .unwrap_or_else(|| json!([{"text": content.clone()}]));
        let response_attachments = msg_db.attachments.unwrap_or_else(|| json!([]));

        let response_role = msg_db
            .role
            .unwrap_or_else(|| msg_db.message_type.to_string());

        // For raw_prompt, still decrypt from the original message
        let raw_prompt = match (
            &msg_db.raw_prompt_ciphertext,
            &msg_db.raw_prompt_nonce,
        ) {
            (Some(ciphertext), Some(nonce)) if !ciphertext.is_empty() && !nonce.is_empty() => {
                crate::crypto::decrypt_gcm(ciphertext, nonce, &dek.0)
                    .ok()
                    .and_then(|secret_bytes| {
                        String::from_utf8(secret_bytes.expose_secret().clone()).ok()
                    })
            }
            _ => None,
        };

        responses.push(MessageResponse {
            id: msg_db.id,
            session_id: msg_db.session_id,
            message_type: msg_db.message_type,
            role: response_role,
            parts: response_parts,
            attachments: response_attachments,
            created_at: msg_db.created_at,
            raw_prompt,
            prompt_tokens: msg_db.prompt_tokens,
            completion_tokens: msg_db.completion_tokens,
            model_name: Some(msg_db.model_name), // Added model_name from database record
        });
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
    auth_session: CurrentAuthSession,
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
    let user = get_authenticated_user(auth_session)?;

    tracing::debug!("Parsed chat_id = {}, user_id = {}", chat_id, user.id);

    // Fetch chat session and verify ownership
    let _chat = fetch_and_verify_chat_ownership(state.pool.clone(), chat_id, user.id).await?;

    // Fetch paginated messages for the chat
    let messages_db =
        fetch_paginated_chat_messages(state.pool.clone(), chat_id, params.limit, params.cursor)
            .await?;

    // Decrypt and transform messages for response with variant support
    let mut responses =
        process_messages_for_response(messages_db, &dek, state.pool.clone(), user.id).await?;

    // Determine the next cursor
    let next_cursor = responses.last().map(|msg| msg.created_at);

    // Reverse the order of messages to be chronological for the frontend
    responses.reverse();

    Ok(Json(PaginatedMessagesResponse {
        messages: responses,
        next_cursor,
    }))
}

// Create a message
/// Creates a new message in a chat session.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Validation fails
/// - Database operation fails
/// - Encryption fails
pub async fn create_message_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor
    Path(chat_id): Path<Uuid>,
    Json(payload): Json<CreateMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let user_id = user.id;

    // Use the SessionDek which provides the user's DEK
    let user_dek_arc = Some(Arc::new(SecretBox::new(Box::new(
        dek.0.expose_secret().clone(),
    ))));

    // Verify chat session ownership (existing logic is fine)
    let chat = state
        .pool
        .get()
        .await // Keep this verification block
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(chat_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to create message".to_string(),
        ));
    }

    let message_role_enum = if payload.role.to_lowercase() == "user" {
        MessageRole::User
    } else {
        MessageRole::Assistant
    };

    // Save the message
    let saved_db_message =
        chat::message_handling::save_message(chat::message_handling::SaveMessageParams {
            state: Arc::new(state.clone()),
            session_id: chat_id,
            user_id,
            message_type_enum: message_role_enum,
            content: &payload.content,
            role_str: Some(payload.role.clone()),
            parts: payload.parts.clone(),
            attachments: payload.attachments.clone(),
            user_dek_secret_box: user_dek_arc.clone(),
            model_name: chat.model_name.clone(),
            raw_prompt_debug: None, // Manual message creation doesn't need raw prompt debug
            status: crate::models::chats::MessageStatus::Completed,
            error_message: None,
        })
        .await?;

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
        status: saved_db_message.status,
        error_message: saved_db_message.error_message,
        superseded_at: saved_db_message.superseded_at,
    };
    let client_message =
        message_for_decryption.into_decrypted_for_client(user_dek_arc.as_deref())?;

    // Use client_message.content (String) for parts if payload.parts is None
    let response_parts = payload
        .parts
        .unwrap_or_else(|| json!([{"text": client_message.content.clone()}]));
    let response_attachments = payload.attachments.unwrap_or_else(|| json!([]));

    let response = MessageResponse {
        id: client_message.id,
        session_id: client_message.session_id, // Renamed from chat_id
        message_type: client_message.message_type,
        role: payload.role, // Keep original role string from request for response consistency with frontend expectations
        parts: response_parts,
        attachments: response_attachments,
        created_at: client_message.created_at,
        raw_prompt: client_message.raw_prompt,
        prompt_tokens: saved_db_message.prompt_tokens,
        completion_tokens: saved_db_message.completion_tokens,
        model_name: Some(saved_db_message.model_name), // Added model_name from database record
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let message_db: Message = pool
        .get()
        .await // Fetches Message struct
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select())
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message_db.session_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
        .unwrap_or_else(|| json!([{"text": decrypted_content_string}]));

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

    let response = MessageResponse {
        id: message_db.id,
        session_id: message_db.session_id,
        message_type: message_db.message_type,
        role: message_db
            .role
            .unwrap_or_else(|| message_db.message_type.to_string()),
        parts: response_parts,
        attachments: message_db.attachments.unwrap_or_else(|| json!([])),
        created_at: message_db.created_at,
        raw_prompt: decrypted_raw_prompt,
        prompt_tokens: message_db.prompt_tokens,
        completion_tokens: message_db.completion_tokens,
        model_name: Some(message_db.model_name), // Added model_name from database record
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
pub async fn vote_message_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<VoteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to find its chat ID
    let message = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select()) // Use SelectableHelper trait
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Check if user has access to the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message.session_id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden("Access denied to vote".to_string()));
    }

    let is_upvoted = payload.type_ == "up";

    // Insert or update the vote
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(crate::schema::old_votes::table) // Use old_votes
                .values((
                    crate::schema::old_votes::dsl::chat_id.eq(message.session_id), // Use old_votes::dsl
                    crate::schema::old_votes::dsl::message_id.eq(id), // Use old_votes::dsl
                    crate::schema::old_votes::dsl::is_upvoted.eq(is_upvoted), // Use old_votes::dsl
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
pub async fn get_votes_by_chat_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user has access to the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden("Access denied to votes".to_string()));
    }

    // Get all votes for the chat
    let votes = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            crate::schema::old_votes::table // Use old_votes
                .filter(crate::schema::old_votes::dsl::chat_id.eq(id)) // Use old_votes::dsl
                .load::<(Uuid, Uuid, bool)>(conn)
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to find its timestamp and chat ID
    let message = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select()) // Use SelectableHelper trait
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Check if user owns the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message.session_id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to delete messages".to_string(),
        ));
    }

    // Get all messages to delete
    let chat_id = message.session_id;
    let timestamp = message.created_at;

    let message_ids = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(chat_id))
                .filter(chat_messages::created_at.ge(timestamp))
                .select(chat_messages::id)
                .load::<Uuid>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if !message_ids.is_empty() {
        // Clone message_ids for different operations
        let message_ids_clone_for_messages = message_ids.clone();
        let message_ids_clone_for_embeddings = message_ids.clone();

        // Delete associated votes first
        pool.get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                // This closure moves the original message_ids
                diesel::delete(
                    crate::schema::old_votes::table // Use old_votes
                        .filter(crate::schema::old_votes::dsl::chat_id.eq(chat_id)) // Use old_votes::dsl
                        .filter(crate::schema::old_votes::dsl::message_id.eq_any(message_ids)) // Use original message_ids here
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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

        // Now delete the messages from PostgreSQL
        pool.get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                // This closure moves the clone
                diesel::delete(
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(chat_id))
                        .filter(chat_messages::id.eq_any(message_ids_clone_for_messages)), // Use the clone here
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First get the message to verify ownership
    let message = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select())
                .first::<Message>(conn)
                .map_err(|e| match e {
                    diesel::result::Error::NotFound => AppError::NotFound("Message not found".to_string()),
                    _ => AppError::DatabaseQueryError(e.to_string()),
                })
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Check if user owns the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message.session_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    if chat.user_id != user.id {
        return Err(AppError::Forbidden(
            "Access denied to delete message".to_string(),
        ));
    }

    let message_id = message.id;
    let chat_id = message.session_id;

    // Delete associated votes first
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(
                crate::schema::old_votes::table
                    .filter(crate::schema::old_votes::dsl::chat_id.eq(chat_id))
                    .filter(crate::schema::old_votes::dsl::message_id.eq(message_id))
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Delete embeddings from Qdrant
    if let Err(e) = state
        .embedding_pipeline_service
        .delete_message_chunks(
            Arc::new(state.clone()),
            vec![message_id],
            user.id,
        )
        .await
    {
        // Log error but don't fail the whole operation
        tracing::warn!("Failed to delete message embeddings from Qdrant: {}", e);
    }

    // Delete the message from PostgreSQL
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(
                chat_messages::table
                    .filter(chat_messages::id.eq(message_id))
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateChatVisibilityRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // First check if user owns the chat
    let chat = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
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
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(id)))
                .set(chat_sessions::visibility.eq(payload.visibility))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek,      // Added SessionDek extractor
    Path(id): Path<Uuid>, // This is session_id
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
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
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek extractor
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateChatSettingsRequest>, // Use standard Json extractor
) -> Result<impl IntoResponse, AppError> {
    // Manually validate the payload
    payload.validate()?; // Ensure validator is imported and used

    let user = auth_session
        .user
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
    pub id: Uuid,
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
