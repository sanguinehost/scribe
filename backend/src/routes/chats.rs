use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::auth::user_store::Backend as AuthBackend;
use crate::crypto; // Added crypto for encryption/decryption
use crate::errors::AppError;
use crate::models::users::User; // Added User import
use crate::PgPool; // Added PgPool import
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
use crate::schema::{chat_messages, chat_sessions};
use axum::{
    Router,
    extract::{Path, State},
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
use serde::Serialize;
use uuid::Uuid;
use validator::Validate; // Remove unused Deserialize

// Shorthand for auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn chat_routes() -> Router<crate::state::AppState> {
    tracing::debug!("chat_routes: entering chat_routes function");
    Router::new()
        .route("/", get(get_chats_handler)) // Keep GET / for listing
        .route("/create_session", post(create_chat_handler)) // More distinct path for POST
        .route("/fetch/:id", get(get_chat_by_id_handler))
        .route("/remove/:id", delete(delete_chat_handler))
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
        .route("/messages/:id", get(get_message_by_id_handler))
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
        payload.character_id,
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
        character_id = %chat.character_id,
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
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Return the full Chat struct directly
    Ok(Json(chat))
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
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Delete the chat (votes and messages will cascade due to foreign key constraints)
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

    Ok(StatusCode::NO_CONTENT)
}

// Get messages for a chat
/// Retrieves all messages for a specific chat session.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Authentication fails
/// - Chat not found or access denied
/// - Database operation fails
/// - Decryption fails
///
/// Helper function to validate and parse the chat ID
///
/// # Errors
///
/// Returns `AppError::BadRequest` if the provided string is not a valid UUID format
fn parse_chat_id(id: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(id)
        .map_err(|_| AppError::BadRequest("Invalid UUID format in path".to_string()))
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
    pool.get().await
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
        .map_err(|e| if e == diesel::result::Error::NotFound {
            tracing::warn!("Chat with id {} not found", chat_id);
            AppError::NotFound(format!("Chat session with id {chat_id} not found"))
        } else {
            tracing::error!("Database error fetching chat: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?;

    // Verify ownership
    if chat.user_id != user_id {
        tracing::warn!("User {} attempted to access chat {} owned by {}", user_id, chat_id, chat.user_id);
        return Err(AppError::Forbidden);
    }

    tracing::debug!("Successfully verified chat ownership for user {}", user_id);
    Ok(chat)
}

/// Helper function to fetch messages for a chat session
async fn fetch_chat_messages(pool: PgPool, chat_id: Uuid) -> Result<Vec<Message>, AppError> {
    pool.get().await
        .map_err(|e| {
            tracing::error!("Failed to get connection from pool for messages query: {}", e);
            AppError::DbPoolError(e.to_string())
        })?
        .interact(move |conn| {
            tracing::debug!("Fetching messages for session_id = {}", chat_id);
            let result = chat_messages::table
                .filter(chat_messages::session_id.eq(chat_id))
                .order_by(chat_messages::created_at.asc())
                .select(Message::as_select())
                .load::<Message>(conn);
            
            match &result {
                Ok(messages) => tracing::debug!("Found {} messages for chat {}", messages.len(), chat_id),
                Err(e) => tracing::error!("Error fetching messages: {}", e),
            }
            
            result.map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| {
            tracing::error!("Join error in messages query: {}", e);
            AppError::InternalServerErrorGeneric(e.to_string())
        })?
}

/// Helper function to decrypt and transform messages for client response
fn process_messages_for_response(
    messages_db: Vec<Message>,
    dek: &crate::auth::session_dek::SessionDek,
) -> Result<Vec<MessageResponse>, AppError> {
    let mut responses = Vec::new();
    
    for msg_db in messages_db {
        let decrypted_client_message = msg_db.clone().into_decrypted_for_client(Some(&dek.0))?;
        
        // Construct response parts and attachments from original msg_db
        let response_parts = msg_db
            .parts
            .unwrap_or_else(|| json!([{"text": decrypted_client_message.content}]));
        let response_attachments = msg_db.attachments.unwrap_or_else(|| json!([]));

        let response_role = msg_db
            .role
            .unwrap_or_else(|| decrypted_client_message.message_type.to_string());

        responses.push(MessageResponse {
            id: decrypted_client_message.id,
            session_id: decrypted_client_message.session_id,
            message_type: decrypted_client_message.message_type,
            role: response_role,
            parts: response_parts,
            attachments: response_attachments,
            created_at: decrypted_client_message.created_at,
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
pub async fn get_messages_by_chat_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // ADDED SessionDek extractor
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("get_messages_by_chat_id_handler: id (as String) = {}", id);
    
    // Parse and validate input
    let chat_id = parse_chat_id(&id)?;
    let user = get_authenticated_user(auth_session)?;
    
    tracing::debug!("Parsed chat_id = {}, user_id = {}", chat_id, user.id);

    // Fetch chat session and verify ownership
    let _chat = fetch_and_verify_chat_ownership(state.pool.clone(), chat_id, user.id).await?;

    // Fetch messages for the chat
    let messages_db = fetch_chat_messages(state.pool.clone(), chat_id).await?;
    
    // Decrypt and transform messages for response
    let responses = process_messages_for_response(messages_db, &dek)?;

    Ok(Json(responses))
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
        return Err(AppError::Forbidden);
    }

    let message_role_enum = if payload.role.to_lowercase() == "user" {
        MessageRole::User
    } else {
        MessageRole::Assistant
    };

    // Save the message
    let saved_db_message = chat::message_handling::save_message(
        chat::message_handling::SaveMessageParams {
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
        }
    )
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
        return Err(AppError::Forbidden);
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
        return Err(AppError::Forbidden); // Changed to unit variant
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
        return Err(AppError::Forbidden); // Changed to unit variant
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
        return Err(AppError::Forbidden); // Changed to unit variant
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
        // Clone message_ids *before* the first closure moves the original
        let message_ids_clone_for_messages = message_ids.clone();

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

        // Now delete the messages
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
        return Err(AppError::Forbidden); // Changed to unit variant
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
