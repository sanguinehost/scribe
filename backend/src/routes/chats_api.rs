use crate::errors::AppError;
use crate::models::chats::{
    Chat, CreateChatRequest, CreateMessageRequest, Message, MessageResponse,
    ChatSettingsResponse, UpdateChatSettingsRequest, UpdateChatVisibilityRequest, Vote, VoteRequest, MessageRole, // Added ChatMessage and ChatMessageForClient
};
use crate::schema::{chat_messages, chat_sessions};
use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::crypto; // Added crypto for encryption/decryption
use secrecy::ExposeSecret; // Added for expose_secret method
use secrecy::SecretBox; // Ensure SecretBox is imported
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Router,
};
use axum_login::AuthSession;
use crate::auth::user_store::Backend as AuthBackend;
// Removed incorrect ValidatedJson import
use validator::Validate;
use diesel::{QueryDsl, ExpressionMethods, RunQueryDsl, SelectableHelper};
use serde_json::json;
use uuid::Uuid;
use crate::state::AppState;
use tracing::info;
use std::sync::Arc;
use crate::services::chat_service;
use crate::models::users::User; // Ensure User is imported

// Shorthand for auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn chat_routes() -> Router<crate::state::AppState> {
    Router::new()
        .route("/chats", get(get_chats_handler).post(create_chat_handler))
        .route("/chats/{id}", get(get_chat_by_id_handler).delete(delete_chat_handler))
        .route("/chats/{id}/messages", get(get_messages_by_chat_id_handler).post(create_message_handler))
        .route("/chats/{id}/visibility", put(update_chat_visibility_handler))
        .route("/chats/{id}/settings", get(get_chat_settings_handler).put(update_chat_settings_handler)) // <-- Add PUT handler
        .route("/messages/{id}", get(get_message_by_id_handler))
        .route("/messages/{id}/vote", post(vote_message_handler))
        .route("/messages/{id}/trailing", delete(delete_trailing_messages_handler))
        .route("/chats/{id}/votes", get(get_votes_by_chat_id_handler))
}

// Get all chats for current user
pub async fn get_chats_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    let chats = pool.get().await
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    // Return the full Chat structs directly
    Ok(Json(chats))
}

// Create a new chat
pub async fn create_chat_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let user_dek_ref: Option<&SecretBox<Vec<u8>>> = user.dek.as_ref().map(|wrapped_dek| &wrapped_dek.0);
    
    info!(%user.id, character_id=%payload.character_id, "Creating chat session");
    
    let app_state = Arc::new(state.clone());
    let chat = chat_service::create_session_and_maybe_first_message(
        app_state, 
        user.id, 
        payload.character_id,
        user_dek_ref, // Pass the reference to the inner SecretBox
    ).await?;
    
    // Generate a custom title if provided (default title is set by the service)
    if !payload.title.trim().is_empty() {
        let pool = state.pool.clone();
        let session_id = chat.id;
        let custom_title = payload.title.clone();
        
        // Update just the title field
        pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                diesel::update(chat_sessions::table.find(session_id))
                    .set(chat_sessions::title.eq(Some(custom_title)))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
            ?;
    }
    
    // Add detailed logging for debugging the chat session after creation
    info!(
        message = "Chat session created in handler",
        chat_id = %chat.id,
        character_id = %chat.character_id,
        user_id = %chat.user_id,
        system_prompt = ?chat.system_prompt,
        chat = ?chat
    );

    // Return the fully configured Chat struct
    Ok((StatusCode::CREATED, Json(chat)))
}

// Get a chat by ID
pub async fn get_chat_by_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(AppError::from) // Use From trait to handle NotFound correctly
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    // Ensure the user owns this chat or it's public
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Return the full Chat struct directly
    Ok(Json(chat))
}

// Delete a chat
pub async fn delete_chat_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    // First check if user owns the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    if chat.user_id != user.id {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Delete the chat (votes and messages will cascade due to foreign key constraints)
    pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::delete(chat_sessions::table.filter(chat_sessions::id.eq(id)))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    Ok(StatusCode::NO_CONTENT)
}

// Get messages for a chat
pub async fn get_messages_by_chat_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let user_dek_ref: Option<&SecretBox<Vec<u8>>> = user.dek.as_ref().map(|wrapped_dek| &wrapped_dek.0);
    let pool = state.pool.clone();
    
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
    
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden);
    }

    let messages_db: Vec<Message> = pool.get().await // Fetching Vec<Message> which includes 'parts'
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(id))
                .order_by(chat_messages::created_at.asc())
                .select(Message::as_select())
                .load::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
    
    let mut responses = Vec::new();
    for msg_db in messages_db {
        let decrypted_client_message = msg_db.clone().into_decrypted_for_client(user_dek_ref)?;

        // Now construct MessageResponse using fields from original msg_db and decrypted_client_message
        let response_parts = msg_db.parts.unwrap_or_else(|| json!([{"text": decrypted_client_message.content}]));
        let response_attachments = msg_db.attachments.unwrap_or_else(|| json!([]));
        let response_role = msg_db.role.unwrap_or_else(|| decrypted_client_message.message_type.to_string());

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

    Ok(Json(responses))
}

// Create a message
pub async fn create_message_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    Json(payload): Json<CreateMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let user_dek_ref: Option<&SecretBox<Vec<u8>>> = user.dek.as_ref().map(|wrapped_dek| &wrapped_dek.0);
    let _pool = state.pool.clone(); // Not strictly needed here if save_message handles its own pool access
    
    // Verify chat session ownership (existing logic is fine)
    let chat = state.pool.get().await // Keep this verification block
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

    let message_role = match payload.role.to_lowercase().as_str() {
        "user" => MessageRole::User,
        "assistant" => MessageRole::Assistant,
        "system" => MessageRole::System,
        _ => return Err(AppError::BadRequest(format!("Invalid role: {}", payload.role))),
    };

    // Call chat_service::save_message
    let saved_db_message = chat_service::save_message(
        Arc::new(state), // Pass Arc<AppState>
        chat_id,
        user.id,
        message_role,
        &payload.content, // Pass content as &str
        user_dek_ref,       // Pass Option<&SecretBox<Vec<u8>>>
    ).await?;

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
        role: Some(payload.role.clone()),      // From the request payload
        parts: payload.parts.clone(),          // From the request payload
        attachments: payload.attachments.clone(), // From the request payload
    };
    let client_message = message_for_decryption.into_decrypted_for_client(user_dek_ref)?;
    
    // Use client_message.content (String) for parts if payload.parts is None
    let response_parts = payload.parts.unwrap_or_else(|| json!([{"text": client_message.content.clone()}]));
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
pub async fn get_message_by_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    dek: SessionDek, // Added SessionDek
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    let message_db: Message = pool.get().await // Fetches Message struct
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
    
    let chat = pool.get().await
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

    let decrypted_content_string = if !message_db.content.is_empty() {
        let nonce_bytes_ref = message_db.content_nonce.as_deref()
            .ok_or_else(|| {
                tracing::error!("Message ID {} content nonce is missing. Cannot decrypt.", message_db.id);
                AppError::DecryptionError("Nonce missing for content decryption".to_string())
            })?;

        if nonce_bytes_ref.is_empty() {
            tracing::error!("Message ID {} content nonce is present but empty. Cannot decrypt.", message_db.id);
            return Err(AppError::DecryptionError("Nonce is empty for content decryption".to_string()));
        }

        crypto::decrypt_gcm(&message_db.content, nonce_bytes_ref, &dek.0)
            .map_err(|e| {
                tracing::error!("Failed to decrypt message content for get_message_by_id {}: {}", message_db.id, e);
                AppError::DecryptionError(format!("Failed to decrypt content for message {}: {}", message_db.id, e))
            })
            .and_then(|secret_bytes| {
                String::from_utf8(secret_bytes.expose_secret().to_vec()).map_err(|e| {
                    tracing::error!("UTF-8 conversion error for decrypted message {}: {}", message_db.id, e);
                    AppError::DecryptionError(format!("UTF-8 conversion error for message {}: {}", message_db.id, e))
                })
            })?
    } else {
        String::new()
    };

    let response_parts = message_db.parts.unwrap_or_else(|| json!([{"text": decrypted_content_string}]));

    let response = MessageResponse {
        id: message_db.id,
        session_id: message_db.session_id,
        message_type: message_db.message_type,
        role: message_db.role.unwrap_or_else(|| message_db.message_type.to_string()),
        parts: response_parts,
        attachments: message_db.attachments.unwrap_or_else(|| json!([])),
        created_at: message_db.created_at,
    };

    Ok(Json(response))
}

// Vote on a message
pub async fn vote_message_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<VoteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    // First get the message to find its chat ID
    let message = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select()) // Use SelectableHelper trait
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    // Check if user has access to the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message.session_id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    if chat.user_id != user.id {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    let is_upvoted = payload.type_ == "up";
    
    // Insert or update the vote
    pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(crate::schema::old_votes::table) // Use old_votes
                .values((
                    crate::schema::old_votes::dsl::chat_id.eq(message.session_id), // Use old_votes::dsl
                    crate::schema::old_votes::dsl::message_id.eq(id), // Use old_votes::dsl
                    crate::schema::old_votes::dsl::is_upvoted.eq(is_upvoted), // Use old_votes::dsl
                ))
                .on_conflict((crate::schema::old_votes::dsl::chat_id, crate::schema::old_votes::dsl::message_id)) // Use old_votes::dsl
                .do_update()
                .set(crate::schema::old_votes::dsl::is_upvoted.eq(is_upvoted)) // Use old_votes::dsl
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    Ok(StatusCode::OK)
}

// Get votes for a chat
pub async fn get_votes_by_chat_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    // First check if user has access to the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Get all votes for the chat
    let votes = pool.get().await
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    Ok(Json(votes))
}

// Delete messages after a certain point in a chat
pub async fn delete_trailing_messages_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    // First get the message to find its timestamp and chat ID
    let message = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(id))
                .select(Message::as_select()) // Use SelectableHelper trait
                .first::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    // Check if user owns the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(message.session_id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    if chat.user_id != user.id {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Get all messages to delete
    let chat_id = message.session_id;
    let timestamp = message.created_at;
    
    let message_ids = pool.get().await
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
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    
    if !message_ids.is_empty() {
        // Clone message_ids *before* the first closure moves the original
        let message_ids_clone_for_messages = message_ids.clone();

        // Delete associated votes first
        pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| { // This closure moves the original message_ids
                diesel::delete(
                    crate::schema::old_votes::table // Use old_votes
                        .filter(crate::schema::old_votes::dsl::chat_id.eq(chat_id)) // Use old_votes::dsl
                        .filter(crate::schema::old_votes::dsl::message_id.eq_any(message_ids)) // Use original message_ids here
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
            ?;
        
        // Now delete the messages
        pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| { // This closure moves the clone
                diesel::delete(
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(chat_id))
                        .filter(chat_messages::id.eq_any(message_ids_clone_for_messages)) // Use the clone here
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
            ?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// Update chat visibility
pub async fn update_chat_visibility_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateChatVisibilityRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
    // First check if user owns the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;
    if chat.user_id != user.id {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    
    // Ensure visibility is one of the allowed values
    if payload.visibility != "public" && payload.visibility != "private" {
        return Err(AppError::BadRequest("Visibility must be 'public' or 'private'".to_string()));
    }
    
    // Update the chat visibility
    pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(id)))
                .set(chat_sessions::visibility.eq(payload.visibility))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
        ?;

    Ok(StatusCode::OK)
}

// Get chat settings by ID
pub async fn get_chat_settings_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>, // This is session_id
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    
    // Call the service function to get chat settings
    // The service function handles ownership check and constructing the response
    let chat_settings_response = chat_service::get_session_settings(
        &state.pool,
        user.id,
        id, // session_id
    )
    .await?;

    Ok(Json(chat_settings_response))
}

// Update chat settings by ID
pub async fn update_chat_settings_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateChatSettingsRequest>, // Use standard Json extractor
) -> Result<impl IntoResponse, AppError> {
    // Manually validate the payload
    payload.validate()?; // Ensure validator is imported and used

    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    let user_id = user.id; // Clone user_id for use in interact closure

    // Fetch the chat session first to check ownership
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from) // Handles NotFound -> AppError::NotFound
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))? // Handle interact error
        ?; // Propagate NotFound error

    // Ensure the user owns this chat
    if chat.user_id != user_id {
        // Test `update_chat_settings_forbidden` expects Forbidden
        return Err(AppError::Forbidden);
    }

    // Perform the update
    let updated_chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::update(chat_sessions::table.find(id))
                .set(payload) // Use the AsChangeset payload directly
                .returning(Chat::as_select()) // Return the updated chat
                .get_result::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))? // Handle interact error
        ?; // Propagate DB error

    // Construct the response from the updated Chat struct
    let response = ChatSettingsResponse::from(updated_chat);

    Ok((StatusCode::OK, Json(response)))
}