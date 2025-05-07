use crate::errors::AppError;
use crate::models::chats::{
    Chat, CreateChatRequest, CreateMessageRequest, Message, MessageResponse, NewChat,
    NewMessage, UpdateChatVisibilityRequest, Vote, VoteRequest, MessageRole,
    ChatSettingsResponse, UpdateChatSettingsRequest, // <-- Add UpdateChatSettingsRequest
};
use crate::schema::{chat_messages, chat_sessions}; // Removed unused old_votes
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Router,
};
use axum_login::AuthSession; // <-- Removed unused UserId import
use crate::auth::user_store::Backend as AuthBackend;
// Removed incorrect ValidatedJson import
use validator::Validate;
use chrono::Utc;
use diesel::{QueryDsl, ExpressionMethods, RunQueryDsl, SelectableHelper}; // Removed BelongingToDsl
use serde_json::json;
use uuid::Uuid;
use crate::state::AppState;
use crate::models::characters::Character; // Added Character model
use crate::schema::characters; // Added characters schema
use tracing::{debug, error, info, instrument, trace}; // Ensure tracing is properly imported
use std::sync::Arc;
use crate::services::chat_service;

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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
    
    // First, verify the character exists and belongs to the user
    tracing::info!(%user.id, character_id=%payload.character_id, "Creating chat session");
    
    // Use the service function that properly handles system_prompt and first_mes
    let app_state = Arc::new(state.clone()); // Clone the state before moving it
    let chat = chat_service::create_session_and_maybe_first_message(
        app_state, 
        user.id, 
        payload.character_id
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
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
            ?;
    }
    
    // Add detailed logging for debugging the chat session after creation
    tracing::info!(
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
    let pool = state.pool.clone();
    
    // First check if user can access the chat
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    // Get all messages for the chat
    let messages = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(id))
                .order_by(chat_messages::created_at.asc())
                .select(Message::as_select()) // Use SelectableHelper trait
                .load::<Message>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    let responses: Vec<MessageResponse> = messages.into_iter().map(|msg| MessageResponse {
        id: msg.id,
        session_id: msg.session_id, // Renamed from chat_id
        message_type: msg.message_type, // Map the message_type field
        role: msg.role.unwrap_or_else(|| "user".to_string()), // Keep role for now, might be used elsewhere
        parts: msg.parts.unwrap_or_else(|| json!([{"text": msg.content}])),
        attachments: msg.attachments.unwrap_or_else(|| json!([])),
        created_at: msg.created_at,
    }).collect();

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
    let pool = state.pool.clone();
    
    // First check if user owns the chat
    let chat = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(chat_id))
                .select(Chat::as_select()) // Use SelectableHelper trait
                .first::<Chat>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    if chat.user_id != user.id {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    let now = Utc::now();
    // Parse role string into MessageRole enum
    let message_role = match payload.role.to_lowercase().as_str() {
        "user" => MessageRole::User,
        "assistant" => MessageRole::Assistant,
        "system" => MessageRole::System, // Allow system role? Maybe restrict later.
        _ => return Err(AppError::BadRequest(format!("Invalid role: {}", payload.role))),
    };

    let new_message = NewMessage {
        id: Uuid::new_v4(),
        session_id: chat_id,
        message_type: message_role, // Use the parsed enum
        content: payload.content.clone(),
        user_id: user.id,
        created_at: now,
        updated_at: now,
        role: Some(payload.role),
        parts: payload.parts,
        attachments: payload.attachments.or(Some(json!([]))),
    };
    
    let message = pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(new_message)
                .returning(Message::as_select()) // Use SelectableHelper trait
                .get_result::<Message>(conn) // Specify return type
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    let response = MessageResponse {
        id: message.id,
        session_id: message.session_id,
        message_type: message.message_type,
        role: message.role.unwrap_or_else(|| "user".to_string()),
        parts: message.parts.unwrap_or_else(|| json!([{"text": message.content}])),
        attachments: message.attachments.unwrap_or_else(|| json!([])),
        created_at: message.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

// Get a message by ID
pub async fn get_message_by_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();
    
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    // Check if user has access to the chat this message belongs to
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;
    
    if chat.user_id != user.id && chat.visibility != Some("public".to_string()) {
        return Err(AppError::Forbidden); // Changed to unit variant
    }

    let response = MessageResponse {
        id: message.id,
        session_id: message.session_id,
        message_type: message.message_type,
        role: message.role.unwrap_or_else(|| "user".to_string()),
        parts: message.parts.unwrap_or_else(|| json!([{"text": message.content}])),
        attachments: message.attachments.unwrap_or_else(|| json!([])),
        created_at: message.created_at,
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))?
        ?;

    Ok(StatusCode::OK)
}

// Get chat settings by ID
pub async fn get_chat_settings_handler(
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
                .select(Chat::as_select()) // Select the whole Chat struct
                .first::<Chat>(conn)
                .map_err(AppError::from) // Handles NotFound -> AppError::NotFound
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))? // Handle interact error
        ?; // Propagate NotFound error

    // Ensure the user owns this chat
    // Test `test_get_chat_settings_forbidden` expects NotFound if user doesn't own it.
    if chat.user_id != user.id {
        return Err(AppError::NotFound(format!("Chat session {} not found for user {}", id, user.id)));
    }

    // Construct the response from the Chat struct using From trait
    let response = ChatSettingsResponse::from(chat);

    Ok(Json(response))
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))? // Handle interact error
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
        .map_err(|e| AppError::InternalServerError(e.to_string()))? // Handle interact error
        ?; // Propagate DB error

    // Construct the response from the updated Chat struct
    let response = ChatSettingsResponse::from(updated_chat);

    Ok((StatusCode::OK, Json(response)))
}