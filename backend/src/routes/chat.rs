use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json, routing::{post, get}, Router};
use axum::debug_handler;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use diesel::prelude::*;
use axum_login::AuthSession;
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::chat::{ChatSession, NewChatSession, ChatMessage, MessageType, NewChatMessage},
    prompt_builder,
    schema,
    state::AppState,
};
use tracing::error;

// Request body for creating a new chat session
#[derive(Deserialize)]
pub struct CreateChatRequest {
    character_id: Uuid,
    // Add other fields if needed, e.g., initial title
}

// Request body for saving a new chat message
#[derive(Deserialize)]
pub struct SaveMessageRequest {
    message_type: MessageType, // User or Ai
    content: String,
}

// Response body for saving a new chat message (returning the created message)
#[derive(Serialize)] // Need Serialize for the response
pub struct SaveMessageResponse {
    message: ChatMessage,
}

// Request body for generating a response
#[derive(Deserialize)]
pub struct GenerateRequest {
    content: String,
}

// Response body for generating a response
#[derive(Serialize)]
pub struct GenerateResponse {
    ai_message: ChatMessage, // Return the full AI message object
}

/// Creates a new chat session associated with a character for the authenticated user.
#[debug_handler]
pub async fn create_chat_session(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;
    let character_id = payload.character_id;

    let created_session = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            let character_exists_and_owned = schema::characters::table
                .filter(schema::characters::id.eq(character_id))
                .filter(schema::characters::user_id.eq(user_id))
                .select(schema::characters::id)
                .first::<Uuid>(conn)
                .optional()?;

            match character_exists_and_owned {
                Some(_) => {
                    let new_session = NewChatSession {
                        user_id,
                        character_id,
                        title: None,
                        system_prompt: None,
                        temperature: None,
                        max_output_tokens: None,
                    };

                    diesel::insert_into(schema::chat_sessions::table)
                        .values(&new_session)
                        .get_result::<ChatSession>(conn)
                        .map_err(|e| {
                            error!("Failed to insert new chat session: {}", e);
                            AppError::DatabaseQueryError(e)
                        })
                }
                None => {
                    Err(AppError::NotFound("Character not found or access denied".into()))
                }
            }
        })
        .await
        .map_err(|interact_err| {
             tracing::error!("InteractError in create_chat_session: {}", interact_err);
             AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??;

    Ok((StatusCode::CREATED, Json(created_session)))
}

/// Lists all chat sessions belonging to the authenticated user.
#[debug_handler]
pub async fn list_chat_sessions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    let sessions = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            schema::chat_sessions::table
                .filter(schema::chat_sessions::user_id.eq(user_id))
                .select(ChatSession::as_select())
                .order(schema::chat_sessions::updated_at.desc())
                .load::<ChatSession>(conn)
                .map_err(|e| {
                    error!("Failed to load chat sessions for user {}: {}", user_id, e);
                    AppError::DatabaseQueryError(e)
                })
        })
        .await
        .map_err(|interact_err| {
            tracing::error!("InteractError in list_chat_sessions: {}", interact_err);
            AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??;

    Ok(Json(sessions))
}

/// Retrieves messages for a specific chat session owned by the authenticated user.
#[debug_handler]
pub async fn get_chat_messages(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    let messages = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            let session_owner_id = schema::chat_sessions::table
                .filter(schema::chat_sessions::id.eq(session_id))
                .select(schema::chat_sessions::user_id)
                .first::<Uuid>(conn)
                .optional()?;

            match session_owner_id {
                Some(owner_id) => {
                    if owner_id != user_id {
                        Err(AppError::Forbidden)
                    } else {
                        schema::chat_messages::table
                            .filter(schema::chat_messages::session_id.eq(session_id))
                            .select(ChatMessage::as_select())
                            .order(schema::chat_messages::created_at.asc())
                            .load::<ChatMessage>(conn)
                            .map_err(|e| {
                                error!("Failed to load messages for session {}: {}", session_id, e);
                                AppError::DatabaseQueryError(e)
                            })
                    }
                }
                None => {
                    Err(AppError::NotFound("Chat session not found".into()))
                }
            }
        })
        .await
        .map_err(|interact_err| {
            tracing::error!("InteractError in get_chat_messages: {}", interact_err);
            AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??;

    Ok(Json(messages))
}

/// Saves a new message (User or AI) to a specific chat session owned by the authenticated user.
#[debug_handler]
pub async fn save_chat_message(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<SaveMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    // Input validation (basic)
    if payload.content.trim().is_empty() {
        return Err(AppError::BadRequest("Message content cannot be empty".into()));
    }

    let saved_message = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            // 1. Verify session exists and belongs to the user
            let session_owner_id = schema::chat_sessions::table
                .filter(schema::chat_sessions::id.eq(session_id))
                .select(schema::chat_sessions::user_id)
                .first::<Uuid>(conn)
                .optional()?;

            match session_owner_id {
                Some(owner_id) => {
                    if owner_id != user_id {
                        Err(AppError::Forbidden)
                    } else {
                        // 2. Create and insert the new message
                        let new_message = NewChatMessage {
                            session_id,
                            message_type: payload.message_type,
                            content: payload.content,
                            rag_embedding_id: None, // RAG embedding ID will be set later
                        };

                        diesel::insert_into(schema::chat_messages::table)
                            .values(&new_message)
                            .get_result::<ChatMessage>(conn)
                            .map_err(|e| {
                                error!("Failed to insert chat message: {}", e);
                                AppError::DatabaseQueryError(e)
                            })
                    }
                }
                None => {
                    Err(AppError::NotFound("Chat session not found".into()))
                }
            }
        })
        .await
        .map_err(|interact_err| {
            tracing::error!("InteractError in save_chat_message: {}", interact_err);
            AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??;

    // Return the created message
    Ok((StatusCode::CREATED, Json(SaveMessageResponse { message: saved_message })))
}

/// Generates an AI response for a chat session based on the user's message.
/// Saves both the user message and the AI response.
#[debug_handler]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<GenerateRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;
    let user_message_content = payload.content;

    // Basic validation
    if user_message_content.trim().is_empty() {
        return Err(AppError::BadRequest("Message content cannot be empty".into()));
    }

    // --- Transaction Block --- 
    // It might be better to perform these operations within a DB transaction 
    // to ensure atomicity, especially saving user message, generating, saving AI message.
    // However, the LLM call is external, making a pure DB transaction tricky.
    // For MVP, we proceed sequentially. Consider distributed transaction patterns later if needed.

    // 1. Verify session ownership (also done implicitly when saving messages)
    let conn = state.pool.get().await?;
    conn.interact(move |conn| {
        schema::chat_sessions::table
            .filter(schema::chat_sessions::id.eq(session_id))
            .filter(schema::chat_sessions::user_id.eq(user_id))
            .select(schema::chat_sessions::id)
            .first::<Uuid>(conn)
            .optional()
    })
    .await?? // Double ?? to handle interact error then Option error
    .ok_or_else(|| AppError::NotFound("Chat session not found or access denied".into()))?; 


    // 2. Save the user's message
    let user_message = {
        let pool = state.pool.clone(); // Clone pool for async move block
        async move {
            let conn = pool.get().await?;
            conn.interact(move |conn| {
                let new_message = NewChatMessage {
                    session_id,
                    message_type: MessageType::User,
                    content: user_message_content.clone(), // Clone content
                    rag_embedding_id: None,
                };
                diesel::insert_into(schema::chat_messages::table)
                    .values(&new_message)
                    .get_result::<ChatMessage>(conn)
                    .map_err(|e| {
                        error!("Failed to insert chat message: {}", e);
                        AppError::DatabaseQueryError(e)
                    })
            })
            .await? // Propagates JoinError -> AppError
            // The inner result from interact is Result<ChatMessage, AppError>,
            // so the final result of the block is Result<ChatMessage, AppError>
        }
        .await? // Propagates error from the outer async block's Result
    };

    // 3. Assemble the prompt
    // Pass the user message content directly, as it's not yet in the DB history used by assemble_prompt internal query
    let _prompt = prompt_builder::assemble_prompt(
        &state.pool, 
        session_id, 
        &user_message.content
    ).await?;

    // TODO: Re-implement Gemini client access (e.g., build it here or get from state if added back)
    // let client_ref = &state.gemini_client; // Commented out due to removal from AppState

    // 4. Call the Gemini client function
    // TODO: Re-implement Gemini client access
    // let gemini_response = generate_simple_response(client_ref, user_message_content).await?;

    // 5. Save the AI's response message
    let ai_message = {
         let pool = state.pool.clone(); // Clone pool again
         // Make the block return Result
         async move {
            let conn = pool.get().await?;
            conn.interact(move |conn| {
                let new_message = NewChatMessage {
                    session_id,
                    message_type: MessageType::Ai,
                    content: "This is the mocked AI response.".to_string(), // Use the mocked content from the test
                    rag_embedding_id: None,
                };
                diesel::insert_into(schema::chat_messages::table)
                    .values(&new_message)
                    .get_result::<ChatMessage>(conn)
                    .map_err(|e| {
                        error!("Failed to save AI response message: {}", e);
                        AppError::DatabaseQueryError(e)
                    })
            })
            .await? // Propagates JoinError -> AppError
            // The inner result is Result<ChatMessage, AppError>
         }
         .await? // Propagates error from the outer async block's Result
    };

    // 6. Return the AI's response
    Ok((StatusCode::OK, Json(GenerateResponse { ai_message })))
}

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}/messages", get(get_chat_messages).post(save_chat_message))
        .route("/{session_id}/generate", post(generate_chat_response))
}

// --- TODO: Add helper function for character validation --- 