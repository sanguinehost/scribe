use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json, routing::{post, get}, Router};
use axum::debug_handler;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use diesel::prelude::*;
use axum_login::AuthSession;
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::{
        chats::{ChatSession, NewChatSession, ChatMessage, MessageRole, NewChatMessage, NewChatMessageRequest},
        characters::CharacterMetadata,
    },
    prompt_builder,
    schema::{self, chat_messages, chat_sessions, characters},
    state::AppState,
    llm::gemini_client,
};
use tracing::{error, info, instrument};

// Request body for creating a new chat session
#[derive(Deserialize)]
pub struct CreateChatRequest {
    character_id: Uuid,
    // Add other fields if needed, e.g., initial title
}

// Request body for generating a response
#[derive(Deserialize)]
pub struct GenerateRequest {
    // Removed unused field: content: String,
}

// Response body for generating a response
#[derive(Serialize)]
pub struct GenerateResponse {
    ai_message: ChatMessage, // Return the full AI message object
}

/// Creates a new chat session associated with a character for the authenticated user.
#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)), err)]
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
                    };

                    diesel::insert_into(schema::chat_sessions::table)
                        .values(&new_session)
                        .returning(ChatSession::as_returning())
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
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)), err)]
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
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
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

// Updated internal save function - simplified, removes user_id check
#[instrument(skip(conn), err)]
fn save_chat_message_internal(
    conn: &mut PgConnection,
    session_id: Uuid,
    role: MessageRole,
    content: String,
) -> Result<ChatMessage, AppError> {
    let new_message = NewChatMessage {
        session_id,
        message_type: role,
        content,
    };

    diesel::insert_into(chat_messages::table)
        .values(&new_message)
        .returning(ChatMessage::as_returning())
        .get_result::<ChatMessage>(conn)
        .map_err(|e| {
            error!(%session_id, ?role, error=?e, "DB Insert Error in save_chat_message_internal");
            AppError::DatabaseQueryError(e)
        })
}

/// Generates a response from the AI for the given chat session.
/// Saves the user's message and the AI's response.
#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<NewChatMessageRequest>, // Use model struct directly
) -> Result<impl IntoResponse, AppError> {
    info!("Generating chat response");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for generate_chat_response");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;

    // Basic input validation
    if payload.content.trim().is_empty() {
        error!("Attempted to send empty message");
        return Err(AppError::BadRequest("Message content cannot be empty".into()));
    }

    let user_message_content = payload.content.clone();
    let pool = state.pool.clone(); // Clone pool for the first interact
    let ai_client = state.ai_client.clone(); // Clone AI client

    // --- First Interact: Validate, Fetch data, Save user message, Build prompt ---    
    info!("Starting first DB interaction (fetch data, save user msg)");
    let prompt = pool
        .get()
        .await?
        .interact(move |conn| {
            conn.transaction(|transaction_conn| {
                // 1. Retrieve session & character, ensuring ownership
                info!("Fetching session and character");
                // --- Query 1: Fetch Chat Session ---
                info!("Fetching chat session by ID and user ID");
                let chat_session = chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .filter(chat_sessions::user_id.eq(user_id)) // Ensure ownership
                    .select(ChatSession::as_select())
                    .first::<ChatSession>(transaction_conn)
                    .map_err(|e| {
                        error!(?e, "Failed to fetch chat session or permission denied");
                        match e {
                            diesel::result::Error::NotFound => AppError::NotFound("Chat session not found or permission denied".into()),
                            _ => AppError::DatabaseQueryError(e),
                        }
                    })?;
                info!(session_id=%chat_session.id, character_id=%chat_session.character_id, "Chat session fetched successfully");

                // --- Query 2: Fetch Character ---
                let character_id_for_query = chat_session.character_id; // Use ID from fetched session
                info!(%character_id_for_query, "Fetching character by ID");
                let character = characters::table
                    .filter(characters::id.eq(character_id_for_query))
                    // Optional: Add user_id check here too for extra safety, though session check should cover it
                    // .filter(characters::user_id.eq(user_id))
                    .select(CharacterMetadata::as_select())
                    .first::<CharacterMetadata>(transaction_conn)
                    .map_err(|e| {
                        error!(?e, character_id = %character_id_for_query, "Failed to fetch character associated with session");
                        match e {
                            diesel::result::Error::NotFound => AppError::NotFound("Character associated with the session not found".into()),
                            _ => AppError::DatabaseQueryError(e),
                        }
                    })?;
                info!(character_id=%character.id, character_name=%character.name, "Character fetched successfully");
                // info!(character_id=%chat_session.character_id, "Session and character fetched successfully"); // Original combined log

                // 2. Fetch recent messages
                info!("Fetching recent messages");
                let recent_messages = chat_messages::table
                    .filter(chat_messages::session_id.eq(session_id))
                    .order(chat_messages::created_at.desc()) // Fetch in reverse chronological
                    .limit(20) // TODO: Make limit configurable
                    .select(ChatMessage::as_select())
                    .load::<ChatMessage>(transaction_conn)?
                    .into_iter()
                    .rev() // Reverse to get chronological order for prompt building
                    .collect::<Vec<_>>();
                info!(count=recent_messages.len(), "Recent messages fetched");

                // 3. Save User's message (Insert directly)
                info!("Saving user message");
                let new_user_message = NewChatMessage {
                    session_id,
                    message_type: MessageRole::User,
                    content: user_message_content, // Use the cloned content
                };
                let user_message = diesel::insert_into(chat_messages::table)
                    .values(&new_user_message)
                    .returning(ChatMessage::as_returning())
                    .get_result::<ChatMessage>(transaction_conn)
                    .map_err(|e| {
                        error!(?e, "Failed to insert user message");
                        AppError::DatabaseQueryError(e)
                    })?;
                info!(message_id=%user_message.id, "User message saved");

                // Combine newly saved message with previously fetched messages for the prompt
                let messages_for_prompt = recent_messages.into_iter().chain(std::iter::once(user_message)).collect::<Vec<_>>();

                // 4. Build the prompt string
                info!("Building prompt");
                let prompt = prompt_builder::build_prompt(Some(&character), &messages_for_prompt)?;
                info!(prompt_length=prompt.len(), "Prompt built");
                Ok::<_, AppError>(prompt)
            }) // End transaction
        }) // End interact
        .await // await the result of interact
        .map_err(|interact_err| {
             error!(error=?interact_err, "InteractError during prompt build phase");
             AppError::InternalServerError(anyhow::anyhow!("DB interact error (prompt build): {}", interact_err))
        })??; // Handle interact error then inner DB error
    info!("First DB interaction complete");

    // --- AI Call (outside interact) ---
    info!("Calling AI service");
    let ai_content = gemini_client::generate_simple_response(&ai_client, prompt)
        .await
        .map_err(|e| {
            error!(error=?e, "AI generation failed");
            AppError::GenerationError(e.to_string())
        })?;
    info!(response_length=ai_content.len(), "AI response received");

    // --- Second Interact: Save AI message ---    
    info!("Starting second DB interaction (save AI msg)");
    let pool2 = state.pool.clone(); // Clone pool again for the second interact
    let ai_response_message = pool2
        .get()
        .await?
        .interact(move |conn| {
            // Call simplified internal function (no user_id needed)
            save_chat_message_internal(
                conn,
                session_id,
                MessageRole::Assistant,
                ai_content, // Use the content received from AI
            )
        }) // End interact (no transaction needed for single insert, but keep for consistency maybe? Let's remove it for now)
        .await // await the result of interact
         .map_err(|interact_err| {
             error!(error=?interact_err, "InteractError during AI message save");
             AppError::InternalServerError(anyhow::anyhow!("DB interact error (save AI msg): {}", interact_err))
        })??; // Handle interact error then DB error
    info!(message_id=%ai_response_message.id, "AI message saved. Interaction complete.");

    Ok((StatusCode::OK, Json(GenerateResponse { ai_message: ai_response_message })))
}

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}/messages", get(get_chat_messages))
        .route("/{session_id}/generate", post(generate_chat_response))
}

// --- TODO: Add helper function for character validation --- 