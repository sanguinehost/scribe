use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json, routing::{post, get}, Router};
use axum::debug_handler;
use serde::Deserialize;
use uuid::Uuid;
use diesel::prelude::*;
use axum_login::AuthSession;
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::{
        chat::{ChatSession, NewChatSession, ChatMessage},
        users::User,
    },
    schema,
    state::AppState,
};

// Request body for creating a new chat session
#[derive(Deserialize)]
pub struct CreateChatRequest {
    character_id: Uuid,
    // Add other fields if needed, e.g., initial title
}

/// Creates a new chat session associated with a character for the authenticated user.
#[debug_handler]
pub async fn create_chat_session(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user: User = auth_session
        .user
        .ok_or(AppError::Unauthorized)?;
    
    let character_id = payload.character_id;
    let user_id = user.id;

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
                        .map_err(AppError::DatabaseError)
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
    let user: User = auth_session
        .user
        .ok_or(AppError::Unauthorized)?;
    
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
                .map_err(AppError::DatabaseError)
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
    let user: User = auth_session
        .user
        .ok_or(AppError::Unauthorized)?;
    
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
                            .map_err(AppError::DatabaseError)
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

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}/messages", get(get_chat_messages))
}

// --- TODO: Add helper function for character validation --- 