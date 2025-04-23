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
        chats::{ChatSession, NewChatSession, ChatMessage as DbChatMessage, MessageRole, NewChatMessage, NewChatMessageRequest},
        characters::Character,
        // users::User, // Removed unused import
    },
    schema::{self, characters},
    state::AppState,
};
use tracing::{error, info, instrument, warn};
use genai::chat::{
    ChatRequest,
    ChatMessage,
    ContentPart,
};

// Default model to use if character doesn't specify one
const DEFAULT_MODEL_NAME: &str = "gemini-1.5-flash-latest";

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
    ai_message: DbChatMessage, // Return the full AI message object
}

/// Creates a new chat session associated with a character for the authenticated user.
#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)), err)]
pub async fn create_chat_session(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Creating new chat session");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for create_chat_session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;
    let character_id = payload.character_id; // Store for use in interact closure

    // Use interact for blocking Diesel operations
    let created_session: ChatSession = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            // Import schema modules within the closure for clarity
            use crate::schema::characters::dsl as characters_dsl;
            use crate::schema::chat_sessions::dsl as chat_sessions_dsl;
            use crate::schema::chat_messages::dsl as chat_messages_dsl;


            // Wrap operations in a transaction
            conn.transaction(|transaction_conn| {
                // 1. Verify character exists and belongs to the user
                info!(%character_id, %user_id, "Verifying character ownership");
                let character_owner_id = characters_dsl::characters
                    .filter(characters::dsl::id.eq(character_id))
                    .select(characters::dsl::user_id)
                    .first::<Uuid>(transaction_conn)
                    .optional()?; // Use optional to handle not found

                match character_owner_id {
                    Some(owner_id) => {
                        if owner_id != user_id {
                            error!(%character_id, %user_id, owner_id=%owner_id, "User does not own character");
                            return Err(AppError::Forbidden); // Character owned by someone else
                        }
                        // Character exists and is owned by the user, proceed.

                        // 2. Create the new chat session
                        info!(%character_id, %user_id, "Inserting new chat session");
                        let new_session = NewChatSession {
                            user_id,
                            character_id,
                        };
                        let created_session: ChatSession = diesel::insert_into(chat_sessions_dsl::chat_sessions)
                            .values(&new_session)
                            .returning(ChatSession::as_returning())
                            .get_result(transaction_conn)
                            .map_err(|e| {
                                error!(error = ?e, "Failed to insert new chat session");
                                AppError::DatabaseQueryError(e)
                            })?;
                         info!(session_id = %created_session.id, "Chat session created");

                        // ---- START: Add first_mes as initial AI message ----
                        info!(%character_id, session_id = %created_session.id, "Fetching character details for first_mes");
                        let character: Character = characters_dsl::characters
                            .filter(characters::dsl::id.eq(character_id))
                            .select(Character::as_select()) // Fetch the full character
                            .first::<Character>(transaction_conn)
                            .map_err(|e| {
                                error!(error = ?e, %character_id, "Failed to fetch full character details during session creation");
                                // If character was found moments ago, this should ideally not fail, but handle just in case
                                match e {
                                    diesel::result::Error::NotFound => AppError::InternalServerError(anyhow::anyhow!("Character inconsistency during session creation")),
                                    _ => AppError::DatabaseQueryError(e),
                                }
                            })?;

                        if let Some(first_message_content) = character.first_mes {
                            if !first_message_content.trim().is_empty() {
                                info!(session_id = %created_session.id, "Character has first_mes, adding as initial assistant message");
                                let first_message = NewChatMessage {
                                    session_id: created_session.id,
                                    message_type: MessageRole::Assistant, // Use Assistant role
                                    content: first_message_content,
                                    // created_at is handled by DB default or trigger
                                };
                                diesel::insert_into(chat_messages_dsl::chat_messages)
                                    .values(&first_message)
                                    .execute(transaction_conn) // We don't need the result of this insert
                                    .map_err(|e| {
                                        error!(error = ?e, session_id = %created_session.id, "Failed to insert first_mes");
                                        AppError::DatabaseQueryError(e)
                                    })?;
                                info!(session_id = %created_session.id, "Successfully inserted first_mes");
                            } else {
                                info!(session_id = %created_session.id, "Character first_mes is empty, skipping initial message.");
                            }
                        } else {
                             info!(session_id = %created_session.id, "Character first_mes is None, skipping initial message.");
                        }
                        // ---- END: Add first_mes ----

                        Ok(created_session) // Return the created session
                    }
                    None => {
                        error!(%character_id, "Character not found during session creation");
                        Err(AppError::NotFound("Character not found".into())) // Character does not exist
                    }
                }
            }) // End transaction
        })
        .await
        .map_err(|interact_err| {
             tracing::error!("InteractError in create_chat_session: {}", interact_err);
             AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??; // Double '?' handles both InteractError and the inner Result<ChatSession, AppError>

    info!(session_id = %created_session.id, "Chat session creation successful");
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
                            .select(DbChatMessage::as_select())
                            .order(schema::chat_messages::created_at.asc())
                            .load::<DbChatMessage>(conn)
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
) -> Result<DbChatMessage, AppError> {
    use crate::schema::chat_messages::dsl as chat_messages_dsl; // Add import needed after edit

    let new_message = NewChatMessage {
        session_id,
        message_type: role,
        content,
    };

    diesel::insert_into(chat_messages_dsl::chat_messages) // Use imported dsl
        .values(&new_message)
        .returning(DbChatMessage::as_returning())
        .get_result::<DbChatMessage>(conn)
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
    let (prompt_history, system_message): (Vec<(MessageRole, String)>, String) = pool
        .get()
        .await?
        .interact(move |conn| {
            // Use schema modules for clarity
            use crate::schema::characters::dsl as characters_dsl;
            use crate::schema::chat_sessions::dsl as chat_sessions_dsl;
            use crate::schema::chat_messages::dsl as chat_messages_dsl;

            conn.transaction(|transaction_conn| {
                // 1. Retrieve session & character, ensuring ownership
                info!("Fetching session and character");
                // --- Query 1: Fetch Chat Session ---
                info!("Fetching chat session by ID and user ID");
                let chat_session = chat_sessions_dsl::chat_sessions // Use imported dsl
                    .filter(chat_sessions_dsl::id.eq(session_id))
                    .filter(chat_sessions_dsl::user_id.eq(user_id)) // Ensure ownership
                    .select(ChatSession::as_select())
                    .first::<ChatSession>(transaction_conn)
                    .map_err(|e| {
                        error!(?e, "Failed to fetch chat session or permission denied");
                        match e {
                            diesel::result::Error::NotFound => AppError::NotFound("Chat session not found or permission denied".into()),
                            _ => AppError::DatabaseQueryError(e),
                        }
                    })?;

                 info!("Fetching character details");
                 // --- Query 2: Fetch Character ---
                 let character = characters_dsl::characters // Use imported dsl
                    .filter(characters_dsl::id.eq(chat_session.character_id))
                    // We already validated session ownership, indirectly validating character access
                    // If characters could be accessed by others, add user_id check here too
                    .select(Character::as_select()) // <-- Fetch the full Character struct
                    .first::<Character>(transaction_conn) // <-- To get Character
                     .map_err(|e| {
                         error!(?e, "Failed to fetch character details for session");
                         match e {
                              diesel::result::Error::NotFound => AppError::NotFound("Character associated with session not found".into()), // Should be rare if DB integrity is maintained
                              _ => AppError::DatabaseQueryError(e),
                          }
                     })?;

                 // Construct the system message here
                 let system_message = character.system_prompt.clone().unwrap_or_default(); // Get system prompt from Character

                info!("Fetching chat history");
                // --- Query 3: Fetch Chat History ---
                let history = chat_messages_dsl::chat_messages // Use imported dsl
                    .filter(chat_messages_dsl::session_id.eq(session_id))
                    .select(DbChatMessage::as_select())
                    .order(chat_messages_dsl::created_at.asc())
                    .load::<DbChatMessage>(transaction_conn)
                    .map_err(|e| {
                        error!(?e, "Failed to load chat history");
                        AppError::DatabaseQueryError(e)
                    })?;

                // --- Save User Message ---
                info!("Saving user message");
                let user_chat_message = save_chat_message_internal(
                    transaction_conn,
                    session_id,
                    MessageRole::User, // Use User role
                    user_message_content,
                )?;

                // --- Build Prompt History ---
                info!("Building prompt history");
                let mut prompt_history = history // Start with existing history
                    .into_iter()
                    .map(|msg| (msg.message_type, msg.content))
                    .collect::<Vec<(MessageRole, String)>>();

                prompt_history.push((user_chat_message.message_type, user_chat_message.content)); // Add the new user message

                 // --- Return both history and system message ---
                 Ok::<_, AppError>((prompt_history, system_message)) // Return history and system message
            }) // End transaction
        })
        .await
        .map_err(|interact_err| {
            tracing::error!("InteractError during fetch/save/build prompt: {}", interact_err);
            AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??; // Double '??' for InteractError and inner Result

    // --- Determine Model Name ---
    // Get model from request payload, fallback to default if not provided by client.
    let model_name = payload.model.unwrap_or_else(|| {
        warn!(
            session_id = %session_id,
            "Client did not specify a model, defaulting to {}",
            DEFAULT_MODEL_NAME
        );
        DEFAULT_MODEL_NAME.to_string()
    });

    // Destructure the tuple from the interact block - Now contains history and system message
    // let (prompt_history, system_message) = prompt; // This line is effectively done by the let binding above
    // Remove the FIXME/TODO comments and placeholder
    // FIXME: Refetch character or pass system_message out of interact block
    // let system_message = ""; // Placeholder - Needs fixing
    // TODO: Re-fetch character here or modify interact block to return (history, system_message)
    // For now, system prompt is lost. Need to fix this.

    info!(prompt_history_len = %prompt_history.len(), %model_name, "Data fetched for AI call");

    // --- Call AI Service ---
    info!("Calling AI service ({})", model_name);

    // Construct genai::ChatRequest messages using correct associated functions
    let messages: Vec<ChatMessage> = prompt_history.into_iter().map(|(role, content)| {
        match role {
            MessageRole::User => ChatMessage::user(content),
            MessageRole::Assistant => ChatMessage::assistant(content), // Use ::assistant
            // Assuming MessageRole::System is not expected here, or needs specific handling
            MessageRole::System => {
                // Decide how to handle system messages from DB history.
                // Option 1: Skip them (Gemini uses the 'system' field)
                 warn!(%session_id, "Skipping System role message from DB history when building genai prompt");
                 // Return Option<ChatMessage> and filter_map later, or handle differently.
                 // For now, let's create a user message as a placeholder, though skipping might be better.
                 ChatMessage::user(format!("[System Message]: {}", content)) // Or skip entirely
                // Option 2: Panic if unexpected
                // panic!("Unexpected MessageRole::System found in prompt history");
            }
        }
    }).collect();

    let chat_request = ChatRequest {
        system: if !system_message.is_empty() {
            // System field expects Option<String>, not ContentPart
            Some(system_message)
        } else {
            None
        },
        messages,
        // TODO: Add other fields like tools, safety_settings, generation_config if needed
        ..Default::default()
    };


    let ai_response_result = ai_client.exec_chat(&model_name, chat_request, None).await; // <-- New call using exec_chat

    let ai_response_content = match ai_response_result {
        Ok(response) => {
             // Extract text content robustly using match on MessageContent and then ContentPart
             response.content.as_ref()
                 .and_then(|content| {
                     match content {
                         genai::chat::MessageContent::Text(s) => Some(s.clone()),
                         genai::chat::MessageContent::Parts(parts) => {
                             // Find the first text part by matching on ContentPart
                             parts.iter().find_map(|part| match part {
                                 ContentPart::Text(s) => Some(s.clone()), // Use imported ContentPart directly
                                 _ => None, // Ignore other part types (e.g., images, function calls)
                             })
                         }
                         _ => None, // Ignore ToolCalls/ToolResponses
                     }
                 })
                .unwrap_or_else(|| {
                    error!(session_id=%session_id, model=%model_name, "LLM response content was empty, malformed, or contained no text parts");
                    "Sorry, I received an empty response.".to_string()
                })
        },
        Err(genai_err) => {
            // Convert genai::Error to AppError first
            let initial_app_error = AppError::from(genai_err);

            // Now match on the resulting AppError
            match initial_app_error {
                // Check if the error was specifically a GeminiError
                AppError::GeminiError(ref underlying_genai_error) => {
                     // Check the underlying genai::Error for the rate limit condition
                    if let genai::Error::WebModelCall { webc_error, .. } = underlying_genai_error {
                        if let genai::webc::Error::ResponseFailedStatus { status, .. } = webc_error {
                            if *status == 429 {
                                error!("Gemini API rate limit hit (429)");
                                return Err(AppError::RateLimited); // Return specific RateLimited error
                            }
                        }
                    }
                    // If not a 429 rate limit, return the original GeminiError
                    error!(error = ?underlying_genai_error, "Gemini API call failed (non-429)");
                    return Err(initial_app_error);
                }
                // Handle any other AppError variants that might have resulted from the From conversion (less likely)
                other_app_error => {
                    error!(error = ?other_app_error, "LLM call failed (converted to non-GeminiError)");
                    return Err(other_app_error);
                }
            }
        }
    };

    // --- Second Interact: Save AI message ---
    info!("Starting second DB interaction (save AI msg)");
    let pool = state.pool.clone(); // Clone pool for the second interact
    let ai_db_message = pool
        .get()
        .await?
        .interact(move |conn| {
            // No transaction needed for single insert
            save_chat_message_internal(
                conn,
                session_id,
                MessageRole::Assistant,
                ai_response_content, // Save the content received from LLM
            )
        })
        .await
         .map_err(|interact_err| {
             tracing::error!("InteractError in generate_chat_response (second block): {}", interact_err);
             AppError::InternalServerError(anyhow::anyhow!("DB interact error saving AI msg: {}", interact_err))
        })??;

    info!("Successfully generated and saved response");
    Ok((StatusCode::OK, Json(GenerateResponse { ai_message: ai_db_message })))
}

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}/messages", get(get_chat_messages))
        .route("/{session_id}/generate", post(generate_chat_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers; // Simplified import
    use crate::models::chats::{ChatSession, ChatMessage};
    // Removed unused: characters::CharacterMetadata, users::User
    // REMOVED INCORRECT IMPORT: use crate::routes::test_helpers::{create_test_state, setup_test_db};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, Method, header}; // Added Method, header
    // Removed unused: use axum_login::AuthSession;
    use serde_json::{json, Value}; // Added Value
    use tower::ServiceExt;
    use uuid::Uuid;
    use http_body_util::BodyExt; // Added for body collection

    #[tokio::test]
    async fn test_create_chat_session_success() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_user", "password").await;
        let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Test Character for Chat").await;
        let request_body = json!({ "character_id": character.id });

        let request = Request::builder()
            .method(Method::POST) // Use Method::POST
            .uri("/api/chats")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
            .header(header::COOKIE, auth_cookie) // Use header::COOKIE
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let session: ChatSession = serde_json::from_slice(&body).expect("Failed to deserialize response");
        assert_eq!(session.user_id, user.id);
        assert_eq!(session.character_id, character.id);
    }

    #[tokio::test]
    async fn test_create_chat_session_unauthorized() {
        let context = test_helpers::setup_test_app().await;
        let request_body = json!({ "character_id": Uuid::new_v4() }); // Dummy ID

        let request = Request::builder()
            .method(Method::POST) // Use Method::POST
            .uri("/api/chats")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();
        // No login simulation

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED, not redirect, for API endpoints without login
    }

    #[tokio::test]
    async fn test_create_chat_session_character_not_found() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "test_char_not_found_user", "password").await;
        let non_existent_char_id = Uuid::new_v4();

        let request_body = json!({ "character_id": non_existent_char_id });

        let request = Request::builder()
            .method(Method::POST) // Use Method::POST
            .uri("/api/chats")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
            .header(header::COOKIE, auth_cookie) // Use cookie
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Optionally check error message structure if your AppError provides it
        // let body = response.into_body().collect().await.unwrap().to_bytes();
        // let error_response: Value = serde_json::from_slice(&body).unwrap();
        // assert!(error_response["error"].as_str().unwrap().contains("Character not found"));
    }

    #[tokio::test]
    async fn test_create_chat_session_character_other_user() {
         let context = test_helpers::setup_test_app().await;
         let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "chat_user_1", "password").await;
         let character = test_helpers::create_test_character(&context.app.db_pool, user1.id, "User1 Character").await;
         let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "chat_user_2", "password").await;

         let request_body = json!({ "character_id": character.id });

         let request = Request::builder()
            .method(Method::POST) // Use Method::POST
            .uri("/api/chats")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
            .header(header::COOKIE, auth_cookie2) // Use user2's cookie
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();

         let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

         // Handler should return FORBIDDEN if character exists but isn't owned by logged-in user
         assert_eq!(response.status(), StatusCode::FORBIDDEN);
         // Optionally check error message
         // let body = response.into_body().collect().await.unwrap().to_bytes();
         // let error_response: Value = serde_json::from_slice(&body).unwrap();
         // assert!(error_response["error"].as_str().unwrap().contains("access denied"));
    }


    #[tokio::test]
    async fn test_list_chat_sessions_success() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "test_list_chats_user", "password").await;

        // Create a character and sessions for the user
        let char1 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 1 for List").await;
        let char2 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 2 for List").await;
        let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char1.id).await;
        let session2 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char2.id).await;

        // Create data for another user (should not be listed)
        let other_user = test_helpers::create_test_user(&context.app.db_pool, "other_list_user", "password").await;
        let other_char = test_helpers::create_test_character(&context.app.db_pool, other_user.id, "Other User Char").await;
        let _other_session = test_helpers::create_test_chat_session(&context.app.db_pool, other_user.id, other_char.id).await; // Renamed to avoid unused var warning

        let request = Request::builder()
            .method(Method::GET) // Use Method::GET
            .uri("/api/chats")
            .header(header::COOKIE, auth_cookie) // Use cookie
            .body(Body::empty())
            .unwrap();

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions: Vec<ChatSession> = serde_json::from_slice(&body).expect("Failed to deserialize list response");

        assert_eq!(sessions.len(), 2);
        // Order is DESC by updated_at, so session2 should likely be first if inserted later
        assert!(sessions.iter().any(|s| s.id == session1.id));
        assert!(sessions.iter().any(|s| s.id == session2.id));
        assert!(sessions.iter().all(|s| s.user_id == user.id));
    }

    #[tokio::test]
    async fn test_list_chat_sessions_empty() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "test_list_empty_user", "password").await;

        let request = Request::builder()
            .method(Method::GET) // Use Method::GET
            .uri("/api/chats")
            .header(header::COOKIE, auth_cookie) // Use cookie
            .body(Body::empty())
            .unwrap();

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions: Vec<ChatSession> = serde_json::from_slice(&body).expect("Failed to deserialize empty list response");
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_list_chat_sessions_unauthorized() {
        let context = test_helpers::setup_test_app().await;

        let request = Request::builder()
            .method(Method::GET) // Use Method::GET
            .uri("/api/chats")
            .body(Body::empty())
            .unwrap();
        // No login

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED
    }

    // TODO: Add tests for get_chat_messages
    // TODO: Add tests for generate_chat_response (requires mocking AI client in TestContext)

    // --- Test Cases from tests/chat_tests.rs (now integrated) ---

    #[tokio::test]
    async fn list_chat_sessions_success_integration() { // Kept suffix for clarity
        let context = test_helpers::setup_test_app().await; // Use non-mutable context
        let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_list_chats_integ", "password").await;
        let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for List Integ").await;
        let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
        let session2 = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
        let other_user = test_helpers::create_test_user(&context.app.db_pool, "other_user_integ", "password").await;
        let other_character = test_helpers::create_test_character(&context.app.db_pool, other_user.id, "Other Char Integ").await;
        let _other_session = test_helpers::create_test_chat_session(&context.app.db_pool, other_user.id, other_character.id).await;
        let request = Request::builder()
            .uri(format!("/api/chats")) // Relative URI ok for oneshot
            .method(Method::GET)
            .header("Cookie", auth_cookie)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
        let sessions_array = body_json.as_array().expect("Response body should be a JSON array");
        assert_eq!(sessions_array.len(), 2, "Should return exactly 2 sessions for the logged-in user");
        let sessions: Vec<ChatSession> = serde_json::from_value(body_json).expect("Failed to deserialize sessions");
        assert!(sessions.iter().all(|s| s.user_id == test_user.id));
        assert!(sessions.iter().any(|s| s.id == session1.id));
        assert!(sessions.iter().any(|s| s.id == session2.id));
    }

    #[tokio::test]
    async fn list_chat_sessions_unauthenticated_integration() {
        let context = test_helpers::setup_test_app().await;
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // API should return 401
    }

    #[tokio::test]
    async fn list_chat_sessions_empty_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_list_empty_integ", "password").await;
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::GET)
            .header("Cookie", auth_cookie)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
        let sessions_array = body_json.as_array().expect("Response body should be a JSON array");
        assert!(sessions_array.is_empty(), "Should return an empty array for a user with no sessions");
    }

    // --- Tests for GET /api/chats/{id}/messages ---

    #[tokio::test]
    async fn get_chat_messages_success_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_msgs_integ", "password").await;
        let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Get Msgs Integ").await;
        let session = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
        let msg1 = test_helpers::create_test_chat_message(&context.app.db_pool, session.id, MessageRole::User, "Hello Integ").await;
        let msg2 = test_helpers::create_test_chat_message(&context.app.db_pool, session.id, MessageRole::Assistant, "Hi there Integ").await;
        let request = Request::builder()
            .uri(format!("/api/chats/{}/messages", session.id))
            .method(Method::GET)
            .header("Cookie", auth_cookie)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
        let messages_array = body_json.as_array().expect("Response body should be a JSON array");
        assert_eq!(messages_array.len(), 2, "Should return 2 messages");
        let messages: Vec<ChatMessage> = serde_json::from_value(body_json).unwrap();
        assert_eq!(messages[0].id, msg1.id);
        assert_eq!(messages[1].id, msg2.id);
    }

    #[tokio::test]
    async fn get_chat_messages_forbidden_integration() {
        let context = test_helpers::setup_test_app().await;
        let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "user1_get_msgs_integ", "password").await;
        let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "Char User 1 Integ").await;
        let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user1.id, character1.id).await;
        let _msg1 = test_helpers::create_test_chat_message(&context.app.db_pool, session1.id, MessageRole::User, "Msg 1 Integ").await;
        let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "user2_get_msgs_integ", "password").await;
        let request = Request::builder()
            .uri(format!("/api/chats/{}/messages", session1.id)) // Request User 1's session ID
            .method(Method::GET)
            .header("Cookie", auth_cookie2) // Authenticated as User 2
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_chat_messages_not_found_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_msgs_404_integ", "password").await;
        let non_existent_session_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(format!("/api/chats/{}/messages", non_existent_session_id))
            .method(Method::GET)
            .header("Cookie", auth_cookie)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_chat_messages_unauthenticated_integration() {
        let context = test_helpers::setup_test_app().await;
        let session_id = Uuid::new_v4(); // Some session ID
        let request = Request::builder()
            .uri(format!("/api/chats/{}/messages", session_id))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED for API
    }

    #[tokio::test]
    async fn get_chat_messages_empty_list_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_empty_msgs_integ", "password").await;
        let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Empty Msgs Integ").await;
        let session = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
        let request = Request::builder()
            .uri(format!("/api/chats/{}/messages", session.id))
            .method(Method::GET)
            .header("Cookie", auth_cookie)
            .body(Body::empty())
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
        let messages_array = body_json.as_array().expect("Response body should be a JSON array");
        assert!(messages_array.is_empty(), "Should return an empty array for a session with no messages");
    }

    // --- Tests for POST /api/chats (from integration tests) ---

    #[tokio::test]
    async fn create_chat_session_success_integration() {
        let context = test_helpers::setup_test_app().await; // Removed mut unless helpers need it
        let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_integ", "password").await;
        let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Create Chat Integ").await;
        let payload = json!({ "character_id": test_character.id });
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .header("Cookie", auth_cookie)
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let created_session: ChatSession = serde_json::from_slice(&body_bytes).expect("Failed to deserialize created session");
        assert_eq!(created_session.user_id, test_user.id);
        assert_eq!(created_session.character_id, test_character.id);
        // Verify in DB
        let session_in_db = test_helpers::get_chat_session_from_db(&context.app.db_pool, created_session.id).await;
        assert!(session_in_db.is_some());
        assert_eq!(session_in_db.unwrap().id, created_session.id);
    }

    #[tokio::test]
    async fn create_chat_session_unauthenticated_integration() {
        let context = test_helpers::setup_test_app().await;
        let character_id = Uuid::new_v4();
        let payload = json!({ "character_id": character_id });
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED for API
    }

    #[tokio::test]
    async fn create_chat_session_character_not_found_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_404_integ", "password").await;
        let non_existent_character_id = Uuid::new_v4();
        let payload = json!({ "character_id": non_existent_character_id });
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .header("Cookie", auth_cookie)
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_chat_session_character_not_owned_integration() {
        let context = test_helpers::setup_test_app().await; // Removed mut
        let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "user1_create_chat_integ", "password").await;
        let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "User 1 Char Integ").await;
        let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "user2_create_chat_integ", "password").await;
        let payload = json!({ "character_id": character1.id }); // User 1's character ID
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .header("Cookie", auth_cookie2) // Authenticated as User 2
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = context.app.router.oneshot(request).await.unwrap();
         assert_eq!(response.status(), StatusCode::FORBIDDEN); // Expect Forbidden
    }

    #[tokio::test]
    async fn create_chat_session_invalid_payload_integration() {
        let context = test_helpers::setup_test_app().await;
        let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_bad_payload_integ", "password").await;
        let invalid_payloads = vec![
            json!({}), // Missing character_id
            json!({ "character_id": "not-a-uuid" }), // Invalid UUID format
        ];
        for payload in invalid_payloads {
            let request = Request::builder()
                .uri(format!("/api/chats"))
                .method(Method::POST)
                .header("Content-Type", "application/json")
                .header("Cookie", &auth_cookie) // Borrow cookie string
                .body(Body::from(payload.to_string()))
                .unwrap();
            let response = context.app.router.clone().oneshot(request).await.unwrap(); // Clone router for loop
            // Expect 422 Unprocessable Entity for validation errors
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Failed for payload: {}", payload);
        }
    }

    // TODO: Add tests for POST /api/chats/{id}/generate
}