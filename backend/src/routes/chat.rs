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
use genai::webc::Error as WebClientError;

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
            // 1. Check if the character exists at all
            let character_exists = schema::characters::table
                .filter(schema::characters::id.eq(character_id))
                .select(schema::characters::user_id) // Select user_id for ownership check
                .first::<Uuid>(conn)
                .optional()?;

            match character_exists {
                Some(owner_id) => {
                    // 2. Check if the character is owned by the current user
                    if owner_id != user_id {
                        // Character exists but belongs to another user
                        Err(AppError::Forbidden)
                    } else {
                        // Character exists and is owned by the user, proceed to create session
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
                }
                None => {
                    // Character does not exist
                    Err(AppError::NotFound("Character not found".into()))
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

                 info!("Fetching character details");
                 // --- Query 2: Fetch Character ---
                 let character = characters::table
                    .filter(characters::id.eq(chat_session.character_id))
                    // We already validated session ownership, indirectly validating character access
                    // If characters could be accessed by others, add user_id check here too
                    .select(CharacterMetadata::as_select()) // Fetch only needed fields
                    .first::<CharacterMetadata>(transaction_conn)
                     .map_err(|e| {
                         error!(?e, "Failed to fetch character details for session");
                         match e {
                              diesel::result::Error::NotFound => AppError::NotFound("Character associated with session not found".into()), // Should be rare if DB integrity is maintained
                              _ => AppError::DatabaseQueryError(e),
                          }
                     })?;

                info!("Fetching chat history");
                // --- Query 3: Fetch Chat History ---
                let history = chat_messages::table
                    .filter(chat_messages::session_id.eq(session_id))
                    .select(ChatMessage::as_select())
                    .order(chat_messages::created_at.asc())
                    .load::<ChatMessage>(transaction_conn)
                     .map_err(|e| {
                         error!(?e, "Failed to fetch chat history");
                         AppError::DatabaseQueryError(e)
                     })?;


                // 2. Save the new user message
                info!("Saving user message");
                let _user_db_message = save_chat_message_internal(
                    transaction_conn,
                    session_id,
                    MessageRole::User,
                    user_message_content, // Use the original content
                )?;


                // 3. Build the prompt using the fetched data
                 info!("Building prompt");
                 // Assuming prompt_builder is synchronous for now
                 prompt_builder::build_prompt(
                     Some(&character),
                     &history, // Pass the fetched history
                     // Add other necessary parameters like user name if needed
                 )
                 .map_err(|e| {
                     // Handle potential errors from prompt building if it can fail
                     error!(?e, "Failed to build prompt");
                     AppError::InternalServerError(anyhow::anyhow!("Prompt building failed: {}", e))
                 })

            }) // End transaction
        }) // End interact
        .await
        .map_err(|interact_err| {
             tracing::error!("InteractError in generate_chat_response (first block): {}", interact_err);
             AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", interact_err))
        })??; // Propagate AppError from inside transaction/interact


    // --- LLM Interaction ---
    info!("Sending prompt to AI client");
    let llm_result = gemini_client::generate_simple_response(
        &ai_client,
        prompt,
    ).await;

    let ai_response_content = match llm_result {
        Ok(content) => content,
        Err(genai_err) => {
            // Convert genai::Error to AppError first
            let initial_app_error = AppError::from(genai_err);

            // Now match on the resulting AppError
            match initial_app_error {
                // Check if the error was specifically a GeminiError
                AppError::GeminiError(ref underlying_genai_error) => {
                     // Check the underlying genai::Error for the rate limit condition
                    if let genai::Error::WebModelCall { webc_error, .. } = underlying_genai_error {
                        if let WebClientError::ResponseFailedStatus { status, .. } = webc_error {
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
    // use super::*; // Removed unused import
    // use crate::models::{chats::{ChatSession, ChatMessage, MessageRole}, users::User}; // Removed unused User import
    use crate::models::{chats::{ChatSession, ChatMessage, MessageRole}};
    use crate::state::AppState;
    // use crate::llm::LLMClient; // Removed unresolved import
    // use crate::test_helpers::{self, create_test_user, setup_test_app, TestContext, create_test_user_and_login}; // Removed unused TestContext import
    use crate::test_helpers::{self, create_test_user, setup_test_app, create_test_user_and_login};
    use axum::{
        body::Body,
        http::{self, Method, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use uuid::Uuid;

    // --- Test Cases ---

    #[tokio::test]
    async fn test_create_chat_session_success() {
        let context = setup_test_app().await; // Removed mut
        let (auth_cookie, user) = create_test_user_and_login(&context.app, "test_create_chat_user", "password").await;
        let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Test Character for Chat").await;
        let request_body = json!({ "character_id": character.id });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/chats")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::COOKIE, auth_cookie)
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
        let context = setup_test_app().await;
        let request_body = json!({ "character_id": Uuid::new_v4() }); // Dummy ID

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/chats")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();
        // No login simulation

        let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED, not redirect, for API endpoints without login
    }

    #[tokio::test]
    async fn test_create_chat_session_character_not_found() {
        let context = setup_test_app().await;
        let (auth_cookie, _user) = create_test_user_and_login(&context.app, "test_char_not_found_user", "password").await;
        let non_existent_char_id = Uuid::new_v4();

        let request_body = json!({ "character_id": non_existent_char_id });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/chats")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::COOKIE, auth_cookie) // Use cookie
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
         let context = setup_test_app().await;
         let (_auth_cookie1, user1) = create_test_user_and_login(&context.app, "chat_user_1", "password").await;
         let character = test_helpers::create_test_character(&context.app.db_pool, user1.id, "User1 Character").await;
         let (auth_cookie2, _user2) = create_test_user_and_login(&context.app, "chat_user_2", "password").await;

         let request_body = json!({ "character_id": character.id });

         let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/chats")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::COOKIE, auth_cookie2) // Use user2's cookie
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
        let context = setup_test_app().await;
        let (auth_cookie, user) = create_test_user_and_login(&context.app, "test_list_chats_user", "password").await;

        // Create a character and sessions for the user
        let char1 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 1 for List").await;
        let char2 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 2 for List").await;
        let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char1.id).await;
        let session2 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char2.id).await;

        // Create data for another user (should not be listed)
        let other_user = create_test_user(&context.app.db_pool, "other_list_user", "password").await;
        let other_char = test_helpers::create_test_character(&context.app.db_pool, other_user.id, "Other User Char").await;
        let _other_session = test_helpers::create_test_chat_session(&context.app.db_pool, other_user.id, other_char.id).await; // Renamed to avoid unused var warning

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/api/chats")
            .header(http::header::COOKIE, auth_cookie) // Use cookie
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
        let context = setup_test_app().await;
        let (auth_cookie, _user) = create_test_user_and_login(&context.app, "test_list_empty_user", "password").await;

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/api/chats")
            .header(http::header::COOKIE, auth_cookie) // Use cookie
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
        let context = setup_test_app().await;

        let request = Request::builder()
            .method(http::Method::GET)
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