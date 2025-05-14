// backend/tests/chat_generate_non_stream_tests.rs
#![cfg(test)]


use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::{BigDecimal, ToPrimitive};
use chrono::Utc;
use diesel::prelude::*;
use genai::chat::{ChatRole, MessageContent};
use http_body_util::BodyExt;
use mime;
use serde_json::{json, Value};
use std::str::FromStr;
use tower::ServiceExt;
use tower_cookies::Cookie;
use uuid::Uuid;
// Import for session DEK handling
use tokio::time::{sleep, Duration};
use scribe_backend::errors::AppError;
use scribe_backend::crypto::decrypt_gcm;
use secrecy::ExposeSecret;

// Crate imports
use scribe_backend::models::{
    character_card::NewCharacter,
    characters::Character,
    chats::{
        ApiChatMessage, Chat as DbChat, ChatMessage as DbChatMessage, GenerateChatRequest,
        MessageRole, NewChat,
    }, // Though create_test_user is a helper
};
use scribe_backend::schema::{characters, chat_messages, chat_sessions, sessions}; // users schema not directly used if create_test_user is a helper
use scribe_backend::services::embedding_pipeline::{EmbeddingMetadata, RetrievedChunk};
use scribe_backend::test_helpers::{self, TestDataGuard};
use scribe_backend::test_helpers::db::create_test_user;
use tracing::{info, error, warn};

// Import the User model for deserialization
use scribe_backend::models::users::User as AppUser; 

// Add a custom ChatCompletionResponse struct since there doesn't seem to be one in scribe_backend::models::chats
#[derive(Debug, serde::Deserialize)]
struct ChatCompletionResponse {
    content: String,
    message_id: String, // Expecting flat structure { "content": "...", "message_id": "..." }
}

// Helper function to debug session data from the database
async fn debug_session_data(pool: &scribe_backend::state::DbPool, session_id: String) -> Result<(), anyhow::Error> {
    info!("DEBUG: Attempting to query session data for ID: {}", session_id);
    let session_id_for_error = session_id.clone();

    let session_record_result = pool.get().await
        .map_err(|e| anyhow::anyhow!("Failed to get database connection: {}", e))?
        .interact(move |conn| {
            sessions::table
                .filter(sessions::id.eq(session_id))
                .select((sessions::id, sessions::session, sessions::expires))
                .first::<(String, String, Option<chrono::DateTime<chrono::Utc>>)>(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to interact with database: {}", e))?;

    match session_record_result {
        Ok((retrieved_id, session_json_string, expires)) => {
            info!("DEBUG: Found session. ID: {}, Expires: {:?}", retrieved_id, expires);
            info!("DEBUG: Raw session JSON string: {}", session_json_string);

            // tower-sessions stores data as a JSON map. The actual session data is often nested.
            // The structure is typically: {"_flash":{},"axum-login.user":"{\"id\":...}","_csrf_token":"..."}
            // We need to parse the outer JSON, then get the "axum-login.user" field, which is *itself* a JSON string.
            let outer_session_data: serde_json::Value = serde_json::from_str(&session_json_string)
                .map_err(|e| anyhow::anyhow!("Failed to parse outer session JSON: {}. Raw: {}", e, session_json_string))?;

            if let Some(axum_login_user_val) = outer_session_data.get("axum-login.user") {
                if let Some(user_json_string) = axum_login_user_val.as_str() {
                    info!("DEBUG: Found 'axum-login.user' string: {}", user_json_string);
                    match serde_json::from_str::<AppUser>(user_json_string) {
                        Ok(user) => {
                            info!("DEBUG: Successfully deserialized User from session: {:?}", user);
                            if user.dek.is_some() {
                                info!("DEBUG: DEK IS PRESENT in the deserialized User object from session.");
                            } else {
                                info!("DEBUG: DEK IS NOT PRESENT in the deserialized User object from session.");
                            }
                        }
                        Err(e) => {
                            error!("DEBUG: Failed to deserialize User from 'axum-login.user' string: {}. String was: {}", e, user_json_string);
                        }
                    }
                } else {
                    warn!("DEBUG: 'axum-login.user' field is not a string: {:?}", axum_login_user_val);
                }
            } else {
                warn!("DEBUG: 'axum-login.user' key not found in session data. Keys present: {:?}", outer_session_data.as_object().map(|o| o.keys().collect::<Vec<_>>()));
            }

            // Log all top-level keys in the session for context
            if let Some(obj) = outer_session_data.as_object() {
                info!("DEBUG: All top-level keys in session data: {:?}", obj.keys().collect::<Vec<_>>());
            } else {
                warn!("DEBUG: Outer session data is not a JSON object.");
            }

            Ok(())
        }
        Err(diesel::result::Error::NotFound) => {
            error!("DEBUG: Session not found for ID: {}", session_id_for_error);
            Err(anyhow::anyhow!("Session not found for ID: {}", session_id_for_error))
        }
        Err(e) => Err(anyhow::anyhow!("Database error querying session: {}", e)),
    }
}

// --- Tests for POST /api/chats/{id}/generate (Non-Streaming JSON) ---

#[tokio::test]
// Removed ignore flag to make sure this test runs in CI
async fn generate_chat_response_uses_session_settings() -> Result<(), anyhow::Error> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let user = create_test_user(
        &test_app.db_pool,
        "gen_settings_user".to_string(),
        "password".to_string(),
    )
    .await?;
    
    info!("Created test user with ID: {}", user.id);

    // API Login
    let login_payload = json!({
        "identifier": user.username,
        "password": "password",
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    
    info!("Sending login request");
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");
    
    // Extract and log all cookies
    let cookie_headers = login_response.headers().get_all(header::SET_COOKIE);
    info!("Login response received, status: {}", login_response.status());
    info!("All cookie headers: {:?}", cookie_headers);
    
    let cookie_header = login_response.headers().get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("No Set-Cookie header found"))?;
    let cookie_str = cookie_header.to_str()?;
    info!("Cookie header string: {}", cookie_str);
    
    let parsed_cookie = Cookie::parse(cookie_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse cookie: {}", e))?;

    info!("Parsed cookie: name={}, value={}", parsed_cookie.name(), parsed_cookie.value());
    
    // Get the session ID from the cookie
    let session_id = parsed_cookie.value();
    info!("Using session ID: {}", session_id);
    
    // Use the entire cookie header in the requests
    let cookie_header_value = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    info!("Using cookie header: {}", cookie_header_value);

    // Give the session store time to persist the session
    info!("Waiting for session to be persisted...");
    sleep(Duration::from_millis(2000)).await;
    
    // Debug the session data to check if the DEK is present
    match debug_session_data(&test_app.db_pool, session_id.to_string()).await {
        Ok(_) => info!("Successfully retrieved session debug info"),
        Err(e) => error!("Failed to debug session data: {}", e),
    }
    
    let now = Utc::now();
    let new_db_character = NewCharacter {
        user_id: user.id,
        name: "Char for Resp Settings".to_string(),
        description: Some("Test Description".to_string().into_bytes()),
        greeting: Some("Test Greeting".to_string().into_bytes()),
        example_dialogue: Some("Test Example Dialog".to_string().into_bytes()),
        visibility: Some("private".to_string()),
        character_version: Some("2.0".to_string()),
        spec: "test".to_string(),
        spec_version: "test".to_string(),
        persona: None,
        world_scenario: None,
        avatar: None,
        chat: None,
        created_at: Some(now),
        creator_notes_multilingual: None,
        nickname: None,
        personality: None,
        tags: None,
        updated_at: Some(now),
        creation_date: Some(now),
        modification_date: Some(now),
        greeting_nonce: None,
        definition: None,
        default_voice: None,
        extensions: None,
        category: None,
        definition_visibility: None,
        example_dialogue_nonce: None,
        favorite: None,
        first_message_visibility: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        persona_visibility: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        world_scenario_visibility: None,
        description_nonce: None,
        personality_nonce: None,
        scenario_nonce: None,
        first_mes_nonce: None,
        mes_example_nonce: None,
        creator_notes_nonce: None,
        system_prompt_nonce: None,
        persona_nonce: None,
        world_scenario_nonce: None,
        definition_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        post_history_instructions_nonce: None,
        post_history_instructions: None,
        scenario: None,
        mes_example: None,
        first_mes: None,
        creator_notes: None,
        system_prompt: None,
        alternate_greetings: None,
        creator: None,
        source: None,
        group_only_greetings: None,
    };
    
    info!("Creating test character");
    let character: Character = {
        let interact_result = conn
            .interact(move |conn_actual| {
                diesel::insert_into(characters::table)
                    .values(&new_db_character)
                    .returning(Character::as_select())
                    .get_result(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    info!("Created test character with ID: {}", character.id);

    let new_chat_session = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some("Test Chat Session for Settings".to_string()),
        history_management_strategy: "truncate_summary".to_string(), // Default
        history_management_limit: 20, // Default
        model_name: "gemini-2.5-flash-preview-04-17".to_string(), // Default
        created_at: Utc::now(),
        updated_at: Utc::now(),
        visibility: Some("private".to_string()),
    };
    
    info!("Creating test chat session with ID: {}", new_chat_session.id);
    let session: DbChat = {
        let interact_result = conn
            .interact(move |conn_actual| {
                diesel::insert_into(chat_sessions::table)
                    .values(&new_chat_session)
                    .returning(DbChat::as_select())
                    .get_result(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    info!("Created test chat session successfully");

    // Set specific settings for this session
    let test_prompt = "Test system prompt for session";
    let test_temp = BigDecimal::from_str("0.88").unwrap();
    let test_tokens = 444_i32;
    let test_top_p = BigDecimal::from_str("0.92").unwrap();

    let test_freq_penalty = BigDecimal::from_str("0.5").unwrap();
    let test_pres_penalty = BigDecimal::from_str("0.3").unwrap();
    let test_top_k = 50_i32;
    let test_rep_penalty = BigDecimal::from_str("1.3").unwrap();
    let test_min_p = BigDecimal::from_str("0.05").unwrap();
    let test_top_a = BigDecimal::from_str("0.75").unwrap();
    let test_seed: Option<i32> = Some(12345);
    let test_logit_bias: Option<Value> = None;

    // Clone non-Copy values needed inside and after the closure
    let tt_clone = test_temp.clone();
    let tfp_clone = test_freq_penalty.clone();
    let tpp_clone = test_pres_penalty.clone();
    let ttop_clone = test_top_p.clone();
    let trp_clone = test_rep_penalty.clone();
    let tminp_clone = test_min_p.clone();
    let ttopa_clone = test_top_a.clone();
    let tlb_clone = test_logit_bias.clone(); // Value might not be Copy

    {
        let interact_result = conn.interact(move |conn_actual| {
            diesel::update(chat_sessions::table.find(session.id))
                .set((
                    chat_sessions::system_prompt.eq(Some(test_prompt.to_string())),
                    chat_sessions::temperature.eq(Some(tt_clone)),
                    chat_sessions::max_output_tokens.eq(Some(test_tokens)),
                    chat_sessions::frequency_penalty.eq(Some(tfp_clone)),
                    chat_sessions::presence_penalty.eq(Some(tpp_clone)),
                    chat_sessions::top_k.eq(Some(test_top_k)),
                    chat_sessions::top_p.eq(Some(ttop_clone)),
                    chat_sessions::repetition_penalty.eq(Some(trp_clone)),
                    chat_sessions::min_p.eq(Some(tminp_clone)),
                    chat_sessions::top_a.eq(Some(ttopa_clone)),
                    chat_sessions::seed.eq(test_seed),
                    chat_sessions::logit_bias.eq(tlb_clone),
                ))
                .execute(conn_actual)
        })
        .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?;
    }
    info!("Updated chat session with test settings");

    // --- Mock RAG Response ---
    let mock_metadata1 = EmbeddingMetadata {
        message_id: Uuid::new_v4(),
        session_id: session.id,
        speaker: "user".to_string(),
        timestamp: Utc::now(),
        text: "This is relevant chunk 1.".to_string(),
    };
    let mock_metadata2 = EmbeddingMetadata {
        message_id: Uuid::new_v4(),
        session_id: session.id,
        speaker: "ai".to_string(),
        timestamp: Utc::now(),
        text: "This is relevant chunk 2, slightly longer.".to_string(),
    };
    let mock_chunks = vec![
        RetrievedChunk {
            score: 0.95,
            text: mock_metadata1.text.clone(),
            metadata: mock_metadata1,
        },
        RetrievedChunk {
            score: 0.88,
            text: mock_metadata2.text.clone(),
            metadata: mock_metadata2,
        },
    ];
    test_app
        .mock_embedding_pipeline_service
        .set_retrieve_response(Ok(mock_chunks));
    // --- End Mock RAG Response ---

    // Configure Mock AI client for a successful response
    if let Some(mock_client) = test_app.mock_ai_client.as_ref() {
        let ai_response_content = "Mock AI success response for session settings test.".to_string();
        let successful_response = genai::chat::ChatResponse {
            model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini/mock-model"),
            provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini/mock-model"),
            content: Some(genai::chat::MessageContent::Text(ai_response_content)),
            reasoning_content: None,
            usage: Default::default(),
        };
        mock_client.set_response(Ok(successful_response));
    } else {
        panic!("Mock AI client not available, even after setting use_real_ai=false");
    }

   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "Hello, world!".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("gemini/mock-model".to_string()),
   };

   // Check session one last time before making chat generate request
   info!("Checking session before chat generate request");
   match debug_session_data(&test_app.db_pool, session_id.to_string()).await {
       Ok(_) => info!("Session verified before chat generate request"),
       Err(e) => error!("Failed to verify session before chat generate: {}", e),
   }

   info!("Building chat generate request");
   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, cookie_header_value)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    info!("Sending chat generate request");
    let response = test_app.router.clone().oneshot(request).await?;
    info!("Received chat generate response, status: {}", response.status());
    
    // Uncomment this to explicitly capture the response body for debugging
    // let body_bytes = response.into_body().collect().await?.to_bytes();
    // info!("Response body: {:?}", String::from_utf8_lossy(&body_bytes));
    
    assert_eq!(response.status(), StatusCode::OK);

    let last_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_request()
        .expect("Mock AI client did not receive a request");
    
    info!("Got last AI request from mock client");

    let last_message_content = last_request.messages.last().unwrap().content.clone();
    let prompt_text = match last_message_content {
        MessageContent::Text(text) => text,
        _ => panic!("Expected last message content to be text"),
    };
    info!("--- DEBUG: Prompt Text Content ---\n{}\n--- END DEBUG ---", prompt_text);
    info!("--- DEBUG: All Messages ---");
    for (i, msg) in last_request.messages.iter().enumerate() {
        let content_text = match &msg.content {
            MessageContent::Text(text) => text.clone(), // Cloned to match String type
            _ => "Non-text content".to_string() // Converted to String
        };
        info!("Message {}: Role={:?}, Content={}", i, msg.role, content_text);
    }
    info!("--- END DEBUG ---");

    let user_message = last_request.messages.iter()
        .find(|msg| matches!(msg.role, ChatRole::User))
        .expect("User message should exist");

    let options = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_options()
        .expect("No options recorded by mock AI client");

    if let Some(temp) = options.temperature {
        let expected_temp = test_temp.to_f64().unwrap();
        assert!((temp - expected_temp).abs() < 0.001, "Temperature value doesn't match");
    } else {
        panic!("Expected temperature to be set in options");
    }
    if let Some(tokens) = options.max_tokens {
        assert_eq!(tokens, test_tokens as u32, "Max tokens value doesn't match");
    } else {
        panic!("Expected max_tokens to be set in options");
    }
    if let Some(top_p_val) = options.top_p { // Renamed to avoid conflict with test_top_p
        let expected_top_p = test_top_p.to_f64().unwrap();
        assert!((top_p_val - expected_top_p).abs() < 0.001, "Top-p value doesn't match");
    } else {
        panic!("Expected top_p to be set in options");
    }

    let db_chat_settings: DbChat = {
        let interact_result = conn
            .interact(move |conn_actual| {
                chat_sessions::table
                    .find(session.id)
                    .select(DbChat::as_select())
                    .first::<DbChat>(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    assert_eq!(db_chat_settings.system_prompt, Some("Test system prompt for session".to_string()));
    assert_eq!(db_chat_settings.temperature, Some(test_temp));
    assert_eq!(db_chat_settings.max_output_tokens, Some(test_tokens));
    assert_eq!(db_chat_settings.frequency_penalty, Some(test_freq_penalty));
    assert_eq!(db_chat_settings.presence_penalty, Some(test_pres_penalty));
    assert_eq!(db_chat_settings.top_k, Some(test_top_k));
    assert_eq!(db_chat_settings.top_p, Some(test_top_p));
    assert_eq!(db_chat_settings.repetition_penalty, Some(test_rep_penalty));
    assert_eq!(db_chat_settings.min_p, Some(test_min_p));
    assert_eq!(db_chat_settings.top_a, Some(test_top_a));
    assert_eq!(db_chat_settings.seed, test_seed);
    assert_eq!(db_chat_settings.logit_bias, test_logit_bias);
    assert_eq!(Some(db_chat_settings.history_management_strategy.as_str()), Some("truncate_summary"));
    assert_eq!(db_chat_settings.history_management_limit, 20);
    assert_eq!(Some(db_chat_settings.model_name.as_str()), Some("gemini-2.5-flash-preview-04-17"));


    // Add a short delay to ensure database operations have completed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    let messages: Vec<DbChatMessage> = {
        let interact_result = conn
            .interact(move |conn_actual| {
                chat_messages::table
                    .filter(chat_messages::session_id.eq(session.id))
                    .order(chat_messages::created_at.asc())
                    .select(DbChatMessage::as_select())
                    .load::<DbChatMessage>(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    assert_eq!(messages.len(), 2, "Should have two messages: user and AI");

    // Decrypt user message for assertion
    let user_db_message = &messages[0];
    assert_eq!(user_db_message.message_type, MessageRole::User);
    let dek_from_user_obj = user.dek.as_ref().expect("User DEK should be present");
    let user_plaintext_bytes = decrypt_gcm(
        &user_db_message.content,
        user_db_message.content_nonce.as_ref().expect("User message nonce should be present"),
        &dek_from_user_obj.0
    ).expect("Failed to decrypt user message content in test assertion");
    let user_decrypted_content_str = String::from_utf8(user_plaintext_bytes.expose_secret().to_vec())
        .expect("User decrypted content is not valid UTF-8");
    assert_eq!(user_decrypted_content_str, payload.history.last().unwrap().content);

    // Decrypt AI message for assertion
    let ai_db_message = &messages[1];
    assert_eq!(ai_db_message.message_type, MessageRole::Assistant);
    // DEK is the same as for the user message
    let ai_plaintext_bytes = decrypt_gcm(
        &ai_db_message.content,
        ai_db_message.content_nonce.as_ref().expect("AI message nonce should be present"),
        &dek_from_user_obj.0
    ).expect("Failed to decrypt AI message content in test assertion");
    let ai_decrypted_content_str = String::from_utf8(ai_plaintext_bytes.expose_secret().to_vec())
        .expect("AI decrypted content is not valid UTF-8");
    
    // The expected AI content is what we set in mock_client.set_response()
    let expected_ai_content = "Mock AI success response for session settings test.".to_string();
    assert_eq!(ai_decrypted_content_str, expected_ai_content);

    // Add another delay to ensure async embedding processing has completed
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    
    // Try a few times in case the embedding processing is still running
    let mut embedding_calls;
    let mut attempts = 0;
    let max_attempts = 5;
    
    loop {
        embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
        
        if embedding_calls.len() >= 2 || attempts >= max_attempts {
            break;
        }
        
        info!("Found {} embedding calls, waiting for more...", embedding_calls.len());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        attempts += 1;
    }
    
    if embedding_calls.len() >= 2 {
        info!("Found expected number of embedding calls after {} attempts", attempts);
    } else {
        info!("Failed to find expected number of embedding calls after {} attempts. Found: {}", 
              attempts, embedding_calls.len());
    }
    
    // We should have exactly 2 embedding calls:
    // 1. One for embedding the user message content (process_and_embed_message)
    // 2. One for retrieving relevant chunks for RAG (retrieve_relevant_chunks)
    assert_eq!(embedding_calls.len(), 2, "Should have two embedding calls (user message embedding and RAG retrieval)");
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_json_stream_initiation_error() -> Result<(), anyhow::Error> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let user = create_test_user(
        &test_app.db_pool,
        "gen_error_user".to_string(),
        "password".to_string(),
    )
    .await?;

    // API Login
    let login_payload = json!({
        "identifier": user.username,
        "password": "password",
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");
    let cookie_header = login_response.headers().get(header::SET_COOKIE).unwrap();
    let cookie_str = cookie_header.to_str().unwrap();
    let parsed_cookie = Cookie::parse(cookie_str).unwrap();

    println!("Cookie name: {}, value: {}", parsed_cookie.name(), parsed_cookie.value());

    // Use the entire cookie header in the requests
    let cookie_header_value = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    // Give the session store time to persist the session
    sleep(Duration::from_millis(1000)).await;

    let now = Utc::now();
    let new_db_character = NewCharacter {
        user_id: user.id,
        name: "Non-Stream Err Char".to_string(),
        description: Some("Test Description".to_string().into_bytes()),
        greeting: Some("Test Greeting".to_string().into_bytes()),
        example_dialogue: Some("Test Example Dialog".to_string().into_bytes()),
        visibility: Some("private".to_string()),
        character_version: Some("2.0".to_string()),
        spec: "test".to_string(),
        spec_version: "test".to_string(),
        persona: None,
        world_scenario: None,
        avatar: None,
        chat: None,
        created_at: Some(now),
        creator_notes_multilingual: None,
        nickname: None,
        personality: None,
        tags: None,
        updated_at: Some(now),
        creation_date: Some(now),
        modification_date: Some(now),
        greeting_nonce: None,
        definition: None,
        default_voice: None,
        extensions: None,
        category: None,
        definition_visibility: None,
        example_dialogue_nonce: None,
        favorite: None,
        first_message_visibility: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        persona_visibility: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        world_scenario_visibility: None,
        description_nonce: None,
        personality_nonce: None,
        scenario_nonce: None,
        first_mes_nonce: None,
        mes_example_nonce: None,
        creator_notes_nonce: None,
        system_prompt_nonce: None,
        persona_nonce: None,
        world_scenario_nonce: None,
        definition_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        post_history_instructions_nonce: None,
        post_history_instructions: None,
        scenario: None,
        mes_example: None,
        first_mes: None,
        creator_notes: None,
        system_prompt: None,
        alternate_greetings: None,
        creator: None,
        source: None,
        group_only_greetings: None,
    };
    let character: Character = {
        let interact_result = conn
            .interact(move |conn_actual| {
                diesel::insert_into(characters::table)
                    .values(&new_db_character)
                    .returning(Character::as_select())
                    .get_result(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };

    let new_chat_session = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some("Test Chat Session for Settings".to_string()),
        history_management_strategy: "truncate_summary".to_string(), // Default
        history_management_limit: 20, // Default
        model_name: "gemini-2.5-flash-preview-04-17".to_string(), // Default
        created_at: Utc::now(),
        updated_at: Utc::now(),
        visibility: Some("private".to_string()),
    };
    let session: DbChat = {
        let interact_result = conn
            .interact(move |conn_actual| {
                diesel::insert_into(chat_sessions::table)
                    .values(&new_chat_session)
                    .returning(DbChat::as_select())
                    .get_result(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };

    // Set specific settings for this session
    let test_prompt = "Error test system prompt";
    let test_temp = BigDecimal::from_str("0.77").unwrap();
    let test_tokens = 333_i32;
    let test_top_p = BigDecimal::from_str("0.82").unwrap();
    let test_freq_penalty = BigDecimal::from_str("0.4").unwrap();
    let test_pres_penalty = BigDecimal::from_str("0.2").unwrap();
    let test_top_k = 40_i32;
    let test_rep_penalty = BigDecimal::from_str("1.2").unwrap();
    let test_min_p = BigDecimal::from_str("0.04").unwrap();
    let test_top_a = BigDecimal::from_str("0.65").unwrap();
    let test_seed: Option<i32> = Some(54321);
    let test_logit_bias: Option<Value> = None;

    // Clone non-Copy values needed inside and after the closure
    let tt_clone_err = test_temp.clone();
    let tfp_clone_err = test_freq_penalty.clone();
    let tpp_clone_err = test_pres_penalty.clone();
    let ttop_clone_err = test_top_p.clone();
    let trp_clone_err = test_rep_penalty.clone();
    let tminp_clone_err = test_min_p.clone();
    let ttopa_clone_err = test_top_a.clone();
    let tlb_clone_err = test_logit_bias.clone();

    {
        let interact_result = conn.interact(move |conn_actual| {
            diesel::update(chat_sessions::table.find(session.id))
                .set((
                    chat_sessions::system_prompt.eq(Some(test_prompt.to_string())),
                    chat_sessions::temperature.eq(Some(tt_clone_err)),
                    chat_sessions::max_output_tokens.eq(Some(test_tokens)),
                    chat_sessions::frequency_penalty.eq(Some(tfp_clone_err)),
                    chat_sessions::presence_penalty.eq(Some(tpp_clone_err)),
                    chat_sessions::top_k.eq(Some(test_top_k)),
                    chat_sessions::top_p.eq(Some(ttop_clone_err)),
                    chat_sessions::repetition_penalty.eq(Some(trp_clone_err)),
                    chat_sessions::min_p.eq(Some(tminp_clone_err)),
                    chat_sessions::top_a.eq(Some(ttopa_clone_err)),
                    chat_sessions::seed.eq(test_seed),
                    chat_sessions::logit_bias.eq(tlb_clone_err),
                ))
                .execute(conn_actual)
        })
        .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?;
    }

    // Set mock AI client to return an error
    if let Some(mock_client) = test_app.mock_ai_client.as_ref() {
        mock_client.set_response(Err(AppError::AiServiceError("Simulated LLM generation error".to_string())));
    } else {
        panic!("Mock AI client not available");
    }

   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "Hello, world!".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("gemini/mock-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, cookie_header_value)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;

    // Assert that the status code is 500 Internal Server Error
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "Expected 500 Internal Server Error due to AI service error");

    // Optionally, check the response body for the error message if it's sent
    // let body_bytes = response.into_body().collect().await?.to_bytes();
    // let body_str = std::str::from_utf8(&body_bytes)?;
    // assert!(body_str.contains("Simulated LLM stream initiation error"));

    let last_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    let last_message_content = last_request.messages.last().unwrap().content.clone();
    let prompt_text = match last_message_content {
        MessageContent::Text(text) => text,
        _ => panic!("Expected last message content to be text"),
    };
    eprintln!("--- DEBUG: Prompt Text Content ---
{}
--- END DEBUG ---", prompt_text);
    eprintln!("--- DEBUG: All Messages ---");
    for (i, msg) in last_request.messages.iter().enumerate() {
        let content_text = match &msg.content {
            MessageContent::Text(text) => text.clone(), // Cloned to match String type
            _ => "Non-text content".to_string() // Converted to String
        };
        eprintln!("Message {}: Role={:?}, Content={}", i, msg.role, content_text);
    }
    eprintln!("--- END DEBUG ---");

    let user_message = last_request.messages.iter()
        .find(|msg| matches!(msg.role, ChatRole::User))
        .expect("User message should exist");

    let options = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_options()
        .expect("No options recorded by mock AI client");

    if let Some(temp) = options.temperature {
        let expected_temp = test_temp.to_f64().unwrap();
        assert!((temp - expected_temp).abs() < 0.001, "Temperature value doesn't match");
    } else {
        panic!("Expected temperature to be set in options");
    }
    if let Some(tokens) = options.max_tokens {
        assert_eq!(tokens, test_tokens as u32, "Max tokens value doesn't match");
    } else {
        panic!("Expected max_tokens to be set in options");
    }
    if let Some(top_p_val) = options.top_p { // Renamed to avoid conflict with test_top_p
        let expected_top_p = test_top_p.to_f64().unwrap();
        assert!((top_p_val - expected_top_p).abs() < 0.001, "Top-p value doesn't match");
    } else {
        panic!("Expected top_p to be set in options");
    }

    let db_chat_settings: DbChat = {
        let interact_result = conn
            .interact(move |conn_actual| {
                chat_sessions::table
                    .find(session.id)
                    .select(DbChat::as_select())
                    .first::<DbChat>(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    
    // Check that the system_prompt is what we set earlier
    assert_eq!(db_chat_settings.system_prompt, Some("Error test system prompt".to_string()));
    assert_eq!(db_chat_settings.temperature, Some(test_temp));
    assert_eq!(db_chat_settings.max_output_tokens, Some(test_tokens));
    assert_eq!(db_chat_settings.frequency_penalty, Some(test_freq_penalty));
    assert_eq!(db_chat_settings.presence_penalty, Some(test_pres_penalty));
    assert_eq!(db_chat_settings.top_k, Some(test_top_k));
    assert_eq!(db_chat_settings.top_p, Some(test_top_p));
    assert_eq!(db_chat_settings.repetition_penalty, Some(test_rep_penalty));
    assert_eq!(db_chat_settings.min_p, Some(test_min_p));
    assert_eq!(db_chat_settings.top_a, Some(test_top_a));
    assert_eq!(db_chat_settings.seed, test_seed);
    assert_eq!(db_chat_settings.logit_bias, test_logit_bias);
    assert_eq!(Some(db_chat_settings.history_management_strategy.as_str()), Some("truncate_summary"));
    assert_eq!(db_chat_settings.history_management_limit, 20);
    assert_eq!(Some(db_chat_settings.model_name.as_str()), Some("gemini-2.5-flash-preview-04-17"));

    let messages: Vec<DbChatMessage> = {
        let interact_result = conn
            .interact(move |conn_actual| {
                chat_messages::table
                    .filter(chat_messages::session_id.eq(session.id))
                    .order(chat_messages::created_at.asc())
                    .select(DbChatMessage::as_select())
                    .load::<DbChatMessage>(conn_actual)
            })
            .await;
        let diesel_result = interact_result.map_err(|e| anyhow::anyhow!("Deadpool interact error: {}", e))?;
        diesel_result?
    };
    assert_eq!(messages.len(), 1, "Should have only the user message since AI response failed");

    let user_db_message = &messages[0];
    assert_eq!(user_db_message.message_type, MessageRole::User);

    let dek_from_user_obj = user.dek.as_ref().expect("User DEK should be present after create_user_and_session_with_dek");
    let plaintext_content_bytes = decrypt_gcm(
        &user_db_message.content,
        user_db_message.content_nonce.as_ref().expect("Nonce should be present for encrypted content"),
        &dek_from_user_obj.0 // Access the inner SecretBox<Vec<u8>>
    ).expect("Failed to decrypt user message content in test assertion");

    let decrypted_content_str = String::from_utf8(plaintext_content_bytes.expose_secret().to_vec())
        .expect("Decrypted content is not valid UTF-8");

    assert_eq!(decrypted_content_str, payload.history.last().unwrap().content);
    // We can't check the AI message since it doesn't exist due to the error

    Ok(())
}

