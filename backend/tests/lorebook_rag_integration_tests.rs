#![allow(unused_imports)] // TODO: Remove this once tests are implemented
use scribe_backend::test_helpers::{spawn_app, TestApp, TestDataGuard, MockAiClient}; // App spawning, test data, MockAiClient
use scribe_backend::models::lorebook_dtos::{
    CreateLorebookPayload, // DTO for creating a lorebook
    LorebookResponse, // DTO for lorebook responses
    CreateLorebookEntryPayload, // DTO for creating lorebook entries
    AssociateLorebookToChatPayload, // DTO for associating lorebook to chat
    ChatSessionLorebookAssociationResponse, // DTO for the association response
};
use scribe_backend::models::chats::{
    Chat as ChatSessionResponseDto, // Using DB model as DTO for now
    CreateChatRequest, // DTO for creating a chat session
    ApiChatMessage, // For chat message structures in GenerateChatRequest
    GenerateChatRequest, // For the payload to /generate
    GenerateResponse as GenerateChatResponse // For the response from /generate
};
use scribe_backend::models::characters::Character as DbCharacter; // For DB character model
use scribe_backend::schema::characters; // For DB schema
use diesel::prelude::*; // For Diesel query builder
use chrono::Utc; // For timestamps
use reqwest::StatusCode; // HTTP status codes
use reqwest::header::{ACCEPT, CONTENT_TYPE}; // For SSE request and response headers
use mime::TEXT_EVENT_STREAM; // For SSE mime type
use futures_util::StreamExt; // For stream operations
use serde_json::json; // For creating JSON payloads if needed
use std::{collections::HashMap, fs, sync::Arc}; // For HashMap, file system operations, and shared ownership
use tokio::time::{sleep, Duration}; // For handling asynchronous operations, potential delays
use uuid::Uuid; // For IDs
use serde::Deserialize; // For deserializing JSON
use scribe_backend::test_helpers::ParsedSseEvent; // For parsing SSE events
use genai::chat::{ChatStreamEvent, StreamChunk, MessageContent as GenAiMessageContent}; // For Mock AI stream response
use scribe_backend::errors::AppError; // For Mock AI stream response
use scribe_backend::services::embedding_pipeline::{RetrievedChunk, RetrievedMetadata, LorebookChunkMetadata}; // For mocking retrieved chunks

// Helper structs for deserializing test_data/test_lorebook.json
#[derive(Deserialize, Debug)]
struct TestLorebookFile {
    entries: HashMap<String, TestLorebookJsonEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TestLorebookJsonEntry {
    key: Vec<String>,
    #[serde(default)] // Handles cases where keysecondary might be missing
    keysecondary: Vec<String>,
    comment: Option<String>, // Used as entry_title
    content: String,
    constant: Option<bool>,
    order: Option<i32>,
    position: Option<i32>, // 0 for before_prompt
    disable: Option<bool>,
    // We only deserialize fields relevant to LorebookEntryCreateRequest
}

// Helper function to import entries from test_data/test_lorebook.json
async fn import_lorebook_entries_via_api(
    test_app: &TestApp,
    auth_client: &reqwest::Client,
    lorebook_id: Uuid,
) {
    let file_content = fs::read_to_string("../test_data/test_lorebook.json")
        .expect("Failed to read test_data/test_lorebook.json");
    let lorebook_data: TestLorebookFile =
        serde_json::from_str(&file_content).expect("Failed to parse test_lorebook.json");

    for (_key, json_entry) in lorebook_data.entries {
        let mut all_keys = json_entry.key.clone();
        all_keys.extend(json_entry.keysecondary.clone());
        let keys_text = if all_keys.is_empty() {
            None
        } else {
            Some(all_keys.join(", "))
        };

        let placement_hint = match json_entry.position {
            Some(0) => Some("before_prompt".to_string()),
            // TODO: Add other mappings if necessary, e.g. SillyTavern positions:
            // 0: Before Char
            // 1: After Char
            // 2: Between Char/Author (not common)
            // 3: Before Prompt
            // 4: After Prompt
            _ => None, // Default or unhandled position
        };

        let entry_payload = CreateLorebookEntryPayload {
            entry_title: json_entry.comment.unwrap_or_else(|| "Untitled Entry".to_string()),
            keys_text,
            content: json_entry.content,
            comment: None, // DTO comment is for additional notes, not the title here
            is_enabled: json_entry.disable.map(|d| !d), // If disable is Some(true), is_enabled is Some(false)
            is_constant: json_entry.constant,
            insertion_order: json_entry.order,
            placement_hint,
        };

        let response = auth_client
            .post(&format!(
                "{}/api/lorebooks/{}/entries",
                test_app.address, lorebook_id
            ))
            .json(&entry_payload)
            .send()
            .await
            .expect("Failed to send create lorebook entry request");

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "Failed to create lorebook entry. Title: '{}', Status: {:?}, Body: {:?}",
            entry_payload.entry_title,
            response.status(),
            response.text().await
        );
        // Optionally parse the response if needed, but for now, status check is enough
        let _created_entry: serde_json::Value = response.json().await.expect("Failed to parse entry response");
    }

    // Give a moment for the async embedding tasks to be initiated
    sleep(Duration::from_millis(200)).await;
}


#[tokio::test]
async fn test_lorebook_import_retrieval_and_rag_integration() {
    // 1. Test setup: Spawn app, create user, log in
    let test_app = spawn_app(true, false, true).await; // Use mock AI, real Qdrant, mock Embedding (via MockEmbeddingPipelineService)
    let _test_data_guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_credentials = ("lore_rag_user@example.com", "Password123!");
    let user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let (auth_client, _user_token_str) =
        scribe_backend::test_helpers::login_user_via_api(&test_app, user_credentials.0, user_credentials.1)
            .await;

    // 2. Create a lorebook via the API
    let lorebook_payload = CreateLorebookPayload {
        name: "Integration Test Lorebook".to_string(),
        description: Some("A lorebook for E2E RAG testing.".to_string()),
    };

    let response = auth_client
        .post(&format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to send create lorebook request");

    assert_eq!(response.status(), StatusCode::CREATED, "Failed to create lorebook. Status: {:?}, Body: {:?}", response.status(), response.text().await);
    let created_lorebook: LorebookResponse = response
        .json()
        .await
        .expect("Failed to parse create lorebook response");

    assert_eq!(created_lorebook.name, lorebook_payload.name);
    assert_eq!(created_lorebook.user_id, user_data.id);
    
    // 3. Import entries into the created lorebook
    import_lorebook_entries_via_api(&test_app, &auth_client, created_lorebook.id).await;

    // Check MockEmbeddingPipelineService calls
    // This part needs to align with how MockEmbeddingPipelineService records calls.
    // Assuming it stores calls in a way that can be retrieved and checked.
    // Let's say it has a method like `get_process_and_embed_calls()`
    // For now, we'll just check that some calls were made.
    // The exact number should be the number of entries in test_lorebook.json
    // The test_lorebook.json has 20 entries (0-19)
    let embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
    assert!(!embedding_calls.is_empty(), "Expected embedding pipeline to be called.");
    // TODO: Be more specific about the number of calls if possible, e.g., assert_eq!(embedding_calls.len(), 20);
    // This depends on whether every entry in the JSON is valid and results in a call.
    // For now, checking it's not empty is a good start.
    // We might need to adjust the count based on how many entries are actually processed.
    // The provided JSON has 20 entries (0-19).
    assert_eq!(embedding_calls.len(), 20, "Expected 20 calls to embedding pipeline for 20 entries.");


    // 4. Create a dummy character for the user
    let character_id = Uuid::new_v4();
    let _db_pool_clone = test_app.db_pool.clone(); // Prefixed with _ as it's unused
    let user_id_clone = user_data.id;
    // It's important to ensure the TestDataGuard is properly set up if direct DB manipulation is done for cleanup.
    // However, for API-driven tests, direct DB writes for setup should be minimized if API alternatives exist.
    // Here, we'll insert directly for simplicity as character creation via API can be verbose.
    let new_character_data = DbCharacter {
        id: character_id,
        user_id: user_id_clone,
        name: "Test RAG Character".to_string(),
        spec: "test_spec_v1".to_string(), // Ensure this spec is valid or use a minimal one
        spec_version: "1.0.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None,
        creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None,
        modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None,
        greeting: None, greeting_nonce: None, definition: None, definition_nonce: None,
        default_voice: None, category: None, definition_visibility: None, example_dialogue: None, example_dialogue_nonce: None,
        favorite: None, first_message_visibility: None, migrated_from: None, model_prompt: None, model_prompt_nonce: None,
        model_prompt_visibility: None, persona_visibility: None, sharing_visibility: None, status: None,
        system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_nonce: None, user_persona_visibility: None, visibility: Some("private".to_string()),
        world_scenario_visibility: None, data_id: None, depth: None, height: None, last_activity: None,
        model_temperature: None, num_interactions: None, permanence: None, revision: None, weight: None,
    };

    test_app.db_pool
        .get()
        .await
        .expect("Failed to get DB connection for character creation")
        .interact(move |actual_conn| { // actual_conn is &mut PgConnection
            diesel::insert_into(characters::table)
                .values(&new_character_data) // Use the moved data
                .execute(actual_conn) // Pass &mut PgConnection directly
        })
        .await
        .expect("Interact task for character insertion failed") // Outer error from interact (e.g., pool error)
        .expect("Failed to insert dummy character"); // Inner error from Diesel (QueryResult)


    // 5. Initiate a chat session
    let chat_session_payload = CreateChatRequest {
        title: "RAG Test Chat Session".to_string(), // CreateChatRequest expects String
        character_id,
        // model_name, settings, active_custom_persona_id, active_impersonated_character_id
        // are not part of CreateChatRequest. Assuming the API changed or these are set elsewhere/defaulted.
    };

    let response = auth_client
        .post(&format!("{}/api/chats", test_app.address))
        .json(&chat_session_payload)
        .send()
        .await
        .expect("Failed to send create chat session request");

    assert_eq!(response.status(), StatusCode::CREATED, "Failed to create chat session. Status: {:?}, Body: {:?}", response.status(), response.text().await);
    let chat_session: ChatSessionResponseDto = response
        .json()
        .await
        .expect("Failed to parse create chat session response");

    assert_eq!(chat_session.character_id, character_id);
    assert_eq!(chat_session.user_id, user_data.id);

    // 6. Associate the lorebook with the chat session
    let associate_payload = AssociateLorebookToChatPayload {
        lorebook_id: created_lorebook.id,
    };

    let response = auth_client
        .post(&format!(
            "{}/api/chats/{}/lorebooks",
            test_app.address, chat_session.id
        ))
        .json(&associate_payload)
        .send()
        .await
        .expect("Failed to send associate lorebook request");
    
    assert_eq!(response.status(), StatusCode::OK, "Failed to associate lorebook. Status: {:?}, Body: {:?}", response.status(), response.text().await);
    let association_response: ChatSessionLorebookAssociationResponse = response
        .json()
        .await
        .expect("Failed to parse associate lorebook response");
    
    assert_eq!(association_response.chat_session_id, chat_session.id);
    assert_eq!(association_response.lorebook_id, created_lorebook.id);
    assert_eq!(association_response.user_id, user_data.id);
    assert_eq!(association_response.lorebook_name, created_lorebook.name);


    // 7. Send a user message to trigger RAG
    let user_message_content = "What's happening in North America in 2025?".to_string();
    let generate_payload = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: user_message_content.clone(),
        }],
        model: None, // Use default model from chat session settings
        query_text_for_rag: None,
    };

   // Configure the mock AI client to return a stream with content
   if let Some(mock_ai) = &test_app.mock_ai_client {
       mock_ai.set_stream_response(vec![
           Ok(ChatStreamEvent::Chunk(StreamChunk {
               content: "Mocked RAG response from AI.".to_string(),
           })),
           Ok(ChatStreamEvent::End(Default::default())),
       ]);
   } else {
       panic!("Mock AI client not found in test_app, cannot set stream response.");
   }

    // Configure MockEmbeddingPipelineService to return the "North America" lorebook entry
    let north_america_content = "{{user}}: \"What's happening in North America in 2025?\"\n\n{{char}}: *Your cosmic awareness focuses on the North American continent, revealing layers of political, economic, and environmental realities.*\n\n*In the United States, President Donald Trump's second administration has implemented significant policy shifts since his January 2025 inauguration. The Treasury has established a Strategic Bitcoin Reserve, converting 5% of national gold reserves to cryptocurrency. Trade relations have deteriorated with neighbors, with tariffs against Canada (23%) and Mexico (31%) triggering retaliatory measures. Domestically, federal agencies face 17% average budget cuts with environmental regulations significantly rolled back.*\n\n*Immigration enforcement has intensified with military deployment along the southern border and mass deportation operations in major cities, creating labor shortages in agriculture and service sectors. Climate impacts continue intensifying with severe drought affecting 67% of the American West, while the Southeast still recovers from Hurricane Patricia (Category 5) that devastated Florida's Gulf Coast in February 2025.*\n\n*Canada faces its own challenges under Prime Minister Pierre Poilievre's Conservative government. Relations with the US have reached their lowest point in decades due to trade disputes and border tensions. The government has prioritized oil sands development in Alberta while reducing federal climate commitments. In Quebec, the sovereignty movement has gained renewed momentum following controversial language laws, with support for independence reaching 47% in recent polling.*\n\n*Mexico under President Claudia Sheinbaum struggles with drug cartel violence reaching unprecedented levels. Three states (Sinaloa, Michoacán, and Tamaulipas) operate largely outside federal control. The economy suffers from US tariffs and reduced foreign investment. Migrant caravans from Central and South America continue arriving at Mexico's southern border, creating humanitarian challenges as they face barriers to northern movement.*".to_string();
    let lorebook_chunk_metadata = LorebookChunkMetadata {
        original_lorebook_entry_id: Uuid::new_v4(), // Dummy ID for mock
        lorebook_id: created_lorebook.id,
        user_id: user_data.id,
        chunk_text: north_america_content.clone(),
        entry_title: Some("North America".to_string()),
        keywords: Some(vec![
            "North America".to_string(), "USA".to_string(), "United States".to_string(),
            "Canada".to_string(), "Mexico".to_string(), "America".to_string(),
            "NAFTA".to_string(), "USMCA".to_string()
        ]),
        is_enabled: true,
        is_constant: false,
        source_type: "lorebook_entry".to_string(),
    };
    let retrieved_chunk = RetrievedChunk {
        score: 0.95, // High score to ensure it's picked up
        text: north_america_content.clone(),
        metadata: RetrievedMetadata::Lorebook(lorebook_chunk_metadata),
    };
    test_app.mock_embedding_pipeline_service.set_retrieve_response(Ok(vec![retrieved_chunk]));

    let response = auth_client
        .post(&format!(
            "{}/api/chat/{}/generate", // Changed "chats" to "chat"
            test_app.address, chat_session.id
        ))
        .header(ACCEPT, TEXT_EVENT_STREAM.as_ref()) // Request SSE stream
        .json(&generate_payload)
        .send()
        .await
        .expect("Failed to send generate chat request");

    let response_status = response.status();
    if response_status != StatusCode::OK {
        let error_body = response.text().await.unwrap_or_else(|_| "Could not read error body".to_string());
        panic!("Failed to generate chat response. Status: {:?}, Body: {:?}", response_status, error_body);
    }

    assert_eq!(
        response.headers().get(CONTENT_TYPE).map(|v| v.to_str().ok()).flatten(),
        Some(TEXT_EVENT_STREAM.as_ref()),
        "Content-Type should be text/event-stream"
    );
    
    // Consume and parse the SSE stream
    let mut stream = response.bytes_stream();
    let mut sse_events: Vec<ParsedSseEvent> = Vec::new();
    
    let mut current_event_name: Option<String> = None;
    let mut current_data_lines: Vec<String> = Vec::new();
    let mut buffer = String::new(); // Buffer for incomplete lines across chunks

    while let Some(item) = stream.next().await {
        let chunk = item.expect("Error while reading SSE stream chunk");
        buffer.push_str(&String::from_utf8(chunk.to_vec()).expect("Chunk not valid UTF-8"));

        // Process complete lines from buffer
        while let Some(newline_pos) = buffer.find('\n') {
            let line_with_ending = buffer.drain(..=newline_pos).collect::<String>();
            let line = line_with_ending.trim_end_matches(['\n', '\r']);

            if line.is_empty() { // End of an event
                if !current_data_lines.is_empty() {
                    sse_events.push(ParsedSseEvent {
                        event: current_event_name.clone(),
                        data: current_data_lines.join("\n"),
                    });
                    current_event_name = None;
                    current_data_lines.clear();
                }
            } else if line.starts_with("event:") {
                current_event_name = Some(line.trim_start_matches("event:").trim().to_string());
            } else if line.starts_with("data:") {
                let data_value = line.trim_start_matches("data:").trim_start_matches(' ');
                current_data_lines.push(data_value.to_string());
            } else if line.starts_with(':') {
                // Comment, ignore
            } // Other fields (id, retry) or malformed lines are ignored for this test
        }
    }

    // After stream ends, process any remaining buffered line
    if !buffer.is_empty() {
        let line = buffer.trim_end_matches(['\n', '\r']);
         if line.starts_with("data:") {
            let data_value = line.trim_start_matches("data:").trim_start_matches(' ');
            current_data_lines.push(data_value.to_string());
        }
    }

    // Process the last event if data was collected
    if !current_data_lines.is_empty() {
        sse_events.push(ParsedSseEvent {
            event: current_event_name.clone(),
            data: current_data_lines.join("\n"),
        });
    }

    // Assert that we received some events, ensuring the endpoint works for streaming.
    let has_content_event = sse_events.iter().any(|e| e.event.as_deref() == Some("content"));
    let has_done_event = sse_events.iter().any(|e| e.event.as_deref() == Some("done") && e.data == "[DONE]");

    assert!(has_content_event, "SSE stream should contain at least one 'content' event. Actual events: {:?}", sse_events);
    assert!(has_done_event, "SSE stream should contain a 'done' event with data '[DONE]'. Actual events: {:?}", sse_events);

    // 8. Assert the prompt content received by MockAiClient
    let last_ai_request = test_app
        .mock_ai_client // This is Option<Arc<MockAiClient>>
        .as_ref()
        .expect("Mock AI client not set in TestApp")
        .get_last_request() // This returns Option<genai::chat::ChatRequest>
        // .await // Removed .await as get_last_request in MockAiClient is synchronous.
               // The MockAiClient's get_last_request is synchronous.
               // However, the test was calling .await on get_last_generate_chat_request()
               // Let's assume the actual trait method might be async, so we keep await for now,
               // but the mock's get_last_request itself is not async.
               // The `genai::ChatClient::send_chat_request` is async.
               // The `MockAiClient::exec_chat` and `stream_chat` are async.
               // The `get_last_request` in `MockAiClient` is NOT async.
               // The test was calling `get_last_generate_chat_request().await` which implies the method it intended to call was async.
               // The `MockAiClient` in `test_helpers.rs` has `get_last_request()` which is sync.
               // The `genai::chat::ChatRequest` is what's stored.
               // Let's assume the test wants the `genai::chat::ChatRequest`.
        .expect("No chat generation request was made to the AI client");
    
    // The genai::chat::ChatRequest has `system_prompt: Option<String>` and `messages: Vec<genai::chat::ChatMessage>`
    // The user's message should be the last message in `last_ai_request.messages`
    let message_struct = last_ai_request
        .messages
        .last()
        .expect("No messages found in AI request");
    let last_message_content = match &message_struct.content { // message_struct.content is genai::chat::MessageContent
        genai::chat::MessageContent::Text(t) => t.as_str(),
        genai::chat::MessageContent::Parts(parts) => {
            parts.iter().find_map(|part| {
                if let genai::chat::ContentPart::Text(text_part) = part {
                    Some(text_part.as_str())
                } else {
                    None
                }
            }).expect("Last message content is not simple text or text part")
        },
        genai::chat::MessageContent::ToolCalls(_) | genai::chat::MessageContent::ToolResponses(_) => {
            panic!("Unexpected ToolCalls or ToolResponses in message content during RAG test")
        }
    };

    // Assertions for the prompt content:
    // a. User's message is present (as the last message content)
    assert!(
        last_message_content.contains(&user_message_content),
        "Last message content does not contain the user's message. Last Message: '{}'",
        last_message_content
    );


    // Assertions for the prompt content:
    // a. User's message is present
    // This assertion is now covered by checking last_message_content above.
    // We can remove this redundant check if last_message_content check is sufficient.
    // For clarity, let's ensure the user_message_content is exactly the last message.

    // Construct the expected full message content that includes RAG context
    let expected_ai_message_content = format!(
        "--- Relevant Context ---\n- Lorebook (Title: \"North America\"): {}\n\n\n\n{}", // Changed to four newlines
        north_america_content, // This is the content from the mock retrieval
        user_message_content   // This is the original user query
    );

    assert_eq!(
        last_message_content,
        expected_ai_message_content.as_str(),
        "The last message sent to AI does not match the expected RAG-augmented content. Last Message: '{}'",
        last_message_content
    );

    // b. Relevant text snippets from "North America" lorebook entry are present
    //    and correctly formatted.
    let expected_lorebook_title_text = "Title: \"North America\"";
    let expected_lorebook_content_snippet1 = "President Donald Trump's second administration has implemented significant policy shifts";
    let expected_lorebook_content_snippet2 = "Strategic Bitcoin Reserve, converting 5% of national gold reserves to cryptocurrency";
    let expected_lorebook_content_snippet3 = "Canada faces its own challenges under Prime Minister Pierre Poilievre's Conservative government.";
    let expected_lorebook_content_snippet4 = "Mexico under President Claudia Sheinbaum struggles with drug cartel violence";


    // Check for the lorebook entry title format in the system prompt (or wherever it's placed by PromptBuilder)
    // Based on current PromptBuilder, lorebook entries are typically part of the system prompt or context.
    // Let's assume they are part of the system prompt for now.
    // If they are part of the user message/history block, this assertion needs to move.
    assert!(
        last_message_content.contains(expected_lorebook_title_text),
        "Last message content does not contain the expected lorebook title text 'Title: \"North America\"'. Last Message: '{}'",
        last_message_content
    );
    
    // Check for content snippets within the last message content.
    assert!(
        last_message_content.contains(expected_lorebook_content_snippet1),
        "Last message content does not contain snippet 1 from North America entry. Last Message: '{}'",
        last_message_content
    );
    assert!(
        last_message_content.contains(expected_lorebook_content_snippet2),
        "Last message content does not contain snippet 2 from North America entry. Last Message: '{}'",
        last_message_content
    );
    assert!(
        last_message_content.contains(expected_lorebook_content_snippet3),
        "Last message content does not contain snippet 3 from North America entry. Last Message: '{}'",
        last_message_content
    );
    assert!(
        last_message_content.contains(expected_lorebook_content_snippet4),
        "Last message content does not contain snippet 4 from North America entry. Last Message: '{}'",
        last_message_content
    );

    // c. Check for the full lorebook entry format: [Lorebook: <Title>] <Content>
    // We'll look for the start of the North America entry.
    // c. Check that the full content of the "North America" lorebook entry is present.
    // The north_america_content variable is defined earlier (around line 307) when setting up the mock embedding response.
    // It's the `text` field of the `RetrievedChunk`.
    assert!(
        last_message_content.contains(&north_america_content),
        "Last message content does not contain the full content of the North America lorebook entry. Last Message: '{}'",
        last_message_content
    );

    // d. Chat history RAG (if applicable) - for the first message, this might be minimal or none.
    //    The `last_ai_request.messages` would contain previous turns if any.
    //    The user's message is asserted to be the last one.
    //    If there's a system prompt, last_ai_request.messages might have more than one entry.
    //    Example: [System Message (with char card, lorebook), User Message]
    //    We've already asserted the user message is the last one.
    //    No further specific assertions for chat history RAG in this first message test beyond what's in system prompt.

}