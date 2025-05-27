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
use scribe_backend::vector_db::qdrant_client::DEFAULT_COLLECTION_NAME; // For Qdrant collection name
use qdrant_client::qdrant::PointId as QdrantPointId; // For Qdrant PointId
use tokio::time::{timeout as tokio_timeout, Instant}; // For polling with timeout
use qdrant_client::qdrant::{Filter, Condition, FieldCondition, Match, r#match::MatchValue, value::Kind as ValueKind, condition::ConditionOneOf}; // For Qdrant filtering
 

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
    sleep(Duration::from_millis(1000)).await;
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
        lorebook_ids: None,
        active_custom_persona_id: None,
        // model_name, settings, active_impersonated_character_id
        // are not part of CreateChatRequest. Assuming the API changed or these are set elsewhere/defaulted.
    };

    let response = auth_client
        .post(&format!("{}/api/chats/create_session", test_app.address))
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
    test_app.mock_embedding_pipeline_service.set_retrieve_responses_sequence(vec![
        Ok(vec![retrieved_chunk.clone()]), // Response for lorebook RAG
        Ok(vec![]),                       // Response for chat history RAG (empty)
    ]);

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
    let mock_keywords_vec = vec![
        "North America".to_string(), "USA".to_string(), "United States".to_string(),
        "Canada".to_string(), "Mexico".to_string(), "America".to_string(),
        "NAFTA".to_string(), "USMCA".to_string()
    ];
    let mock_keywords_str = mock_keywords_vec.join(", ");

    let expected_ai_message_content = format!(
        "---\nRelevant Context:\n- Lorebook (North America - {}): {}\n---\n\n{}",
        mock_keywords_str,
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
    //    The title format is now "TITLE - KEYWORDS"
    let expected_lorebook_title_text = format!("Lorebook (North America - {})", mock_keywords_str);
    let expected_lorebook_content_snippet1 = "President Donald Trump's second administration has implemented significant policy shifts";
    let expected_lorebook_content_snippet2 = "Strategic Bitcoin Reserve, converting 5% of national gold reserves to cryptocurrency";
    let expected_lorebook_content_snippet3 = "Canada faces its own challenges under Prime Minister Pierre Poilievre's Conservative government.";
    let expected_lorebook_content_snippet4 = "Mexico under President Claudia Sheinbaum struggles with drug cartel violence";


    // Check for the lorebook entry title format in the system prompt (or wherever it's placed by PromptBuilder)
    // Based on current PromptBuilder, lorebook entries are typically part of the system prompt or context.
    // Let's assume they are part of the system prompt for now.
    // If they are part of the user message/history block, this assertion needs to move.
    assert!(
        last_message_content.contains(&expected_lorebook_title_text),
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
#[tokio::test]
async fn test_associate_lorebook_triggers_initial_embedding() {
    // 1. Setup
    let test_app = spawn_app(true, false, true).await; // mock AI, real Qdrant, mock Embedding
    let _test_data_guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_credentials = ("assoc_embed_user@example.com", "Password123!");
    let user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let (auth_client, _token) =
        scribe_backend::test_helpers::login_user_via_api(&test_app, user_credentials.0, user_credentials.1)
            .await;

    // Create Lorebook
    let lorebook_payload = CreateLorebookPayload {
        name: "Initial Embedding Test Lorebook".to_string(),
        description: Some("For testing initial embedding on association.".to_string()),
    };
    let lorebook_response = auth_client
        .post(&format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to send create lorebook request");
    assert_eq!(lorebook_response.status(), StatusCode::CREATED);
    let created_lorebook: LorebookResponse = lorebook_response
        .json()
        .await
        .expect("Failed to parse create lorebook response");
    let lorebook_id = created_lorebook.id;

    // Create Lorebook Entries
    let entry1_payload = CreateLorebookEntryPayload {
        entry_title: "Enabled Entry 1".to_string(),
        keys_text: Some("enabled,first".to_string()),
        content: "Content for enabled entry 1.".to_string(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(false),
        insertion_order: Some(10),
        placement_hint: None,
    };
    let entry1_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, lorebook_id))
        .json(&entry1_payload)
        .send().await.expect("Failed to create entry 1");
    assert_eq!(entry1_response.status(), StatusCode::CREATED);
    let entry1: serde_json::Value = entry1_response.json().await.expect("Failed to parse entry 1 response");
    let entry1_id = Uuid::parse_str(entry1["id"].as_str().unwrap()).unwrap();

    let entry2_payload = CreateLorebookEntryPayload {
        entry_title: "Disabled Entry 2".to_string(),
        keys_text: Some("disabled,second".to_string()),
        content: "Content for disabled entry 2.".to_string(),
        comment: None,
        is_enabled: Some(false), // Explicitly disabled
        is_constant: Some(false),
        insertion_order: Some(20),
        placement_hint: None,
    };
    let entry2_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, lorebook_id))
        .json(&entry2_payload)
        .send().await.expect("Failed to create entry 2");
    assert_eq!(entry2_response.status(), StatusCode::CREATED);
    
    let entry3_payload = CreateLorebookEntryPayload {
        entry_title: "Enabled Entry 3".to_string(),
        keys_text: Some("enabled,third".to_string()),
        content: "Content for enabled entry 3, another one.".to_string(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(true),
        insertion_order: Some(30),
        placement_hint: Some("before_prompt".to_string()),
    };
    let entry3_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, lorebook_id))
        .json(&entry3_payload)
        .send().await.expect("Failed to create entry 3");
    assert_eq!(entry3_response.status(), StatusCode::CREATED);
    let entry3: serde_json::Value = entry3_response.json().await.expect("Failed to parse entry 3 response");
    let entry3_id = Uuid::parse_str(entry3["id"].as_str().unwrap()).unwrap();

    // Clear any embedding calls from entry creation
    test_app.mock_embedding_pipeline_service.clear_calls();
    assert_eq!(test_app.mock_embedding_pipeline_service.get_calls().len(), 0, "Embedding calls should be cleared before association.");


    // Create Chat Session
    let test_character = scribe_backend::test_helpers::db::create_test_character(&test_app.db_pool, user_data.id, "AssocChar".to_string()).await.expect("Failed to create test character for association test");

    let chat_session_payload = CreateChatRequest {
        title: "Chat for Lorebook Association Test".to_string(),
        character_id: test_character.id,
        lorebook_ids: None,
        active_custom_persona_id: None,
    };
    let chat_response = auth_client
        .post(&format!("{}/api/chats/create_session", test_app.address))
        .json(&chat_session_payload)
        .send().await.expect("Failed to create chat session");
    assert_eq!(chat_response.status(), StatusCode::CREATED);
    let chat_session: ChatSessionResponseDto = chat_response.json().await.expect("Failed to parse chat session response");


    // 2. Action: Associate lorebook with chat session
    let associate_payload = AssociateLorebookToChatPayload { lorebook_id };
    let assoc_response = auth_client
        .post(&format!("{}/api/chats/{}/lorebooks", test_app.address, chat_session.id))
        .json(&associate_payload)
        .send().await.expect("Failed to associate lorebook");
    
    assert_eq!(assoc_response.status(), StatusCode::OK, "Failed to associate lorebook. Body: {:?}", assoc_response.text().await);

    // Give a moment for async embedding tasks
    sleep(Duration::from_millis(1000)).await; // Increased delay

    // 3. Assertions
    let embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
    assert_eq!(embedding_calls.len(), 2, "Expected 2 embedding calls for the two enabled entries. Got: {:?}", embedding_calls);

    // Verify details for entry1
    let call_for_entry1 = embedding_calls.iter().find_map(|call| {
        if let scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { original_lorebook_entry_id, .. } = call {
            if *original_lorebook_entry_id == entry1_id { Some(call) } else { None }
        } else { None }
    });
    assert!(call_for_entry1.is_some(), "No embedding call found for enabled entry 1 (ID: {})", entry1_id);
    if let Some(scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { lorebook_id: call_lorebook_id, user_id: call_user_id, decrypted_content, decrypted_title, decrypted_keywords, is_enabled, is_constant, .. }) = call_for_entry1 {
        assert_eq!(*call_lorebook_id, lorebook_id);
        assert_eq!(*call_user_id, user_data.id);
        assert_eq!(*decrypted_content, entry1_payload.content);
        assert_eq!(*decrypted_title, Some(entry1_payload.entry_title.clone()));
        assert_eq!(*decrypted_keywords, Some(vec!["enabled".to_string(), "first".to_string()]));
        assert_eq!(*is_enabled, entry1_payload.is_enabled.unwrap());
        assert_eq!(*is_constant, entry1_payload.is_constant.unwrap());
    }
    
    // Verify details for entry3
    let call_for_entry3 = embedding_calls.iter().find_map(|call| {
        if let scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { original_lorebook_entry_id, .. } = call {
            if *original_lorebook_entry_id == entry3_id { Some(call) } else { None }
        } else { None }
    });
    assert!(call_for_entry3.is_some(), "No embedding call found for enabled entry 3 (ID: {})", entry3_id);
    if let Some(scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { lorebook_id: call_lorebook_id, user_id: call_user_id, decrypted_content, decrypted_title, decrypted_keywords, is_enabled, is_constant, .. }) = call_for_entry3 {
        assert_eq!(*call_lorebook_id, lorebook_id);
        assert_eq!(*call_user_id, user_data.id);
        assert_eq!(*decrypted_content, entry3_payload.content);
        assert_eq!(*decrypted_title, Some(entry3_payload.entry_title.clone()));
        assert_eq!(*decrypted_keywords, Some(vec!["enabled".to_string(), "third".to_string()]));
        assert_eq!(*is_enabled, entry3_payload.is_enabled.unwrap());
        assert_eq!(*is_constant, entry3_payload.is_constant.unwrap());
    }
}


#[tokio::test]
async fn test_update_lorebook_entry_triggers_re_embedding() {
    // 1. Setup
    let test_app = spawn_app(true, false, true).await; // mock AI, real Qdrant, mock Embedding
    let _test_data_guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_credentials = ("update_embed_user@example.com", "Password123!");
    let user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let (auth_client, _token) =
        scribe_backend::test_helpers::login_user_via_api(&test_app, user_credentials.0, user_credentials.1)
            .await;

    // Create Lorebook
    let lorebook_payload = CreateLorebookPayload {
        name: "Re-embedding Test Lorebook".to_string(),
        description: Some("For testing re-embedding on entry update.".to_string()),
    };
    let lorebook_response = auth_client
        .post(&format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to send create lorebook request");
    assert_eq!(lorebook_response.status(), StatusCode::CREATED);
    let created_lorebook: LorebookResponse = lorebook_response
        .json()
        .await
        .expect("Failed to parse create lorebook response");
    let lorebook_id = created_lorebook.id;

    // Create Initial Lorebook Entry
    let initial_entry_payload = CreateLorebookEntryPayload {
        entry_title: "Initial Entry Title".to_string(),
        keys_text: Some("initial,test".to_string()),
        content: "Initial content for re-embedding test.".to_string(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(false),
        insertion_order: Some(10),
        placement_hint: None,
    };
    let entry_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, lorebook_id))
        .json(&initial_entry_payload)
        .send().await.expect("Failed to create initial entry");
    assert_eq!(entry_response.status(), StatusCode::CREATED);
    let created_entry: serde_json::Value = entry_response.json().await.expect("Failed to parse entry response");
    let entry_id = Uuid::parse_str(created_entry["id"].as_str().unwrap()).unwrap();

    // Clear initial embedding calls
    test_app.mock_embedding_pipeline_service.clear_calls();
    assert_eq!(test_app.mock_embedding_pipeline_service.get_calls().len(), 0, "Embedding calls should be cleared before update.");

    // 2. Action: Update the lorebook entry
    let update_payload = scribe_backend::models::lorebook_dtos::UpdateLorebookEntryPayload {
        entry_title: Some("Updated Entry Title".to_string()),
        keys_text: Some("updated,re_embed".to_string()),
        content: Some("Updated content that should trigger re-embedding.".to_string()),
        comment: Some("Updated comment.".to_string()),
        is_enabled: Some(true), // Keep it enabled
        is_constant: Some(true), // Change constant status
        insertion_order: Some(20),
        placement_hint: Some("after_prompt".to_string()),
    };

    let update_response = auth_client
        .put(&format!("{}/api/lorebooks/{}/entries/{}", test_app.address, lorebook_id, entry_id))
        .json(&update_payload)
        .send().await.expect("Failed to send update entry request");
    
    assert_eq!(update_response.status(), StatusCode::OK, "Failed to update entry. Body: {:?}", update_response.text().await);

    // Give a moment for async embedding task
    sleep(Duration::from_millis(1000)).await;

    // 3. Assertions
    let embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
    assert_eq!(embedding_calls.len(), 1, "Expected 1 embedding call after update. Got: {:?}", embedding_calls);

    if let Some(scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { original_lorebook_entry_id, lorebook_id: call_lorebook_id, user_id: call_user_id, decrypted_content, decrypted_title, decrypted_keywords, is_enabled, is_constant, .. }) = embedding_calls.first() {
        assert_eq!(*original_lorebook_entry_id, entry_id);
        assert_eq!(*call_lorebook_id, lorebook_id);
        assert_eq!(*call_user_id, user_data.id);
        assert_eq!(*decrypted_content, update_payload.content.as_ref().unwrap().as_str());
        assert_eq!(*decrypted_title, update_payload.entry_title.clone());
        assert_eq!(*decrypted_keywords, Some(vec!["updated".to_string(), "re_embed".to_string()]));
        assert_eq!(*is_enabled, update_payload.is_enabled.unwrap());
        assert_eq!(*is_constant, update_payload.is_constant.unwrap());
    } else {
        panic!("Expected ProcessAndEmbedLorebookEntry call, got: {:?}", embedding_calls.first());
    }

    // Test disabling an entry
    test_app.mock_embedding_pipeline_service.clear_calls();
    let disable_payload = scribe_backend::models::lorebook_dtos::UpdateLorebookEntryPayload {
        entry_title: None, keys_text: None, content: None, comment: None,
        is_enabled: Some(false), // Disable the entry
        is_constant: None, insertion_order: None, placement_hint: None,
    };
    let disable_response = auth_client
        .put(&format!("{}/api/lorebooks/{}/entries/{}", test_app.address, lorebook_id, entry_id))
        .json(&disable_payload)
        .send().await.expect("Failed to send disable entry request");
    assert_eq!(disable_response.status(), StatusCode::OK);
    sleep(Duration::from_millis(200)).await;

    let embedding_calls_after_disable = test_app.mock_embedding_pipeline_service.get_calls();
    assert_eq!(embedding_calls_after_disable.len(), 1, "Expected 1 embedding call after disabling. Got: {:?}", embedding_calls_after_disable);
    if let Some(scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { original_lorebook_entry_id, is_enabled, decrypted_content, decrypted_title, .. }) = embedding_calls_after_disable.first() {
        assert_eq!(*original_lorebook_entry_id, entry_id);
        assert_eq!(*is_enabled, false, "Entry should be marked as disabled in embedding call.");
        // Content, title, keywords should still be the "updated" ones from previous step as they weren't changed in this payload
        assert_eq!(*decrypted_content, update_payload.content.as_ref().unwrap().as_str());
        assert_eq!(*decrypted_title, update_payload.entry_title.clone());
    } else {
        panic!("Expected ProcessAndEmbedLorebookEntry call after disable, got: {:?}", embedding_calls_after_disable.first());
    }
}

#[tokio::test]
#[ignore = "This test requires real Gemini API key and Qdrant service"]
async fn test_rag_retrieves_lorebook_entry_after_embedding_completion() -> anyhow::Result<()> {
    // 1. Test setup: Spawn app with REAL embedding pipeline and REAL Qdrant, MOCK AI
    let test_app = scribe_backend::test_helpers::spawn_app_with_options(false, false, true, true).await; // Use mock AI, real Qdrant, real embedding pipeline
    let _test_data_guard = TestDataGuard::new(test_app.db_pool.clone()); // Handles DB/Qdrant cleanup

    let user_credentials = ("china_rag_user@example.com", "PasswordChina123!");
    let user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create test user for China RAG test");

    let (auth_client, _user_token_str) =
        scribe_backend::test_helpers::login_user_via_api(&test_app, user_credentials.0, user_credentials.1)
            .await;

    // Create a character
    let character = scribe_backend::test_helpers::db::create_test_character(
        &test_app.db_pool,
        user_data.id,
        "ChinaRAGChar".to_string(),
    )
    .await
    .expect("Failed to create character for China RAG test");

    // Create a lorebook
    let lorebook_payload = CreateLorebookPayload {
        name: "China Test Lorebook".to_string(),
        description: Some("Lorebook for testing China keyword RAG.".to_string()),
    };
    let response = auth_client
        .post(&format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to send create lorebook request");
    assert_eq!(response.status(), StatusCode::CREATED, "Failed to create lorebook. Body: {:?}", response.text().await);
    let created_lorebook: LorebookResponse = response
        .json()
        .await
        .expect("Failed to parse create lorebook response");

    // Create the specific "China" lorebook entry
    let china_entry_title = "About China".to_string();
    let china_entry_keywords = "China".to_string();
    let china_entry_content = "An entry about the country China and its rich culture, including the Great Wall.".to_string();
    let china_entry_payload = CreateLorebookEntryPayload {
        entry_title: china_entry_title.clone(),
        keys_text: Some(china_entry_keywords.clone()),
        content: china_entry_content.clone(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(false),
        insertion_order: Some(1),
        placement_hint: None,
    };

    let entry_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, created_lorebook.id))
        .json(&china_entry_payload)
        .send()
        .await
        .expect("Failed to send create China lorebook entry request");
    assert_eq!(entry_response.status(), StatusCode::CREATED, "Failed to create China lorebook entry. Body: {:?}", entry_response.text().await);
    let created_china_entry: serde_json::Value = entry_response
        .json()
        .await
        .expect("Failed to parse create China lorebook entry response");
    let china_entry_id = Uuid::parse_str(
        created_china_entry["id"].as_str().expect("China entry ID not found in response")
    ).expect("Failed to parse China entry ID as UUID");

    // NOTE: Lorebook entries are only embedded when the lorebook is associated with a chat session

    // Create a chat session
    let chat_session_payload = CreateChatRequest {
        title: "China RAG Test Session".to_string(),
        character_id: character.id,
        lorebook_ids: None,
        active_custom_persona_id: None,
    };
    let chat_response = auth_client
        .post(&format!("{}/api/chats/create_session", test_app.address))
        .json(&chat_session_payload)
        .send()
        .await
        .expect("Failed to send create chat session request");
    assert_eq!(chat_response.status(), StatusCode::CREATED, "Failed to create chat session. Body: {:?}", chat_response.text().await);
    let chat_session: ChatSessionResponseDto = chat_response
        .json()
        .await
        .expect("Failed to parse create chat session response");

    // Associate the lorebook with the chat session
    let associate_payload = AssociateLorebookToChatPayload {
        lorebook_id: created_lorebook.id,
    };
    let assoc_response = auth_client
        .post(&format!("{}/api/chats/{}/lorebooks", test_app.address, chat_session.id))
        .json(&associate_payload)
        .send()
        .await
        .expect("Failed to send associate lorebook request");
    assert_eq!(assoc_response.status(), StatusCode::OK, "Failed to associate lorebook. Body: {:?}", assoc_response.text().await);

    // Give the background embedding task time to start after association
    sleep(Duration::from_secs(2)).await;

    // Ensure embedding completion by polling Qdrant
    // The embedding pipeline creates new UUIDs for each chunk, so we need to search by filter instead
    let polling_timeout_duration = Duration::from_secs(30); // Increased timeout to 30 seconds
    let polling_interval = Duration::from_millis(500); // Increased interval to 500ms
    let start_time = Instant::now();
    let mut point_found_in_qdrant = false;

    println!("Polling Qdrant for lorebook entry with ID: {}", china_entry_id);

    // Create a filter to find points with the lorebook entry ID
    let filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "original_lorebook_entry_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(china_entry_id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
        ],
        ..Default::default()
    };

    while Instant::now().duration_since(start_time) < polling_timeout_duration {
        match test_app.qdrant_service.retrieve_points(Some(filter.clone()), 10).await {
            Ok(points) => {
                if !points.is_empty() {
                    println!("Found {} points in Qdrant for lorebook entry {}", points.len(), china_entry_id);
                    point_found_in_qdrant = true;
                    break;
                } else {
                    println!("No points found in Qdrant for lorebook entry {} yet, retrying...", china_entry_id);
                }
            }
            Err(e) => {
                // Error during polling, could be transient or collection not ready
                println!("Error polling Qdrant for lorebook entry {}: {:?}. Retrying...", china_entry_id, e);
            }
        }
        sleep(polling_interval).await;
    }

    assert!(point_found_in_qdrant, "Timeout waiting for lorebook entry {} to be embedded in Qdrant.", china_entry_id);
    println!("Lorebook entry {} confirmed in Qdrant.", china_entry_id);
    
    // Configure MockAiClient for the chat generation
    let mock_ai_response_content = "AI acknowledges China query.";
    if let Some(mock_ai) = &test_app.mock_ai_client {
        mock_ai.set_stream_response(vec![
            Ok(ChatStreamEvent::Chunk(StreamChunk {
                content: mock_ai_response_content.to_string(),
            })),
            Ok(ChatStreamEvent::End(Default::default())),
        ]);
    } else {
        panic!("Mock AI client not found in test_app for China RAG test.");
    }
    
    // Send a user message to trigger RAG
    let user_query = "Tell me about China.".to_string();
    let generate_payload = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: user_query.clone(),
        }],
        model: None,
        query_text_for_rag: Some(user_query.clone()), // Explicitly set query text for RAG
    };

    let generate_response = auth_client
        .post(&format!("{}/api/chat/{}/generate", test_app.address, chat_session.id))
        .header(ACCEPT, TEXT_EVENT_STREAM.as_ref())
        .header("X-Scribe-Enable-RAG", "true") // Ensure RAG is enabled
        .json(&generate_payload)
        .send()
        .await
        .expect("Failed to send generate chat request for China RAG test");

    let response_status = generate_response.status();
    if response_status != StatusCode::OK {
        let error_body = generate_response.text().await.unwrap_or_else(|_| "Could not read error body".to_string());
        panic!("Generate chat request failed. Status: {:?}, Body: {:?}", response_status, error_body);
    }
    
    // Consume stream to allow background tasks to complete (like saving messages)
    let mut stream = generate_response.bytes_stream();
    while let Some(item) = stream.next().await {
        item.expect("Error reading stream chunk");
    }

    // Assertions on the prompt sent to MockAiClient
    let last_ai_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client not set")
        .get_last_request()
        .expect("No chat generation request was made to the AI client");

    let last_message_to_ai = last_ai_request
        .messages
        .last()
        .expect("No messages found in AI request");
    
    let last_message_content_str = match &last_message_to_ai.content {
        GenAiMessageContent::Text(t) => t.clone(),
        GenAiMessageContent::Parts(parts) => {
            parts.iter().find_map(|part| {
                if let genai::chat::ContentPart::Text(text_part) = part {
                    Some(text_part.clone())
                } else {
                    None
                }
            }).expect("Last message content is not simple text or text part")
        },
        _ => panic!("Unexpected message content type in AI request"),
    };

    let expected_rag_snippet = format!(
        "- Lorebook ({} - {}): {}",
        china_entry_title,
        china_entry_keywords, // Assuming keys_text becomes the keywords string directly
        china_entry_content
    );

    assert!(
        last_message_content_str.contains(&expected_rag_snippet),
        "Last message to AI does not contain the expected RAG snippet for China. Expected snippet: '{}'. Got: '{}'",
        expected_rag_snippet,
        last_message_content_str
    );

    assert!(
        last_message_content_str.contains(&user_query),
        "Last message to AI does not contain the original user query. Got: '{}'",
        last_message_content_str
    );
    
    // Check for RAG context headers
    assert!(
        last_message_content_str.contains("---\nRelevant Context:\n"),
        "RAG context header missing. Got: '{}'",
        last_message_content_str
    );
    assert!(
        last_message_content_str.contains("\n---\n\n"), // End of RAG context before user query
        "RAG context footer missing. Got: '{}'",
        last_message_content_str
    );

    println!("Successfully verified RAG context for China entry in AI prompt.");

    Ok(())
}

#[tokio::test]
async fn test_rag_retrieves_lorebook_entry_with_mocks() -> anyhow::Result<()> {
    // Test setup: Spawn app with MOCK embedding pipeline, MOCK Qdrant, MOCK AI
    let test_app = spawn_app(false, false, false).await;
    let _test_data_guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_credentials = ("rag_mock_user@example.com", "PasswordRAG123!");
    let user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create test user for RAG mock test");

    let (auth_client, _user_token_str) =
        scribe_backend::test_helpers::login_user_via_api(&test_app, user_credentials.0, user_credentials.1)
            .await;

    // Create a character
    let character = scribe_backend::test_helpers::db::create_test_character(
        &test_app.db_pool,
        user_data.id,
        "RAGMockChar".to_string(),
    )
    .await
    .expect("Failed to create character for RAG mock test");

    // Create a lorebook
    let lorebook_payload = CreateLorebookPayload {
        name: "China Test Lorebook Mock".to_string(),
        description: Some("Lorebook for testing China keyword RAG with mocks.".to_string()),
    };
    let response = auth_client
        .post(&format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to send create lorebook request");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_lorebook: LorebookResponse = response
        .json()
        .await
        .expect("Failed to parse create lorebook response");

    // Create the specific "China" lorebook entry
    let china_entry_title = "About China".to_string();
    let china_entry_keywords = "China".to_string();
    let china_entry_content = "An entry about the country China and its rich culture, including the Great Wall.".to_string();
    let china_entry_payload = CreateLorebookEntryPayload {
        entry_title: china_entry_title.clone(),
        keys_text: Some(china_entry_keywords.clone()),
        content: china_entry_content.clone(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(false),
        insertion_order: Some(1),
        placement_hint: None,
    };

    let entry_response = auth_client
        .post(&format!("{}/api/lorebooks/{}/entries", test_app.address, created_lorebook.id))
        .json(&china_entry_payload)
        .send()
        .await
        .expect("Failed to send create China lorebook entry request");
    assert_eq!(entry_response.status(), StatusCode::CREATED);
    let created_china_entry: serde_json::Value = entry_response
        .json()
        .await
        .expect("Failed to parse create China lorebook entry response");
    let china_entry_id = Uuid::parse_str(
        created_china_entry["id"].as_str().expect("China entry ID not found in response")
    ).expect("Failed to parse China entry ID as UUID");

    // Create a chat session
    let chat_session_payload = CreateChatRequest {
        title: "China RAG Test Session Mock".to_string(),
        character_id: character.id,
        lorebook_ids: None,
        active_custom_persona_id: None,
    };
    let chat_response = auth_client
        .post(&format!("{}/api/chats/create_session", test_app.address))
        .json(&chat_session_payload)
        .send()
        .await
        .expect("Failed to send create chat session request");
    assert_eq!(chat_response.status(), StatusCode::CREATED);
    let chat_session: ChatSessionResponseDto = chat_response
        .json()
        .await
        .expect("Failed to parse create chat session response");

    // Associate the lorebook with the chat session
    let associate_payload = AssociateLorebookToChatPayload {
        lorebook_id: created_lorebook.id,
    };
    let assoc_response = auth_client
        .post(&format!("{}/api/chats/{}/lorebooks", test_app.address, chat_session.id))
        .json(&associate_payload)
        .send()
        .await
        .expect("Failed to send associate lorebook request");
    assert_eq!(assoc_response.status(), StatusCode::OK);

    // Give the background embedding task time to complete
    sleep(Duration::from_millis(500)).await;

    // Verify that the embedding pipeline was called for the lorebook entry
    let embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
    let embed_call_found = embedding_calls.iter().any(|call| {
        if let scribe_backend::test_helpers::PipelineCall::ProcessAndEmbedLorebookEntry { 
            original_lorebook_entry_id, 
            decrypted_content, 
            decrypted_keywords, 
            .. 
        } = call {
            *original_lorebook_entry_id == china_entry_id &&
            decrypted_content.contains("China") &&
            decrypted_keywords.as_ref().map_or(false, |k| k.contains(&"China".to_string()))
        } else {
            false
        }
    });
    assert!(embed_call_found, "No embedding call found for China lorebook entry");

    // Configure the mock embedding pipeline to return the China lorebook entry when searched
    let china_chunk = RetrievedChunk {
        score: 0.95,
        text: china_entry_content.clone(),
        metadata: RetrievedMetadata::Lorebook(LorebookChunkMetadata {
            original_lorebook_entry_id: china_entry_id,
            lorebook_id: created_lorebook.id,
            user_id: user_data.id,
            chunk_text: china_entry_content.clone(),
            entry_title: Some(china_entry_title.clone()),
            keywords: Some(vec!["China".to_string()]),
            is_enabled: true,
            is_constant: false,
            source_type: "lorebook_entry".to_string(),
        }),
    };
    // The service calls retrieve_relevant_chunks twice: once for lorebooks, once for chat history
    test_app.mock_embedding_pipeline_service.add_retrieve_response(Ok(vec![china_chunk.clone()])); // For lorebook search
    test_app.mock_embedding_pipeline_service.add_retrieve_response(Ok(vec![])); // For chat history search (empty)
    
    // Configure MockAiClient for the chat generation
    let mock_ai_response_content = "Based on the lorebook, China has a rich culture including the Great Wall.";
    if let Some(mock_ai) = &test_app.mock_ai_client {
        mock_ai.set_stream_response(vec![
            Ok(ChatStreamEvent::Chunk(StreamChunk {
                content: mock_ai_response_content.to_string(),
            })),
            Ok(ChatStreamEvent::End(Default::default())),
        ]);
    } else {
        panic!("Mock AI client not found in test_app for China RAG test.");
    }
    
    // Send a user message to trigger RAG
    let user_query = "Tell me about China.".to_string();
    let generate_payload = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: user_query.clone(),
        }],
        model: None,
        query_text_for_rag: Some(user_query.clone()),
    };

    let generate_response = auth_client
        .post(&format!("{}/api/chat/{}/generate", test_app.address, chat_session.id))
        .header(ACCEPT, TEXT_EVENT_STREAM.as_ref())
        .header("X-Scribe-Enable-RAG", "true")
        .json(&generate_payload)
        .send()
        .await
        .expect("Failed to send generate chat request for China RAG test");

    assert_eq!(generate_response.status(), StatusCode::OK);
    
    // Consume stream to allow background tasks to complete
    let mut stream = generate_response.bytes_stream();
    while let Some(item) = stream.next().await {
        item.expect("Error reading stream chunk");
    }

    // Verify that retrieve_relevant_chunks was called
    let retrieve_calls = test_app.mock_embedding_pipeline_service.get_calls();
    let retrieve_call_found = retrieve_calls.iter().any(|call| {
        if let scribe_backend::test_helpers::PipelineCall::RetrieveRelevantChunks { 
            query_text, 
            active_lorebook_ids_for_search,
            .. 
        } = call {
            query_text.contains("China") &&
            active_lorebook_ids_for_search.as_ref().map_or(false, |ids| ids.contains(&created_lorebook.id))
        } else {
            false
        }
    });
    assert!(retrieve_call_found, "No retrieve_relevant_chunks call found for China query");

    // Verify that the AI was called with the lorebook context
    let last_ai_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client not set")
        .get_last_request()
        .expect("No AI request was made");

    // Check that the prompt includes the lorebook content
    let prompt_contains_china_info = last_ai_request.messages.iter().any(|msg| {
        match &msg.content {
            GenAiMessageContent::Text(text) => {
                text.contains("China") && text.contains("Great Wall")
            }
            GenAiMessageContent::Parts(parts) => {
                parts.iter().any(|part| {
                    match part {
                        genai::chat::ContentPart::Text(text) => {
                            text.contains("China") && text.contains("Great Wall")
                        }
                        _ => false
                    }
                })
            }
            _ => false // Handle ToolCalls and ToolResponses
        }
    });
    assert!(prompt_contains_china_info, 
            "AI prompt should contain China lorebook information. Messages: {:?}", 
            last_ai_request.messages);

    Ok(())
}