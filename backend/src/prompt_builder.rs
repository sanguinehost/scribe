use crate::{
    errors::AppError,
    models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    },
    state::AppState,
};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

const RAG_CHUNK_LIMIT: u64 = 7; // Increased from 3

/// Assembles the prompt for the LLM, incorporating RAG context.
pub async fn build_prompt_with_rag(
    state: Arc<AppState>,
    session_id: Uuid,
    character: Option<&CharacterMetadata>,
    history: &[ChatMessage],
) -> Result<String, AppError> {
    let mut prompt = String::new();
    let char_name = character.map(|c| c.name.as_str()).unwrap_or("Character");

    // --- RAG Context Retrieval ---
    let mut rag_context_section = String::new();
    // --- RAG Query Text Construction ---
    // Use the last user message and the last assistant message (if available) for better context
    let query_text = {
        let last_user = history.iter().filter(|m| m.message_type == MessageRole::User).last();
        let last_assistant = history.iter().filter(|m| m.message_type == MessageRole::Assistant).last();

        match (last_user, last_assistant) {
            (Some(user), Some(assistant)) => format!("{}\n{}", String::from_utf8_lossy(&user.content), String::from_utf8_lossy(&assistant.content)),
            (Some(user), None) => String::from_utf8_lossy(&user.content).into_owned(),
            (None, Some(assistant)) => String::from_utf8_lossy(&assistant.content).into_owned(), // Should ideally not happen in normal flow but handle defensively
            (None, None) => String::new(), // No messages to query with
        }
    };

    if !query_text.is_empty() {
        info!(%session_id, "Retrieving RAG context for prompt building using combined query");
        match state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(state.clone(), session_id, &query_text, RAG_CHUNK_LIMIT)
            .await
        {
            Ok(retrieved_chunks) => {
                if !retrieved_chunks.is_empty() {
                    info!(
                        count = retrieved_chunks.len(),
                        "Adding retrieved chunks to prompt context"
                    );
                    rag_context_section.push_str("---\nRelevant Historical Context:\n");
                    for chunk in retrieved_chunks {
                        rag_context_section.push_str(&format!(
                            "- (Score: {:.2}) {}\n",
                            chunk.score,
                            chunk.text.trim()
                        ));
                    }
                    rag_context_section.push_str("---\n\n");
                } else {
                    info!("No relevant historical chunks found via RAG.");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to retrieve RAG context, proceeding without it.");
            }
        }
    } else {
        info!("History is empty, skipping RAG context retrieval.");
    }

    // --- Character Details ---
    if let Some(char_data) = character {
        prompt.push_str(&format!("Character Name: {}\n", char_data.name));
        if let Some(description_vec) = &char_data.description { // Renamed to description_vec to avoid conflict
            prompt.push_str(&format!("Description: {}\n", String::from_utf8_lossy(description_vec)));
        }
        prompt.push_str("\n");
    }

    // --- RAG Context Insertion ---
    prompt.push_str(&rag_context_section);

    // --- Static Instruction ---
    prompt.push_str("---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");

    // --- History ---
    prompt.push_str("---\nHistory:\n");
    if history.is_empty() {
        prompt.push_str("(Start of conversation)\n");
    } else {
        for message in history {
            let prefix = match message.message_type {
                MessageRole::User => "User:",
                MessageRole::Assistant => "Assistant:",
                MessageRole::System => "System:",
            };
            // Convert content to String for trimming and formatting
            let content_str = String::from_utf8_lossy(&message.content);
            prompt.push_str(&format!("{} {}\n", prefix, content_str.trim()));
        }
    }
    prompt.push_str("---\n");

    // Final prompt for AI completion
    prompt.push_str(&format!("\n{}:", char_name));

    Ok(prompt)
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        models::characters::CharacterMetadata,
        models::chats::{ChatMessage, MessageRole},
        services::embedding_pipeline::{EmbeddingMetadata, RetrievedChunk},
        state::AppState,
        test_helpers::{MockEmbeddingPipelineService, PipelineCall},
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    // Helper to create a mock AppState for testing
    async fn mock_app_state() -> (Arc<AppState>, Arc<MockEmbeddingPipelineService>) {
        let mock_embedding_service = Arc::new(MockEmbeddingPipelineService::new());

        // Create a basic AppState with default values
        let pool = crate::test_helpers::db::setup_test_database(None).await;
        let config = Arc::new(crate::config::Config::default());
        let ai_client = Arc::new(crate::test_helpers::MockAiClient::new());
        let embedding_client = Arc::new(crate::test_helpers::MockEmbeddingClient::new());
        let qdrant_service =
            Arc::new(crate::vector_db::qdrant_client::QdrantClientService::new_test_dummy());

        // Create AppState with our mock service
        let app_state = Arc::new(AppState {
            pool,
            config,
            ai_client,
            embedding_client,
            qdrant_service,
            embedding_pipeline_service: mock_embedding_service.clone(),
            embedding_call_tracker: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        });

        (app_state, mock_embedding_service)
    }

    #[tokio::test]
    async fn test_build_prompt_empty_history_no_char_no_rag() {
        let (state, _mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![];

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();

        assert!(!prompt.contains("Character Name:"));
        assert!(!prompt.contains("Relevant Historical Context:"));
        assert!(prompt.contains("---\nHistory:\n(Start of conversation)\n---\n"));
        assert!(prompt.contains("\nCharacter:"));
    }

    #[tokio::test]
    async fn test_build_prompt_with_char_details() {
        let (state, _mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![];
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: Some("A friendly test bot.".as_bytes().to_vec()),
            description_nonce: None, // Added missing field
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: Some("Bot greeting".as_bytes().to_vec()),
        };

        let prompt = build_prompt_with_rag(state, session_id, Some(&char_meta), &history)
            .await
            .unwrap();

        assert!(prompt.contains("Character Name: Test Bot"));
        assert!(prompt.contains("Description: A friendly test bot."));
        assert!(prompt.contains("\nTest Bot:"));
    }

    #[tokio::test]
    async fn test_build_prompt_with_history() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::User,
                content: "Hello!".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Hi there!".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
        ];

        // Set a mock response for the retrieve_relevant_chunks call
        // The function uses the last message, which is from the Assistant with "Hi there!" content
        mock_rag.set_retrieve_response(Ok(vec![]));

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();

        // Print the prompt for debugging
        eprintln!(
            "--- Prompt for test_build_prompt_with_history ---\n{}
---",
            prompt
        );

        assert!(prompt.contains("---\nHistory:\n"));
        assert!(
            prompt.contains("User: Hello!"),
            "Prompt does not contain 'User: Hello!'"
        );
        assert!(
            prompt.contains("Assistant: Hi there!"),
            "Prompt does not contain 'Assistant: Hi there!'"
        );
        assert!(prompt.contains("---\n"));
        assert!(prompt.contains("\nCharacter:"));

        // Debug output for the calls
        let calls = mock_rag.get_calls();
        eprintln!("Number of calls to mock_rag: {}", calls.len());
        for (idx, call) in calls.iter().enumerate() {
            eprintln!("Call {}: {:?}", idx, call);
        }

        assert!(
            !calls.is_empty(),
            "Expected at least one call to retrieve_relevant_chunks"
        );

        // Verify the call parameters - now combines last user and assistant
        if let Some(PipelineCall::RetrieveRelevantChunks { query_text, limit, .. }) = calls.last() {
            assert_eq!(
                query_text, "Hello!\nHi there!",
                "Query text should combine last user and assistant messages"
            );
            assert_eq!(*limit, RAG_CHUNK_LIMIT, "RAG limit passed to service should match constant");
        }
    }

    #[tokio::test]
    async fn test_build_prompt_with_rag_context() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Tell me about dogs".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        }];

        let mock_chunks = vec![
            RetrievedChunk {
                score: 0.9,
                text: "Dogs are mammals.".to_string(),
                metadata: EmbeddingMetadata {
                    message_id: Uuid::new_v4(),
                    session_id,
                    speaker: "ai".to_string(),
                    timestamp: Utc::now(),
                    text: "Dogs are mammals.".to_string(),
                },
            },
            RetrievedChunk {
                score: 0.8,
                text: "They bark.".to_string(),
                metadata: EmbeddingMetadata {
                    message_id: Uuid::new_v4(),
                    session_id,
                    speaker: "user".to_string(),
                    timestamp: Utc::now(),
                    text: "They bark.".to_string(),
                },
            },
        ];

        // Setup the mock to return our predefined chunks
        mock_rag.set_retrieve_response(Ok(mock_chunks.clone()));

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();

        // Print the prompt for debugging
        eprintln!(
            "--- Prompt for test_build_prompt_with_rag_context ---\n{}
---",
            prompt
        );

        // Debug output for the calls
        let calls = mock_rag.get_calls();
        eprintln!("Number of calls to mock_rag: {}", calls.len());
        for (idx, call) in calls.iter().enumerate() {
            eprintln!("Call {}: {:?}", idx, call);
        }

        // Check for RAG content in the prompt - the exact format that's used in build_prompt_with_rag function
        assert!(
            prompt.contains("Relevant Historical Context:"),
            "Prompt does not contain the RAG context header"
        );
        assert!(
            prompt.contains("- (Score: 0.90) Dogs are mammals."),
            "Prompt does not contain the first RAG chunk"
        );
        assert!(
            prompt.contains("- (Score: 0.80) They bark."),
            "Prompt does not contain the second RAG chunk"
        );

        // Check other sections
        assert!(
            prompt.contains("---\nHistory:\n"),
            "Prompt does not contain the history section"
        );
        assert!(
            prompt.contains("User: Tell me about dogs"),
            "Prompt does not contain 'User: Tell me about dogs'"
        );
        assert!(
            prompt.contains("---\n"),
            "Prompt does not contain the history section end"
        );

        assert!(
            !calls.is_empty(),
            "Expected at least one call to retrieve_relevant_chunks"
        );

        // Verify the call parameters - only last user message exists
        if let Some(PipelineCall::RetrieveRelevantChunks { query_text, limit, .. }) = calls.last() {
            assert_eq!(
                query_text, "Tell me about dogs",
                "Query text should be the last user message when no assistant message exists"
            );
             assert_eq!(*limit, RAG_CHUNK_LIMIT, "RAG limit passed to service should match constant");
        } else {
            panic!("Expected RetrieveRelevantChunks call");
        }
    }

    #[tokio::test]
    async fn test_build_prompt_rag_retrieval_error() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Query that causes error".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        }];

        // Setup the mock to simulate a retrieval error
        mock_rag.set_retrieve_response(Err(AppError::InternalServerErrorGeneric(
            "Simulated RAG retrieval failure".to_string(),
        )));

        let prompt_result = build_prompt_with_rag(state, session_id, None, &history).await;

        assert!(
            prompt_result.is_ok(),
            "Expected Ok result even with RAG error"
        );
        let prompt = prompt_result.unwrap();

        // Print the prompt for debugging
        eprintln!(
            "--- Prompt for test_build_prompt_rag_retrieval_error ---\n{}
---",
            prompt
        );

        // Debug output for the calls
        let calls = mock_rag.get_calls();
        eprintln!("Number of calls to mock_rag: {}", calls.len());
        for (idx, call) in calls.iter().enumerate() {
            eprintln!("Call {}: {:?}", idx, call);
        }

        assert!(
            !prompt.contains("Relevant Historical Context:"),
            "Prompt contains RAG context section despite error"
        );

        assert!(
            prompt.contains("---\nHistory:\n"),
            "Prompt does not contain history section"
        );
        assert!(
            prompt.contains("User: Query that causes error"),
            "Prompt does not contain 'User: Query that causes error'"
        );
        assert!(
            prompt.contains("---\n"),
            "Prompt does not contain history section end"
        );

        assert!(
            !calls.is_empty(),
            "Expected at least one call to retrieve_relevant_chunks"
        );

        // Verify the call parameters - only last user message exists
        if let Some(PipelineCall::RetrieveRelevantChunks { query_text, limit, .. }) = calls.last() {
            assert_eq!(
                query_text, "Query that causes error",
                "Query text should be the last user message when no assistant message exists"
            );
             assert_eq!(*limit, RAG_CHUNK_LIMIT, "RAG limit passed to service should match constant");
        } else {
            panic!("Expected RetrieveRelevantChunks call");
        }
    }

    #[tokio::test]
    async fn test_build_prompt_no_rag_on_empty_history() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![];

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();

        assert!(!prompt.contains("---\nRelevant Historical Context:\n"));

        let calls = mock_rag.get_calls();
        assert!(calls.is_empty());
    }

    // --- NEW TESTS START HERE ---

    #[tokio::test]
    async fn test_build_prompt_char_without_description() {
        let (state, _mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![]; // Empty history, RAG won't be called
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Minimal Bot".to_string(),
            description: None, // No description
            description_nonce: None, // Added missing field
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: None,
        };

        let prompt = build_prompt_with_rag(state, session_id, Some(&char_meta), &history)
            .await
            .unwrap();

        assert!(prompt.contains("Character Name: Minimal Bot"));
        assert!(!prompt.contains("Description:")); // Ensure description line is absent
        assert!(prompt.contains("\nMinimal Bot:"));
    }

    #[tokio::test]
    async fn test_build_prompt_with_system_message_in_history() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::User,
                content: "User query".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::System, // System message
                content: "System instruction".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data (System messages might not have a real user_id, but the field is required)
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Assistant response".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
        ];

        // Mock RAG to return empty results based on the last message ("Assistant response")
        mock_rag.set_retrieve_response(Ok(vec![]));

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();

        assert!(prompt.contains("---\nHistory:\n"));
        assert!(prompt.contains("User: User query"));
        assert!(prompt.contains("System: System instruction")); // Check for system message
        assert!(prompt.contains("Assistant: Assistant response"));
        assert!(prompt.contains("---\n"));
        assert!(prompt.contains("\nCharacter:")); // Default character name

        // Verify RAG call - uses last user ("User query") and last assistant ("Assistant response")
        let calls = mock_rag.get_calls();
        assert!(!calls.is_empty());
        if let Some(PipelineCall::RetrieveRelevantChunks { query_text, limit, .. }) = calls.last() {
            assert_eq!(query_text, "User query\nAssistant response");
             assert_eq!(*limit, RAG_CHUNK_LIMIT, "RAG limit passed to service should match constant");
        } else {
            panic!("Expected RetrieveRelevantChunks call");
        }
    }

    #[tokio::test]
    async fn test_build_prompt_full_scenario_char_history_rag() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Mega Bot".to_string(),
            description: Some("The ultimate bot.".as_bytes().to_vec()),
            description_nonce: None, // Added missing field
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: Some("Mega greeting".as_bytes().to_vec()),
        };
        let history = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::User,
                content: "First user message".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Bot reply".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
            },
        ];
        let mock_chunks = vec![RetrievedChunk {
            score: 0.75,
            text: "Relevant fact".to_string(),
            metadata: EmbeddingMetadata {
                message_id: Uuid::new_v4(),
                session_id,
                speaker: "user".to_string(),
                timestamp: Utc::now(),
                text: "Relevant fact".to_string(),
            },
        }];

        // Mock RAG to return chunks based on the last message ("Bot reply")
        mock_rag.set_retrieve_response(Ok(mock_chunks.clone()));

        let prompt = build_prompt_with_rag(state, session_id, Some(&char_meta), &history)
            .await
            .unwrap();

        // Check Character Details
        assert!(prompt.contains("Character Name: Mega Bot"));
        assert!(prompt.contains("Description: The ultimate bot."));

        // Check RAG Context
        assert!(prompt.contains("Relevant Historical Context:"));
        assert!(prompt.contains("- (Score: 0.75) Relevant fact"));

        // Check History
        assert!(prompt.contains("---\nHistory:\n"));
        assert!(prompt.contains("User: First user message"));
        assert!(prompt.contains("Assistant: Bot reply"));
        assert!(prompt.contains("---\n"));

        // Check Final Line
        assert!(prompt.contains("\nMega Bot:"));

        // Verify RAG call - uses last user ("First user message") and last assistant ("Bot reply")
        let calls = mock_rag.get_calls();
        assert!(!calls.is_empty());
        if let Some(PipelineCall::RetrieveRelevantChunks { query_text, limit, .. }) = calls.last() {
            assert_eq!(query_text, "First user message\nBot reply");
             assert_eq!(*limit, RAG_CHUNK_LIMIT, "RAG limit passed to service should match constant");
        } else {
            panic!("Expected RetrieveRelevantChunks call");
        }
    }
}
