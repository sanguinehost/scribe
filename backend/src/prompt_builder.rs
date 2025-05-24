use crate::{
    errors::AppError,
    models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    },
    services::embedding_pipeline::RetrievedMetadata, // Added for matching
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
        let last_user = history
            .iter()
            .filter(|m| m.message_type == MessageRole::User)
            .last();
        let last_assistant = history
            .iter()
            .filter(|m| m.message_type == MessageRole::Assistant)
            .last();

        match (last_user, last_assistant) {
            (Some(user), Some(assistant)) => format!(
                "{}\n{}",
                String::from_utf8_lossy(&user.content),
                String::from_utf8_lossy(&assistant.content)
            ),
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
                    rag_context_section.push_str("---\nRelevant Context:\n"); // Changed header
                    for chunk in retrieved_chunks {
                        match chunk.metadata {
                            RetrievedMetadata::Chat(chat_meta) => {
                                rag_context_section.push_str(&format!(
                                    "- Chat (Score: {:.2}, Speaker: {}): {}\n",
                                    chunk.score,
                                    chat_meta.speaker,
                                    chunk.text.trim()
                                ));
                            }
                            RetrievedMetadata::Lorebook(lore_meta) => {
                                let title_str = lore_meta.entry_title.as_deref().unwrap_or("N/A");
                                let keywords_str = lore_meta.keywords.as_ref().map_or_else(
                                    || "N/A".to_string(),
                                    |kw| kw.join(", "),
                                );
                                rag_context_section.push_str(&format!(
                                    "- Lorebook (Score: {:.2}, Title: \"{}\", Keywords: [{}], Enabled: {}, Constant: {}): {}\n",
                                    chunk.score,
                                    title_str,
                                    keywords_str,
                                    lore_meta.is_enabled,
                                    lore_meta.is_constant,
                                    chunk.text.trim()
                                ));
                            }
                        }
                    }
                    rag_context_section.push_str("---\n\n");
                } else {
                    info!("No relevant context chunks found via RAG."); // Changed log
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
        if let Some(description_vec) = &char_data.description {
            // Renamed to description_vec to avoid conflict
            prompt.push_str(&format!(
                "Description: {}\n",
                String::from_utf8_lossy(description_vec)
            ));
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
        services::embedding_pipeline::{
            ChatMessageChunkMetadata, LorebookChunkMetadata, RetrievedChunk, RetrievedMetadata, // Added LorebookChunkMetadata
        },
        state::AppState,
        test_helpers::{MockEmbeddingPipelineService, PipelineCall},
    };
    use crate::services::lorebook_service::LorebookService;
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
        
        let encryption_service = Arc::new(crate::services::encryption_service::EncryptionService::new());
        let chat_override_service = Arc::new(crate::services::chat_override_service::ChatOverrideService::new(pool.clone(), encryption_service.clone()));
        let user_persona_service = Arc::new(crate::services::user_persona_service::UserPersonaService::new(pool.clone(), encryption_service.clone()));
        let token_counter_service = Arc::new(crate::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
            crate::services::tokenizer_service::TokenizerService::new(
                config.tokenizer_model_path.as_ref().expect("Tokenizer path is None").as_str()
            )
            .expect("Failed to create tokenizer for test")
        ));
        let lorebook_service = Arc::new(LorebookService::new(pool.clone(), encryption_service.clone()));


        // Create AppState with our mock service
        let app_state = Arc::new(AppState::new(
            pool,
            config,
            ai_client,
            embedding_client,
            qdrant_service,
            mock_embedding_service.clone(), // This is embedding_pipeline_service
            chat_override_service,
            user_persona_service,
            token_counter_service,
            encryption_service.clone(), // Added encryption service
            lorebook_service, // Added lorebook_service
        ));

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
        assert!(!prompt.contains("Relevant Context:")); // Updated header
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
                prompt_tokens: None,
                completion_tokens: None,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Hi there!".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
                prompt_tokens: None,
                completion_tokens: None,
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
        if let Some(PipelineCall::RetrieveRelevantChunks {
            query_text, limit, ..
        }) = calls.last()
        {
            assert_eq!(
                query_text, "Hello!\nHi there!",
                "Query text should combine last user and assistant messages"
            );
            assert_eq!(
                *limit, RAG_CHUNK_LIMIT,
                "RAG limit passed to service should match constant"
            );
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
            prompt_tokens: None,
            completion_tokens: None,
        }];

        let mock_chunks = vec![
            RetrievedChunk {
                score: 0.9,
                text: "Dogs are mammals.".to_string(),
                metadata: RetrievedMetadata::Chat(ChatMessageChunkMetadata {
                    message_id: Uuid::new_v4(),
                    session_id,
                    speaker: "ai".to_string(),
                    timestamp: Utc::now(),
                    text: "Dogs are mammals.".to_string(),
                }),
            },
            RetrievedChunk {
                score: 0.8,
                text: "They bark.".to_string(),
                metadata: RetrievedMetadata::Chat(ChatMessageChunkMetadata {
                    message_id: Uuid::new_v4(),
                    session_id,
                    speaker: "user".to_string(),
                    timestamp: Utc::now(),
                    text: "They bark.".to_string(),
                }),
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
            prompt.contains("Relevant Context:"), // Updated header
            "Prompt does not contain the RAG context header"
        );
        assert!(
            prompt.contains("- Chat (Score: 0.90, Speaker: ai): Dogs are mammals."), // Updated format
            "Prompt does not contain the first RAG chunk with new formatting"
        );
        assert!(
            prompt.contains("- Chat (Score: 0.80, Speaker: user): They bark."), // Updated format
            "Prompt does not contain the second RAG chunk with new formatting"
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
        if let Some(PipelineCall::RetrieveRelevantChunks {
            query_text, limit, ..
        }) = calls.last()
        {
            assert_eq!(
                query_text, "Tell me about dogs",
                "Query text should be the last user message when no assistant message exists"
            );
            assert_eq!(
                *limit, RAG_CHUNK_LIMIT,
                "RAG limit passed to service should match constant"
            );
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
            prompt_tokens: None,
            completion_tokens: None,
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
            !prompt.contains("Relevant Context:"), // Updated header
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
        if let Some(PipelineCall::RetrieveRelevantChunks {
            query_text, limit, ..
        }) = calls.last()
        {
            assert_eq!(
                query_text, "Query that causes error",
                "Query text should be the last user message when no assistant message exists"
            );
            assert_eq!(
                *limit, RAG_CHUNK_LIMIT,
                "RAG limit passed to service should match constant"
            );
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

        assert!(!prompt.contains("---\nRelevant Context:\n")); // Updated header

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
            description: None,       // No description
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
                prompt_tokens: None,
                completion_tokens: None,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::System, // System message
                content: "System instruction".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data (System messages might not have a real user_id, but the field is required)
                prompt_tokens: None,
                completion_tokens: None,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Assistant response".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
                prompt_tokens: None,
                completion_tokens: None,
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
        if let Some(PipelineCall::RetrieveRelevantChunks {
            query_text, limit, ..
        }) = calls.last()
        {
            assert_eq!(query_text, "User query\nAssistant response");
            assert_eq!(
                *limit, RAG_CHUNK_LIMIT,
                "RAG limit passed to service should match constant"
            );
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
                prompt_tokens: None,
                completion_tokens: None,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Bot reply".as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                user_id: Uuid::new_v4(), // Add dummy user_id for test data
                prompt_tokens: None,
                completion_tokens: None,
            },
        ];
        let mock_chunks = vec![RetrievedChunk {
            score: 0.75,
            text: "Relevant fact".to_string(),
            metadata: RetrievedMetadata::Chat(ChatMessageChunkMetadata {
                message_id: Uuid::new_v4(),
                session_id,
                speaker: "user".to_string(),
                timestamp: Utc::now(),
                text: "Relevant fact".to_string(),
            }),
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
        assert!(prompt.contains("Relevant Context:")); // Updated header
        assert!(prompt.contains("- Chat (Score: 0.75, Speaker: user): Relevant fact")); // Updated format

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
        if let Some(PipelineCall::RetrieveRelevantChunks {
            query_text, limit, ..
        }) = calls.last()
        {
            assert_eq!(query_text, "First user message\nBot reply");
            assert_eq!(
                *limit, RAG_CHUNK_LIMIT,
                "RAG limit passed to service should match constant"
            );
        } else {
            panic!("Expected RetrieveRelevantChunks call");
        }
    }

    #[tokio::test]
    async fn test_build_prompt_with_lorebook_rag_context() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let history = vec![ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Tell me about dragons".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id,
            prompt_tokens: None,
            completion_tokens: None,
        }];

        let mock_lore_chunks = vec![
            RetrievedChunk {
                score: 0.92,
                text: "Dragons breathe fire and hoard gold.".to_string(),
                metadata: RetrievedMetadata::Lorebook(LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(),
                    lorebook_id: Uuid::new_v4(),
                    user_id,
                    chunk_text: "Dragons breathe fire and hoard gold.".to_string(),
                    entry_title: Some("Dragon Facts".to_string()),
                    keywords: Some(vec!["dragon".to_string(), "mythology".to_string()]),
                    is_enabled: true,
                    is_constant: false,
                }),
            },
            RetrievedChunk {
                score: 0.85,
                text: "Some dragons are friendly.".to_string(),
                metadata: RetrievedMetadata::Lorebook(LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(),
                    lorebook_id: Uuid::new_v4(),
                    user_id,
                    chunk_text: "Some dragons are friendly.".to_string(),
                    entry_title: Some("Dragon Types".to_string()),
                    keywords: None,
                    is_enabled: true,
                    is_constant: true,
                }),
            },
        ];

        mock_rag.set_retrieve_response(Ok(mock_lore_chunks.clone()));

        let prompt = build_prompt_with_rag(state, session_id, None, &history)
            .await
            .unwrap();
        
        eprintln!("--- Prompt for test_build_prompt_with_lorebook_rag_context ---\n{}\n---", prompt);

        assert!(prompt.contains("Relevant Context:"), "Prompt missing RAG context header");
        assert!(
            prompt.contains("- Lorebook (Score: 0.92, Title: \"Dragon Facts\", Keywords: [dragon, mythology], Enabled: true, Constant: false): Dragons breathe fire and hoard gold."),
            "Prompt missing first lorebook chunk or has incorrect formatting"
        );
        assert!(
            prompt.contains("- Lorebook (Score: 0.85, Title: \"Dragon Types\", Keywords: [N/A], Enabled: true, Constant: true): Some dragons are friendly."),
            "Prompt missing second lorebook chunk or has incorrect formatting for None keywords"
        );
        assert!(prompt.contains("User: Tell me about dragons"), "Prompt missing user history");
    }
}
