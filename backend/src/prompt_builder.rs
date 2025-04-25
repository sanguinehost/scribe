use crate::{
    errors::AppError,
    models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    },
    state::{AppState},
    test_helpers::{AppStateBuilder, MockEmbeddingPipelineService},
    services::embedding_pipeline::{RetrievedChunk, EmbeddingMetadata},
};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::Utc;

const RAG_CHUNK_LIMIT: u64 = 3;

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
    if let Some(last_message) = history.last() {
        let query_text = &last_message.content;
        info!(%session_id, "Retrieving RAG context for prompt building");
        match state.embedding_pipeline_service.retrieve_relevant_chunks(state.clone(), session_id, query_text, RAG_CHUNK_LIMIT).await {
            Ok(retrieved_chunks) => {
                if !retrieved_chunks.is_empty() {
                    info!(count = retrieved_chunks.len(), "Adding retrieved chunks to prompt context");
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
        if let Some(description) = &char_data.description {
            prompt.push_str(&format!("Description: {}\n", description));
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
            prompt.push_str(&format!("{} {}\n", prefix, message.content.trim()));
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
        state::{AppState},
        test_helpers::{AppStateBuilder, MockEmbeddingPipelineService},
        services::embedding_pipeline::{RetrievedChunk, EmbeddingMetadata},
        errors::AppError,
        models::chats::{ChatMessage, MessageRole},
        models::characters::CharacterMetadata,
    };
    use std::sync::Arc;
    use uuid::Uuid;
    use chrono::Utc;
    use std::collections::VecDeque;
    use tokio::sync::Mutex;

    // Helper to create a mock AppState for testing
    async fn mock_app_state() -> (Arc<AppState>, Arc<MockEmbeddingPipelineService>) {
        let mock_embedding_service = Arc::new(MockEmbeddingPipelineService::new());
        let state = AppStateBuilder::new()
            .with_embedding_pipeline_service(mock_embedding_service.clone())
            .build_for_test().await
            .expect("Failed to build mock AppState");
        (state, mock_embedding_service)
    }

    #[tokio::test]
    async fn test_build_prompt_empty_history_no_char_no_rag() {
        let (state, _mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![];

        let prompt = build_prompt_with_rag(state, session_id, None, &history).await.unwrap();

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
            description: Some("A friendly test bot.".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: Some("Bot greeting".to_string()),
        };

        let prompt = build_prompt_with_rag(state, session_id, Some(&char_meta), &history).await.unwrap();

        assert!(prompt.contains("Character Name: Test Bot"));
        assert!(prompt.contains("Description: A friendly test bot."));
        assert!(prompt.contains("\nTest Bot:"));
    }

    #[tokio::test]
    async fn test_build_prompt_with_history() {
        let (state, _mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::User,
                content: "Hello!".to_string(),
                created_at: Utc::now(),
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "Hi there!".to_string(),
                created_at: Utc::now(),
            },
        ];

        let prompt = build_prompt_with_rag(state, session_id, None, &history).await.unwrap();

        // Print the prompt for debugging
        eprintln!("--- Prompt for test_build_prompt_with_history ---\n{}
---", prompt);

        assert!(prompt.contains("---\nHistory:\n"));
        assert!(prompt.contains("User: Hello!"), "Prompt does not contain 'User: Hello!'");
        assert!(prompt.contains("Assistant: Hi there!"), "Prompt does not contain 'Assistant: Hi there!'");
        assert!(prompt.contains("---\n"));
        assert!(prompt.contains("\nCharacter:"));

        assert!(_mock_rag.get_last_query_text().is_some());
        assert_eq!(_mock_rag.get_last_query_text().unwrap(), "Hi there!");
    }

    #[tokio::test]
    async fn test_build_prompt_with_rag_context() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Tell me about dogs".to_string(),
            created_at: Utc::now(),
        }];

        let mock_chunks = vec![
            RetrievedChunk {
                score: 0.9,
                text: "Dogs are mammals.".to_string(),
                metadata: EmbeddingMetadata {
                    message_id: Uuid::new_v4(),
                    session_id, speaker: "ai".to_string(), timestamp: Utc::now(), text: "Dogs are mammals.".to_string()
                }
            },
            RetrievedChunk {
                score: 0.8,
                text: "They bark.".to_string(),
                metadata: EmbeddingMetadata {
                    message_id: Uuid::new_v4(),
                    session_id, speaker: "user".to_string(), timestamp: Utc::now(), text: "They bark.".to_string()
                }
            },
        ];
        mock_rag.set_response(Ok(mock_chunks));

        let prompt = build_prompt_with_rag(state, session_id, None, &history).await.unwrap();

        // Print the prompt for debugging
        eprintln!("--- Prompt for test_build_prompt_with_rag_context ---\n{}
---", prompt);

        assert!(prompt.contains("---\nRelevant Historical Context:\n"));
        assert!(prompt.contains("- (Score: 0.90) Dogs are mammals."));
        assert!(prompt.contains("- (Score: 0.80) They bark."));
        assert!(prompt.contains("---\n\n"));
        assert!(prompt.contains("---\nHistory:\n"));
        assert!(prompt.contains("User: Tell me about dogs"), "Prompt does not contain 'User: Tell me about dogs'");
        assert!(prompt.contains("---\n"));

        assert!(mock_rag.get_last_query_text().is_some());
        assert_eq!(mock_rag.get_last_query_text().unwrap(), "Tell me about dogs");
    }

    #[tokio::test]
    async fn test_build_prompt_rag_retrieval_error() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Query that causes error".to_string(),
            created_at: Utc::now(),
        }];

        mock_rag.set_response(Err(AppError::InternalServerError("RAG DB down".to_string())));

        let prompt_result = build_prompt_with_rag(state, session_id, None, &history).await;

        assert!(prompt_result.is_ok());
        let prompt = prompt_result.unwrap();

        // Print the prompt for debugging
        eprintln!("--- Prompt for test_build_prompt_rag_retrieval_error ---\n{}
---", prompt);

        assert!(!prompt.contains("---\nRelevant Historical Context:\n"));

        assert!(prompt.contains("---\nHistory:\n"));
        assert!(prompt.contains("User: Query that causes error"), "Prompt does not contain 'User: Query that causes error'");
        assert!(prompt.contains("---\n"));

        assert!(mock_rag.get_last_query_text().is_some());
        assert_eq!(mock_rag.get_last_query_text().unwrap(), "Query that causes error");
    }

    #[tokio::test]
    async fn test_build_prompt_no_rag_on_empty_history() {
        let (state, mock_rag) = mock_app_state().await;
        let session_id = Uuid::new_v4();
        let history = vec![];

        let prompt = build_prompt_with_rag(state, session_id, None, &history).await.unwrap();

        assert!(!prompt.contains("---\nRelevant Historical Context:\n"));

        assert!(mock_rag.get_last_query_text().is_none());
    }
}