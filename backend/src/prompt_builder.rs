use crate::{
    errors::AppError,
    models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    },
    state::AppState, // Add AppState import
    // services::embedding_pipeline::RetrievedChunk, // Add RAG imports (only need the result struct)
};
use std::sync::Arc; // Add Arc import
use tracing::{info, warn}; // Add tracing
use uuid::Uuid; // Add Uuid import
 // Added import here

const RAG_CHUNK_LIMIT: u64 = 3; // Max number of chunks to retrieve

/// Assembles the prompt for the LLM, incorporating RAG context.
pub async fn build_prompt_with_rag( // Rename and make async
    state: Arc<AppState>,
    session_id: Uuid,
    character: Option<&CharacterMetadata>,
    history: &[ChatMessage], // History should include the latest user message for query
) -> Result<String, AppError> {
    let mut prompt = String::new();
    let char_name = character.map(|c| c.name.as_str()).unwrap_or("Character");

    // --- RAG Context Retrieval ---
    let mut rag_context_section = String::new(); // Keep this line from previous attempt
    if let Some(last_message) = history.last() {
        // Use the last message content as the query
        let query_text = &last_message.content;
        info!(%session_id, "Retrieving RAG context for prompt building");
        match state.embedding_pipeline_service.retrieve_relevant_chunks(state.clone(), session_id, query_text, RAG_CHUNK_LIMIT).await {
            Ok(retrieved_chunks) => {
                if !retrieved_chunks.is_empty() {
                    info!(count = retrieved_chunks.len(), "Adding retrieved chunks to prompt context");
                    rag_context_section.push_str("---\nRelevant Historical Context:\n");
                    for chunk in retrieved_chunks {
                        // Format the chunk nicely, maybe include score or metadata if useful
                        rag_context_section.push_str(&format!(
                            "- (Score: {:.2}) {}\n",
                            chunk.score,
                            chunk.text.trim() // Use the text from the retrieved chunk
                        ));
                    }
                     rag_context_section.push_str("---\n\n");
                } else {
                    info!("No relevant historical chunks found via RAG.");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to retrieve RAG context, proceeding without it.");
                // Don't fail the whole prompt build, just log the warning
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
        // Add other fields from CharacterMetadata if needed (persona, scenario, etc.)
        // Note: The current CharacterMetadata struct in models/characters.rs
        // only has id, user_id, name, description, created_at, updated_at.
        // It needs to be updated to include persona, scenario etc. if they are
        // required for the prompt.
        /*
        if let Some(personality) = &char_data.persona { // Assuming persona field exists
            prompt.push_str(&format!("Personality: {}\n", personality));
        }
        if let Some(scenario) = &char_data.world_scenario { // Assuming world_scenario field exists
            prompt.push_str(&format!("Scenario: {}\n", scenario));
        }
        */
        prompt.push_str("\n");
    }

    // --- RAG Context Insertion ---
    // Insert the retrieved context before the main history
    prompt.push_str(&rag_context_section);

    // --- Static Instruction ---
    prompt.push_str("---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");

    // --- History ---
    prompt.push_str("---\nHistory:\n");
    if history.is_empty() {
        prompt.push_str("(Start of conversation)\n");
    } else {
        for message in history {
            // Determine prefix based on the message role
            let prefix = match message.message_type { // Use message_type instead of role
                MessageRole::User => "User:",
                MessageRole::Assistant => "Assistant:",
                MessageRole::System => "System:", // Include system messages if present
            };
            prompt.push_str(&format!("{}: {}
", prefix, message.content.trim()));
        }
    }
    prompt.push_str("---\n"); // End History section

    // Final prompt for AI completion
    prompt.push_str(&format!("\n{}:", char_name));

    Ok(prompt)
}


// --- Unit Tests ---
// Note: Testing build_prompt_with_rag now requires mocking AppState and its dependencies (embedding, qdrant).
// This is more complex and might require dedicated test infrastructure or refactoring.
// The existing tests for the basic prompt structure are kept below but commented out
// as they target the old synchronous `build_prompt` function.
#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module
    use chrono::Utc; // Add Utc import for tests

    // Helper function to create a dummy chat message
    fn create_dummy_message(role: MessageRole, content: &str) -> ChatMessage {
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: role,
            content: content.to_string(),
            created_at: Utc::now(),
        }
    }
}