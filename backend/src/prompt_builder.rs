use crate::{
    errors::AppError,
    models::{
        character_card::Character,
        chat::{ChatMessage, ChatSession, MessageType},
    },
    schema,
};
use diesel::prelude::*;
use deadpool_diesel::postgres::Pool;
use uuid::Uuid;

const MAX_HISTORY_MESSAGES: usize = 20; // Limit the number of messages included in the prompt

/// Assembles the prompt for the LLM based on character, session settings, and history.
pub async fn assemble_prompt(
    pool: &Pool,
    session_id: Uuid,
    latest_user_message_content: &str, // The newest message not yet in history
) -> Result<String, AppError> {
    let conn = pool.get().await?;

    // Use interact to run DB queries off the Tokio thread pool
    let (maybe_session, history_result) = conn
        .interact(move |conn| {
            // 1. Get the session (don't fail here if not found yet)
            let maybe_session = schema::chat_sessions::table
                .find(session_id)
                .select(ChatSession::as_select())
                .first::<ChatSession>(conn)
                .optional()?;
            
            // If session exists, get history, otherwise return empty history
            let history = if let Some(session) = &maybe_session {
                 schema::chat_messages::table
                    .filter(schema::chat_messages::session_id.eq(session.id))
                    .order(schema::chat_messages::created_at.desc())
                    .limit(MAX_HISTORY_MESSAGES as i64) // Cast usize to i64 for limit
                    .select(ChatMessage::as_select())
                    .load::<ChatMessage>(conn)?
                    .into_iter()
                    .rev() // Reverse to get chronological order (oldest first)
                    .collect::<Vec<_>>()
            } else {
                Vec::new() // Return empty vec if session doesn't exist
            };

            // Return session option and history result separately
            Ok::<_, diesel::result::Error>((maybe_session, history))
        })
        .await
        .map_err(|e| AppError::InternalServerError(anyhow::anyhow!("DB interact error: {}", e)))??;

    // Now, check if the session was found. If not, return NotFound.
    let session = maybe_session
        .ok_or_else(|| AppError::NotFound(format!("Chat session {} not found", session_id)))?;
    let history = history_result; // Already Vec<ChatMessage>

    // Get character associated with the found session
    // This needs another DB call or a join in the first interact block
    // Let's add a separate call for simplicity for now
    let character = conn
        .interact(move |conn| {
             schema::characters::table
                .find(session.character_id)
                .select(Character::as_select())
                .first::<Character>(conn)
        })
        .await??; // Propagate interact error then Diesel error

    // --- Assemble the prompt string ---

    let mut prompt = String::new();

    // Character details (Using fields available in Character model)
    prompt.push_str(&format!("Character Name: {}\n", character.name));
     if let Some(description) = &character.description {
         prompt.push_str(&format!("Description: {}\n", description));
     }
     if let Some(personality) = &character.personality {
         prompt.push_str(&format!("Personality: {}\n", personality));
     }
     if let Some(scenario) = &character.scenario {
         prompt.push_str(&format!("Scenario: {}
", scenario));
     }
    // Add other relevant character fields if needed (e.g., example_dialogue)
    prompt.push_str("
");


    // System prompt (from session settings - Task 4.x)
    if let Some(system_prompt) = &session.system_prompt {
        if !system_prompt.trim().is_empty() {
            prompt.push_str(&format!("System Prompt: {}

", system_prompt));
        }
    }

    // Static Instruction (Using --- instead of ###)
    prompt.push_str("---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

");

    // History (Using --- instead of ###)
    prompt.push_str("---
History:
");
    if history.is_empty() && latest_user_message_content.trim().is_empty() {
         prompt.push_str("(Start of conversation)
");
    } else {
        for message in history {
            let prefix = match message.message_type {
                MessageType::User => "User",
                MessageType::Ai => {
                    // Use character.name directly (it's String)
                    &character.name
                }
            };
            // Ensure content is trimmed and formatted correctly
            prompt.push_str(&format!("{}: {}
", prefix, message.content.trim()));
        }
         // Add the latest user message that triggered this generation
         if !latest_user_message_content.trim().is_empty() {
            // Ensure content is trimmed
            prompt.push_str(&format!("User: {}
", latest_user_message_content.trim()));
         }
    }
    prompt.push_str("---
"); // End History section


    // Final prompt for AI completion
     // Use character.name directly (it's String)
     let char_name = &character.name;
     prompt.push_str(&format!("\n{}:", char_name)); // AI should start its response here


    Ok(prompt)
}

/*
// --- Unit Tests ---
// TODO: Move these tests to integration tests in tests/ directory
// They rely on helpers (TestDataGuard) and AppState which are integration test concerns.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{character_card::NewCharacter, chat::NewChatMessage},
        state::AppState, // For getting pool in integration-style test
        // This path is likely wrong for inline unit tests trying to access integration helpers
        // Use crate::tests::helpers would be needed if helpers were in src/tests/helpers.rs
        // But integration tests are typically in tests/ directory outside src/
        tests::helpers::{self, TestDataGuard}, // Assuming helpers exist
    };
    use bigdecimal::BigDecimal;
    use std::str::FromStr;


    // Helper to create necessary DB entries for a prompt assembly test
    async fn setup_test_data(app: &AppState) -> (Uuid, Uuid, Uuid, TestDataGuard) {
        // ... test setup code ...
    }


    #[tokio::test]
    async fn test_assemble_prompt_basic() {
        // ... test code ...
    }

    #[tokio::test]
    async fn test_assemble_prompt_no_history() {
        // ... test code ...
    }

     #[tokio::test]
    async fn test_assemble_prompt_no_system_prompt() {
        // ... test code ...
    }


    // TODO: Add test for MAX_HISTORY_MESSAGES limit
    // TODO: Add test for missing character fields (e.g., no persona)
    // TODO: Add test for session not found error
    // TODO: Add test for character not found error (if session exists but character doesn't - should be unlikely)


}
*/ 