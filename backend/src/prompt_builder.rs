use crate::{
    errors::AppError,
    models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    },
};

/// Assembles the prompt for the LLM based on character, session settings, and history.
pub fn build_prompt(
    character: Option<&CharacterMetadata>,
    history: &[ChatMessage],
) -> Result<String, AppError> {
    let mut prompt = String::new();
    let char_name = character.map(|c| c.name.as_str()).unwrap_or("Character");

    // Character details (if provided)
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

    // Static Instruction
    prompt.push_str("---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");

    // History
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