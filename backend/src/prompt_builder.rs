use crate::{
    errors::AppError,
    models::characters::CharacterMetadata,
};

/// Assembles the character-specific part of the system prompt.
/// RAG context is handled by the calling service and prepended to the user message.
pub fn build_prompt_with_rag( // Renaming to build_system_prompt_character_info might be clearer later
    character: Option<&CharacterMetadata>,
) -> Result<String, AppError> { // No longer async, no AppState needed

    let mut prompt = String::new();

    if let Some(char_data) = character {
        if let Some(description_vec) = &char_data.description {
            if !description_vec.is_empty() {
                prompt.push_str(&format!("Character Name: {}\n", char_data.name));
                prompt.push_str(&format!(
                    "Description: {}\n",
                    String::from_utf8_lossy(description_vec)
                ));
                prompt.push_str("\n");
                // Only add static instruction if there's a character description
                prompt.push_str("---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");
            } else {
                // No description, return empty string (no character persona to instruct on)
                return Ok(String::new());
            }
        } else {
            // No description, return empty string
            return Ok(String::new());
        }
    } else {
        // No character, return empty string
        return Ok(String::new());
    }

    Ok(prompt)
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::characters::CharacterMetadata;
    use chrono::Utc;
    use uuid::Uuid;

    const EXPECTED_STATIC_INSTRUCTION: &str = "---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n";

    #[test]
    fn test_build_prompt_no_character() {
        let prompt = build_prompt_with_rag(None).unwrap();
        assert!(prompt.is_empty(), "Expected empty prompt when no character is provided, got: {}", prompt);
    }

    #[test]
    fn test_build_prompt_character_with_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: Some("A friendly test bot.".as_bytes().to_vec()),
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: Some("Bot greeting".as_bytes().to_vec()),
        };

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();

        assert!(prompt.contains("Character Name: Test Bot"), "Prompt missing character name. Got: '{}'", prompt);
        assert!(prompt.contains("Description: A friendly test bot."), "Prompt missing character description. Got: '{}'", prompt);
        assert!(prompt.contains(EXPECTED_STATIC_INSTRUCTION), "Prompt missing static instruction. Got: '{}'", prompt);
        assert!(!prompt.contains("Relevant Context:"), "Prompt should not contain RAG context. Got: '{}'", prompt);
        assert!(!prompt.contains("---\nHistory:\n"), "Prompt should not contain History. Got: '{}'", prompt);
    }

    #[test]
    fn test_build_prompt_character_no_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Minimal Bot".to_string(),
            description: None, // No description
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();
        
        assert!(prompt.is_empty(), "Expected empty prompt for char without description, got: {}", prompt);
    }

    #[test]
    fn test_build_prompt_character_empty_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Silent Bot".to_string(),
            description: Some("".as_bytes().to_vec()), // Empty description
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();
        
        assert!(prompt.is_empty(), "Expected empty prompt for char with empty description, got: {}", prompt);
    }

    // The following original tests are now largely redundant due to the simplification
    // of build_prompt_with_rag. They are removed as their core assertions (RAG, history)
    // are no longer applicable to this function. The essential cases (no char, char with desc,
    // char without desc) are covered by the tests above.
    //
    // - test_build_prompt_empty_history_no_char_no_rag -> covered by test_build_prompt_no_character
    // - test_build_prompt_with_char_details -> covered by test_build_prompt_character_with_description
    // - test_build_prompt_with_history -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_with_rag_context -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_rag_retrieval_error -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_no_rag_on_empty_history -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_char_without_description -> covered by test_build_prompt_character_no_description
    // - test_build_prompt_with_system_message_in_history -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_full_scenario_char_history_rag -> now like test_build_prompt_character_with_description
    // - test_build_prompt_with_lorebook_rag_context -> logic moved out, now like test_build_prompt_no_character
    // - test_build_prompt_with_active_lorebooks_in_rag_call -> logic moved out, now like test_build_prompt_no_character
}
