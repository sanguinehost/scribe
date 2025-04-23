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

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        characters::CharacterMetadata,
        chats::{ChatMessage, MessageRole},
    };
    use chrono::Utc;
    use uuid::Uuid;

    fn create_dummy_character(name: &str, description: Option<&str>) -> CharacterMetadata {
        CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.map(String::from),
            first_mes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn create_dummy_message(role: MessageRole, content: &str) -> ChatMessage {
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: role,
            content: content.to_string(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_build_prompt_with_character_and_history() {
        let character = create_dummy_character("Alice", Some("A curious adventurer"));
        let history = vec![
            create_dummy_message(MessageRole::User, "Hello!"),
            create_dummy_message(MessageRole::Assistant, "Hi there!"),
        ];
        let prompt = build_prompt(Some(&character), &history).unwrap();

        let expected = "Character Name: Alice
Description: A curious adventurer

---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
User:: Hello!
Assistant:: Hi there!
---

Alice:";
        assert_eq!(prompt, expected);
    }

     #[test]
    fn test_build_prompt_with_character_no_description() {
        let character = create_dummy_character("Bob", None);
        let history = vec![
            create_dummy_message(MessageRole::User, "Testing"),
        ];
        let prompt = build_prompt(Some(&character), &history).unwrap();

        let expected = "Character Name: Bob

---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
User:: Testing
---

Bob:";
        assert_eq!(prompt, expected);
    }

    #[test]
    fn test_build_prompt_with_character_no_history() {
        let character = create_dummy_character("Charlie", Some("Likes testing"));
        let history = vec![];
        let prompt = build_prompt(Some(&character), &history).unwrap();

        let expected = "Character Name: Charlie
Description: Likes testing

---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
(Start of conversation)
---

Charlie:";
        assert_eq!(prompt, expected);
    }

    #[test]
    fn test_build_prompt_no_character_with_history() {
        let history = vec![
            create_dummy_message(MessageRole::User, "First message"),
            create_dummy_message(MessageRole::System, "System note"),
            create_dummy_message(MessageRole::Assistant, "AI response"),
        ];
        let prompt = build_prompt(None, &history).unwrap();

        let expected = "---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
User:: First message
System:: System note
Assistant:: AI response
---

Character:"; // Defaults to "Character"
        assert_eq!(prompt, expected);
    }

    #[test]
    fn test_build_prompt_no_character_no_history() {
        let history = vec![];
        let prompt = build_prompt(None, &history).unwrap();

        let expected = "---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
(Start of conversation)
---

Character:"; // Defaults to "Character"
        assert_eq!(prompt, expected);
    }

     #[test]
    fn test_build_prompt_history_trimming() {
        let character = create_dummy_character("Trimmer", None);
        let history = vec![
            create_dummy_message(MessageRole::User, "  Leading and trailing spaces  "),
        ];
        let prompt = build_prompt(Some(&character), &history).unwrap();

        let expected = "Character Name: Trimmer

---
Instruction:
Continue the chat based on the conversation history. Stay in character.
---

---
History:
User:: Leading and trailing spaces
---

Trimmer:"; // Check that content is trimmed
        assert_eq!(prompt, expected);
    }
} 