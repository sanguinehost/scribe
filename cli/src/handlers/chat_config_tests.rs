#[cfg(test)]
mod tests {
    use super::super::chat_config::handle_chat_config_action;
    use crate::handlers::test_helpers::{
        mock_chat_session, mock_character_data_for_client, MockHttpClient, MockIoHandler,
    };
    use crate::client::types::StreamEvent;
    use scribe_backend::models::chats::{ChatSettingsResponse, UpdateChatSettingsRequest};
    use std::sync::Arc;
    use uuid::Uuid;
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_chat_config_action_success() {
        // 1. Setup test data
        let character_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let chat_sessions = vec![mock_chat_session(chat_id, character_id)];
        
        // 2. Setup mock response for chat settings update
        let temp_bd = BigDecimal::from_str("0.8").unwrap();
        let updated_settings = ChatSettingsResponse {
            system_prompt: Some("Updated system prompt".to_string()),
            temperature: Some(temp_bd),
            max_output_tokens: Some(1024),
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            seed: None,
            stop_sequences: None,
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            model_name: "custom-model".to_string(),
            gemini_thinking_budget: Some(2048),
            gemini_enable_code_execution: Some(true),
        };

        // 3. Setup HTTP client mock
        let mut client = MockHttpClient::default();
        client.list_chat_sessions_result = Some(Arc::new(Ok(chat_sessions)));
        client.update_chat_settings_result = Some(Arc::new(Ok(updated_settings.clone())));

        // 4. Setup IO handler mock with predefined user inputs
        let mut io_handler = MockIoHandler::new(vec![
            "1",                  // Select the first chat session
            "",                   // Keep current model
            "2048",               // Set thinking budget to 2048
            "true",               // Enable code execution
            "This is a test prompt", // Set system prompt
            "0.8",                // Set temperature to 0.8
        ]);

        // 5. Execute the function under test
        let result = handle_chat_config_action(&client, &mut io_handler, "default-model").await;

        // 6. Verify the result
        assert!(result.is_ok(), "Chat config action failed: {:?}", result.err());

        // 7. Verify expected outputs in IO handler
        io_handler.expect_output("Configure Chat Session Settings");
        io_handler.expect_output("Available chat sessions");
        io_handler.expect_output("Chat session settings updated successfully");
        io_handler.expect_output("Model:");
        io_handler.expect_output("Thinking Budget: 2048");
        io_handler.expect_output("Code Execution Enabled: true");
        io_handler.expect_output("Temperature: 0.80");
    }

    #[tokio::test]
    async fn test_chat_config_action_no_sessions() {
        // 1. Setup HTTP client mock with empty chat sessions list
        let mut client = MockHttpClient::default();
        client.list_chat_sessions_result = Some(Arc::new(Ok(vec![])));

        // 2. Setup IO handler mock
        let mut io_handler = MockIoHandler::new(vec![]);

        // 3. Execute the function under test
        let result = handle_chat_config_action(&client, &mut io_handler, "default-model").await;

        // 4. Verify the result
        assert!(result.is_ok(), "Chat config action failed: {:?}", result.err());

        // 5. Verify expected outputs in IO handler
        io_handler.expect_output("Configure Chat Session Settings");
        io_handler.expect_output("You have no chat sessions. Please create a chat session first.");
        io_handler.expect_no_output_containing("Available chat sessions");
    }

    #[tokio::test]
    async fn test_chat_config_action_invalid_input() {
        // 1. Setup test data
        let character_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let chat_sessions = vec![mock_chat_session(chat_id, character_id)];

        // 2. Setup HTTP client mock
        let mut client = MockHttpClient::default();
        client.list_chat_sessions_result = Some(Arc::new(Ok(chat_sessions)));

        // 3. Setup IO handler mock with invalid inputs
        let mut io_handler = MockIoHandler::new(vec![
            "invalid",  // Invalid selection
        ]);

        // 4. Execute the function under test
        let result = handle_chat_config_action(&client, &mut io_handler, "default-model").await;

        // 5. Verify the result
        assert!(result.is_ok(), "Chat config action failed: {:?}", result.err());

        // 6. Verify expected outputs in IO handler
        io_handler.expect_output("Configure Chat Session Settings");
        io_handler.expect_output("Available chat sessions");
        io_handler.expect_output("Invalid selection. Please try again.");
    }

    #[tokio::test]
    async fn test_chat_config_action_invalid_settings() {
        // 1. Setup test data
        let character_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let chat_sessions = vec![mock_chat_session(chat_id, character_id)];
        
        // 2. Setup mock response for chat settings update
        let temp_bd = BigDecimal::from_str("0.8").unwrap();
        let updated_settings = ChatSettingsResponse {
            system_prompt: Some("Updated system prompt".to_string()),
            temperature: Some(temp_bd),
            max_output_tokens: Some(1024),
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            seed: None,
            stop_sequences: None,
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            model_name: "custom-model".to_string(),
            gemini_thinking_budget: Some(2048),
            gemini_enable_code_execution: Some(true),
        };

        // 3. Setup HTTP client mock
        let mut client = MockHttpClient::default();
        client.list_chat_sessions_result = Some(Arc::new(Ok(chat_sessions)));
        client.update_chat_settings_result = Some(Arc::new(Ok(updated_settings.clone())));

        // 4. Setup IO handler mock with invalid setting values
        let mut io_handler = MockIoHandler::new(vec![
            "1",                 // Select the first chat session
            "",                  // Keep current model
            "not-a-number",      // Invalid thinking budget
            "maybe",             // Invalid code execution value
            "",                  // Skip system prompt
            "3.5",               // Invalid temperature (too high)
        ]);

        // 5. Execute the function under test
        let result = handle_chat_config_action(&client, &mut io_handler, "default-model").await;

        // 6. Verify the result
        assert!(result.is_ok(), "Chat config action failed: {:?}", result.err());

        // 7. Verify expected outputs in IO handler
        io_handler.expect_output("Invalid budget, skipping");
        io_handler.expect_output("Invalid input, skipping code execution setting");
        io_handler.expect_output("Invalid temperature, skipping");
        io_handler.expect_output("Chat session settings updated successfully");
    }
}