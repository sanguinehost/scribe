#[cfg(test)]
mod chat_override_tests {
    use scribe_cli::client::types::{
        ChatSessionDetails, ClientCharacterDataForClient, OverrideSuccessResponse,
    };
    use scribe_cli::handlers::chat_overrides::{
        handle_chat_edit_character_oneliner, handle_chat_edit_character_wizard,
    };
    use scribe_cli::test_helpers::{
        mock_character_data_for_client, MockCliError, MockHttpClient, MockIoHandler,
    };
    use scribe_cli::ChatEditCharacterArgs; // Ensure this is pub
    use std::sync::Arc;
    use chrono::Utc;
    use uuid::Uuid;

    fn default_chat_override_args(session_id: Uuid) -> ChatEditCharacterArgs {
        ChatEditCharacterArgs {
            session_id: Some(session_id),
            field: Some("description".to_string()),
            value: Some("Chat-specific description".to_string()),
            interactive: false,
        }
    }
    
    fn mock_chat_session_details(session_id: Uuid, character_id: Uuid) -> ChatSessionDetails {
        ChatSessionDetails {
            id: session_id,
            user_id: Uuid::new_v4(),
            character_id, // Original character_id for the session
            title: Some("Test Chat Session".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_handle_chat_edit_character_oneliner_success() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();

        let session_id = Uuid::new_v4();
        let field_name = "personality".to_string();
        let new_value = "A very inquisitive personality for this chat.".to_string();

        let mock_response = OverrideSuccessResponse {
            message: "Override applied".to_string(),
            session_id,
            field_name: field_name.clone(),
            new_value: new_value.clone(),
        };
        mock_http_client.set_chat_character_override_result = Some(Arc::new(Ok(mock_response)));

        let args = ChatEditCharacterArgs {
            session_id: Some(session_id),
            field: Some(field_name.clone()),
            value: Some(new_value.clone()),
            interactive: false,
        };

        let result =
            handle_chat_edit_character_oneliner(&mock_http_client, &mut mock_io_handler, args)
                .await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("Setting chat character override from command line arguments...");
        mock_io_handler.expect_output(&format!(
            "Successfully applied override for field '{}' in chat session {}.",
            field_name, session_id
        ));
        mock_io_handler.expect_output(&format!("  New value: {}", new_value));
    }

    #[tokio::test]
    async fn test_handle_chat_edit_character_oneliner_missing_session_id() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mock_http_client = MockHttpClient::new();

        let args = ChatEditCharacterArgs {
            session_id: None, // Missing
            field: Some("description".to_string()),
            value: Some("test value".to_string()),
            interactive: false,
        };
        let result =
            handle_chat_edit_character_oneliner(&mock_http_client, &mut mock_io_handler, args)
                .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Missing --session-id argument"));
        }
    }

    #[tokio::test]
    async fn test_handle_chat_edit_character_wizard_success() {
        let session_id = Uuid::new_v4();
        let original_character_id = Uuid::new_v4();
        let field_to_edit = "description".to_string();
        let new_value = "Wizard new description for chat".to_string();

        let inputs = vec![
            session_id.to_string(),      // Session ID
            "1".to_string(),             // Field to edit (1 for description)
            new_value.clone(),           // New value
            "Y".to_string(),                         // Confirm override? Yes
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let mock_session_details = mock_chat_session_details(session_id, original_character_id);
        mock_http_client.get_chat_session_result = Some(Arc::new(Ok(mock_session_details)));

        let mock_effective_char = mock_character_data_for_client(original_character_id, "Original Char", Some("Original Desc"));
        mock_http_client.get_effective_character_for_chat_result = Some(Arc::new(Ok(mock_effective_char.clone())));
        
        let mock_override_response = OverrideSuccessResponse {
            message: "Override set!".to_string(),
            session_id,
            field_name: field_to_edit.clone(),
            new_value: new_value.clone(),
        };
        mock_http_client.set_chat_character_override_result = Some(Arc::new(Ok(mock_override_response)));

        let result =
            handle_chat_edit_character_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("\n--- Edit Character Overrides for Chat Session (Wizard) ---");
        mock_io_handler.expect_output("Enter Chat Session ID (UUID):");
        mock_io_handler.expect_output(&format!("Fetching effective character data for session {} (Original Character ID: {})...", session_id, original_character_id));
        mock_io_handler.expect_output("\n--- Current Effective Character Details (with overrides) ---");
        // The following line was asserting against a string that included the character_id and session_id,
        // but the handler output for the character details itself doesn't include that directly in the "Name:" line.
        // The details are printed after "--- Current Effective Character Details (with overrides) ---"
        // We will check for the name and other fields individually as they are printed by the handler.
        mock_io_handler.expect_output(&format!("  Name: {}", mock_effective_char.name));
        mock_io_handler.expect_output("Enter field number to override:");
        mock_io_handler.expect_output(&format!("Current value for '{}': {}", field_to_edit, mock_effective_char.description.as_deref().unwrap_or("N/A")));
        mock_io_handler.expect_output(&format!("Enter new value for '{}' (leave blank to clear override, if supported by backend):", field_to_edit));
        mock_io_handler.expect_output(&format!("\nApply override for '{}' to '{}'? (Y/n)", field_to_edit, new_value));
        mock_io_handler.expect_output(&format!("Successfully applied override for field '{}' in chat session {}.", field_to_edit, session_id));
        mock_io_handler.expect_output(&format!("  New value: {}", new_value));
    }
    
    #[tokio::test]
    async fn test_handle_chat_edit_character_wizard_cancel_submission() {
        let session_id = Uuid::new_v4();
        let original_character_id = Uuid::new_v4();
        let inputs = vec![
            session_id.to_string(),
            "1".to_string(), // Field to edit (1 for description)
            "A value that won't be submitted".to_string(),
            "n".to_string(), // Confirm override? No
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let mock_session_details = mock_chat_session_details(session_id, original_character_id);
        mock_http_client.get_chat_session_result = Some(Arc::new(Ok(mock_session_details)));
        let mock_effective_char = mock_character_data_for_client(original_character_id, "Original", Some("Desc"));
        mock_http_client.get_effective_character_for_chat_result = Some(Arc::new(Ok(mock_effective_char)));
        // set_chat_character_override_result should not be called

        let result =
            handle_chat_edit_character_wizard(&mock_http_client, &mut mock_io_handler).await;
        
        assert!(result.is_ok());
        mock_io_handler.expect_output("Override cancelled.");
        mock_io_handler.expect_no_output_containing("applied successfully");
    }

    #[tokio::test]
    async fn test_handle_chat_edit_character_oneliner_client_error() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();
        let session_id = Uuid::new_v4();

        mock_http_client.set_chat_character_override_result = Some(Arc::new(Err(
            MockCliError::ApiError("Failed to set override on server".to_string()),
        )));

        let args = default_chat_override_args(session_id);
        let result =
            handle_chat_edit_character_oneliner(&mock_http_client, &mut mock_io_handler, args)
                .await;

        assert!(result.is_err());
        mock_io_handler.expect_output("Setting chat character override from command line arguments...");
        mock_io_handler.expect_output("Error setting chat character override: API returned an error: status=500 Internal Server Error, message=Failed to set override on server");
    }
}