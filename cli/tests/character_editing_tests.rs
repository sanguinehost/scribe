#[cfg(test)]
mod character_editing_tests {
    use scribe_cli::handlers::characters::{
        handle_character_edit_oneliner, handle_character_edit_wizard,
    };
    use scribe_cli::test_helpers::{mock_character_data_for_client, MockCliError, MockHttpClient, MockIoHandler};
    use scribe_cli::CharacterEditArgs; // Ensure this is pub
    use std::sync::Arc;
    use uuid::Uuid;

    fn default_edit_args(id: Uuid) -> CharacterEditArgs {
        CharacterEditArgs {
            id: Some(id),
            name: Some("Updated Name".to_string()),
            description: Some("Updated description.".to_string()),
            first_mes: Some("Updated hello!".to_string()),
            personality: Some("Updated Testy".to_string()),
            scenario: Some("An updated test scenario".to_string()),
            system_prompt: Some("Updated system prompt".to_string()),
            interactive: false,
        }
    }

    #[tokio::test]
    async fn test_handle_character_edit_oneliner_success() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();

        let char_id = Uuid::new_v4();
        let updated_char_name = "Updated Character OneLiner";
        let mock_updated_char = mock_character_data_for_client(char_id, updated_char_name, Some("Updated Desc"));
        
        mock_http_client.update_character_result =
            Some(Arc::new(Ok(mock_updated_char.clone())));

        let args = CharacterEditArgs {
            id: Some(char_id),
            name: Some(updated_char_name.to_string()),
            description: Some("Updated OneLiner description".to_string()),
            interactive: false,
            ..default_edit_args(char_id) // Fill others or use Default
        };

        let result =
            handle_character_edit_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("Updating character from command line arguments...");
        mock_io_handler.expect_output(&format!(
            "Character '{}' (ID: {}) updated successfully.",
            updated_char_name, char_id
        ));
    }

    #[tokio::test]
    async fn test_handle_character_edit_oneliner_missing_id_error() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mock_http_client = MockHttpClient::new(); // No call expected

        let args = CharacterEditArgs {
            id: None, // Missing ID
            name: Some("No ID Update".to_string()),
            interactive: false,
            ..default_edit_args(Uuid::nil()) // Uuid::nil() as placeholder
        };

        let result =
            handle_character_edit_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Missing --id argument"));
        }
    }
    
    #[tokio::test]
    async fn test_handle_character_edit_oneliner_no_fields_to_update() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mock_http_client = MockHttpClient::new(); // No call expected

        let char_id = Uuid::new_v4();
        let args = CharacterEditArgs {
            id: Some(char_id),
            name: None,
            description: None,
            first_mes: None,
            personality: None,
            scenario: None,
            system_prompt: None,
            interactive: false,
        };

        let result =
            handle_character_edit_oneliner(&mock_http_client, &mut mock_io_handler, args).await;
        
        assert!(result.is_ok()); // Handler returns Ok(()) in this case
        mock_io_handler.expect_output("No fields provided to update.");
    }


    #[tokio::test]
    async fn test_handle_character_edit_wizard_success() {
        let char_id = Uuid::new_v4();
        let inputs = vec![
            char_id.to_string(),    // Character ID to edit
            "y".to_string(),                    // Edit Name? Yes
            "Wizard Updated Name".to_string(),  // New Name
            "y".to_string(),                    // Edit Description? Yes
            "Wizard Updated Desc".to_string(),  // New Description
            "n".to_string(),                    // Edit Personality? No
            "n".to_string(),                    // Edit Scenario? No
            "n".to_string(),                    // Edit First Message? No
            "n".to_string(),                    // Edit System Prompt? No
            "n".to_string(),                    // Edit Creator Notes? No
            "n".to_string(),                    // Edit Tags? No
            "Y".to_string(),                    // Submit changes? Yes
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let original_char = mock_character_data_for_client(char_id, "Original Wizard", Some("Original Desc"));
        mock_http_client.get_character_result = Some(Arc::new(Ok(original_char.clone())));

        let updated_response_char = mock_character_data_for_client(char_id, "Wizard Updated Name", Some("Wizard Updated Desc"));
        mock_http_client.update_character_result = Some(Arc::new(Ok(updated_response_char.clone())));

        let result = handle_character_edit_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("--- Edit Existing Character (Wizard) ---");
        mock_io_handler.expect_output("Enter Character ID (UUID) to edit:");
        mock_io_handler.expect_output("Fetching current character data...");
        mock_io_handler.expect_output("--- Current Character Details ---");
        mock_io_handler.expect_output(&format!("  Name: {}", original_char.name));
        mock_io_handler.expect_output("Edit Name ('Original Wizard')? (y/N)");
        mock_io_handler.expect_output("New Name:");
        mock_io_handler.expect_output("Edit Description ('Original Desc')? (y/N)");
        mock_io_handler.expect_output("New Description (leave blank to keep current, type 'none' to clear):");
        mock_io_handler.expect_output("--- Review Changes ---");
        mock_io_handler.expect_output("  - Name: 'Original Wizard' -> 'Wizard Updated Name'");
        mock_io_handler.expect_output("  - Description: 'Original Desc' -> 'Wizard Updated Desc'");
        mock_io_handler.expect_output("Submit these changes? (Y/n)");
        mock_io_handler.expect_output(&format!(
            "Character '{}' (ID: {}) updated successfully.",
            "Wizard Updated Name", char_id
        ));
    }

    #[tokio::test]
    async fn test_handle_character_edit_wizard_cancel_submission() {
        let char_id = Uuid::new_v4();
        let inputs = vec![
            char_id.to_string(),    // Character ID
            "y".to_string(),                    // Edit Name? Yes
            "Wizard Cancel Edit".to_string(),   // New Name
            "n".to_string(),                    // Edit Description? No
            "n".to_string(),                    // Edit Personality? No
            "n".to_string(),                    // Edit Scenario? No
            "n".to_string(),                    // Edit First Message? No
            "n".to_string(),                    // Edit System Prompt? No
            "n".to_string(),                    // Edit Creator Notes? No
            "n".to_string(),                    // Edit Tags? No
            "n".to_string(),                    // Submit changes? No
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let original_char = mock_character_data_for_client(char_id, "Original", Some("Desc"));
        mock_http_client.get_character_result = Some(Arc::new(Ok(original_char)));
        // update_character_result should not be called

        let result = handle_character_edit_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("--- Edit Existing Character (Wizard) ---");
        mock_io_handler.expect_output("Submit these changes? (Y/n)");
        mock_io_handler.expect_output("Character update cancelled.");
        mock_io_handler.expect_no_output_containing("updated successfully.");
    }
    
    #[tokio::test]
    async fn test_handle_character_edit_wizard_no_changes_made() {
        let char_id = Uuid::new_v4();
        let inputs = vec![
            char_id.to_string(),    // Character ID
            "n".to_string(),                    // Edit Name? No
            "n".to_string(),                    // Edit Description? No
            // ... all other fields "n"
            "n".to_string(), "n".to_string(), "n".to_string(), "n".to_string(), "n".to_string(), "n".to_string(),
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let original_char = mock_character_data_for_client(char_id, "Original NoChange", Some("NoChange Desc"));
        mock_http_client.get_character_result = Some(Arc::new(Ok(original_char.clone())));
        // update_character_result should not be called

        let result = handle_character_edit_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("--- Edit Existing Character (Wizard) ---");
        mock_io_handler.expect_output("Fetching current character data...");
        mock_io_handler.expect_output("No changes made. Exiting character edit.");
        mock_io_handler.expect_no_output_containing("Submit these changes?");
        mock_io_handler.expect_no_output_containing("updated successfully.");
    }

    #[tokio::test]
    async fn test_handle_character_edit_oneliner_client_error() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();
        let char_id = Uuid::new_v4();

        mock_http_client.update_character_result = Some(Arc::new(Err(
            MockCliError::ApiError("Failed to update character on server".to_string()),
        )));

        let args = CharacterEditArgs {
            id: Some(char_id),
            name: Some("Error Update".to_string()),
            interactive: false,
            ..default_edit_args(char_id)
        };

        let result =
            handle_character_edit_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_err());
        mock_io_handler.expect_output("Updating character from command line arguments...");
        mock_io_handler.expect_output("Error updating character: API returned an error: status=500 Internal Server Error, message=Failed to update character on server");
    }
}