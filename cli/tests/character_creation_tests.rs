#![allow(clippy::uninlined_format_args)]
#![allow(clippy::manual_string_new)]

#[cfg(test)]
mod character_creation_tests {
    use scribe_cli::CharacterCreateArgs; // Ensure this is pub in lib.rs or main.rs if main.rs is a lib
    use scribe_cli::handlers::characters::{
        handle_character_create_oneliner, handle_character_create_wizard,
    };
    use scribe_cli::test_helpers::{
        MockCliError, MockHttpClient, MockIoHandler, mock_character_data_for_client,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    fn default_create_args() -> CharacterCreateArgs {
        CharacterCreateArgs {
            name: Some("Test Character".to_string()),
            description: Some("A test description.".to_string()),
            first_mes: Some("Hello, test!".to_string()),
            personality: Some("Testy".to_string()),
            scenario: Some("A test scenario".to_string()),
            system_prompt: Some("Test system prompt".to_string()),
            creator_notes: Some("Test creator notes".to_string()),
            tags: Some(vec!["test".to_string(), "cli".to_string()]),
            alternate_greetings: Some(vec!["Hi test!".to_string()]),
            creator: Some("Test Creator".to_string()),
            character_version: Some("1.0".to_string()),
            interactive: false,
        }
    }

    #[tokio::test]
    async fn test_handle_character_create_oneliner_success() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();

        let char_id = Uuid::new_v4();
        let expected_char_name = "Test Character OneLiner";
        let mock_created_char =
            mock_character_data_for_client(char_id, expected_char_name, Some("Desc"));

        mock_http_client.create_character_result = Some(Arc::new(Ok(mock_created_char.clone())));

        let args = CharacterCreateArgs {
            name: Some(expected_char_name.to_string()),
            description: Some("OneLiner description".to_string()),
            first_mes: Some("OneLiner first mes".to_string()),
            interactive: false,
            ..default_create_args() // Fill in other optional fields if needed or use Default
        };

        let result =
            handle_character_create_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("Creating character from command line arguments...");
        mock_io_handler.expect_output(&format!(
            "Character '{}' created successfully with ID: {}",
            expected_char_name, char_id
        ));
        mock_io_handler.expect_output("Description: Desc");
    }

    #[tokio::test]
    async fn test_handle_character_create_oneliner_missing_name_error() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mock_http_client = MockHttpClient::new(); // No call expected

        let args = CharacterCreateArgs {
            name: None, // Missing name
            description: Some("OneLiner description".to_string()),
            first_mes: Some("OneLiner first mes".to_string()),
            interactive: false,
            ..default_create_args()
        };

        let result =
            handle_character_create_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Missing --name argument"));
        }
        // No output to io_handler before the error typically
    }

    #[tokio::test]
    async fn test_handle_character_create_wizard_success() {
        let inputs = vec![
            "Wizard Character".to_string(),   // Name
            "Wizard Description".to_string(), // Description
            "Wizard First Mes".to_string(),   // First Message
            "Wizard Personality".to_string(), // Personality
            "Wizard Scenario".to_string(),    // Scenario
            "".to_string(),                   // System Prompt (optional)
            "".to_string(),                   // Creator Notes (optional)
            "n".to_string(),                  // Add tags? No
            "n".to_string(),                  // Add alternate greetings? No
            "Y".to_string(),                  // Submit? Yes
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mut mock_http_client = MockHttpClient::new();

        let char_id = Uuid::new_v4();
        let expected_char_name = "Wizard Character";
        let mock_created_char =
            mock_character_data_for_client(char_id, expected_char_name, Some("Wizard Description"));

        mock_http_client.create_character_result = Some(Arc::new(Ok(mock_created_char.clone())));

        // Mock the DTO that would be created by the wizard
        // This is a simplification; in a real test, you'd verify the DTO construction.
        // For now, we focus on the handler calling the client.

        let result = handle_character_create_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("--- Create New Character (Manual Wizard) ---");
        mock_io_handler.expect_output("Character Name:");
        mock_io_handler.expect_output("Description:");
        mock_io_handler.expect_output("First Message (Greeting):");
        mock_io_handler.expect_output("Personality (optional):");
        mock_io_handler.expect_output("--- Review Character ---");
        mock_io_handler.expect_output(&format!("Name: {}", expected_char_name));
        mock_io_handler.expect_output("Submit this character? (Y/n)");
        mock_io_handler.expect_output(&format!(
            "Character '{}' created successfully with ID: {}",
            expected_char_name, char_id
        ));
    }

    #[tokio::test]
    async fn test_handle_character_create_wizard_cancel_submission() {
        let inputs = vec![
            "Wizard Cancel".to_string(),
            "Cancel Desc".to_string(),
            "Cancel First Mes".to_string(),
            "".to_string(),  // Personality skip
            "".to_string(),  // Scenario skip
            "".to_string(),  // System Prompt (optional)
            "".to_string(),  // Creator Notes (optional)
            "n".to_string(), // Tags skip
            "n".to_string(), // Alt greetings skip
            "n".to_string(), // Submit? No
        ];
        let mut mock_io_handler = MockIoHandler::new(inputs);
        let mock_http_client = MockHttpClient::new(); // No client call expected

        let result = handle_character_create_wizard(&mock_http_client, &mut mock_io_handler).await;

        assert!(result.is_ok());
        mock_io_handler.expect_output("--- Create New Character (Manual Wizard) ---");
        mock_io_handler.expect_output("Submit this character? (Y/n)");
        mock_io_handler.expect_output("Character creation cancelled.");
        mock_io_handler.expect_no_output_containing("created successfully");
    }

    #[tokio::test]
    async fn test_handle_character_create_oneliner_client_error() {
        let mut mock_io_handler = MockIoHandler::new(vec![]);
        let mut mock_http_client = MockHttpClient::new();

        mock_http_client.create_character_result = Some(Arc::new(Err(MockCliError::ApiError(
            "Failed to create character on server".to_string(),
        ))));

        let args = CharacterCreateArgs {
            name: Some("Error Character".to_string()),
            description: Some("Error description".to_string()),
            first_mes: Some("Error first mes".to_string()),
            interactive: false,
            ..default_create_args()
        };

        let result =
            handle_character_create_oneliner(&mock_http_client, &mut mock_io_handler, args).await;

        assert!(result.is_err());
        mock_io_handler.expect_output("Creating character from command line arguments...");
        mock_io_handler.expect_output("Error creating character: API returned an error: status=500 Internal Server Error, message=Failed to create character on server");
    }
}
