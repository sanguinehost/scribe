use crate::chat::run_chat_loop; // Import the chat loop function
use crate::chat::run_stream_test_loop; // Import the stream test loop function
use crate::client::HttpClient; // Added StreamEvent
use crate::error::CliError;
use crate::io::IoHandler;
// Added missing Stream trait import
use scribe_backend::models::auth::LoginPayload;
use scribe_backend::models::characters::CharacterMetadata;
use scribe_backend::models::chats::MessageRole;
use scribe_backend::models::users::User;
use std::path::Path;
use uuid::Uuid;
use secrecy::Secret;
use bigdecimal::BigDecimal;
use crate::client::{RegisterPayload};

// --- Action Functions ---

pub async fn handle_login_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<User, CliError> {
    io_handler.write_line("\nPlease log in.")?;
    let username = io_handler.read_line("Username:")?;
    let password = io_handler.read_line("Password:")?;
    let credentials = LoginPayload { 
        identifier: username, 
        password: Secret::new(password) 
    };
    http_client.login(&credentials).await
}

pub async fn handle_registration_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<User, CliError> {
    io_handler.write_line("\nPlease register a new user.")?;
    let username = io_handler.read_line("Choose Username:")?;
    let email = io_handler.read_line("Enter Email:")?;
    let password = io_handler.read_line("Choose Password:")?;
    
    if username.len() < 3 {
        return Err(CliError::InputError(
            "Username must be at least 3 characters long.".into(),
        ));
    }
    if password.len() < 8 {
        return Err(CliError::InputError(
            "Password must be at least 8 characters long.".into(),
        ));
    }
    
    let credentials = RegisterPayload { 
        username, 
        email,
        password: Secret::new(password) 
    };
    http_client.register(&credentials).await
}

pub async fn handle_health_check_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line("\nChecking backend health...")?;
    match http_client.health_check().await {
        Ok(health_status) => {
            io_handler.write_line(&format!("Backend status: {}", health_status.status))?;
            Ok(())
        }
        Err(e) => Err(e), // Error is logged by the main loop caller
    }
}

pub async fn handle_upload_character_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<CharacterMetadata, CliError> {
    io_handler.write_line("\nUpload a new character.")?;
    let name = io_handler.read_line("Character Name:")?;
    let file_path = io_handler.read_line("Path to Character Card (.png):")?;

    if name.trim().is_empty() {
        return Err(CliError::InputError(
            "Character name cannot be empty.".into(),
        ));
    }
    if file_path.trim().is_empty() {
        return Err(CliError::InputError("File path cannot be empty.".into()));
    }
    // Basic check, could be more robust
    if !file_path.to_lowercase().ends_with(".png") {
        io_handler
            .write_line("Warning: File does not end with .png. The backend might reject it.")?;
    }

    // Check if file exists before attempting upload
    if !Path::new(&file_path).exists() {
        return Err(CliError::InputError(format!(
            "File not found at path: {}",
            file_path
        )));
    }

    io_handler.write_line("Uploading...")?;
    http_client.upload_character(&name, &file_path).await
}

pub async fn handle_view_character_details_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    let character_id = select_character(http_client, io_handler).await?;

    io_handler.write_line("\nFetching character details...")?;
    match http_client.get_character(character_id).await {
        Ok(character) => {
            io_handler.write_line(&format!("--- Character Details (ID: {}) ---", character.id))?;
            io_handler.write_line(&format!("  Name: {}", character.name))?;
            io_handler.write_line(&format!(
                "  Description: {}",
                character.description.as_deref().unwrap_or("N/A")
            ))?;
            io_handler.write_line("------------------------------------")?;
            Ok(())
        }
        Err(e) => Err(e), // Error logged by caller
    }
}

pub async fn handle_list_chat_sessions_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line("\nFetching your chat sessions...")?;
    match http_client.list_chat_sessions().await {
        Ok(sessions) => {
            if sessions.is_empty() {
                io_handler.write_line("You have no active chat sessions.")?;
            } else {
                io_handler.write_line("Your chat sessions:")?;
                // TODO: Ideally, fetch character names for better display instead of just IDs
                for session in sessions {
                    io_handler.write_line(&format!(
                        "  - Session ID: {}, Character ID: {}, Last Updated: {}",
                        session.id, session.character_id, session.updated_at
                    ))?;
                }
            }
            Ok(())
        }
        Err(e) => Err(e), // Logged by caller
    }
}

pub async fn handle_view_chat_history_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line("\nSelect a chat session to view its history.")?;

    let sessions = http_client.list_chat_sessions().await?;
    if sessions.is_empty() {
        return Err(CliError::InputError("No chat sessions found.".to_string()));
    }

    io_handler.write_line("Available chat sessions:")?;
    // TODO: Fetch character names for better display
    for (index, session) in sessions.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
            index + 1,
            session.id,
            session.character_id,
            session.updated_at
        ))?;
    }

    let selected_session_id = loop {
        let choice_str = io_handler.read_line("Select session by number:")?;
        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= sessions.len() => {
                break sessions[choice - 1].id;
            }
            _ => {
                io_handler.write_line(&format!(
                    "Invalid selection. Please enter a number between 1 and {}.",
                    sessions.len()
                ))?;
            }
        }
    };

    io_handler.write_line(&format!(
        "\nFetching messages for session {}...",
        selected_session_id
    ))?;
    match http_client.get_chat_messages(selected_session_id).await {
        Ok(messages) => {
            io_handler.write_line(&format!(
                "--- Chat History (Session: {}) ---",
                selected_session_id
            ))?;
            if messages.is_empty() {
                io_handler.write_line("  (No messages in this session yet)")?;
            } else {
                for message in messages {
                    let prefix = match message.message_type {
                        MessageRole::User => "You:",
                        MessageRole::Assistant => "AI:",
                        MessageRole::System => "System:",
                    };
                    io_handler.write_line(&format!("  {} {}", prefix, message.content))?;
                }
            }
            io_handler.write_line("------------------------------------")?;
            Ok(())
        }
        Err(e) => Err(e), // Logged by caller
    }
}

pub async fn handle_resume_chat_session_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
    current_model: &str,
) -> Result<(), CliError> {
    io_handler.write_line("\nSelect a chat session to resume.")?;

    let sessions = http_client.list_chat_sessions().await?;
    if sessions.is_empty() {
        return Err(CliError::InputError(
            "No chat sessions found to resume.".to_string(),
        ));
    }

    io_handler.write_line("Available chat sessions:")?;
    // TODO: Fetch character names for better display
    for (index, session) in sessions.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
            index + 1,
            session.id,
            session.character_id,
            session.updated_at
        ))?;
    }

    let selected_session_id = loop {
        let choice_str = io_handler.read_line("Select session by number:")?;
        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= sessions.len() => {
                break sessions[choice - 1].id;
            }
            _ => {
                io_handler.write_line(&format!(
                    "Invalid selection. Please enter a number between 1 and {}.",
                    sessions.len()
                ))?;
            }
        }
    };

    io_handler.write_line(&format!(
        "\nFetching recent messages for session {}...",
        selected_session_id
    ))?;
    match http_client.get_chat_messages(selected_session_id).await {
        Ok(messages) => {
            io_handler.write_line(&format!(
                "--- Recent History (Session: {}) ---",
                selected_session_id
            ))?;
            if messages.is_empty() {
                io_handler.write_line("  (No messages in this session yet)")?;
            } else {
                for message in messages {
                    let prefix = match message.message_type {
                        MessageRole::User => "You:",
                        MessageRole::Assistant => "AI:",
                        MessageRole::System => "System:",
                    };
                    io_handler.write_line(&format!("  {} {}", prefix, message.content))?;
                }
            }
            io_handler.write_line("------------------------------------")?;
        }
        Err(e) => {
            tracing::error!(error = ?e, %selected_session_id, "Failed to fetch chat history before resuming");
            io_handler.write_line(&format!(
                "Warning: Could not fetch recent chat history: {}",
                e
            ))?;
        }
    }

    tracing::info!(chat_id = %selected_session_id, "Resuming chat session");
    if let Err(e) = run_chat_loop(http_client, selected_session_id, io_handler, current_model).await
    {
        tracing::error!(error = ?e, "Chat loop failed");
        io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
    }
    io_handler.write_line("Chat finished.")?;
    Ok(())
}

/// Handles the model settings submenu actions.
pub async fn handle_model_settings_action<C: HttpClient, H: IoHandler>(
    _http_client: &C, // Not used yet, but keep for consistency
    io_handler: &mut H,
    current_model: &mut String,
) -> Result<(), CliError> {
    // Define the full model names for clarity in prompts/examples if needed
    const EXPERIMENTAL_MODEL: &str = "gemini-2.5-pro-exp-03-25";
    const PAID_MODEL: &str = "gemini-2.5-pro-preview-03-25";

    loop {
        io_handler.write_line("\n--- Model Settings ---")?;
        // Display the current full model name
        io_handler.write_line(&format!(
            "[1] View Current Model (Currently: {})",
            current_model
        ))?;
        io_handler.write_line("[2] Change Model")?;
        io_handler.write_line("[b] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice:")?;

        match choice.as_str() {
            "1" => {
                // Explicitly confirm the current full model name
                io_handler
                    .write_line(&format!("The current model is set to: {}", current_model))?;
            }
            "2" => {
                // Prompt for the full model name directly, providing examples
                let prompt = format!(
                    "Enter the full model name (e.g., '{}', '{}'):",
                    EXPERIMENTAL_MODEL, PAID_MODEL
                );
                let new_model = io_handler.read_line(&prompt)?;
                let trimmed_model = new_model.trim();

                if trimmed_model.is_empty() {
                    io_handler.write_line("Model name cannot be empty. No changes made.")?;
                } else {
                    // Store the exact name entered by the user
                    *current_model = trimmed_model.to_string();
                    tracing::info!(new_model = %current_model, "Chat model updated");
                    io_handler.write_line(&format!("Model updated to: {}", current_model))?;
                }
            }
            "b" | "B" => {
                io_handler.write_line("Returning to main menu.")?;
                return Ok(()); // Exit the settings submenu loop
            }
            _ => {
                io_handler.write_line("Invalid choice, please try again.")?;
            }
        }
    }
    // Note: The loop is infinite until 'b' is chosen, so this Ok(()) is unreachable,
    // but needed for the function signature. Loop exit returns Ok explicitly.
}

// --- Character Selection ---
// Kept in handlers for now, could be moved to selectors.rs later
pub async fn select_character<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<Uuid, CliError> {
    io_handler.write_line("\nFetching your characters...")?;
    let characters = http_client.list_characters().await?;

    if characters.is_empty() {
        return Err(CliError::InputError(
            "No characters found. Please upload a character first.".to_string(),
        ));
    }

    io_handler.write_line("Available characters:")?;
    for (index, char) in characters.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] {} (ID: {})",
            index + 1,
            char.name,
            char.id
        ))?;
    }

    loop {
        let choice_str = io_handler.read_line("Select character by number:")?;
        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= characters.len() => {
                let selected_char = &characters[choice - 1];
                io_handler.write_line(&format!("Selected: {}", selected_char.name))?;
                return Ok(selected_char.id);
            }
            _ => {
                io_handler.write_line(&format!(
                    "Invalid selection. Please enter a number between 1 and {}.",
                    characters.len()
                ))?;
            }
        }
    }
}

/// Handles the streaming chat test action.
/// Selects a character, creates a session, gets a user message, and runs the stream test loop.
pub async fn handle_stream_test_action<Http: HttpClient, IO: IoHandler>(
    http_client: &Http,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Test Streaming Chat (with Thinking) ---")?;

    // 1. Select Character
    let character_id = select_character(http_client, io_handler).await?;
    tracing::info!(%character_id, "Character selected for streaming test");

    // 2. Create Chat Session
    io_handler.write_line("Creating a new chat session for the test...")?;
    let chat_session = http_client.create_chat_session(character_id).await?;
    let chat_id = chat_session.id;
    tracing::info!(%chat_id, "Chat session created for streaming test");
    io_handler.write_line(&format!("Chat session created (ID: {}).", chat_id))?;

    // 3. Get User's Initial Message
    let user_message = io_handler.read_line("Enter your message to start the stream test:")?;
    if user_message.trim().is_empty() {
        io_handler.write_line("Message cannot be empty. Aborting test.")?;
        return Ok(());
    }

    // 4. Run the Stream Test Loop (function to be defined in chat.rs)
    io_handler.write_line("\nInitiating streaming response...")?;
    if let Err(e) = run_stream_test_loop(http_client, chat_id, &user_message, io_handler).await {
        tracing::error!(error = ?e, "Stream test loop failed");
        io_handler.write_line(&format!("Stream test encountered an error: {}", e))?;
        // Return Ok here as the action itself didn't fail, the loop did.
        // The error is reported to the user.
    } else {
        io_handler.write_line("\nStreaming test finished.")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{HealthStatus, HttpClient, StreamEvent}; // Added StreamEvent
    use crate::error::CliError; // Need base CliError
    use crate::io::IoHandler; // Need IoHandler trait
    use async_trait::async_trait;
    use chrono::Utc;
    use futures_util::Stream; // Added Stream trait import
    use scribe_backend::models::auth::LoginPayload;
    use scribe_backend::models::characters::CharacterMetadata;
    use scribe_backend::models::chats::{ChatMessage, Chat, MessageRole};
    use scribe_backend::models::users::User;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs; // Need fs for temp file writing
    use std::pin::Pin; // Added Pin
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use uuid::Uuid; // Needed for mock impl

    // --- Mocks (Moved here from main.rs tests) ---

    // Define a simple, cloneable error for mocking purposes
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum MockCliError {
        // Made pub for use in this test module
        AuthFailed(String),
        RegistrationFailed(String),
        ApiError(String), // Simplified API error
        NotFound,
        Internal(String),
        // Add other variants as needed for specific test cases
    }

    impl From<MockCliError> for CliError {
        fn from(mock_err: MockCliError) -> Self {
            match mock_err {
                MockCliError::AuthFailed(msg) => CliError::AuthFailed(msg),
                MockCliError::RegistrationFailed(msg) => CliError::RegistrationFailed(msg),
                MockCliError::ApiError(msg) => CliError::ApiError {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR, // Use a default status
                    message: msg,
                },
                MockCliError::NotFound => CliError::NotFound,
                MockCliError::Internal(msg) => CliError::Internal(msg),
            }
        }
    }

    #[derive(Default)] // Added default derive
    pub struct MockIoHandler {
        // Made pub
        inputs: RefCell<VecDeque<String>>,
        outputs: RefCell<Vec<String>>,
    }

    impl MockIoHandler {
        // Made pub
        pub fn new(inputs: Vec<&str>) -> Self {
            MockIoHandler {
                inputs: RefCell::new(inputs.into_iter().map(String::from).collect()),
                outputs: RefCell::new(Vec::new()),
            }
        }
        // Made pub
        pub fn expect_output(&self, expected: &str) {
            assert!(
                self.outputs
                    .borrow()
                    .iter()
                    .any(|line| line.contains(expected)),
                "Expected output containing '{}', but got: {:?}",
                expected,
                self.outputs.borrow()
            );
        }
        // Made pub
        pub fn expect_no_output_containing(&self, unexpected: &str) {
            assert!(
                !self
                    .outputs
                    .borrow()
                    .iter()
                    .any(|line| line.contains(unexpected)),
                "Did not expect output containing '{}', but got: {:?}",
                unexpected,
                self.outputs.borrow()
            );
        }
    }

    // #[async_trait::async_trait] // IoHandler is not async yet
    impl IoHandler for MockIoHandler {
        fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
            self.outputs.borrow_mut().push(prompt.to_string());
            self.inputs.borrow_mut().pop_front().ok_or_else(|| {
                CliError::InputError("MockIoHandler: No more inputs provided".to_string())
            })
        }

        fn write_line(&mut self, line: &str) -> Result<(), CliError> {
            self.outputs.borrow_mut().push(line.to_string());
            Ok(())
        }

        fn write_raw(&mut self, text: &str) -> Result<(), CliError> {
            // For the mock, just store the raw text like write_line
            self.outputs.borrow_mut().push(text.to_string());
            Ok(())
        }
    }

    #[derive(Default)] // Use default for simple mock state
    // Made pub
    pub struct MockHttpClient {
        login_result: Option<Arc<Result<User, MockCliError>>>,
        register_result: Option<Arc<Result<User, MockCliError>>>,
        health_check_result: Option<Arc<Result<HealthStatus, MockCliError>>>,
        upload_character_result: Option<Arc<Result<CharacterMetadata, MockCliError>>>,
        list_characters_result: Option<Arc<Result<Vec<CharacterMetadata>, MockCliError>>>,
        get_character_result: Option<Arc<Result<CharacterMetadata, MockCliError>>>,
        list_chat_sessions_result: Option<Arc<Result<Vec<Chat>, MockCliError>>>,
        get_chat_messages_result: Option<Arc<Result<Vec<ChatMessage>, MockCliError>>>,
        create_chat_session_result: Option<Arc<Result<Chat, MockCliError>>>, // Added
        generate_response_result: Option<Arc<Result<ChatMessage, MockCliError>>>,
        logout_result: Option<Arc<Result<(), MockCliError>>>, // Added
        me_result: Option<Arc<Result<User, MockCliError>>>,   // Added
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn login(&self, _credentials: &LoginPayload) -> Result<User, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.login_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: login result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }

        async fn register(&self, _credentials: &RegisterPayload) -> Result<User, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.register_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: register result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }

        async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.list_characters_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: list_characters result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn create_chat_session(&self, _character_id: Uuid) -> Result<Chat, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.create_chat_session_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: create_chat_session result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into)
        }
        async fn upload_character(
            &self,
            _name: &str,
            _file_path: &str,
        ) -> Result<CharacterMetadata, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.upload_character_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: upload_character result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn health_check(&self) -> Result<HealthStatus, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.health_check_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: health_check result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn logout(&self) -> Result<(), CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.logout_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: logout result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn me(&self) -> Result<User, CliError> {
            let mock_result = Arc::unwrap_or_clone(self.me_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: me result not set".into(),
                )))
            }));
            mock_result.map_err(Into::into)
        }
        async fn get_character(&self, _character_id: Uuid) -> Result<CharacterMetadata, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.get_character_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: get_character result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.list_chat_sessions_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: list_chat_sessions result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }
        async fn get_chat_messages(&self, _session_id: Uuid) -> Result<Vec<ChatMessage>, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.get_chat_messages_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: get_chat_messages result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }

        // Add missing implementation for generate_response (matching the trait signature)
        async fn generate_response(
            &self,
            _chat_id: Uuid,
            _message_content: &str,
            _model_name: Option<String>,
        ) -> Result<ChatMessage, CliError> {
            let mock_result =
                Arc::unwrap_or_clone(self.generate_response_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: generate_response result not set".into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }

        // Add missing implementation for send_message
        async fn send_message(
            &self,
            _chat_id: Uuid,
            _content: &str,
            _model_name: Option<&str>,
        ) -> Result<ChatMessage, CliError> {
            // Use the configurable result field, similar to generate_response
            let mock_result =
                Arc::unwrap_or_clone(self.generate_response_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: generate_response_result (for send_message) not set"
                            .into(),
                    )))
                }));
            mock_result.map_err(Into::into)
        }

        // Add mock implementation for stream_chat_response
        async fn stream_chat_response(
            &self,
            _chat_id: Uuid,
            _message_content: &str,
            _request_thinking: bool,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError>
        {
            // Default mock implementation: return an error or an empty stream.
            // For most handler tests, we don't need to simulate a full stream.
            // If a specific test needs a stream, it can configure a dedicated mock field.
            Err(CliError::Internal(
                "MockHttpClient: stream_chat_response not implemented/configured".into(),
            ))
            // Or return an empty stream:
            // Ok(Box::pin(futures_util::stream::empty())) // Use futures_util::stream::empty
        }
    }

    // --- Helper Functions for Creating Mocks ---
    fn mock_user(username: &str) -> User {
        User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            email: "user@example.com".to_string(),
            password_hash: "hashed_password".to_string(), // Mocked
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn mock_character(id: Uuid, name: &str, description: Option<&str>) -> CharacterMetadata {
        CharacterMetadata {
            id,
            user_id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.map(String::from),
            first_mes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn mock_chat_session(id: Uuid, character_id: Uuid) -> Chat {
        Chat {
            id,
            user_id: Uuid::new_v4(),
            character_id,
            title: Some("Mock Chat".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            system_prompt: Some("You are a helpful mock assistant".to_string()),
            temperature: Some(BigDecimal::from_str("0.7").unwrap()),
            max_output_tokens: Some(1024),
            frequency_penalty: Some(BigDecimal::from_str("0").unwrap()),
            presence_penalty: Some(BigDecimal::from_str("0").unwrap()),
            top_k: Some(40),
            top_p: Some(BigDecimal::from_str("0.95").unwrap()),
            repetition_penalty: Some(BigDecimal::from_str("1.03").unwrap()),
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            visibility: Some("private".to_string()),
        }
    }

    fn mock_chat_message(
        id: Uuid,
        session_id: Uuid,
        role: MessageRole,
        content: &str,
    ) -> ChatMessage {
        ChatMessage {
            id,
            session_id,
            user_id: Uuid::nil(), // Use Uuid::nil() for test context
            message_type: role,
            content: content.to_string(),
            created_at: Utc::now(),
            // removed metadata, token_count
        }
    }

    // --- Action Handler Tests (Moved from main.rs tests) ---

    #[tokio::test]
    async fn test_handle_login_action_success() {
        let mut mock_io = MockIoHandler::new(vec!["testuser", "password123"]);
        let mock_http = MockHttpClient {
            login_result: Some(Arc::new(Ok(mock_user("testuser")))),
            ..Default::default()
        };

        let result = handle_login_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "testuser");
        mock_io.expect_output("Please log in.");
    }

    #[tokio::test]
    async fn test_handle_login_action_failure() {
        let mut mock_io = MockIoHandler::new(vec!["testuser", "wrongpass"]);
        let mock_http = MockHttpClient {
            login_result: Some(Arc::new(Err(MockCliError::AuthFailed(
                "Invalid credentials".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_login_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::AuthFailed(msg) => assert_eq!(msg, "Invalid credentials"),
            e => panic!("Expected AuthFailed error, got {:?}", e),
        }
        mock_io.expect_output("Please log in.");
    }

    #[tokio::test]
    async fn test_handle_registration_action_success() {
        let mut mock_io = MockIoHandler::new(vec!["newuser", "user@example.com", "goodpassword"]);
        let mock_http = MockHttpClient {
            register_result: Some(Arc::new(Ok(mock_user("newuser")))),
            ..Default::default()
        };

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "newuser");
        mock_io.expect_output("Please register a new user.");
    }

    #[tokio::test]
    async fn test_handle_registration_action_failure_username_taken() {
        let mut mock_io = MockIoHandler::new(vec!["existinguser", "existing@example.com", "goodpassword"]);
        let mock_http = MockHttpClient {
            register_result: Some(Arc::new(Err(MockCliError::RegistrationFailed(
                "Username already taken".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::RegistrationFailed(msg) => assert_eq!(msg, "Username already taken"),
            e => panic!("Expected RegistrationFailed error, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    }

    #[tokio::test]
    async fn test_handle_registration_action_failure_short_username() {
        let mut mock_io = MockIoHandler::new(vec!["us", "short@example.com", "goodpassword"]);
        let mock_http = MockHttpClient::default(); // HTTP client won't be called

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => {
                assert!(msg.contains("at least 3 characters"))
            }
            e => panic!("Expected InputError error, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    }

    #[tokio::test]
    async fn test_handle_registration_action_failure_short_password() {
        let mut mock_io = MockIoHandler::new(vec!["validuser", "valid@example.com", "short"]);
        let mock_http = MockHttpClient::default(); // HTTP client won't be called

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => {
                assert!(msg.contains("at least 8 characters"))
            }
            e => panic!("Expected InputError error, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    }

    #[tokio::test]
    async fn test_handle_health_check_action_success() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            health_check_result: Some(Arc::new(Ok(HealthStatus {
                status: "OK".to_string(),
            }))),
            ..Default::default()
        };

        let result = handle_health_check_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Checking backend health...");
        mock_io.expect_output("Backend status: OK");
    }

    #[tokio::test]
    async fn test_handle_health_check_action_failure() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            health_check_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Database connection failed".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_health_check_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => {
                assert_eq!(message, "Database connection failed");
            }
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Checking backend health...");
        mock_io.expect_no_output_containing("Backend status:");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_success() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().with_extension("png"); // Ensure .png extension
        fs::write(&path, "dummy png data").unwrap();
        let file_path_str = path.to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let expected_char_id = Uuid::new_v4();
        let mock_http = MockHttpClient {
            upload_character_result: Some(Arc::new(Ok(mock_character(
                expected_char_id,
                "Test Char",
                Some("Uploaded char"),
            )))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        let character = result.unwrap();
        assert_eq!(character.id, expected_char_id);
        assert_eq!(character.name, "Test Char");
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Path to Character Card (.png):");
        mock_io.expect_output("Uploading...");

        fs::remove_file(&path).ok(); // Clean up temp file
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_empty_name() {
        let mut mock_io = MockIoHandler::new(vec!["", "dummy_path.png"]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("Character name cannot be empty")),
            e => panic!("Expected InputError for empty name, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_empty_path() {
        let mut mock_io = MockIoHandler::new(vec!["Test Char", ""]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("File path cannot be empty")),
            e => panic!("Expected InputError for empty path, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_file_not_found() {
        let non_existent_path = "./non_existent_file_for_test.png";
        let _ = fs::remove_file(non_existent_path); // Ensure it doesn't exist

        let mut mock_io = MockIoHandler::new(vec!["Test Char", non_existent_path]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("File not found at path")),
            e => panic!("Expected InputError for file not found, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_not_png_warning() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "dummy data").unwrap(); // No .png extension
        let file_path_str = temp_file.path().to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let mock_http = MockHttpClient {
            upload_character_result: Some(Arc::new(Ok(mock_character(
                Uuid::new_v4(),
                "Test Char",
                None,
            )))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Warning: File does not end with .png");
        mock_io.expect_output("Uploading...");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_api_error() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().with_extension("png"); // Ensure .png extension
        fs::write(&path, "dummy png data").unwrap();
        let file_path_str = path.to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let mock_http = MockHttpClient {
            upload_character_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Invalid character card format".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => {
                assert_eq!(message, "Invalid character card format");
            }
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Uploading...");
        fs::remove_file(&path).ok(); // Clean up
    }

    #[tokio::test]
    async fn test_handle_view_character_details_success() {
        let char1_id = Uuid::new_v4();
        let char2_id = Uuid::new_v4();
        let characters = vec![
            mock_character(char1_id, "Char One", Some("Desc 1")),
            mock_character(char2_id, "Char Two", None),
        ];
        let selected_char_details = mock_character(char1_id, "Char One", Some("Desc 1"));

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first character
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(characters))),
            get_character_result: Some(Arc::new(Ok(selected_char_details))),
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your characters...");
        mock_io.expect_output("[1] Char One");
        mock_io.expect_output("[2] Char Two");
        mock_io.expect_output("Select character by number:");
        mock_io.expect_output("Selected: Char One");
        mock_io.expect_output("Fetching character details...");
        mock_io.expect_output(&format!("--- Character Details (ID: {}) ---", char1_id));
        mock_io.expect_output("Name: Char One");
        mock_io.expect_output("Description: Desc 1");
    }

    #[tokio::test]
    async fn test_handle_view_character_details_no_characters() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("No characters found")),
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your characters...");
    }

    #[tokio::test]
    async fn test_handle_view_character_details_list_api_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Access denied".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => assert_eq!(message, "Access denied"),
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your characters...");
    }

    #[tokio::test]
    async fn test_handle_view_character_details_get_api_error() {
        let char1_id = Uuid::new_v4();
        let characters = vec![mock_character(char1_id, "Char One", None)];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first character
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(characters))),
            get_character_result: Some(Arc::new(Err(MockCliError::NotFound))), // Simulate get error
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::NotFound => { /* Expected */ }
            e => panic!("Expected NotFound error, got {:?}", e),
        }
        mock_io.expect_output("Fetching character details...");
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_success() {
        let session1_id = Uuid::new_v4();
        let session2_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let char2_id = Uuid::new_v4();
        let sessions = vec![
            mock_chat_session(session1_id, char1_id),
            mock_chat_session(session2_id, char2_id),
        ];

        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your chat sessions...");
        mock_io.expect_output("Your chat sessions:");
        mock_io.expect_output(&format!("Session ID: {}", session1_id));
        mock_io.expect_output(&format!("Character ID: {}", char1_id));
        mock_io.expect_output(&format!("Session ID: {}", session2_id));
        mock_io.expect_output(&format!("Character ID: {}", char2_id));
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_empty() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your chat sessions...");
        mock_io.expect_output("You have no active chat sessions.");
        mock_io.expect_no_output_containing("Your chat sessions:");
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_api_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Not logged in".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => assert_eq!(message, "Not logged in"),
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your chat sessions...");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_success() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];
        let messages = vec![
            mock_chat_message(Uuid::new_v4(), session1_id, MessageRole::User, "Hello"),
            mock_chat_message(
                Uuid::new_v4(),
                session1_id,
                MessageRole::Assistant,
                "Hi there!",
            ),
        ];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first session
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(messages))),
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Select a chat session to view its history.");
        mock_io.expect_output("Available chat sessions:");
        mock_io.expect_output(&format!("[{}] Session ID: {}", 1, session1_id));
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching messages for session {}...", session1_id));
        mock_io.expect_output(&format!("--- Chat History (Session: {}) ---", session1_id));
        mock_io.expect_output("You: Hello");
        mock_io.expect_output("AI: Hi there!");
        mock_io.expect_output("------------------------------------");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_no_sessions() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("No chat sessions found")),
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to view its history.");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_list_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::Internal(
                "DB error".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::Internal(msg) => assert_eq!(msg, "DB error"),
            e => panic!("Expected Internal error, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to view its history.");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_get_messages_error() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first session
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Err(MockCliError::NotFound))), // Simulate error fetching messages
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::NotFound => { /* Expected */ }
            e => panic!("Expected NotFound error, got {:?}", e),
        }
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching messages for session {}...", session1_id));
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_invalid_selection() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];

        // Provide invalid input first, then valid
        let mut mock_io = MockIoHandler::new(vec!["abc", "0", "2", "1"]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(vec![]))), // Empty messages for simplicity
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok()); // Should eventually succeed after valid input
        mock_io.expect_output("Invalid selection. Please enter a number between 1 and 1.");
        mock_io.expect_output("--- Chat History (Session:"); // Check final output part
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_success() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];
        let messages = vec![mock_chat_message(
            Uuid::new_v4(),
            session1_id,
            MessageRole::User,
            "Previous message",
        )];
        let ai_response = mock_chat_message(
            Uuid::new_v4(),
            session1_id,
            MessageRole::Assistant,
            "AI response",
        );

        // Input: Select session 1, type 'hello', then 'quit'
        let mut mock_io = MockIoHandler::new(vec!["1", "hello", "quit"]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(messages))),
            generate_response_result: Some(Arc::new(Ok(ai_response))), // Mock the generate response
            ..Default::default()
        };

        let result =
            handle_resume_chat_session_action(&mock_http, &mut mock_io, "current_model").await;

        assert!(result.is_ok());
        mock_io.expect_output("Select a chat session to resume.");
        mock_io.expect_output("Available chat sessions:");
        mock_io.expect_output(&format!("[{}] Session ID: {}", 1, session1_id));
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!(
            "Fetching recent messages for session {}...",
            session1_id
        ));
        mock_io.expect_output(&format!(
            "--- Recent History (Session: {}) ---",
            session1_id
        ));
        mock_io.expect_output("You: Previous message");
        mock_io.expect_output("Entering chat session");
        mock_io.expect_output("You:"); // Prompt for 'hello'
        mock_io.expect_output("AI: AI response"); // Reverted to expect the actual mock content
        mock_io.expect_output("You:"); // Prompt for 'quit'
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_no_sessions() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // No sessions
            ..Default::default()
        };

        let result =
            handle_resume_chat_session_action(&mock_http, &mut mock_io, "current_model").await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => {
                assert!(msg.contains("No chat sessions found to resume"))
            }
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to resume.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_list_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::Internal(
                "List error".to_string(),
            )))),
            ..Default::default()
        };

        let result =
            handle_resume_chat_session_action(&mock_http, &mut mock_io, "current_model").await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::Internal(msg) => assert_eq!(msg, "List error"),
            e => panic!("Expected Internal error, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to resume.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_get_messages_error_warning() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];

        // Input: Select session 1, then 'quit' immediately
        let mut mock_io = MockIoHandler::new(vec!["1", "quit"]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Err(MockCliError::NotFound))), // Error fetching history
            ..Default::default()
        };

        let result =
            handle_resume_chat_session_action(&mock_http, &mut mock_io, "current_model").await;

        assert!(result.is_ok());
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!(
            "Fetching recent messages for session {}...",
            session1_id
        ));
        mock_io.expect_output("Warning: Could not fetch recent chat history"); // Check for warning
        mock_io.expect_output("Entering chat session");
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_generate_error() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![mock_chat_session(session1_id, char1_id)];

        // Input: Select session 1, type 'hello', then 'quit'
        let mut mock_io = MockIoHandler::new(vec!["1", "hello", "quit"]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(vec![]))), // No history
            generate_response_result: Some(Arc::new(Err(MockCliError::ApiError(
                "LLM unavailable".to_string(),
            )))),
            ..Default::default()
        };

        let result =
            handle_resume_chat_session_action(&mock_http, &mut mock_io, "current_model").await;

        assert!(result.is_ok());
        mock_io.expect_output("Entering chat session");
        mock_io.expect_output("You:"); // Prompt for 'hello'
        // Expect the actual error message format printed by the chat loop
        mock_io.expect_output("Error sending message: API returned an error: status=500 Internal Server Error, message=LLM unavailable.");
        mock_io.expect_output("You:"); // Prompt for 'quit'
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }
}
