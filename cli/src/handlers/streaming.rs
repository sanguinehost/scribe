use crate::chat::run_interactive_streaming_chat_loop;
use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::{ApiChatMessage, UpdateChatSettingsRequest};
use crate::handlers::characters::select_character;

/// Handler function for testing the streaming chat functionality
pub async fn handle_stream_test_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    current_model: &str,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Test Streaming Chat (with Thinking) ---")?;
    io_handler.write_line(&format!("Using model: {}", current_model))?;

    // 1. Select Character
    let character_id = select_character(client, io_handler).await?;
    tracing::info!(%character_id, "Character selected for streaming test");

    // 2. Create Chat Session
    io_handler.write_line("Creating a new chat session for the test...")?;
    let chat_session = client.create_chat_session(character_id).await?;
    let chat_id = chat_session.id;
    tracing::info!(%chat_id, "Chat session created for streaming test");
    io_handler.write_line(&format!("Chat session created (ID: {}).", chat_id))?;

    // +++ Optional: Set Gemini-specific settings for this test session +++
    let mut settings_to_update = UpdateChatSettingsRequest { 
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        // Initialize other fields from UpdateChatSettingsRequest to None or their defaults
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: Some(current_model.to_string()), // Use the current model
    };

    let budget_str = io_handler.read_line("Set Gemini Thinking Budget (optional, integer, e.g. 1024, press Enter to skip):")?;
    if !budget_str.trim().is_empty() {
        match budget_str.trim().parse::<i32>() {
            Ok(budget) => settings_to_update.gemini_thinking_budget = Some(budget),
            Err(_) => io_handler.write_line("Invalid budget, skipping.")?,
        }
    }

    let exec_str = io_handler.read_line("Enable Gemini Code Execution (optional, true/false, press Enter to skip):")?;
    if !exec_str.trim().is_empty() {
        match exec_str.trim().to_lowercase().as_str() {
            "true" => settings_to_update.gemini_enable_code_execution = Some(true),
            "false" => settings_to_update.gemini_enable_code_execution = Some(false),
            _ => io_handler.write_line("Invalid input, skipping code execution setting.")?,
        }
    }

    // Always update settings to use our configured model and any other settings
    io_handler.write_line("Updating session with model and Gemini-specific settings for this test...")?;
    match client.update_chat_settings(chat_id, &settings_to_update).await {
        Ok(_) => io_handler.write_line("Test session settings updated.")?,
        Err(e) => io_handler.write_line(&format!("Warning: Failed to update test session settings: {}. Proceeding with defaults.", e))?,
    }
    // +++ End Gemini settings for test +++

    // 3. Get User's Initial Message
    let user_message = io_handler.read_line("Enter your message to start the stream test:")?;
    if user_message.trim().is_empty() {
        io_handler.write_line("Message cannot be empty. Aborting test.")?;
        return Ok(());
    }

    // +++ Construct initial history payload +++
    let initial_history = vec![ApiChatMessage {
        // Assuming ApiChatMessage has these fields based on backend usage
        role: "user".to_string(), // Role should be "user"
        content: user_message.clone(), // Clone the user message content
    }];
    // +++ End construction +++

    // 4. Run the Stream Test Loop
    io_handler.write_line("\nInitiating streaming response...")?;
    if let Err(e) = run_interactive_streaming_chat_loop(client, chat_id, io_handler, current_model).await {
        tracing::error!(error = ?e, "Stream test loop failed");
        io_handler.write_line(&format!("Stream test encountered an error: {}", e))?;
        // Return Ok here as the action itself didn't fail, the loop did.
        // The error is reported to the user.
    } else {
        io_handler.write_line("\nStreaming test finished.")?;
    }

    Ok(())
}