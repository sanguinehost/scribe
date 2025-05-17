use crate::chat::run_chat_loop;
use crate::chat::run_interactive_streaming_chat_loop; // Add this import for streaming chat
use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::{MessageRole, UpdateChatSettingsRequest}; // Import UpdateChatSettingsRequest

/// Handler function for listing chat sessions
pub async fn handle_list_chat_sessions_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nFetching your chat sessions...")?;
    match client.list_chat_sessions().await {
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

/// Handler function for viewing chat history
pub async fn handle_view_chat_history_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nSelect a chat session to view its history.")?;

    let sessions = client.list_chat_sessions().await?;
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
    match client.get_chat_messages(selected_session_id).await {
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
                    let content_str = String::from_utf8_lossy(&message.content).to_string();
                    io_handler.write_line(&format!("  {} {}", prefix, content_str))?;
                }
            }
            io_handler.write_line("------------------------------------")?;
            Ok(())
        }
        Err(e) => Err(e), // Logged by caller
    }
}

/// Handler function for resuming a chat session
pub async fn handle_resume_chat_session_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    current_model: &str,
) -> Result<(), CliError> {
    io_handler.write_line("\nSelect a chat session to resume.")?;

    let sessions = client.list_chat_sessions().await?;
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
    match client.get_chat_messages(selected_session_id).await {
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
                    let content_str = String::from_utf8_lossy(&message.content).to_string();
                    io_handler.write_line(&format!("  {} {}", prefix, content_str))?;
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

    // Configure streaming chat by default with standard settings
    tracing::info!(chat_id = %selected_session_id, "Resuming chat session");
    io_handler.write_line(&format!("Using model for streaming: {}", current_model))?;
    
    // Setup default settings with thinking budget of 1024
    let settings_to_update = UpdateChatSettingsRequest {
        gemini_thinking_budget: Some(1024), // Default to 1024
        gemini_enable_code_execution: None, // Not currently relevant
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
        model_name: Some(current_model.to_string()),
    };
    
    // Update session settings
    io_handler.write_line("Updating session with streaming settings...")?;
    match client.update_chat_settings(selected_session_id, &settings_to_update).await {
        Ok(_) => io_handler.write_line("Session settings updated for streaming.")?,
        Err(e) => io_handler.write_line(&format!("Warning: Failed to update session settings: {}. Proceeding with defaults.", e))?,
    }
    
    // Use streaming chat by default
    if let Err(e) = run_interactive_streaming_chat_loop(
        client,
        selected_session_id,
        io_handler,
        current_model,
    ).await {
        tracing::error!(error = ?e, "Chat loop failed");
        io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
    }
    io_handler.write_line("Chat finished.")?;
    Ok(())
}