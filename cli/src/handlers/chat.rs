use crate::chat::run_interactive_streaming_chat_loop; // Add this import for streaming chat
use crate::client::HttpClient;
use crate::error::CliError;
use crate::handlers::default_settings::apply_default_settings_to_session;
use crate::io::IoHandler;
use scribe_backend::models::chats::UpdateChatSettingsRequest; // Import UpdateChatSettingsRequest

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
                    // Format the timestamp directly
                    let updated_at_str = session.updated_at.format("%Y-%m-%d %H:%M:%S").to_string();

                    io_handler.write_line(&format!(
                        "  - Session ID: {}, Character ID: {}, Last Updated: {}",
                        session.id, 
                        session.character_id.map_or("None".to_string(), |id| id.to_string()),
                        updated_at_str
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
        // Format the timestamp directly
        let updated_at_str = session.updated_at.format("%Y-%m-%d %H:%M:%S").to_string();

        io_handler.write_line(&format!(
            "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
            index + 1,
            session.id,
            session.character_id.map_or("None".to_string(), |id| id.to_string()),
            updated_at_str
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
        "\nFetching messages for session {selected_session_id}..."
    ))?;
    match client.get_chat_messages(selected_session_id).await {
        Ok(messages) => {
            io_handler.write_line(&format!(
                "--- Chat History (Session: {selected_session_id}) ---"
            ))?;
            if messages.is_empty() {
                io_handler.write_line("  (No messages in this session yet)")?;
            } else {
                for message in messages {
                    io_handler.write_line("")?; // Add a blank line for spacing
                    let formatted_timestamp = message.created_at.format("%Y-%m-%d %H:%M:%S UTC");

                    // Determine prefix based on message.role (case-insensitive)
                    let role_lower = message.role.to_lowercase();
                    let prefix = if role_lower == "user" {
                        "You:"
                    } else if role_lower == "assistant" {
                        "AI:"
                    } else if role_lower == "system" {
                        "System:"
                    } else {
                        // Fallback for unknown roles, using the original role string, capitalized
                        let mut c = message.role.chars();
                        match c.next() {
                            None => "Unknown:", // Should not happen if role is not empty
                            Some(f) => &format!("{}{}:", f.to_uppercase(), c.as_str()),
                        }
                    };

                    // Extract content from parts array
                    let content_str = message
                        .parts
                        .as_array()
                        .and_then(|parts_array| parts_array.first())
                        .and_then(|first_part| first_part.get("text"))
                        .and_then(|text_value| text_value.as_str())
                        .unwrap_or("[empty message]") // Fallback for missing content
                        .to_string();

                    io_handler.write_line(&format!(
                        "  [{formatted_timestamp}] {prefix}\n    {content_str}"
                    ))?;
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
        // Format the timestamp directly
        let updated_at_str = session.updated_at.format("%Y-%m-%d %H:%M:%S").to_string();

        io_handler.write_line(&format!(
            "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
            index + 1,
            session.id,
            session.character_id.map_or("None".to_string(), |id| id.to_string()),
            updated_at_str
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
        "\nFetching recent messages for session {selected_session_id}..."
    ))?;
    match client.get_chat_messages(selected_session_id).await {
        Ok(messages) => {
            io_handler.write_line(&format!(
                "--- Recent History (Session: {selected_session_id}) ---"
            ))?;
            if messages.is_empty() {
                io_handler.write_line("  (No messages in this session yet)")?;
            } else {
                for message in messages {
                    io_handler.write_line("")?; // Add a blank line for spacing
                    let formatted_timestamp = message.created_at.format("%Y-%m-%d %H:%M:%S UTC");

                    // Determine prefix based on message.role (case-insensitive)
                    let role_lower = message.role.to_lowercase();
                    let prefix = if role_lower == "user" {
                        "You:"
                    } else if role_lower == "assistant" {
                        "AI:"
                    } else if role_lower == "system" {
                        "System:"
                    } else {
                        let mut c = message.role.chars();
                        match c.next() {
                            None => "Unknown:",
                            Some(f) => &format!("{}{}:", f.to_uppercase(), c.as_str()),
                        }
                    };

                    // Extract content from parts array
                    let content_str = message
                        .parts
                        .as_array()
                        .and_then(|parts_array| parts_array.first())
                        .and_then(|first_part| first_part.get("text"))
                        .and_then(|text_value| text_value.as_str())
                        .unwrap_or("[empty message]")
                        .to_string();

                    io_handler.write_line(&format!(
                        "  [{formatted_timestamp}] {prefix}\n    {content_str}"
                    ))?;
                }
            }
            io_handler.write_line("------------------------------------")?;
        }
        Err(e) => {
            tracing::error!(error = ?e, %selected_session_id, "Failed to fetch chat history before resuming");
            io_handler.write_line(&format!(
                "Warning: Could not fetch recent chat history: {e}"
            ))?;
        }
    }

    // Configure streaming chat by default with standard settings
    tracing::info!(chat_id = %selected_session_id, "Resuming chat session");
    io_handler.write_line(&format!("Using model for streaming: {current_model}"))?;

    // Apply default settings from configuration
    io_handler.write_line("Applying default chat settings...")?;
    match apply_default_settings_to_session(client, selected_session_id).await {
        Ok(_) => {
            io_handler.write_line("Session ready with your default settings.")?;
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Warning: Failed to apply default settings: {e}. Proceeding with system defaults."
            ))?;

            // Fallback to basic settings if default settings application fails
            let settings_to_update = UpdateChatSettingsRequest {
                gemini_thinking_budget: Some(1024), // Default thinking budget is 1024
                gemini_enable_code_execution: None, // Not currently relevant
                system_prompt: None,
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
                history_management_strategy: None,
                history_management_limit: None,
                model_name: Some(current_model.to_string()),
                chronicle_id: None, // Not relevant for CLI
                agent_mode: None, // Not used in CLI
            };

            match client
                .update_chat_settings(selected_session_id, &settings_to_update)
                .await
            {
                Ok(_) => {
                    io_handler.write_line("Session ready with basic settings.")?;
                }
                Err(e) => {
                    io_handler.write_line(&format!(
                        "Warning: Failed to update session settings: {e}. Proceeding with defaults."
                    ))?;
                }
            }
        }
    }

    // Use streaming chat by default
    if let Err(e) = run_interactive_streaming_chat_loop(
        client,
        selected_session_id,
        io_handler,
        current_model,
        None, // first_mes_content is not applicable when resuming a session
    )
    .await
    {
        tracing::error!(error = ?e, "Streaming chat loop failed while resuming session");
        io_handler.write_line(&format!("Chat encountered an error: {e}"))?;
    }
    io_handler.write_line("Chat finished.")?;
    Ok(())
}
