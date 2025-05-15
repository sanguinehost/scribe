use crate::chat::run_chat_loop;
use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::MessageRole;

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

    tracing::info!(chat_id = %selected_session_id, "Resuming chat session");
    if let Err(e) = run_chat_loop(client, selected_session_id, io_handler, current_model).await
    {
        tracing::error!(error = ?e, "Chat loop failed");
        io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
    }
    io_handler.write_line("Chat finished.")?;
    Ok(())
}