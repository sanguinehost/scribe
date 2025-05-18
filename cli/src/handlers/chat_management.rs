use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;

/// Handler function for managing/deleting chat sessions
pub async fn handle_delete_chat_session_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nSelect a chat session to delete.")?;

    let sessions = client.list_chat_sessions().await?;
    if sessions.is_empty() {
        return Err(CliError::InputError(
            "No chat sessions found to delete.".to_string(),
        ));
    }

    io_handler.write_line("Available chat sessions:")?;
    for (index, session) in sessions.iter().enumerate() {
        // Format the timestamp directly
        let updated_at_str = session.updated_at.format("%Y-%m-%d %H:%M:%S").to_string();

        io_handler.write_line(&format!(
            "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
            index + 1,
            session.id,
            session.character_id,
            updated_at_str
        ))?;
    }

    let selected_session = loop {
        let choice_str = io_handler.read_line("Select session by number (or 'c' to cancel):")?;

        if choice_str.trim().to_lowercase() == "c" {
            io_handler.write_line("Operation cancelled.")?;
            return Ok(());
        }

        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= sessions.len() => {
                break choice - 1; // Adjust to 0-based indexing for the sessions vector
            }
            _ => {
                io_handler.write_line(&format!(
                    "Invalid selection. Please enter a number between 1 and {} (or 'c' to cancel).",
                    sessions.len()
                ))?;
            }
        }
    };

    let session_id = sessions[selected_session].id;

    // Confirm deletion
    let confirmation = io_handler.read_line(&format!(
        "Are you sure you want to delete chat session {}? This action cannot be undone. (y/n):",
        session_id
    ))?;

    if confirmation.trim().to_lowercase() != "y" {
        io_handler.write_line("Operation cancelled.")?;
        return Ok(());
    }

    // Proceed with deletion
    io_handler.write_line(&format!("Deleting chat session {}...", session_id))?;
    match client.delete_chat(session_id).await {
        Ok(_) => {
            io_handler.write_line("Chat session successfully deleted.")?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Failed to delete chat session: {}", e))?;
            Err(e)
        }
    }
}
