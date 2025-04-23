// cli/src/chat.rs

use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use uuid::Uuid;
use tracing; // Needed for tracing::error

/// Handles the interactive chat session with the AI.
/// Prompts the user for input, sends it to the backend, displays the response,
/// and repeats until the user types 'quit' or 'exit'.
pub async fn run_chat_loop<IO: IoHandler, Http: HttpClient>(
    http_client: &Http,
    chat_id: Uuid,
    io_handler: &mut IO,
    current_model: &str,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\nEntering chat session (ID: {}). Type 'quit' or 'exit' to leave.",
        chat_id
    ))?;
    io_handler.write_line("--------------------------------------------------")?;

    loop {
        let user_input = io_handler.read_line("You: ")?;
        let trimmed_input = user_input.trim();

        if trimmed_input.eq_ignore_ascii_case("quit") || trimmed_input.eq_ignore_ascii_case("exit") {
            io_handler.write_line("Leaving chat session.")?;
            break;
        }

        if trimmed_input.is_empty() {
            continue; // Skip empty input
        }

        match http_client.send_message(chat_id, trimmed_input, Some(current_model)).await {
            Ok(ai_message) => {
                io_handler.write_line(&format!("AI: {}", ai_message.content))?;
                io_handler.write_line("--------------------------------------------------")?;
            }
            Err(CliError::RateLimitExceeded) => {
                io_handler.write_line("API rate limit exceeded. Please wait a moment and try again.")?;
                io_handler.write_line("--------------------------------------------------")?;
            }
            Err(e) => {
                tracing::error!(error = ?e, chat_id = %chat_id, "Failed to send message or receive response");
                io_handler.write_line(&format!("Error sending message: {}. Try again or type 'quit' to exit.", e))?;
                io_handler.write_line("--------------------------------------------------")?;
            }
        }
    }
    Ok(())
} 