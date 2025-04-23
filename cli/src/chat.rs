// cli/src/chat.rs

use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::ChatMessage; // Needed for ai_message.content
use uuid::Uuid;
use tracing; // Needed for tracing::error

/// Handles the interactive chat session with the AI.
/// Prompts the user for input, sends it to the backend, displays the response,
/// and repeats until the user types 'quit' or 'exit'.
pub async fn run_chat_loop<IO: IoHandler, Http: HttpClient>(
    http_client: &Http,
    chat_id: Uuid,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\nEntering chat session (ID: {}). Type 'quit' or 'exit' to leave.",
        chat_id
    ))?;
    io_handler.write_line("--------------------------------------------------")?;

    loop {
        let user_input = io_handler.read_line("You:")?;

        if user_input.eq_ignore_ascii_case("quit") || user_input.eq_ignore_ascii_case("exit") {
            io_handler.write_line("Leaving chat session.")?;
            break;
        }

        if user_input.is_empty() {
            continue; // Skip empty input
        }

        match http_client.generate_response(chat_id, &user_input).await {
            Ok(ai_message) => {
                // Assuming generate_response returns ChatMessage which has a `content` field
                io_handler.write_line(&format!("AI: {}", ai_message.content))?;
            }
            Err(e) => {
                // Check for specific errors first
                match e {
                    CliError::RateLimited => {
                        // Specific message for rate limiting
                        io_handler.write_line("API rate limit exceeded. Please wait a moment and try again.")?;
                        // Optionally, could pause here or break the loop depending on desired UX
                    }
                    // Handle other errors generically
                    _ => {
                        tracing::error!(error = ?e, %chat_id, "Failed to get AI response");
                        io_handler.write_line(&format!(
                            "Error: Could not get response from AI. Please try again. ({})",
                            e
                        ))?;
                    }
                }
            }
        }
        // Separator after each turn
        io_handler.write_line("--------------------------------------------------")?;
    }
    Ok(())
} 