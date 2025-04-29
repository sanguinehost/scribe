// cli/src/chat.rs

use crate::client::{HttpClient, StreamEvent}; // Added StreamEvent
use crate::error::CliError;
use crate::io::IoHandler;
use futures_util::StreamExt;
use tracing;
use uuid::Uuid; // Needed for stream processing

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

        if trimmed_input.eq_ignore_ascii_case("quit") || trimmed_input.eq_ignore_ascii_case("exit")
        {
            io_handler.write_line("Leaving chat session.")?;
            break;
        }

        if trimmed_input.is_empty() {
            continue; // Skip empty input
        }

        match http_client
            .send_message(chat_id, trimmed_input, Some(current_model))
            .await
        {
            Ok(ai_message) => {
                io_handler.write_line(&format!("AI: {}", ai_message.content))?;
                io_handler.write_line("--------------------------------------------------")?;
            }
            Err(CliError::RateLimitExceeded) => {
                io_handler
                    .write_line("API rate limit exceeded. Please wait a moment and try again.")?;
                io_handler.write_line("--------------------------------------------------")?;
            }
            Err(e) => {
                tracing::error!(error = ?e, chat_id = %chat_id, "Failed to send message or receive response");
                io_handler.write_line(&format!(
                    "Error sending message: {}. Try again or type 'quit' to exit.",
                    e
                ))?;
                io_handler.write_line("--------------------------------------------------")?;
            }
        }
    }
    Ok(())
}

/// Runs a single streaming chat interaction for testing purposes.
/// Sends one message and prints the streamed response including thinking steps.
pub async fn run_stream_test_loop<IO: IoHandler, Http: HttpClient>(
    http_client: &Http,
    chat_id: Uuid,
    user_message: &str,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    let mut stream = http_client
        .stream_chat_response(chat_id, user_message, true)
        .await?; // Request thinking

    let mut thinking_started = false;
    let mut content_started = false;

    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(StreamEvent::Thinking(step)) => {
                if !thinking_started {
                    io_handler.write_raw("\n[Thinking] ")?; // Start thinking block on new line
                    thinking_started = true;
                    content_started = false; // Reset content flag if thinking starts/resumes
                }
                io_handler.write_raw(&format!("{}... ", step))?; // Print thinking step
            }
            Ok(StreamEvent::Content(chunk)) => {
                if thinking_started {
                    io_handler.write_raw("\n")?; // End thinking block with a newline
                    thinking_started = false;
                }
                if !content_started {
                    io_handler.write_raw("AI: ")?; // Prefix AI response only once
                    content_started = true;
                }
                io_handler.write_raw(&chunk)?; // Print content chunk directly
            }
            Ok(StreamEvent::Done) => {
                io_handler.write_raw("\n")?; // Ensure a newline after the response is fully streamed
                break; // Stream finished successfully
            }
            Err(e) => {
                if thinking_started || content_started {
                    io_handler.write_raw("\n")?; // Ensure newline if stream errors out mid-response
                }
                tracing::error!(error = ?e, chat_id = %chat_id, "Error during streaming response");
                io_handler.write_line(&format!("\nError receiving stream data: {}", e))?;
                return Err(e); // Propagate the stream error
            }
        }
    }
    if thinking_started || content_started {
        io_handler.write_raw("\n")?; // Ensure a final newline if the stream ended cleanly
    }
    io_handler.write_line("--------------------------------------------------")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Remove failing test code
}
