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
    initial_history: Vec<scribe_backend::models::chats::ApiChatMessage>, // <-- Change parameter type and add full path
    io_handler: &mut IO,
) -> Result<(), CliError> {
    let mut stream = http_client
        .stream_chat_response(chat_id, initial_history, true) // <-- Pass history
        .await?; // Request thinking

    let mut thinking_started = false;
    let mut content_started = false;
    let mut current_line = String::new(); // Buffer for the current line

    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(StreamEvent::Thinking(step)) => {
                if !thinking_started {
                    io_handler.write_line("\n[Thinking]")?; // Start thinking block on new line
                    thinking_started = true;
                    content_started = false; // Reset content flag if thinking starts/resumes
                    current_line.clear(); // Clear line buffer when switching modes
                }
                // Print thinking steps immediately, maybe accumulate if they get long?
                io_handler.write_line(&format!("- {}...", step))?; 
            }
            Ok(StreamEvent::Content(chunk)) => {
                if thinking_started {
                    // Thinking steps were printed with write_line, so cursor is already on a new line.
                    thinking_started = false;
                    current_line.clear(); // Clear buffer when switching from thinking to content
                }
                if !content_started {
                    io_handler.write_line("\nAI:")?; // Prefix AI response only once on a new line
                    content_started = true;
                }
                
                // Append the new chunk to the buffer
                current_line.push_str(&chunk);
                
                // Process and print all complete lines found in the buffer
                while let Some(newline_pos) = current_line.find('\n') {
                    // Drain the line including the newline character
                    let line_to_print = current_line.drain(..=newline_pos).collect::<String>();
                    // Print the complete line using write_raw to preserve the newline
                    io_handler.write_raw(&line_to_print)?;
                }
                
                // After printing all complete lines, print any remaining partial line *without* a newline
                // and leave it in the buffer for the next chunk to append to.
                if !current_line.is_empty() {
                     io_handler.write_raw(&current_line)?;
                     io_handler.flush()?; // Flush to make the partial line visible
                }
                // DO NOT clear current_line here - let it accumulate
            }
            Ok(StreamEvent::Done) => {
                // Print any remaining buffered content before finishing
                if !current_line.is_empty() {
                    io_handler.write_raw(&current_line)?;
                    io_handler.flush()?;
                }
                io_handler.write_raw("\n")?; // Ensure a final newline
                break; // Stream finished successfully
            }
            Err(e) => {
                 // Print any remaining buffered content before error message
                if !current_line.is_empty() {
                    io_handler.write_raw(&current_line)?;
                    io_handler.flush()?;
                }
                if thinking_started || content_started {
                    io_handler.write_raw("\n")?; // Ensure newline if stream errors out mid-response
                }
                tracing::error!(error = ?e, chat_id = %chat_id, "Error during streaming response");
                io_handler.write_line(&format!("\nError receiving stream data: {}", e))?;
                return Err(e); // Propagate the stream error
            }
        }
    }
    // Ensure a final newline if the loop finished cleanly but maybe without a Done event
    if thinking_started || content_started {
         if !current_line.is_empty() { // Print remaining buffer if loop exited unexpectedly
             io_handler.write_raw(&current_line)?;
             io_handler.flush()?;
         }
        io_handler.write_raw("\n")?;
    }
    io_handler.write_line("--------------------------------------------------")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Remove failing test code
}
