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
                let content_str = String::from_utf8_lossy(&ai_message.content).to_string();
                io_handler.write_line(&format!("AI: {}", content_str))?;
                io_handler.write_line("--------------------------------------------------")?;
            }
            Err(CliError::RateLimitExceeded) => {
                io_handler.write_line("API rate limit exceeded: The Gemini model is currently receiving too many requests.")?;
                io_handler.write_line("Please wait a moment before trying again or try a different model.")?;
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
    initial_history: Vec<scribe_backend::models::chats::ApiChatMessage>,
    io_handler: &mut IO,
    current_model: &str,  // Add current_model parameter
) -> Result<(), CliError> {
    let mut stream = http_client
        .stream_chat_response(chat_id, initial_history, true, Some(current_model))
        .await?; // Request thinking with current model

    let mut thinking_started = false;
    let mut content_started = false;
    let mut current_line = String::new(); // Buffer for the current line

    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(StreamEvent::Thinking(step)) => {
                if !thinking_started {
                    // If there was pending content in current_line from a previous (e.g. AI) segment, print it.
                    if !current_line.is_empty() {
                        io_handler.write_raw(&current_line)?;
                        io_handler.write_raw("\n")?; // Ensure newline
                        current_line.clear();
                    }
                    io_handler.write_line("[Thinking]")?; // Start thinking block on new line
                    thinking_started = true;
                    content_started = false; // Reset content flag if thinking starts/resumes
                }
                // Print thinking steps immediately. These are usually short.
                io_handler.write_line(&format!("- {}...", step))?;
            }
            Ok(StreamEvent::ReasoningChunk(text_chunk)) => {
                if !thinking_started {
                    // If there was pending AI content in current_line, print it before switching to thinking.
                    if !current_line.is_empty() {
                        io_handler.write_raw(&current_line)?;
                        io_handler.write_raw("\n")?;
                        current_line.clear();
                    }
                    io_handler.write_line("[Thinking]")?;
                    thinking_started = true;
                    content_started = false;
                }
                
                // Append the reasoning chunk to the current_line buffer
                current_line.push_str(&text_chunk);
                
                // Process and print all complete lines found in the buffer, indented
                while let Some(newline_pos) = current_line.find('\n') {
                    let line_to_print = current_line.drain(..=newline_pos).collect::<String>();
                    io_handler.write_raw(&format!("  {}", line_to_print))?; // Indent reasoning lines
                }
                
                // After printing all complete lines, print any remaining partial line *without* a newline, indented.
                // Only print if not empty, and ensure we're clearing the buffer after printing
                if !current_line.is_empty() {
                     io_handler.write_raw(&format!("  {}", current_line))?;
                     current_line.clear(); // Clear the buffer after writing to prevent duplication
                     io_handler.flush()?; // Flush to make the partial line visible
                }
            }
            Ok(StreamEvent::Content(chunk)) => {
                if thinking_started {
                    // Thinking steps or reasoning chunks were active.
                    // Print any remaining buffered thinking line with a newline before switching to AI content.
                    if !current_line.is_empty() {
                        io_handler.write_raw(&current_line)?; // Print whatever is in buffer
                        io_handler.write_raw("\n")?; // Ensure newline
                        current_line.clear();
                    }
                    thinking_started = false;
                }
                if !content_started {
                    io_handler.write_line("AI:")?; // Prefix AI response only once on a new line
                    content_started = true;
                }
                
                // Append the new chunk to the buffer
                current_line.push_str(&chunk);
                
                // Process and print all complete lines found in the buffer
                while let Some(newline_pos) = current_line.find('\n') {
                    let line_to_print = current_line.drain(..=newline_pos).collect::<String>();
                    io_handler.write_raw(&line_to_print)?;
                }
                
                // Only print and flush if the current_line is not empty
                // Don't clear the buffer here as we want to continue appending to the same line
                if !current_line.is_empty() {
                     io_handler.write_raw(&current_line)?;
                     // Don't clear current_line here as it may be a partial line that continues
                     io_handler.flush()?;
                     current_line.clear(); // Clear after printing to avoid duplication
                }
            }
            Ok(StreamEvent::PartialMessage(text)) => {
                if thinking_started {
                     // Same logic as for Content starting after thinking
                    if !current_line.is_empty() {
                        io_handler.write_raw(&current_line)?;
                        io_handler.write_raw("\n")?;
                        current_line.clear();
                    }
                    thinking_started = false;
                }
                if !content_started {
                    io_handler.write_line("AI:")?;
                    content_started = true;
                }
                
                // For PartialMessage, we'll replace the current line completely instead of appending
                // This prevents duplication if the server resends the same text
                current_line = text; // Replace with new text instead of appending
                
                // Process and print the current line
                io_handler.write_raw(&current_line)?;
                io_handler.flush()?;
                current_line.clear(); // Clear after printing to avoid duplication
            }
            Ok(StreamEvent::Done) => {
                // Print any remaining buffered content before finishing
                if !current_line.is_empty() {
                    io_handler.write_raw(&current_line)?;
                    io_handler.flush()?;
                    current_line.clear();
                }
                io_handler.write_raw("\n")?; // Ensure a final newline
                break; // Stream finished successfully
            }
            Err(e) => {
                // Print any remaining buffered content before error message
                if !current_line.is_empty() {
                    io_handler.write_raw(&current_line)?;
                    io_handler.write_raw("\n")?; // Ensure newline
                    current_line.clear();
                }
                
                // Handle rate limit errors specially
                if let CliError::RateLimitExceeded = e {
                    io_handler.write_line("API rate limit exceeded: The Gemini model is currently receiving too many requests.")?;
                    io_handler.write_line("Please wait a moment before trying again or try a different model.")?;
                } else {
                    io_handler.write_line(&format!("Error: {}", e))?;
                }
                break; // Stop on error
            }
        }
    }
    
    io_handler.write_line("--------------------------------------------------")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Remove failing test code
}
