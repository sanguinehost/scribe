// cli/src/client/util.rs

use crate::error::CliError;
use reqwest::{Response, StatusCode, Url};
use serde::Deserialize; // For local error parsing structs
use serde::de::DeserializeOwned;
use serde_json;
use tracing;

use super::types::NonStreamingResponse; // For handle_non_streaming_chat_response
use scribe_backend::models::chats::ChatMessage; // For handle_non_streaming_chat_response

// Helper to join path to base URL
pub(super) fn build_url(base: &Url, path: &str) -> Result<Url, CliError> {
    base.join(path).map_err(CliError::UrlParse)
}

// Helper to handle API responses
// Add std::fmt::Debug to T for logging
pub(super) async fn handle_response<T: DeserializeOwned + std::fmt::Debug>(
    response: Response,
) -> Result<T, CliError> {
    let status = response.status();
    let type_name = std::any::type_name::<T>(); // Get type name for logs

    // Try to get response text
    let response_body = match response.text().await {
        Ok(text) => {
            // Use eprintln for debug logging as requested
            // Attempt to parse the response body for safe logging.
            // If T is CharacterDataForClient or Vec<CharacterDataForClient>,
            // its Debug impl (now custom) will be used.
            match serde_json::from_str::<T>(&text) {
                Ok(parsed_data_for_log) => {
                    tracing::trace!(
                        target: "scribe_cli::client::util",
                        type_name,
                        %status,
                        parsed_body = ?parsed_data_for_log,
                        "Successfully parsed response body for logging"
                    );
                }
                Err(parse_err) => {
                    // If parsing fails, log a redacted version of the body or a placeholder.
                    // Also log the parsing error for debugging why it failed, but not the raw body.
                    tracing::trace!(
                        target: "scribe_cli::client::util",
                        type_name,
                        %status,
                        body = "[RAW_BODY_REDACTED_DUE_TO_PARSE_ERROR_FOR_LOGGING]",
                        %parse_err,
                        "Response body for T={} (raw, parse error for logging)", type_name
                    );
                    // Optionally, log a very short, non-sensitive prefix of the text if deemed necessary for some debugging,
                    // but full redaction on parse error is safest for sensitive data.
                    // e.g., tracing::trace!("Raw body prefix (first 30 chars): '{}...'", text.chars().take(30).collect::<String>());
                }
            }
            text
        }
        Err(e) => {
            tracing::debug!(target: "scribe_cli::client::util", %type_name, error = ?e, "Failed to get response text");
            // Existing tracing log, kept for consistency with other parts of the codebase if desired
            tracing::error!("Failed to get response text for T={}: {}", type_name, e);
            return Err(CliError::Reqwest(e));
        }
    };

    if status.is_success() {
        match serde_json::from_str::<T>(&response_body) {
            Ok(data) => {
                // Don't log the full data at trace level as it might be large or contain binary
                tracing::trace!(target: "scribe_cli::client::util", %type_name, "Successfully deserialized response");
                Ok(data)
            }
            Err(e) => {
                tracing::debug!(target: "scribe_cli::client::util", %type_name, body = %response_body, error = ?e, "Failed to deserialize response body");
                // Existing tracing logs
                tracing::error!(
                    "Failed to deserialize successful response for T={}: {}",
                    type_name,
                    e
                );
                // Don't print the full response body as it might contain binary data
                let truncated_body = if response_body.len() > 200 {
                    format!(
                        "{}... (truncated, {} total bytes)",
                        &response_body.chars().take(200).collect::<String>(),
                        response_body.len()
                    )
                } else {
                    response_body.clone()
                };
                tracing::error!("Response text for T={} was: {}", type_name, truncated_body);
                // Map to CliError::Json or CliError::Internal as appropriate
                // Using CliError::Json as it's more specific for deserialization issues
                Err(CliError::Json(e))
            }
        }
    } else {
        tracing::debug!(target: "scribe_cli::client::util", %type_name, %status, body = %response_body, "API request failed with non-success status");

        // IMPORTANT: Check for 429 Too Many Requests *before* trying to parse body
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(target: "scribe_cli::client::util", %type_name, "Received 429 Too Many Requests, returning CliError::RateLimitExceeded.");
            // The original tracing::warn is kept below, this one is more specific to the eprint replacement
            tracing::warn!(
                "Received 429 Too Many Requests from backend for T={}",
                type_name
            );
            return Err(CliError::RateLimitExceeded);
        }

        // Define local structs for attempting to parse a structured error response
        // These are based on the user's previous diff's implied structure.
        #[derive(Deserialize, Debug)]
        struct ApiErrorDetail {
            message: String,
            details: Option<serde_json::Value>, // Using serde_json::Value for flexibility
        }
        #[derive(Deserialize, Debug)]
        struct StructuredApiErrorResponse {
            error: ApiErrorDetail,
        }

        let structured_error_result: Result<StructuredApiErrorResponse, _> =
            serde_json::from_str(&response_body);

        if let Ok(parsed_error) = structured_error_result {
            tracing::trace!(target: "scribe_cli::client::util", %type_name, parsed_error = ?parsed_error, "Successfully parsed structured API error");
            // Existing tracing log
            tracing::error!(
                target: "scribe_cli::client::util", // Updated target
                %status,
                parsed_error_message = %parsed_error.error.message,
                parsed_error_details = ?parsed_error.error.details,
                raw_body = %response_body,
                "API request failed for T={}: (parsed structured error)", type_name
            );
            Err(CliError::ApiError {
                status,
                // Use the message from the parsed error if available, otherwise fall back to the whole body
                message: parsed_error.error.message,
            })
        } else {
            tracing::debug!(target: "scribe_cli::client::util", %type_name, error = ?structured_error_result.err(), body = %response_body, "Failed to parse response body as StructuredApiErrorResponse");
            // Existing tracing log
            tracing::error!(
                target: "scribe_cli::client::util", // Updated target
                %status,
                error_body = %response_body,
                "API request failed for T={}: (raw error body)", type_name
            );
            // Fallback if error response itself can't be deserialized into the structure
            Err(CliError::ApiError {
                status,
                message: response_body, // Use the full response_body as the message
            })
        }
    }
}

// NEW: Helper function specifically for handling the non-streaming chat response
pub(super) async fn handle_non_streaming_chat_response(
    response: Response,
) -> Result<ChatMessage, CliError> {
    let status = response.status();

    // Get the content type to determine how to process the response
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();

    if !status.is_success() {
        // For error status codes, handle the same way as before
        if status == StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!("Received 429 Too Many Requests from backend");
            return Err(CliError::RateLimitExceeded);
        }

        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error body".to_string());
        tracing::error!(target: "scribe_cli::client::util", %status, error_body = %error_text, "API request failed");
        return Err(CliError::ApiError {
            status,
            message: error_text,
        });
    }

    // Get the response text
    let response_text = match response.text().await {
        Ok(text) => {
            if text.trim().is_empty() {
                tracing::warn!(target: "scribe_cli::client::util", "Received empty response body with success status");
                return Err(CliError::Internal(
                    "Received empty response from server".to_string(),
                ));
            }
            text
        }
        Err(e) => {
            tracing::error!(target: "scribe_cli::client::util", error = ?e, "Failed to get text from response");
            return Err(CliError::Reqwest(e));
        }
    };

    tracing::debug!(target: "scribe_cli::client::util", "Received response text: {}", response_text);

    // Check if we have an SSE response (text/event-stream or contains "event:" and "data:")
    if content_type.contains("text/event-stream")
        || (response_text.contains("event:") && response_text.contains("data:"))
    {
        tracing::debug!(target: "scribe_cli::client::util", "Detected SSE format response");

        // Check for error event (including rate limit errors from Gemini)
        if response_text.contains("event: error") {
            let error_data = response_text
                .lines()
                .find(|line| line.starts_with("data:"))
                .map(|line| line.trim_start_matches("data:").trim())
                .unwrap_or("Unknown error in SSE stream");

            tracing::error!(target: "scribe_cli::client::util", error_data = %error_data, "SSE stream contained error event");

            // Check for rate limit errors (status code 429) in the error text
            if error_data.contains("429")
                || error_data.contains("Too Many Requests")
                || error_data.contains("rate limit")
            {
                return Err(CliError::RateLimitExceeded);
            }

            return Err(CliError::Backend(format!("Server error: {error_data}")));
        }

        // Extract content from a successful response
        // Look for "event: content" or "event: done" followed by data
        let content = response_text
            .lines()
            .skip_while(|line| !line.contains("event: content"))
            .skip(1) // Skip the "event: content" line
            .take_while(|line| !line.contains("event:")) // Take until next event
            .filter(|line| line.starts_with("data:"))
            .map(|line| line.trim_start_matches("data:").trim())
            .collect::<Vec<&str>>()
            .join("");

        if content.is_empty() {
            // If no content, check for done event with data
            let done_data = response_text
                .lines()
                .skip_while(|line| !line.contains("event: done"))
                .skip(1) // Skip the "event: done" line
                .take_while(|line| !line.contains("event:"))
                .filter(|line| line.starts_with("data:"))
                .map(|line| line.trim_start_matches("data:").trim())
                .collect::<Vec<&str>>()
                .join("");

            if !done_data.is_empty() {
                // Use the done event data
                tracing::debug!(target: "scribe_cli::client::util", done_data = %done_data, "Using data from done event");
                return Ok(ChatMessage {
                    id: uuid::Uuid::new_v4(), // Generate an ID since we don't have one
                    session_id: uuid::Uuid::nil(),
                    user_id: uuid::Uuid::nil(),
                    message_type: scribe_backend::models::chats::MessageRole::Assistant,
                    content: done_data.into_bytes(),
                    content_nonce: None,
                    created_at: chrono::Utc::now(),
                    prompt_tokens: None,
                    completion_tokens: None,
                });
            }

            tracing::warn!(target: "scribe_cli::client::util", "No content found in SSE response");
            return Err(CliError::Internal(
                "No message content found in server response".to_string(),
            ));
        }

        // Return the content we found
        tracing::debug!(target: "scribe_cli::client::util", content_len = content.len(), "Found content in SSE response");
        return Ok(ChatMessage {
            id: uuid::Uuid::new_v4(), // Generate an ID since we don't have one
            session_id: uuid::Uuid::nil(),
            user_id: uuid::Uuid::nil(),
            message_type: scribe_backend::models::chats::MessageRole::Assistant,
            content: content.into_bytes(),
            content_nonce: None,
            created_at: chrono::Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
        });
    }

    // If not SSE, try parsing as JSON (original implementation)
    match serde_json::from_str::<NonStreamingResponse>(&response_text) {
        Ok(body) => {
            // Construct a partial ChatMessage. The chat loop primarily needs the content.
            // Other fields like created_at, session_id are not strictly needed by the loop
            // but we can add them with default/dummy values if necessary elsewhere.
            Ok(ChatMessage {
                id: body.message_id,
                session_id: uuid::Uuid::nil(), // Not provided by this endpoint, set to nil
                user_id: uuid::Uuid::nil(),    // Use Uuid::nil() for CLI context
                message_type: scribe_backend::models::chats::MessageRole::Assistant,
                content: body.content.into_bytes(), // Convert String to Vec<u8>
                content_nonce: None,                // Add missing field
                created_at: chrono::Utc::now(),     // Use current time
                prompt_tokens: None,
                completion_tokens: None,
            })
        }
        Err(e) => {
            tracing::error!(target: "scribe_cli::client::util", error = ?e, response_text = %response_text, "Failed to parse JSON in non-streaming chat response");
            Err(CliError::Json(e))
        }
    }
}
