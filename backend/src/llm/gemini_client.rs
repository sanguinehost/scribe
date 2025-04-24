use async_trait::async_trait;
use genai::{
    chat::{ChatMessage, ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent}, // Add ChatStreamEvent
    Client, ClientBuilder,
};
use std::sync::Arc; // Added Arc
use futures::{StreamExt, TryStreamExt}; // For stream mapping
use std::pin::Pin;
use futures::stream::Stream;

use crate::errors::AppError;
use super::{AiClient, ChatStream, ChatStreamItem}; // Import the trait and types from the parent module

/// Wrapper struct around the genai::Client to implement our AiClient trait.
pub struct ScribeGeminiClient {
    inner: Client,
}

#[async_trait]
impl AiClient for ScribeGeminiClient {
    /// Executes a chat request using the underlying genai::Client.
    async fn exec_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>, // Use ChatOptions
    ) -> Result<ChatResponse, AppError> {
        // Delegate the call to the inner genai::Client
        // Convert the genai::Error to AppError using the existing From impl
        self.inner
            .exec_chat(model_name, request, config_override.as_ref())
            .await
            .map_err(AppError::from)
    }

    /// Executes a streaming chat request using the underlying genai::Client.
    async fn stream_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        // Call the underlying client's chat_stream method
        let chat_stream_response = self.inner
            .exec_chat_stream(model_name, request, config_override.as_ref())
            .await
            .map_err(AppError::from)?;

        // Extract the actual stream from the response
        let inner_stream = chat_stream_response.stream;

        // Map the stream items from Result<ChatStreamEvent, genai::Error> to Result<ChatStreamEvent, AppError>
        let mapped_stream = inner_stream.map(|result| {
            result.map_err(AppError::from)
        });

        // Box the stream and pin it
        let boxed_stream: ChatStream = Box::pin(mapped_stream);
        Ok(boxed_stream)
    }

}

/// Implement AiClient for Arc<ScribeGeminiClient> to fix the error
#[async_trait]
impl AiClient for Arc<ScribeGeminiClient> {
    async fn exec_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatResponse, AppError> {
        // Delegate to the inner ScribeGeminiClient
        (**self).exec_chat(model_name, request, config_override).await
    }

    // Delegate stream_chat for Arc<ScribeGeminiClient>
    async fn stream_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        (**self).stream_chat(model_name, request, config_override).await
    }

}

/// Builds the ScribeGeminiClient wrapper.
pub async fn build_gemini_client() -> Result<Arc<ScribeGeminiClient>, AppError> {
    // TODO: Implement proper auth resolver based on genai docs/examples if needed
    let client = ClientBuilder::default().build();

    Ok(Arc::new(ScribeGeminiClient { inner: client }))
}

// Basic example function to test the client - Updated to use the trait object
pub async fn generate_simple_response(
    client: &dyn AiClient, // Use trait object reference
    user_message: String,
    model_name: &str,
) -> Result<String, AppError> {
    let chat_request = ChatRequest::default().append_message(ChatMessage::user(user_message));

    tracing::debug!(%model_name, "Executing chat with specified model via trait");

    // Call exec_chat via the trait
    let response = client
        .exec_chat(model_name, chat_request, None)
        .await?;

    // Extract the text content from the response
    let content = response
        .content_text_as_str()
        .ok_or_else(|| AppError::BadRequest("No text content in LLM response".to_string()))?
        .to_string();

    Ok(content)
}

// TODO: Add unit tests for client building and maybe a mocked generation test (Task 2.3 TDD)

#[cfg(test)]
mod tests {
    use super::*;
    use dotenvy::dotenv;
    // Removed unused: use crate::llm::AiClient;

    // Test if the client wrapper can be built successfully
    #[tokio::test]
    async fn test_build_gemini_client_wrapper_ok() {
        dotenv().ok(); // Load .env file
        let result = build_gemini_client().await;
        assert!(result.is_ok(), "Failed to build Gemini client wrapper: {:?}", result.err());
        // We can't easily assert the inner client type without more complex setup
    }

    // Integration test: Calls the actual Gemini API via the wrapper and trait
    #[tokio::test]
    #[ignore] // Ignored by default
    async fn test_generate_simple_response_integration_via_wrapper() {
        dotenv().ok();

        // Build the client wrapper (returns Arc<ScribeGeminiClient>)
        let client_wrapper = build_gemini_client()
            .await
            .expect("Failed to build Gemini client wrapper for integration test");

        // Define a simple user message
        let user_message = "Test Wrapper: Say hello!".to_string();
        let model_name_for_test = "gemini-1.5-flash-latest"; // Use a common model

        // Call the generation function using the trait object reference
        // Dereference the Arc to get &ScribeGeminiClient, which automatically coerces to &dyn AiClient
        let result = generate_simple_response(&*client_wrapper, user_message, model_name_for_test).await;

        // Assert that the call was successful and returned a non-empty response
        match result {
            Ok(response) => {
                println!("Gemini Response (via wrapper): {}", response);
                assert!(!response.is_empty(), "Gemini returned an empty response");
            }
            Err(e) => {
                panic!("Gemini API call (via wrapper) failed: {:?}", e);
            }
        }
    }


    // Integration test: Calls the actual Gemini API stream via the wrapper and trait
    #[tokio::test]
    #[ignore] // Ignored by default
    async fn test_stream_chat_integration_via_wrapper() {
        dotenv().ok();

        // Build the client wrapper
        let client_wrapper = build_gemini_client()
            .await
            .expect("Failed to build Gemini client wrapper for streaming integration test");

        // Define a simple user message
        let user_message = "Test Stream Wrapper: Say hello stream!".to_string();
        let model_name_for_test = "gemini-1.5-flash-latest"; // Use a common model
        let chat_request = ChatRequest::default().append_message(ChatMessage::user(user_message));

        // Call the streaming function using the trait object reference
        let stream_result = client_wrapper
            .stream_chat(model_name_for_test, chat_request, None)
            .await;

        match stream_result {
            Ok(mut stream) => {
                let mut full_response = String::new();
                let mut chunk_count = 0;
                while let Some(item_result) = stream.next().await {
                    match item_result {
                        Ok(ChatStreamEvent::Chunk(chunk)) => {
                            // Access content directly and check if it's not empty
                            if !chunk.content.is_empty() {
                                print!("{}", chunk.content); // Print chunks as they arrive
                                full_response.push_str(&chunk.content);
                                chunk_count += 1;
                            }
                        }
                        Ok(ChatStreamEvent::End(_)) => { // Use End variant
                            println!("\nStream ended.");
                            break;
                        }
                        Err(e) => {
                            panic!("Error during stream processing: {:?}", e);
                        }
                        _ => {} // Ignore other event types for this simple test
                    }
                }
                println!("\nFull Gemini Stream Response (via wrapper): {}", full_response);
                assert!(!full_response.is_empty(), "Gemini stream returned an empty response");
                assert!(chunk_count > 0, "Gemini stream did not produce any chunks");
            }
            Err(e) => {
                panic!("Gemini API stream call (via wrapper) failed: {:?}", e);
            }
        }
    }

    // TODO: Add a mocked test for generate_simple_response using a MockAiClient
}