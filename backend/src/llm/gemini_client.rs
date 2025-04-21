use genai::{
    chat::{ChatMessage, ChatRequest},
    Client, ClientBuilder,
};

use crate::errors::AppError;

// TODO: Consider moving this to a more central configuration area if reused
const MODEL_NAME: &str = "gemini-2.5-pro-exp-03-25";

pub async fn build_gemini_client() -> Result<Client, AppError> {

    // TODO: Implement proper auth resolver based on genai docs/examples if needed
    // For now, assume direct API key usage is handled by the underlying adapter.
    // This might need refinement depending on how `genai` expects the key.
    let client = ClientBuilder::default()
        // Potentially add .with_auth_resolver_fn here if direct key isn't enough
        .build(); // Build should not return a result directly

    Ok(client)
}

// Basic example function to test the client
// We'll refine this later to integrate with chat history, settings, etc. (Task 2.4, 2.5)
pub async fn generate_simple_response(
    client: &Client,
    user_message: String,
) -> Result<String, AppError> {
    let chat_request = ChatRequest::default()
        .append_message(ChatMessage::user(user_message));

    let response = client
        .exec_chat(MODEL_NAME, chat_request, None) // Pass MODEL_NAME here
        .await?;

    // Extract the text content from the response
    // Use content_text_as_str() for potentially simpler extraction
    let content = response
        .content_text_as_str()
        // Use GeminiError or a more specific variant if appropriate
        .ok_or_else(|| AppError::BadRequest("No text content in LLM response".to_string()))?
        .to_string();

    Ok(content)
}

// TODO: Add unit tests for client building and maybe a mocked generation test (Task 2.3 TDD)

#[cfg(test)]
mod tests {
    use super::*;
    use dotenvy::dotenv;

    // Test if the client can be built successfully when GEMINI_API_KEY is set
    #[tokio::test]
    async fn test_build_gemini_client_ok() {
        dotenv().ok(); // Load .env file
        let result = build_gemini_client().await;
        // Assert that the client was built successfully
        // This implicitly checks if the API key was read from env
        assert!(result.is_ok(), "Failed to build Gemini client: {:?}", result.err());
    }

    // Integration test: Calls the actual Gemini API
    // Run with: cargo test -- --ignored llm::gemini_client::tests::test_generate_simple_response_integration
    #[tokio::test]
    #[ignore] // Ignored by default to avoid unnecessary API calls/costs
    async fn test_generate_simple_response_integration() {
        dotenv().ok(); // Load .env file

        // Build the client
        let client = build_gemini_client()
            .await
            .expect("Failed to build Gemini client for integration test");

        // Define a simple user message
        let user_message = "Test: Say hello!".to_string();

        // Call the generation function
        let result = generate_simple_response(&client, user_message).await;

        // Assert that the call was successful and returned a non-empty response
        match result {
            Ok(response) => {
                println!("Gemini Response: {}", response);
                assert!(!response.is_empty(), "Gemini returned an empty response");
            }
            Err(e) => {
                panic!("Gemini API call failed: {:?}", e);
            }
        }
    }

    // TODO: Add a mocked test for generate_simple_response
    // This would require a mocking framework or feature flags to swap the client
}