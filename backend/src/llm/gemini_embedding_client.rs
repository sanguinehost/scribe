// Gemini Embedding Client using REST API

use crate::config::Config;
use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use async_trait::async_trait;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, instrument};

// --- Request Structs ---

#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    content: Content<'a>,
    #[serde(rename = "taskType")] // Match API naming
    task_type: &'a str,
}

#[derive(Serialize)]
struct Content<'a> {
    parts: Vec<Part<'a>>,
}

#[derive(Serialize)]
struct Part<'a> {
    text: &'a str,
}

// --- Response Structs ---

#[derive(Deserialize)]
struct EmbeddingResponse {
    embedding: Embedding,
    // Add potential error fields if needed for better error handling
}

#[derive(Deserialize)]
struct Embedding {
    values: Vec<f32>,
}

// --- Error Response Struct ---
#[derive(Deserialize, Debug)]
struct GeminiApiErrorResponse {
     error: GeminiApiError,
}
#[derive(Deserialize, Debug)]
struct GeminiApiError {
    code: i32,
    message: String,
    status: String,
}

// --- Client Implementation (To be added below) ---
const DEFAULT_EMBEDDING_MODEL: &str = "models/gemini-embedding-exp-03-07"; // Use the latest experimental model as per docs

#[derive(Clone)] // Add Clone
pub struct RestGeminiEmbeddingClient {
    reqwest_client: ReqwestClient,
    config: Arc<Config>,
    model_name: String,
}

// --- Trait Implementation (To be added below) ---
// --- Builder Function (To be added below) ---
#[async_trait]
impl EmbeddingClient for RestGeminiEmbeddingClient {
    #[instrument(skip(self, text), fields(task_type, model_name = %self.model_name), err)] // Add instrument
    async fn embed_content(
        &self,
        text: &str,
        task_type: &str,
    ) -> Result<Vec<f32>, AppError> {
        let api_key = self.config.gemini_api_key.as_ref()
            .ok_or_else(|| {
                error!("GEMINI_API_KEY not configured");
                AppError::ConfigError("GEMINI_API_KEY not configured".to_string())
            })?;

        // Construct URL (e.g., "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-exp-03-07:embedContent?key=...")
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/{}:embedContent?key={}",
            self.model_name, api_key
        );

        let request_body = EmbeddingRequest {
            model: &self.model_name,
            content: Content { parts: vec![Part { text }] },
            task_type,
        };

        let response = self.reqwest_client.post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "HTTP request to Gemini Embedding API failed");
                AppError::HttpRequestError(e.to_string()) // Or wrap the reqwest error
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.json::<GeminiApiErrorResponse>().await; // Try to parse API error
             error!(status = %status, error_details = ?error_body, "Gemini Embedding API returned error status");
             let error_message = error_body.map(|b| b.error.message).unwrap_or_else(|e| format!("Failed to parse error body: {}", e));
            // Consider mapping status codes to specific AppError variants if needed
            return Err(AppError::GeminiError(format!(
                "Gemini API error ({}): {}",
                status, error_message
            )));
        }

        let embedding_response = response.json::<EmbeddingResponse>().await
            .map_err(|e| {
                 error!(error = %e, "Failed to parse successful Gemini Embedding API response");
                AppError::SerializationError(format!("Failed to parse Gemini embedding response: {}", e))
            })?;

        Ok(embedding_response.embedding.values)
    }
}

// --- Builder Function (To be added below) ---
pub fn build_gemini_embedding_client(config: Arc<Config>) -> Result<RestGeminiEmbeddingClient, AppError> {
     // Consider adding timeout defaults
     let reqwest_client = ReqwestClient::builder()
         .timeout(Duration::from_secs(30)) // Example timeout
         .build()
         .map_err(|e| AppError::InternalServerError(format!("Failed to build Reqwest client: {}", e)))?; // Use appropriate error

     // Potentially allow model name override via config later
     let model_name = DEFAULT_EMBEDDING_MODEL.to_string();

     Ok(RestGeminiEmbeddingClient {
         reqwest_client,
         config,
         model_name,
     })
}

// --- Unit Tests (To be added later) ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    // Removed mockito import as we are doing integration tests
    use std::env;
    use dotenvy::dotenv;
    use std::sync::Arc;

    // Helper to create a mock config with or without API key
    fn create_test_config(api_key: Option<String>) -> Arc<Config> { // No need for pub(self)
        Arc::new(Config {
            database_url: Some("test_db_url".to_string()),
            gemini_api_key: api_key,
            // cookie_signing_key: Some("test_signing_key".to_string()), // Field does not exist in Config
            // Add other necessary default fields for Config if any
            ..Default::default() // Assuming Config derives Default or has a suitable default constructor
        })
    }

    #[test]
    fn test_build_gemini_embedding_client_success() {
        // Provide a dummy key for the config, builder doesn't validate it
        let config = create_test_config(Some("dummy-key".to_string()));
        let result = build_gemini_embedding_client(config);
        assert!(result.is_ok());
        let client = result.unwrap();
        // Check if the model name is set to the default
        assert_eq!(client.model_name, DEFAULT_EMBEDDING_MODEL);
        // We could potentially check the reqwest client's default timeout if needed,
        // but basic successful construction is the main goal here.
    }

    #[tokio::test]
    #[ignore] // Integration test: requires network and valid GEMINI_API_KEY env var
    async fn test_embed_content_success_integration() {
        dotenv().ok(); // Load .env file for API key

        let api_key = env::var("GEMINI_API_KEY")
            .expect("GEMINI_API_KEY must be set in environment for this integration test");

        let config = create_test_config(Some(api_key));
        
        // Use the builder to create the client for integration tests
        let client = build_gemini_embedding_client(config)
            .expect("Failed to build client for integration test");

        let text = "This is a test sentence for embedding.";
        // Use a valid task type from the Gemini docs
        let task_type = "RETRIEVAL_DOCUMENT";

        let result = client.embed_content(text, task_type).await;

        match result {
            Ok(embedding) => {
                assert!(!embedding.is_empty(), "Embedding vector should not be empty");
                // We don't know the exact dimension of gemini-embedding-exp-03-07,
                // but we can check it's non-zero.
                println!("Received embedding vector of dimension: {}", embedding.len());
            }
            Err(e) => {
                panic!("Integration test failed: embed_content returned error: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_embed_content_missing_api_key() {
        let config = create_test_config(None); // No API key
        let model_name = DEFAULT_EMBEDDING_MODEL.to_string();

        let reqwest_client = ReqwestClient::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name,
        };

        let text = "Test input text";
        let task_type = "RETRIEVAL_QUERY";

        let result = client.embed_content(text, task_type).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::ConfigError(msg) => {
                assert_eq!(msg, "GEMINI_API_KEY not configured");
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    // Note: Tests for specific network errors (e.g., timeout) or malformed responses
    // are harder to simulate reliably without mocking.

    #[tokio::test]
    #[ignore] // Integration test: requires network but should fail due to invalid key
    async fn test_embed_content_invalid_api_key_integration() {
        // No need for dotenv here, we are providing an invalid key directly
        let invalid_api_key = "invalid_test_api_key_string".to_string();
        let config = create_test_config(Some(invalid_api_key)); // Should be accessible now

        // Use the builder to create the client
        let client = build_gemini_embedding_client(config)
            .expect("Failed to build client for integration test");

        let text = "Test text for invalid key";
        let task_type = "RETRIEVAL_QUERY";

        let result = client.embed_content(text, task_type).await;

        assert!(result.is_err(), "Expected an error due to invalid API key");

        match result.err().unwrap() {
            AppError::GeminiError(msg) => {
                // Check if the error message indicates an API key issue (content may vary)
                println!("Received expected GeminiError: {}", msg);
                assert!(msg.contains("API key not valid") || msg.contains("invalid") || msg.contains("400"),
                        "Error message should indicate an invalid API key problem. Actual: {}", msg);
            }
            other_err => {
                panic!("Expected AppError::GeminiError, but got {:?}", other_err);
            }
        }
    }
} // <-- Move closing brace here