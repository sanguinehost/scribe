// Gemini Embedding Client using REST API

use crate::config::Config;
use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use async_trait::async_trait;
use reqwest::Client as ReqwestClient;
// use serde::ser::SerializeStruct; // Not needed with skip_serializing_if
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, instrument};

// --- Request Structs ---

// --- Single Embedding Request Structs ---
#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    content: ContentWithTitle<'a>, // Changed
    #[serde(rename = "taskType")]
    task_type: &'a str,
}

// Content structure for embedding requests
#[derive(Serialize)]
struct ContentWithTitle<'a> {
    parts: Vec<Part<'a>>,
    // Note: title field removed as it's not supported by Gemini API
}

#[derive(Serialize)]
struct Part<'a> {
    text: &'a str,
}

// --- Single Embedding Response Structs ---
#[derive(Deserialize)]
struct EmbeddingResponse {
    embedding: EmbeddingData,
}

#[derive(Deserialize, Debug)]
struct EmbeddingData {
    values: Vec<f32>,
}

// --- Batch Embedding Request Structs ---

/// Public request struct for a single item in a batch embedding request.
#[derive(Debug, Clone)] // Added derive for easier use
pub struct BatchEmbeddingContentRequest<'a> {
    pub text: &'a str,
    pub task_type: &'a str,
}

/// Internal struct for a single request within the batchEmbedContents API payload.
#[derive(Serialize)]
struct SingleBatchRequestInternal<'a> {
    // Model is specified at the top level of the batch request for the API,
    // but we might include it here if we were to support per-item model overrides (not typical for this API).
    // For now, it's simpler to assume one model per batch call.
    content: ContentWithTitle<'a>,
    #[serde(rename = "taskType")]
    task_type: &'a str,
}

/// Internal container for the batchEmbedContents API payload.
#[derive(Serialize)]
struct BatchEmbedRequestContainerInternal<'a> {
    requests: Vec<SingleBatchRequestInternal<'a>>,
}


// --- Batch Embedding Response Structs ---

#[derive(Deserialize, Debug)] // Added Debug
struct BatchEmbeddingResponse {
    embeddings: Vec<EmbeddingData>, // API returns a list of embeddings
}


// --- Common Error Response Struct ---
#[derive(Deserialize, Debug)]
struct GeminiApiErrorResponse {
    error: GeminiApiError,
}
#[derive(Deserialize, Debug)]
struct GeminiApiError {
    // code: i32, // Commented out: unused field
    message: String,
    // status: String, // Commented out: unused field
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
    #[instrument(skip(self, text), fields(task_type, model_name = %self.model_name), err)]
    async fn embed_content(
        &self,
        text: &str,
        task_type: &str,
        _title: Option<&str>, // Keep parameter for trait compatibility, but ignore it
    ) -> Result<Vec<f32>, AppError> {
        let api_key = self.config.gemini_api_key.as_ref().ok_or_else(|| {
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
            content: ContentWithTitle {
                parts: vec![Part { text }],
            },
            task_type,
        };

        let response = self
            .reqwest_client
            .post(&url)
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
            let error_message = error_body
                .map(|b| b.error.message)
                .unwrap_or_else(|e| format!("Failed to parse error body: {}", e));
            // Consider mapping status codes to specific AppError variants if needed
            return Err(AppError::GeminiError(format!(
                "Gemini API error ({}): {}",
                status, error_message
            )));
        }

        let embedding_response = response.json::<EmbeddingResponse>().await.map_err(|e| {
            error!(error = %e, "Failed to parse successful Gemini Embedding API response");
            AppError::SerializationError(format!(
                "Failed to parse Gemini embedding response: {}",
                e
            ))
        })?;

        Ok(embedding_response.embedding.values)
    }

    #[instrument(skip(self, requests), fields(num_requests = requests.len(), model_name = %self.model_name), err)]
    async fn batch_embed_contents(
        &self,
        requests: Vec<BatchEmbeddingContentRequest<'_>>,
    ) -> Result<Vec<Vec<f32>>, AppError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let api_key = self.config.gemini_api_key.as_ref().ok_or_else(|| {
            error!("GEMINI_API_KEY not configured for batch embedding");
            AppError::ConfigError("GEMINI_API_KEY not configured".to_string())
        })?;

        // Construct URL (e.g., "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-exp-03-07:batchEmbedContents?key=...")
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/{}:batchEmbedContents?key={}",
            self.model_name, api_key
        );

        let internal_requests: Vec<SingleBatchRequestInternal> = requests
            .into_iter()
            .map(|req| SingleBatchRequestInternal {
                content: ContentWithTitle {
                    parts: vec![Part { text: req.text }],
                },
                task_type: req.task_type,
            })
            .collect();

        let request_body = BatchEmbedRequestContainerInternal {
            requests: internal_requests,
        };
        
        let response = self
            .reqwest_client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "HTTP request to Gemini Batch Embedding API failed");
                AppError::HttpRequestError(e.to_string())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.json::<GeminiApiErrorResponse>().await;
            error!(status = %status, error_details = ?error_body, "Gemini Batch Embedding API returned error status");
            let error_message = error_body
                .map(|b| b.error.message)
                .unwrap_or_else(|e| format!("Failed to parse error body: {}", e));
            return Err(AppError::GeminiError(format!(
                "Gemini Batch API error ({}): {}",
                status, error_message
            )));
        }

        let batch_response = response.json::<BatchEmbeddingResponse>().await.map_err(|e| {
            error!(error = %e, "Failed to parse successful Gemini Batch Embedding API response");
            AppError::SerializationError(format!(
                "Failed to parse Gemini batch embedding response: {}",
                e
            ))
        })?;

        Ok(batch_response
            .embeddings
            .into_iter()
            .map(|emb_data| emb_data.values)
            .collect())
    }
}

// --- Builder Function ---
pub fn build_gemini_embedding_client(
    config: Arc<Config>,
) -> Result<RestGeminiEmbeddingClient, AppError> {
    // Consider adding timeout defaults
    let reqwest_client = ReqwestClient::builder()
        .timeout(Duration::from_secs(30)) // Example timeout
        .build()
        .map_err(|e| {
            error!("Failed to build Reqwest client for Gemini: {}", e);
            AppError::InternalServerErrorGeneric(format!("Failed to build Reqwest client: {}", e))
        })?;

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
    use dotenvy::dotenv;
    use httpmock::prelude::*;
    use serde_json::json;
    // Removed unused: use std::env;
    use std::sync::Arc;

    // Helper to create a mock config with or without API key
    fn create_test_config(api_key: Option<String>) -> Arc<Config> {
        Arc::new(Config {
            database_url: Some("test_db_url".to_string()),
            gemini_api_key: api_key,
            ..Default::default()
        })
    }

    // Helper function for testing with mock server
    async fn custom_embed_content(
        client: &RestGeminiEmbeddingClient,
        server_url: &str,
        text: &str,
        task_type: &str,
        _title: Option<&str>, // Kept for compatibility but ignored
    ) -> Result<Vec<f32>, AppError> {
        let api_key =
            client.config.gemini_api_key.as_ref().ok_or_else(|| {
                AppError::ConfigError("GEMINI_API_KEY not configured".to_string())
            })?;

        // Use the mock server URL instead of the real API URL
        let url = format!(
            "{}/v1beta/{}:embedContent?key={}",
            server_url, client.model_name, api_key
        );

        let request_body = EmbeddingRequest {
            model: &client.model_name,
            content: ContentWithTitle {
                parts: vec![Part { text }],
            },
            task_type,
        };

        let response = client
            .reqwest_client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AppError::HttpRequestError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.json::<GeminiApiErrorResponse>().await;
            let error_message = error_body
                .map(|b| b.error.message)
                .unwrap_or_else(|e| format!("Failed to parse error body: {}", e));

            return Err(AppError::GeminiError(format!(
                "Gemini API error ({}): {}",
                status, error_message
            )));
        }

        let embedding_response = response.json::<EmbeddingResponse>().await.map_err(|e| {
            AppError::SerializationError(format!(
                "Failed to parse Gemini embedding response: {}",
                e
            ))
        })?;

        Ok(embedding_response.embedding.values)
    }

    // Helper function for testing batch_embed_contents with mock server
    #[allow(dead_code)] // This is a test helper
    async fn custom_batch_embed_contents(
        client: &RestGeminiEmbeddingClient,
        server_url: &str,
        requests: Vec<BatchEmbeddingContentRequest<'_>>,
    ) -> Result<Vec<Vec<f32>>, AppError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let api_key = client.config.gemini_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigError("GEMINI_API_KEY not configured".to_string())
        })?;

        let url = format!(
            "{}/v1beta/{}:batchEmbedContents?key={}",
            server_url, client.model_name, api_key
        );

        let internal_requests: Vec<SingleBatchRequestInternal> = requests
            .into_iter()
            .map(|req| SingleBatchRequestInternal {
                content: ContentWithTitle {
                    parts: vec![Part { text: req.text }],
                },
                task_type: req.task_type,
            })
            .collect();
        
        let request_body = BatchEmbedRequestContainerInternal {
            requests: internal_requests,
        };

        let response = client
            .reqwest_client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AppError::HttpRequestError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.json::<GeminiApiErrorResponse>().await;
            let error_message = error_body
                .map(|b| b.error.message)
                .unwrap_or_else(|e| format!("Failed to parse error body: {}", e));
            return Err(AppError::GeminiError(format!(
                "Gemini Batch API error ({}): {}",
                status, error_message
            )));
        }

        let batch_response = response.json::<BatchEmbeddingResponse>().await.map_err(|e| {
            AppError::SerializationError(format!(
                "Failed to parse Gemini batch embedding response: {}",
                e
            ))
        })?;
        
        Ok(batch_response
            .embeddings
            .into_iter()
            .map(|emb_data| emb_data.values)
            .collect())
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
    }

    // New unit tests with httpmock

    #[tokio::test]
    async fn test_embed_content_successful_response() {
        // Start a mock server
        let server = MockServer::start();
        let api_key = "test_api_key";

        // Create a mock for successful embedding response
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key)
                .header("content-type", "application/json")
                .json_body(json!({
                    "model": "models/test-model",
                    "content": {
                        "parts": [{ "text": "Test text" }]
                    },
                    "taskType": "RETRIEVAL_QUERY"
                }));

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "embedding": {
                        "values": [0.1, 0.2, 0.3, 0.4, 0.5]
                    }
                }));
        });

        // Create a client with our mocked server URL
        let config = create_test_config(Some(api_key.to_string()));
        let reqwest_client = ReqwestClient::new();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name: "models/test-model".to_string(),
        };

        // Call our custom function
        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "RETRIEVAL_QUERY",
            None, // title is None
        )
        .await;

        // Verify the mock was called
        mock.assert();

        // Verify the result
        assert!(result.is_ok());
        let embedding = result.unwrap();
        assert_eq!(embedding, vec![0.1, 0.2, 0.3, 0.4, 0.5]);
    }

    #[tokio::test]
    async fn test_embed_content_with_title() {
        let server = MockServer::start();
        let api_key = "test_api_key_with_title";
        let test_title = "My Document Title";

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key)
                .json_body(json!({
                    "model": "models/test-model",
                    "content": {
                        "parts": [{ "text": "Text with title" }]
                        // Note: title field removed as it's not supported by Gemini API
                    },
                    "taskType": "RETRIEVAL_DOCUMENT"
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "embedding": {
                        "values": [0.7, 0.8, 0.9]
                    }
                }));
        });

        let config = create_test_config(Some(api_key.to_string()));
        let client = RestGeminiEmbeddingClient {
            reqwest_client: ReqwestClient::new(),
            config,
            model_name: "models/test-model".to_string(),
        };

        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Text with title",
            "RETRIEVAL_DOCUMENT",
            Some(test_title), // Still pass title but it will be ignored
        )
        .await;

        mock.assert();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0.7, 0.8, 0.9]);
    }


    #[tokio::test]
    async fn test_embed_content_api_error_response() {
        // Start a mock server
        let server = MockServer::start();
        let api_key = "test_api_key";

        // Create a mock for API error response
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key);

            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!({
                    "error": {
                        "code": 400,
                        "message": "Invalid task type",
                        "status": "INVALID_ARGUMENT"
                    }
                }));
        });

        // Create a client with our mocked server URL
        let config = create_test_config(Some(api_key.to_string()));
        let reqwest_client = ReqwestClient::new();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name: "models/test-model".to_string(),
        };

        // Call our custom function
        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "INVALID_TASK_TYPE",
            None, // title is None
        )
        .await;

        // Verify the mock was called
        mock.assert();

        // Verify the result is an error
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::GeminiError(msg) => {
                assert!(msg.contains("400"));
                assert!(msg.contains("Invalid task type"));
            }
            err => panic!("Expected GeminiError, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_embed_content_malformed_response() {
        // Start a mock server
        let server = MockServer::start();
        let api_key = "test_api_key";

        // Create a mock for malformed response
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key);

            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"embedding":{"WRONG_FIELD":[0.1, 0.2]}}"#); // Missing "values" field
        });

        // Create a client with our mocked server URL
        let config = create_test_config(Some(api_key.to_string()));
        let reqwest_client = ReqwestClient::new();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name: "models/test-model".to_string(),
        };

        // Call our custom function
        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "RETRIEVAL_QUERY",
            None, // title is None
        )
        .await;

        // Verify the mock was called
        mock.assert();

        // Verify the result is a serialization error
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Failed to parse Gemini embedding response"));
            }
            err => panic!("Expected SerializationError, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_embed_content_http_error() {
        // Start a mock server
        let server = MockServer::start();
        let api_key = "test_api_key";

        // Create a mock for HTTP error
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key);

            then.status(500).body("Internal Server Error");
        });

        // Create a client with our mocked server URL
        let config = create_test_config(Some(api_key.to_string()));
        let reqwest_client = ReqwestClient::new();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name: "models/test-model".to_string(),
        };

        // Call our custom function
        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "RETRIEVAL_QUERY",
            None, // title is None
        )
        .await;

        // Verify the mock was called
        mock.assert();

        // Verify the result is an error
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::GeminiError(msg) => {
                assert!(msg.contains("500"));
            }
            err => panic!("Expected GeminiError, got {:?}", err),
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
        let title = None; // title is None

        let result = client.embed_content(text, task_type, title).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::ConfigError(msg) => {
                assert_eq!(msg, "GEMINI_API_KEY not configured");
            }
            _ => panic!("Expected ConfigError"),
        }
    }
    // Test for reqwest::Error during send()
    #[tokio::test]
    async fn test_embed_content_request_send_error() {
        // Start a mock server
        let server = MockServer::start();
        let api_key = "test_api_key";

        // Configure the mock to return a network error
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key);
            // Introduce a delay longer than the client timeout to cause send() to fail
            then.status(204) // Status doesn't matter much, it won't be reached
                .delay(Duration::from_millis(200)); // Delay > client timeout (100ms)
        });

        // Create a client pointing to the mock server
        let config = create_test_config(Some(api_key.to_string()));
        // Use a client with a short timeout to ensure the network error simulation triggers quickly if needed
        let reqwest_client = ReqwestClient::builder()
            .timeout(Duration::from_millis(100)) // Short timeout
            .build()
            .unwrap();

        let client = RestGeminiEmbeddingClient {
            reqwest_client,
            config,
            model_name: "models/test-model".to_string(),
        };

        // Call the custom function that uses the mock server URL
        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "RETRIEVAL_QUERY",
            None, // title is None
        )
        .await;

        // Verify the mock was called (or attempted)
        mock.assert(); // Asserts that the request matching the criteria was received

        // Verify the result is an HttpRequestError
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::HttpRequestError(msg) => {
                // The exact error message from reqwest might vary depending on the simulated error
                println!("Received expected HttpRequestError: {}", msg);
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            err => panic!("Expected HttpRequestError, got {:?}", err),
        }
    }

    // --- Integration Tests (Require API Key and Network) ---

    #[tokio::test]
    #[ignore] // Requires GEMINI_API_KEY
    async fn test_embed_content_success_integration() {
        // Correctly load config using dotenv and build the client
        dotenv().ok(); // Load .env for GEMINI_API_KEY
        let config = Arc::new(Config::load().expect("Failed to load config for integration test"));
        // Ensure config loaded the key
        assert!(
            config.gemini_api_key.is_some(),
            "GEMINI_API_KEY must be set in .env or environment for this integration test"
        );

        let client = build_gemini_embedding_client(config)
            .expect("Failed to build client for integration test");

        let text = "This is a test sentence for embedding.";
        let task_type = "RETRIEVAL_DOCUMENT"; // Use a valid task type
        let title = None; // Title is not supported by Gemini API

        let result = client.embed_content(text, task_type, title).await;

        match result {
            Ok(embedding) => {
                assert!(
                    !embedding.is_empty(),
                    "Embedding vector should not be empty"
                );
                println!(
                    "Received embedding vector of dimension: {}",
                    embedding.len()
                );
            }
            Err(e) => {
                panic!(
                    "Integration test failed: embed_content returned error: {:?}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires Network, but not a valid API key
    async fn test_embed_content_invalid_api_key_integration() {
        // Create config with an explicitly invalid key, DO NOT modify env vars
        let config = create_test_config(Some("invalid-key-for-test".to_string()));

        let client = build_gemini_embedding_client(config)
            .expect("Failed to build client with invalid key config");

        let text = "Test text for invalid key";
        let task_type = "RETRIEVAL_QUERY";
        let title = None;

        let result = client.embed_content(text, task_type, title).await;

        assert!(result.is_err(), "Expected an error due to invalid API key");

        match result.err().unwrap() {
            AppError::GeminiError(msg) => {
                println!("Received expected GeminiError: {}", msg);
                assert!(
                    msg.contains("API key not valid") || msg.contains("400"), // Gemini API might return 400 for invalid key
                    "Error message should indicate an invalid API key problem. Actual: {}",
                    msg
                );
            }
            other_err => {
                panic!("Expected AppError::GeminiError, but got {:?}", other_err);
            }
        }
    }

    // Test for API error status with a body that is *not* valid GeminiError JSON
    #[tokio::test]
    async fn test_embed_content_api_error_malformed_body() {
        let server = MockServer::start();
        let api_key = "test_api_key";
        let config = create_test_config(Some(api_key.to_string()));
        let client = RestGeminiEmbeddingClient {
            reqwest_client: ReqwestClient::new(),
            config,
            model_name: "models/test-model".to_string(),
        };

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key);
            then.status(500)
                .header("content-type", "text/plain") // Simulate non-JSON error body
                .body("Internal Server Error Text");
        });

        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            "RETRIEVAL_QUERY",
            None, // title is None
        )
        .await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::GeminiError(msg) => {
                assert!(msg.contains("Gemini API error (500 Internal Server Error)"));
                assert!(msg.contains("Failed to parse error body")); // Check that parsing failure is mentioned
            }
            _ => panic!("Expected AppError::GeminiError"),
        }
        mock.assert();
    }

    // Test using a different task type
    #[tokio::test]
    async fn test_embed_content_different_task_type() {
        let server = MockServer::start();
        let api_key = "test_api_key";
        let task_type = "RETRIEVAL_DOCUMENT"; // Different task type
        let config = create_test_config(Some(api_key.to_string()));
        let client = RestGeminiEmbeddingClient {
            reqwest_client: ReqwestClient::new(),
            config,
            model_name: "models/test-model".to_string(),
        };

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key)
                .json_body(json!({
                    "model": "models/test-model",
                    "content": {
                        "parts": [{ "text": "Test text" }]
                    },
                    "taskType": task_type // Verify this task type is sent
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "embedding": {
                        "values": [0.6, 0.7, 0.8]
                    }
                }));
        });

        let result = custom_embed_content(
            &client,
            &server.base_url(),
            "Test text",
            task_type,
            None, // title is None
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0.6, 0.7, 0.8]);
        mock.assert();
    }

    // Test with empty input text (expecting API error)
    #[tokio::test]
    async fn test_embed_content_empty_text() {
        let server = MockServer::start();
        let api_key = "test_api_key";
        let config = create_test_config(Some(api_key.to_string()));
        let client = RestGeminiEmbeddingClient {
            reqwest_client: ReqwestClient::new(),
            config,
            model_name: "models/test-model".to_string(),
        };

        // Assume the API returns a 400 Bad Request for empty text
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/test-model:embedContent")
                .query_param("key", api_key)
                .json_body(json!({
                    "model": "models/test-model",
                    "content": {
                        "parts": [{ "text": "" }] // Empty text
                    },
                    "taskType": "RETRIEVAL_QUERY"
                }));
            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!({
                    "error": {
                        "message": "Invalid content format."
                    }
                }));
        });

        let result =
            custom_embed_content(&client, &server.base_url(), "", "RETRIEVAL_QUERY", None).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::GeminiError(msg) => {
                assert!(msg.contains("400"));
                assert!(msg.contains("Invalid content format."));
            }
            _ => panic!("Expected AppError::GeminiError"),
        }
        mock.assert();
    }

    // --- Integration Tests (Require API Key and Network) ---
    // #[tokio::test]
    // #[ignore] // Ignore by default, requires real API key
}
