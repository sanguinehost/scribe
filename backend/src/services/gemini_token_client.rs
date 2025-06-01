use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::errors::{AppError, Result};
use crate::services::tokenizer_service::TokenEstimate;

/// Simple client for Gemini API token counting
#[derive(Debug, Clone)]
pub struct GeminiTokenClient {
    client: Client,
    api_key: String,
    api_base_url: String,
}

/// Request body for countTokens API
#[derive(Debug, Serialize)]
struct CountTokensRequest {
    contents: Vec<ContentBlock>,
}

/// Request body for generateContent API (for usage metadata)
#[derive(Debug, Serialize)]
struct GenerateContentRequest {
    contents: Vec<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GenerationConfig>,
}

/// Content block for API requests
#[derive(Debug, Serialize, Deserialize)]
struct ContentBlock {
    parts: Vec<Part>,
    role: String,
}

/// Content part for API requests
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Part {
    Text { text: String },
    InlineData { inline_data: InlineData },
    FileData { file_data: FileData },
}

/// Inline data for multimodal content
#[derive(Debug, Serialize, Deserialize)]
struct InlineData {
    mime_type: String,
    data: String,
}

/// File data for multimodal content
#[derive(Debug, Serialize, Deserialize)]
struct FileData {
    file_uri: String,
    mime_type: String,
}

/// Generation configuration
#[derive(Debug, Serialize, Deserialize)]
struct GenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

/// Response from countTokens API
#[derive(Debug, Deserialize)]
struct CountTokensResponse {
    #[serde(rename = "totalTokens")]
    total_tokens: i32,
    // prompt_tokens_details is not used.
    // If it were, PromptTokensDetail struct would be needed.
}

// struct PromptTokensDetail {
//     modality: String,
//     #[serde(rename = "tokenCount")]
//     token_count: i32,
// }

/// Response from generateContent API
#[derive(Debug, Deserialize)]
struct GenerateContentResponse {
    // candidates are not used.
    // If they were, Candidate struct would be needed.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_metadata: Option<UsageMetadata>,
}

// Candidate from generateContent response
// #[derive(Debug, Deserialize)]
// struct Candidate {
//     content: ContentBlock, // Not used
//     #[serde(skip_serializing_if = "Option::is_none")]
//     finish_reason: Option<String>, // Not used
//     #[serde(skip_serializing_if = "Option::is_none")]
//     safety_ratings: Option<Vec<SafetyRating>>, // Not used
// }

// Safety rating from generateContent response
// #[derive(Debug, Deserialize)]
// struct SafetyRating {
//     category: String, // Not used
//     probability: String, // Not used
// }

/// Usage metadata from generateContent response
#[derive(Debug, Deserialize)]
struct UsageMetadata {
    #[serde(rename = "promptTokenCount")]
    prompt: i32,
    #[serde(rename = "candidatesTokenCount")]
    candidates: i32,
    #[serde(rename = "totalTokenCount")]
    total: i32,
}

impl GeminiTokenClient {
    /// Create a new `GeminiTokenClient`
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self::new_with_base_url(
            api_key,
            "https://generativelanguage.googleapis.com/v1beta".to_string(),
        )
    }

    /// Create a new `GeminiTokenClient` with custom base URL
    /// 
    /// # Panics
    /// 
    /// Panics if the HTTP client cannot be created.
    #[must_use]
    pub fn new_with_base_url(api_key: String, api_base_url: String) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            api_base_url,
        }
    }

    /// Count tokens for a text-only input
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or if the response cannot be parsed.
    pub async fn count_tokens(&self, text: &str, model: &str) -> Result<TokenEstimate> {
        debug!("Counting tokens for text with Gemini API");

        let url = format!(
            "{}/models/{}:countTokens?key={}",
            self.api_base_url, model, self.api_key
        );

        let request = CountTokensRequest {
            contents: vec![ContentBlock {
                parts: vec![Part::Text {
                    text: text.to_string(),
                }],
                role: "user".to_string(),
            }],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send countTokens request: {}", e);
                AppError::HttpRequestError(format!("Failed to count tokens: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Gemini API returned error {}: {}", status, error_text);
            return Err(AppError::GeminiError(format!(
                "Gemini API returned error {status}: {error_text}"
            )));
        }

        let count_response: CountTokensResponse = response.json().await.map_err(|e| {
            error!("Failed to parse countTokens response: {}", e);
            AppError::SerializationError(format!("Failed to parse token count response: {e}"))
        })?;

        debug!(
            "Received token count from API: {} tokens",
            count_response.total_tokens
        );

        // Convert API response to TokenEstimate (all text tokens for countTokens API)
        Ok(TokenEstimate {
            total: count_response.total_tokens.max(0).try_into().unwrap_or(0),
            text: count_response.total_tokens.max(0).try_into().unwrap_or(0),
            images: 0,
            video: 0,
            audio: 0,
            is_estimate: false, // Not an estimate since it came from the API
        })
    }

    /// Count tokens for multimodal content (uses generateContent with minimal output)
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, image encoding fails, or if the response cannot be parsed.
    pub async fn count_tokens_multimodal(
        &self,
        text: &str,
        images: Vec<(Vec<u8>, String)>, // (image_data, mime_type)
        model: &str,
    ) -> Result<TokenEstimate> {
        debug!("Counting tokens for multimodal content with Gemini API");

        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.api_base_url, model, self.api_key
        );

        // Create parts with text and images
        let mut parts = vec![Part::Text {
            text: text.to_string(),
        }];

        // Add images as inline data
        for (image_data, mime_type) in images {
            let base64_data =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &image_data);
            parts.push(Part::InlineData {
                inline_data: InlineData {
                    mime_type,
                    data: base64_data,
                },
            });
        }

        // Create request with minimal generation config to save tokens
        let request = GenerateContentRequest {
            contents: vec![ContentBlock {
                parts,
                role: "user".to_string(),
            }],
            generation_config: Some(GenerationConfig {
                max_output_tokens: Some(1), // Minimal output
                temperature: Some(0.0),     // Deterministic
            }),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send generateContent request: {}", e);
                AppError::HttpRequestError(format!("Failed to count multimodal tokens: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Gemini API returned error {}: {}", status, error_text);
            return Err(AppError::GeminiError(format!(
                "Gemini API returned error {status}: {error_text}"
            )));
        }

        let content_response: GenerateContentResponse = response.json().await.map_err(|e| {
            error!("Failed to parse generateContent response: {}", e);
            AppError::SerializationError(format!("Failed to parse token count response: {e}"))
        })?;

        // Extract usage metadata (if available)
        content_response.usage_metadata.map_or_else(|| {
            error!("Gemini API response did not include usage metadata");
            Err(AppError::GeminiError(
                "Gemini API response did not include usage metadata".to_string(),
            ))
        }, |usage| {
            debug!(
                "Received token counts - Prompt: {}, Output: {}, Total: {}",
                usage.prompt, usage.candidates, usage.total
            );

            // Since we can't differentiate between text and image tokens from the API directly,
            // we report the prompt tokens as the total with an unknown breakdown
            Ok(TokenEstimate {
                total: usage.prompt.max(0).try_into().unwrap_or(0),
                text: usage.prompt.max(0).try_into().unwrap_or(0), // Approximation - all counted as text
                images: 0,                               // No breakdown available from API
                video: 0,
                audio: 0,
                is_estimate: true, // This is an estimate of the breakdown
            })
        })
    }

    /// Count tokens for chat history
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or if the response cannot be parsed.
    pub async fn count_tokens_chat(
        &self,
        messages: &[(String, String)], // (role, text)
        model: &str,
    ) -> Result<TokenEstimate> {
        debug!("Counting tokens for chat history with Gemini API");

        let url = format!(
            "{}/models/{}:countTokens?key={}",
            self.api_base_url, model, self.api_key
        );

        // Convert messages to content blocks
        let contents = messages
            .iter()
            .map(|(role, text)| ContentBlock {
                parts: vec![Part::Text { text: text.clone() }],
                role: role.clone(),
            })
            .collect();

        let request = CountTokensRequest { contents };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send countTokens request: {}", e);
                AppError::HttpRequestError(format!("Failed to count chat tokens: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Gemini API returned error {}: {}", status, error_text);
            return Err(AppError::GeminiError(format!(
                "Gemini API returned error {status}: {error_text}"
            )));
        }

        let count_response: CountTokensResponse = response.json().await.map_err(|e| {
            error!("Failed to parse countTokens response: {}", e);
            AppError::SerializationError(format!("Failed to parse token count response: {e}"))
        })?;

        debug!(
            "Received token count from API for chat: {} tokens",
            count_response.total_tokens
        );

        // Convert API response to TokenEstimate (all text tokens for countTokens API)
        Ok(TokenEstimate {
            total: count_response.total_tokens.max(0).try_into().unwrap_or(0),
            text: count_response.total_tokens.max(0).try_into().unwrap_or(0),
            images: 0,
            video: 0,
            audio: 0,
            is_estimate: false, // Not an estimate since it came from the API
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a valid API key and will be ignored by default
    // To run these tests, use: cargo test -- --ignored

    #[tokio::test]
    #[ignore]
    async fn test_count_tokens() {
        let api_key_result = std::env::var("GEMINI_API_KEY");
        if api_key_result.is_err() {
            println!("GEMINI_API_KEY not set, skipping test_count_tokens.");
            return;
        }
        let api_key = api_key_result.unwrap();

        let client = GeminiTokenClient::new(api_key);
        let text = "The quick brown fox jumps over the lazy dog.";
        let model = "gemini-2.5-flash-preview-04-17";

        let result = client
            .count_tokens(text, model)
            .await
            .expect("Failed to count tokens");

        println!("Token count: {}", result.total);
        assert!(result.total > 0);
        assert_eq!(result.total, result.text);
    }

    #[tokio::test]
    #[ignore]
    async fn test_count_tokens_chat() {
        let api_key_result = std::env::var("GEMINI_API_KEY");
        if api_key_result.is_err() {
            println!("GEMINI_API_KEY not set, skipping test_count_tokens_chat.");
            return;
        }
        let api_key = api_key_result.unwrap();

        let client = GeminiTokenClient::new(api_key);
        let messages = vec![
            ("user".to_string(), "Hi my name is Bob".to_string()),
            ("model".to_string(), "Hi Bob!".to_string()),
            (
                "user".to_string(),
                "What is the meaning of life?".to_string(),
            ),
        ];
        let model = "gemini-2.5-flash-preview-04-17";

        let result = client
            .count_tokens_chat(&messages, model)
            .await
            .expect("Failed to count chat tokens");

        println!("Chat token count: {}", result.total);
        assert!(result.total > 0);
    }
}
