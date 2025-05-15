use std::path::PathBuf;
use tracing::{debug, warn};

use crate::errors::{AppError, Result};
use crate::services::tokenizer_service::{TokenEstimate, TokenizerService};
use crate::services::gemini_token_client::GeminiTokenClient;

/// HybridTokenCounter combines local tokenization with API-based counting
///
/// This service provides a hybrid approach to token counting:
/// 1. Local estimation using TokenizerService for quick client-side validation
/// 2. API-based token counting using GeminiTokenClient for exact billing
/// 3. Fallback behavior when API is unavailable
#[derive(Debug, Clone)]
pub struct HybridTokenCounter {
    /// Local tokenizer for offline estimation
    tokenizer: TokenizerService,
    /// Gemini API client for online verification (optional)
    api_client: Option<GeminiTokenClient>,
    /// Default model to use for token counting
    default_model: String,
}

/// Counting mode for the hybrid token counter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountingMode {
    /// Use only local estimation
    LocalOnly,
    /// Use only API-based counting
    ApiOnly,
    /// Try API first, fall back to local if unavailable
    HybridPreferApi,
    /// Try local first, validate with API if available
    HybridPreferLocal,
}

impl HybridTokenCounter {
    /// Create a new HybridTokenCounter with both local and API-based counting
    pub fn new(
        tokenizer: TokenizerService,
        api_client: Option<GeminiTokenClient>,
        default_model: impl Into<String>,
    ) -> Self {
        Self {
            tokenizer,
            api_client,
            default_model: default_model.into(),
        }
    }
    
    /// Create a new HybridTokenCounter with only local estimation
    pub fn new_local_only(tokenizer: TokenizerService) -> Self {
        Self {
            tokenizer,
            api_client: None,
            default_model: "gemini-1.5-pro".to_string(), // Default model
        }
    }
    
    /// Create a new HybridTokenCounter with only API-based counting
    pub fn new_api_only(
        api_client: GeminiTokenClient,
        default_model: impl Into<String>,
    ) -> Self {
        // Still need a tokenizer for fallback
        let tokenizer = TokenizerService::new("/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model")
            .expect("Failed to create tokenizer for fallback");
            
        Self {
            tokenizer,
            api_client: Some(api_client),
            default_model: default_model.into(),
        }
    }
    
    /// Set the default model to use for token counting
    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = model.into();
        self
    }
    
    /// Count tokens for a text input, using the specified counting mode
    pub async fn count_tokens(
        &self,
        text: &str,
        mode: CountingMode,
        model: Option<&str>,
    ) -> Result<TokenEstimate> {
        let model_name = model.unwrap_or(&self.default_model);
        
        match mode {
            CountingMode::LocalOnly => {
                debug!("Counting tokens using local estimation only");
                self.tokenizer.estimate_text_tokens(text)
            },
            
            CountingMode::ApiOnly => {
                debug!("Counting tokens using API only");
                if let Some(client) = &self.api_client {
                    client.count_tokens(text, model_name).await
                } else {
                    Err(AppError::ConfigError("API client not configured for token counting".to_string()))
                }
            },
            
            CountingMode::HybridPreferApi => {
                debug!("Counting tokens using hybrid approach (API preferred)");
                if let Some(client) = &self.api_client {
                    match client.count_tokens(text, model_name).await {
                        Ok(estimate) => Ok(estimate),
                        Err(e) => {
                            warn!("API token counting failed, falling back to local estimation: {}", e);
                            self.tokenizer.estimate_text_tokens(text)
                        }
                    }
                } else {
                    debug!("No API client available, using local token estimation");
                    self.tokenizer.estimate_text_tokens(text)
                }
            },
            
            CountingMode::HybridPreferLocal => {
                debug!("Counting tokens using hybrid approach (local preferred)");
                // Always get local estimate first
                let local_estimate = self.tokenizer.estimate_text_tokens(text)?;
                
                // If API client is available, validate with API
                if let Some(client) = &self.api_client {
                    match client.count_tokens(text, model_name).await {
                        Ok(api_estimate) => {
                            // Log any significant discrepancies
                            let difference = if api_estimate.total > local_estimate.total {
                                api_estimate.total as f64 / local_estimate.total as f64
                            } else {
                                local_estimate.total as f64 / api_estimate.total as f64
                            };
                            
                            if difference > 1.1 { // More than 10% difference
                                warn!("Token count discrepancy - Local: {}, API: {}", 
                                      local_estimate.total, api_estimate.total);
                            }
                            
                            // Return the API estimate
                            Ok(api_estimate)
                        },
                        Err(e) => {
                            warn!("API token counting failed, using local estimation: {}", e);
                            Ok(local_estimate)
                        }
                    }
                } else {
                    // No API client, use local estimate
                    Ok(local_estimate)
                }
            }
        }
    }
    
    /// Count tokens for multimodal content
    pub async fn count_tokens_multimodal(
        &self,
        text: &str,
        image_paths: Option<&[PathBuf]>,
        video_duration: Option<f64>,
        audio_duration: Option<f64>,
        mode: CountingMode,
        model: Option<&str>,
    ) -> Result<TokenEstimate> {
        let model_name = model.unwrap_or(&self.default_model);
        
        // For LocalOnly mode, use the tokenizer's estimate
        if mode == CountingMode::LocalOnly {
            debug!("Counting multimodal tokens using local estimation only");
            return self.tokenizer.estimate_content_tokens(
                Some(text),
                image_paths,
                video_duration,
                audio_duration,
            );
        }
        
        // For API modes, try to use the API if available
        if let Some(client) = &self.api_client {
            // Currently, we can only handle images through the API client
            // Other media types need more complex handling or separate API calls
            if mode == CountingMode::ApiOnly && (video_duration.is_some() || audio_duration.is_some()) {
                return Err(AppError::NotImplemented(
                    "API-only token counting for video and audio is not implemented".to_string()
                ));
            }
            
            // For images, convert image paths to image data
            let mut image_data = Vec::new();
            if let Some(paths) = image_paths {
                for path in paths {
                    if !path.exists() {
                        warn!("Image path does not exist: {}", path.display());
                        continue;
                    }
                    
                    match std::fs::read(path) {
                        Ok(data) => {
                            // Determine mime type from extension
                            let mime_type = match path.extension().and_then(|e| e.to_str()) {
                                Some("jpg") | Some("jpeg") => "image/jpeg",
                                Some("png") => "image/png",
                                Some("webp") => "image/webp",
                                Some("gif") => "image/gif",
                                _ => "image/jpeg", // Default to JPEG
                            };
                            
                            image_data.push((data, mime_type.to_string()));
                        },
                        Err(e) => {
                            warn!("Failed to read image file {}: {}", path.display(), e);
                        }
                    }
                }
            }
            
            // Try to get token count from API
            let api_result = if !image_data.is_empty() {
                client.count_tokens_multimodal(text, image_data, model_name).await
            } else {
                client.count_tokens(text, model_name).await
            };
            
            // Handle API result based on mode
            match (api_result, mode) {
                (Ok(api_estimate), _) => {
                    // For video and audio, add local estimates
                    if video_duration.is_some() || audio_duration.is_some() {
                        let mut result = api_estimate;
                        
                        if let Some(duration) = video_duration {
                            let video_estimate = self.tokenizer.estimate_video_tokens(duration);
                            result.video = video_estimate.video;
                            result.total += video_estimate.video;
                            result.is_estimate = true;
                        }
                        
                        if let Some(duration) = audio_duration {
                            let audio_estimate = self.tokenizer.estimate_audio_tokens(duration);
                            result.audio = audio_estimate.audio;
                            result.total += audio_estimate.audio;
                            result.is_estimate = true;
                        }
                        
                        Ok(result)
                    } else {
                        // No video/audio, return API estimate directly
                        Ok(api_estimate)
                    }
                },
                (Err(e), CountingMode::ApiOnly) => {
                    // API-only mode, propagate error
                    Err(e)
                },
                (Err(e), _) => {
                    // Hybrid modes, fall back to local estimation
                    warn!("API token counting failed, falling back to local estimation: {}", e);
                    self.tokenizer.estimate_content_tokens(
                        Some(text),
                        image_paths,
                        video_duration,
                        audio_duration,
                    )
                }
            }
        } else if mode == CountingMode::ApiOnly {
            // API-only mode but no API client
            Err(AppError::ConfigError("API client not configured for token counting".to_string()))
        } else {
            // No API client for hybrid modes, use local estimation
            debug!("No API client available, using local token estimation");
            self.tokenizer.estimate_content_tokens(
                Some(text),
                image_paths,
                video_duration,
                audio_duration,
            )
        }
    }
    
    /// Count tokens for chat history
    pub async fn count_tokens_chat(
        &self,
        messages: &[(String, String)], // (role, text)
        mode: CountingMode,
        model: Option<&str>,
    ) -> Result<TokenEstimate> {
        let model_name = model.unwrap_or(&self.default_model);
        
        // For LocalOnly mode, estimate each message separately
        if mode == CountingMode::LocalOnly {
            debug!("Counting chat tokens using local estimation only");
            let mut total_estimate = TokenEstimate::default();
            
            for (_, text) in messages {
                let message_estimate = self.tokenizer.estimate_text_tokens(text)?;
                total_estimate.text += message_estimate.text;
                total_estimate.total += message_estimate.total;
            }
            
            return Ok(total_estimate);
        }
        
        // For API modes, try to use the API if available
        if let Some(client) = &self.api_client {
            let api_result = client.count_tokens_chat(messages, model_name).await;
            
            match (api_result, mode) {
                (Ok(api_estimate), _) => {
                    // API call succeeded
                    Ok(api_estimate)
                },
                (Err(e), CountingMode::ApiOnly) => {
                    // API-only mode, propagate error
                    Err(e)
                },
                (Err(e), _) => {
                    // Hybrid modes, fall back to local estimation
                    warn!("API token counting failed, falling back to local estimation: {}", e);
                    let mut total_estimate = TokenEstimate::default();
                    
                    for (_, text) in messages {
                        let message_estimate = self.tokenizer.estimate_text_tokens(text)?;
                        total_estimate.text += message_estimate.text;
                        total_estimate.total += message_estimate.total;
                    }
                    
                    Ok(total_estimate)
                }
            }
        } else if mode == CountingMode::ApiOnly {
            // API-only mode but no API client
            Err(AppError::ConfigError("API client not configured for token counting".to_string()))
        } else {
            // No API client for hybrid modes, use local estimation
            debug!("No API client available, using local token estimation");
            let mut total_estimate = TokenEstimate::default();
            
            for (_, text) in messages {
                let message_estimate = self.tokenizer.estimate_text_tokens(text)?;
                total_estimate.text += message_estimate.text;
                total_estimate.total += message_estimate.total;
            }
            
            Ok(total_estimate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    fn get_test_model_path() -> PathBuf {
        PathBuf::from("/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model")
    }
    
    #[test]
    fn test_hybrid_counter_local_only() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        let counter = HybridTokenCounter::new_local_only(tokenizer);
        
        assert!(counter.api_client.is_none());
        assert_eq!(counter.default_model, "gemini-1.5-pro");
    }
    
    #[tokio::test]
    async fn test_count_tokens_local_only() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        let counter = HybridTokenCounter::new_local_only(tokenizer);
        
        let text = "This is a test message";
        let estimate = counter.count_tokens(text, CountingMode::LocalOnly, None)
            .await
            .expect("Failed to count tokens locally");
        
        assert!(estimate.text > 0);
        assert_eq!(estimate.images, 0);
        assert_eq!(estimate.video, 0);
        assert_eq!(estimate.audio, 0);
        assert!(!estimate.is_estimate); // Text estimation is not an estimate
    }
    
    #[tokio::test]
    async fn test_count_multimodal_local_only() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        let counter = HybridTokenCounter::new_local_only(tokenizer);
        
        let text = "This is a test message with video and audio";
        let video_duration = Some(5.0); // 5 seconds
        let audio_duration = Some(30.0); // 30 seconds
        
        let estimate = counter.count_tokens_multimodal(
            text,
            None, // No images
            video_duration,
            audio_duration,
            CountingMode::LocalOnly,
            None,
        )
        .await
        .expect("Failed to count multimodal tokens locally");
        
        assert!(estimate.text > 0);
        assert_eq!(estimate.images, 0);
        
        // Video: 5.0 seconds * 263 tokens/second = 1315
        assert_eq!(estimate.video, 1315);
        
        // Audio: 30.0 seconds * 32 tokens/second = 960
        assert_eq!(estimate.audio, 960);
        
        // Total should be sum of all parts
        assert_eq!(estimate.total, estimate.text + estimate.video + estimate.audio);
        
        // Mixed content should be marked as an estimate
        assert!(estimate.is_estimate);
    }
    
    #[tokio::test]
    async fn test_count_chat_local_only() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        let counter = HybridTokenCounter::new_local_only(tokenizer);
        
        let messages = vec![
            ("user".to_string(), "Hi my name is Bob".to_string()),
            ("model".to_string(), "Hi Bob!".to_string()),
            ("user".to_string(), "What is the meaning of life?".to_string()),
        ];
        
        let estimate = counter.count_tokens_chat(
            &messages,
            CountingMode::LocalOnly,
            None,
        )
        .await
        .expect("Failed to count chat tokens locally");
        
        assert!(estimate.text > 0);
        assert_eq!(estimate.images, 0);
        assert_eq!(estimate.video, 0);
        assert_eq!(estimate.audio, 0);
        
        // Check if local estimation produces reasonable results
        let single_estimate = counter.count_tokens(
            "Hi my name is Bob",
            CountingMode::LocalOnly,
            None,
        )
        .await
        .expect("Failed to count single message tokens");
        
        // Chat count should be greater than a single message
        assert!(estimate.total > single_estimate.total);
    }
    
    // Tests that require an API key are marked as ignored
    // To run these tests: cargo test -- --ignored
    
    #[tokio::test]
    #[ignore]
    async fn test_api_token_counting() {
        let api_key = std::env::var("GEMINI_API_KEY")
            .expect("GEMINI_API_KEY environment variable not set");
            
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        let api_client = GeminiTokenClient::new(api_key);
        let counter = HybridTokenCounter::new(tokenizer, Some(api_client), "gemini-1.5-pro");
        
        let text = "The quick brown fox jumps over the lazy dog.";
        
        let api_estimate = counter.count_tokens(text, CountingMode::ApiOnly, None)
            .await
            .expect("Failed to count tokens with API");
            
        let local_estimate = counter.count_tokens(text, CountingMode::LocalOnly, None)
            .await
            .expect("Failed to count tokens locally");
            
        println!("API estimate: {} tokens", api_estimate.total);
        println!("Local estimate: {} tokens", local_estimate.total);
        
        // Check that both methods return non-zero token counts
        assert!(api_estimate.total > 0);
        assert!(local_estimate.total > 0);
    }
}