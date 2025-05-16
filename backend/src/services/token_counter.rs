use std::sync::Arc;
use tracing::{debug, error, info};
use crate::errors::Result;
use crate::services::tokenizer_service::{TokenizerService, TokenEstimate};
use crate::llm::gemini_client::GeminiClient;

/// Hybrid token counter that uses local tokenizer or cloud API based on model
#[derive(Debug)]
pub struct HybridTokenCounter {
    local_tokenizer: Arc<TokenizerService>,
    gemini_client: Option<Arc<GeminiClient>>,
    default_model: String,
}

impl HybridTokenCounter {
    /// Create a new hybrid token counter
    pub fn new(
        local_tokenizer: Arc<TokenizerService>, 
        gemini_client: Option<Arc<GeminiClient>>,
        default_model: String,
    ) -> Self {
        Self {
            local_tokenizer,
            gemini_client,
            default_model,
        }
    }
    
    /// Count tokens for the given text using the appropriate tokenizer
    pub fn count_tokens(&self, text: &str, model_name: Option<&str>) -> Result<Option<i32>> {
        let model = model_name.unwrap_or(&self.default_model);
        
        // For Gemini models, try to use the Gemini client if available
        if model.contains("gemini") && self.gemini_client.is_some() {
            let client = self.gemini_client.as_ref().unwrap();
            match client.count_tokens(text).await {
                Ok(count) => {
                    debug!("Counted {} tokens for '{}' using Gemini API", count, model);
                    Ok(Some(count as i32))
                },
                Err(e) => {
                    error!("Failed to count tokens using Gemini API: {}", e);
                    // Fall back to local tokenizer
                    debug!("Falling back to local tokenizer");
                    self.count_tokens_local(text)
                }
            }
        } else {
            // Use local tokenizer for all other models
            self.count_tokens_local(text)
        }
    }
    
    /// Count tokens using the local tokenizer
    fn count_tokens_local(&self, text: &str) -> Result<Option<i32>> {
        match self.local_tokenizer.count_tokens(text) {
            Ok(count) => {
                debug!("Counted {} tokens using local tokenizer", count);
                Ok(Some(count as i32))
            },
            Err(e) => {
                error!("Failed to count tokens using local tokenizer: {}", e);
                // Return None instead of failing
                Ok(None)
            }
        }
    }
}