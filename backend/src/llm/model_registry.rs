// src/llm/model_registry.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Model capabilities including context window and output limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapabilities {
    /// Context window size in tokens
    pub context_window_size: u32,
    /// Maximum output tokens in a single generation
    pub max_output_tokens: u32,
    /// Model provider (e.g., "google", "local", "openai")
    pub provider: String,
    /// Whether this is a local model
    pub is_local: bool,
    /// Whether the model is currently available for use
    pub is_available: bool,
    /// Additional model-specific metadata
    pub metadata: HashMap<String, String>,
}

impl Default for ModelCapabilities {
    fn default() -> Self {
        Self {
            context_window_size: 8192, // Conservative default
            max_output_tokens: 2048,   // Conservative default
            provider: "unknown".to_string(),
            is_local: false,
            is_available: false,
            metadata: HashMap::new(),
        }
    }
}

/// Unified model registry for all supported models (local and cloud)
pub struct ModelRegistry {
    models: HashMap<String, ModelCapabilities>,
}

impl ModelRegistry {
    /// Create a new model registry with all known models
    pub fn new() -> Self {
        let mut registry = Self {
            models: HashMap::new(),
        };
        
        registry.register_cloud_models();
        registry.register_local_models();
        
        registry
    }
    
    /// Register Google Gemini cloud models
    fn register_cloud_models(&mut self) {
        // Gemini 2.5 Pro
        self.models.insert(
            "gemini-2.5-pro".to_string(),
            ModelCapabilities {
                context_window_size: 1048576, // 1M tokens
                max_output_tokens: 8192,      // Conservative for cost control
                provider: "google".to_string(),
                is_local: false,
                is_available: true, // Always available if API key is configured
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("model_family".to_string(), "gemini".to_string());
                    meta.insert("version".to_string(), "2.5".to_string());
                    meta.insert("type".to_string(), "pro".to_string());
                    meta
                },
            },
        );
        
        // Gemini 2.5 Flash
        self.models.insert(
            "gemini-2.5-flash".to_string(),
            ModelCapabilities {
                context_window_size: 1048576, // 1M tokens
                max_output_tokens: 8192,      // Conservative for cost control
                provider: "google".to_string(),
                is_local: false,
                is_available: true,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("model_family".to_string(), "gemini".to_string());
                    meta.insert("version".to_string(), "2.5".to_string());
                    meta.insert("type".to_string(), "flash".to_string());
                    meta
                },
            },
        );
        
        // Gemini 2.5 Flash Lite
        self.models.insert(
            "gemini-2.5-flash-lite-preview-06-17".to_string(),
            ModelCapabilities {
                context_window_size: 1048576, // 1M tokens
                max_output_tokens: 8192,      // Conservative for cost control
                provider: "google".to_string(),
                is_local: false,
                is_available: true,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("model_family".to_string(), "gemini".to_string());
                    meta.insert("version".to_string(), "2.5".to_string());
                    meta.insert("type".to_string(), "flash-lite".to_string());
                    meta
                },
            },
        );
    }
    
    /// Register local LlamaCpp models
    fn register_local_models(&mut self) {
        #[cfg(feature = "local-llm")]
        {
            use crate::llm::llamacpp::hardware::ModelSelection;
            
            for model in ModelSelection::all_models() {
                let mut metadata = HashMap::new();
                metadata.insert("model_family".to_string(), "local".to_string());
                metadata.insert("filename".to_string(), model.filename().to_string());
                metadata.insert("description".to_string(), model.description().to_string());
                
                self.models.insert(
                    model.model_id().to_string(),
                    ModelCapabilities {
                        context_window_size: model.context_window_size(),
                        max_output_tokens: model.max_output_tokens(),
                        provider: "llamacpp".to_string(),
                        is_local: true,
                        is_available: false, // Will be updated based on actual availability
                        metadata,
                    },
                );
            }
        }
    }
    
    /// Get model capabilities by model ID
    pub fn get_capabilities(&self, model_id: &str) -> Option<&ModelCapabilities> {
        self.models.get(model_id)
    }
    
    /// Get all registered models
    pub fn get_all_models(&self) -> &HashMap<String, ModelCapabilities> {
        &self.models
    }
    
    /// Get all cloud models
    pub fn get_cloud_models(&self) -> HashMap<String, &ModelCapabilities> {
        self.models
            .iter()
            .filter(|(_, caps)| !caps.is_local)
            .map(|(id, caps)| (id.clone(), caps))
            .collect()
    }
    
    /// Get all local models  
    pub fn get_local_models(&self) -> HashMap<String, &ModelCapabilities> {
        self.models
            .iter()
            .filter(|(_, caps)| caps.is_local)
            .map(|(id, caps)| (id.clone(), caps))
            .collect()
    }
    
    /// Update the availability status of a model
    pub fn set_model_availability(&mut self, model_id: &str, is_available: bool) {
        if let Some(capabilities) = self.models.get_mut(model_id) {
            capabilities.is_available = is_available;
        }
    }
    
    /// Set metadata for a model
    pub fn set_model_metadata(&mut self, model_id: &str, key: &str, value: &str) {
        if let Some(capabilities) = self.models.get_mut(model_id) {
            capabilities.metadata.insert(key.to_string(), value.to_string());
        }
    }
    
    /// Check if a model exists in the registry
    pub fn has_model(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }
    
    /// Get the recommended context settings for a model
    pub fn get_recommended_context_settings(&self, model_id: &str) -> Option<RecommendedContextSettings> {
        let capabilities = self.get_capabilities(model_id)?;
        
        // Calculate recommended token budgets based on context window size
        let context_window = capabilities.context_window_size;
        let total_limit = std::cmp::min(context_window, 200_000); // Cap at 200k for cost control
        
        // Allocate budgets based on context size
        let (history_ratio, rag_ratio) = if total_limit <= 8000 {
            (0.7, 0.25) // Small context: prioritize recent history
        } else if total_limit <= 32000 {
            (0.65, 0.3) // Medium context: balanced
        } else if total_limit <= 128000 {
            (0.6, 0.35) // Large context: more RAG
        } else {
            (0.55, 0.4) // Very large context: even more RAG
        };
        
        Some(RecommendedContextSettings {
            total_token_limit: total_limit,
            recent_history_budget: (total_limit as f32 * history_ratio) as u32,
            rag_budget: (total_limit as f32 * rag_ratio) as u32,
        })
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Recommended context settings for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedContextSettings {
    /// Total token limit for context
    pub total_token_limit: u32,
    /// Recommended budget for recent chat history
    pub recent_history_budget: u32,
    /// Recommended budget for RAG context
    pub rag_budget: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_model_registry_creation() {
        let registry = ModelRegistry::new();
        
        // Should have cloud models
        assert!(registry.has_model("gemini-2.5-pro"));
        assert!(registry.has_model("gemini-2.5-flash"));
        assert!(registry.has_model("gemini-2.5-flash-lite-preview-06-17"));
        
        // Cloud models should have 1M context
        let gemini_pro = registry.get_capabilities("gemini-2.5-pro").unwrap();
        assert_eq!(gemini_pro.context_window_size, 1048576);
        assert!(!gemini_pro.is_local);
        assert_eq!(gemini_pro.provider, "google");
    }
    
    #[cfg(feature = "local-llm")]
    #[test]
    fn test_local_models_registration() {
        let registry = ModelRegistry::new();
        
        // Should have local models when feature is enabled
        assert!(registry.has_model("gpt-oss-20b-q4"));
        assert!(registry.has_model("qwen3-30b-a3b-thinking-q4"));
        
        // Local models should have 131k context
        let gpt_oss = registry.get_capabilities("gpt-oss-20b-q4").unwrap();
        assert_eq!(gpt_oss.context_window_size, 131072);
        assert!(gpt_oss.is_local);
        assert_eq!(gpt_oss.provider, "llamacpp");
    }
    
    #[test]
    fn test_recommended_context_settings() {
        let registry = ModelRegistry::new();
        
        // Test Gemini model recommendations
        let settings = registry.get_recommended_context_settings("gemini-2.5-pro").unwrap();
        assert_eq!(settings.total_token_limit, 200_000); // Capped at 200k
        assert!(settings.recent_history_budget > 0);
        assert!(settings.rag_budget > 0);
        assert!(settings.recent_history_budget + settings.rag_budget <= settings.total_token_limit);
    }
}