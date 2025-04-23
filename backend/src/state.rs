// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::{Pool as DeadpoolPool};
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Use the AiClient trait from our llm module
use crate::llm::AiClient;

// --- DB Connection Pool Type ---
pub type DbPool = DeadpoolPool;
// Note: deadpool::Pool is already Cloneable.

// --- Shared application state ---
#[derive(Clone)] 
pub struct AppState {
    pub pool: DeadpoolPool,
    // Change to Arc<Config> and make public
    pub config: Arc<Config>, 
    // Remove gemini_client field for now
    // pub gemini_client: GeminiApiClient,
    #[cfg(test)] // Only include mock_response in test builds
    pub mock_llm_response: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    // Change to use the AiClient trait object
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
}

impl AppState {
    // Update constructor signature to accept the trait object Arc
    pub fn new(
        pool: DeadpoolPool,
        config: Arc<Config>,
        ai_client: Arc<dyn AiClient + Send + Sync>, // Use trait object Arc here
    ) -> Self {
        Self {
            pool,
            config,
            #[cfg(test)]
            mock_llm_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            ai_client, // Assign the passed-in client Arc
        }
    }
}
