// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::{Pool as DeadpoolPool};
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Use the genai client and the builder function from our llm module
use genai::Client as GenAiClient;
// Removed unused import: use crate::llm::gemini_client::build_gemini_client;

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
    pub ai_client: Arc<GenAiClient>, // Add AI client
}

impl AppState {
    // Update constructor signature to accept Arc<GenAiClient>
    pub fn new(pool: DeadpoolPool, config: Arc<Config>, ai_client: Arc<GenAiClient>) -> Self {
        // Removed internal client creation logic
        Self {
            pool,
            config,
            #[cfg(test)]
            mock_llm_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            ai_client, // Assign the passed-in client Arc
        }
    }
}
