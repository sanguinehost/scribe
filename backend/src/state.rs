// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::Pool as DeadpoolPool;
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Removed #[cfg(test)] - Mutex needed unconditionally now for tracker
use tokio::sync::Mutex as TokioMutex; // Add Mutex for test tracking
// Use the AiClient trait from our llm module
use crate::llm::AiClient;
use crate::llm::EmbeddingClient; // Add this
use crate::services::embeddings::EmbeddingPipelineServiceTrait;
// Remove concrete service import, use trait
// use crate::vector_db::QdrantClientService;
use crate::vector_db::qdrant_client::QdrantClientServiceTrait;
// use crate::auth::user_store::Backend as AuthBackend; // For axum-login
use crate::auth::user_store::Backend as AuthBackend; // Added for shared AuthBackend
use crate::services::EmailService; // For email service
use crate::services::chat_override_service::ChatOverrideService; // <<< ADDED THIS IMPORT
use crate::services::encryption_service::EncryptionService; // Added for EncryptionService
use crate::services::file_storage_service::FileStorageService; // Added for FileStorageService
use crate::services::hybrid_token_counter::HybridTokenCounter; // Added for token counting
use crate::services::lorebook::LorebookService; // Added for LorebookService
use crate::services::user_persona_service::UserPersonaService; // <<< ADDED THIS IMPORT
use std::fmt;
use uuid::Uuid; // For embedding_call_tracker // For manual Debug impl

// --- DB Connection Pool Type ---
pub type DbPool = DeadpoolPool;
// Note: deadpool::Pool is already Cloneable.

/// Configuration for `AppState` services to reduce constructor arguments
pub struct AppStateServices {
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
    pub embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
    pub qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    pub embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
    pub chat_override_service: Arc<ChatOverrideService>,
    pub user_persona_service: Arc<UserPersonaService>,
    pub token_counter: Arc<HybridTokenCounter>,
    pub encryption_service: Arc<EncryptionService>,
    pub lorebook_service: Arc<LorebookService>,
    pub auth_backend: Arc<AuthBackend>,
    pub file_storage_service: Arc<FileStorageService>,
    pub email_service: Arc<dyn EmailService + Send + Sync>,
}

// --- Shared application state ---
#[derive(Clone)]
pub struct AppState {
    pub pool: DeadpoolPool,
    // Change to Arc<Config> and make public
    pub config: Arc<Config>,
    // Remove gemini_client field for now
    // pub gemini_client: GeminiApiClient,
    // #[cfg(test)] // Remove cfg(test)
    // pub mock_llm_response: std::sync::Arc<tokio::sync::Mutex<Option<String>>>, // Keep for now if other tests use it
    // Change to use the AiClient trait object
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
    pub embedding_client: Arc<dyn EmbeddingClient + Send + Sync>, // Add Send + Sync
    // Change to use the trait object for Qdrant service
    pub qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    pub embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>, // Add Send + Sync
    pub chat_override_service: Arc<ChatOverrideService>, // <<< ADDED THIS FIELD
    pub user_persona_service: Arc<UserPersonaService>,   // <<< ADDED THIS FIELD
    // Remove #[cfg(test)]
    pub embedding_call_tracker: Arc<TokioMutex<Vec<Uuid>>>, // Track message IDs for embedding calls
    pub token_counter: Arc<HybridTokenCounter>,             // Added for token counting
    pub encryption_service: Arc<EncryptionService>, // Added for lorebook and other encryption needs
    pub lorebook_service: Arc<LorebookService>,     // Added for LorebookService
    pub auth_backend: Arc<AuthBackend>,             // Added for shared AuthBackend instance
    pub file_storage_service: Arc<FileStorageService>, // Added for file storage
    pub email_service: Arc<dyn EmailService + Send + Sync>, // Added for email service
}

// Manual Debug implementation for AppState
impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("pool", &"<DeadpoolPool>") // Placeholder for pool
            .field("config", &self.config) // Config should be Debug
            .field("ai_client", &"<Arc<dyn AiClient>>")
            .field("embedding_client", &"<Arc<dyn EmbeddingClient>>")
            .field("qdrant_service", &"<Arc<dyn QdrantClientServiceTrait>>")
            .field(
                "embedding_pipeline_service",
                &"<Arc<dyn EmbeddingPipelineServiceTrait>>",
            )
            .field("chat_override_service", &"<Arc<ChatOverrideService>>") // <<< ADDED THIS LINE FOR DEBUG
            .field("user_persona_service", &"<Arc<UserPersonaService>>") // <<< ADDED THIS LINE FOR DEBUG
            .field("embedding_call_tracker", &"<Arc<TokioMutex<Vec<Uuid>>>>") // Or try to debug its contents if safe
            .field("token_counter", &"<Arc<HybridTokenCounter>>") // Added
            .field("encryption_service", &"<Arc<EncryptionService>>") // Added
            .field("lorebook_service", &"<Arc<LorebookService>>") // Added for LorebookService
            .field("auth_backend", &"<Arc<AuthBackend>>") // Added
            .field("file_storage_service", &"<Arc<FileStorageService>>") // Added
            .field("email_service", &"<Arc<dyn EmailService>>") // Added for email service
            .finish()
    }
}

impl AppState {
    /// Create new `AppState` with reduced constructor arguments
    #[must_use]
    pub fn new(pool: DeadpoolPool, config: Arc<Config>, services: AppStateServices) -> Self {
        Self {
            pool,
            config,
            ai_client: services.ai_client,
            embedding_client: services.embedding_client,
            qdrant_service: services.qdrant_service,
            embedding_pipeline_service: services.embedding_pipeline_service,
            chat_override_service: services.chat_override_service,
            user_persona_service: services.user_persona_service,
            embedding_call_tracker: Arc::new(TokioMutex::new(Vec::new())),
            token_counter: services.token_counter,
            encryption_service: services.encryption_service,
            lorebook_service: services.lorebook_service,
            auth_backend: services.auth_backend,
            file_storage_service: services.file_storage_service,
            email_service: services.email_service,
        }
    }
}
