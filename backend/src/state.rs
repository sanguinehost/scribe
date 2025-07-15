// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::Pool as DeadpoolPool;
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Removed #[cfg(test)] - Mutex needed unconditionally now for tracker
use tokio::sync::{Mutex as TokioMutex, Semaphore}; // Add Mutex for test tracking and Semaphore for concurrency control
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
use crate::services::narrative_intelligence_service::NarrativeIntelligenceService;
// ECS Services
use crate::services::{
    EcsEntityManager, EcsGracefulDegradation, EcsEnhancedRagService, HybridQueryService, 
    ChronicleEventListener, ChronicleEcsTranslator, ChronicleService, WorldModelService, 
    AgenticOrchestrator, AgenticStateUpdateService, HierarchicalContextAssembler,
    IntentDetectionService, QueryStrategyPlanner,
    agentic::entity_resolution_tool::EntityResolutionTool,
    agentic::tactical_agent::TacticalAgent,
};
use crate::config::NarrativeFeatureFlags;
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
    // ECS Services
    pub redis_client: Arc<redis::Client>,
    pub feature_flags: Arc<NarrativeFeatureFlags>,
    pub ecs_entity_manager: Arc<EcsEntityManager>,
    pub ecs_graceful_degradation: Arc<EcsGracefulDegradation>,
    pub ecs_enhanced_rag_service: Arc<EcsEnhancedRagService>,
    pub hybrid_query_service: Arc<HybridQueryService>,
    pub chronicle_event_listener: Arc<ChronicleEventListener>,
    pub chronicle_ecs_translator: Arc<ChronicleEcsTranslator>,
    pub chronicle_service: Arc<ChronicleService>,
    pub world_model_service: Arc<WorldModelService>,
    pub agentic_orchestrator: Arc<AgenticOrchestrator>,
    pub agentic_state_update_service: Arc<AgenticStateUpdateService>,
    pub hierarchical_context_assembler: Option<Arc<HierarchicalContextAssembler>>,
    pub tactical_agent: Option<Arc<TacticalAgent>>,
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
    pub narrative_intelligence_service: Option<Arc<NarrativeIntelligenceService>>, // Flash-integrated narrative orchestrator
    pub rechronicle_semaphore: Arc<Semaphore>, // Global semaphore to limit concurrent re-chronicle jobs
    // ECS Services
    pub redis_client: Arc<redis::Client>,
    pub feature_flags: Arc<NarrativeFeatureFlags>,
    pub ecs_entity_manager: Arc<EcsEntityManager>,
    pub ecs_graceful_degradation: Arc<EcsGracefulDegradation>,
    pub ecs_enhanced_rag_service: Arc<EcsEnhancedRagService>,
    pub hybrid_query_service: Arc<HybridQueryService>,
    pub chronicle_event_listener: Arc<ChronicleEventListener>,
    pub chronicle_ecs_translator: Arc<ChronicleEcsTranslator>,
    pub chronicle_service: Arc<ChronicleService>,
    pub world_model_service: Arc<WorldModelService>,
    pub agentic_orchestrator: Arc<AgenticOrchestrator>,
    pub agentic_state_update_service: Arc<AgenticStateUpdateService>,
    pub hierarchical_context_assembler: Option<Arc<HierarchicalContextAssembler>>,
    pub tactical_agent: Option<Arc<TacticalAgent>>,
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
            .field("narrative_intelligence_service", &"<Option<Arc<NarrativeIntelligenceService>>>") // Flash-integrated narrative orchestrator
            .field("rechronicle_semaphore", &"<Arc<Semaphore>>") // Added for re-chronicle concurrency control
            .field("redis_client", &"<Arc<redis::Client>>") // ECS Redis cache
            .field("feature_flags", &"<Arc<NarrativeFeatureFlags>>") // ECS feature control
            .field("ecs_entity_manager", &"<Arc<EcsEntityManager>>") // ECS core service
            .field("ecs_graceful_degradation", &"<Arc<EcsGracefulDegradation>>") // ECS degradation handling
            .field("ecs_enhanced_rag_service", &"<Arc<EcsEnhancedRagService>>") // ECS RAG enhancement
            .field("hybrid_query_service", &"<Arc<HybridQueryService>>") // ECS hybrid queries
            .field("world_model_service", &"<Arc<WorldModelService>>") // ECS world model service
            .field("agentic_orchestrator", &"<Arc<AgenticOrchestrator>>") // Agentic context orchestration
            .field("agentic_state_update_service", &"<Arc<AgenticStateUpdateService>>") // Agentic state updates
            .field("hierarchical_context_assembler", &"<Option<Arc<HierarchicalContextAssembler>>>") // Hierarchical context assembly
            .field("tactical_agent", &"<Option<Arc<TacticalAgent>>>") // Tactical layer agent
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
            narrative_intelligence_service: None, // Will be set later after AppState is fully constructed
            rechronicle_semaphore: Arc::new(Semaphore::new(20)), // Allow 20 concurrent re-chronicle jobs globally
            // ECS Services
            redis_client: services.redis_client,
            feature_flags: services.feature_flags,
            ecs_entity_manager: services.ecs_entity_manager,
            ecs_graceful_degradation: services.ecs_graceful_degradation,
            ecs_enhanced_rag_service: services.ecs_enhanced_rag_service,
            hybrid_query_service: services.hybrid_query_service,
            chronicle_event_listener: services.chronicle_event_listener,
            chronicle_ecs_translator: services.chronicle_ecs_translator,
            chronicle_service: services.chronicle_service,
            world_model_service: services.world_model_service,
            agentic_orchestrator: services.agentic_orchestrator,
            agentic_state_update_service: services.agentic_state_update_service,
            hierarchical_context_assembler: services.hierarchical_context_assembler,
            tactical_agent: services.tactical_agent,
        }
    }

    /// Set the narrative intelligence service after AppState construction  
    /// This is needed to break the circular dependency during construction
    pub fn set_narrative_intelligence_service(&mut self, service: Arc<NarrativeIntelligenceService>) {
        self.narrative_intelligence_service = Some(service);
    }
    
    /// Set the hierarchical context assembler after AppState construction
    /// This is needed to break the circular dependency since EntityResolutionTool needs AppState
    pub fn set_hierarchical_context_assembler(&mut self, entity_resolution_tool: Arc<EntityResolutionTool>) {
        // Create new HierarchicalContextAssembler with the proper EntityResolutionTool
        let assembler = Arc::new(HierarchicalContextAssembler::new(
            self.ai_client.clone(),
            Arc::new(IntentDetectionService::new(self.ai_client.clone())),
            Arc::new(QueryStrategyPlanner::new(self.ai_client.clone())),
            entity_resolution_tool,
            self.encryption_service.clone(),
            Arc::new(self.pool.clone()),
        ));
        self.hierarchical_context_assembler = Some(assembler);
    }
    
    /// Set the tactical agent after AppState construction
    /// This uses the factory method to create a properly configured TacticalAgent
    pub fn set_tactical_agent(&mut self) {
        use crate::services::agentic::factory::AgenticNarrativeFactory;
        let tactical_agent = AgenticNarrativeFactory::create_tactical_agent(&Arc::new(self.clone()));
        self.tactical_agent = Some(tactical_agent);
    }
}
