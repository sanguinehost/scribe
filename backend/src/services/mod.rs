pub mod agentic;
pub mod character_generation;
pub mod character_parser;
pub mod character_service;
pub mod chat;
pub mod chat_override_service;
pub mod chronicle_backfill_processor;
pub mod chronicle_deduplication_service;
pub mod chronicle_ecs_consistency_monitor;
pub mod chronicle_ecs_translator;
pub mod chronicle_event_listener;
pub mod chronicle_service;
pub mod ecs_chronicle_event_handler;
pub mod ecs_component_lifecycle_manager;
pub mod ecs_entity_manager;
pub mod ecs_enhanced_rag_service;
pub mod ecs_graceful_degradation;
pub mod ecs_outbox_processor;
pub mod event_valence_processor;
pub mod email_service;
pub mod embeddings;
pub mod encryption_service;
pub mod extraction_dispatcher;
pub mod file_storage_service;
pub mod gemini_token_client;
pub mod history_manager;
pub mod hybrid_query_service;
pub mod hybrid_token_counter;
pub mod lorebook;
pub mod narrative_intelligence_service;
pub mod narrative_ontology_service;
pub mod rag_budget_manager;
pub mod tokenizer_service;
pub mod user_persona_service;
pub mod user_settings_service;

// Re-export agentic components
pub use agentic::{
    AgenticNarrativeFactory, NarrativeAgentRunner, NarrativeWorkflowConfig, 
    ScribeTool, ToolRegistry
};

pub use character_service::CharacterService;
pub use chat_override_service::ChatOverrideService;
pub use chronicle_backfill_processor::{ChronicleBackfillProcessor, BackfillConfig, BackfillResult, ChronicleBackfillStats};
pub use chronicle_deduplication_service::{ChronicleDeduplicationService, DeduplicationConfig, DuplicateDetectionResult};
pub use chronicle_ecs_consistency_monitor::{
    ChronicleEcsConsistencyMonitor, ConsistencyMonitorConfig, ConsistencyCheckResult, 
    ConsistencyInconsistency, InconsistencyType, InconsistencySeverity, StateReconstructionResult,
    ConsistencyHealthStatus, HealthStatus
};
pub use chronicle_ecs_translator::ChronicleEcsTranslator;
pub use chronicle_event_listener::{ChronicleEventListener, ChronicleEventListenerConfig, ChronicleEventNotification, ChronicleNotificationType, ChronicleEventProcessingResult};
pub use chronicle_service::ChronicleService;
pub use ecs_chronicle_event_handler::{EcsChronicleEventHandler, ChronicleEventHandlerConfig};
pub use ecs_component_lifecycle_manager::{EcsComponentLifecycleManager, ComponentLifecycleConfig, ComponentValidationRule, LifecycleOperationResult, DependencyResolution};
pub use ecs_entity_manager::{
    EcsEntityManager, EntityManagerConfig, EntityQueryResult, ComponentUpdate, ComponentOperation, 
    ComponentQuery, EntityQueryOptions, ComponentSort, SortDirection, QueryExecutionStats, AdvancedQueryResult,
    CacheWarmingStats, CacheWarmingResult, CacheWarmingRecommendations
};
pub use ecs_enhanced_rag_service::{
    EcsEnhancedRagService, EcsEnhancedRagConfig, EnhancedRagQuery, EnhancedRagResult,
    EnhancedChronicleEvent, EntityStateSnapshot, EntityStateContext, RelationshipContext
};
pub use ecs_graceful_degradation::{
    EcsGracefulDegradation, GracefulDegradationConfig, CircuitState, EcsHealthStatus,
    FallbackOperationResult, RecoveryAttemptResult
};
pub use hybrid_query_service::{
    HybridQueryService, HybridQueryConfig, HybridQuery, HybridQueryResult, HybridQueryType,
    HybridQueryOptions, EntityTimelineContext, TimelineEvent, RelationshipAnalysis,
    RelationshipMetrics, RelationshipTrend, HybridQuerySummary, QueryPerformanceMetrics
};
pub use ecs_outbox_processor::{EcsOutboxProcessor, OutboxProcessorConfig, OutboxEventHandler, EventProcessingResult, OutboxProcessingStats, LoggingEventHandler};
pub use event_valence_processor::{EventValenceProcessor, ValenceProcessingResult, ValenceProcessingConfig};
pub use email_service::{EmailService, create_email_service};
pub use encryption_service::EncryptionService;
pub use file_storage_service::FileStorageService;
pub use lorebook::LorebookService;
pub use narrative_intelligence_service::{NarrativeIntelligenceService, NarrativeProcessingResult, NarrativeProcessingConfig, BatchEventData, EventDataToInsert};
pub use narrative_ontology_service::NarrativeOntologyService;
pub use user_persona_service::UserPersonaService;
pub use user_settings_service::UserSettingsService;
