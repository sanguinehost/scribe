pub mod agentic;
pub mod character_generation;
pub mod character_parser;
pub mod character_service;
pub mod chat;
pub mod chat_override_service;
pub mod checksum_state_validator;
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
pub mod historical_chronicle_processor;
pub mod hybrid_query_service;
pub mod hybrid_query_gemini_schemas;
pub mod intent_detection_service;
pub mod hybrid_query_router;
pub mod hybrid_token_counter;
pub mod lorebook;
pub mod narrative_intelligence_service;
pub mod narrative_ontology_service;
pub mod rag_budget_manager;
pub mod tokenizer_service;
pub mod user_persona_service;
pub mod user_settings_service;
pub mod world_model_service;
pub mod nlp_query_handler;
pub mod planning;
pub mod progressive_cache;
pub mod prompt_templates;
pub mod query_strategy_planner;
pub mod query_strategy_planner_structured_output;
pub mod query_registry;
pub mod context_assembly_engine;
pub mod context_optimization_service;
pub mod context_optimization_structured_output;
pub mod hierarchical_context_assembler;
pub mod agentic_orchestrator;
pub mod agentic_query_cache;
pub mod agentic_metrics;
pub mod agentic_state_update_service;
pub mod agentic_state_update_structured_output;
pub mod agent_prompt_templates;
pub mod task_queue;
pub mod orchestrator;

// Re-export agentic components
pub use agentic::{
    AgenticNarrativeFactory, NarrativeAgentRunner, NarrativeWorkflowConfig, 
    ScribeTool, TacticalAgent
};

pub use character_service::CharacterService;
pub use chat_override_service::ChatOverrideService;
pub use checksum_state_validator::{
    ChecksumStateValidator, ChecksumValidatorConfig, StateChecksum, ChecksumValidationResult,
    ComponentValidationResult, ValidationComponent, ValidationCheckpoint, ChecksumItemCounts
};
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
    CacheWarmingStats, CacheWarmingResult, CacheWarmingRecommendations, EntityHierarchyInfo, EntityContainmentTree,
    MoveEntityOptions, MoveEntityResult, PositionData
};
pub use ecs_enhanced_rag_service::{
    EcsEnhancedRagService, EcsEnhancedRagConfig, EnhancedRagQuery, EnhancedRagResult,
    EnhancedChronicleEvent, EntityStateSnapshot, EntityStateContext, RelationshipContext
};
pub use ecs_graceful_degradation::{
    EcsGracefulDegradation, GracefulDegradationConfig, CircuitState, EcsHealthStatus,
    FallbackOperationResult, RecoveryAttemptResult
};
pub use historical_chronicle_processor::{
    HistoricalChronicleProcessor, HistoricalProcessorConfig, EnqueueResult, 
    BackfillResult as HistoricalBackfillResult, BackfillProgress
};
pub use hybrid_query_service::{
    HybridQueryService, HybridQueryConfig, HybridQuery, HybridQueryResult, HybridQueryType,
    HybridQueryOptions, EntityTimelineContext, TimelineEvent, RelationshipAnalysis,
    RelationshipMetrics, RelationshipTrend, HybridQuerySummary, QueryPerformanceMetrics
};
pub use hybrid_query_router::{
    HybridQueryRouter, HybridQueryRouterConfig, QueryRoutingStrategy, RoutingDecision,
    QueryComplexity, QueryPerformanceContract, FailureMode, RoutingMetrics,
    ServiceCircuitBreakers, CircuitBreakerState, DataVolume
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
pub use world_model_service::{WorldModelService, WorldModelOptions, LLMContextFocus, TimeFocus, ReasoningDepth};
pub use intent_detection_service::{
    IntentDetectionService, QueryIntent, NarrativeIntent, IntentType, EntityFocus, TimeScope, SpatialScope,
    ReasoningDepth as IntentReasoningDepth, ContextPriority
};
pub use query_strategy_planner::{
    QueryStrategyPlanner, QueryExecutionPlan, QueryStrategy, PlannedQuery, PlannedQueryType
};
pub use context_assembly_engine::{
    ContextAssemblyEngine, AssembledContext, QueryExecutionResult
};
pub use context_optimization_service::{
    ContextOptimizationService, ContextOptimization, OptimizedEntity, PrunedContent, OptimizationStrategy
};
pub use hierarchical_context_assembler::HierarchicalContextAssembler;
pub use agentic_orchestrator::{
    AgenticOrchestrator, AgenticRequest, AgenticResponse, QualityMode, ExecutionSummary, TokenUsageSummary
};
pub use agentic_query_cache::{
    AgenticQueryCache, AgenticCacheConfig, CacheKey, QueryType, CacheStats, CacheMetrics
};
pub use agentic_metrics::{
    AgenticMetrics, AgenticMetricsCollector, MetricsConfig, RequestTracker, 
    ProcessingStats, CacheStats as MetricsCacheStats, TokenAnalytics, QualityMetrics,
    TimingMetrics, ErrorMetrics, TrendData, PerformanceMeasurement, PhaseTimer,
    TokenOptimizationInsights, TokenOptimizationRecommendation, RecommendationPriority,
    OptimizationCategory, PotentialSavings, ImplementationEffort, CostAnalysis,
    EfficiencyTrends, TokenBreakdown, TokenEfficiency, BudgetUtilization
};
pub use agentic_state_update_service::{
    AgenticStateUpdateService, StateUpdateConfig, StateUpdateResult,
    SpatialUpdateSummary, RelationshipUpdateSummary, TemporalUpdateSummary
};
pub use agent_prompt_templates::{
    AgentPromptTemplates, PromptTemplateVersion, TemplateValidationResult
};
pub use task_queue::{
    TaskQueueService, EnrichmentTask, NewEnrichmentTask, EnrichmentTaskPayload,
    CreateTaskRequest, DequeuedTask, TaskStatus, TaskPriority, TaskUpdate
};
pub use orchestrator::{
    OrchestratorAgent, OrchestratorConfig, OrchestratorError, ReasoningPhase,
    ReasoningContext, PerceptionResult, StrategyResult, PlanResult, ExecutionResult,
    ReflectionResult, ReasoningLoopResult, TaskContext
};
