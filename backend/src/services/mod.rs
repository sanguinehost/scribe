pub mod agentic;
pub mod character_generation;
pub mod character_parser;
pub mod character_service;
pub mod chat;
pub mod chat_override_service;
pub mod chronicle_backfill_processor;
pub mod chronicle_deduplication_service;
pub mod chronicle_ecs_translator;
pub mod chronicle_service;
pub mod event_valence_processor;
pub mod email_service;
pub mod embeddings;
pub mod encryption_service;
pub mod extraction_dispatcher;
pub mod file_storage_service;
pub mod gemini_token_client;
pub mod history_manager;
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
pub use chronicle_ecs_translator::ChronicleEcsTranslator;
pub use chronicle_service::ChronicleService;
pub use event_valence_processor::{EventValenceProcessor, ValenceProcessingResult, ValenceProcessingConfig};
pub use email_service::{EmailService, create_email_service};
pub use encryption_service::EncryptionService;
pub use file_storage_service::FileStorageService;
pub use lorebook::LorebookService;
pub use narrative_intelligence_service::{NarrativeIntelligenceService, NarrativeProcessingResult, NarrativeProcessingConfig, BatchEventData, EventDataToInsert};
pub use narrative_ontology_service::NarrativeOntologyService;
pub use user_persona_service::UserPersonaService;
pub use user_settings_service::UserSettingsService;
