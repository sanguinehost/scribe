pub mod agentic;
pub mod ai;
pub mod ai_client_factory;
pub mod character_generation;
pub mod character_parser;
pub mod character_service;
pub mod chat;
pub mod chat_override_service;
pub mod chronicle_deduplication_service;
pub mod chronicle_service;
pub mod cognitive;
pub mod email_service;
pub mod embeddings;
pub mod encryption_service;
pub mod extraction_dispatcher;
pub mod game_state_service;
pub mod history_manager;
pub mod hybrid_token_counter;
pub mod lorebook;
pub mod narrative_intelligence_service;
#[cfg(feature = "payment")]
pub mod payment;
pub mod rag_budget_manager;
pub mod reconciliation_detector;
pub mod safety_utils;
pub mod secure_llm_service;
pub mod template_preference_service;
pub mod token_client;
pub mod tokenizer_service;
pub mod user_persona_service;
pub mod user_settings_service;

// Re-export agentic components
pub use agentic::{
    AgenticNarrativeFactory, NarrativeAgentRunner, NarrativeWorkflowConfig, ScribeTool,
    ToolRegistry,
};

pub use character_service::CharacterService;
pub use chat_override_service::ChatOverrideService;
pub use chronicle_deduplication_service::{
    ChronicleDeduplicationService, DeduplicationConfig, DuplicateDetectionResult,
};
pub use chronicle_service::ChronicleService;
pub use cognitive::RecallPipeline;
pub use email_service::{create_email_service, EmailService};
pub use encryption_service::EncryptionService;
pub use lorebook::LorebookService;
pub use narrative_intelligence_service::{
    NarrativeIntelligenceService, NarrativeProcessingConfig, NarrativeProcessingResult,
};
pub use secure_llm_service::SecureLlmService;
pub use template_preference_service::TemplatePreferenceService;
pub use user_persona_service::UserPersonaService;
pub use user_settings_service::UserSettingsService;
