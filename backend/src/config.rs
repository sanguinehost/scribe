// backend/src/config.rs

use serde::Deserialize;

pub mod feature_flags;
pub use feature_flags::*;

// Renamed from Settings to Config
#[derive(Deserialize, Clone)]
pub struct Config {
    // Database & API Keys
    pub database_url: Option<String>,
    pub gemini_api_key: Option<String>,
    #[serde(default = "default_gemini_api_base_url")]
    pub gemini_api_base_url: String,

    // Server Config
    #[serde(default = "default_port")]
    pub port: u16,
    pub cookie_signing_key: Option<String>, // Keep optional if it can be generated
    #[serde(default = "default_session_cookie_secure")]
    pub session_cookie_secure: bool,
    pub environment: Option<String>, // Environment (development, staging, production)
    pub cookie_domain: Option<String>, // Cookie domain for sessions

    // Qdrant Config
    pub qdrant_url: Option<String>,
    #[serde(default = "default_qdrant_collection_name")]
    pub qdrant_collection_name: String,
    #[serde(default = "default_embedding_dimension")]
    pub embedding_dimension: u64, // Added
    #[serde(default = "default_qdrant_distance_metric")]
    pub qdrant_distance_metric: String, // Added
    #[serde(default = "default_qdrant_on_disk")]
    pub qdrant_on_disk: Option<bool>, // Added

    // Chunking Config - Added
    #[serde(default = "default_chunking_metric")]
    pub chunking_metric: String, // "word" or "char"
    #[serde(default = "default_chunking_max_size")]
    pub chunking_max_size: usize,
    #[serde(default = "default_chunking_overlap")]
    pub chunking_overlap: usize,

    // Tokenizer Config - Added
    #[serde(default = "default_tokenizer_model_path")]
    pub tokenizer_model_path: String,
    #[serde(default = "default_token_counter_default_model")]
    pub token_counter_default_model: String,

    // Context Token Limits - Added
    #[serde(default = "default_context_total_token_limit")]
    pub context_total_token_limit: usize,
    #[serde(default = "default_context_recent_history_token_budget")]
    pub context_recent_history_token_budget: usize,
    #[serde(default = "default_context_rag_token_budget")]
    pub context_rag_token_budget: usize,
    
    // Strategic Truncation Settings
    #[serde(default = "default_min_tail_messages_to_preserve")]
    pub min_tail_messages_to_preserve: usize,

    // File Storage Config
    #[serde(default = "default_upload_storage_path")]
    pub upload_storage_path: String,

    // Frontend URL
    #[serde(default = "default_frontend_base_url")]
    pub frontend_base_url: String,

    // Email Configuration
    #[serde(default = "default_app_env")]
    pub app_env: String,
    pub from_email: Option<String>,
    
    // Narrative Feature Flags
    #[serde(default)]
    pub narrative_flags: NarrativeFeatureFlags,

    // Re-chronicle config
    #[serde(default = "default_rechronicle_confidence_threshold")]
    pub rechronicle_confidence_threshold: f32,
    
    // Model Configuration - Centralized model management
    // Core models
    #[serde(default = "default_chat_model")]
    pub chat_model: String, // Default model for chat completions
    #[serde(default = "default_fast_model")]
    pub fast_model: String, // Fast/lite model for quick operations
    #[serde(default = "default_advanced_model")]
    pub advanced_model: String, // Advanced model for complex reasoning
    #[serde(default = "default_embedding_model")]
    pub embedding_model: String, // Model for vector embeddings
    
    // Feature-specific models
    #[serde(default = "default_token_counter_model")]
    pub token_counter_model: String, // Model for token counting
    #[serde(default = "default_suggestion_model")]
    pub suggestion_model: String, // Model for generating suggestions
    #[serde(default = "default_optimization_model")]
    pub optimization_model: String, // Model for context optimization
    
    // Agentic model configuration
    #[serde(default = "default_agentic_triage_model")]
    pub agentic_triage_model: String,
    #[serde(default = "default_agentic_planning_model")]
    pub agentic_planning_model: String,
    #[serde(default = "default_agentic_extraction_model")]
    pub agentic_extraction_model: String,
    #[serde(default = "default_agentic_entity_resolution_model")]
    pub agentic_entity_resolution_model: String,
    #[serde(default = "default_agentic_max_tool_executions")]
    pub agentic_max_tool_executions: usize,
    
    // Living World agent models
    #[serde(default = "default_perception_agent_model")]
    pub perception_agent_model: String,
    #[serde(default = "default_strategic_agent_model")]
    pub strategic_agent_model: String,
    #[serde(default = "default_tactical_agent_model")]
    pub tactical_agent_model: String,
    
    // Tool-specific models
    #[serde(default = "default_intent_detection_model")]
    pub intent_detection_model: String,
    #[serde(default = "default_query_planning_model")]
    pub query_planning_model: String,
    #[serde(default = "default_hybrid_query_model")]
    pub hybrid_query_model: String,
    
    // Redis Configuration - Optional for caching
    pub redis_url: Option<String>,
    #[serde(default = "default_redis_enabled")]
    pub redis_enabled: bool,
    #[serde(default = "default_redis_timeout_ms")]
    pub redis_timeout_ms: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "gemini_api_key",
                &self.gemini_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("gemini_api_base_url", &"[REDACTED]")
            .field("port", &self.port)
            .field(
                "cookie_signing_key",
                &self.cookie_signing_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("session_cookie_secure", &self.session_cookie_secure)
            .field("environment", &self.environment)
            .field("cookie_domain", &self.cookie_domain)
            .field(
                "qdrant_url",
                &self.qdrant_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("qdrant_collection_name", &self.qdrant_collection_name)
            .field("embedding_dimension", &self.embedding_dimension)
            .field("qdrant_distance_metric", &self.qdrant_distance_metric)
            .field("qdrant_on_disk", &self.qdrant_on_disk)
            .field("chunking_metric", &self.chunking_metric)
            .field("chunking_max_size", &self.chunking_max_size)
            .field("chunking_overlap", &self.chunking_overlap)
            .field("tokenizer_model_path", &self.tokenizer_model_path)
            .field(
                "token_counter_default_model",
                &self.token_counter_default_model,
            )
            .field("context_total_token_limit", &self.context_total_token_limit)
            .field(
                "context_recent_history_token_budget",
                &self.context_recent_history_token_budget,
            )
            .field("context_rag_token_budget", &self.context_rag_token_budget)
            .field("upload_storage_path", &self.upload_storage_path)
            .field("frontend_base_url", &self.frontend_base_url)
            .field("app_env", &self.app_env)
            .field(
                "from_email",
                &self.from_email.as_ref().map(|_| "[REDACTED]"),
            )
            .field("rechronicle_confidence_threshold", &self.rechronicle_confidence_threshold)
            // Model configuration fields
            .field("chat_model", &self.chat_model)
            .field("fast_model", &self.fast_model)
            .field("advanced_model", &self.advanced_model)
            .field("embedding_model", &self.embedding_model)
            .field("token_counter_model", &self.token_counter_model)
            .field("suggestion_model", &self.suggestion_model)
            .field("optimization_model", &self.optimization_model)
            .field("agentic_triage_model", &self.agentic_triage_model)
            .field("agentic_planning_model", &self.agentic_planning_model)
            .field("agentic_extraction_model", &self.agentic_extraction_model)
            .field("agentic_entity_resolution_model", &self.agentic_entity_resolution_model)
            .field("agentic_max_tool_executions", &self.agentic_max_tool_executions)
            .field("perception_agent_model", &self.perception_agent_model)
            .field("strategic_agent_model", &self.strategic_agent_model)
            .field("tactical_agent_model", &self.tactical_agent_model)
            .field("intent_detection_model", &self.intent_detection_model)
            .field("query_planning_model", &self.query_planning_model)
            .field("hybrid_query_model", &self.hybrid_query_model)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "[REDACTED]"))
            .field("redis_enabled", &self.redis_enabled)
            .field("redis_timeout_ms", &self.redis_timeout_ms)
            .finish()
    }
}

fn default_gemini_api_base_url() -> String {
    "https://generativelanguage.googleapis.com".to_string()
}

// Default value functions for serde
const fn default_port() -> u16 {
    8080
}
const fn default_session_cookie_secure() -> bool {
    true
} // Default to secure
fn default_qdrant_collection_name() -> String {
    "scribe_embeddings".to_string()
}
const fn default_embedding_dimension() -> u64 {
    768
} // Default for models/text-embedding-004
fn default_qdrant_distance_metric() -> String {
    "Cosine".to_string()
} // Added
const fn default_qdrant_on_disk() -> Option<bool> {
    None
} // Added
fn default_chunking_metric() -> String {
    "word".to_string()
}
const fn default_chunking_max_size() -> usize {
    200
} // Default for word metric
const fn default_chunking_overlap() -> usize {
    20
} // Default for word metric
fn default_tokenizer_model_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let model_path = std::path::Path::new(manifest_dir)
        .join("resources")
        .join("tokenizers")
        .join("gemma.model");
    model_path.to_string_lossy().into_owned()
} // Path relative to crate root (backend/)
fn default_token_counter_default_model() -> String {
    "gemini-2.5-flash".to_string()
} // Added

// Core model defaults
fn default_chat_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_fast_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_advanced_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_embedding_model() -> String {
    "models/text-embedding-004".to_string()
}

// Feature-specific model defaults
fn default_token_counter_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_suggestion_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_optimization_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

// Defaults for context token limits
const fn default_context_total_token_limit() -> usize {
    200_000
}
const fn default_context_recent_history_token_budget() -> usize {
    150_000
}
const fn default_context_rag_token_budget() -> usize {
    50_000
}
const fn default_min_tail_messages_to_preserve() -> usize {
    8 // Preserve last 8 messages to maintain conversation continuity
}
fn default_upload_storage_path() -> String {
    "./uploads".to_string()
}

fn default_frontend_base_url() -> String {
    "https://localhost:5173".to_string()
}

fn default_app_env() -> String {
    "development".to_string()
}

fn default_rechronicle_confidence_threshold() -> f32 {
    0.5
}

fn default_agentic_triage_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_agentic_planning_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_agentic_extraction_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_agentic_entity_resolution_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

const fn default_agentic_max_tool_executions() -> usize {
    15
}

// Living World agent model defaults
fn default_perception_agent_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_strategic_agent_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_tactical_agent_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

// Tool-specific model defaults
fn default_intent_detection_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_query_planning_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

fn default_hybrid_query_model() -> String {
    "gemini-2.5-flash-lite-preview-06-17".to_string()
}

// Redis configuration defaults
const fn default_redis_enabled() -> bool {
    false // Disabled by default for self-hosting
}

const fn default_redis_timeout_ms() -> u64 {
    500 // 500ms timeout for Redis operations
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if required environment variables are missing or invalid,
    /// or if the configuration parsing fails.
    /// Loads configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` if environment variable parsing fails,
    /// such as when required variables are missing or have invalid formats.
    pub fn load() -> Result<Self, anyhow::Error> {
        // In a real scenario, load from config file (e.g., config.toml)
        // or environment variables using libraries like `config` or `dotenvy` + `envy`.
        // For now, return a default placeholder.
        // Ok(Config { // Renamed
        //     placeholder: "default_value".to_string(),
        // })
        // Example loading with envy (requires adding envy crate)
        // envy::from_env::<Config>().map_err(anyhow::Error::from)
        // Ok(Config::default()) // Return default for now
        // Load config from environment variables using envy
        envy::from_env::<Self>().map_err(anyhow::Error::from)
    }
}

// Default implementation for Config
impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: None,
            gemini_api_key: None,
            gemini_api_base_url: default_gemini_api_base_url(),
            port: default_port(),
            cookie_signing_key: None,
            session_cookie_secure: default_session_cookie_secure(),
            environment: None,
            cookie_domain: None,
            qdrant_url: None,
            qdrant_collection_name: default_qdrant_collection_name(),
            embedding_dimension: default_embedding_dimension(),
            qdrant_distance_metric: default_qdrant_distance_metric(), // Added
            qdrant_on_disk: default_qdrant_on_disk(),                 // Added
            chunking_metric: default_chunking_metric(),
            chunking_max_size: default_chunking_max_size(),
            chunking_overlap: default_chunking_overlap(),
            tokenizer_model_path: default_tokenizer_model_path(),
            token_counter_default_model: default_token_counter_default_model(),
            context_total_token_limit: default_context_total_token_limit(),
            context_recent_history_token_budget: default_context_recent_history_token_budget(),
            context_rag_token_budget: default_context_rag_token_budget(),
            min_tail_messages_to_preserve: default_min_tail_messages_to_preserve(),
            upload_storage_path: default_upload_storage_path(),
            frontend_base_url: default_frontend_base_url(),
            app_env: default_app_env(),
            from_email: None,
            narrative_flags: NarrativeFeatureFlags::default(),
            rechronicle_confidence_threshold: default_rechronicle_confidence_threshold(),
            // Core models
            chat_model: default_chat_model(),
            fast_model: default_fast_model(),
            advanced_model: default_advanced_model(),
            embedding_model: default_embedding_model(),
            // Feature-specific models
            token_counter_model: default_token_counter_model(),
            suggestion_model: default_suggestion_model(),
            optimization_model: default_optimization_model(),
            // Agentic models
            agentic_triage_model: default_agentic_triage_model(),
            agentic_planning_model: default_agentic_planning_model(),
            agentic_extraction_model: default_agentic_extraction_model(),
            agentic_entity_resolution_model: default_agentic_entity_resolution_model(),
            agentic_max_tool_executions: default_agentic_max_tool_executions(),
            // Living World models
            perception_agent_model: default_perception_agent_model(),
            strategic_agent_model: default_strategic_agent_model(),
            tactical_agent_model: default_tactical_agent_model(),
            // Tool-specific models
            intent_detection_model: default_intent_detection_model(),
            query_planning_model: default_query_planning_model(),
            hybrid_query_model: default_hybrid_query_model(),
            // Redis configuration
            redis_url: None,
            redis_enabled: default_redis_enabled(),
            redis_timeout_ms: default_redis_timeout_ms(),
        }
    }
}
