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
    pub qdrant_api_key: Option<String>,
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
    
    // Security Configuration
    #[serde(default)]
    pub security: SecurityConfig,
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
            .field(
                "qdrant_api_key",
                &self.qdrant_api_key.as_ref().map(|_| "[REDACTED]"),
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
            .field("frontend_base_url", &self.frontend_base_url)
            .field("app_env", &self.app_env)
            .field(
                "from_email",
                &self.from_email.as_ref().map(|_| "[REDACTED]"),
            )
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

fn default_frontend_base_url() -> String {
    "https://localhost:5173".to_string()
}

fn default_app_env() -> String {
    "development".to_string()
}

/// Security configuration for LLM operations
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_max_context_tokens")]
    pub max_context_tokens: usize,
    #[serde(default = "default_max_requests_per_minute")]
    pub max_requests_per_minute: u32,
    #[serde(default = "default_max_requests_per_hour")]
    pub max_requests_per_hour: u32,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
    #[serde(default = "default_audit_retention_hours")]
    pub audit_retention_hours: u64,
    #[serde(default = "default_prompt_max_length")]
    pub prompt_max_length: usize,
    #[serde(default = "default_response_max_length")]
    pub response_max_length: usize,
    #[serde(default = "default_security_logging_enabled")]
    pub security_logging_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: default_max_context_tokens(),
            max_requests_per_minute: default_max_requests_per_minute(),
            max_requests_per_hour: default_max_requests_per_hour(),
            max_concurrent_requests: default_max_concurrent_requests(),
            audit_retention_hours: default_audit_retention_hours(),
            prompt_max_length: default_prompt_max_length(),
            response_max_length: default_response_max_length(),
            security_logging_enabled: default_security_logging_enabled(),
        }
    }
}

fn default_max_context_tokens() -> usize {
    1048576 // 1M tokens to support full range (4k to 1M) for all models including Gemini
}

fn default_max_requests_per_minute() -> u32 {
    10 // 10 requests per minute per user
}

fn default_max_requests_per_hour() -> u32 {
    100 // 100 requests per hour per user
}

fn default_max_concurrent_requests() -> u32 {
    3 // 3 concurrent requests per user
}

fn default_audit_retention_hours() -> u64 {
    168 // 1 week retention
}

fn default_prompt_max_length() -> usize {
    8192 // 8KB max prompt
}

fn default_response_max_length() -> usize {
    8192 // 8KB max response
}

fn default_security_logging_enabled() -> bool {
    true // Security logging enabled by default
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
        // Load config from environment variables using envy
        let mut config = envy::from_env::<Self>().map_err(anyhow::Error::from)?;
        
        // Apply environment-specific defaults after loading
        config.apply_environment_defaults();
        
        Ok(config)
    }
    
    /// Apply environment-specific defaults based on the detected or configured environment
    pub fn apply_environment_defaults(&mut self) {
        let environment = self.environment.as_deref().unwrap_or("local");
        
        // Set environment-specific defaults for Qdrant URL if not already set
        if self.qdrant_url.is_none() {
            self.qdrant_url = Some(match environment {
                "staging" => "https://qdrant.staging.local:6334".to_string(),
                "production" => "https://qdrant.production.local:6334".to_string(), 
                "container" => "https://qdrant:6334".to_string(),
                "local" | _ => "https://localhost:6334".to_string(),
            });
        }
        
        // Set environment-specific cookie security defaults
        if environment == "local" && self.session_cookie_secure {
            // For local development, default to non-secure cookies for easier testing
            self.session_cookie_secure = false;
        }
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
            qdrant_api_key: None,
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
            frontend_base_url: default_frontend_base_url(),
            app_env: default_app_env(),
            from_email: None,
            narrative_flags: NarrativeFeatureFlags::default(),
            security: SecurityConfig::default(),
        }
    }
}
