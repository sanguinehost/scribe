// backend/src/config.rs

use serde::Deserialize;

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
    "gemini-2.5-flash-preview-05-20".to_string()
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
        }
    }
}
