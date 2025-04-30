// backend/src/config.rs

use serde::Deserialize;

// Renamed from Settings to Config
#[derive(Deserialize, Debug, Clone)] // Removed Default as we use serde defaults now
pub struct Config {
    // Database & API Keys
    pub database_url: Option<String>,
    pub gemini_api_key: Option<String>,

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
}

// Default value functions for serde
fn default_port() -> u16 { 8080 }
fn default_session_cookie_secure() -> bool { true } // Default to secure
fn default_qdrant_collection_name() -> String { "scribe_embeddings".to_string() }
fn default_embedding_dimension() -> u64 { 768 } // Default for gemini-embedding-exp-03-07
fn default_qdrant_distance_metric() -> String { "Cosine".to_string() } // Added
fn default_qdrant_on_disk() -> Option<bool> { None } // Added
fn default_chunking_metric() -> String { "word".to_string() }
fn default_chunking_max_size() -> usize { 200 } // Default for word metric
fn default_chunking_overlap() -> usize { 20 } // Default for word metric

impl Config {
    // Placeholder function to load settings (e.g., from file or env)
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
        envy::from_env::<Config>().map_err(anyhow::Error::from)
    }
}

// Default implementation for Config
impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: None,
            gemini_api_key: None,
            port: default_port(),
            cookie_signing_key: None,
            session_cookie_secure: default_session_cookie_secure(),
            qdrant_url: None,
            qdrant_collection_name: default_qdrant_collection_name(),
            embedding_dimension: default_embedding_dimension(),
            qdrant_distance_metric: default_qdrant_distance_metric(), // Added
            qdrant_on_disk: default_qdrant_on_disk(), // Added
            chunking_metric: default_chunking_metric(),
            chunking_max_size: default_chunking_max_size(),
            chunking_overlap: default_chunking_overlap(),
        }
    }
}
