// backend/src/llm/llamacpp/mod.rs
// LlamaCpp integration module (only available with local-llm feature)

#[cfg(feature = "local-llm")]
pub mod client;

#[cfg(feature = "local-llm")]
pub mod server;

#[cfg(feature = "local-llm")]
pub mod model_manager;

#[cfg(feature = "local-llm")]
pub mod health;

#[cfg(feature = "local-llm")]
pub mod fallback;

#[cfg(feature = "local-llm")]
pub mod security;

#[cfg(feature = "local-llm")]
pub mod hardware;

#[cfg(feature = "local-llm")]
pub mod metrics;

#[cfg(feature = "local-llm")]
pub use client::LlamaCppClient;

#[cfg(feature = "local-llm")]
pub use server::LlamaCppServerManager;

#[cfg(feature = "local-llm")]
pub use model_manager::ModelManager;

#[cfg(feature = "local-llm")]
pub use hardware::ModelSelection;

#[cfg(feature = "local-llm")]
pub use health::HealthChecker;

#[cfg(feature = "local-llm")]
pub use fallback::{FallbackStrategy, LlamaCppResilience};

#[cfg(feature = "local-llm")]
pub use security::{PromptSanitizer, OutputValidator, ResourceLimiter};

#[cfg(feature = "local-llm")]
pub use hardware::{HardwareCapabilities, HardwareRequirements, detect_hardware};

#[cfg(feature = "local-llm")]
pub use metrics::{PerformanceMetrics, MetricsCollector, LlamaCppMetrics};

#[cfg(feature = "local-llm")]
use crate::errors::AppError;

#[cfg(feature = "local-llm")]
use std::time::Duration;

#[cfg(feature = "local-llm")]
use serde::{Deserialize, Serialize};

/// Configuration for LlamaCpp integration
#[cfg(feature = "local-llm")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaCppConfig {
    pub enabled: bool,
    pub model_path: String,
    pub model_url: Option<String>,
    pub server_host: String,
    pub server_port: u16,
    pub context_size: usize,
    pub gpu_layers: Option<i32>,
    pub threads: Option<usize>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub health_check_interval_seconds: u64,
    pub enable_tool_calling: bool,
    pub parallel_requests: Option<usize>,
    pub chat_template: Option<String>,
}

#[cfg(feature = "local-llm")]
impl Default for LlamaCppConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enable by default when local-llm feature is compiled
            model_path: "models/gpt-oss-20b-Q4_K_M.gguf".to_string(),
            model_url: Some("https://huggingface.co/unsloth/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-Q4_K_M.gguf".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: 11435,
            context_size: 8192,
            gpu_layers: Some(999), // All layers to GPU by default
            threads: None, // Auto-detect
            timeout_seconds: 120,
            max_retries: 3,
            health_check_interval_seconds: 30,
            enable_tool_calling: true, // Enable tool calling by default
            parallel_requests: Some(4), // Default to 4 parallel requests
            chat_template: Some("auto".to_string()), // Auto-detect template
        }
    }
}

impl LlamaCppConfig {
    /// Create config with environment variable overrides
    pub fn from_env() -> Self {
        use std::env;
        
        let mut config = Self::default();
        
        // Override with environment variables if present
        if let Ok(val) = env::var("LLAMACPP_ENABLE_TOOLS") {
            config.enable_tool_calling = val.parse().unwrap_or(true);
        }
        
        if let Ok(val) = env::var("LLAMACPP_PARALLEL_REQUESTS") {
            config.parallel_requests = val.parse().ok();
        }
        
        if let Ok(val) = env::var("LLAMACPP_CHAT_TEMPLATE") {
            config.chat_template = Some(val);
        }
        
        // Override other common settings
        if let Ok(val) = env::var("LLAMACPP_SERVER_HOST") {
            config.server_host = val;
        }
        
        if let Ok(val) = env::var("LLAMACPP_SERVER_PORT") {
            config.server_port = val.parse().unwrap_or(11435);
        }
        
        if let Ok(val) = env::var("LLAMACPP_CONTEXT_SIZE") {
            config.context_size = val.parse().unwrap_or(8192);
        }
        
        if let Ok(val) = env::var("LLAMACPP_GPU_LAYERS") {
            config.gpu_layers = val.parse().ok();
        }
        
        config
    }
}

/// Local LLM specific errors
#[cfg(feature = "local-llm")]
#[derive(thiserror::Error, Debug, Clone)]
pub enum LocalLlmError {
    #[error("LlamaCpp server unavailable: {0}")]
    ServerUnavailable(String),
    
    #[error("Model loading failed: {0}")]
    ModelLoadFailed(String),
    
    #[error("Insufficient resources (RAM: {ram_gb}GB, VRAM: {vram_gb}GB required)")]
    InsufficientResources { ram_gb: f32, vram_gb: f32 },
    
    #[error("Fallback to remote API: {reason}")]
    FallbackTriggered { reason: String },
    
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    
    #[error("Model download failed: {0}")]
    ModelDownloadFailed(String),
    
    #[error("Hardware detection failed: {0}")]
    HardwareDetectionFailed(String),
    
    #[error("Server startup timeout")]
    ServerStartupTimeout,
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
}

#[cfg(feature = "local-llm")]
impl From<LocalLlmError> for AppError {
    fn from(err: LocalLlmError) -> Self {
        match err {
            LocalLlmError::ServerUnavailable(msg) => AppError::BadGateway(msg),
            LocalLlmError::SecurityViolation(msg) => AppError::Forbidden(msg),
            LocalLlmError::ResourceLimitExceeded(msg) => AppError::BadRequest(msg),
            _ => AppError::InternalServerErrorGeneric(err.to_string()),
        }
    }
}