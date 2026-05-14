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

    // LanceDB Config (for embedded-vector mode)
    #[serde(default)]
    pub lancedb_data_dir: Option<std::path::PathBuf>, // Override default LanceDB data directory

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

    // Payment Configuration (only with payment feature)
    #[cfg(feature = "payment")]
    #[serde(default)]
    pub payment: PaymentConfig,

    #[serde(default = "default_adjoint_threshold")]
    pub adjoint_threshold: f32,
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
    1000
} // Default for word metric
const fn default_chunking_overlap() -> usize {
    50
} // Default for word metric
fn default_tokenizer_model_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let model_path = std::path::Path::new(manifest_dir)
        .join("resources")
        .join("tokenizers")
        .join("tokenizer.json");
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

const fn default_adjoint_threshold() -> f32 {
    1.0 // Default thermodynamic surprise limit
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

// Payment configuration (only with payment feature)
#[cfg(feature = "payment")]
#[derive(Deserialize, Clone)]
pub struct PaymentConfig {
    /// Paddle API key for payment processing
    pub paddle_api_key: Option<String>,

    /// Paddle webhook secret for signature verification
    pub paddle_webhook_secret: Option<String>,

    /// Encryption key for payment transaction data at rest (base64 encoded 256-bit key)
    /// CRITICAL: This key encrypts customer PII from Paddle webhooks
    /// Generate with: openssl rand -base64 32
    /// WARNING: Loss of this key means permanent loss of access to payment transaction customer data
    #[serde(default)]
    pub data_encryption_key: Option<String>,

    // Paddle subscription price IDs (from Secrets Manager)
    /// Paddle price ID for Basic plan - monthly billing
    pub paddle_basic_monthly_price_id: Option<String>,

    /// Paddle price ID for Basic plan - yearly billing
    pub paddle_basic_yearly_price_id: Option<String>,

    /// Paddle price ID for Premium plan - monthly billing
    pub paddle_premium_monthly_price_id: Option<String>,

    /// Paddle price ID for Premium plan - yearly billing
    pub paddle_premium_yearly_price_id: Option<String>,

    // Paddle credit package price IDs (from Secrets Manager)
    /// Paddle price ID for 250 credits package
    pub paddle_credits_250_price_id: Option<String>,

    /// Paddle price ID for 500/550 credits package
    pub paddle_credits_500_price_id: Option<String>,

    /// Paddle price ID for 1500 credits package
    pub paddle_credits_1500_price_id: Option<String>,

    /// Paddle price ID for 3500 credits package
    pub paddle_credits_3500_price_id: Option<String>,

    /// Paddle price ID for 8000 credits package
    pub paddle_credits_8000_price_id: Option<String>,

    /// Whether to use Paddle sandbox mode (for development/testing)
    #[serde(default = "default_paddle_sandbox_mode")]
    pub paddle_sandbox_mode: bool,

    /// Base URL for payment completion redirects (e.g., https://scribe.sanguinehost.com)
    #[serde(default = "default_payment_base_url")]
    pub payment_base_url: String,

    /// Free tier monthly token limit
    #[serde(default = "default_free_tier_token_limit")]
    pub free_tier_token_limit: i64,

    /// Whether to enforce payment limits (can disable for testing)
    #[serde(default = "default_enforce_limits")]
    pub enforce_limits: bool,

    /// Grace period in days after subscription expires
    #[serde(default = "default_grace_period_days")]
    pub grace_period_days: i32,

    // Credit System Configuration
    /// Path to subscription tiers JSON configuration file
    #[serde(default = "default_subscription_config_path")]
    pub subscription_config_path: String,

    /// Enable credit system (feature flag)
    #[serde(default = "default_credits_enabled")]
    pub credits_enabled: bool,

    /// Enable soft limits (feature flag)
    #[serde(default = "default_soft_limits_enabled")]
    pub soft_limits_enabled: bool,

    /// Days until credits expire (0 = never)
    #[serde(default = "default_credit_expiry_days")]
    pub credit_expiry_days: u32,

    /// Minimum credits that can be purchased
    #[serde(default = "default_min_credit_purchase")]
    pub min_credit_purchase: u32,

    /// Maximum credit balance allowed
    #[serde(default = "default_max_credit_balance")]
    pub max_credit_balance: u32,

    /// Enable daily usage tracking
    #[serde(default = "default_usage_tracking_enabled")]
    pub usage_tracking_enabled: bool,

    /// Daily usage reset time (UTC hour, 0-23)
    #[serde(default = "default_usage_reset_hour_utc")]
    pub usage_reset_hour_utc: u8,

    /// Retention period for webhook events in days (for cleanup job)
    #[serde(default = "default_webhook_retention_days")]
    pub webhook_event_retention_days: i64,
}

#[cfg(feature = "payment")]
impl std::fmt::Debug for PaymentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentConfig")
            .field(
                "paddle_api_key",
                &self.paddle_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "paddle_webhook_secret",
                &self.paddle_webhook_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "data_encryption_key",
                &self.data_encryption_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "paddle_basic_monthly_price_id",
                &self.paddle_basic_monthly_price_id.as_deref(),
            )
            .field(
                "paddle_basic_yearly_price_id",
                &self.paddle_basic_yearly_price_id.as_deref(),
            )
            .field(
                "paddle_premium_monthly_price_id",
                &self.paddle_premium_monthly_price_id.as_deref(),
            )
            .field(
                "paddle_premium_yearly_price_id",
                &self.paddle_premium_yearly_price_id.as_deref(),
            )
            .field(
                "paddle_credits_250_price_id",
                &self.paddle_credits_250_price_id.as_deref(),
            )
            .field(
                "paddle_credits_500_price_id",
                &self.paddle_credits_500_price_id.as_deref(),
            )
            .field(
                "paddle_credits_1500_price_id",
                &self.paddle_credits_1500_price_id.as_deref(),
            )
            .field(
                "paddle_credits_3500_price_id",
                &self.paddle_credits_3500_price_id.as_deref(),
            )
            .field(
                "paddle_credits_8000_price_id",
                &self.paddle_credits_8000_price_id.as_deref(),
            )
            .field("paddle_sandbox_mode", &self.paddle_sandbox_mode)
            .field("payment_base_url", &self.payment_base_url)
            .field("free_tier_token_limit", &self.free_tier_token_limit)
            .field("enforce_limits", &self.enforce_limits)
            .field("grace_period_days", &self.grace_period_days)
            .field("subscription_config_path", &self.subscription_config_path)
            .field("credits_enabled", &self.credits_enabled)
            .field("soft_limits_enabled", &self.soft_limits_enabled)
            .field("credit_expiry_days", &self.credit_expiry_days)
            .field("min_credit_purchase", &self.min_credit_purchase)
            .field("max_credit_balance", &self.max_credit_balance)
            .field("usage_tracking_enabled", &self.usage_tracking_enabled)
            .field("usage_reset_hour_utc", &self.usage_reset_hour_utc)
            .field(
                "webhook_event_retention_days",
                &self.webhook_event_retention_days,
            )
            .finish()
    }
}

#[cfg(feature = "payment")]
impl Default for PaymentConfig {
    fn default() -> Self {
        Self {
            paddle_api_key: None,
            paddle_webhook_secret: None,
            data_encryption_key: None,
            paddle_basic_monthly_price_id: None,
            paddle_basic_yearly_price_id: None,
            paddle_premium_monthly_price_id: None,
            paddle_premium_yearly_price_id: None,
            paddle_credits_250_price_id: None,
            paddle_credits_500_price_id: None,
            paddle_credits_1500_price_id: None,
            paddle_credits_3500_price_id: None,
            paddle_credits_8000_price_id: None,
            paddle_sandbox_mode: default_paddle_sandbox_mode(),
            payment_base_url: default_payment_base_url(),
            free_tier_token_limit: default_free_tier_token_limit(),
            enforce_limits: default_enforce_limits(),
            grace_period_days: default_grace_period_days(),
            subscription_config_path: default_subscription_config_path(),
            credits_enabled: default_credits_enabled(),
            soft_limits_enabled: default_soft_limits_enabled(),
            credit_expiry_days: default_credit_expiry_days(),
            min_credit_purchase: default_min_credit_purchase(),
            max_credit_balance: default_max_credit_balance(),
            usage_tracking_enabled: default_usage_tracking_enabled(),
            usage_reset_hour_utc: default_usage_reset_hour_utc(),
            webhook_event_retention_days: default_webhook_retention_days(),
        }
    }
}

#[cfg(feature = "payment")]
fn default_paddle_sandbox_mode() -> bool {
    true // Default to sandbox mode for safety
}

#[cfg(feature = "payment")]
fn default_payment_base_url() -> String {
    "https://localhost:8080".to_string() // Default for local development
}

#[cfg(feature = "payment")]
fn default_free_tier_token_limit() -> i64 {
    50000 // 50K tokens per month for free tier
}

#[cfg(feature = "payment")]
fn default_enforce_limits() -> bool {
    false // Default to not enforcing limits (for development)
}

#[cfg(feature = "payment")]
fn default_grace_period_days() -> i32 {
    7 // 7 days grace period after subscription expires
}

#[cfg(feature = "payment")]
fn default_subscription_config_path() -> String {
    "./backend/config/subscription_tiers.json".to_string()
}

#[cfg(feature = "payment")]
fn default_credits_enabled() -> bool {
    std::env::var("CREDITS_ENABLED")
        .ok()
        .and_then(|val| val.parse::<bool>().ok())
        .unwrap_or(false) // Credit system disabled by default (gradual rollout)
}

#[cfg(feature = "payment")]
fn default_soft_limits_enabled() -> bool {
    std::env::var("SOFT_LIMITS_ENABLED")
        .ok()
        .and_then(|val| val.parse::<bool>().ok())
        .unwrap_or(false) // Soft limits disabled by default (gradual rollout)
}

#[cfg(feature = "payment")]
fn default_credit_expiry_days() -> u32 {
    365 // Credits expire after 1 year by default
}

#[cfg(feature = "payment")]
fn default_min_credit_purchase() -> u32 {
    250 // Minimum 250 credits per purchase
}

#[cfg(feature = "payment")]
fn default_max_credit_balance() -> u32 {
    100000 // Maximum 100,000 credit balance
}

#[cfg(feature = "payment")]
fn default_usage_tracking_enabled() -> bool {
    true // Usage tracking enabled by default
}

#[cfg(feature = "payment")]
fn default_usage_reset_hour_utc() -> u8 {
    0 // Reset at midnight UTC
}

#[cfg(feature = "payment")]
fn default_webhook_retention_days() -> i64 {
    90 // Keep webhook events for 90 days (audit/compliance)
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

        // Manually load PaymentConfig since envy doesn't handle nested structs with prefixes well
        #[cfg(feature = "payment")]
        {
            config.payment = envy::prefixed("PAYMENT_")
                .from_env::<PaymentConfig>()
                .map_err(|e| anyhow::anyhow!("Failed to load PaymentConfig: {}", e))?;
        }

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
                "local" => "https://localhost:6334".to_string(),
                _ => "https://localhost:6334".to_string(),
            });
        }

        // Set environment-specific cookie security defaults
        if (environment == "local" || environment == "desktop") && self.session_cookie_secure {
            // For local development and desktop, default to non-secure cookies
            // Desktop uses custom protocol (scribe://) which doesn't support Secure flag
            self.session_cookie_secure = false;
        }
    }

    /// Validates the configuration for correctness and completeness
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration settings are invalid or missing
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate payment configuration if feature is enabled
        #[cfg(feature = "payment")]
        {
            self.validate_payment_config()?;
        }

        Ok(())
    }

    /// Validates payment-specific configuration
    #[cfg(feature = "payment")]
    fn validate_payment_config(&self) -> Result<(), anyhow::Error> {
        // Check if subscription config file exists and is valid
        if !std::path::Path::new(&self.payment.subscription_config_path).exists() {
            return Err(anyhow::anyhow!(
                "Subscription config file not found at: {}",
                self.payment.subscription_config_path
            ));
        }

        // Load and validate subscription configuration
        let config_content = std::fs::read_to_string(&self.payment.subscription_config_path)
            .map_err(|e| anyhow::anyhow!("Failed to read subscription config: {}", e))?;

        let tiers_config: crate::DbJson = serde_json::from_str(&config_content)
            .map_err(|e| anyhow::anyhow!("Invalid subscription config JSON: {}", e))?;

        // Validate required sections exist
        if tiers_config.get("tiers").is_none() {
            return Err(anyhow::anyhow!(
                "Missing 'tiers' section in subscription config"
            ));
        }

        if tiers_config.get("credit_system").is_none() {
            return Err(anyhow::anyhow!(
                "Missing 'credit_system' section in subscription config"
            ));
        }

        if tiers_config.get("feature_flags").is_none() {
            return Err(anyhow::anyhow!(
                "Missing 'feature_flags' section in subscription config"
            ));
        }

        // Validate each tier has required fields
        let tiers = tiers_config["tiers"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("'tiers' must be an object"))?;

        for (tier_name, tier_config) in tiers {
            self.validate_tier_config(tier_name, tier_config)?;
        }

        // Validate credit system configuration
        let credit_system = &tiers_config["credit_system"];
        self.validate_credit_system_config(credit_system)?;

        // Validate feature flags
        let feature_flags = &tiers_config["feature_flags"];
        self.validate_feature_flags(feature_flags)?;

        tracing::info!("Payment configuration validation passed");
        Ok(())
    }

    #[cfg(feature = "payment")]
    fn validate_tier_config(
        &self,
        tier_name: &str,
        tier_config: &serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        // Required fields for all tiers
        let required_fields = ["display_name", "limits", "credits", "models"];
        for field in &required_fields {
            if tier_config.get(field).is_none() {
                return Err(anyhow::anyhow!(
                    "Tier '{}' missing required field: '{}'",
                    tier_name,
                    field
                ));
            }
        }

        // Validate limits section
        let limits = &tier_config["limits"];
        let required_limit_fields = ["daily_messages", "daily_limit_type", "context_tokens"];
        for field in &required_limit_fields {
            if limits.get(field).is_none() {
                return Err(anyhow::anyhow!(
                    "Tier '{}' limits missing required field: '{}'",
                    tier_name,
                    field
                ));
            }
        }

        // Validate daily_messages is a positive number
        if let Some(daily_messages) = limits["daily_messages"].as_i64() {
            if daily_messages <= 0 {
                return Err(anyhow::anyhow!(
                    "Tier '{}' daily_messages must be positive, got: {}",
                    tier_name,
                    daily_messages
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Tier '{}' daily_messages must be a number",
                tier_name
            ));
        }

        // Validate context_tokens is positive
        if let Some(context_tokens) = limits["context_tokens"].as_i64() {
            if context_tokens <= 0 {
                return Err(anyhow::anyhow!(
                    "Tier '{}' context_tokens must be positive, got: {}",
                    tier_name,
                    context_tokens
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Tier '{}' context_tokens must be a number",
                tier_name
            ));
        }

        // Validate daily_limit_type is valid
        if let Some(limit_type) = limits["daily_limit_type"].as_str() {
            if !["hard", "soft"].contains(&limit_type) {
                return Err(anyhow::anyhow!(
                    "Tier '{}' daily_limit_type must be 'hard' or 'soft', got: '{}'",
                    tier_name,
                    limit_type
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Tier '{}' daily_limit_type must be a string",
                tier_name
            ));
        }

        Ok(())
    }

    #[cfg(feature = "payment")]
    fn validate_credit_system_config(
        &self,
        credit_system: &serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        // Check required fields
        if credit_system.get("enabled").is_none() {
            return Err(anyhow::anyhow!("Credit system missing 'enabled' field"));
        }

        if credit_system.get("model_costs").is_none() {
            return Err(anyhow::anyhow!("Credit system missing 'model_costs' field"));
        }

        // Validate model costs are non-negative
        let model_costs = credit_system["model_costs"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("'model_costs' must be an object"))?;

        for (model_name, cost) in model_costs {
            if let Some(cost_value) = cost.as_i64() {
                if cost_value < 0 {
                    return Err(anyhow::anyhow!(
                        "Model '{}' cost must be non-negative, got: {}",
                        model_name,
                        cost_value
                    ));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Model '{}' cost must be a number",
                    model_name
                ));
            }
        }

        // Validate supported models are present
        let supported_models = [
            "gemini-2.5-flash-lite",
            "gemini-2.5-flash",
            "gemini-2.5-pro",
        ];
        for model in &supported_models {
            if !model_costs.contains_key(*model) {
                return Err(anyhow::anyhow!(
                    "Model costs missing supported model: '{}'",
                    model
                ));
            }
        }

        Ok(())
    }

    #[cfg(feature = "payment")]
    fn validate_feature_flags(
        &self,
        feature_flags: &serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        // Check required feature flags exist
        let required_flags = ["credits_enabled", "soft_limits_enabled"];
        for flag in &required_flags {
            if feature_flags.get(flag).is_none() {
                return Err(anyhow::anyhow!(
                    "Feature flags missing required flag: '{}'",
                    flag
                ));
            }

            // Ensure they are booleans
            if !feature_flags[flag].is_boolean() {
                return Err(anyhow::anyhow!("Feature flag '{}' must be a boolean", flag));
            }
        }

        Ok(())
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
            adjoint_threshold: 1.0,
            lancedb_data_dir: None,                                   // LanceDB data directory
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
            #[cfg(feature = "payment")]
            payment: PaymentConfig::default(),
        }
    }
}
