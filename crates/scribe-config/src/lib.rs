// crates/scribe-config/src/lib.rs

use serde::Deserialize;
use std::fmt;
use validator::Validate;

pub mod feature_flags;
pub use feature_flags::*;

#[cfg(test)]
mod tests;

#[derive(Deserialize, Clone, Validate)]
pub struct Config {
    // Database & API Keys
    pub database_url: Option<String>,
    pub gemini_api_key: Option<String>,
    #[serde(default = "default_gemini_api_base_url")]
    pub gemini_api_base_url: String,

    // Server Config
    #[serde(default = "default_port")]
    pub port: u16,
    pub cookie_signing_key: Option<String>,
    #[serde(default = "default_session_cookie_secure")]
    pub session_cookie_secure: bool,
    pub environment: Option<String>,
    pub cookie_domain: Option<String>,

    // Qdrant Config
    pub qdrant_url: Option<String>,
    pub qdrant_api_key: Option<String>,
    #[serde(default = "default_qdrant_collection_name")]
    pub qdrant_collection_name: String,
    #[serde(default = "default_embedding_dimension")]
    pub embedding_dimension: u64,
    #[serde(default = "default_qdrant_distance_metric")]
    pub qdrant_distance_metric: String,
    pub qdrant_on_disk: Option<bool>,

    // LanceDB Config
    pub lancedb_data_dir: Option<std::path::PathBuf>,

    // Chunking Config
    #[serde(default = "default_chunking_metric")]
    pub chunking_metric: String,
    #[serde(default = "default_chunking_max_size")]
    pub chunking_max_size: usize,
    #[serde(default = "default_chunking_overlap")]
    pub chunking_overlap: usize,

    // Tokenizer Config
    #[serde(default = "default_tokenizer_model_path")]
    pub tokenizer_model_path: String,
    #[serde(default = "default_token_counter_default_model")]
    pub token_counter_default_model: String,

    // Context Token Limits
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

    #[serde(default = "default_app_env")]
    pub app_env: String,
    pub from_email: Option<String>,

    #[serde(default)]
    pub narrative_flags: NarrativeFeatureFlags,

    #[serde(default)]
    pub security: SecurityConfig,

    #[cfg(feature = "payment")]
    #[serde(default)]
    pub payment: PaymentConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("Config");
        ds.field("database_url", &self.database_url.as_ref().map(|_| "[REDACTED]"))
          .field("gemini_api_key", &self.gemini_api_key.as_ref().map(|_| "[REDACTED]"))
          .field("port", &self.port)
          .field("environment", &self.environment)
          .field("app_env", &self.app_env);
          
        #[cfg(feature = "payment")]
        ds.field("payment", &self.payment);
        
        ds.finish()
    }
}

// ... Default functions ...
fn default_gemini_api_base_url() -> String { "https://generativelanguage.googleapis.com".to_string() }
const fn default_port() -> u16 { 8080 }
const fn default_session_cookie_secure() -> bool { true }
fn default_qdrant_collection_name() -> String { "scribe_embeddings".to_string() }
const fn default_embedding_dimension() -> u64 { 768 }
fn default_qdrant_distance_metric() -> String { "Cosine".to_string() }
fn default_chunking_metric() -> String { "word".to_string() }
const fn default_chunking_max_size() -> usize { 1000 }
const fn default_chunking_overlap() -> usize { 50 }
fn default_tokenizer_model_path() -> String { "resources/tokenizers/tokenizer.json".to_string() }
fn default_token_counter_default_model() -> String { "gemini-2.5-flash".to_string() }
const fn default_context_total_token_limit() -> usize { 200_000 }
const fn default_context_recent_history_token_budget() -> usize { 150_000 }
const fn default_context_rag_token_budget() -> usize { 50_000 }
const fn default_min_tail_messages_to_preserve() -> usize { 8 }
fn default_frontend_base_url() -> String { "https://localhost:5173".to_string() }
fn default_app_env() -> String { "development".to_string() }

#[derive(Debug, Clone, Deserialize, Validate)]
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

fn default_max_context_tokens() -> usize { 1048576 }
fn default_max_requests_per_minute() -> u32 { 10 }
fn default_max_requests_per_hour() -> u32 { 100 }
fn default_max_concurrent_requests() -> u32 { 3 }
fn default_audit_retention_hours() -> u64 { 168 }
fn default_prompt_max_length() -> usize { 8192 }
fn default_response_max_length() -> usize { 8192 }
fn default_security_logging_enabled() -> bool { true }

#[cfg(feature = "payment")]
#[derive(Deserialize, Clone, Debug)]
pub struct PaymentConfig {
    pub paddle_api_key: Option<String>,
    pub paddle_webhook_secret: Option<String>,
    pub data_encryption_key: Option<String>,
    pub paddle_basic_monthly_price_id: Option<String>,
    pub paddle_basic_yearly_price_id: Option<String>,
    pub paddle_premium_monthly_price_id: Option<String>,
    pub paddle_premium_yearly_price_id: Option<String>,
    pub paddle_credits_250_price_id: Option<String>,
    pub paddle_credits_500_price_id: Option<String>,
    pub paddle_credits_1500_price_id: Option<String>,
    pub paddle_credits_3500_price_id: Option<String>,
    pub paddle_credits_8000_price_id: Option<String>,
    #[serde(default = "default_paddle_sandbox_mode")]
    pub paddle_sandbox_mode: bool,
    #[serde(default = "default_payment_base_url")]
    pub payment_base_url: String,
    #[serde(default = "default_free_tier_token_limit")]
    pub free_tier_token_limit: i64,
    #[serde(default = "default_enforce_limits")]
    pub enforce_limits: bool,
    #[serde(default = "default_grace_period_days")]
    pub grace_period_days: i32,
    #[serde(default = "default_subscription_config_path")]
    pub subscription_config_path: String,
    #[serde(default = "default_credits_enabled")]
    pub credits_enabled: bool,
    #[serde(default = "default_soft_limits_enabled")]
    pub soft_limits_enabled: bool,
    #[serde(default = "default_credit_expiry_days")]
    pub credit_expiry_days: u32,
    #[serde(default = "default_min_credit_purchase")]
    pub min_credit_purchase: u32,
    #[serde(default = "default_max_credit_balance")]
    pub max_credit_balance: u32,
    #[serde(default = "default_usage_tracking_enabled")]
    pub usage_tracking_enabled: bool,
    #[serde(default = "default_usage_reset_hour_utc")]
    pub usage_reset_hour_utc: u8,
    #[serde(default = "default_webhook_retention_days")]
    pub webhook_event_retention_days: i64,
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
fn default_paddle_sandbox_mode() -> bool { true }
#[cfg(feature = "payment")]
fn default_payment_base_url() -> String { "https://localhost:8080".to_string() }
#[cfg(feature = "payment")]
fn default_free_tier_token_limit() -> i64 { 50000 }
#[cfg(feature = "payment")]
fn default_enforce_limits() -> bool { false }
#[cfg(feature = "payment")]
fn default_grace_period_days() -> i32 { 7 }
#[cfg(feature = "payment")]
fn default_subscription_config_path() -> String { "./backend/config/subscription_tiers.json".to_string() }
#[cfg(feature = "payment")]
fn default_credits_enabled() -> bool { false }
#[cfg(feature = "payment")]
fn default_soft_limits_enabled() -> bool { false }
#[cfg(feature = "payment")]
fn default_credit_expiry_days() -> u32 { 365 }
#[cfg(feature = "payment")]
fn default_min_credit_purchase() -> u32 { 250 }
#[cfg(feature = "payment")]
fn default_max_credit_balance() -> u32 { 100000 }
#[cfg(feature = "payment")]
fn default_usage_tracking_enabled() -> bool { true }
#[cfg(feature = "payment")]
fn default_usage_reset_hour_utc() -> u8 { 0 }
#[cfg(feature = "payment")]
fn default_webhook_retention_days() -> i64 { 90 }

impl Config {
    pub fn load() -> Result<Self, anyhow::Error> {
        let mut config = envy::from_env::<Self>().map_err(anyhow::Error::from)?;

        #[cfg(feature = "payment")]
        {
            config.payment = envy::prefixed("PAYMENT_")
                .from_env::<PaymentConfig>()
                .map_err(|e| anyhow::anyhow!("Failed to load PaymentConfig: {}", e))?;
        }

        config.apply_environment_defaults();
        Ok(config)
    }

    pub fn apply_environment_defaults(&mut self) {
        let environment = self.environment.as_deref().unwrap_or("local");

        if self.qdrant_url.is_none() {
            self.qdrant_url = Some(match environment {
                "staging" => "https://qdrant.staging.local:6334".to_string(),
                "production" => "https://qdrant.production.local:6334".to_string(),
                "container" => "https://qdrant:6334".to_string(),
                _ => "https://localhost:6334".to_string(),
            });
        }

        if (environment == "local" || environment == "desktop") && self.session_cookie_secure {
            self.session_cookie_secure = false;
        }
    }
}
