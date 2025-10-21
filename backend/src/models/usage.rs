use crate::DbDateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::DbUuid as Uuid;

/// Token usage tracking for a specific chat session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTokenUsage {
    pub chat_id: crate::DbUuid,
    pub total_prompt_tokens: i32,
    pub total_completion_tokens: i32,
    pub total_tokens: i32,
    pub estimated_cost_cents: i32,
    pub estimated_cost_dollars: f64,
    pub tokens_counted_at: DbDateTime,
    pub model_name: String,
}

/// Aggregated token usage summary for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageSummary {
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_tokens: i64,
    pub total_cost_cents: i64,
    pub total_cost_dollars: f64,
    pub tokens_last_reset_at: Option<DbDateTime>,
    pub token_usage_updated_at: DbDateTime,
}
