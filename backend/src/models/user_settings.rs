use crate::schema::user_settings;
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone, Debug)]
#[diesel(table_name = user_settings)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserSettings {
    pub id: Uuid,
    pub user_id: Uuid,

    // Generation Settings (nullable - fall back to system defaults if not set)
    pub default_model_name: Option<String>,
    pub default_temperature: Option<BigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<BigDecimal>,
    pub default_presence_penalty: Option<BigDecimal>,
    pub default_top_p: Option<BigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Gemini-Specific Settings
    pub default_gemini_thinking_budget: Option<i32>,
    pub default_gemini_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,

    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub typing_speed: Option<i32>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = user_settings)]
pub struct NewUserSettings {
    pub user_id: Uuid,

    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<BigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<BigDecimal>,
    pub default_presence_penalty: Option<BigDecimal>,
    pub default_top_p: Option<BigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Gemini-Specific Settings
    pub default_gemini_thinking_budget: Option<i32>,
    pub default_gemini_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpdateUserSettingsRequest {
    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<BigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<BigDecimal>,
    pub default_presence_penalty: Option<BigDecimal>,
    pub default_top_p: Option<BigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Gemini-Specific Settings
    pub default_gemini_thinking_budget: Option<i32>,
    pub default_gemini_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)] // Added Deserialize
pub struct UserSettingsResponse {
    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<BigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<BigDecimal>,
    pub default_presence_penalty: Option<BigDecimal>,
    pub default_top_p: Option<BigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Gemini-Specific Settings
    pub default_gemini_thinking_budget: Option<i32>,
    pub default_gemini_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,

    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserSettings> for UserSettingsResponse {
    fn from(settings: UserSettings) -> Self {
        Self {
            default_model_name: settings.default_model_name,
            default_temperature: settings.default_temperature,
            default_max_output_tokens: settings.default_max_output_tokens,
            default_frequency_penalty: settings.default_frequency_penalty,
            default_presence_penalty: settings.default_presence_penalty,
            default_top_p: settings.default_top_p,
            default_top_k: settings.default_top_k,
            default_seed: settings.default_seed,
            default_gemini_thinking_budget: settings.default_gemini_thinking_budget,
            default_gemini_enable_code_execution: settings.default_gemini_enable_code_execution,
            default_context_total_token_limit: settings.default_context_total_token_limit,
            default_context_recent_history_budget: settings.default_context_recent_history_budget,
            default_context_rag_budget: settings.default_context_rag_budget,
            auto_save_chats: settings.auto_save_chats,
            theme: settings.theme,
            notifications_enabled: settings.notifications_enabled,
            typing_speed: settings.typing_speed,
            created_at: settings.created_at,
            updated_at: settings.updated_at,
        }
    }
}
