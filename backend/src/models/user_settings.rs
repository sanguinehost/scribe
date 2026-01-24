use crate::db::{DbBigDecimal, DbId, DbJson, DbTimestamp};
use crate::schema::user_settings;
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone, Debug)]
#[diesel(table_name = user_settings)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct UserSettings {
    pub id: DbId,
    pub user_id: DbId,

    // Generation Settings (nullable - fall back to system defaults if not set)
    pub default_model_name: Option<String>,
    pub default_temperature: Option<DbBigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<DbBigDecimal>,
    pub default_presence_penalty: Option<DbBigDecimal>,
    pub default_top_p: Option<DbBigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Thinking & Code Execution Settings
    pub default_thinking_budget: Option<i32>,
    pub default_thinking_level: Option<String>,
    pub default_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,
    pub default_rag_chronicles_limit: Option<i32>,
    pub default_rag_lorebooks_limit: Option<i32>,
    pub default_rag_older_chat_limit: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,

    // Local LLM Settings
    pub preferred_local_model: Option<String>,
    pub local_llm_enabled: Option<bool>,
    pub local_model_preferences: Option<DbJson>,

    // Timestamps
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub typing_speed: Option<i32>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = user_settings)]
#[diesel(treat_none_as_null = true)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewUserSettings {
    pub user_id: DbId,

    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<DbBigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<DbBigDecimal>,
    pub default_presence_penalty: Option<DbBigDecimal>,
    pub default_top_p: Option<DbBigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Thinking & Code Execution Settings
    pub default_thinking_budget: Option<i32>,
    pub default_thinking_level: Option<String>,
    pub default_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,
    pub default_rag_chronicles_limit: Option<i32>,
    pub default_rag_lorebooks_limit: Option<i32>,
    pub default_rag_older_chat_limit: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,
    pub preferred_local_model: Option<String>,
    pub local_llm_enabled: Option<bool>,
    pub local_model_preferences: Option<DbJson>,
}

#[derive(Deserialize, Debug, Clone, validator::Validate)]
pub struct UpdateUserSettingsRequest {
    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<DbBigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<DbBigDecimal>,
    pub default_presence_penalty: Option<DbBigDecimal>,
    pub default_top_p: Option<DbBigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Thinking & Code Execution Settings
    pub default_thinking_budget: Option<i32>,
    pub default_thinking_level: Option<String>,
    pub default_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub default_rag_chronicles_limit: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub default_rag_lorebooks_limit: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub default_rag_older_chat_limit: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,
    pub preferred_local_model: Option<String>,
    pub local_llm_enabled: Option<bool>,
    pub local_model_preferences: Option<DbJson>,
}

#[derive(Serialize, Deserialize, Debug, Clone)] // Added Deserialize
pub struct UserSettingsResponse {
    // Generation Settings
    pub default_model_name: Option<String>,
    pub default_temperature: Option<DbBigDecimal>,
    pub default_max_output_tokens: Option<i32>,
    pub default_frequency_penalty: Option<DbBigDecimal>,
    pub default_presence_penalty: Option<DbBigDecimal>,
    pub default_top_p: Option<DbBigDecimal>,
    pub default_top_k: Option<i32>,
    pub default_seed: Option<i32>,

    // Thinking & Code Execution Settings
    pub default_thinking_budget: Option<i32>,
    pub default_thinking_level: Option<String>,
    pub default_enable_code_execution: Option<bool>,

    // Context Management Settings
    pub default_context_total_token_limit: Option<i32>,
    pub default_context_recent_history_budget: Option<i32>,
    pub default_context_rag_budget: Option<i32>,
    pub default_rag_chronicles_limit: Option<i32>,
    pub default_rag_lorebooks_limit: Option<i32>,
    pub default_rag_older_chat_limit: Option<i32>,

    // Application Preferences
    pub auto_save_chats: Option<bool>,
    pub theme: Option<String>,
    pub notifications_enabled: Option<bool>,
    pub typing_speed: Option<i32>,
    pub preferred_local_model: Option<String>,
    pub local_llm_enabled: Option<bool>,
    pub local_model_preferences: Option<DbJson>,

    // Timestamps
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
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
            default_thinking_budget: settings.default_thinking_budget,
            default_thinking_level: settings.default_thinking_level,
            default_enable_code_execution: settings.default_enable_code_execution,
            default_context_total_token_limit: settings.default_context_total_token_limit,
            default_context_recent_history_budget: settings.default_context_recent_history_budget,
            default_context_rag_budget: settings.default_context_rag_budget,
            default_rag_chronicles_limit: settings.default_rag_chronicles_limit,
            default_rag_lorebooks_limit: settings.default_rag_lorebooks_limit,
            default_rag_older_chat_limit: settings.default_rag_older_chat_limit,
            auto_save_chats: settings.auto_save_chats,
            theme: settings.theme,
            notifications_enabled: settings.notifications_enabled,
            typing_speed: settings.typing_speed,
            preferred_local_model: settings.preferred_local_model,
            local_llm_enabled: settings.local_llm_enabled,
            local_model_preferences: settings.local_model_preferences,
            created_at: settings.created_at,
            updated_at: settings.updated_at,
        }
    }
}
