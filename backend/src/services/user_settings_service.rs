use diesel::{OptionalExtension, prelude::*};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use bigdecimal::BigDecimal;
use crate::{
    config::Config,
    errors::AppError,
    models::user_settings::{
        UpdateUserSettingsRequest, UserSettingsResponse,
    },
    schema::user_settings,
    state::DbPool,
};

pub struct UserSettingsService;

impl UserSettingsService {
    /// Gets user settings for a specific user, creating default settings if none exist
    #[instrument(skip(pool), err)]
    pub async fn get_user_settings(
        pool: &DbPool,
        user_id: Uuid,
        config: &Config,
    ) -> Result<UserSettingsResponse, AppError> {
        let conn = pool.get().await?;

        // Clone config values we need to move into the closure
        let default_model = config.token_counter_default_model.clone();
        let context_total_limit = config.context_total_token_limit as i32;
        let context_history_budget = config.context_recent_history_token_budget as i32;
        let context_rag_budget = config.context_rag_token_budget as i32;

        conn.interact(move |conn| {
            // Check if user settings exist using a simple query
            let settings_exist = user_settings::table
                .filter(user_settings::user_id.eq(user_id))
                .select(user_settings::id)
                .first::<uuid::Uuid>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            match settings_exist {
                Some(_) => {
                    // Settings exist, retrieve them using selective fields
                    let settings = user_settings::table
                        .filter(user_settings::user_id.eq(user_id))
                        .select((
                            user_settings::default_model_name,
                            user_settings::default_temperature,
                            user_settings::default_max_output_tokens,
                            user_settings::default_frequency_penalty,
                            user_settings::default_presence_penalty,
                            user_settings::default_top_p,
                            user_settings::default_top_k,
                            user_settings::default_seed,
                            user_settings::default_gemini_thinking_budget,
                            user_settings::default_gemini_enable_code_execution,
                            user_settings::default_context_total_token_limit,
                            user_settings::default_context_recent_history_budget,
                            user_settings::default_context_rag_budget,
                            user_settings::auto_save_chats,
                            user_settings::theme,
                        ))
                        .first::<(
                            Option<String>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>,
                            Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<i32>,
                            Option<i32>, Option<bool>, Option<i32>, Option<i32>, Option<i32>,
                            Option<bool>, Option<String>,
                        )>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    let (timestamps, ui_settings, local_settings) = user_settings::table
                        .filter(user_settings::user_id.eq(user_id))
                        .select((
                            (user_settings::created_at, user_settings::updated_at),
                            (user_settings::notifications_enabled, user_settings::typing_speed),
                            (user_settings::preferred_local_model, user_settings::local_llm_enabled, user_settings::local_model_preferences),
                        ))
                        .first::<(
                            (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
                            (Option<bool>, Option<i32>),
                            (Option<String>, Option<bool>, Option<serde_json::Value>),
                        )>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    let response = UserSettingsResponse {
                        default_model_name: settings.0,
                        default_temperature: settings.1,
                        default_max_output_tokens: settings.2,
                        default_frequency_penalty: settings.3,
                        default_presence_penalty: settings.4,
                        default_top_p: settings.5,
                        default_top_k: settings.6,
                        default_seed: settings.7,
                        default_gemini_thinking_budget: settings.8,
                        default_gemini_enable_code_execution: settings.9,
                        default_context_total_token_limit: settings.10,
                        default_context_recent_history_budget: settings.11,
                        default_context_rag_budget: settings.12,
                        auto_save_chats: settings.13,
                        theme: settings.14,
                        notifications_enabled: ui_settings.0,
                        typing_speed: ui_settings.1,
                        preferred_local_model: local_settings.0,
                        local_llm_enabled: local_settings.1,
                        local_model_preferences: local_settings.2,
                        created_at: timestamps.0,
                        updated_at: timestamps.1,
                    };

                    info!(%user_id, "Found existing user settings");
                    Ok(response)
                }
                None => {
                    info!(%user_id, "No user settings found, creating default settings");
                    // Use raw SQL to avoid Diesel tuple size limit
                    use diesel::sql_query;
                    
                    // First, insert with raw SQL without returning
                    sql_query(
                        r#"
                        INSERT INTO user_settings (
                            user_id, default_model_name, default_context_total_token_limit, 
                            default_context_recent_history_budget, default_context_rag_budget, 
                            auto_save_chats, theme, notifications_enabled, typing_speed, 
                            local_llm_enabled
                        ) VALUES (
                            $1, $2, $3, $4, $5, TRUE, 'system', TRUE, 30, FALSE
                        )
                        "#
                    )
                    .bind::<diesel::sql_types::Uuid, _>(user_id)
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(default_model.clone()))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_total_limit))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_history_budget))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_rag_budget))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Then retrieve using a simple query
                    let created_settings = user_settings::table
                        .filter(user_settings::user_id.eq(user_id))
                        .select((
                            user_settings::default_model_name,
                            user_settings::default_context_total_token_limit,
                            user_settings::default_context_recent_history_budget,
                            user_settings::default_context_rag_budget,
                            user_settings::auto_save_chats,
                            user_settings::theme,
                            user_settings::notifications_enabled,
                            user_settings::typing_speed,
                            user_settings::local_llm_enabled,
                            user_settings::created_at,
                            user_settings::updated_at,
                        ))
                        .first::<(Option<String>, Option<i32>, Option<i32>, Option<i32>, Option<bool>, Option<String>, Option<bool>, Option<i32>, Option<bool>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Manually construct the response
                    let response = UserSettingsResponse {
                        default_model_name: created_settings.0,
                        default_temperature: None,
                        default_max_output_tokens: None,
                        default_frequency_penalty: None,
                        default_presence_penalty: None,
                        default_top_p: None,
                        default_top_k: None,
                        default_seed: None,
                        default_gemini_thinking_budget: None,
                        default_gemini_enable_code_execution: None,
                        default_context_total_token_limit: created_settings.1,
                        default_context_recent_history_budget: created_settings.2,
                        default_context_rag_budget: created_settings.3,
                        auto_save_chats: created_settings.4,
                        theme: created_settings.5,
                        notifications_enabled: created_settings.6,
                        typing_speed: created_settings.7,
                        preferred_local_model: None,
                        local_llm_enabled: created_settings.8,
                        local_model_preferences: None,
                        created_at: created_settings.9,
                        updated_at: created_settings.10,
                    };

                    info!(%user_id, "Created default user settings");
                    Ok(response)
                }
            }
        })
        .await?
    }

    /// Updates user settings for a specific user
    #[instrument(skip(pool), err)]
    pub async fn update_user_settings(
        pool: &DbPool,
        user_id: Uuid,
        update_request: UpdateUserSettingsRequest,
        config: &Config,
    ) -> Result<UserSettingsResponse, AppError> {
        let conn = pool.get().await?;

        // Clone config values we need to move into the closure
        let default_model = config.token_counter_default_model.clone();
        let context_total_limit = config.context_total_token_limit as i32;
        let context_history_budget = config.context_recent_history_token_budget as i32;
        let context_rag_budget = config.context_rag_token_budget as i32;

        conn.interact(move |conn| {
            // Check if user settings exist, create if needed
            let settings_id = user_settings::table
                .filter(user_settings::user_id.eq(user_id))
                .select(user_settings::id)
                .first::<uuid::Uuid>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let settings_id = match settings_id {
                Some(id) => id,
                None => {
                    // Create default settings first using raw SQL
                    use diesel::sql_query;
                    sql_query(
                        r#"
                        INSERT INTO user_settings (
                            user_id, default_model_name, default_context_total_token_limit,
                            default_context_recent_history_budget, default_context_rag_budget,
                            auto_save_chats, theme, notifications_enabled, typing_speed,
                            local_llm_enabled
                        ) VALUES (
                            $1, $2, $3, $4, $5, TRUE, 'system', TRUE, 30, FALSE
                        )
                        "#
                    )
                    .bind::<diesel::sql_types::Uuid, _>(user_id)
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(default_model.clone()))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_total_limit))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_history_budget))
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Int4>, _>(Some(context_rag_budget))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Get the ID of the newly created settings
                    user_settings::table
                        .filter(user_settings::user_id.eq(user_id))
                        .select(user_settings::id)
                        .first::<uuid::Uuid>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                }
            };

            // Split the update into two parts to avoid Diesel tuple size limit
            
            // First update: Core generation and context settings (15 fields)
            diesel::update(user_settings::table.filter(user_settings::id.eq(settings_id)))
                .set((
                    user_settings::default_model_name.eq(update_request.default_model_name),
                    user_settings::default_temperature.eq(update_request.default_temperature),
                    user_settings::default_max_output_tokens.eq(update_request.default_max_output_tokens),
                    user_settings::default_frequency_penalty.eq(update_request.default_frequency_penalty),
                    user_settings::default_presence_penalty.eq(update_request.default_presence_penalty),
                    user_settings::default_top_p.eq(update_request.default_top_p),
                    user_settings::default_top_k.eq(update_request.default_top_k),
                    user_settings::default_seed.eq(update_request.default_seed),
                    user_settings::default_gemini_thinking_budget.eq(update_request.default_gemini_thinking_budget),
                    user_settings::default_gemini_enable_code_execution.eq(update_request.default_gemini_enable_code_execution),
                    user_settings::default_context_total_token_limit.eq(update_request.default_context_total_token_limit),
                    user_settings::default_context_recent_history_budget.eq(update_request.default_context_recent_history_budget),
                    user_settings::default_context_rag_budget.eq(update_request.default_context_rag_budget),
                    user_settings::auto_save_chats.eq(update_request.auto_save_chats),
                    user_settings::theme.eq(update_request.theme),
                ))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Second update: UI preferences and local LLM settings (5 fields)
            diesel::update(user_settings::table.filter(user_settings::id.eq(settings_id)))
                .set((
                    user_settings::notifications_enabled.eq(update_request.notifications_enabled),
                    user_settings::typing_speed.eq(update_request.typing_speed),
                    user_settings::preferred_local_model.eq(update_request.preferred_local_model),
                    user_settings::local_llm_enabled.eq(update_request.local_llm_enabled),
                    user_settings::local_model_preferences.eq(update_request.local_model_preferences),
                ))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // After updates, retrieve the updated settings using selective queries
            let settings = user_settings::table
                .filter(user_settings::id.eq(settings_id))
                .select((
                    user_settings::default_model_name,
                    user_settings::default_temperature,
                    user_settings::default_max_output_tokens,
                    user_settings::default_frequency_penalty,
                    user_settings::default_presence_penalty,
                    user_settings::default_top_p,
                    user_settings::default_top_k,
                    user_settings::default_seed,
                    user_settings::default_gemini_thinking_budget,
                    user_settings::default_gemini_enable_code_execution,
                    user_settings::default_context_total_token_limit,
                    user_settings::default_context_recent_history_budget,
                    user_settings::default_context_rag_budget,
                    user_settings::auto_save_chats,
                    user_settings::theme,
                ))
                .first::<(
                    Option<String>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>,
                    Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<i32>,
                    Option<i32>, Option<bool>, Option<i32>, Option<i32>, Option<i32>,
                    Option<bool>, Option<String>,
                )>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let (timestamps, ui_settings, local_settings) = user_settings::table
                .filter(user_settings::id.eq(settings_id))
                .select((
                    (user_settings::created_at, user_settings::updated_at),
                    (user_settings::notifications_enabled, user_settings::typing_speed),
                    (user_settings::preferred_local_model, user_settings::local_llm_enabled, user_settings::local_model_preferences),
                ))
                .first::<(
                    (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
                    (Option<bool>, Option<i32>),
                    (Option<String>, Option<bool>, Option<serde_json::Value>),
                )>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let updated_settings = UserSettingsResponse {
                default_model_name: settings.0,
                default_temperature: settings.1,
                default_max_output_tokens: settings.2,
                default_frequency_penalty: settings.3,
                default_presence_penalty: settings.4,
                default_top_p: settings.5,
                default_top_k: settings.6,
                default_seed: settings.7,
                default_gemini_thinking_budget: settings.8,
                default_gemini_enable_code_execution: settings.9,
                default_context_total_token_limit: settings.10,
                default_context_recent_history_budget: settings.11,
                default_context_rag_budget: settings.12,
                auto_save_chats: settings.13,
                theme: settings.14,
                notifications_enabled: ui_settings.0,
                typing_speed: ui_settings.1,
                preferred_local_model: local_settings.0,
                local_llm_enabled: local_settings.1,
                local_model_preferences: local_settings.2,
                created_at: timestamps.0,
                updated_at: timestamps.1,
            };

            info!(%user_id, "Updated user settings");
            Ok(updated_settings)
        })
        .await?
    }

    /// Deletes user settings for a specific user (resets to system defaults)
    #[instrument(skip(pool), err)]
    pub async fn delete_user_settings(pool: &DbPool, user_id: Uuid) -> Result<(), AppError> {
        let conn = pool.get().await?;

        conn.interact(move |conn| {
            let deleted_count =
                diesel::delete(user_settings::table.filter(user_settings::user_id.eq(user_id)))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if deleted_count > 0 {
                info!(%user_id, deleted_count, "Deleted user settings");
            } else {
                warn!(%user_id, "No user settings found to delete");
            }

            Ok(())
        })
        .await?
    }
}
