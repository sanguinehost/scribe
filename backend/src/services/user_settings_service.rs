use diesel::{OptionalExtension, prelude::*};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    errors::AppError,
    models::user_settings::{
        NewUserSettings, UpdateUserSettingsRequest, UserSettings, UserSettingsResponse,
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
            // Try to get existing settings
            let existing_settings = user_settings::table
                .filter(user_settings::user_id.eq(user_id))
                .first::<UserSettings>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            match existing_settings {
                Some(settings) => {
                    info!(%user_id, "Found existing user settings");
                    Ok(UserSettingsResponse::from(settings))
                }
                None => {
                    info!(%user_id, "No user settings found, creating default settings");
                    // Create default settings for the user
                    let new_settings = NewUserSettings {
                        user_id,
                        default_model_name: Some(default_model.clone()),
                        default_temperature: None, // Will use system defaults
                        default_max_output_tokens: None,
                        default_frequency_penalty: None,
                        default_presence_penalty: None,
                        default_top_p: None,
                        default_top_k: None,
                        default_seed: None,
                        default_gemini_thinking_budget: None,
                        default_gemini_enable_code_execution: None,
                        default_context_total_token_limit: Some(context_total_limit),
                        default_context_recent_history_budget: Some(context_history_budget),
                        default_context_rag_budget: Some(context_rag_budget),
                        auto_save_chats: Some(true),
                        theme: Some("system".to_string()),
                        notifications_enabled: Some(true),
                        typing_speed: Some(30), // Default typing speed
                    };

                    let created_settings = diesel::insert_into(user_settings::table)
                        .values(&new_settings)
                        .get_result::<UserSettings>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    info!(%user_id, "Created default user settings");
                    Ok(UserSettingsResponse::from(created_settings))
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
            // First ensure the user has settings (create if not exists)
            let existing_settings = user_settings::table
                .filter(user_settings::user_id.eq(user_id))
                .first::<UserSettings>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let settings = match existing_settings {
                Some(settings) => settings,
                None => {
                    // Create default settings first
                    let new_settings = NewUserSettings {
                        user_id,
                        default_model_name: Some(default_model.clone()),
                        default_temperature: None,
                        default_max_output_tokens: None,
                        default_frequency_penalty: None,
                        default_presence_penalty: None,
                        default_top_p: None,
                        default_top_k: None,
                        default_seed: None,
                        default_gemini_thinking_budget: None,
                        default_gemini_enable_code_execution: None,
                        default_context_total_token_limit: Some(context_total_limit),
                        default_context_recent_history_budget: Some(context_history_budget),
                        default_context_rag_budget: Some(context_rag_budget),
                        auto_save_chats: Some(true),
                        theme: Some("system".to_string()),
                        notifications_enabled: Some(true),
                        typing_speed: Some(30), // Default typing speed
                    };

                    diesel::insert_into(user_settings::table)
                        .values(&new_settings)
                        .get_result::<UserSettings>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                }
            };

            // Update the settings with the new values
            let updated_settings =
                diesel::update(user_settings::table.filter(user_settings::id.eq(settings.id)))
                    .set((
                        user_settings::default_model_name.eq(update_request
                            .default_model_name
                            .or(settings.default_model_name)),
                        user_settings::default_temperature.eq(update_request
                            .default_temperature
                            .or(settings.default_temperature)),
                        user_settings::default_max_output_tokens.eq(update_request
                            .default_max_output_tokens
                            .or(settings.default_max_output_tokens)),
                        user_settings::default_frequency_penalty.eq(update_request
                            .default_frequency_penalty
                            .or(settings.default_frequency_penalty)),
                        user_settings::default_presence_penalty.eq(update_request
                            .default_presence_penalty
                            .or(settings.default_presence_penalty)),
                        user_settings::default_top_p
                            .eq(update_request.default_top_p.or(settings.default_top_p)),
                        user_settings::default_top_k
                            .eq(update_request.default_top_k.or(settings.default_top_k)),
                        user_settings::default_seed
                            .eq(update_request.default_seed.or(settings.default_seed)),
                        user_settings::default_gemini_thinking_budget.eq(update_request
                            .default_gemini_thinking_budget
                            .or(settings.default_gemini_thinking_budget)),
                        user_settings::default_gemini_enable_code_execution.eq(update_request
                            .default_gemini_enable_code_execution
                            .or(settings.default_gemini_enable_code_execution)),
                        user_settings::default_context_total_token_limit.eq(update_request
                            .default_context_total_token_limit
                            .or(settings.default_context_total_token_limit)),
                        user_settings::default_context_recent_history_budget.eq(update_request
                            .default_context_recent_history_budget
                            .or(settings.default_context_recent_history_budget)),
                        user_settings::default_context_rag_budget.eq(update_request
                            .default_context_rag_budget
                            .or(settings.default_context_rag_budget)),
                        user_settings::auto_save_chats
                            .eq(update_request.auto_save_chats.or(settings.auto_save_chats)),
                        user_settings::theme.eq(update_request.theme.or(settings.theme)),
                        user_settings::notifications_enabled.eq(update_request
                            .notifications_enabled
                            .or(settings.notifications_enabled)),
                        user_settings::typing_speed.eq(update_request
                            .typing_speed
                            .or(settings.typing_speed)),
                    ))
                    .get_result::<UserSettings>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            info!(%user_id, "Updated user settings");
            Ok(UserSettingsResponse::from(updated_settings))
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
