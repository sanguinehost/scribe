// backend/src/services/ai_client_factory.rs
// Factory for creating appropriate AI clients based on user preferences

use crate::{
    config::Config,
    errors::AppError,
    llm::AiClient,
    models::user_settings::UserSettingsResponse,
    services::user_settings_service::UserSettingsService,
    state::DbPool,
};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[cfg(feature = "local-llm")]
use crate::llm::llamacpp::{LlamaCppClient, LlamaCppConfig};

/// Factory for creating AI clients based on user preferences
pub struct AiClientFactory {
    pool: DbPool,
    config: Arc<Config>,
    fallback_client: Arc<dyn AiClient + Send + Sync>,
}

impl AiClientFactory {
    /// Create a new AiClientFactory
    pub fn new(
        pool: DbPool,
        config: Arc<Config>,
        fallback_client: Arc<dyn AiClient + Send + Sync>,
    ) -> Self {
        Self {
            pool,
            config,
            fallback_client,
        }
    }

    /// Get the appropriate AI client based on provider type
    /// Returns the correct client for the specified provider (local, gemini, etc.)
    pub async fn get_client_for_provider(
        &self,
        user_id: Uuid,
        provider: Option<&str>,
        model_name: Option<&str>,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        info!(%user_id, provider = ?provider, model_name = ?model_name, "🔍 DEBUG: get_client_for_provider called with params");
        let provider = provider.unwrap_or("gemini"); // Default to gemini if no provider specified
        
        match provider {
            "local" | "llamacpp" => {
                #[cfg(feature = "local-llm")]
                {
                    match self.create_local_llm_client_for_model(user_id, model_name).await {
                        Ok(client) => {
                            info!(%user_id, model_name = ?model_name, "Created local LLM client for user");
                            Ok(client)
                        }
                        Err(e) => {
                            warn!(
                                %user_id,
                                error = ?e,
                                "Failed to create local LLM client, falling back to default"
                            );
                            Ok(self.fallback_client.clone())
                        }
                    }
                }

                #[cfg(not(feature = "local-llm"))]
                {
                    warn!(
                        %user_id,
                        "Local LLM requested but feature not compiled, using fallback client"
                    );
                    Ok(self.fallback_client.clone())
                }
            }
            "gemini" | _ => {
                info!(%user_id, provider, "Using Gemini client");
                Ok(self.fallback_client.clone())
            }
        }
    }

    /// Get the appropriate AI client for a user (legacy method for backward compatibility)
    /// Returns fallback client if user settings can't be loaded or local LLM is disabled
    pub async fn get_client_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        // Get user settings
        let user_settings = match UserSettingsService::get_user_settings(
            &self.pool,
            user_id,
            &self.config,
        ).await {
            Ok(settings) => settings,
            Err(e) => {
                warn!(%user_id, error = ?e, "Failed to get user settings, using fallback client");
                return Ok(self.fallback_client.clone());
            }
        };

        // Check if local LLM is enabled for this user
        let local_llm_enabled = user_settings.local_llm_enabled.unwrap_or(false);
        
        if !local_llm_enabled {
            info!(%user_id, "Local LLM disabled for user, using fallback client");
            return Ok(self.fallback_client.clone());
        }

        // Try to create local LLM client if enabled
        #[cfg(feature = "local-llm")]
        {
            match self.create_local_llm_client(&user_settings).await {
                Ok(client) => {
                    info!(%user_id, "Created local LLM client for user");
                    Ok(client)
                }
                Err(e) => {
                    warn!(
                        %user_id,
                        error = ?e,
                        "Failed to create local LLM client, falling back to default"
                    );
                    Ok(self.fallback_client.clone())
                }
            }
        }

        #[cfg(not(feature = "local-llm"))]
        {
            warn!(
                %user_id,
                "Local LLM requested but feature not compiled, using fallback client"
            );
            Ok(self.fallback_client.clone())
        }
    }

    /// Create a local LLM client for a specific model
    #[cfg(feature = "local-llm")]
    async fn create_local_llm_client_for_model(
        &self,
        user_id: Uuid,
        model_name: Option<&str>,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        // Get user settings for preferences
        let user_settings = UserSettingsService::get_user_settings(
            &self.pool,
            user_id,
            &self.config,
        ).await.ok(); // It's OK if user settings don't exist, we'll use defaults

        // Get base config from environment
        let mut config = LlamaCppConfig::from_env();

        // Override with specific model if provided
        if let Some(model) = model_name {
            config.model_path = format!("models/{}", model);
        } else if let Some(settings) = &user_settings {
            // Fall back to user's preferred model if available
            if let Some(preferred_model) = &settings.preferred_local_model {
                config.model_path = preferred_model.clone();
            }
        }

        // Apply user-specific model preferences from JSONB field
        if let Some(settings) = &user_settings {
            if let Some(model_preferences) = &settings.local_model_preferences {
                self.apply_model_preferences(&mut config, model_preferences)?;
            }
        }

        // Create the client
        let client = LlamaCppClient::new(config).await
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to create LlamaCpp client: {}", e)
            ))?;

        Ok(Arc::new(client))
    }

    /// Create a local LLM client based on user settings (legacy method)
    #[cfg(feature = "local-llm")]
    async fn create_local_llm_client(
        &self,
        user_settings: &UserSettingsResponse,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        // Get base config from environment
        let mut config = LlamaCppConfig::from_env();

        // Override with user preferences if available
        if let Some(preferred_model) = &user_settings.preferred_local_model {
            config.model_path = preferred_model.clone();
        }

        // Apply user-specific model preferences from JSONB field
        if let Some(model_preferences) = &user_settings.local_model_preferences {
            self.apply_model_preferences(&mut config, model_preferences)?;
        }

        // Create the client
        let client = LlamaCppClient::new(config).await
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to create LlamaCpp client: {}", e)
            ))?;

        Ok(Arc::new(client))
    }

    /// Apply user-specific model preferences to the LlamaCpp config
    #[cfg(feature = "local-llm")]
    fn apply_model_preferences(
        &self,
        config: &mut LlamaCppConfig,
        preferences: &serde_json::Value,
    ) -> Result<(), AppError> {
        if let Some(obj) = preferences.as_object() {
            // Apply context size if specified
            if let Some(ctx_size) = obj.get("context_size").and_then(|v| v.as_u64()) {
                config.context_size = ctx_size as usize;
            }

            // Apply GPU layers if specified
            if let Some(gpu_layers) = obj.get("gpu_layers").and_then(|v| v.as_i64()) {
                config.gpu_layers = Some(gpu_layers as i32);
            }
            
            // Apply threads if specified
            if let Some(threads) = obj.get("threads").and_then(|v| v.as_u64()) {
                config.threads = Some(threads as usize);
            }

            // Could add more preference mappings here as needed
        }

        Ok(())
    }

    /// Get the fallback client (typically Gemini)
    pub fn get_fallback_client(&self) -> Arc<dyn AiClient + Send + Sync> {
        self.fallback_client.clone()
    }

    /// Check if local LLM is available for any user
    /// This is useful for frontend to show/hide local LLM options
    pub async fn is_local_llm_available(&self) -> bool {
        #[cfg(feature = "local-llm")]
        {
            // Try to detect hardware to see if local LLM could work
            match crate::llm::llamacpp::hardware::detect_hardware() {
                Ok(_) => true,
                Err(e) => {
                    error!(error = ?e, "Hardware detection failed");
                    false
                }
            }
        }

        #[cfg(not(feature = "local-llm"))]
        {
            false
        }
    }
}

impl std::fmt::Debug for AiClientFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiClientFactory")
            .field("config", &self.config)
            .field("fallback_client", &"<dyn AiClient>")
            .finish()
    }
}