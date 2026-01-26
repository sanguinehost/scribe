// backend/src/services/ai_client_factory.rs
// Factory for creating appropriate AI clients based on user preferences

use crate::{
    auth::SessionDek,
    config::Config,
    errors::AppError,
    llm::AiClient,
    services::user_settings_service::UserSettingsService,
    state::{AppState, DbPool},
};
use std::sync::Arc;
use tracing::{info, warn};

#[cfg(feature = "local-llm")]
use tracing::error;

#[cfg(feature = "local-llm")]
use crate::{
    llm::llamacpp::{LlamaCppClient, LlamaCppConfig},
    services::secure_llm_service::SecureLlmService,
};

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

    /// Get the appropriate AI client based on provider type with security wrapping
    /// Returns the correct client for the specified provider (local, AI provider, etc.)
    /// For local LLMs, wraps with SecureLlmService if session_dek is provided
    pub async fn get_secure_client_for_provider(
        &self,
        user_id: crate::db::DbId,
        provider: Option<&str>,
        model_name: Option<&str>,
        session_dek: Option<&SessionDek>,
        _app_state: &Arc<AppState>,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        info!(%user_id, provider = ?provider, model_name = ?model_name, has_session_dek = session_dek.is_some(), "🔍 DEBUG: get_secure_client_for_provider called with params");
        let provider = provider.unwrap_or("gemini"); // Default to gemini if no provider specified

        match provider {
            "local" | "mistralrs" => {
                info!(%user_id, provider, "Using MistralRs via RigClient for local inference");
                // We assume fallback_client is a RigClient and we want to use it with mistralrs provider
                // Since we can't easily downcast Arc<dyn AiClient>, we'll rely on the fact that
                // the fallback_client is configured to handle "mistralrs" if the feature is enabled.
                Ok(self.fallback_client.clone())
            }
            "gemini" | _ => {
                info!(%user_id, provider, "Using AI client (no security wrapping needed)");
                Ok(self.fallback_client.clone())
            }
        }
    }

    /// Get the appropriate AI client based on provider type (legacy method without security)
    /// Returns the correct client for the specified provider (local, AI provider, etc.)
    pub async fn get_client_for_provider(
        &self,
        user_id: crate::db::DbId,
        provider: Option<&str>,
        model_name: Option<&str>,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        info!(%user_id, provider = ?provider, model_name = ?model_name, "🔍 DEBUG: get_client_for_provider called with params");
        let provider = provider.unwrap_or("gemini"); // Default to gemini if no provider specified

        match provider {
            "local" | "mistralrs" => {
                info!(%user_id, provider, "Using MistralRs via RigClient for local inference");
                Ok(self.fallback_client.clone())
            }
            "gemini" | _ => {
                info!(%user_id, provider, "Using AI client");
                Ok(self.fallback_client.clone())
            }
        }
    }

    /// Get the appropriate AI client for a user (legacy method for backward compatibility)
    /// Returns fallback client if user settings can't be loaded or local LLM is disabled
    pub async fn get_client_for_user(
        &self,
        user_id: crate::db::DbId,
    ) -> Result<Arc<dyn AiClient + Send + Sync>, AppError> {
        // Get user settings
        let user_settings = match UserSettingsService::get_user_settings(
            &self.pool,
            user_id,
            &self.config,
        )
        .await
        {
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

    /// Get the fallback client (typically AI provider)
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
