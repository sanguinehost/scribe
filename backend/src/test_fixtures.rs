use crate::{
    auth::user_store::Backend as AuthBackend,
    config::Config,
    llm::{AiClient, EmbeddingClient},
    services::{
        email_service::{EmailService, create_email_service},
        file_storage_service::FileStorageService,
    },
    state::{AppState, DbPool},
    state_builder::AppStateServicesBuilder,
    test_helpers::{MockAiClient, MockEmbeddingClient, MockQdrantClientService},
    vector_db::qdrant_client::QdrantClientServiceTrait,
};
use std::sync::Arc;

/// Factory for creating test fixtures with sensible defaults
pub struct TestFixtures;

impl TestFixtures {
    /// Create a minimal test AppState with mock services
    /// Only requires database pool and config - all other services are mocked
    pub async fn minimal_app_state(
        pool: DbPool,
        config: Arc<Config>,
    ) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
        let mock_ai_client: Arc<dyn AiClient + Send + Sync> = Arc::new(MockAiClient::new());
        let mock_embedding_client: Arc<dyn EmbeddingClient + Send + Sync> =
            Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync> =
            Arc::new(MockQdrantClientService::new());

        let services = AppStateServicesBuilder::new(pool.clone(), config.clone())
            .with_ai_client(mock_ai_client)
            .with_embedding_client(mock_embedding_client)
            .with_qdrant_service(mock_qdrant_service)
            .build()
            .await?;

        Ok(AppState::new(pool, config, services))
    }

    /// Create a test AppState with real services where possible, mocked externals
    /// Use this when you need to test actual service logic but don't want external dependencies
    pub async fn real_services_app_state(
        pool: DbPool,
        config: Arc<Config>,
    ) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
        let mock_ai_client: Arc<dyn AiClient + Send + Sync> = Arc::new(MockAiClient::new());
        let mock_embedding_client: Arc<dyn EmbeddingClient + Send + Sync> =
            Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync> =
            Arc::new(MockQdrantClientService::new());

        // All other services will be created with defaults by the builder
        let services = AppStateServicesBuilder::new(pool.clone(), config.clone())
            .with_ai_client(mock_ai_client)
            .with_embedding_client(mock_embedding_client)
            .with_qdrant_service(mock_qdrant_service)
            .build()
            .await?;

        Ok(AppState::new(pool, config, services))
    }

    /// Create a test AppState with custom overrides
    /// Start with defaults and override only what you need for your specific test
    pub fn custom_app_state(pool: DbPool, config: Arc<Config>) -> AppStateServicesBuilder {
        let mock_ai_client: Arc<dyn AiClient + Send + Sync> = Arc::new(MockAiClient::new());
        let mock_embedding_client: Arc<dyn EmbeddingClient + Send + Sync> =
            Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync> =
            Arc::new(MockQdrantClientService::new());

        AppStateServicesBuilder::new(pool, config)
            .with_ai_client(mock_ai_client)
            .with_embedding_client(mock_embedding_client)
            .with_qdrant_service(mock_qdrant_service)
    }

    /// Create a logging email service for tests
    pub async fn test_email_service()
    -> Result<Arc<dyn EmailService + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
        create_email_service("development", "http://localhost:3000".to_string(), None)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Create a test file storage service
    pub fn test_file_storage_service() -> Arc<FileStorageService> {
        Arc::new(
            FileStorageService::new("./test_uploads")
                .expect("Failed to create test file storage service"),
        )
    }

    /// Create a test auth backend
    pub fn test_auth_backend(pool: DbPool) -> Arc<AuthBackend> {
        Arc::new(AuthBackend::new(pool))
    }
}

/// Macro to simplify test AppState creation with specific service overrides
#[macro_export]
macro_rules! test_app_state {
    ($pool:expr, $config:expr $(, $service:ident = $value:expr)*) => {
        {
            let mut builder = $crate::test_fixtures::TestFixtures::custom_app_state($pool, $config);
            $(
                builder = builder.$service($value);
            )*
            $crate::state::AppState::new($pool.clone(), $config.clone(), builder.build().await.expect("Failed to build app state in test macro"))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;

    #[tokio::test]
    async fn test_minimal_app_state_creation() {
        test_helpers::ensure_tracing_initialized();

        // This test just verifies the fixture compiles and runs
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let _app_state =
            TestFixtures::minimal_app_state(test_app.db_pool.clone(), test_app.config.clone())
                .await
                .expect("Failed to create minimal app state");
        // If we get here without panicking, the fixture works
    }

    #[tokio::test]
    async fn test_custom_app_state_builder() {
        test_helpers::ensure_tracing_initialized();

        let test_app = test_helpers::spawn_app(false, false, false).await;
        let custom_email_service = TestFixtures::test_email_service()
            .await
            .expect("Failed to create email service");

        let services =
            TestFixtures::custom_app_state(test_app.db_pool.clone(), test_app.config.clone())
                .with_email_service(custom_email_service)
                .build()
                .await
                .expect("Failed to build services");

        let app_state = AppState::new(test_app.db_pool.clone(), test_app.config.clone(), services);

        // Verify the app state was created successfully
        assert!(app_state.config.database_url.is_some());
    }
}
