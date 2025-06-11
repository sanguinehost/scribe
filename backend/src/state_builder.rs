use crate::{
    auth::user_store::Backend as AuthBackend,
    config::Config,
    llm::{AiClient, EmbeddingClient},
    services::{
        chat_override_service::ChatOverrideService,
        email_service::{EmailService, LoggingEmailService},
        embeddings::{EmbeddingPipelineService, EmbeddingPipelineServiceTrait},
        encryption_service::EncryptionService,
        file_storage_service::FileStorageService,
        gemini_token_client::GeminiTokenClient,
        hybrid_token_counter::HybridTokenCounter,
        lorebook_service::LorebookService,
        tokenizer_service::TokenizerService,
        user_persona_service::UserPersonaService,
    },
    state::{AppState, AppStateServices, DbPool},
    text_processing::chunking::ChunkConfig,
    vector_db::qdrant_client::QdrantClientServiceTrait,
};
use std::sync::Arc;

/// Builder for creating AppStateServices with sensible defaults and optional overrides
pub struct AppStateServicesBuilder {
    // Required dependencies
    db_pool: DbPool,
    config: Arc<Config>,
    
    // Service overrides - all optional
    ai_client: Option<Arc<dyn AiClient + Send + Sync>>,
    embedding_client: Option<Arc<dyn EmbeddingClient + Send + Sync>>,
    qdrant_service: Option<Arc<dyn QdrantClientServiceTrait + Send + Sync>>,
    embedding_pipeline_service: Option<Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>>,
    chat_override_service: Option<Arc<ChatOverrideService>>,
    user_persona_service: Option<Arc<UserPersonaService>>,
    token_counter: Option<Arc<HybridTokenCounter>>,
    encryption_service: Option<Arc<EncryptionService>>,
    lorebook_service: Option<Arc<LorebookService>>,
    auth_backend: Option<Arc<AuthBackend>>,
    file_storage_service: Option<Arc<FileStorageService>>,
    email_service: Option<Arc<dyn EmailService + Send + Sync>>,
}

impl AppStateServicesBuilder {
    /// Create a new builder with required dependencies
    pub fn new(db_pool: DbPool, config: Arc<Config>) -> Self {
        Self {
            db_pool,
            config,
            ai_client: None,
            embedding_client: None,
            qdrant_service: None,
            embedding_pipeline_service: None,
            chat_override_service: None,
            user_persona_service: None,
            token_counter: None,
            encryption_service: None,
            lorebook_service: None,
            auth_backend: None,
            file_storage_service: None,
            email_service: None,
        }
    }

    pub fn with_ai_client(mut self, client: Arc<dyn AiClient + Send + Sync>) -> Self {
        self.ai_client = Some(client);
        self
    }

    pub fn with_embedding_client(mut self, client: Arc<dyn EmbeddingClient + Send + Sync>) -> Self {
        self.embedding_client = Some(client);
        self
    }

    pub fn with_qdrant_service(mut self, service: Arc<dyn QdrantClientServiceTrait + Send + Sync>) -> Self {
        self.qdrant_service = Some(service);
        self
    }

    pub fn with_embedding_pipeline_service(
        mut self,
        service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
    ) -> Self {
        self.embedding_pipeline_service = Some(service);
        self
    }

    pub fn with_chat_override_service(mut self, service: Arc<ChatOverrideService>) -> Self {
        self.chat_override_service = Some(service);
        self
    }

    pub fn with_user_persona_service(mut self, service: Arc<UserPersonaService>) -> Self {
        self.user_persona_service = Some(service);
        self
    }

    pub fn with_token_counter(mut self, counter: Arc<HybridTokenCounter>) -> Self {
        self.token_counter = Some(counter);
        self
    }

    pub fn with_encryption_service(mut self, service: Arc<EncryptionService>) -> Self {
        self.encryption_service = Some(service);
        self
    }

    pub fn with_lorebook_service(mut self, service: Arc<LorebookService>) -> Self {
        self.lorebook_service = Some(service);
        self
    }

    pub fn with_auth_backend(mut self, backend: Arc<AuthBackend>) -> Self {
        self.auth_backend = Some(backend);
        self
    }

    pub fn with_file_storage_service(mut self, service: Arc<FileStorageService>) -> Self {
        self.file_storage_service = Some(service);
        self
    }

    pub fn with_email_service(mut self, service: Arc<dyn EmailService + Send + Sync>) -> Self {
        self.email_service = Some(service);
        self
    }

    /// Build AppStateServices with defaults for any unspecified services
    /// 
    /// # Panics
    /// 
    /// Panics if required services (AI client, embedding client, Qdrant service) are not provided
    /// and cannot be created from configuration.
    pub fn build(self) -> AppStateServices {
        // Get or create encryption service first as many services depend on it
        let encryption_service = self.encryption_service
            .unwrap_or_else(|| Arc::new(EncryptionService::new()));

        // Get or create auth backend
        let auth_backend = self.auth_backend
            .unwrap_or_else(|| Arc::new(AuthBackend::new(self.db_pool.clone())));

        // Get or create file storage service
        let file_storage_service = self.file_storage_service
            .unwrap_or_else(|| {
                Arc::new(FileStorageService::new(&self.config.upload_storage_path)
                    .expect("Failed to create file storage service"))
            });

        // Get or create email service
        let email_service = self.email_service
            .unwrap_or_else(|| {
                Arc::new(LoggingEmailService::new(self.config.frontend_base_url.clone()))
            });

        // Get or create token counter
        let token_counter = self.token_counter
            .unwrap_or_else(|| {
                let tokenizer_service = TokenizerService::new(&self.config.tokenizer_model_path)
                    .expect("Failed to create tokenizer service");
                
                let gemini_token_client = self.config.gemini_api_key.as_ref()
                    .map(|api_key| GeminiTokenClient::new(api_key.clone()));
                
                Arc::new(HybridTokenCounter::new(
                    tokenizer_service,
                    gemini_token_client,
                    self.config.token_counter_default_model.clone(),
                ))
            });

        // Get or create embedding pipeline service
        let embedding_pipeline_service = self.embedding_pipeline_service
            .unwrap_or_else(|| {
                let chunk_config = ChunkConfig::from(self.config.as_ref());
                Arc::new(EmbeddingPipelineService::new(chunk_config))
            });

        // Get or create chat override service
        let chat_override_service = self.chat_override_service
            .unwrap_or_else(|| {
                Arc::new(ChatOverrideService::new(
                    self.db_pool.clone(),
                    encryption_service.clone(),
                ))
            });

        // Get or create user persona service
        let user_persona_service = self.user_persona_service
            .unwrap_or_else(|| {
                Arc::new(UserPersonaService::new(
                    self.db_pool.clone(),
                    encryption_service.clone(),
                ))
            });

        // For required external services, we need them to be provided
        let ai_client = self.ai_client
            .expect("AI client must be provided");
        
        let embedding_client = self.embedding_client
            .expect("Embedding client must be provided");
        
        let qdrant_service = self.qdrant_service
            .expect("Qdrant service must be provided");

        // Get or create lorebook service (depends on qdrant)
        let lorebook_service = self.lorebook_service
            .unwrap_or_else(|| {
                Arc::new(LorebookService::new(
                    self.db_pool.clone(),
                    encryption_service.clone(),
                    qdrant_service.clone(),
                ))
            });

        AppStateServices {
            ai_client,
            embedding_client,
            qdrant_service,
            embedding_pipeline_service,
            chat_override_service,
            user_persona_service,
            token_counter,
            encryption_service,
            lorebook_service,
            auth_backend,
            file_storage_service,
            email_service,
        }
    }
}

/// Extension trait for AppState to create it using the builder pattern
impl AppState {
    /// Create AppState using the builder pattern
    pub fn builder(pool: DbPool, config: Arc<Config>) -> AppStateBuilder {
        AppStateBuilder::new(pool, config)
    }
}

/// Builder for creating AppState with a fluent API
pub struct AppStateBuilder {
    pool: DbPool,
    config: Arc<Config>,
    services_builder: AppStateServicesBuilder,
}

impl AppStateBuilder {
    fn new(pool: DbPool, config: Arc<Config>) -> Self {
        let services_builder = AppStateServicesBuilder::new(pool.clone(), config.clone());
        Self {
            pool,
            config,
            services_builder,
        }
    }

    // Delegate all service methods to the services builder
    pub fn with_ai_client(mut self, client: Arc<dyn AiClient + Send + Sync>) -> Self {
        self.services_builder = self.services_builder.with_ai_client(client);
        self
    }

    pub fn with_embedding_client(mut self, client: Arc<dyn EmbeddingClient + Send + Sync>) -> Self {
        self.services_builder = self.services_builder.with_embedding_client(client);
        self
    }

    pub fn with_qdrant_service(mut self, service: Arc<dyn QdrantClientServiceTrait + Send + Sync>) -> Self {
        self.services_builder = self.services_builder.with_qdrant_service(service);
        self
    }

    pub fn with_embedding_pipeline_service(
        self,
        service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
    ) -> Self {
        Self {
            services_builder: self.services_builder.with_embedding_pipeline_service(service),
            ..self
        }
    }

    pub fn with_chat_override_service(self, service: Arc<ChatOverrideService>) -> Self {
        Self {
            services_builder: self.services_builder.with_chat_override_service(service),
            ..self
        }
    }

    pub fn with_user_persona_service(self, service: Arc<UserPersonaService>) -> Self {
        Self {
            services_builder: self.services_builder.with_user_persona_service(service),
            ..self
        }
    }

    pub fn with_token_counter(self, counter: Arc<HybridTokenCounter>) -> Self {
        Self {
            services_builder: self.services_builder.with_token_counter(counter),
            ..self
        }
    }

    pub fn with_encryption_service(self, service: Arc<EncryptionService>) -> Self {
        Self {
            services_builder: self.services_builder.with_encryption_service(service),
            ..self
        }
    }

    pub fn with_lorebook_service(self, service: Arc<LorebookService>) -> Self {
        Self {
            services_builder: self.services_builder.with_lorebook_service(service),
            ..self
        }
    }

    pub fn with_auth_backend(self, backend: Arc<AuthBackend>) -> Self {
        Self {
            services_builder: self.services_builder.with_auth_backend(backend),
            ..self
        }
    }

    pub fn with_file_storage_service(self, service: Arc<FileStorageService>) -> Self {
        Self {
            services_builder: self.services_builder.with_file_storage_service(service),
            ..self
        }
    }

    pub fn with_email_service(self, service: Arc<dyn EmailService + Send + Sync>) -> Self {
        Self {
            services_builder: self.services_builder.with_email_service(service),
            ..self
        }
    }

    /// Build the AppState
    pub fn build(self) -> AppState {
        let services = self.services_builder.build();
        AppState::new(self.pool, self.config, services)
    }
}