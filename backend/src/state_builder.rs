use crate::{
    auth::user_store::Backend as AuthBackend,
    config::Config,
    llm::{AiClient, EmbeddingClient},
    services::{
        chat_override_service::ChatOverrideService,
        chronicle_service::ChronicleService,
        email_service::{EmailService, create_email_service},
        embeddings::{EmbeddingPipelineService, EmbeddingPipelineServiceTrait},
        encryption_service::EncryptionService,
        file_storage_service::FileStorageService,
        gemini_token_client::GeminiTokenClient,
        hybrid_token_counter::HybridTokenCounter,
        lorebook::LorebookService,
        narrative_intelligence_service::NarrativeIntelligenceService,
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

    pub fn with_qdrant_service(
        mut self,
        service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    ) -> Self {
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
    pub async fn build(self) -> Result<AppStateServices, Box<dyn std::error::Error + Send + Sync>> {
        // Get or create encryption service first as many services depend on it
        let encryption_service = self
            .encryption_service
            .unwrap_or_else(|| Arc::new(EncryptionService::new()));

        // Get or create auth backend
        let auth_backend = self
            .auth_backend
            .unwrap_or_else(|| Arc::new(AuthBackend::new(self.db_pool.clone())));

        // Get or create file storage service
        let file_storage_service = self.file_storage_service.unwrap_or_else(|| {
            Arc::new(
                FileStorageService::new(&self.config.upload_storage_path)
                    .expect("Failed to create file storage service"),
            )
        });

        // Get or create email service
        let email_service = match self.email_service {
            Some(service) => service,
            None => {
                create_email_service(
                    &self.config.app_env,
                    self.config.frontend_base_url.clone(),
                    self.config.from_email.clone(),
                )
                .await?
            }
        };

        // Get or create token counter
        let token_counter = self.token_counter.unwrap_or_else(|| {
            let tokenizer_service = TokenizerService::new(&self.config.tokenizer_model_path)
                .expect("Failed to create tokenizer service");

            let gemini_token_client = self
                .config
                .gemini_api_key
                .as_ref()
                .map(|api_key| GeminiTokenClient::new(api_key.clone()));

            Arc::new(HybridTokenCounter::new(
                tokenizer_service,
                gemini_token_client,
                self.config.token_counter_default_model.clone(),
            ))
        });

        // Get or create embedding pipeline service
        let embedding_pipeline_service = self.embedding_pipeline_service.unwrap_or_else(|| {
            let chunk_config = ChunkConfig::from(self.config.as_ref());
            Arc::new(EmbeddingPipelineService::new(chunk_config))
        });

        // Get or create chat override service
        let chat_override_service = self.chat_override_service.unwrap_or_else(|| {
            Arc::new(ChatOverrideService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ))
        });

        // Get or create user persona service
        let user_persona_service = self.user_persona_service.unwrap_or_else(|| {
            Arc::new(UserPersonaService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ))
        });

        // For required external services, we need them to be provided
        let ai_client = self.ai_client.expect("AI client must be provided");

        let embedding_client = self
            .embedding_client
            .expect("Embedding client must be provided");

        let qdrant_service = self
            .qdrant_service
            .expect("Qdrant service must be provided");

        // Get or create lorebook service (depends on qdrant)
        let lorebook_service = self.lorebook_service.unwrap_or_else(|| {
            Arc::new(LorebookService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
                qdrant_service.clone(),
            ))
        });

        // Create chronicle service for narrative intelligence
        let _chronicle_service = Arc::new(ChronicleService::new(
            self.db_pool.clone(),
        ));

        // NOTE: NarrativeIntelligenceService creation is deferred until after AppState is built
        // due to circular dependency (service needs AppState, but AppState is built from services)
        // We'll create a placeholder for now and set it properly after AppState construction

        // TODO: Initialize proper ECS services - temporarily using placeholders to fix compilation
        let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap_or_else(|_| {
            // Fallback for environments without Redis
            redis::Client::open("redis://127.0.0.1:6379/").unwrap()
        }));
        let feature_flags = Arc::new(crate::config::NarrativeFeatureFlags::default());
        
        // Create minimal ECS services to satisfy type requirements
        let ecs_entity_manager = Arc::new(crate::services::EcsEntityManager::new(
            Arc::new(self.db_pool.clone()),
            redis_client.clone(),
            None,
        ));
        let ecs_graceful_degradation = Arc::new(crate::services::EcsGracefulDegradation::new(
            Default::default(),
            feature_flags.clone(),
            Some(ecs_entity_manager.clone()),
            None,
        ));
        
        // Create concrete embedding service for ECS (avoiding trait object issues)
        let ecs_embedding_service = Arc::new(crate::services::embeddings::EmbeddingPipelineService::new(
            crate::text_processing::chunking::ChunkConfig {
                metric: crate::text_processing::chunking::ChunkingMetric::Word,
                max_size: 500,
                overlap: 50,
            }
        ));
        
        let ecs_enhanced_rag_service = Arc::new(crate::services::EcsEnhancedRagService::new(
            Arc::new(self.db_pool.clone()),
            Default::default(),
            feature_flags.clone(),
            ecs_entity_manager.clone(),
            ecs_graceful_degradation.clone(),
            ecs_embedding_service,
        ));
        let hybrid_query_service = Arc::new(crate::services::HybridQueryService::new(
            Arc::new(self.db_pool.clone()),
            Default::default(),
            feature_flags.clone(),
            ecs_entity_manager.clone(),
            ecs_enhanced_rag_service.clone(),
            ecs_graceful_degradation.clone(),
        ));

        // Create chronicle-related services for ECS integration
        let chronicle_service = Arc::new(crate::services::ChronicleService::new(self.db_pool.clone()));
        let chronicle_ecs_translator = Arc::new(crate::services::ChronicleEcsTranslator::new(
            Arc::new(self.db_pool.clone())
        ));
        let chronicle_event_listener = Arc::new(crate::services::ChronicleEventListener::new(
            Default::default(), // Use default config
            feature_flags.clone(),
            chronicle_ecs_translator.clone(),
            ecs_entity_manager.clone(),
            chronicle_service.clone(),
        ));

        // Create WorldModelService for ECS world state snapshots
        let world_model_service = Arc::new(crate::services::WorldModelService::new(
            Arc::new(self.db_pool.clone()),
            ecs_entity_manager.clone(),
            hybrid_query_service.clone(),
            chronicle_service.clone(),
        ));

        // Create agentic state update service first
        let agentic_state_update_service = Arc::new(crate::services::AgenticStateUpdateService::new(
            ai_client.clone(),
            ecs_entity_manager.clone(),
        ));

        // Create agentic orchestrator with all required services
        let agentic_orchestrator = Arc::new(crate::services::AgenticOrchestrator::new(
            ai_client.clone(),
            hybrid_query_service.clone(),
            Arc::new(self.db_pool.clone()),
            agentic_state_update_service.clone(),
        ));

        Ok(AppStateServices {
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
            // ECS Services
            redis_client,
            feature_flags,
            ecs_entity_manager,
            ecs_graceful_degradation,
            ecs_enhanced_rag_service,
            hybrid_query_service,
            chronicle_event_listener,
            chronicle_ecs_translator,
            chronicle_service,
            world_model_service,
            agentic_orchestrator,
            agentic_state_update_service,
            // narrative_intelligence_service will be added after AppState is built
        })
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

    pub fn with_qdrant_service(
        mut self,
        service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    ) -> Self {
        self.services_builder = self.services_builder.with_qdrant_service(service);
        self
    }

    pub fn with_embedding_pipeline_service(
        self,
        service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
    ) -> Self {
        Self {
            services_builder: self
                .services_builder
                .with_embedding_pipeline_service(service),
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
    pub async fn build(self) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
        let services = self.services_builder.build().await?;
        let mut app_state = AppState::new(self.pool, self.config, services);
        
        // Now create the narrative intelligence service with the fully constructed AppState
        let narrative_intelligence_service = Arc::new(
            NarrativeIntelligenceService::for_development_with_deps(
                app_state.ai_client.clone(),
                Arc::new(ChronicleService::new(app_state.pool.clone())),
                app_state.lorebook_service.clone(),
                app_state.qdrant_service.clone(),
                app_state.embedding_client.clone(),
                Arc::new(app_state.clone()),
            )
        );
        
        // Set the narrative intelligence service
        app_state.set_narrative_intelligence_service(narrative_intelligence_service);
        
        Ok(app_state)
    }
}
