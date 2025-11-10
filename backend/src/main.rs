use axum::{extract::DefaultBodyLimit, routing::get, Router};
#[cfg(feature = "postgres-backend")]
use deadpool_diesel::postgres::{Manager as DeadpoolManager, Runtime as DeadpoolRuntime};
#[cfg(feature = "postgres-backend")]
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

// Use modules from the library crate
use anyhow::Context;
use anyhow::Result;
use scribe_backend::auth::session_store::DieselSessionStore;
use scribe_backend::auth::user_store::Backend as AuthBackend;
use scribe_backend::db::DbPool;
#[cfg(feature = "desktop")]
use scribe_backend::desktop; // Desktop mode initialization
use scribe_backend::errors::AppError;
use scribe_backend::logging::init_subscriber;
use scribe_backend::middleware::unified_login_required;
use scribe_backend::routes::admin::admin_routes;
use scribe_backend::routes::auth::auth_routes;
#[cfg(feature = "postgres-backend")]
use scribe_backend::routes::documents::document_routes;
use scribe_backend::routes::health::health_check;
#[cfg(feature = "payment")]
use scribe_backend::routes::payment::{payment_routes, payment_webhook_routes};
use scribe_backend::routes::{
    avatars::avatar_routes,        // Added for avatar routes
    characters::characters_router, // Use the router function import
    chat::chat_routes,
    chats,
    chronicles,
    generation_routes,                // Added for generation routes
    llm_routes::llm_router,           // Added for LLM management routes
    lorebook_routes::lorebook_routes, // Added for lorebook routes
    template_preferences_routes::template_preferences_routes, // Added for template preferences routes
    templates,                                                // Added for template routes
    user_persona_routes::user_personas_router,                // Added for user persona routes
    user_settings_routes::user_settings_routes,
};
use scribe_backend::state::{AppState, AppStateServices};
use std::env; // Added for current_dir

// Imports for axum-login and tower-sessions
use axum_login::AuthManagerLayerBuilder; // Modified
                                         // Import SessionManagerLayer directly from tower_sessions
use axum::extract::Request as AxumRequest;
use axum::middleware::{self as axum_middleware, Next};
use axum::response::Response as AxumResponse;
use axum_server::tls_rustls::RustlsConfig;
use hex::decode;
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring;
use scribe_backend::config::Config; // Import Config instead
use scribe_backend::llm::gemini_client::build_gemini_client; // Import the async builder
use scribe_backend::llm::gemini_embedding_client::build_gemini_embedding_client; // Add this
use scribe_backend::services::ai_client_factory::AiClientFactory;
use scribe_backend::services::chat_override_service::ChatOverrideService;
use scribe_backend::services::chronicle_service::ChronicleService;
use scribe_backend::services::embeddings::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait,
};
use scribe_backend::services::encryption_service::EncryptionService;
use scribe_backend::services::gemini_token_client::GeminiTokenClient; // Added
use scribe_backend::services::hybrid_token_counter::HybridTokenCounter; // Added
use scribe_backend::services::lorebook::LorebookService;
use scribe_backend::services::narrative_intelligence_service::NarrativeIntelligenceService;
use scribe_backend::services::tokenizer_service::TokenizerService; // Added
use scribe_backend::services::user_persona_service::UserPersonaService;
use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import chunking config structs

#[cfg(any(
    feature = "embedded-vector",
    not(any(feature = "remote-vector", feature = "embedded-vector"))
))]
use scribe_backend::vector_db::NoOpQdrantService;
#[cfg(feature = "remote-vector")]
use scribe_backend::vector_db::QdrantClientService;
use std::path::PathBuf;
use std::sync::Arc;
use time::Duration;
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_sessions::cookie::Key; // Use Key from tower_sessions::cookie for with_signed
use tower_sessions::{cookie::SameSite, Expiry, SessionManagerLayer}; // Add Arc for config // Add Qdrant service import // Add embedding pipeline service import
use tracing::{info, warn};

// Define the embedded migrations macro - use different directories based on backend
#[cfg(feature = "postgres-backend")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[cfg(feature = "sqlite-backend")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations_sqlite");

// Generate or load certificate for cloud environments
async fn load_cloud_certificate() -> Result<RustlsConfig> {
    // Try to load certificate from environment variables first (for proper certificates)
    if let (Ok(cert_pem), Ok(key_pem)) = (env::var("TLS_CERT_PEM"), env::var("TLS_KEY_PEM")) {
        tracing::info!(
            "Loading TLS certificate from environment variables for end-to-end encryption"
        );

        let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
            .await
            .context("Failed to create RustlsConfig from environment certificate")?;

        tracing::info!("TLS certificate loaded successfully from environment");
        return Ok(config);
    }

    // Fallback to self-signed certificate if no proper certificate is provided
    tracing::info!(
        "No certificate provided in environment, generating self-signed certificate for end-to-end encryption"
    );

    // Generate a simple self-signed certificate for internal communication
    let subject_alt_names = vec![
        "localhost".to_string(),
        "backend.staging.local".to_string(),
        "staging-scribe-backend".to_string(),
    ];
    let cert_key = generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    // Get PEM-encoded certificate and private key
    let cert_pem = cert_key.cert.pem();
    let key_pem = cert_key.key_pair.serialize_pem();

    tracing::info!("Self-signed certificate generated successfully");

    // Create RustlsConfig from the generated certificate and key
    let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
        .await
        .context("Failed to create RustlsConfig from generated certificate")?;

    Ok(config)
}

async fn main_request_logging_middleware(req: AxumRequest, next: Next) -> AxumResponse {
    tracing::info!(target: "main_router_debug", "MAIN ROUTER: Method={}, URI={}", req.method(), req.uri());
    next.run(req).await
}

// Removed custom rejection handler functions (handle_auth_rejection, handle_unauthorized_rejection)
// Relying on default axum_login::Error -> AppError conversion via From trait

#[tokio::main]
async fn main() -> Result<()> {
    initialize_runtime();
    let config = Arc::new(Config::load().context("Failed to load configuration")?);

    // Validate configuration on startup
    #[cfg(feature = "payment")]
    {
        tracing::info!("Validating payment system configuration...");
        config
            .validate()
            .context("Configuration validation failed")?;
        tracing::info!("Payment system configuration validation passed");
    }

    let pool = setup_database_pool(&config);
    run_migrations(&pool).await?;

    // Initialize desktop mode if enabled (create default user for Quick Start)
    #[cfg(feature = "desktop")]
    initialize_desktop_mode(&pool).await?;

    let services = initialize_services(&config, &pool).await?;

    let (app_state, auth_layer) = setup_app_state_and_auth(&config, &pool, services)?;

    // Start payment scheduler if payment feature is enabled
    #[cfg(feature = "payment")]
    {
        if config.payment.credits_enabled || config.payment.soft_limits_enabled {
            tracing::info!("Starting payment scheduler for periodic tasks...");
            let scheduler = Arc::new(scribe_backend::services::payment::PaymentScheduler::new(
                config.clone(),
                pool.clone(),
            ));
            scheduler.start().await;
            tracing::info!("Payment scheduler started successfully");
        } else {
            tracing::info!("Payment scheduler disabled (credits and soft limits are disabled)");
        }
    }

    let app = build_router(app_state, auth_layer);

    start_server(&config, app).await
}

// Initialize runtime and basic setup
fn initialize_runtime() {
    // Install the default crypto provider (ring) for rustls FIRST.
    let _ = ring::default_provider().install_default();
    dotenvy::dotenv().ok();
    init_subscriber();
    tracing::info!("Starting Scribe backend server...");
    tracing::info!(
        "Build configuration: {}",
        scribe_backend::features::feature_summary()
    );
}

// Setup database pool
#[cfg(feature = "postgres-backend")]
fn setup_database_pool(config: &Config) -> DbPool {
    let db_url = config
        .database_url
        .as_ref()
        .expect("DATABASE_URL not set in config");
    tracing::info!("Connecting to database...");
    let manager = DeadpoolManager::new(db_url, DeadpoolRuntime::Tokio1);

    // Configure pool size based on environment
    let mut pool_config = deadpool_diesel::postgres::PoolConfig::default();
    let max_size = match config.environment.as_deref() {
        Some("development") => 50, // Local docker has max_connections = 200
        Some("staging") | Some("production") => 20, // Cloud RDS has ~90 total connections
        _ => 20,                   // Default to conservative for unknown environments
    };
    pool_config.max_size = max_size;
    pool_config.timeouts.wait = Some(std::time::Duration::from_secs(30)); // 30 second timeout

    let pool: DbPool = DeadpoolPool::builder(manager)
        .config(pool_config)
        .runtime(DeadpoolRuntime::Tokio1)
        .build()
        .expect("Failed to create DB pool.");
    tracing::info!(
        "Database connection pool established with max_size: {}",
        max_size
    );
    pool
}

#[cfg(feature = "sqlite-backend")]
fn setup_database_pool(config: &Config) -> DbPool {
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::SqliteConnection;

    let db_url = config
        .database_url
        .as_ref()
        .expect("DATABASE_URL not set in config");

    tracing::info!("🗄️  DATABASE_URL: {}", db_url);
    tracing::info!("Connecting to SQLite database...");

    // Verify database file exists
    if let Some(db_path) = db_url.strip_prefix("sqlite://") {
        let path = std::path::Path::new(db_path);
        if path.exists() {
            tracing::info!("✓ Database file exists at: {}", db_path);
        } else {
            tracing::warn!("⚠️  Database file does NOT exist yet at: {}", db_path);
        }
    }

    let manager = ConnectionManager::<SqliteConnection>::new(db_url);

    // Configure pool size based on environment
    let max_size = match config.environment.as_deref() {
        Some("development") => 50,
        Some("staging") | Some("production") => 20,
        _ => 20,
    };

    let pool = Pool::builder()
        .max_size(max_size)
        .connection_timeout(std::time::Duration::from_secs(30))
        .build(manager)
        .expect("Failed to create DB pool.");

    tracing::info!(
        "Database connection pool established with max_size: {}",
        max_size
    );
    pool
}

// Initialize all services
async fn initialize_services(config: &Arc<Config>, pool: &DbPool) -> Result<AppStateServices> {
    #[cfg(feature = "local-llm")]
    let mut llamacpp_server_manager: Option<
        Arc<scribe_backend::llm::llamacpp::LlamaCppServerManager>,
    > = None;
    // --- Initialize GenAI Client Asynchronously ---
    let api_key = config
        .gemini_api_key
        .as_ref()
        .ok_or_else(|| AppError::ConfigError("GEMINI_API_KEY is required".to_string()))?;
    let ai_client = build_gemini_client(api_key, &config.gemini_api_base_url)?;
    let ai_client_arc = Arc::new(ai_client);

    // --- Initialize Embedding Client ---
    let embedding_client = build_gemini_embedding_client(config.clone())?;
    let embedding_client_arc = Arc::new(embedding_client);

    // --- Initialize Tokenizer Service ---
    let tokenizer_service = setup_tokenizer_service(config)?;

    // --- Initialize Gemini Token Client (Optional) ---
    let gemini_token_client = setup_gemini_token_client(config);

    // --- Initialize Hybrid Token Counter ---
    let hybrid_token_counter =
        setup_hybrid_token_counter(config, tokenizer_service, gemini_token_client);

    // --- Initialize Services ---
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        pool.clone(),
        encryption_service.clone(),
    ));
    let user_persona_service = Arc::new(UserPersonaService::new(
        pool.clone(),
        encryption_service.clone(),
    ));

    // --- Create Chunking Config and Embedding Pipeline ---
    let chunk_config = create_chunk_config(config);
    let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(chunk_config))
        as Arc<dyn EmbeddingPipelineServiceTrait>;

    // --- Initialize Vector DB Service (Qdrant or No-Op) ---
    #[cfg(feature = "remote-vector")]
    let qdrant_service = {
        tracing::info!("Initializing Qdrant client service (remote-vector mode)...");
        let service = Arc::new(QdrantClientService::new(config.clone()).await?);
        tracing::info!("Qdrant client service initialized.");
        service
            as Arc<
                dyn scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait
                    + Send
                    + Sync,
            >
    };

    #[cfg(feature = "embedded-vector")]
    let qdrant_service = {
        tracing::info!("Initializing no-op vector service (embedded-vector mode)...");
        let service = Arc::new(NoOpQdrantService::new(config.clone()).await?);
        tracing::info!("No-op vector service initialized.");
        service
            as Arc<
                dyn scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait
                    + Send
                    + Sync,
            >
    };

    // Fallback when neither remote-vector nor embedded-vector is enabled
    #[cfg(not(any(feature = "remote-vector", feature = "embedded-vector")))]
    let qdrant_service = {
        tracing::info!("Initializing no-op vector service (no vector features enabled)...");
        let service = Arc::new(NoOpQdrantService::new(config.clone()).await?);
        tracing::info!("No-op vector service initialized.");
        service
            as Arc<
                dyn scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait
                    + Send
                    + Sync,
            >
    };

    // --- Initialize Lorebook Service (needs qdrant_service) ---
    let lorebook_service = Arc::new(LorebookService::new(
        pool.clone(),
        encryption_service.clone(),
        qdrant_service.clone(),
    ));

    // --- Initialize Chronicle Service ---
    let _chronicle_service = Arc::new(ChronicleService::new(pool.clone()));

    let auth_backend = Arc::new(AuthBackend::new(pool.clone()));

    // --- Initialize Token Service ---
    let token_service = if let Some(cookie_key) = config.cookie_signing_key.as_ref() {
        // Use the cookie key directly as a string for JWT signing
        info!("Initializing token service for JWT authentication");
        Some(Arc::new(scribe_backend::auth::TokenService::new(
            cookie_key,
        )))
    } else {
        warn!("No cookie signing key available, token authentication will be disabled");
        None
    };

    // --- Initialize AI Client Factory ---
    let ai_client_factory = Arc::new(AiClientFactory::new(
        pool.clone(),
        config.clone(),
        ai_client_arc.clone(), // Use Gemini as fallback client
    ));

    // --- Initialize Local LLM Server (if feature enabled) ---
    #[cfg(feature = "local-llm")]
    {
        use scribe_backend::llm::llamacpp::{LlamaCppConfig, LlamaCppServerManager, ModelManager};
        use tracing::{info, warn};

        info!("Initializing local LLM server...");
        let llm_config = LlamaCppConfig::from_env();

        if llm_config.enabled {
            match ModelManager::new(llm_config.clone()).await {
                Ok(model_manager) => {
                    let model_manager_arc = Arc::new(model_manager);

                    // Check if there are any downloaded models
                    let downloaded_models =
                        model_manager_arc.list_models().await.unwrap_or_default();

                    if downloaded_models.is_empty() {
                        info!(
                            "No models downloaded yet. Local LLM UI will be available for model downloads."
                        );
                    } else {
                        info!(
                            "Found {} downloaded models. Server will start on-demand when a model is activated.",
                            downloaded_models.len()
                        );
                    }

                    // Create server manager but don't start it - it will start on-demand
                    match LlamaCppServerManager::new(llm_config, model_manager_arc).await {
                        Ok(server_manager) => {
                            let server_manager_arc: Arc<LlamaCppServerManager> =
                                Arc::new(server_manager);
                            info!(
                                "Local LLM server manager initialized. Server will start when a model is activated."
                            );
                            // Store the server manager for UI management
                            llamacpp_server_manager = Some(server_manager_arc);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to initialize local LLM server manager: {}. Local LLM features will be unavailable.",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize model manager: {}. Local LLM features will be unavailable.",
                        e
                    );
                }
            }
        } else {
            info!("Local LLM disabled in configuration");
        }
    }

    // --- Initialize Narrative Intelligence Service ---
    // Note: Will be initialized after AppState is created due to circular dependency

    let services = AppStateServices {
        ai_client: ai_client_arc,
        embedding_client: embedding_client_arc,
        qdrant_service,
        embedding_pipeline_service,
        chat_override_service,
        user_persona_service,
        token_counter: hybrid_token_counter,
        encryption_service,
        lorebook_service,
        auth_backend,
        token_service,
        email_service: {
            // Create email service based on environment
            let app_env = config.environment.as_deref().unwrap_or("development");
            let base_url = config.frontend_base_url.clone();
            let from_email = config.from_email.clone();
            scribe_backend::services::email_service::create_email_service(
                app_env, base_url, from_email,
            )
            .await?
        },
        ai_client_factory,
        rate_limiter: Arc::new(
            scribe_backend::middleware::llm_security::LlmRateLimiter::new(
                config.security.max_requests_per_minute,
                config.security.max_requests_per_hour,
            ),
        ),
        #[cfg(feature = "local-llm")]
        llamacpp_server_manager: llamacpp_server_manager,
        #[cfg(feature = "local-llm")]
        security_audit_logger: None, // Will be set by the builder if needed
        #[cfg(feature = "local-llm")]
        model_integrity_verifier: None, // Will be set by the builder if needed
    };

    Ok(services)
}

// Setup tokenizer service
fn setup_tokenizer_service(config: &Config) -> Result<TokenizerService> {
    tracing::info!("Initializing TokenizerService...");
    let final_tokenizer_model_path = resolve_tokenizer_model_path(config);

    let tokenizer_service = TokenizerService::new(&final_tokenizer_model_path).context(format!(
        "Failed to load tokenizer model from {}",
        final_tokenizer_model_path.display()
    ))?;

    tracing::info!(
        "TokenizerService initialized with model: {}",
        tokenizer_service.model_name()
    );
    Ok(tokenizer_service)
}

// Helper function to resolve the tokenizer model path and log relevant information
#[allow(clippy::cognitive_complexity)]
fn resolve_tokenizer_model_path(config: &Config) -> PathBuf {
    let tokenizer_model_relative_path_str = config.tokenizer_model_path.clone();
    let backend_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let final_tokenizer_model_path = backend_crate_dir.join(&tokenizer_model_relative_path_str);

    if let Ok(cwd) = env::current_dir() {
        tracing::info!("Current working directory: {}", cwd.display());
    } else {
        tracing::warn!("Failed to get current working directory.");
    }

    tracing::info!(
        "Tokenizer model relative path from config: {}",
        tokenizer_model_relative_path_str
    );
    tracing::info!(
        "Backend crate directory (CARGO_MANIFEST_DIR): {}",
        backend_crate_dir.display()
    );
    tracing::info!(
        "Resolved absolute tokenizer model path to be used: {}",
        final_tokenizer_model_path.display()
    );

    final_tokenizer_model_path
}

// Setup Gemini token client
fn setup_gemini_token_client(config: &Config) -> Option<GeminiTokenClient> {
    config.gemini_api_key.as_ref().map_or_else(|| {
        tracing::warn!("GEMINI_API_KEY not set, GeminiTokenClient for token counting will not be available.");
        None
    }, |api_key| {
        tracing::info!("Initializing GeminiTokenClient for token counting...");
        Some(GeminiTokenClient::new(api_key.clone()))
    })
}

// Setup hybrid token counter
fn setup_hybrid_token_counter(
    config: &Config,
    tokenizer_service: TokenizerService,
    gemini_token_client: Option<GeminiTokenClient>,
) -> Arc<HybridTokenCounter> {
    tracing::info!("Initializing HybridTokenCounter...");
    let token_counter_default_model = config.token_counter_default_model.clone();
    let hybrid_token_counter = HybridTokenCounter::new(
        tokenizer_service,
        gemini_token_client,
        token_counter_default_model.clone(),
    );
    tracing::info!(
        "HybridTokenCounter initialized with default model: {}",
        token_counter_default_model
    );
    Arc::new(hybrid_token_counter)
}

// Create chunking configuration
fn create_chunk_config(config: &Config) -> ChunkConfig {
    let chunk_metric = match config.chunking_metric.to_lowercase().as_str() {
        "word" => ChunkingMetric::Word,
        _ => ChunkingMetric::Char,
    };
    let chunk_config = ChunkConfig {
        metric: chunk_metric,
        max_size: config.chunking_max_size,
        overlap: config.chunking_overlap,
    };
    tracing::info!(?chunk_config, "Using chunking configuration");
    chunk_config
}

// Setup app state and authentication
fn setup_app_state_and_auth(
    config: &Arc<Config>,
    pool: &DbPool,
    services: AppStateServices,
) -> Result<(
    AppState,
    axum_login::AuthManagerLayer<AuthBackend, DieselSessionStore>,
)> {
    // --- Session Store Setup ---
    let session_store = DieselSessionStore::new(pool.clone());

    let secret_key = config
        .cookie_signing_key
        .as_ref()
        .context("COOKIE_SIGNING_KEY must be set in config")?;
    let key_bytes =
        decode(secret_key).context("Invalid COOKIE_SIGNING_KEY format in config (must be hex)")?;
    let _signing_key = Key::from(&key_bytes);

    let mut session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(config.session_cookie_secure)
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_path("/".to_string())
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    // Set cookie domain if specified in config (for production/staging)
    if let Some(ref domain) = config.cookie_domain {
        tracing::info!("Setting session cookie domain to: {}", domain);
        session_manager_layer = session_manager_layer.with_domain(domain.clone());
    } else {
        tracing::info!("No cookie domain specified, using default (localhost-compatible)");
    }

    let auth_backend = services.auth_backend.clone();
    let auth_layer =
        AuthManagerLayerBuilder::new((*auth_backend).clone(), session_manager_layer).build();

    let mut app_state = AppState::new(pool.clone(), config.clone(), services);

    // Initialize narrative intelligence service after AppState creation to avoid circular dependency
    let chronicle_service = Arc::new(ChronicleService::new(pool.clone()));
    let narrative_intelligence_service =
        Arc::new(NarrativeIntelligenceService::for_production_with_deps(
            app_state.ai_client.clone(),
            chronicle_service,
            app_state.lorebook_service.clone(),
            app_state.qdrant_service.clone(),
            app_state.embedding_client.clone(),
            Arc::new(app_state.clone()),
        ));
    app_state.set_narrative_intelligence_service(narrative_intelligence_service);

    Ok((app_state, auth_layer))
}

// Build the router with all routes and middleware
fn build_router(
    app_state: AppState,
    auth_layer: axum_login::AuthManagerLayer<AuthBackend, DieselSessionStore>,
) -> Router {
    let protected_api_routes = Router::new()
        .nest(
            "/characters",
            characters_router(app_state.clone()).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        ) // 10MB limit for character uploads
        .nest("/chat", {
            #[cfg(feature = "payment")]
            let routes = {
                let routes =
                    chat_routes(app_state.clone()).layer(DefaultBodyLimit::max(50 * 1024 * 1024)); // 50MB limit for chat history

                // Add soft limit enforcement before LLM security
                routes.layer(axum::middleware::from_fn(
                    scribe_backend::middleware::soft_limit_enforcement_middleware,
                ))
            };

            #[cfg(not(feature = "payment"))]
            let routes =
                chat_routes(app_state.clone()).layer(DefaultBodyLimit::max(50 * 1024 * 1024)); // 50MB limit for chat history

            routes.layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                scribe_backend::middleware::llm_security::llm_security_middleware,
            ))
        })
        .nest("/chats", chats::chat_routes())
        .nest(
            "/chronicles",
            chronicles::create_chronicles_router(app_state.clone()),
        );

    #[cfg(feature = "postgres-backend")]
    let protected_api_routes = protected_api_routes.nest("/documents", document_routes());

    let protected_api_routes = protected_api_routes
        .nest("/generation", generation_routes::router()) // AI generation routes
        .nest("/llm", llm_router()); // LLM management routes

    #[cfg(feature = "payment")]
    let protected_api_routes = protected_api_routes.nest("/payment", payment_routes()); // Payment routes

    let protected_api_routes = protected_api_routes
        .nest("/personas", user_personas_router(app_state.clone()))
        .nest("/user-settings", user_settings_routes(app_state.clone()))
        .nest(
            "/template-preferences",
            template_preferences_routes(app_state.clone()),
        )
        .nest("/", lorebook_routes())
        .nest("/templates", templates::create_router())
        .nest("/admin", admin_routes())
        .merge(avatar_routes().layer(DefaultBodyLimit::max(10 * 1024 * 1024))) // 10MB limit for avatar uploads
        .route_layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            unified_login_required,
        ));

    // Health endpoint - not rate limited for monitoring purposes
    let health_routes = Router::new()
        .route("/api/health", get(health_check))
        .with_state(app_state.clone());

    // Public auth routes (no authentication required) - rate limited
    // NOTE: Auth layer provides session/auth_session extractors but doesn't enforce authentication
    // The actual authentication requirement is enforced by protected routes or handler logic
    let public_auth_routes = Router::new()
        .nest("/auth", auth_routes()) // Auth routes under /api/auth (login, register, desktop config, auto-login, etc.)
        .layer(auth_layer.clone()) // Auth layer for session/auth_session extractors
        .layer(GovernorLayer {
            config: std::sync::Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(5000) // Very high rate for development - 1ms per request
                    .burst_size(5000) // High burst capacity for rapid development requests
                    .key_extractor(SmartIpKeyExtractor)
                    .finish()
                    .unwrap(),
            ),
        });

    // Protected API routes - require authentication AND rate limited
    let protected_rate_limited_routes = Router::new()
        .merge(protected_api_routes) // Protected routes under /api
        .layer(GovernorLayer {
            config: std::sync::Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(5000) // Very high rate for development - 1ms per request
                    .burst_size(5000) // High burst capacity for rapid development requests
                    .key_extractor(SmartIpKeyExtractor)
                    .finish()
                    .unwrap(),
            ),
        });

    // Webhook routes (no authentication, no rate limiting - signature verified in handler)
    #[cfg(feature = "payment")]
    tracing::info!("🎯 Setting up webhook routes in main.rs");
    #[cfg(feature = "payment")]
    let webhook_routes = Router::new()
        .nest("/api/payment", payment_webhook_routes()) // Webhook routes under /api/payment
        .with_state(app_state.clone());
    #[cfg(feature = "payment")]
    tracing::info!("🎯 Webhook routes configured");

    // Configure CORS for the frontend
    let cors = if app_state.config.environment.as_deref() == Some("desktop") {
        // Desktop mode - allow any localhost/127.0.0.1 origin (safe for local-only desktop app)
        // Tauri WebView uses random ports (e.g., http://127.0.0.1:1430), so we can't use static origins
        use tower_http::cors::AllowOrigin;
        tracing::info!("Configuring CORS for desktop mode with permissive localhost origins");
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(
                |origin: &axum::http::HeaderValue, _parts| {
                    let origin_str = origin.to_str().unwrap_or("");
                    let is_allowed = origin_str.starts_with("http://localhost")
                        || origin_str.starts_with("https://localhost")
                        || origin_str.starts_with("http://127.0.0.1")
                        || origin_str.starts_with("https://127.0.0.1")
                        || origin_str.starts_with("tauri://localhost");
                    if !is_allowed {
                        tracing::debug!("CORS rejected origin: {}", origin_str);
                    }
                    is_allowed
                },
            ))
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
                axum::http::header::CACHE_CONTROL,
                axum::http::header::PRAGMA,
            ])
            .allow_credentials(true)
    } else {
        // Cloud mode - strict origins
        // With the proxy pattern, requests will appear to come from staging.scribe.sanguinehost.com
        // via Vercel's edge proxy, but they'll have the correct origin headers
        CorsLayer::new()
            .allow_origin([
                "https://staging.scribe.sanguinehost.com".parse().unwrap(),
                "https://scribe-frontend.vercel.app".parse().unwrap(),
                "https://localhost:5173".parse().unwrap(),
                "http://localhost:5173".parse().unwrap(),
                "http://localhost:3000".parse().unwrap(),
                "tauri://localhost".parse().unwrap(), // Tauri desktop app origin (fallback)
            ])
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
                axum::http::header::CACHE_CONTROL,
                axum::http::header::PRAGMA,
            ])
            .allow_credentials(true)
    };

    // Build API routes with proper auth layering
    // Public auth routes (no auth layer) + Protected routes (with auth layer)
    let api_routes = Router::new()
        .nest("/api", public_auth_routes) // Public auth routes - NO auth required
        .nest(
            "/api",
            protected_rate_limited_routes.layer(auth_layer.clone()), // Auth layer ONLY on protected routes
        )
        .with_state(app_state.clone());

    // Combine all routes
    #[cfg(feature = "payment")]
    let final_router = {
        let base_router = Router::new()
            .merge(health_routes) // Health endpoint not rate limited
            .merge(api_routes); // All API routes (public + protected)
        base_router.merge(webhook_routes) // Webhook routes without auth
    };

    #[cfg(not(feature = "payment"))]
    let final_router = Router::new()
        .merge(health_routes) // Health endpoint not rate limited
        .merge(api_routes); // All API routes (public + protected)

    final_router
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .with_state(app_state)
        .layer(axum_middleware::from_fn(
            scribe_backend::middleware::security_headers_middleware,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        )
        .layer(axum_middleware::from_fn(main_request_logging_middleware))
}

// Start the server with TLS configuration
async fn start_server(config: &Config, app: Router) -> Result<()> {
    let port = config.port;
    let addr_str = format!("0.0.0.0:{port}");
    let addr: SocketAddr = addr_str.parse().expect("Invalid address format");

    // Load TLS configuration based on environment
    let environment = config.environment.as_deref().unwrap_or("local");

    let tls_config = match environment {
        "staging" | "production" => {
            // For AWS cloud environments, load certificates from environment variables
            tracing::info!(
                "AWS environment detected ({}), loading certificates from Secrets Manager",
                environment
            );
            load_cloud_certificate()
                .await
                .context("Failed to load certificate for AWS cloud deployment")?
        }
        "container" => {
            // For containerized development, try environment variables first, then files
            tracing::info!("Container environment detected, loading certificates");

            // Try loading from environment variables first (preferred for containers)
            if let (Ok(cert_pem), Ok(key_pem)) = (env::var("TLS_CERT_PEM"), env::var("TLS_KEY_PEM"))
            {
                tracing::info!("Loading TLS certificates from environment variables for container");
                RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                    .await
                    .context("Failed to create RustlsConfig from container environment variables")?
            } else {
                // Fallback to mounted certificate files in container
                tracing::info!("Loading TLS certificates from mounted files in container");
                let cert_path = PathBuf::from("/app/certs/cert.pem");
                let key_path = PathBuf::from("/app/certs/key.pem");

                RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .context("Failed to load TLS certificates from container files. Ensure certificates are mounted to /app/certs/")?
            }
        }
        "desktop" => {
            // For desktop mode, generate self-signed certificates in-memory
            tracing::info!(
                "Desktop environment detected, generating in-memory self-signed certificates"
            );

            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

            let cert_key = generate_simple_self_signed(subject_alt_names)
                .context("Failed to generate self-signed certificate for desktop mode")?;

            let cert_pem = cert_key.cert.pem();
            let key_pem = cert_key.key_pair.serialize_pem();

            tracing::info!("Desktop self-signed certificate generated successfully");

            RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                .await
                .context("Failed to create RustlsConfig from desktop certificate")?
        }
        "local" | _ => {
            // For local development, support environment variable override for certificate paths
            let (cert_path, key_path) = if let (Ok(cert_env), Ok(key_env)) =
                (env::var("TLS_CERT_PATH"), env::var("TLS_KEY_PATH"))
            {
                tracing::info!("Using TLS certificate paths from environment variables");
                (PathBuf::from(cert_env), PathBuf::from(key_env))
            } else {
                // Default to .certs directory
                tracing::info!(
                    "Local environment detected, loading certificates from .certs directory"
                );

                let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let project_root = manifest_dir
                    .parent()
                    .context("Failed to get project root from manifest dir")?;

                (
                    project_root.join(".certs-backend/cert.pem"),
                    project_root.join(".certs-backend/key.pem"),
                )
            };

            tracing::info!(
                cert_path = %cert_path.display(),
                key_path = %key_path.display(),
                "Loading TLS certificates for local development"
            );

            RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .context("Failed to load TLS certificate/key for local development. Run 'scripts/dev-certs-local.sh' or 'scripts/init-certs.sh local init' to generate certificates.")?
        }
    };

    tracing::info!(
        "Starting HTTPS server with TLS certificates on {} (environment: {})",
        addr,
        environment
    );

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("HTTPS server failed to start")?;

    Ok(())
}

// Extracted migration logic
#[cfg(feature = "postgres-backend")]
async fn run_migrations(pool: &DbPool) -> Result<()> {
    tracing::info!("Attempting to run database migrations...");
    let conn = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get connection for migration: {}", e))?;
    conn.interact(|conn| match conn.run_pending_migrations(MIGRATIONS) {
        Ok(versions) => {
            if versions.is_empty() {
                tracing::info!("No pending migrations found.");
            } else {
                tracing::info!("Successfully ran migrations: {:?}", versions);
            }
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to run database migrations: {:?}", e);
            Err(anyhow::anyhow!("Migration diesel error: {:?}", e))
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("Migration interact task failed: {}", e))??; // Propagate InteractError then inner Result
    Ok(())
}

#[cfg(feature = "sqlite-backend")]
async fn run_migrations(pool: &DbPool) -> Result<()> {
    tracing::info!("Attempting to run database migrations...");
    let mut conn = pool
        .get()
        .map_err(|e| anyhow::anyhow!("Failed to get connection for migration: {}", e))?;
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(versions) => {
            if versions.is_empty() {
                tracing::info!("No pending migrations found.");
            } else {
                tracing::info!("Successfully ran migrations: {:?}", versions);
            }
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to run database migrations: {:?}", e);
            Err(anyhow::anyhow!("Migration diesel error: {:?}", e))
        }
    }
}

// Desktop mode initialization - verify desktop configuration
#[cfg(feature = "desktop")]
async fn initialize_desktop_mode(_pool: &DbPool) -> Result<()> {
    tracing::info!("Initializing desktop mode...");

    // Load and log desktop configuration status
    let config = desktop::load_desktop_config()?;

    tracing::info!(
        "Desktop configuration loaded: setup_complete={}, auth_mode={:?}",
        config.setup_complete,
        config.auth_mode
    );

    // Note: User creation is handled by the /api/auth/desktop/setup endpoint
    // on first run. This allows the setup flow to properly establish sessions
    // and handle errors without chicken-and-egg initialization issues.

    tracing::info!("Desktop mode initialization complete");
    Ok(())
}

// --- Test module remains unchanged ---
#[cfg(test)]
mod tests {

    // Import the necessary trait

    // Use the r2d2 Pool directly from deadpool_diesel
    // Ensure PgPool is in scope for the test
    // Remove import for unavailable module
    // use testcontainers_modules::postgres::Postgres;

    // Note: Health check test moved to tests/health_check.rs for integration testing
    // since the new health_check function requires AppState
}
