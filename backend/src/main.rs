use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::get, // Remove post
};
use deadpool_diesel::postgres::{
    Manager as DeadpoolManager, PoolConfig, Runtime as DeadpoolRuntime,
};
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

// Use modules from the library crate
use anyhow::Context;
use anyhow::Result;
use scribe_backend::PgPool;
use scribe_backend::auth::session_store::DieselSessionStore;
use scribe_backend::auth::user_store::Backend as AuthBackend;
use scribe_backend::errors::AppError;
use scribe_backend::logging::init_subscriber;
use scribe_backend::routes::admin::admin_routes;
use scribe_backend::routes::auth::auth_routes;
use scribe_backend::routes::health::health_check;
use scribe_backend::routes::{
    avatars::avatar_routes,        // Added for avatar routes
    characters::characters_router, // Use the router function import
    chat::chat_routes,
    chats,
    chronicles,
    documents::document_routes,
    lorebook_routes::lorebook_routes, // Added for lorebook routes
    user_persona_routes::user_personas_router, // Added for user persona routes
    user_settings_routes::user_settings_routes,
};
use scribe_backend::state::{AppState, AppStateServices};
use std::env; // Added for current_dir

// Imports for axum-login and tower-sessions
use axum_login::{AuthManagerLayerBuilder, login_required}; // Modified
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
use scribe_backend::services::chat_override_service::ChatOverrideService;
use scribe_backend::services::chronicle_service::ChronicleService;
use scribe_backend::services::embeddings::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait,
};
use scribe_backend::services::encryption_service::EncryptionService;
use scribe_backend::services::file_storage_service::FileStorageService; // Added
use scribe_backend::services::gemini_token_client::GeminiTokenClient; // Added
use scribe_backend::services::hybrid_token_counter::HybridTokenCounter; // Added
use scribe_backend::services::lorebook::LorebookService;
use scribe_backend::services::narrative_intelligence_service::NarrativeIntelligenceService;
use scribe_backend::services::tokenizer_service::TokenizerService; // Added
use scribe_backend::services::user_persona_service::UserPersonaService;
use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import chunking config structs
use scribe_backend::vector_db::QdrantClientService;
// ECS Services imports
use scribe_backend::services::{EcsEntityManager, EcsGracefulDegradation, EcsEnhancedRagService, HybridQueryService, ChronicleEventListener, ChronicleEcsTranslator};
use scribe_backend::config::NarrativeFeatureFlags;
use std::path::PathBuf;
use std::sync::Arc;
use time::Duration;
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor,
};
use tower_sessions::cookie::Key; // Use Key from tower_sessions::cookie for with_signed
use tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite}; // Add Arc for config // Add Qdrant service import // Add embedding pipeline service import

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

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
    let pool = setup_database_pool(&config);
    run_migrations(&pool).await?;

    let services = initialize_services(&config, &pool).await?;

    let (app_state, auth_layer) = setup_app_state_and_auth(&config, &pool, services)?;

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
}

// Setup database pool
fn setup_database_pool(config: &Config) -> PgPool {
    let db_url = config
        .database_url
        .as_ref()
        .expect("DATABASE_URL not set in config");
    tracing::info!("Connecting to database...");
    let manager = DeadpoolManager::new(db_url, DeadpoolRuntime::Tokio1);

    // Configure pool size based on environment
    let mut pool_config = PoolConfig::default();
    let max_size = match config.environment.as_deref() {
        Some("development") => 50, // Local docker has max_connections = 200
        Some("staging") | Some("production") => 20, // Cloud RDS has ~90 total connections
        _ => 20,                   // Default to conservative for unknown environments
    };
    pool_config.max_size = max_size;
    pool_config.timeouts.wait = Some(std::time::Duration::from_secs(30)); // 30 second timeout

    let pool: PgPool = DeadpoolPool::builder(manager)
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

// Initialize all services
async fn initialize_services(config: &Arc<Config>, pool: &PgPool) -> Result<AppStateServices> {
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

    // --- Initialize Qdrant Client Service ---
    tracing::info!("Initializing Qdrant client service...");
    let qdrant_service = Arc::new(QdrantClientService::new(config.clone()).await?);
    tracing::info!("Qdrant client service initialized.");

    // --- Initialize Lorebook Service (needs qdrant_service) ---
    let lorebook_service = Arc::new(LorebookService::new(
        pool.clone(),
        encryption_service.clone(),
        qdrant_service.clone(),
    ));

    // --- Initialize Chronicle Service ---
    let chronicle_service = Arc::new(ChronicleService::new(
        pool.clone(),
    ));

    let auth_backend = Arc::new(AuthBackend::new(pool.clone()));

    // --- Initialize File Storage Service ---
    let file_storage_service = Arc::new(
        FileStorageService::new(&config.upload_storage_path)
            .context("Failed to initialize file storage service")?,
    );

    // Initialize storage directories
    file_storage_service
        .init()
        .await
        .context("Failed to initialize file storage directories")?;

    // Initialize ECS services
    let ecs_services = initialize_ecs_services(config, &pool).await?;
    
    // --- Initialize Narrative Intelligence Service ---
    // Note: Will be initialized after AppState is created due to circular dependency

    Ok(AppStateServices {
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
        file_storage_service,
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
        // ECS Services
        redis_client: ecs_services.redis_client,
        feature_flags: ecs_services.feature_flags,
        ecs_entity_manager: ecs_services.ecs_entity_manager,
        ecs_graceful_degradation: ecs_services.ecs_graceful_degradation,
        ecs_enhanced_rag_service: ecs_services.ecs_enhanced_rag_service,
        hybrid_query_service: ecs_services.hybrid_query_service,
        chronicle_event_listener: ecs_services.chronicle_event_listener,
        chronicle_ecs_translator: ecs_services.chronicle_ecs_translator,
        chronicle_service: ecs_services.chronicle_service,
    })
}

/// ECS services container for dependency injection
struct EcsServices {
    redis_client: Arc<redis::Client>,
    feature_flags: Arc<NarrativeFeatureFlags>,
    ecs_entity_manager: Arc<EcsEntityManager>,
    ecs_graceful_degradation: Arc<EcsGracefulDegradation>,
    ecs_enhanced_rag_service: Arc<EcsEnhancedRagService>,
    hybrid_query_service: Arc<HybridQueryService>,
    chronicle_event_listener: Arc<ChronicleEventListener>,
    chronicle_ecs_translator: Arc<ChronicleEcsTranslator>,
    chronicle_service: Arc<ChronicleService>,
}

// Initialize ECS services with proper dependency order
async fn initialize_ecs_services(
    config: &Arc<Config>,
    pool: &PgPool,
) -> Result<EcsServices> {
    tracing::info!("Initializing ECS services...");
    
    // Initialize Redis client for ECS caching
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let redis_client = Arc::new(redis::Client::open(redis_url.as_str())
        .context("Failed to create Redis client for ECS")?);
    tracing::info!("Redis client initialized for ECS caching");
    
    // Initialize feature flags (start with defaults, could load from config later)
    let feature_flags = Arc::new(NarrativeFeatureFlags::default());
    tracing::info!("Feature flags initialized with defaults");
    
    // Initialize ECS Entity Manager (requires: db_pool, redis_client)
    let ecs_entity_manager = Arc::new(EcsEntityManager::new(
        Arc::new(pool.clone()),
        redis_client.clone(),
        None, // Use default config
    ));
    tracing::info!("ECS Entity Manager initialized");
    
    // Initialize ECS Graceful Degradation (requires: feature_flags, entity_manager)
    let ecs_graceful_degradation = Arc::new(EcsGracefulDegradation::new(
        Default::default(), // Use default config
        feature_flags.clone(),
        Some(ecs_entity_manager.clone()),
        None, // No consistency monitor for now
    ));
    tracing::info!("ECS Graceful Degradation initialized");
    
    // Initialize ECS Enhanced RAG Service (requires: db_pool, feature_flags, entity_manager, degradation, embedding_service)
    // Create a dedicated embedding service for ECS (reusing chunk config pattern from main initialization)
    let chunk_config = create_chunk_config(config);
    let ecs_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(chunk_config));
    
    let ecs_enhanced_rag_service = Arc::new(EcsEnhancedRagService::new(
        Arc::new(pool.clone()),
        Default::default(), // Use default config
        feature_flags.clone(),
        ecs_entity_manager.clone(),
        ecs_graceful_degradation.clone(),
        ecs_embedding_service,
    ));
    tracing::info!("ECS Enhanced RAG Service initialized");
    
    // Initialize Hybrid Query Service (requires: db_pool, feature_flags, entity_manager, rag_service, degradation)
    let hybrid_query_service = Arc::new(HybridQueryService::new(
        Arc::new(pool.clone()),
        Default::default(), // Use default config
        feature_flags.clone(),
        ecs_entity_manager.clone(),
        ecs_enhanced_rag_service.clone(),
        ecs_graceful_degradation.clone(),
    ));
    tracing::info!("Hybrid Query Service initialized");
    
    // Initialize Chronicle-related ECS services
    let chronicle_service = Arc::new(ChronicleService::new(pool.clone()));
    tracing::info!("Chronicle Service initialized");
    
    let chronicle_ecs_translator = Arc::new(ChronicleEcsTranslator::new(
        Arc::new(pool.clone())
    ));
    tracing::info!("Chronicle ECS Translator initialized");
    
    let mut chronicle_event_listener = ChronicleEventListener::new(
        Default::default(), // Use default config
        feature_flags.clone(),
        chronicle_ecs_translator.clone(),
        ecs_entity_manager.clone(),
        chronicle_service.clone(),
    );
    
    // Start the chronicle event listener
    chronicle_event_listener
        .start()
        .await
        .context("Failed to start chronicle event listener")?;
    tracing::info!("Chronicle Event Listener initialized and started");
    
    let chronicle_event_listener = Arc::new(chronicle_event_listener);
    
    tracing::info!("All ECS services initialized successfully");
    
    Ok(EcsServices {
        redis_client,
        feature_flags,
        ecs_entity_manager,
        ecs_graceful_degradation,
        ecs_enhanced_rag_service,
        hybrid_query_service,
        chronicle_event_listener,
        chronicle_ecs_translator,
        chronicle_service,
    })
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
    pool: &PgPool,
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
    let narrative_intelligence_service = Arc::new(
        NarrativeIntelligenceService::for_production_with_deps(
            app_state.ai_client.clone(),
            chronicle_service,
            app_state.lorebook_service.clone(),
            app_state.qdrant_service.clone(),
            app_state.embedding_client.clone(),
            Arc::new(app_state.clone()),
        )
    );
    app_state.set_narrative_intelligence_service(narrative_intelligence_service);

    Ok((app_state, auth_layer))
}

// Build the router with all routes and middleware
fn build_router(
    app_state: AppState,
    auth_layer: axum_login::AuthManagerLayer<AuthBackend, DieselSessionStore>,
) -> Router {
    let entities_router = chronicles::create_entities_router(app_state.clone());
    tracing::info!("Entities router created, adding to protected routes");
    
    let protected_api_routes = Router::new()
        .nest(
            "/characters",
            characters_router(app_state.clone()).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        ) // 10MB limit for character uploads
        .nest("/chat", chat_routes(app_state.clone()).layer(DefaultBodyLimit::max(50 * 1024 * 1024))) // 50MB limit for chat history
        .nest("/chats", chats::chat_routes())
        .nest("/chronicles", chronicles::create_chronicles_router(app_state.clone()))
        .nest("/entities", entities_router)
        .nest("/documents", document_routes())
        .nest("/personas", user_personas_router(app_state.clone()))
        .nest("/user-settings", user_settings_routes(app_state.clone()))
        .nest("/", lorebook_routes())
        .nest("/admin", admin_routes())
        .merge(avatar_routes().layer(DefaultBodyLimit::max(10 * 1024 * 1024))) // 10MB limit for avatar uploads
        .route_layer(login_required!(AuthBackend));

    // Health endpoint - not rate limited for monitoring purposes
    let health_routes = Router::new().route("/api/health", get(health_check));

    // Rate-limited API routes (both public and protected)
    let rate_limited_api_routes = Router::new()
        .nest("/auth", auth_routes()) // Auth routes under /api/auth
        .merge(protected_api_routes) // Protected routes under /api
        .layer(GovernorLayer {
            config: std::sync::Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(2000) // Increased from 500 to allow more requests
                    .burst_size(5000) // Increased from 1000 to handle rapid bursts
                    .key_extractor(GlobalKeyExtractor)
                    .finish()
                    .unwrap(),
            ),
        });

    // Configure CORS for the frontend
    // With the proxy pattern, requests will appear to come from staging.scribe.sanguinehost.com
    // via Vercel's edge proxy, but they'll have the correct origin headers
    let cors = CorsLayer::new()
        .allow_origin([
            "https://staging.scribe.sanguinehost.com".parse().unwrap(), // Primary frontend domain
            "https://localhost:5173".parse().unwrap(),                  // Local development
            "http://localhost:5173".parse().unwrap(),                   // Local development (HTTP)
            "http://localhost:3000".parse().unwrap(), // Local development alt port
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
        .allow_credentials(true);

    Router::new()
        .merge(health_routes) // Health endpoint not rate limited
        .nest("/api", rate_limited_api_routes) // All other API routes are rate limited
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        .with_state(app_state)
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

    // Check if we're in a cloud environment (staging/production)
    let environment = config.environment.as_deref().unwrap_or("development");

    if environment == "staging" || environment == "production" {
        // For cloud environments, load certificates for end-to-end encryption
        tracing::info!(
            "Cloud environment detected ({}), loading certificates for end-to-end encryption",
            environment
        );

        let tls_config = load_cloud_certificate()
            .await
            .context("Failed to load certificate for cloud deployment")?;

        tracing::info!("Starting HTTPS server with TLS certificates on {}", addr);

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .context("HTTPS server failed to start")?;
    } else {
        // For local development, use certificates from .certs directory
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let project_root = manifest_dir
            .parent()
            .context("Failed to get project root from manifest dir")?;

        let cert_path = project_root.join(".certs/cert.pem");
        let key_path = project_root.join(".certs/key.pem");

        tracing::info!(cert_path = %cert_path.display(), key_path = %key_path.display(), "Loading TLS certificates for local development");

        let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .context("Failed to load TLS certificate/key for local development. Run 'scripts/dev_certs.sh' to generate certificates.")?;

        tracing::info!("Starting HTTPS server with local certificates on {}", addr);

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .context("HTTPS server failed to start")?;
    }

    Ok(())
}

// Extracted migration logic
async fn run_migrations(pool: &PgPool) -> Result<()> {
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

// --- Test module remains unchanged ---
#[cfg(test)]
mod tests {
    use super::*;
    // Import the necessary trait

    // Use the r2d2 Pool directly from deadpool_diesel
    // Ensure PgPool is in scope for the test
    // Remove import for unavailable module
    // use testcontainers_modules::postgres::Postgres;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0.status, "ok");
    }
}
