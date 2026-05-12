#![recursion_limit = "8192"]
use axum::{
    extract::DefaultBodyLimit, http::StatusCode, response::IntoResponse, routing::get, Json, Router,
};
#[cfg(feature = "postgres-backend")]
use deadpool_diesel::postgres::{Manager as DeadpoolManager, Runtime as DeadpoolRuntime};
#[cfg(feature = "postgres-backend")]
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

// Use modules from the library crate
use anyhow::Context;
use anyhow::Result;
use scribe_backend::auth::session_store::DieselSessionStore;
use scribe_backend::auth::user_store::Backend as AuthBackend;
use scribe_backend::db::DbPool;
#[cfg(feature = "desktop")]
use scribe_backend::desktop; // Desktop mode initialization
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
    telemetry_routes::ingest_telemetry,
    template_preferences_routes::template_preferences_routes, // Added for template preferences routes
    templates,                                                // Added for template routes
    user_persona_routes::user_personas_router,                // Added for user persona routes
    user_settings_routes::user_settings_routes,
};
use scribe_backend::services::cognitive::RecallPipeline;
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
                                    // use scribe_backend::llm::gemini_client::build_gemini_client; // Import the async builder
use scribe_backend::llm::cloud_embedding_client::build_cloud_embedding_client; // Add this
use scribe_backend::services::ai_client_factory::AiClientFactory;
use scribe_backend::services::character_service::CharacterService;
use scribe_backend::services::chat_override_service::ChatOverrideService;
use scribe_backend::services::chronicle_service::ChronicleService;
use scribe_backend::services::embeddings::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait,
};
use scribe_backend::services::encryption_service::EncryptionService;
use scribe_backend::services::hybrid_token_counter::HybridTokenCounter; // Added
use scribe_backend::services::lorebook::LorebookService;
use scribe_backend::services::narrative_intelligence_service::NarrativeIntelligenceService;
use scribe_backend::services::token_client::TokenClient; // Added
use scribe_backend::services::tokenizer_service::TokenizerService; // Added
use scribe_backend::services::user_persona_service::UserPersonaService;
use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import chunking config structs

use scribe_backend::llm::UnifiedEmbeddingModel;
use std::path::PathBuf;
use std::sync::Arc;
use time::Duration;
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_sessions::cookie::{Key, SameSite}; // Use Key and SameSite from tower_sessions::cookie
use tower_sessions::service::PrivateCookie; // Found in tower_sessions::service in 0.14.0
use tower_sessions::{Expiry, SessionManagerLayer};
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
    let key_pem = cert_key.signing_key.serialize_pem();

    tracing::info!("Self-signed certificate generated successfully");

    // Create RustlsConfig from the generated certificate and key
    let config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
        .await
        .context("Failed to create RustlsConfig from generated certificate")?;

    Ok(config)
}

async fn main_request_logging_middleware(req: AxumRequest, next: Next) -> AxumResponse {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("unknown")
        .to_string();

    // Attempt to identify event_type for logging/alerting
    let event_type = if path.contains("/auth/login") {
        Some("auth_attempt")
    } else if path.contains("/payment/webhook") {
        Some("payment_webhook")
    } else {
        None
    };

    // Debug X-Forwarded-For to solve IP resolution issues
    // Must be cloned before req is moved into next.run(req)
    let xff_header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_string();

    // DEBUG: Log all headers to find where the IP is hiding
    let all_headers = req
        .headers()
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
        .collect::<Vec<_>>()
        .join(", ");

    tracing::info!(
        target: "main_router_debug",
        method = %method,
        uri = %uri,
        path = %path,
        query = %query,
        client_ip = %client_ip,
        xff_header = %xff_header,
        all_headers = %all_headers,
        event_type = %event_type.unwrap_or("none"),
        "MAIN ROUTER: Received request"
    );

    let res = next.run(req).await;
    let latency = start.elapsed().as_millis() as u64;
    let status = res.status();

    // Enrich response log with event_type if it was unsuccessful
    let response_event_type = if !status.is_success() {
        match (event_type, status.as_u16()) {
            (Some("auth_attempt"), 401 | 403) => Some("auth_failure"),
            (Some("payment_webhook"), _) => Some("payment_webhook_error"),
            _ => None,
        }
    } else {
        event_type
    };

    // Extract user_id from response extensions (propagated from capture_user_id_middleware via inner layers)
    let user_id = res
        .extensions()
        .get::<scribe_backend::middleware::PrivacySafeUserId>()
        .map(|uid| uid.0.clone());

    tracing::info!(
        target: "main_router_debug",
        status = status.as_u16(),
        method = %method,
        latency = latency,
        path = %path,
        client_ip = %client_ip,
        xff_header = %xff_header, // Logging raw XFF for debugging
        user_id = %user_id.unwrap_or_else(|| "none".to_string()),
        event_type = %response_event_type.unwrap_or("none"),
        "MAIN ROUTER: Response sent"
    );

    res
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
    use diesel::prelude::*;
    use diesel::r2d2::{ConnectionManager, CustomizeConnection, Pool};
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

    // Connection customizer to enable WAL mode and set busy_timeout
    // This fixes "database is locked" errors by allowing concurrent reads during writes
    #[derive(Debug, Clone, Copy)]
    struct SqliteCustomizer;

    impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqliteCustomizer {
        fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
            // Enable WAL mode for better concurrency (allows concurrent reads during writes)
            diesel::sql_query("PRAGMA journal_mode = WAL;")
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;

            // Set busy_timeout to 10 seconds (connections will wait instead of failing immediately)
            diesel::sql_query("PRAGMA busy_timeout = 10000;")
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;

            // Enable foreign key constraints
            diesel::sql_query("PRAGMA foreign_keys = ON;")
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;

            Ok(())
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
        .connection_customizer(Box::new(SqliteCustomizer))
        .build(manager)
        .expect("Failed to create DB pool.");

    tracing::info!(
        "Database connection pool established with max_size: {}, WAL mode enabled, busy_timeout: 10s",
        max_size
    );
    pool
}

// Initialize all services
async fn initialize_services(config: &Arc<Config>, pool: &DbPool) -> Result<AppStateServices> {
    // --- Initialize MistralRs Service (if feature enabled) ---
    #[cfg(feature = "local-llm")]
    let mistralrs_service = {
        // For now, we initialize with a default model if it exists, or None
        // Real model loading will happen on-demand or via settings
        None
    };

    // Use RigClient instead of ScribeGeminiClient
    let ai_client =
        scribe_backend::llm::rig_client::RigClient::new(config.gemini_api_key.clone(), None);

    #[cfg(feature = "local-llm")]
    let ai_client = if let Some(ms) = mistralrs_service {
        ai_client.with_mistralrs(ms)
    } else {
        ai_client
    };

    let ai_client_arc = Arc::new(ai_client);

    // --- Initialize Embedding Client ---
    let embedding_client = build_cloud_embedding_client(config.clone())?;
    let embedding_client_arc = Arc::new(embedding_client);

    // --- Initialize Tokenizer Service ---
    let tokenizer_service = setup_tokenizer_service(config)?;

    // --- Initialize Token Client (Optional) ---
    let token_client = setup_token_client(config);

    // --- Initialize Hybrid Token Counter ---
    let hybrid_token_counter = setup_hybrid_token_counter(config, tokenizer_service, token_client);

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
    let character_service = Arc::new(CharacterService::new(
        pool.clone(),
        encryption_service.clone(),
    ));

    // --- Create Chunking Config and Embedding Pipeline ---
    let chunk_config = create_chunk_config(config);
    let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(chunk_config))
        as Arc<dyn EmbeddingPipelineServiceTrait>;

    // --- Initialize Vector DB Service (Rig-based) ---
    let embedding_model = UnifiedEmbeddingModel::Cloud((*embedding_client_arc).clone());

    tracing::info!("Initializing Vector DB service...");
    let qdrant_service =
        scribe_backend::vector_db::create_vector_service(config.clone(), embedding_model).await?;
    qdrant_service.ensure_collection_exists().await?;
    tracing::info!("Vector DB service initialized.");

    // --- Initialize Lorebook Service (needs qdrant_service) ---
    let lorebook_service = Arc::new(LorebookService::new(
        pool.clone(),
        encryption_service.clone(),
        qdrant_service.clone(),
    ));

    // --- Initialize Chronicle Service ---
    let _chronicle_service = Arc::new(ChronicleService::new(pool.clone(), ai_client_arc.clone()));

    // --- Initialize Recall Pipeline ---
    let recall_pipeline = Arc::new(RecallPipeline::new(pool.clone()));

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
        use scribe_backend::services::ai::mistralrs_service::MistralRsService;
        // TODO: Implement MistralRs equivalent of LlamaCppServerManager if needed
        // For now, we've integrated MistralRs into RigClient
    }

    // --- Initialize Narrative Intelligence Service ---
    // Note: Will be initialized after AppState is created due to circular dependency

    let services = AppStateServices {
        ai_client: ai_client_arc,
        embedding_client: embedding_client_arc,
        qdrant_service,
        embedding_pipeline_service,
        chat_override_service,
        character_service,
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
        recall_pipeline,
        #[cfg(feature = "local-llm")]
        llamacpp_server_manager: None, // Removed LlamaCppServerManager
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
    let tokenizer_model_path = PathBuf::from(&config.tokenizer_model_path);

    // If it's an absolute path, use it directly
    if tokenizer_model_path.is_absolute() {
        return tokenizer_model_path;
    }

    // Try relative to current working directory first
    if tokenizer_model_path.exists() {
        return tokenizer_model_path;
    }

    // Fallback to CARGO_MANIFEST_DIR for local development
    let backend_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let final_tokenizer_model_path = backend_crate_dir.join(&config.tokenizer_model_path);

    if let Ok(cwd) = env::current_dir() {
        tracing::info!("Current working directory: {}", cwd.display());
    } else {
        tracing::warn!("Failed to get current working directory.");
    }

    tracing::info!(
        "Tokenizer model relative path from config: {}",
        tokenizer_model_path.display()
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

// Setup token client
fn setup_token_client(config: &Config) -> Option<TokenClient> {
    config.gemini_api_key.as_ref().map_or_else(
        || {
            tracing::warn!(
                "GEMINI_API_KEY not set, TokenClient for token counting will not be available."
            );
            None
        },
        |api_key| {
            tracing::info!("Initializing TokenClient for token counting...");
            Some(TokenClient::new(api_key.clone()))
        },
    )
}

// Setup hybrid token counter
fn setup_hybrid_token_counter(
    config: &Config,
    tokenizer_service: TokenizerService,
    token_client: Option<TokenClient>,
) -> Arc<HybridTokenCounter> {
    tracing::info!("Initializing HybridTokenCounter...");
    let token_counter_default_model = config.token_counter_default_model.clone();
    let hybrid_token_counter = HybridTokenCounter::new(
        tokenizer_service,
        token_client,
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
    axum_login::AuthManagerLayer<AuthBackend, DieselSessionStore, PrivateCookie>,
)> {
    // --- Session Store Setup ---
    let session_store = DieselSessionStore::new(pool.clone());

    let secret_key = config
        .cookie_signing_key
        .as_ref()
        .context("COOKIE_SIGNING_KEY must be set in config")?;
    let key_bytes =
        decode(secret_key).context("Invalid COOKIE_SIGNING_KEY format in config (must be hex)")?;
    let signing_key = Key::from(&key_bytes);
    let mut session_manager_layer = SessionManagerLayer::new(session_store)
        .with_private(signing_key)
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
    let chronicle_service = Arc::new(ChronicleService::new(
        pool.clone(),
        app_state.ai_client.clone(),
    ));
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
    auth_layer: axum_login::AuthManagerLayer<AuthBackend, DieselSessionStore, PrivateCookie>,
) -> Router {
    let protected_api_routes = Router::new()
        .nest(
            "/characters",
            characters_router(app_state.clone()).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        ) // 10MB limit for character uploads
        .nest("/chat", {
            let routes = chat_routes(app_state.clone())
                .merge(scribe_backend::routes::game_state::router(
                    app_state.clone(),
                ))
                .layer(DefaultBodyLimit::max(50 * 1024 * 1024)); // 50MB limit for chat history

            #[cfg(feature = "payment")]
            let routes = routes.layer(axum::middleware::from_fn(
                scribe_backend::middleware::soft_limit_enforcement_middleware,
            ));

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

    // Note: Payment routes moved to central consolidation below

    let protected_api_routes = protected_api_routes
        .nest("/personas", user_personas_router(app_state.clone()))
        .nest("/user-settings", user_settings_routes(app_state.clone()))
        .nest(
            "/template-preferences",
            template_preferences_routes(app_state.clone()),
        )
        .merge(lorebook_routes())
        .nest("/templates", templates::create_router())
        .nest("/admin", admin_routes())
        .merge(avatar_routes().layer(DefaultBodyLimit::max(10 * 1024 * 1024))) // 10MB limit for avatar uploads
        .route_layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            unified_login_required,
        ));

    // Public auth routes (no authentication required) - rate limited
    // NOTE: Auth layer provides session/auth_session extractors but doesn't enforce authentication
    // The actual authentication requirement is enforced by protected routes or handler logic
    let public_auth_routes = Router::new()
        .nest("/auth", auth_routes()) // Auth routes under /api/auth (login, register, desktop config, auto-login, etc.)
        .route("/telemetry", axum::routing::post(ingest_telemetry)) // Telemetry ingestion route (supports unauthenticated payloads)
        .layer(axum_middleware::from_fn(
            scribe_backend::middleware::capture_user_id_middleware,
        ))
        .layer(auth_layer.clone()) // Auth layer for session/auth_session extractors
        .layer(GovernorLayer::new(std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .per_second(5000) // Very high rate for development - 1ms per request
                .burst_size(5000) // High burst capacity for rapid development requests
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .unwrap(),
        )));

    // Protected API routes - require authentication AND rate limited
    let protected_rate_limited_routes = Router::new()
        .merge(protected_api_routes) // Protected routes under /api
        .layer(GovernorLayer::new(std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .per_second(5000) // Very high rate for development - 1ms per request
                .burst_size(5000) // High burst capacity for rapid development requests
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .unwrap(),
        )));

    // Webhook routes (no authentication, no rate limiting - signature verified in handler)
    #[cfg(feature = "payment")]
    let payment_router = {
        // Build a consolidated payment router
        payment_webhook_routes().merge(payment_routes())
    };

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
    // Build a consolidated API router to avoid conflicting nests and shadowing
    let mut api_router = Router::new()
        // Health/Diagnostic routes (Highest priority inside /api)
        .route("/health", get(health_check))
        .route(
            "/health/error",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Diagnostic Error",
                )
            }),
        )
        .route(
            "/health/slow",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                "Health Slow OK"
            }),
        )
        .route(
            "/health/anomaly",
            get(|| async {
                use scribe_backend::logging::security_events::SecurityEvent;
                let event = SecurityEvent::CreditOperationAnomaly {
                    timestamp: chrono::Utc::now().into(),
                    user_hash: "user#paperboy_hashed".to_string(),
                    operation_type: "add".to_string(),
                    amount: 1000000.0,
                    anomaly_reason: "diagnostic_manual_trigger".to_string(),
                    baseline_deviation: 10.0,
                };
                if let Ok(json) = event.to_json() {
                    tracing::warn!(
                        event_type = "credit_operation_anomaly",
                        severity = "P0",
                        "{}",
                        json
                    );
                }
                "Credit Anomaly Triggered"
            }),
        )
        .route(
            "/health/ttft",
            get(|| async {
                tracing::info!(
                    event_type = "llm_ttft",
                    provider = "gemini",
                    duration_ms = 3500_u64,
                    "Time to First Token: 3500ms"
                );
                "Mock TTFT Triggered"
            }),
        )
        .route(
            "/health/llm_failure",
            get(|| async {
                tracing::error!(
                    event_type = "llm_generation_failure",
                    provider = "gemini",
                    error = "mock api timeout",
                    "Failed to generate LLM response"
                );
                "Mock LLM Failure Triggered"
            }),
        )
        .route(
            "/health/db_error",
            get(|| async {
                tracing::error!(
                    event_type = "database_error",
                    error = "mock connection timeout",
                    "Database connection failure simulated"
                );
                "Mock Database Error Triggered"
            }),
        )
        .route(
            "/health/payment_fail",
            get(|| async {
                tracing::error!(
                    event_type = "payment_failed",
                    reason = "mock card rejection",
                    "Payment failure event simulated"
                );
                "Mock Payment Failure Triggered"
            }),
        )
        .route("/health/debug", get(|| async { "Health Debug OK" }))
        .route("/ping", get(|| async { "API Ping OK" }))
        // Auth routes (Public)
        .merge(public_auth_routes);

    // Payment routes (Priority nesting under /payment)
    #[cfg(feature = "payment")]
    {
        // payment_router already merges webhook and protected payment routes in main()
        api_router = api_router.nest("/payment", payment_router);
    }

    // Merge all other protected routes with auth layer
    api_router = api_router.merge(
        protected_rate_limited_routes
            .layer(axum_middleware::from_fn(
                scribe_backend::middleware::capture_user_id_middleware,
            ))
            .layer(auth_layer),
    );

    // Final top-level router assembly
    // Priority:
    // 1. Critical Diagnostics (directly on root and /probe)
    // 2. Main API (/api)
    // 3. 404 Fallback
    Router::new()
        // Highest priority: Critical diagnostics to avoid any shadowing
        .route("/probe/ping", get(|| async { "Probe Ping OK 12345" }))
        .route("/probe/root", get(|| async { "Probe Root OK 12345" }))
        .route("/ping", get(|| async { "Root Ping OK 12345" }))
        // Main API nesting
        .nest("/api", api_router)
        // Fallback for everything else
        .fallback(fallback_404)
        // Layers applied from outside in
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .with_state(app_state)
        .layer(axum_middleware::from_fn(
            scribe_backend::middleware::security_headers_middleware,
        ))
        // Logging middleware runs INSIDE the TraceLayer span so it can access/record fields
        .layer(axum_middleware::from_fn(main_request_logging_middleware))
        // TraceLayer should be outermost of the logging layers to ensure span exists for inner layers
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "http.request",
                        method = %request.method(),
                        uri = %request.uri(),
                        status_code = tracing::field::Empty,
                        "otel.status_code" = tracing::field::Empty,
                        user_id = tracing::field::Empty,
                    )
                })
                .on_response(
                    |_res: &AxumResponse, _latency: std::time::Duration, span: &tracing::Span| {
                        let status = _res.status();
                        span.record("status_code", status.as_u16() as u64);
                        // Set span status to error if status code is 5xx
                        if status.is_server_error() {
                            span.record("otel.status_code", "ERROR");
                            span.record("status_code", 2u64); // OpenObserve alert specifically looks for status_code=2
                        }
                    },
                ),
        )
}

/// Global 404 fallback handler that returns JSON
async fn fallback_404(method: axum::http::Method, uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path();
    tracing::warn!(
        target: "main_router_debug",
        method = %method,
        path = %path,
        "ROUTING ERROR: Request matched no routes (Returning 404)"
    );
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Not Found",
            "error_code": "NOT_FOUND",
            "path": path,
            "method": method.as_str()
        })),
    )
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
            let key_pem = cert_key.signing_key.serialize_pem();

            tracing::info!("Desktop self-signed certificate generated successfully");

            RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                .await
                .context("Failed to create RustlsConfig from desktop certificate")?
        }
        "local" => {
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
        _ => {
            // For other environments, support environment variable override for certificate paths
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
