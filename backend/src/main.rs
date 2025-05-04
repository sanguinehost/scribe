use axum::{
    Router,
    routing::{get, post},
};
use deadpool_diesel::postgres::{
    Manager as DeadpoolManager, PoolConfig, Runtime as DeadpoolRuntime,
};
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::net::SocketAddr;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

// Use modules from the library crate
use scribe_backend::auth::session_store::DieselSessionStore;
use scribe_backend::logging::init_subscriber;
use scribe_backend::routes::auth::auth_routes;
use scribe_backend::routes::health::health_check;
use scribe_backend::routes::{
    characters::{get_character_handler, list_characters_handler, upload_character_handler},
    chat::chat_routes,
    chats_api,
    documents_api::document_routes,
};
use scribe_backend::state::AppState;
use anyhow::Context;
use anyhow::Result;
use scribe_backend::auth::user_store::Backend as AuthBackend;
use scribe_backend::PgPool;
// Make sure AppError is in scope

// Imports for axum-login and tower-sessions
use axum_login::{AuthManagerLayerBuilder, login_required};
// Import SessionManagerLayer directly from tower_sessions
use cookie::Key as CookieKey; // Re-add for signing key variable
use hex; // Added for hex::decode
use scribe_backend::config::Config; // Import Config instead
use std::sync::Arc;
use time; // Used for tower_sessions::Expiry
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use tower_sessions::{cookie::SameSite, Expiry, SessionManagerLayer}; // Add Arc for config
// Import the builder function
use scribe_backend::llm::gemini_client::build_gemini_client; // Import the async builder
use scribe_backend::llm::gemini_embedding_client::build_gemini_embedding_client; // Add this
use scribe_backend::services::embedding_pipeline::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait,
};
use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import chunking config structs
use scribe_backend::vector_db::QdrantClientService; // Add Qdrant service import // Add embedding pipeline service import

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    init_subscriber();

    tracing::info!("Starting Scribe backend server...");

    let config = Arc::new(Config::load().expect("Failed to load configuration")); // Load Config into Arc
    let db_url = config
        .database_url
        .as_ref()
        .expect("DATABASE_URL not set in config");
    tracing::info!("Connecting to database...");
    let manager = DeadpoolManager::new(db_url, DeadpoolRuntime::Tokio1);
    let pool_config = PoolConfig::default(); // Use default config for now
    let pool: PgPool = DeadpoolPool::builder(manager)
        .config(pool_config)
        .runtime(DeadpoolRuntime::Tokio1)
        .build()
        .expect("Failed to create DB pool.");
    tracing::info!("Database connection pool established.");

    run_migrations(&pool).await?; // Extract migration logic to function

    // --- Initialize GenAI Client Asynchronously ---
    let ai_client = build_gemini_client().await?;
    let ai_client_arc = Arc::new(ai_client); // Wrap in Arc for AppState

    // --- Initialize Embedding Client ---
    let embedding_client = build_gemini_embedding_client(config.clone())?;
    let embedding_client_arc = Arc::new(embedding_client); // Wrap in Arc

    // --- Initialize Qdrant Client Service ---
    tracing::info!("Initializing Qdrant client service...");
    let qdrant_service = QdrantClientService::new(config.clone()).await?;
    let qdrant_service_arc = Arc::new(qdrant_service);
    tracing::info!("Qdrant client service initialized.");

    // --- Session Store Setup ---
    // Ideally load from config/env, generating is okay for dev
    let session_store = DieselSessionStore::new(pool.clone());

    // Use the signing key from the config
    let secret_key = config.cookie_signing_key
        .as_ref()
        .context("COOKIE_SIGNING_KEY must be set in config")?;
    let key_bytes =
        hex::decode(secret_key).context("Invalid COOKIE_SIGNING_KEY format in config (must be hex)")?;
    let cookie_signing_key = CookieKey::from(&key_bytes); // Keep the original variable name

    // Build the session manager layer (handles session data)
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(config.session_cookie_secure) // Use config value directly
        .with_same_site(SameSite::Lax)
        // Use with_signed to enable signed cookies with the key
        .with_signed(cookie_signing_key)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    // Configure the auth backend
    let auth_backend = AuthBackend::new(pool.clone());

    // Build the auth layer, passing the SessionManagerLayer
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer).build();

    // -- Create Chunking Config from main Config --
    let chunk_metric = match config.chunking_metric.to_lowercase().as_str() {
        "word" => ChunkingMetric::Word,
        "char" | _ => ChunkingMetric::Char, // Default to Char if invalid or not "word"
    };
    let chunk_config = ChunkConfig {
        metric: chunk_metric,
        max_size: config.chunking_max_size,
        overlap: config.chunking_overlap,
    };
    tracing::info!(?chunk_config, "Using chunking configuration");

    // -- Create Embedding Pipeline Service --
    let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(chunk_config))
        as Arc<dyn EmbeddingPipelineServiceTrait>; // Instantiate with config

    // -- Create AppState --
    let app_state = AppState::new(
        pool.clone(),
        config.clone(),
        ai_client_arc,
        embedding_client_arc,
        qdrant_service_arc,
        embedding_pipeline_service, // Add the embedding pipeline service
    );

    // --- Define Protected Routes ---
    let protected_api_routes = Router::new()
        // Character routes (require login)
        // TODO: Consolidate character route definition here instead of merging below?
        .nest(
            "/characters",
            Router::new()
                .route("/upload", post(upload_character_handler))
                .route("/", get(list_characters_handler))
                .route("/{id}", get(get_character_handler)),
        )
        // Chat routes (require login)
        .nest("/chats", chat_routes()) // Mount the chat router
        .nest("/chats-api", chats_api::chat_routes()) // Mount the old chats API router at a different path
        // Mount document API routes
        .merge(document_routes()) 
        // Add other protected API routes here...
        .route_layer(login_required!(AuthBackend)); // Apply login required, return 401 on failure

    // --- Define Public Routes ---
    let public_api_routes = Router::new()
        .route("/health", get(health_check)) // Use imported health_check
        .merge(Router::new().nest("/auth", auth_routes())); // Mount all auth routes

    // Combine routers and add layers
    let app = Router::new()
        // Mount API routes under /api
        .nest("/api", public_api_routes)
        .nest("/api", protected_api_routes) // Mount protected routes also under /api
        .layer(auth_layer) // Apply auth layer (handles session loading/user identification)
        // Apply cookie management layer *after* the auth layer if it needs access to session data set by auth
        // OR before if auth layer needs cookies set by it. Axum layers execute outside-in.
        // Usually CookieManagerLayer goes near the outside.
        .layer(CookieManagerLayer::new()) // Remove the key here
        .with_state(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    // Use port from config, default to 3000
    let port = config.port;
    let addr_str = format!("0.0.0.0:{}", port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address format");

    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
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

    // Comment out test requiring unavailable testcontainers module
    /*
    #[tokio::test]
    #[ignore] // Ignore by default as it requires Docker
    async fn test_migrations_with_testcontainer() -> Result<(), anyhow::Error> {
        let postgres_image = Postgres::default().with_user("test").with_password("test").with_db_name("test");
        let node = postgres_image.start().await?;
        let port = node.get_host_port_ipv4(5432).await?;
        let db_url = format!("postgres://test:test@localhost:{}/test", port);

        // Create a pool for the test database
        let manager = DeadpoolManager::new(&db_url, DeadpoolRuntime::Tokio1);
        let pool_config = PoolConfig::default();
        let test_pool: PgPool = DeadpoolPool::builder(manager)
            .config(pool_config)
            .runtime(DeadpoolRuntime::Tokio1)
            .build()
            .expect("Failed to create test DB pool.");

        // Run migrations against the test database
        let migration_result = run_migrations(&test_pool).await;

        assert!(migration_result.is_ok(), "Migrations failed to run: {:?}", migration_result.err());

        Ok(())
    }
    */
}
