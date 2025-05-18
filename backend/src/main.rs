use axum::{
    Router,
    routing::get, // Remove post
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
use anyhow::Context;
use anyhow::Result;
use scribe_backend::PgPool;
use scribe_backend::auth::session_store::DieselSessionStore;
use scribe_backend::auth::user_store::Backend as AuthBackend;
use scribe_backend::logging::init_subscriber;
use scribe_backend::routes::admin::admin_routes;
use scribe_backend::routes::auth::auth_routes;
use scribe_backend::routes::health::health_check;
use scribe_backend::routes::{
    characters::characters_router, // Use the router function import
    chat::chat_routes,
    chats,
    documents::document_routes,
};
use scribe_backend::state::AppState;

// Imports for axum-login and tower-sessions
use axum_login::{AuthManagerLayerBuilder, login_required}; // Modified
// Import SessionManagerLayer directly from tower_sessions
use hex; // Added for hex::decode
use scribe_backend::config::Config; // Import Config instead
use scribe_backend::llm::gemini_client::build_gemini_client; // Import the async builder
use scribe_backend::llm::gemini_embedding_client::build_gemini_embedding_client; // Add this
use scribe_backend::services::embedding_pipeline::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait,
};
use scribe_backend::services::gemini_token_client::GeminiTokenClient; // Added
use scribe_backend::services::hybrid_token_counter::HybridTokenCounter; // Added
use scribe_backend::services::tokenizer_service::TokenizerService; // Added
use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import chunking config structs
use scribe_backend::vector_db::QdrantClientService;
use std::sync::Arc;
use time; // Used for tower_sessions::Expiry
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use tower_sessions::cookie::Key; // Use Key from tower_sessions::cookie for with_signed
use tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite}; // Add Arc for config // Add Qdrant service import // Add embedding pipeline service import
// Removed unused: use tokio::net::TcpListener;
use axum_server::tls_rustls::RustlsConfig; // <-- ADD this
use rustls::crypto::ring;
use std::path::PathBuf; // <-- Add PathBuf import // <-- Import the ring provider module

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

// Removed custom rejection handler functions (handle_auth_rejection, handle_unauthorized_rejection)
// Relying on default axum_login::Error -> AppError conversion via From trait

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring) for rustls FIRST.
    // Get the default provider instance and then install it.
    let _ = ring::default_provider().install_default(); // Handle unused Result

    dotenvy::dotenv().ok();
    init_subscriber();

    tracing::info!("Starting Scribe backend server...");

    let config = Arc::new(Config::load().context("Failed to load configuration")?);
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

    // --- Initialize Tokenizer Service ---
    tracing::info!("Initializing TokenizerService...");
    let tokenizer_model_path = config
        .tokenizer_model_path
        .as_ref()
        .cloned()
        .context("Tokenizer model path not set in config")?;
    let tokenizer_service = TokenizerService::new(&tokenizer_model_path).context(format!(
        "Failed to load tokenizer model from {}",
        tokenizer_model_path
    ))?;
    tracing::info!(
        "TokenizerService initialized with model: {}",
        tokenizer_service.model_name()
    );

    // --- Initialize Gemini Token Client (Optional) ---
    let gemini_token_client = if let Some(api_key) = config.gemini_api_key.as_ref() {
        tracing::info!("Initializing GeminiTokenClient for token counting...");
        Some(GeminiTokenClient::new(api_key.clone()))
    } else {
        tracing::warn!(
            "GEMINI_API_KEY not set, GeminiTokenClient for token counting will not be available."
        );
        None
    };

    // --- Initialize Hybrid Token Counter ---
    tracing::info!("Initializing HybridTokenCounter...");
    let token_counter_default_model = config
        .token_counter_default_model
        .as_ref()
        .cloned()
        .context("Token counter default model not set in config")?;
    let hybrid_token_counter = HybridTokenCounter::new(
        tokenizer_service,
        gemini_token_client,
        token_counter_default_model.clone(),
    );
    let hybrid_token_counter_arc = Arc::new(hybrid_token_counter);
    tracing::info!(
        "HybridTokenCounter initialized with default model: {}",
        token_counter_default_model
    );

    // --- Session Store Setup ---
    // Ideally load from config/env, generating is okay for dev
    let session_store = DieselSessionStore::new(pool.clone());

    // Use the signing key from the config
    let secret_key = config
        .cookie_signing_key
        .as_ref()
        .context("COOKIE_SIGNING_KEY must be set in config")?;
    let key_bytes = hex::decode(secret_key)
        .context("Invalid COOKIE_SIGNING_KEY format in config (must be hex)")?;
    let _signing_key = Key::from(&key_bytes); // Key is now tower_sessions::cookie::Key (unused in current config)

    // Build the session manager layer (handles session data)
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(config.session_cookie_secure) // Use config value directly
        .with_same_site(SameSite::Lax)
        // .with_signed(signing_key.clone()) // CookieManagerLayer will handle signing
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    // Configure the auth backend
    let auth_backend = AuthBackend::new(pool.clone());

    // Build the auth layer, passing the SessionManagerLayer
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer.clone())
        // .with_login_key(SignedLoginKey::new(signing_key.clone())) // Removed: No longer part of axum-login API here
        .build();

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
        hybrid_token_counter_arc,   // Added
    );

    // --- Define Protected Routes ---
    let protected_api_routes = Router::new()
        // Character routes (require login)
        // Use the dedicated characters_router function
        .nest("/characters", characters_router(app_state.clone())) // Use the router function
        // Chat routes (require login)
        .nest("/chat", chat_routes(app_state.clone())) // Static chat generation routes
        .nest("/chats", chats::chat_routes()) // API routes for chat sessions - mounted at /api/chats
        // Mount document API routes
        .nest("/documents", document_routes()) // Corrected: /api/documents
        // Admin routes (require login + admin role check in handlers)
        .nest("/admin", admin_routes())
        .route_layer(login_required!(AuthBackend)); // Simplify macro: remove user type (i64)

    // --- Define Public Routes ---
    let public_api_routes = Router::new()
        .route("/health", get(health_check)) // Use imported health_check
        .merge(Router::new().nest("/auth", auth_routes())); // Mount all auth routes

    // Combine routers and add layers
    let app = Router::new()
        // Mount API routes under /api
        .nest("/api", public_api_routes) // public_api_routes should be defined to take AppState if its handlers need it.
        .nest("/api", protected_api_routes) // protected_api_routes now internally handle their state.
        // Apply layers: Order matters! Outside-in execution.
        .layer(CookieManagerLayer::new()) // 1. Manages cookies.
        .layer(auth_layer) // 2. Uses cookies (via CookieManagerLayer) to load session/user
        .with_state(app_state.clone()) // Keeping this for now, as public_api_routes (e.g. auth_routes) might rely on it.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        ); // 3. Tracing (often near the outside)

    // --- Configure TLS --- <-- Add TLS Config Block
    // Get the directory containing backend's Cargo.toml at compile time
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Navigate to project root (parent of backend dir)
    let project_root = manifest_dir
        .parent()
        .context("Failed to get project root from manifest dir")?;

    let cert_path = project_root.join(".certs/cert.pem");
    let key_path = project_root.join(".certs/key.pem");

    tracing::info!(cert_path = %cert_path.display(), key_path = %key_path.display(), "Loading TLS certificates");

    let tls_config = RustlsConfig::from_pem_file(
        cert_path, // Use the constructed path
        key_path,  // Use the constructed path
    )
    .await
    .context("Failed to load TLS certificate/key for Axum server")?;

    // Use port from config, default to 8080 (adjust if needed)
    let port = config.port;
    let addr_str = format!("0.0.0.0:{}", port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address format");

    tracing::info!("Starting HTTPS server on {}", addr);

    // --- Start HTTPS Server --- <-- Change server binding/serving
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("HTTPS server failed to start")?;

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
