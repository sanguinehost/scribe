use axum::{routing::{get, post}, Router};
use deadpool_diesel::postgres::{Manager as DeadpoolManager, PoolConfig, Runtime as DeadpoolRuntime};
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::env;
use std::net::SocketAddr;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

// Use modules from the library crate
use scribe_backend::logging::init_subscriber;
use scribe_backend::routes::{chat::chat_routes, characters::{get_character_handler, list_characters_handler, upload_character_handler}};
use scribe_backend::routes::auth::{register_handler, login_handler, logout_handler, me_handler}; // Import auth handlers
use scribe_backend::routes::health::health_check; // Import from new location
use scribe_backend::state::AppState;
use scribe_backend::auth::session_store::DieselSessionStore; // Import DieselSessionStore
 // Import User model
use anyhow::Result;
use anyhow::Context;
use scribe_backend::auth::user_store::Backend as AuthBackend;
// Import PgPool from the library crate
use scribe_backend::PgPool;
 // Make sure AppError is in scope

// Imports for axum-login and tower-sessions
use axum_login::{
    login_required,
    AuthManagerLayerBuilder,
};
// Import SessionManagerLayer directly from tower_sessions
use tower_sessions::{
    cookie::SameSite,
    Expiry,
    SessionManagerLayer,
};
use cookie::Key as CookieKey; // Re-add for signing key variable
use tower_cookies::CookieManagerLayer; // Re-add CookieManagerLayer
use time; // Used for tower_sessions::Expiry
use hex; // Added for hex::decode
use scribe_backend::config::Config; // Import Config instead
use std::sync::Arc; // Add Arc for config
// Import the builder function
use scribe_backend::llm::gemini_client::build_gemini_client; // Import the async builder

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    init_subscriber();

    tracing::info!("Starting Scribe backend server...");

    let config = Arc::new(Config::load().expect("Failed to load configuration")); // Load Config into Arc
    let db_url = config.database_url.as_ref().expect("DATABASE_URL not set in config");
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
    let ai_client = build_gemini_client()
        .await?;
    let ai_client_arc = Arc::new(ai_client); // Wrap in Arc for AppState

    // --- Session Store Setup ---
    // Ideally load from config/env, generating is okay for dev
    let session_store = DieselSessionStore::new(pool.clone());

    // Generate a signing key for cookies
    let secret_key = env::var("COOKIE_SIGNING_KEY").expect("COOKIE_SIGNING_KEY must be set");
    let key_bytes = hex::decode(secret_key).context("Invalid COOKIE_SIGNING_KEY format (must be hex)")?;
    let _cookie_signing_key = CookieKey::from(&key_bytes); // Renamed variable for clarity

    // Build the session manager layer (handles session data)
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Set based on env/config in production
        .with_same_site(SameSite::Lax)
        // .with_signing_key(cookie_signing_key.clone()) // REMOVED: Signing is handled by CookieManagerLayer now
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));


    // Configure the auth backend
    let auth_backend = AuthBackend::new(pool.clone());

    // Build the auth layer, passing the SessionManagerLayer
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer).build();

    // Create AppState - pass the initialized AI client Arc
    let app_state = AppState::new(pool.clone(), config.clone(), ai_client_arc); // Pass Arc<GenAiClient>

    // --- Define Protected Routes ---
    let protected_api_routes = Router::new()
        // Authentication routes (require login)
        .route("/auth/me", get(me_handler))
        .route("/auth/logout", post(logout_handler))
        // Character routes (require login)
        // TODO: Consolidate character route definition here instead of merging below?
        .nest("/characters", 
            Router::new()
                .route("/upload", post(upload_character_handler))
                .route("/", get(list_characters_handler))
                .route("/{id}", get(get_character_handler))
        )
        // Chat routes (require login)
        .nest("/chats", chat_routes()) // Mount the chat router
        // Add other protected API routes here...
        .route_layer(login_required!(AuthBackend)); // Apply login required, return 401 on failure

    // --- Define Public Routes ---
    let public_api_routes = Router::new()
        .route("/health", get(health_check)) // Use imported health_check
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler));

    // Combine routers and add layers
    let app = Router::new()
        // Mount API routes under /api
        .nest("/api", public_api_routes)
        .nest("/api", protected_api_routes) // Mount protected routes also under /api
        .layer(auth_layer) // Apply auth layer (handles session loading/user identification)
        // Apply cookie management layer *after* the auth layer if it needs access to session data set by auth
        // OR before if auth layer needs cookies set by it. Axum layers execute outside-in.
        // Usually CookieManagerLayer goes near the outside.
        .layer(CookieManagerLayer::new())
        .with_state(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
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
    let conn = pool.get().await.map_err(|e| anyhow::anyhow!("Failed to get connection for migration: {}", e))?;
    conn.interact(|conn| {
        match conn.run_pending_migrations(MIGRATIONS) {
            Ok(versions) => {
                if versions.is_empty() {
                    tracing::info!("No pending migrations found.");
                } else {
                    tracing::info!("Successfully ran migrations: {:?}", versions);
                }
                Ok(())
            },
            Err(e) => {
                tracing::error!("Failed to run database migrations: {:?}", e);
                Err(anyhow::anyhow!("Migration diesel error: {:?}", e))
            }
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
     // Needed for Result<()> in main

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0.status, "ok");
    }
}
