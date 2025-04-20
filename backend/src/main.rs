use axum::{routing::{get, post}, Json, Router};
use deadpool_diesel::postgres::{Manager as DeadpoolManager, PoolConfig, Runtime as DeadpoolRuntime};
// Use the r2d2 Pool directly from deadpool_diesel
use deadpool_diesel::Pool as DeadpoolPool;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use serde::Serialize;
use std::env;
use std::net::SocketAddr;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

// Use modules from the library crate
use scribe_backend::logging::init_subscriber;
use scribe_backend::routes::characters::{get_character_handler, list_characters_handler, upload_character_handler};
use scribe_backend::routes::auth::{register_handler, login_handler, logout_handler, me_handler}; // Import auth handlers
use scribe_backend::state::AppState;
use scribe_backend::auth::session_store::DieselSessionStore; // Import DieselSessionStore
 // Import User model
use anyhow::Result;
use anyhow::Context;
use scribe_backend::auth::user_store::Backend as AuthBackend;
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

// Alias the specific Pool type we're using
pub type PgPool = DeadpoolPool<DeadpoolManager>;

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_subscriber();

    tracing::info!("Starting Scribe backend server...");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    tracing::info!("Connecting to database...");
    let manager = DeadpoolManager::new(database_url, DeadpoolRuntime::Tokio1);
    let pool_config = PoolConfig::default(); // Use default config for now
    let pool: PgPool = DeadpoolPool::builder(manager)
        .config(pool_config)
        .runtime(DeadpoolRuntime::Tokio1)
        .build()
        .expect("Failed to create DB pool.");
    tracing::info!("Database connection pool established.");

    run_migrations(&pool).await?; // Extract migration logic to function

    // --- Session Store Setup ---
    // Ideally load from config/env, generating is okay for dev
    let session_store = DieselSessionStore::new(pool.clone());

    // Generate a signing key for cookies
    let secret_key = env::var("COOKIE_SIGNING_KEY").expect("COOKIE_SIGNING_KEY must be set");
    let key_bytes = hex::decode(secret_key).context("Invalid COOKIE_SIGNING_KEY format (must be hex)")?;
    let _cookie_signing_key = CookieKey::from(&key_bytes);

    // Build the session manager layer (handles session data)
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Set based on env/config in production
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    // Build the signed cookie layer (handles cookie signing)
    // REMOVED: let signed_cookie_layer = SignedCookieLayer::new(cookie_signing_key.clone());

    // Note: AuthManagerLayerBuilder expects the SessionStore implementor.
    // tower-cookies layers need to be applied *outside* the auth layer usually.
    // Let's pass SessionManagerLayer to AuthManagerLayerBuilder and apply cookie layers later.

    // Configure the auth backend
    let auth_backend = AuthBackend::new(pool.clone());

    // Build the auth layer, passing the SessionManagerLayer
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer).build();

    // Create the AppState (needs to be defined before use)
    let app_state = AppState {
        pool: pool.clone(),
    };

    // Character routes (assuming they are protected)
    let characters_routes = Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler))
        .route("/{id}", get(get_character_handler))
        .route_layer(login_required!(AuthBackend, login_url = "/auth/login"));

    // Separate routers for protected and public routes
    let protected_routes = Router::new()
        .route("/api/auth/me", get(me_handler)) // Example protected route
        .route("/api/auth/logout", post(logout_handler))
        .route("/api/characters", get(list_characters_handler).post(upload_character_handler)) // Protect character routes
        .route("/api/characters/{id}", get(get_character_handler))
        // Add other protected routes here (chats, etc.)
        .merge(characters_routes);

    let public_routes = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler));

    // Combine routers and add layers
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(auth_layer)
        // Re-add explicit CookieManagerLayer
        .layer(CookieManagerLayer::new())
        // Potentially apply signed cookie layer here if needed separately?
        // Check axum-login examples for layer order with tower-cookies.
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

#[derive(Serialize)]
struct HealthStatus {
    status: String,
}

async fn health_check() -> Json<HealthStatus> {
    tracing::debug!("Health check endpoint called");
    Json(HealthStatus {
        status: "ok".to_string(),
    })
}

// --- Test module remains unchanged ---
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0.status, "ok");
    }
}
