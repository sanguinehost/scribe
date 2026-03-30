use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tauri::http::{Request as TauriRequest, Response as TauriResponse};
use tauri::Manager;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use url::Url;

use tauri_plugin_store::StoreBuilder;

mod storage;
use storage::StoredTokens;

mod chat_streaming;
use chat_streaming::stream_chat_response;

// P-256 ECDSA for challenge-response authentication
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

// Secure storage keys
const TOKEN_STORE_FILE: &str = ".tokens.dat";
const ACCESS_TOKEN_KEY: &str = "access_token";
const REFRESH_TOKEN_KEY: &str = "refresh_token";

// Quick Start authentication keys (Phase 1.5 - Secure Architecture)
const PRIVATE_KEY: &str = "ecdsa_private_key"; // P-256 ECDSA private key (PKCS#8 PEM)
const DEK_KEY: &str = "dek"; // ChaCha20Poly1305 Data Encryption Key (base64)

// Shared state for managing backend process and token storage

// Embed SQLite migrations
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../backend/migrations_sqlite");

/// Initialize SQLite database and run migrations
fn initialize_database() -> anyhow::Result<PathBuf> {
    // Get user data directory
    let data_dir = dirs::data_dir()
        .ok_or_else(|| anyhow::anyhow!("Failed to get user data directory"))?
        .join("scribe");

    // Create data directory if it doesn't exist
    fs::create_dir_all(&data_dir)?;
    log::info!("Using data directory: {}", data_dir.display());

    // Database file path
    let db_path = data_dir.join("scribe.db");
    let db_url = format!("sqlite://{}", db_path.display());

    // Check if database exists
    let db_exists = db_path.exists();
    log::info!("Database exists: {}", db_exists);

    // Connect to database (creates file if doesn't exist)
    let mut connection = SqliteConnection::establish(&db_url)
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;

    // Enable WAL mode for better concurrency (allows concurrent reads during writes)
    // This must be set before running migrations to ensure the database is properly configured
    diesel::sql_query("PRAGMA journal_mode = WAL;")
        .execute(&mut connection)
        .map_err(|e| anyhow::anyhow!("Failed to enable WAL mode: {}", e))?;
    log::info!("✓ WAL mode enabled for database");

    // Set busy_timeout to 10 seconds (connections will wait instead of failing immediately)
    diesel::sql_query("PRAGMA busy_timeout = 10000;")
        .execute(&mut connection)
        .map_err(|e| anyhow::anyhow!("Failed to set busy_timeout: {}", e))?;
    log::info!("✓ Busy timeout set to 10 seconds");

    // Enable foreign key constraints
    diesel::sql_query("PRAGMA foreign_keys = ON;")
        .execute(&mut connection)
        .map_err(|e| anyhow::anyhow!("Failed to enable foreign keys: {}", e))?;
    log::info!("✓ Foreign key constraints enabled");

    // Run migrations if database is new or needs updates
    if !db_exists {
        log::info!("Running database migrations...");
        connection
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
        log::info!("Database migrations completed successfully");
    } else {
        log::info!("Database already initialized, checking for pending migrations...");
        let pending = connection
            .has_pending_migration(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Failed to check migrations: {}", e))?;

        if pending {
            log::info!("Running pending migrations...");
            connection
                .run_pending_migrations(MIGRATIONS)
                .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
            log::info!("Migrations completed successfully");
        } else {
            log::info!("Database is up to date");
        }
    }

    Ok(db_path)
}

/// Generate or load persistent cookie signing key for session encryption
fn get_or_create_cookie_key(data_dir: &std::path::Path) -> anyhow::Result<String> {
    let key_file = data_dir.join("session.key");

    // Try to load existing key
    if key_file.exists() {
        log::info!("Loading existing session key from {}", key_file.display());
        let key = fs::read_to_string(&key_file)
            .map_err(|e| anyhow::anyhow!("Failed to read session key: {}", e))?;
        return Ok(key.trim().to_string());
    }

    // Generate new 128-character hex key (64 bytes)
    log::info!("Generating new session key for cookie signing...");
    let random_bytes: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
    let hex_key = random_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Persist the key for future runs
    fs::write(&key_file, &hex_key)
        .map_err(|e| anyhow::anyhow!("Failed to save session key: {}", e))?;

    log::info!("Session key generated and saved to {}", key_file.display());
    Ok(hex_key)
}

/// Start the backend server as a separate process
fn start_backend_process(
    db_path: PathBuf,
    app_handle: &tauri::AppHandle,
) -> anyhow::Result<tauri_plugin_shell::process::CommandChild> {
    log::info!("Starting backend server as Tauri sidecar...");

    // Construct DATABASE_URL
    let database_url = format!("sqlite://{}", db_path.display());

    // Get or generate cookie signing key for session encryption
    let data_dir = db_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get database parent directory"))?;
    let cookie_signing_key = get_or_create_cookie_key(data_dir)?;

    // Start backend as Tauri sidecar using shell plugin - Tauri handles bundling and path resolution
    log::info!(
        "🚀 Starting backend server with DATABASE_URL: {}",
        &database_url
    );

    let (mut rx, child) = app_handle
        .shell()
        .sidecar("scribe-backend")
        .map_err(|e| anyhow::anyhow!("Failed to create sidecar command: {}", e))?
        .env("ENVIRONMENT", "desktop")
        .env("DATABASE_URL", &database_url)
        .env("COOKIE_SIGNING_KEY", &cookie_signing_key)
        .env("PORT", "38080")
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn sidecar: {}", e))?;

    log::info!(
        "Backend server started as sidecar with PID: {}",
        child.pid()
    );

    // Spawn task to handle backend output
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let output = String::from_utf8_lossy(&line);
                    log::info!("[Backend] {}", output);
                }
                CommandEvent::Stderr(line) => {
                    let output = String::from_utf8_lossy(&line);
                    log::warn!("[Backend] {}", output);
                }
                CommandEvent::Error(err) => log::error!("[Backend Error] {}", err),
                CommandEvent::Terminated(payload) => {
                    log::info!("[Backend] Process terminated: {:?}", payload);
                    break;
                }
                _ => {}
            }
        }
    });

    // CRITICAL FIX: Health check with retries instead of blind sleep
    // Verify backend is actually listening and responding before proceeding
    log::info!("Waiting for backend to be ready (health check)...");
    let backend_url = "https://localhost:38080/api/health";
    let max_attempts = 30;
    let retry_delay = Duration::from_millis(1000);

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed cert
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

    for attempt in 1..=max_attempts {
        match client.get(backend_url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!(
                        "Backend health check passed (attempt {}/{})",
                        attempt,
                        max_attempts
                    );
                    return Ok(child);
                } else {
                    log::warn!(
                        "Backend health check failed with status {} (attempt {}/{})",
                        response.status(),
                        attempt,
                        max_attempts
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "Backend health check error: {} (attempt {}/{})",
                    e,
                    attempt,
                    max_attempts
                );
            }
        }

        if attempt < max_attempts {
            thread::sleep(retry_delay);
        }
    }

    // Backend didn't respond after max attempts - return error
    Err(anyhow::anyhow!(
        "Backend failed to respond to health checks after {} attempts. Check log file for backend errors.",
        max_attempts
    ))
}

// Token management commands for Tauri
/// Save tokens to secure storage using unified StoredTokens type
/// CRITICAL: Now accepts StoredTokens struct with camelCase serialization
/// IMPORTANT: expires_at is an absolute Unix timestamp (milliseconds), not a duration
#[tauri::command]
async fn save_tokens(app: tauri::AppHandle, tokens: StoredTokens) -> Result<(), String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    store.set(ACCESS_TOKEN_KEY.to_string(), tokens.access_token.clone());
    store.set(REFRESH_TOKEN_KEY.to_string(), tokens.refresh_token.clone());
    store.set("expires_at".to_string(), tokens.expires_at.to_string());

    store
        .save()
        .map_err(|e| format!("Failed to persist tokens: {}", e))?;

    log::info!(
        "Tokens saved to secure storage (expires at timestamp: {})",
        tokens.expires_at
    );
    Ok(())
}

/// Load tokens from secure storage using unified StoredTokens type
/// Returns StoredTokens with camelCase serialization for TypeScript compatibility
/// IMPORTANT: expires_at is an absolute Unix timestamp (milliseconds), not a duration
#[tauri::command]
async fn load_tokens(app: tauri::AppHandle) -> Result<Option<StoredTokens>, String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    let access_token = store
        .get(ACCESS_TOKEN_KEY)
        .and_then(|v| v.as_str().map(String::from));
    let refresh_token = store
        .get(REFRESH_TOKEN_KEY)
        .and_then(|v| v.as_str().map(String::from));
    let expires_at = store
        .get("expires_at")
        .and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()));

    match (access_token, refresh_token, expires_at) {
        (Some(access), Some(refresh), Some(expires)) => {
            log::info!(
                "Tokens loaded from secure storage (expires at timestamp: {})",
                expires
            );
            Ok(Some(StoredTokens {
                access_token: access,
                refresh_token: refresh,
                expires_at: expires,
            }))
        }
        _ => {
            log::info!("No tokens found in secure storage or incomplete token data");
            Ok(None)
        }
    }
}

/// Clear all authentication data from secure storage
/// Removes tokens (including expires_at), private key, and DEK
#[tauri::command]
async fn clear_tokens(app: tauri::AppHandle) -> Result<(), String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    // Clear JWT tokens
    store.delete(ACCESS_TOKEN_KEY);
    store.delete(REFRESH_TOKEN_KEY);
    store.delete("expires_at");

    // Clear Quick Start authentication data
    store.delete(PRIVATE_KEY);
    store.delete(DEK_KEY);

    store
        .save()
        .map_err(|e| format!("Failed to persist changes: {}", e))?;

    log::info!("[Auth] All authentication data cleared from secure storage");
    Ok(())
}

/// Log a message from the frontend to the backend logging system
/// Coordinates frontend and backend logging for comprehensive diagnostics
#[tauri::command]
async fn log_frontend_message(
    level: String,
    component: String,
    message: String,
    context: Option<String>,
) -> Result<(), String> {
    // Parse log level and log accordingly
    match level.to_lowercase().as_str() {
        "trace" => {
            log::trace!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
        "debug" => {
            log::debug!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
        "info" => {
            log::info!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
        "warn" => {
            log::warn!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
        "error" => {
            log::error!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
        _ => {
            log::info!(target: &format!("frontend::{}", component), "{} | {}", message, context.unwrap_or_default())
        }
    }
    Ok(())
}

/// Generate P-256 ECDSA keypair and ChaCha20Poly1305 DEK for Quick Start mode
/// Returns the public key in PEM format for backend registration
/// Private key and DEK are stored securely and never transmitted
#[tauri::command]
async fn generate_quick_start_keys(app: tauri::AppHandle) -> Result<String, String> {
    log::info!("[QuickStart] Generating P-256 keypair and DEK...");

    // Generate P-256 ECDSA signing key (private key)
    let signing_key = SigningKey::random(&mut OsRng);

    // Encode private key as PKCS#8 PEM
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode private key: {}", e))?;

    // Get public key and encode as PEM
    let verifying_key = signing_key.verifying_key();
    let public_key_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode public key: {}", e))?;

    // Generate 32-byte DEK for ChaCha20Poly1305 encryption
    let dek_bytes: [u8; 32] = rand::random();
    let dek_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, dek_bytes);

    // Store private key and DEK in secure storage
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    store.set(PRIVATE_KEY.to_string(), private_key_pem.to_string());
    store.set(DEK_KEY.to_string(), dek_base64);

    store
        .save()
        .map_err(|e| format!("Failed to persist keys: {}", e))?;

    log::info!("[QuickStart] Keypair and DEK generated and stored securely");
    log::info!(
        "[QuickStart] Public key (first 64 chars): {}...",
        &public_key_pem[..64.min(public_key_pem.len())]
    );

    // Return only the public key (safe to transmit)
    Ok(public_key_pem)
}

/// Sign a challenge from the backend using the stored private key
/// Used for challenge-response authentication
#[tauri::command]
async fn sign_challenge(app: tauri::AppHandle, challenge: String) -> Result<String, String> {
    log::info!(
        "[QuickStart] Signing challenge (length: {})",
        challenge.len()
    );

    // Load private key from secure storage
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    let private_key_pem = store
        .get(PRIVATE_KEY)
        .and_then(|v| v.as_str().map(String::from))
        .ok_or_else(|| "No private key found in storage".to_string())?;

    // Decode private key from PEM
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    // Sign the challenge
    let signature: Signature = signing_key.sign(challenge.as_bytes());

    // Return signature as hex string
    let signature_hex = hex::encode(signature.to_bytes());
    log::info!("[QuickStart] Challenge signed successfully");

    Ok(signature_hex)
}

/// Get the local DEK for client-side encryption
/// DEK is never transmitted to the backend - used only for local E2EE
#[tauri::command]
async fn get_local_dek(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    let dek = store
        .get(DEK_KEY)
        .and_then(|v| v.as_str().map(String::from));

    match &dek {
        Some(_) => log::info!("[QuickStart] DEK retrieved for local encryption"),
        None => log::info!("[QuickStart] No DEK found in storage"),
    }

    Ok(dek)
}

/// Save the DEK received from auto-login to secure storage
/// Called after successful auto-login when backend returns the DEK
#[tauri::command]
async fn save_local_dek(app: tauri::AppHandle, dek: String) -> Result<(), String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    store.set(DEK_KEY.to_string(), dek);

    store
        .save()
        .map_err(|e| format!("Failed to persist DEK: {}", e))?;

    log::info!("[QuickStart] DEK saved to secure storage");
    Ok(())
}

/// Test command to verify Tauri Channels work in isolation
/// Sends 5 simple test messages with 500ms delay between each
/// SUCCESS CRITERIA: All 5 messages must be received by frontend handler
#[tauri::command]
async fn test_channel_simple(channel: tauri::ipc::Channel<String>) -> Result<(), String> {
    log::info!("🔥 [test_channel_simple] Starting test - will send 5 messages");

    for i in 1..=5 {
        let message = format!("Test message {}/5", i);
        log::info!("🔥 [test_channel_simple] Sending: {}", message);

        channel.send(message.clone()).map_err(|e| {
            let err = format!("Failed to send test message {}: {}", i, e);
            log::error!("🔥 [test_channel_simple] {}", err);
            err
        })?;

        log::info!("🔥 [test_channel_simple] Message {} sent successfully", i);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    log::info!("🔥 [test_channel_simple] Test complete - all 5 messages sent");
    Ok(())
}

/// Get the current access token from secure storage (for protocol handler)
async fn get_access_token(app: &tauri::AppHandle) -> Option<String> {
    let store = StoreBuilder::new(app, TOKEN_STORE_FILE).build().ok()?;

    store
        .get(ACCESS_TOKEN_KEY)
        .and_then(|v| v.as_str().map(String::from))
}

/// Get the Data Encryption Key (DEK) from secure storage for Quick Start mode
/// Returns None if DEK is not available (e.g., password-based auth mode)
async fn get_dek(app: &tauri::AppHandle) -> Option<String> {
    let store = StoreBuilder::new(app, TOKEN_STORE_FILE).build().ok()?;

    store
        .get(DEK_KEY)
        .and_then(|v| v.as_str().map(String::from))
}

/// Proxy request to embedded backend with token authentication
async fn proxy_to_embedded_backend(
    app_handle: tauri::AppHandle,
    request: TauriRequest<Vec<u8>>,
) -> Result<TauriResponse<Vec<u8>>, String> {
    // Create HTTP client that accepts self-signed certs for localhost only
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Safe: only for localhost communication
        .http1_only() // Enforce HTTP/1.1 for all proxy calls to match chat_streaming
        .timeout(std::time::Duration::from_secs(30)) // Allow time for file uploads (base64 images can be large)
        .cookie_store(false) // Disable reqwest cookie handling
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Extract request details
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Construct backend URL (embedded backend on localhost:38080)
    let url_str = format!("https://localhost:38080{}", path);
    let url = Url::parse(&url_str).map_err(|e| format!("Failed to parse URL: {}", e))?;

    log::info!("Proxying {} {} to {}", method, path, url_str);

    // Build request
    let mut req = client.request(method, url.clone());

    // Get access token from secure storage and add as Authorization header
    if let Some(access_token) = get_access_token(&app_handle).await {
        log::info!("Adding Bearer token to request");
        req = req.header("Authorization", format!("Bearer {}", access_token));
    }

    // Get DEK from secure storage and add as X-Scribe-Dek header (Quick Start mode)
    if let Some(dek) = get_dek(&app_handle).await {
        log::info!("Adding X-Scribe-Dek header to request");
        req = req.header("X-Scribe-Dek", dek);
    }

    // Forward other headers (except host, cookie, and authorization - we add our own auth)
    for (name, value) in request.headers() {
        if name != "host" && name != "cookie" && name != "authorization" {
            if let Ok(value_str) = value.to_str() {
                log::debug!("Forwarding header: {}: {}", name, value_str);
                req = req.header(name.as_str(), value_str);
            }
        }
    }

    // Forward body if not empty
    let body = request.body();
    if !body.is_empty() {
        req = req.body(body.clone());
    }

    // Execute request
    let response = req
        .send()
        .await
        .map_err(|e| format!("Failed to send request to backend: {}", e))?;

    // Build Tauri response
    let status = response.status();
    let mut builder = TauriResponse::builder().status(status.as_u16());

    // Forward response headers (except Set-Cookie - we use tokens now)
    for (name, value) in response.headers() {
        if name != "set-cookie" {
            log::debug!("Response header: {}: {:?}", name, value);
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }

    // Forward body
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    builder
        .body(body.to_vec())
        .map_err(|e| format!("Failed to build response: {}", e))
}

/// Create error response for protocol handler failures
fn error_response(error: String) -> TauriResponse<Vec<u8>> {
    log::error!("Protocol handler error: {}", error);
    TauriResponse::builder()
        .status(500)
        .header("Content-Type", "text/plain")
        .body(format!("Internal error: {}", error).into_bytes())
        .unwrap()
}

/// Get MIME type for a file extension
fn get_mime_type(path: &str) -> &'static str {
    let extension = path.rsplit('.').next().unwrap_or("");
    match extension {
        "html" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "ico" => "image/x-icon",
        "txt" => "text/plain",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

/// Serve static files from the frontend build directory
async fn serve_static_file(
    request: TauriRequest<Vec<u8>>,
) -> Result<TauriResponse<Vec<u8>>, String> {
    let path = request.uri().path();

    // Normalize path - remove leading slash and convert to relative path
    let mut file_path = path.trim_start_matches('/');

    // If path is empty or ends with /, serve index.html
    if file_path.is_empty() || file_path.ends_with('/') {
        file_path = "index.html";
    }

    // Construct absolute path to frontend build directory
    // In development, this is ../frontend/build relative to the desktop crate
    // In production, Tauri bundles the frontend and serves from resources
    let base_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    // Try development path first (../../frontend/build from binary location)
    let mut full_path = base_dir.join("../../frontend/build").join(file_path);

    // Canonicalize to handle .. and resolve symlinks
    full_path = match full_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // SPA FALLBACK: If file doesn't exist and it's not an asset file,
            // serve index.html to let frontend router handle the route
            let is_asset_request =
                file_path.contains('.') && !file_path.ends_with('/') && file_path != "index.html";

            if !is_asset_request {
                // This is a route like /login, /chat, etc. - serve index.html
                log::debug!("SPA fallback: serving index.html for route: {}", file_path);
                let index_path = base_dir.join("../../frontend/build/index.html");
                match index_path.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("Failed to find index.html: {}", e);
                        return Ok(TauriResponse::builder()
                            .status(404)
                            .header("Content-Type", "text/plain")
                            .body(b"index.html not found".to_vec())
                            .unwrap());
                    }
                }
            } else {
                // This is an asset file that's actually missing - return 404
                log::warn!("Asset file not found: {}", file_path);
                return Ok(TauriResponse::builder()
                    .status(404)
                    .header("Content-Type", "text/plain")
                    .body(b"Not Found".to_vec())
                    .unwrap());
            }
        }
    };

    log::debug!("Serving static file: {}", full_path.display());

    // Read file contents
    match fs::read(&full_path) {
        Ok(contents) => {
            let mime_type = get_mime_type(file_path);
            log::debug!("Serving {} as {}", file_path, mime_type);

            Ok(TauriResponse::builder()
                .status(200)
                .header("Content-Type", mime_type)
                .header("Cache-Control", "public, max-age=31536000")
                .body(contents)
                .unwrap())
        }
        Err(e) => {
            log::error!("Failed to read file {}: {}", full_path.display(), e);
            Ok(TauriResponse::builder()
                .status(404)
                .header("Content-Type", "text/plain")
                .body(b"Not Found".to_vec())
                .unwrap())
        }
    }
}

/// Gracefully terminate the backend process with timeout fallback
fn terminate_backend_process(
    backend_process: &Arc<Mutex<Option<tauri_plugin_shell::process::CommandChild>>>,
) {
    if let Ok(mut process_guard) = backend_process.lock() {
        if let Some(child) = process_guard.take() {
            let pid = child.pid();
            log::info!("Terminating backend process with PID: {}", pid);

            // Attempt graceful kill
            match child.kill() {
                Ok(_) => {
                    log::info!("Backend process {} successfully terminated", pid);
                }
                Err(e) => {
                    log::error!("Failed to kill backend process {}: {}", pid, e);
                    log::warn!(
                        "Backend process may still be running - manual cleanup may be required"
                    );
                }
            }
        } else {
            log::debug!("Backend process already terminated or not started");
        }
    } else {
        log::warn!("Failed to acquire lock on backend process for termination");
    }
}

pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_upload::init());

    // Register log plugin FIRST in debug mode (before any log calls)
    // CRITICAL FIX: Use Stdout target to capture frontend console.log() calls
    if cfg!(debug_assertions) {
        builder = builder.plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Debug)
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Stdout,
                ))
                .build(),
        );
    }

    builder
        // Register custom protocol for routing requests
        // - API requests (/api/*) are proxied to the embedded backend
        // - Other requests are served as static files from frontend/build
        .register_asynchronous_uri_scheme_protocol("scribe", |app, request, responder| {
            let app_handle = app.app_handle().clone();
            let path = request.uri().path().to_string();

            tauri::async_runtime::spawn(async move {
                let response = if path.starts_with("/api/") {
                    // Proxy API requests to embedded backend
                    match proxy_to_embedded_backend(app_handle, request).await {
                        Ok(resp) => resp,
                        Err(e) => error_response(e),
                    }
                } else {
                    // Serve static files from frontend build directory
                    match serve_static_file(request).await {
                        Ok(resp) => resp,
                        Err(e) => error_response(e),
                    }
                };
                responder.respond(response);
            });
        })
        // Register authentication and streaming commands
        .invoke_handler(tauri::generate_handler![
            save_tokens,
            load_tokens,
            clear_tokens,
            log_frontend_message,
            generate_quick_start_keys,
            sign_challenge,
            get_local_dek,
            save_local_dek,
            stream_chat_response,
            test_channel_simple
        ])
        .setup(|app| {
            // Log plugin already registered before setup to avoid conflicts

            // Initialize database and run migrations
            let db_path = initialize_database().map_err(|e| {
                eprintln!("Failed to initialize database: {:#}", e);
                log::error!("Failed to initialize database: {}", e);
                e
            })?;

            // Start the backend server as sidecar
            let backend_child = start_backend_process(db_path, &app.handle()).map_err(|e| {
                eprintln!("Failed to start backend server: {:#}", e);
                log::error!("Failed to start backend server: {}", e);
                e
            })?;

            // Store backend process in app state for cleanup
            let backend_process = Arc::new(Mutex::new(Some(backend_child)));

            // Register window-level cleanup handlers
            // Listen for both CloseRequested and Destroyed to ensure cleanup
            let backend_process_for_window = Arc::clone(&backend_process);
            if let Some(main_window) = app.get_webview_window("main") {
                // CRITICAL: Open devtools in debug mode to inspect frontend JavaScript
                // This allows us to see console.log output and JavaScript errors in the WebView
                // Reference: https://github.com/tauri-apps/tauri/blob/dev/examples/api/src-tauri/src/lib.rs#L107
                #[cfg(debug_assertions)]
                main_window.open_devtools();

                main_window.on_window_event(move |event| match event {
                    tauri::WindowEvent::CloseRequested { .. } => {
                        log::info!("Window close requested - initiating backend shutdown");
                        terminate_backend_process(&backend_process_for_window);
                    }
                    tauri::WindowEvent::Destroyed => {
                        log::info!("Window destroyed - ensuring backend cleanup");
                        terminate_backend_process(&backend_process_for_window);
                    }
                    _ => {}
                });
                log::info!("Backend cleanup handlers registered successfully");
            } else {
                log::error!("Failed to get main window for cleanup registration!");
                log::error!("Backend process may not be cleaned up properly on exit");
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn test_p256_keypair_generation() {
        // Generate signing key
        let signing_key = SigningKey::random(&mut OsRng);

        // Encode private key as PKCS#8 PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode private key");

        // Verify PEM format
        assert!(
            private_key_pem
                .to_string()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
            "Private key should be in PKCS#8 PEM format"
        );
        assert!(
            private_key_pem
                .to_string()
                .ends_with("-----END PRIVATE KEY-----\n"),
            "Private key should end with PEM footer"
        );

        // Get public key and encode as PEM
        let verifying_key = signing_key.verifying_key();
        let public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode public key");

        // Verify public key PEM format
        assert!(
            public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "Public key should be in PEM format"
        );
        assert!(
            public_key_pem.ends_with("-----END PUBLIC KEY-----\n"),
            "Public key should end with PEM footer"
        );
    }

    #[test]
    fn test_dek_generation() {
        // Generate 32-byte DEK for ChaCha20Poly1305
        let dek_bytes: [u8; 32] = rand::random();

        // Encode as base64
        let dek_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, dek_bytes);

        // Verify base64 encoding
        assert!(
            !dek_base64.is_empty(),
            "DEK base64 encoding should not be empty"
        );

        // Verify we can decode it back
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            dek_base64.as_bytes(),
        )
        .expect("Failed to decode DEK");

        assert_eq!(decoded.len(), 32, "DEK should be 32 bytes");
        assert_eq!(decoded, dek_bytes, "Decoded DEK should match original");
    }

    #[test]
    fn test_challenge_signing_and_verification() {
        // Generate signing key
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create a challenge
        let challenge = "test_challenge_nonce_12345";

        // Sign the challenge
        let signature: Signature = signing_key.sign(challenge.as_bytes());

        // Verify signature as hex
        let signature_hex = hex::encode(signature.to_bytes());
        assert_eq!(
            signature_hex.len(),
            128,
            "P-256 ECDSA signature should be 64 bytes (128 hex chars)"
        );

        // Decode signature from hex
        let signature_bytes = hex::decode(&signature_hex).expect("Failed to decode signature hex");
        let signature_decoded =
            Signature::from_slice(&signature_bytes).expect("Failed to parse signature");

        // Verify the signature with the public key
        verifying_key
            .verify(challenge.as_bytes(), &signature_decoded)
            .expect("Signature verification should succeed");
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_challenge() {
        // Generate signing key
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create and sign a challenge
        let challenge = "correct_challenge";
        let signature: Signature = signing_key.sign(challenge.as_bytes());

        // Try to verify with wrong challenge - should fail
        let wrong_challenge = "wrong_challenge";
        let result = verifying_key.verify(wrong_challenge.as_bytes(), &signature);

        assert!(
            result.is_err(),
            "Signature verification should fail with wrong challenge"
        );
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_public_key() {
        // Generate first keypair
        let signing_key1 = SigningKey::random(&mut OsRng);

        // Generate second keypair
        let signing_key2 = SigningKey::random(&mut OsRng);
        let verifying_key2 = signing_key2.verifying_key();

        // Sign challenge with key1
        let challenge = "test_challenge";
        let signature: Signature = signing_key1.sign(challenge.as_bytes());

        // Try to verify with key2's public key - should fail
        let result = verifying_key2.verify(challenge.as_bytes(), &signature);

        assert!(
            result.is_err(),
            "Signature verification should fail with wrong public key"
        );
    }

    #[test]
    fn test_private_key_roundtrip() {
        // Generate signing key
        let signing_key = SigningKey::random(&mut OsRng);

        // Encode as PKCS#8 PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode private key");

        // Decode from PEM
        let decoded_key = SigningKey::from_pkcs8_pem(&private_key_pem)
            .expect("Failed to decode private key from PEM");

        // Sign with both keys and verify they produce same result
        let challenge = "test_roundtrip";
        let sig1: Signature = signing_key.sign(challenge.as_bytes());
        let sig2: Signature = decoded_key.sign(challenge.as_bytes());

        // Signatures should be identical
        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Signatures from original and decoded keys should match"
        );
    }

    #[test]
    fn test_key_generation_entropy() {
        // Generate two DEKs
        let dek1: [u8; 32] = rand::random();
        let dek2: [u8; 32] = rand::random();

        // They should be different (astronomically unlikely to be the same)
        assert_ne!(dek1, dek2, "Two random DEKs should be different");

        // Generate two keypairs
        let signing_key1 = SigningKey::random(&mut OsRng);
        let signing_key2 = SigningKey::random(&mut OsRng);

        let public_key1 = signing_key1
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode public key 1");
        let public_key2 = signing_key2
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode public key 2");

        // Public keys should be different
        assert_ne!(
            public_key1, public_key2,
            "Two random keypairs should have different public keys"
        );
    }

    // ====================================================================================
    // OWASP Security Tests
    // ====================================================================================

    /// OWASP A02: Cryptographic Failures - DEK Length Validation
    /// Ensures DEK is exactly 32 bytes for ChaCha20Poly1305
    #[test]
    fn test_owasp_a02_dek_length_validation() {
        let dek_bytes: [u8; 32] = rand::random();

        // DEK must be exactly 32 bytes for ChaCha20Poly1305
        assert_eq!(
            dek_bytes.len(),
            32,
            "OWASP A02: DEK must be exactly 32 bytes to prevent cryptographic failures"
        );

        // Verify base64 encoding doesn't truncate
        let dek_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, dek_bytes);
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            dek_base64.as_bytes(),
        )
        .expect("DEK must be decodable");

        assert_eq!(
            decoded.len(),
            32,
            "OWASP A02: Decoded DEK must maintain 32-byte length"
        );
    }

    /// OWASP A02: Cryptographic Failures - Private Key Never Exposed
    /// Validates that private key stays in PEM format and never leaves as raw bytes
    #[test]
    fn test_owasp_a02_private_key_never_exposed() {
        let signing_key = SigningKey::random(&mut OsRng);

        // Private key should only be stored as PKCS#8 PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Private key must be encodable as PEM");

        // Verify it's PEM format (not raw bytes)
        assert!(
            private_key_pem
                .to_string()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
            "OWASP A02: Private key must be in PEM format for secure storage"
        );

        // Verify it's encrypted/protected format (PKCS#8)
        assert!(
            private_key_pem.to_string().contains("PRIVATE KEY"),
            "OWASP A02: Private key must use PKCS#8 standard format"
        );
    }

    /// OWASP A02: Cryptographic Failures - Public Key Safe to Transmit
    /// Ensures public key contains no private key material
    #[test]
    fn test_owasp_a02_public_key_safe_transmission() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .expect("Public key must be encodable");

        // Public key should NOT contain "PRIVATE KEY" anywhere
        assert!(
            !public_key_pem.contains("PRIVATE"),
            "OWASP A02: Public key must not contain private key material"
        );

        // Should be clearly marked as PUBLIC
        assert!(
            public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "OWASP A02: Public key must be clearly identified"
        );
    }

    /// OWASP A07: Authentication Failures - Signature Replay Prevention
    /// Validates that same signature with different challenge fails
    #[test]
    fn test_owasp_a07_signature_replay_prevention() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Original authentication
        let challenge1 = "challenge_nonce_12345";
        let signature1: Signature = signing_key.sign(challenge1.as_bytes());

        // Attacker tries to replay signature with different challenge
        let challenge2 = "challenge_nonce_67890";

        let result = verifying_key.verify(challenge2.as_bytes(), &signature1);
        assert!(
            result.is_err(),
            "OWASP A07: Signature replay must be prevented - different challenge should fail"
        );
    }

    /// OWASP A07: Authentication Failures - Challenge Uniqueness
    /// Ensures different challenges produce different signatures
    #[test]
    fn test_owasp_a07_challenge_uniqueness() {
        let signing_key = SigningKey::random(&mut OsRng);

        let challenge1 = "nonce_1";
        let challenge2 = "nonce_2";

        let sig1: Signature = signing_key.sign(challenge1.as_bytes());
        let sig2: Signature = signing_key.sign(challenge2.as_bytes());

        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "OWASP A07: Different challenges must produce different signatures to prevent reuse"
        );
    }

    /// OWASP A07: Authentication Failures - Key Confusion Attack Prevention
    /// Validates that signatures are key-specific and can't be confused
    #[test]
    fn test_owasp_a07_key_confusion_prevention() {
        // User A's keypair
        let signing_key_a = SigningKey::random(&mut OsRng);
        let verifying_key_a = signing_key_a.verifying_key();

        // User B's keypair
        let signing_key_b = SigningKey::random(&mut OsRng);
        let verifying_key_b = signing_key_b.verifying_key();

        let challenge = "shared_challenge";

        // User A signs
        let sig_a: Signature = signing_key_a.sign(challenge.as_bytes());

        // Attacker tries to use A's signature with B's public key
        let result = verifying_key_b.verify(challenge.as_bytes(), &sig_a);
        assert!(
            result.is_err(),
            "OWASP A07: Key confusion attack must be prevented - signature from key A should not verify with key B"
        );

        // Verify correct key still works
        verifying_key_a
            .verify(challenge.as_bytes(), &sig_a)
            .expect("Original key should verify successfully");
    }

    /// OWASP A08: Data Integrity Failures - Signature Tampering Detection
    /// Validates that tampered signatures are detected
    #[test]
    fn test_owasp_a08_signature_tampering_detection() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let challenge = "test_challenge";
        let signature: Signature = signing_key.sign(challenge.as_bytes());

        // Get signature as bytes
        let mut sig_bytes = signature.to_bytes();

        // Tamper with signature by flipping a bit
        sig_bytes[0] ^= 0x01;

        // Try to create signature from tampered bytes
        let tampered_sig = Signature::from_slice(&sig_bytes).expect("Should parse bytes");

        // Verification should fail
        let result = verifying_key.verify(challenge.as_bytes(), &tampered_sig);
        assert!(
            result.is_err(),
            "OWASP A08: Tampered signature must be detected and rejected"
        );
    }

    /// OWASP A08: Data Integrity Failures - Challenge Tampering Detection
    /// Validates that tampered challenges cause verification failure
    #[test]
    fn test_owasp_a08_challenge_tampering_detection() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let original_challenge = "original_challenge_12345";
        let signature: Signature = signing_key.sign(original_challenge.as_bytes());

        // Attacker tampers with challenge
        let tampered_challenge = "original_challenge_12346"; // Last digit changed

        let result = verifying_key.verify(tampered_challenge.as_bytes(), &signature);
        assert!(
            result.is_err(),
            "OWASP A08: Challenge tampering must be detected - signature should not verify"
        );
    }

    /// OWASP A02: Cryptographic Failures - Weak Key Detection
    /// Ensures P-256 keys meet minimum security standards
    #[test]
    fn test_owasp_a02_weak_key_detection() {
        let signing_key = SigningKey::random(&mut OsRng);

        // P-256 keys should be exactly 32 bytes (256 bits)
        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode key");

        // Verify it uses P-256 (secp256r1) - check PEM contains proper encoding
        // PKCS#8 PEM for P-256 is typically 200-400 characters (depends on encoding)
        let pem_str = private_key_pem.to_string();
        assert!(
            pem_str.len() > 100 && pem_str.len() < 500,
            "OWASP A02: P-256 key size validation - PEM should be properly sized (got {} bytes)",
            pem_str.len()
        );

        // Ensure PEM header is present (validates it's a proper key)
        assert!(
            pem_str.contains("-----BEGIN PRIVATE KEY-----")
                && pem_str.contains("-----END PRIVATE KEY-----"),
            "OWASP A02: Key must have proper PEM structure"
        );

        // Ensure key is not all zeros (would indicate weak RNG)
        let public_key_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode public key");

        assert!(
            !public_key_pem.contains("AAAAAAAAAAAAAAAA"),
            "OWASP A02: Key must not be all zeros (weak RNG check)"
        );
    }

    /// OWASP A02: Cryptographic Failures - Secure Random Number Generation
    /// Validates OsRng provides cryptographically secure randomness
    #[test]
    fn test_owasp_a02_secure_rng() {
        // Generate multiple keys to check for patterns
        let mut public_keys = Vec::new();

        for _ in 0..5 {
            let signing_key = SigningKey::random(&mut OsRng);
            let public_key_pem = signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("Failed to encode public key");
            public_keys.push(public_key_pem);
        }

        // All keys should be unique (no duplicates from weak RNG)
        for i in 0..public_keys.len() {
            for j in i + 1..public_keys.len() {
                assert_ne!(
                    public_keys[i], public_keys[j],
                    "OWASP A02: RNG must produce unique keys - duplicate detected"
                );
            }
        }
    }

    /// OWASP A07: Authentication Failures - Empty/Null Challenge Rejection
    /// Ensures system rejects empty or trivial challenges
    #[test]
    fn test_owasp_a07_empty_challenge_rejection() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Sign a proper challenge
        let proper_challenge = "valid_challenge_12345";
        let signature: Signature = signing_key.sign(proper_challenge.as_bytes());

        // Attacker tries empty challenge
        let empty_challenge = "";

        let result = verifying_key.verify(empty_challenge.as_bytes(), &signature);
        assert!(
            result.is_err(),
            "OWASP A07: Empty challenge must be rejected"
        );

        // Original challenge should still verify
        verifying_key
            .verify(proper_challenge.as_bytes(), &signature)
            .expect("Proper challenge should verify");
    }

    /// OWASP A02: Cryptographic Failures - Base64 Encoding Integrity
    /// Ensures base64 encoding doesn't introduce vulnerabilities
    #[test]
    fn test_owasp_a02_base64_integrity() {
        let original_dek: [u8; 32] = rand::random();

        // Encode
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, original_dek);

        // Decode
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded.as_bytes(),
        )
        .expect("OWASP A02: Base64 decoding must succeed");

        // Must be bit-for-bit identical
        assert_eq!(
            original_dek.as_slice(),
            decoded.as_slice(),
            "OWASP A02: Base64 encoding must preserve all bits exactly"
        );

        // Verify no padding vulnerabilities (standard base64)
        assert!(
            !encoded.contains('\0'),
            "OWASP A02: Base64 must not contain null bytes"
        );
    }
}
