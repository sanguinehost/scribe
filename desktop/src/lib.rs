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

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri_plugin_store::StoreBuilder;

// Token storage keys
const TOKEN_STORE_FILE: &str = ".tokens.dat";
const ACCESS_TOKEN_KEY: &str = "access_token";
const REFRESH_TOKEN_KEY: &str = "refresh_token";

// Shared state for managing backend process and token storage

// Shared state for managing backend process
struct BackendProcess(Arc<Mutex<Option<tauri_plugin_shell::process::CommandChild>>>);

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
    let hex_key = random_bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Persist the key for future runs
    fs::write(&key_file, &hex_key)
        .map_err(|e| anyhow::anyhow!("Failed to save session key: {}", e))?;

    log::info!("Session key generated and saved to {}", key_file.display());
    Ok(hex_key)
}

/// Start the backend server as a separate process
fn start_backend_process(db_path: PathBuf, app_handle: &tauri::AppHandle) -> anyhow::Result<tauri_plugin_shell::process::CommandChild> {
    log::info!("Starting backend server as Tauri sidecar...");

    // Construct DATABASE_URL
    let database_url = format!("sqlite://{}", db_path.display());

    // Get or generate cookie signing key for session encryption
    let data_dir = db_path.parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get database parent directory"))?;
    let cookie_signing_key = get_or_create_cookie_key(data_dir)?;

    // Start backend as Tauri sidecar using shell plugin - Tauri handles bundling and path resolution
    let (mut rx, child) = app_handle
        .shell()
        .sidecar("scribe-backend")
        .map_err(|e| anyhow::anyhow!("Failed to create sidecar command: {}", e))?
        .env("ENVIRONMENT", "desktop")
        .env("DATABASE_URL", &database_url)
        .env("COOKIE_SIGNING_KEY", &cookie_signing_key)
        .env("PORT", "38080")
        .env("RUST_LOG", "info")
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn sidecar: {}", e))?;

    log::info!("Backend server started as sidecar with PID: {}", child.pid());

    // Spawn task to handle backend output
    let app_handle_clone = app_handle.clone();
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

    // Give the backend a moment to start listening
    thread::sleep(Duration::from_secs(3));

    Ok(child)
}

// Token management commands for Tauri
#[derive(Debug, Serialize, Deserialize)]
struct TokenPair {
    access_token: String,
    refresh_token: String,
}

/// Save tokens to secure storage
#[tauri::command]
async fn save_tokens(
    app: tauri::AppHandle,
    access_token: String,
    refresh_token: String,
) -> Result<(), String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    store
        .set(ACCESS_TOKEN_KEY.to_string(), access_token.into())
        .map_err(|e| format!("Failed to save access token: {}", e))?;
    
    store
        .set(REFRESH_TOKEN_KEY.to_string(), refresh_token.into())
        .map_err(|e| format!("Failed to save refresh token: {}", e))?;

    store.save().map_err(|e| format!("Failed to persist tokens: {}", e))?;
    
    log::info!("Tokens saved to secure storage");
    Ok(())
}

/// Load tokens from secure storage
#[tauri::command]
async fn load_tokens(app: tauri::AppHandle) -> Result<Option<TokenPair>, String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    let access_token = store.get(ACCESS_TOKEN_KEY).and_then(|v| v.as_str().map(String::from));
    let refresh_token = store.get(REFRESH_TOKEN_KEY).and_then(|v| v.as_str().map(String::from));

    match (access_token, refresh_token) {
        (Some(access), Some(refresh)) => {
            log::info!("Tokens loaded from secure storage");
            Ok(Some(TokenPair {
                access_token: access,
                refresh_token: refresh,
            }))
        }
        _ => {
            log::info!("No tokens found in secure storage");
            Ok(None)
        }
    }
}

/// Clear tokens from secure storage
#[tauri::command]
async fn clear_tokens(app: tauri::AppHandle) -> Result<(), String> {
    let store = StoreBuilder::new(&app, TOKEN_STORE_FILE)
        .build()
        .map_err(|e| format!("Failed to build store: {}", e))?;

    store.delete(ACCESS_TOKEN_KEY)
        .map_err(|e| format!("Failed to delete access token: {}", e))?;
    
    store.delete(REFRESH_TOKEN_KEY)
        .map_err(|e| format!("Failed to delete refresh token: {}", e))?;

    store.save().map_err(|e| format!("Failed to persist changes: {}", e))?;
    
    log::info!("Tokens cleared from secure storage");
    Ok(())
}

/// Get the current access token from secure storage (for protocol handler)
async fn get_access_token(app: &tauri::AppHandle) -> Option<String> {
    let store = StoreBuilder::new(app, TOKEN_STORE_FILE)
        .build()
        .ok()?;

    store.get(ACCESS_TOKEN_KEY)
        .and_then(|v| v.as_str().map(String::from))
}

/// Proxy request to embedded backend with token authentication
async fn proxy_to_embedded_backend(
    app_handle: tauri::AppHandle,
    request: TauriRequest<Vec<u8>>
) -> Result<TauriResponse<Vec<u8>>, String> {
    // Create HTTP client that accepts self-signed certs for localhost only
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)  // Safe: only for localhost communication
        .timeout(std::time::Duration::from_secs(30))
        .cookie_store(false)  // Disable reqwest cookie handling
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Extract request details
    let method = request.method().clone();
    let path = request.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Construct backend URL (embedded backend on localhost:38080)
    let url_str = format!("https://localhost:38080{}", path);
    let url = Url::parse(&url_str)
        .map_err(|e| format!("Failed to parse URL: {}", e))?;

    log::info!("Proxying {} {} to {}", method, path, url_str);

    // Build request
    let mut req = client.request(method, url.clone());

    // Get access token from secure storage and add as Authorization header
    if let Some(access_token) = get_access_token(&app_handle).await {
        log::info!("Adding Bearer token to request");
        req = req.header("Authorization", format!("Bearer {}", access_token));
    }

    // Forward other headers (except host and cookie - we use tokens now)
    for (name, value) in request.headers() {
        if name != "host" && name != "cookie" {
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
    let response = req.send().await
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
    let body = response.bytes().await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    builder.body(body.to_vec())
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        // Register custom protocol for proxying to embedded backend
        // This allows the WebView to connect without certificate validation issues
        .register_asynchronous_uri_scheme_protocol("scribe", |app, request, responder| {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let response = match proxy_to_embedded_backend(app_handle, request).await {
                    Ok(resp) => resp,
                    Err(e) => error_response(e),
                };
                responder.respond(response);
            });
        })
        // Register token management commands
        .invoke_handler(tauri::generate_handler![
            save_tokens,
            load_tokens,
            clear_tokens
        ])
        .setup(|app| {
            // Setup logging
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Initialize database and run migrations
            let db_path = initialize_database()
                .map_err(|e| {
                    eprintln!("Failed to initialize database: {:#}", e);
                    log::error!("Failed to initialize database: {}", e);
                    e
                })?;

            // Start the backend server as sidecar
            let backend_child = start_backend_process(db_path, &app.handle())
                .map_err(|e| {
                    eprintln!("Failed to start backend server: {:#}", e);
                    log::error!("Failed to start backend server: {}", e);
                    e
                })?;

            // Store backend process in app state for cleanup
            let backend_process = Arc::new(Mutex::new(Some(backend_child)));
            app.manage(BackendProcess(Arc::clone(&backend_process)));

            // Register cleanup handler on window close
            let backend_process_clone = Arc::clone(&backend_process);
            let main_window = app.get_webview_window("main").expect("Failed to get main window");
            main_window.on_window_event(move |event| {
                if let tauri::WindowEvent::Destroyed = event {
                    log::info!("Window destroyed, killing backend server...");
                    if let Ok(mut process_guard) = backend_process_clone.lock() {
                        if let Some(mut child) = process_guard.take() {
                            log::info!("Killing backend process with PID: {}", child.pid());
                            let _ = child.kill();
                            log::info!("Backend server terminated");
                        }
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
