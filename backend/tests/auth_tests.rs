#![cfg(test)]
// backend/tests/auth_tests.rs

// --- Imports (similar to characters_tests, but focused on auth) ---
use scribe_backend::{
    auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend},
    errors::AppError,
    models::{users::User, users::NewUser}, // Import NewUser
    routes::auth::{login_handler, register_handler, logout_handler, me_handler},
    schema::users,
    state::AppState,
    config::Config,
};
use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post, routing::get, // Add get for /me route
    Router,
};
use axum_login::{
    tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite},
    AuthManagerLayerBuilder,
};
use bcrypt; // For direct verification if needed, though backend handles it
use deadpool_diesel::{
    postgres::Manager as DeadpoolManager,
    Pool as DeadpoolPool,
    Runtime as DeadpoolRuntime,
};
use diesel::{prelude::*, PgConnection};
use dotenvy;
use http_body_util::BodyExt;
use serde::de::DeserializeOwned; // For get_json_body
use serde_json::{json, Value};
use std::{
    env,
    sync::Once, 
    sync::Arc,
};
use time;
use tower::ServiceExt; // For `oneshot`
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tracing_subscriber::{EnvFilter, fmt}; // For tracing setup
use uuid::Uuid;
use tracing::{info, error, instrument};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use reqwest::Client;
use http::header::SET_COOKIE;
// Remove unused AuthUser
// use axum_login::{ AuthUser };
// Remove unused MemoryStore
// use tower_sessions::MemoryStore;

// --- Test Helpers (Copied/Adapted from characters_tests.rs) ---

// Global static for ensuring tracing is initialized only once
static TRACING_INIT: Once = Once::new();

// Helper function to initialize tracing safely (respecting RUST_LOG)
fn ensure_tracing_initialized() {
    TRACING_INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "scribe_backend=info,tower_http=info,sqlx=warn".into()); // Default filter
        fmt()
            .with_env_filter(filter)
            // .with_test_writer() // Optional: use test writer
            .try_init()
            .ok(); // Ignore error if already initialized
    });
}

// Helper function to extract JSON body from response
async fn get_json_body<T: DeserializeOwned>(
    response: Response<Body>,
) -> AnyhowResult<(StatusCode, T)> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let json_body: T = serde_json::from_slice(&body_bytes)
        .with_context(|| {
            format!(
                "Failed to deserialize JSON body. Status: {}. Body: {}",
                status,
                String::from_utf8_lossy(&body_bytes)
            )
        })?;
    Ok((status, json_body))
}

// Helper to create a deadpool pool
fn create_test_pool() -> DeadpoolPool<DeadpoolManager> {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = DeadpoolManager::new(&database_url, DeadpoolRuntime::Tokio1);
    DeadpoolPool::builder(manager)
        .build()
        .expect("Failed to create test DB pool.")
}

// Helper struct to manage test data cleanup (users only for now)
struct TestDataGuard {
    pool: DeadpoolPool<DeadpoolManager>,
    user_ids: Vec<Uuid>,
}

impl TestDataGuard {
    fn new(pool: DeadpoolPool<DeadpoolManager>) -> Self {
        TestDataGuard {
            pool,
            user_ids: Vec::new(),
        }
    }

    fn add_user(&mut self, user_id: Uuid) {
        self.user_ids.push(user_id);
    }

    // Cleanup function (run explicitly at end of test)
    async fn cleanup(self) -> Result<(), anyhow::Error> {
        if self.user_ids.is_empty() {
            return Ok(());
        }
        tracing::debug!(user_ids = ?self.user_ids, "--- Cleaning up test users ---");

        let pool_clone = self.pool.clone();
        let obj = pool_clone.get().await.context("Failed to get DB connection for cleanup")?;
        let user_ids_to_delete = self.user_ids.clone();

        let delete_result = obj.interact(move |conn| {
            diesel::delete(users::table.filter(users::id.eq_any(user_ids_to_delete)))
                .execute(conn)
        }).await;

        match delete_result {
            Ok(Ok(count)) => tracing::debug!("Cleaned up {} users.", count),
            Ok(Err(db_err)) => {
                tracing::error!(error = ?db_err, "DB error cleaning up users");
                return Err(anyhow::Error::new(db_err).context("DB error cleaning up users"));
            }
            Err(interact_err) => {
                tracing::error!(error = ?interact_err, "Interact error cleaning up users");
                return Err(anyhow::anyhow!("Interact error cleaning up users: {:?}", interact_err));
            }
        }

        tracing::debug!("--- Cleanup complete ---");
        Ok(())
    }
}

// Helper function to run DB operations via pool interact
async fn run_db_op<F, T>(pool: &DeadpoolPool<DeadpoolManager>, op: F) -> AnyhowResult<T>
where
    F: FnOnce(&mut PgConnection) -> Result<T, diesel::result::Error> + Send + 'static,
    T: Send + 'static,
{
    let obj = pool.get().await.context("Failed to get DB connection")?;
    match obj.interact(op).await {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(db_err)) => Err(anyhow::Error::new(db_err).context("DB operation failed inside interact")),
        Err(interact_err) => match interact_err {
            deadpool_diesel::InteractError::Panic(_) => Err(anyhow::anyhow!("DB operation panicked")),
            deadpool_diesel::InteractError::Aborted => Err(anyhow::anyhow!("DB operation aborted")),
        },
    }
}

// Helper function to insert a user directly for testing, performing hashing synchronously
fn insert_test_user_direct(
    conn: &mut PgConnection,
    username: &str,
    password: &str, // Take plain password
) -> Result<User, diesel::result::Error> {
    info!(%username, "Inserting test user directly (sync hash)");

    // Hash synchronously within the test helper
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| {
            error!(%username, error=?e, "Sync bcrypt hashing failed in test helper");
            // Map bcrypt error to a generic Diesel error or panic for test failure
            diesel::result::Error::QueryBuilderError(Box::new(e))
        })?;

    let new_user = NewUser {
        username: username.to_string(),
        password_hash: hashed_password,
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .map_err(|e| {
            error!(username = %username, error=?e, "DB insert failed in test helper");
            e // Return original Diesel error
        })
}

// Helper function to build the test app router with auth layers
fn build_test_app(pool: DeadpoolPool<DeadpoolManager>) -> Router {
    let session_store = DieselSessionStore::new(pool.clone());
    // Configure the session layer
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Required for tests
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(1)));

    let auth_backend = AuthBackend::new(pool.clone());
    // Pass the session_layer INTO the AuthManagerLayerBuilder
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_layer).build();

    // Assuming 'pool' is already defined
    // Load config and create AppState
    let config = Arc::new(Config::load().expect("Failed to load test config for auth_tests"));
    let app_state = AppState::new(pool.clone(), config); // Updated line

    // Define auth routes
    let auth_routes = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/me", get(me_handler));

    // Build full app with state and layers in the standard order
    Router::new()
        .nest("/api/auth", auth_routes)
        .with_state(app_state)
        .layer(CookieManagerLayer::new()) // Apply CookieManagerLayer first
        .layer(auth_layer) // Apply AuthManagerLayer (containing SessionManagerLayer) second
}

// Helper to spawn the app in the background for reqwest tests
async fn spawn_app(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0") // Bind to random available port
        .await
        .expect("Failed to bind to random port");
    let addr = listener.local_addr().expect("Failed to get local address");
    tracing::debug!(address = %addr, "Test server listening");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Test server failed");
    });

    addr
}

// --- Test Cases ---

#[tokio::test]
async fn test_register_success() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    let username = format!("register_success_{}", Uuid::new_v4());
    let password = "password123";

    let credentials = json!({
        "username": username,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&credentials)?))?;

    let response = app.oneshot(request).await?;

    // Assert response status
    assert_eq!(response.status(), StatusCode::CREATED, "Registration should succeed");

    // Assert response body (should contain the created user, excluding password)
    let (status, user_body) = get_json_body::<User>(response).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(user_body.username, username);

    // Add user ID to guard for cleanup
    guard.add_user(user_body.id);

    // Verify user exists in DB (optional, but good practice)
    let fetched_user = run_db_op(&pool, move |conn| {
        users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
    }).await?;
    assert_eq!(fetched_user.id, user_body.id);

    // Cleanup test data
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_register_duplicate_username() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    let username = format!("register_duplicate_{}", Uuid::new_v4());
    let password = "password123";

    // --- First registration (should succeed) ---
    let credentials = json!({
        "username": username,
        "password": password
    });
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&credentials)?))?;
    let response1 = app.clone().oneshot(request1).await?;
    assert_eq!(response1.status(), StatusCode::CREATED, "First registration failed");
    let (_, user_body) = get_json_body::<User>(response1).await?;
    guard.add_user(user_body.id); // Ensure cleanup

    // --- Second registration (should fail with 409 Conflict) ---
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&credentials)?))?;
    let response2 = app.oneshot(request2).await?;

    // Assert status code is 409 Conflict
    assert_eq!(response2.status(), StatusCode::CONFLICT, "Duplicate registration did not return 409");

    // Assert error message (optional, depends on AppError mapping)
    let (status, error_body) = get_json_body::<Value>(response2).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_body["error"], "Username is already taken");

    // Cleanup test data
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_login_success() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    info!("--- Running test: test_login_success ---");

    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());

    // 1. Setup: Create a test user with a unique username
    let unique_part = Uuid::new_v4().to_string()[..8].to_string(); // Use a portion for readability
    let username = format!("test_login_{}", unique_part);
    let password = "testPassword123";
    let user = run_db_op(&pool, {
        let username = username.clone(); // Clone for the closure
        let password = password.to_string(); // Convert password to String for closure
        move |conn| {
            insert_test_user_direct(conn, &username, &password)
        }
    }).await.context(format!("Failed to insert test user '{}' for login", username))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, "Test user created for login");

    // 2. Build App and Spawn Server
    let app = build_test_app(pool.clone());
    let server_addr = spawn_app(app).await;
    let base_url = format!("http://{}", server_addr);

    // 3. Create Reqwest Client with Cookie Store
    let client = Client::builder()
        .cookie_store(true) // Enable automatic cookie handling
        .build()
        .context("Failed to build reqwest client")?;

    // 4. Perform Login Request
    let login_url = format!("{}/api/auth/login", base_url);
    let login_credentials = json!({
        "username": username, // Use the generated unique username
        "password": password,
    });

    info!(url = %login_url, %username, "Sending login request...");
    let response = client.post(&login_url)
        .json(&login_credentials)
        .send()
        .await
        .context("Failed to send login request")?;

    // 5. Assertions
    let status = response.status();
    info!(%status, headers = ?response.headers(), "Received login response");

    assert_eq!(status, StatusCode::OK, "Login request did not return OK");

    // Check for Set-Cookie header
    let set_cookie_header = response.headers().get(SET_COOKIE);
    assert!(
        set_cookie_header.is_some(),
        "Set-Cookie header was not found in the login response. Headers: {:?}",
        response.headers()
    );

    if let Some(cookie_value) = set_cookie_header {
        info!(cookie = ?cookie_value, "Set-Cookie header found");
        // Optional: Further parsing/assertions on the cookie value (e.g., name)
        assert!(cookie_value.to_str()?.contains("id="), "Set-Cookie header does not contain 'id='");
    }

    // Check response body (optional, but good practice)
    let body: Value = response.json().await.context("Failed to parse login response JSON")?;
    // Assert the structure of the returned User object
    assert_eq!(body["username"], username, "Response body username mismatch");
    assert_eq!(body["id"], user.id.to_string(), "Response body user ID mismatch");
    assert!(body.get("password_hash").is_none(), "Password hash should not be present in response");
    assert!(body.get("created_at").is_some(), "created_at field missing");
    assert!(body.get("updated_at").is_some(), "updated_at field missing");

    info!("Login successful and Set-Cookie header present.");

    // Cleanup
    guard.cleanup().await.context("Failed during cleanup")?;
    info!("--- Test finished: test_login_success ---");
    Ok(())
}

#[tokio::test]
async fn test_login_wrong_password() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    let username = format!("login_wrong_pass_{}", Uuid::new_v4());
    let correct_password = "password123";
    let wrong_password = "wrongpassword";

    // Insert user directly
    let user = run_db_op(&pool, {
        let username = username.clone();
        let password = correct_password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &password)
    }).await
    .with_context(|| format!("Failed to insert test user '{}' directly into DB", username))?;
    guard.add_user(user.id); // Ensure cleanup

    // Attempt Login with wrong password
    let credentials = json!({
        "username": username,
        "password": wrong_password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&credentials)?))?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Login with wrong password should return 401");

    // Verify error message (depends on AppError mapping)
    let (status, error_body) = get_json_body::<Value>(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_body["error"], "Invalid credentials");

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_login_user_not_found() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let guard = TestDataGuard::new(pool.clone()); // Guard without users
    let app = build_test_app(pool.clone());

    let username = format!("login_nonexistent_{}", Uuid::new_v4());
    let password = "password123";

    // Attempt Login with non-existent user
    let credentials = json!({
        "username": username,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&credentials)?))?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Login with non-existent user should return 401");

    // Verify error message
    let (status, error_body) = get_json_body::<Value>(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_body["error"], "Invalid credentials"); // Or potentially "User not found" depending on error mapping

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_logout_success() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    let username = format!("logout_success_{}", Uuid::new_v4());
    let password = "password123";

    // Insert user
    let user = run_db_op(&pool, {
        let username = username.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &password)
    }).await.with_context(|| "Failed to insert user")?;
    guard.add_user(user.id);

    // --- Log in first ---
    let login_credentials = json!({
        "username": username,
        "password": password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_credentials)?))?;
    let login_response = app.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed before logout");

    // Extract session cookie
    let session_cookie = login_response.headers().get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie"))?
        .to_str()?.to_string();

    // --- Attempt Logout ---
    let logout_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .header(header::COOKIE, &session_cookie) // Send the session cookie
        .body(Body::empty())?;
    let logout_response = app.clone().oneshot(logout_request).await?;

    // Assertions for logout
    assert_eq!(logout_response.status(), StatusCode::OK, "Logout request failed");

    // Verify Set-Cookie header clears the session
    let logout_set_cookie = logout_response.headers().get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Logout response missing Set-Cookie"))?
        .to_str()?;
    assert!(logout_set_cookie.contains("id="), "Logout Set-Cookie missing id=");
    assert!(logout_set_cookie.contains("Max-Age=0") || logout_set_cookie.contains("expires=Thu, 01 Jan 1970"), "Logout Set-Cookie did not clear session");

    // --- Verify logout worked by calling /me ---
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, &session_cookie) // Send the *original* cookie
        .body(Body::empty())?;
    let me_response = app.oneshot(me_request).await?;

    assert_eq!(me_response.status(), StatusCode::UNAUTHORIZED, "/me should be unauthorized after logout");

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_logout_no_session() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    // Attempt Logout without logging in (no cookie)
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Logout should still return OK even if no session existed
    assert_eq!(response.status(), StatusCode::OK, "Logout without session failed");

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_me_success() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    let username = format!("me_success_{}", Uuid::new_v4());
    let password = "password123";

    // Insert user
    let user = run_db_op(&pool, {
        let username = username.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &password)
    }).await.with_context(|| "Failed to insert user")?;
    guard.add_user(user.id);

    // --- Log in ---
    let login_credentials = json!({
        "username": username,
        "password": password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_credentials)?))?;
    let login_response = app.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed before /me test");

    // Extract session cookie
    let session_cookie = login_response.headers().get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie"))?
        .to_str()?.to_string();

    // --- Call /me endpoint ---
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, &session_cookie) // Send the session cookie
        .body(Body::empty())?;
    let me_response = app.oneshot(me_request).await?;

    // Assertions
    assert_eq!(me_response.status(), StatusCode::OK, "/me request failed");

    let (status, user_body) = get_json_body::<User>(me_response).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user_body.id, user.id);
    assert_eq!(user_body.username, user.username);

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_me_unauthorized() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let pool = create_test_pool();
    let guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone());

    // Call /me endpoint without logging in (no cookie)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "/me without login should be unauthorized");

    guard.cleanup().await?;
    Ok(())
}

// --- Test Setup Helpers ---

// Temporary handler to test CookieManagerLayer
#[axum::debug_handler]
#[instrument(skip(cookies), err)]
async fn test_cookie_handler(cookies: Cookies) -> Result<impl IntoResponse, AppError> {
    info!("Executing test_cookie_handler");
    // Add a simple cookie
    cookies.add(Cookie::new("test-cookie", "test-value"));
    Ok(StatusCode::OK)
}

#[tokio::test]
async fn test_cookie_layer_sets_cookie() -> AnyhowResult<()> {
    ensure_tracing_initialized();
    let _pool = create_test_pool(); // Prefixed with _
    // Build a minimal app with just the cookie layer and the test handler
    let app = Router::new()
        .route("/test-cookie", get(test_cookie_handler))
        .layer(CookieManagerLayer::new()); // Apply only the cookie layer

    // Send request
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test-cookie")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(response.status(), StatusCode::OK, "Test cookie handler failed");

    // Verify Set-Cookie header exists for our test cookie
    let set_cookie_header = response.headers().get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Test cookie handler response missing Set-Cookie header"))?
        .to_str()?;
    assert!(set_cookie_header.contains("test-cookie=test-value"), "Set-Cookie header missing test cookie info");

    Ok(())
}