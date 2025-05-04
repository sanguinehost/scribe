#![cfg(test)]
// backend/tests/auth_tests.rs

// --- Imports (similar to characters_tests, but focused on auth) ---
use anyhow::{Context, Result as AnyhowResult};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get, // Add get for /me route
    routing::post,
};
use axum_login::{
    AuthManagerLayerBuilder,
    tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite},
};
use axum_login::AuthnBackend;
use bcrypt; // For direct verification if needed, though backend handles it
use deadpool_diesel::{
    Pool as DeadpoolPool, Runtime as DeadpoolRuntime, postgres::Manager as DeadpoolManager,
};
use diesel::{PgConnection, prelude::*};
use dotenvy;
use http_body_util::BodyExt;
use scribe_backend::{
    auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend},
    config::Config,
    errors::AppError,
    models::{
        auth::{AuthResponse, LoginPayload}, // Updated auth models
        users::{NewUser, User},
    },
    auth::session_store::SessionRecord, // Import SessionRecord correctly
    routes::auth::{login_handler, logout_handler, me_handler, register_handler},
    schema::{users, sessions}, // Import sessions schema
    state::AppState,
    test_helpers::{MockEmbeddingClient, MockEmbeddingPipelineService},
    vector_db::QdrantClientService,
};
use serde::de::DeserializeOwned; // For get_json_body
use serde_json::{Value, json};
use std::{env, sync::Arc};
use time::{self, OffsetDateTime}; // Import OffsetDateTime
use tower::ServiceExt; // For `oneshot`
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tracing::{error, info, instrument};
use uuid::Uuid;
// use tokio::net::TcpListener; // Unused
use std::net::SocketAddr;
// use scribe_backend::test_helpers::{self, create_test_user, setup_test_app, TestContext}; // Unused
use axum_login::tower_sessions::{SessionStore, session::{Id, Record}, session_store}; // Import SessionStore traits and session_store module
use chrono::Utc; // For Utc::now()
// No longer needed: use scribe_backend::auth::session_store::offset_to_utc;
use std::collections::HashMap; // For manually creating Record.data
use rand; // Import rand crate

// --- Test Helpers (Copied/Adapted from characters_tests.rs) ---

// Helper function to extract JSON body from response
async fn get_json_body<T: DeserializeOwned>(
    response: Response<Body>,
) -> AnyhowResult<(StatusCode, T)> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let json_body: T = serde_json::from_slice(&body_bytes).with_context(|| {
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
        let obj = pool_clone
            .get()
            .await
            .context("Failed to get DB connection for cleanup")?;
        let user_ids_to_delete = self.user_ids.clone();

        let delete_result = obj
            .interact(move |conn| {
                diesel::delete(users::table.filter(users::id.eq_any(user_ids_to_delete)))
                    .execute(conn)
            })
            .await;

        match delete_result {
            Ok(Ok(count)) => tracing::debug!("Cleaned up {} users.", count),
            Ok(Err(db_err)) => {
                tracing::error!(error = ?db_err, "DB error cleaning up users");
                return Err(anyhow::Error::new(db_err).context("DB error cleaning up users"));
            }
            Err(interact_err) => {
                tracing::error!(error = ?interact_err, "Interact error cleaning up users");
                return Err(anyhow::anyhow!(
                    "Interact error cleaning up users: {:?}",
                    interact_err
                ));
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
        Ok(Err(db_err)) => {
            Err(anyhow::Error::new(db_err).context("DB operation failed inside interact"))
        }
        Err(interact_err) => match interact_err {
            deadpool_diesel::InteractError::Panic(_) => {
                Err(anyhow::anyhow!("DB operation panicked"))
            }
            deadpool_diesel::InteractError::Aborted => Err(anyhow::anyhow!("DB operation aborted")),
        },
    }
}

// Helper function to insert a user directly for testing, performing hashing synchronously
fn insert_test_user_direct(
    conn: &mut PgConnection,
    username: &str,
    email: &str, // Add email parameter
    password: &str, // Take plain password
) -> Result<User, diesel::result::Error> {
    info!(%username, %email, "Inserting test user directly (sync hash)");

    // Hash synchronously within the test helper
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| {
        error!(%username, error=?e, "Sync bcrypt hashing failed in test helper");
        // Map bcrypt error to a generic Diesel error or panic for test failure
        diesel::result::Error::QueryBuilderError(Box::new(e))
    })?;

    let new_user = NewUser {
        username: username.to_string(),
        email: email.to_string(), // Add email
        password_hash: hashed_password,
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .map_err(|e| {
            error!(username = %username, email = %email, error=?e, "DB insert failed in test helper");
            e // Return original Diesel error
        })
}

// Helper function to build the test app router with auth layers
async fn build_test_app(pool: DeadpoolPool<DeadpoolManager>) -> Router {
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
    // Build AI client
    let ai_client = Arc::new(
        scribe_backend::llm::gemini_client::build_gemini_client()
            .await
            .expect("Failed to build Gemini client for auth tests. Is GOOGLE_API_KEY set?"),
    );
    // Instantiate mock embedding client
    let embedding_client = Arc::new(MockEmbeddingClient::new());
    // Instantiate mock embedding pipeline service
    let embedding_pipeline_service = Arc::new(MockEmbeddingPipelineService::new());
    // Instantiate Qdrant service
    let qdrant_service = Arc::new(
        QdrantClientService::new(config.clone())
            .await
            .expect("Failed to create QdrantClientService for auth test"),
    );
    let app_state = AppState::new(
        pool.clone(),
        config,
        ai_client,
        embedding_client,
        qdrant_service,
        embedding_pipeline_service,
    );

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

// Helper function to spawn the app for testing
#[allow(dead_code)] // Added to silence unused function warning
async fn spawn_app(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to random port");
    let addr = listener.local_addr().expect("Failed to get local address");
    tracing::debug!(address = %addr, "Test server listening");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Test server failed");
    });

    addr
}

// --- Test Cases ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_register_success() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("register_success_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username); // Use unique email
    let password = "password123";

    // Use RegisterPayload
    let payload = json!({
        "username": username,
        "email": email,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = app.oneshot(request).await?;

    // Assert response status
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Registration should succeed"
    );

    // Assert response body (should match AuthResponse)
    let (status, auth_response) = get_json_body::<AuthResponse>(response).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(auth_response.username, username);
    assert_eq!(auth_response.email, email); // Check email in response

    // Add user ID to guard for cleanup
    guard.add_user(auth_response.user_id);

    // Verify user exists in DB (optional, but good practice)
    let fetched_user = run_db_op(&pool, {
        let user_id = auth_response.user_id; // Clone for closure
        move |conn| {
            users::table
                .find(user_id) // Find by ID
                .select(User::as_select()) // Select specific columns matching User struct
                .first::<User>(conn)
        }
    })
    .await?;
    assert_eq!(fetched_user.id, auth_response.user_id);
    assert_eq!(fetched_user.username, username);
    assert_eq!(fetched_user.email, email); // Verify email in DB

    // Cleanup test data
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_register_duplicate_username() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("register_duplicate_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username); // Unique email for this user
    let password = "password123";

    // --- First registration (should succeed) ---
    let payload1 = json!({
        "username": username,
        "email": email,
        "password": password
    });
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload1)?))?;
    let response1 = app.clone().oneshot(request1).await?;
    assert_eq!(
        response1.status(),
        StatusCode::CREATED,
        "First registration failed"
    );
    let (_, auth_response) = get_json_body::<AuthResponse>(response1).await?;
    guard.add_user(auth_response.user_id); // Ensure cleanup

    // --- Second registration (same username, different email - should fail) ---
    let payload2 = json!({
        "username": username, // Same username
        "email": format!("another_{}", email), // Different email
        "password": password
    });
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload2)?))?;
    let response2 = app.oneshot(request2).await?;

    // Assert status code is 409 Conflict
    assert_eq!(
        response2.status(),
        StatusCode::CONFLICT,
        "Duplicate registration did not return 409"
    );

    // Assert error message (optional, depends on AppError mapping)
    let (status, error_body) = get_json_body::<Value>(response2).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_body["error"], "Username is already taken");

    // Cleanup test data
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_register_duplicate_email() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username1 = format!("register_dup_email1_{}", Uuid::new_v4());
    let username2 = format!("register_dup_email2_{}", Uuid::new_v4());
    let email = format!("duplicate_email_{}@test.com", Uuid::new_v4()); // Same email
    let password = "password123";

    // --- First registration (should succeed) ---
    let payload1 = json!({
        "username": username1,
        "email": email,
        "password": password
    });
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload1)?))?;
    let response1 = app.clone().oneshot(request1).await?;
    assert_eq!(
        response1.status(),
        StatusCode::CREATED,
        "First registration failed"
    );
    let (_, auth_response) = get_json_body::<AuthResponse>(response1).await?;
    guard.add_user(auth_response.user_id); // Ensure cleanup

    // --- Second registration (different username, same email - should fail) ---
    let payload2 = json!({
        "username": username2, // Different username
        "email": email,       // Same email
        "password": password
    });
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload2)?))?;
    let response2 = app.oneshot(request2).await?;

    // Assert status code is 409 Conflict
    assert_eq!(
        response2.status(),
        StatusCode::CONFLICT,
        "Duplicate email registration did not return 409"
    );

    // Assert error message
    let (status, error_body) = get_json_body::<Value>(response2).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_body["error"], "Email is already taken"); // Check for email taken error

    // Cleanup test data
    guard.cleanup().await?;
    Ok(())
}


#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_login_success() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    // Build the app directly, no need to spawn
    let app = build_test_app(pool.clone()).await;

    let username = format!("test_login_{}", Uuid::new_v4().to_string()[..8].to_string());
    let email = format!("{}@test.com", username);
    let password = "testPassword123";
    let user = run_db_op(&pool, {
        let username = username.clone(); // Clone for the closure
        let email = email.clone(); // Clone email
        let password = password.to_string(); // Convert password to String for closure
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .context(format!(
        "Failed to insert test user '{}'/'{}' for login",
        username, email
    ))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, %email, "Test user created for login");

    // --- Use app.oneshot() ---
    // Use LoginPayload with username as identifier
    let login_payload = json!({
        "identifier": username, // Use username as identifier
        "password": password,
    });

    info!(identifier = %username, "Sending login request via oneshot...");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let response = app.oneshot(request).await?; // Use oneshot here

    // --- Assertions ---
    let status = response.status();
    info!(%status, headers = ?response.headers(), "Received login response");

    assert_eq!(status, StatusCode::OK, "Login request did not return OK");

    // Check for Set-Cookie header
    let set_cookie_header = response.headers().get(header::SET_COOKIE);
    assert!(
        set_cookie_header.is_some(),
        "Set-Cookie header was not found in the login response. Headers: {:?}",
        response.headers()
    );

    if let Some(cookie_value) = set_cookie_header {
        info!(cookie = ?cookie_value, "Set-Cookie header found");
        // Optional: Further parsing/assertions on the cookie value (e.g., name)
        assert!(
            cookie_value.to_str()?.contains("id="),
            "Set-Cookie header does not contain 'id='"
        );
    }

    // Check response body (should match AuthResponse)
    let (body_status, auth_response): (StatusCode, AuthResponse) = get_json_body(response)
        .await
        .context("Failed to parse login response JSON")?;
    assert_eq!(body_status, StatusCode::OK, "Body status code mismatch");

    // Assert the structure of the returned AuthResponse object
    assert_eq!(
        auth_response.username, username,
        "Response body username mismatch"
    );
    assert_eq!(
        auth_response.email, email, // Check email
        "Response body email mismatch"
    );
    assert_eq!(
        auth_response.user_id, user.id,
        "Response body user ID mismatch"
    );

    info!("Login successful and Set-Cookie header present.");

    // Cleanup
    guard.cleanup().await.context("Failed during cleanup")?;
    Ok(())
}


#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_login_success_with_email() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("test_login_email_{}", Uuid::new_v4().to_string()[..8].to_string());
    let email = format!("{}@test.com", username);
    let password = "testPassword123";
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password)
    })
    .await
    .context(format!(
        "Failed to insert test user '{}'/'{}' for email login",
        username, email
    ))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, %email, "Test user created for email login");

    // --- Use app.oneshot() ---
    // Use LoginPayload with email as identifier
    let login_payload = json!({
        "identifier": email, // Use email as identifier
        "password": password,
    });

    info!(identifier = %email, "Sending login request via oneshot using email...");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let response = app.oneshot(request).await?;

    // --- Assertions ---
    let status = response.status();
    info!(%status, headers = ?response.headers(), "Received email login response");

    assert_eq!(status, StatusCode::OK, "Email login request did not return OK");

    // Check for Set-Cookie header
    let set_cookie_header = response.headers().get(header::SET_COOKIE);
    assert!(
        set_cookie_header.is_some(),
        "Set-Cookie header was not found in the email login response. Headers: {:?}",
        response.headers()
    );

    // Check response body (should match AuthResponse)
    let (body_status, auth_response): (StatusCode, AuthResponse) = get_json_body(response)
        .await
        .context("Failed to parse email login response JSON")?;
    assert_eq!(body_status, StatusCode::OK, "Body status code mismatch");

    // Assert the structure of the returned AuthResponse object
    assert_eq!(
        auth_response.username, username,
        "Response body username mismatch"
    );
    assert_eq!(
        auth_response.email, email,
        "Response body email mismatch"
    );
    assert_eq!(
        auth_response.user_id, user.id,
        "Response body user ID mismatch"
    );

    info!("Email login successful and Set-Cookie header present.");

    // Cleanup
    guard.cleanup().await.context("Failed during cleanup")?;
    Ok(())
}


#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_login_wrong_password() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("login_wrong_pass_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let correct_password = "password123";
    let wrong_password = "wrongpassword";

    // Insert user directly
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = correct_password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| format!("Failed to insert test user '{}'/'{}' directly into DB", username, email))?;
    guard.add_user(user.id); // Ensure cleanup

    // Attempt Login with wrong password (using username as identifier)
    let payload = json!({
        "identifier": username, // Use username as identifier
        "password": wrong_password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Login with wrong password should return 401"
    );

    // Verify error message (depends on AppError mapping)
    let (status, error_body) = get_json_body::<Value>(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_body["error"], "Invalid identifier or password"); // Updated expected error message

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_login_user_not_found() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let _app = build_test_app(pool.clone()).await;

    let identifier = format!("login_nonexistent_{}", Uuid::new_v4()); // Could be username or email
    let password = "password123";

    // Attempt Login with non-existent user
    let payload = json!({
        "identifier": identifier,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = _app.oneshot(request).await?;

    // Assertions
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Login with non-existent user should return 401"
    );

    // Verify error message
    let (status, error_body) = get_json_body::<Value>(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_body["error"], "Invalid identifier or password"); // Updated expected error message

    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI - Requires DB
async fn test_verify_credentials_invalid_hash_in_db() -> AnyhowResult<()> {
    // Covers lines 156-157 in auth/mod.rs (verify_credentials -> HashingError)
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("verify_invalid_hash_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";
    let invalid_hash = "this_is_not_a_valid_bcrypt_hash";

    // 1. Insert user with a valid hash initially (using the helper)
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| format!("Failed to insert test user '{}'/'{}'", username, email))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, %email, "Test user created");

    // 2. Manually update the hash in the DB to an invalid one
    let update_result = run_db_op(&pool, {
        let user_id = user.id;
        move |conn| {
            diesel::update(users::table.find(user_id))
                .set(users::password_hash.eq(invalid_hash))
                .execute(conn)
        }
    })
    .await;
    update_result.context("Failed to update user hash to invalid string")?;
    info!(user_id = %user.id, %username, "Updated password hash to invalid string in DB");

    // 3. Attempt to verify credentials using username as identifier - should fail during bcrypt::verify
    let verification_result = run_db_op(&pool, {
        let identifier = username.clone(); // Use username as identifier
        let password = Secret::new(password.to_string()); // Wrap password in Secret
        move |conn| {
            scribe_backend::auth::verify_credentials(conn, &identifier, password) // Pass identifier
                // Map AuthError to a Diesel error variant for run_db_op compatibility
                .map_err(|auth_err| diesel::result::Error::QueryBuilderError(Box::new(auth_err)))
        }
    })
    .await;

    info!(user_id = %user.id, %username, ?verification_result, "Verification result with invalid hash");

    // 4. Assert that the error is HashingError
    assert!(verification_result.is_err(), "Verification should fail with invalid hash in DB");
    match verification_result {
        Err(e) => {
            // Drill down through the wrapped errors: anyhow -> diesel -> Box<AuthError>
            let root_cause = e.root_cause();
            info!(root_cause = ?root_cause, "Root cause of the error");

            // Attempt to downcast the root cause directly to AuthError
            if let Some(auth_error) = root_cause.downcast_ref::<AuthError>() {
                 match auth_error {
                    AuthError::HashingError => {
                        info!("Successfully caught expected AuthError::HashingError as root cause");
                    }
                    _ => {
                        panic!("Expected root cause to be AuthError::HashingError, but got {:?}", auth_error);
                    }
                }
            } else {
                 // Fallback: Check if it's the wrapped Diesel error containing the Boxed AuthError
                 // This might be necessary depending on how anyhow wraps things.
                 if let Some(diesel_error) = e.downcast_ref::<diesel::result::Error>() {
                     if let diesel::result::Error::QueryBuilderError(boxed_err) = diesel_error {
                         if let Some(auth_error) = boxed_err.downcast_ref::<AuthError>() {
                             assert!(matches!(auth_error, AuthError::HashingError), "Expected boxed AuthError::HashingError, got {:?}", auth_error);
                             info!("Successfully caught expected HashingError inside Diesel QueryBuilderError");
                         } else {
                             panic!("Boxed error inside QueryBuilderError was not an AuthError: {:?}", boxed_err);
                         }
                     } else {
                         panic!("Error was a Diesel error, but not QueryBuilderError: {:?}", diesel_error);
                     }
                 } else {
                    panic!("Error was not an AuthError root cause and could not be downcasted to diesel::result::Error. Original anyhow error: {:?}", e);
                 }
            }
        }
        Ok(_) => {
            panic!("Expected an error during verification, but got Ok");
        }
    }

    // Cleanup
    guard.cleanup().await?;
    Ok(())
}
#[tokio::test]
#[ignore] // Requires DB access via pool
async fn test_login_hashing_error_in_db() -> AnyhowResult<()> {
    // Covers line 110 in routes/auth.rs (Err(e) from auth_session.authenticate)
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("login_hash_err_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";
    let invalid_hash = "this_is_not_a_valid_bcrypt_hash";

    // 1. Insert user with a valid hash initially
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| format!("Failed to insert test user '{}'/'{}'", username, email))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, %email, "Test user created for login hashing error test");

    // 2. Manually update the hash in the DB to an invalid one
    let update_result = run_db_op(&pool, {
        let user_id = user.id;
        move |conn| {
            diesel::update(users::table.find(user_id))
                .set(users::password_hash.eq(invalid_hash))
                .execute(conn)
        }
    })
    .await;
    update_result.context("Failed to update user hash to invalid string")?;
    info!(user_id = %user.id, %username, "Updated password hash to invalid string in DB");

    // 3. Attempt to login via the API endpoint (using username as identifier)
    let payload = json!({
        "identifier": username, // Use username as identifier
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    info!(%username, "Sending login request via oneshot with invalid hash in DB...");
    let response = app.oneshot(request).await?;

    // 4. Assertions
    let status = response.status();
    info!(%status, headers = ?response.headers(), "Received login response for invalid hash");

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Login with invalid hash in DB should return 500 Internal Server Error"
    );

    // Verify error message (check for the generic internal server error message)
    let (body_status, error_body) = get_json_body::<Value>(response).await?;
    assert_eq!(body_status, StatusCode::INTERNAL_SERVER_ERROR);
    let error_message = error_body["error"].as_str().unwrap_or("");
    // Check for the generic error message returned by AppError::InternalServerError
    assert_eq!(
        error_message,
        "An unexpected error occurred",
        "Error message mismatch. Got: {}", error_message
    );


    // Cleanup
    guard.cleanup().await?;
    Ok(())
}
#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_logout_success() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("logout_success_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";

    // Insert user
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| "Failed to insert user")?;
    guard.add_user(user.id);

    // --- Log in first (using username as identifier) ---
    let login_payload = json!({
        "identifier": username, // Use username as identifier
        "password": password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;
    let login_response = app.clone().oneshot(login_request).await?;
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login failed before logout"
    );

    // Extract session cookie
    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie"))?
        .to_str()?
        .to_string();

    // --- Attempt Logout ---
    let logout_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .header(header::COOKIE, &session_cookie) // Send the session cookie
        .body(Body::empty())?;
    let logout_response = app.clone().oneshot(logout_request).await?;

    // Assertions for logout
    assert_eq!(
        logout_response.status(),
        StatusCode::OK,
        "Logout request failed"
    );

    // Verify Set-Cookie header clears the session
    let logout_set_cookie = logout_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Logout response missing Set-Cookie"))?
        .to_str()?;
    assert!(
        logout_set_cookie.contains("id="),
        "Logout Set-Cookie missing id="
    );
    assert!(
        logout_set_cookie.contains("Max-Age=0")
            || logout_set_cookie.contains("expires=Thu, 01 Jan 1970"),
        "Logout Set-Cookie did not clear session"
    );

    // --- Verify logout worked by calling /me ---
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, &session_cookie) // Send the *original* cookie
        .body(Body::empty())?;
    let me_response = app.oneshot(me_request).await?;

    assert_eq!(
        me_response.status(),
        StatusCode::UNAUTHORIZED,
        "/me should be unauthorized after logout"
    );

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_logout_no_session() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let app = build_test_app(pool.clone()).await;

    // Attempt Logout without logging in (no cookie)
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Logout should still return OK even if no session existed
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Logout without session failed"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_me_success() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let app = build_test_app(pool.clone()).await;

    let username = format!("me_success_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";

    // Insert user
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| "Failed to insert user")?;
    guard.add_user(user.id);

    // --- Log in (using username as identifier) ---
    let login_payload = json!({
        "identifier": username, // Use username as identifier
        "password": password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;
    let login_response = app.clone().oneshot(login_request).await?;
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login failed before /me test"
    );

    // Extract session cookie
    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie"))?
        .to_str()?
        .to_string();

    // --- Call /me endpoint ---
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, &session_cookie) // Send the session cookie
        .body(Body::empty())?;
    let me_response = app.oneshot(me_request).await?;

    // Assertions
    assert_eq!(me_response.status(), StatusCode::OK, "/me request failed");

    // Assert response body matches AuthResponse
    let (status, auth_response) = get_json_body::<AuthResponse>(me_response).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(auth_response.user_id, user.id);
    assert_eq!(auth_response.username, user.username);
    assert_eq!(auth_response.email, user.email); // Check email

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_me_unauthorized() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let app = build_test_app(pool.clone()).await;

    // Call /me endpoint without logging in (no cookie)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "/me without login should be unauthorized"
    );

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
#[ignore] // Added ignore for CI
async fn test_cookie_layer_sets_cookie() -> AnyhowResult<()> {
    let app = Router::new()
        .route("/", get(test_cookie_handler))
        .layer(CookieManagerLayer::new());

    // Send request
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;

    // Assertions
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Test cookie handler failed"
    );

    // Verify Set-Cookie header exists for our test cookie
    let set_cookie_header = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Test cookie handler response missing Set-Cookie header"))?
        .to_str()?;
    assert!(
        set_cookie_header.contains("test-cookie=test-value"),
        "Set-Cookie header missing test cookie info"
    );

    Ok(())
}

// --- Unit Tests for auth module helpers ---

use scribe_backend::auth::{AuthError};
use deadpool_diesel::InteractError;
use secrecy::Secret;

#[test]
fn test_auth_error_from_interact_error() {
    let interact_error = InteractError::Aborted; // Example InteractError variant
    let auth_error = AuthError::from(interact_error);
    assert!(matches!(auth_error, AuthError::InteractError(_)));
    assert_eq!(auth_error.to_string(), "Database interaction error: Aborted");

    // Optional: Test other variants if needed
    // let panic_error = InteractError::Panic(std::panic::Location::caller().to_string()); // Requires more setup
    // let auth_error_panic = AuthError::from(panic_error);
    // assert!(matches!(auth_error_panic, AuthError::InteractError(_)));
}

// --- Tests for DieselSessionStore ---

// Helper to create a session store instance for tests
fn create_test_session_store(pool: DeadpoolPool<DeadpoolManager>) -> DieselSessionStore {
    DieselSessionStore::new(pool)
}

#[tokio::test]
#[ignore] // Requires DB
async fn test_session_store_save_load_delete() -> AnyhowResult<()> {
    let pool = create_test_pool();
    let store = create_test_session_store(pool.clone());
    let session_id_val = rand::random::<i128>(); // Use rand::random per compiler suggestion
    let session_id = Id(session_id_val); // Construct Id using tuple struct syntax
    let expiry_date = OffsetDateTime::now_utc() + time::Duration::hours(1);
    // Manually construct Record as ::new() is private
    let mut data = HashMap::new();
    data.insert("user_id".to_string(), serde_json::to_value(Uuid::new_v4().to_string())?);
    let record = Record {
        id: session_id.clone(), // Clone Id here
        data,
        expiry_date,
    };

    // 1. Save
    store.save(&record).await.context("Failed to save session")?;
    info!(session_id = %session_id, "Session saved");

    // 2. Load
    let loaded_record_opt = store.load(&session_id).await.context("Failed to load session")?;
    assert!(loaded_record_opt.is_some(), "Session should be found after saving");
    let loaded_record = loaded_record_opt.unwrap();
    info!(session_id = %session_id, "Session loaded");

    // Assert data integrity (ignoring expiry precision differences)
    assert_eq!(loaded_record.id, session_id);
    // Access data via the .data field
    assert_eq!(
        loaded_record.data.get("user_id").and_then(|v| v.as_str()),
        record.data.get("user_id").and_then(|v| v.as_str())
    );
    // Compare expiry timestamps loosely (within a second) due to potential conversion nuances
    assert!((loaded_record.expiry_date - expiry_date).abs() < time::Duration::seconds(1));

    // 3. Delete
    store.delete(&session_id).await.context("Failed to delete session")?;
    info!(session_id = %session_id, "Session deleted");

    // 4. Verify deletion
    let loaded_after_delete = store.load(&session_id).await.context("Failed to load session after delete")?;
    assert!(loaded_after_delete.is_none(), "Session should not be found after deletion");
    info!(session_id = %session_id, "Verified session deletion");

    Ok(())
}

#[tokio::test]
#[ignore] // Requires DB
async fn test_session_store_load_invalid_json() -> AnyhowResult<()> {
    // Covers lines 84-86 (map_json_error), 292 (load deserialize error)
    let pool = create_test_pool();
    let store = create_test_session_store(pool.clone());
    let session_id_val = rand::random::<i128>(); // Use rand::random per compiler suggestion
    let session_id_str = session_id_val.to_string(); // String version for DB interaction
    let invalid_json = "{ \"key\": \"value\", invalid }"; // Malformed JSON

    // Manually insert invalid record within a transaction
    let insert_result = run_db_op(&pool, {
        let sid = session_id_str.clone(); // Use String for DB
        move |conn| {
            let record = SessionRecord {
                id: sid, // Use String ID
                expires: Some(Utc::now() + chrono::Duration::hours(1)),
                session: invalid_json.to_string(),
            };
            diesel::insert_into(sessions::table)
                .values(&record)
                .execute(conn)
        }
    }).await;

    // Check if insertion itself failed unexpectedly (it shouldn't just for bad JSON string)
    insert_result.context("Manual insertion of invalid JSON failed unexpectedly")?;
    info!(session_id = %session_id_val, "Manually inserted record with invalid JSON");

    // Attempt to load the record with invalid JSON
    let load_result = store.load(&Id(session_id_val)).await; // Construct Id with i128
    info!(session_id = %session_id_val, ?load_result, "Load result for invalid JSON");

    // Assert that loading failed with a Decode error
    assert!(load_result.is_err(), "Loading invalid JSON should result in an error");
    match load_result {
        Err(session_store::Error::Decode(e)) => {
            info!(error=%e, "Successfully caught expected Decode error");
            // Removed specific error message check: assert!(e.contains("expected `,` or `}` at line 1 column 21"));
        }
        Err(e) => panic!("Expected Decode error, but got different error: {:?}", e),
        Ok(_) => panic!("Expected an error when loading invalid JSON, but got Ok"),
    }

    // Cleanup: Delete the manually inserted record
    let delete_result = run_db_op(&pool, {
        let sid = session_id_str.clone(); // Use String for DB query
        move |conn| {
            diesel::delete(sessions::table.find(sid))
                .execute(conn)
        }
    }).await;
    delete_result.context("Failed to clean up manually inserted invalid record")?;
    info!(session_id = %session_id_val, "Cleaned up invalid JSON record");

    Ok(())
}

#[tokio::test]
#[ignore] // Requires DB
async fn test_session_store_load_expired_session() -> AnyhowResult<()> {
    // Covers lines 305-307 (load expired session logic)
    let pool = create_test_pool();
    let store = create_test_session_store(pool.clone());
    let session_id_val = rand::random::<i128>(); // Use rand::random per compiler suggestion
    let session_id = Id(session_id_val); // Construct Id with i128
    let session_id_str = session_id_val.to_string(); // String version for DB interaction
    // Set expiry firmly in the past
    let expiry_date = OffsetDateTime::now_utc() - time::Duration::days(1);
    // Manually construct Record
    let mut data = HashMap::new();
    data.insert("data".to_string(), serde_json::to_value("some_expired_data")?);
    let record = Record {
        id: session_id.clone(),
        data,
        expiry_date,
    };

    // 1. Save the expired record
    store.save(&record).await.context("Failed to save expired session")?;
    info!(session_id = %session_id, "Saved expired session");

    // Verify it exists momentarily in DB (optional sanity check)
    let exists_before_load = run_db_op(&pool, {
        let sid = session_id_str.clone(); // Use String for DB query
        move |conn| {
            sessions::table.find(sid).select(sessions::id).first::<String>(conn).optional() // Check for String
        }
    }).await?.is_some();
    assert!(exists_before_load, "Expired session should exist in DB before loading");

    // 2. Load the expired record
    let loaded_record_opt = store.load(&session_id).await.context("Failed to load expired session")?;
    info!(session_id = %session_id_val, ?loaded_record_opt, "Load result for expired session"); // Log i128 ID

    // Assert that loading returns None because it was expired
    assert!(loaded_record_opt.is_none(), "Loading an expired session should return None");

    // 3. Verify deletion happened during load
    let loaded_after_load = run_db_op(&pool, {
        let sid = session_id_str.clone(); // Use String for DB query
        move |conn| {
            sessions::table.find(sid).select(sessions::id).first::<String>(conn).optional() // Check for String
        }
    }).await?;
    assert!(loaded_after_load.is_none(), "Expired session should have been deleted during load");
    info!(session_id = %session_id_val, "Verified expired session was deleted during load"); // Log i128 ID

    Ok(())
}

// --- Tests for AuthBackend (user_store.rs) ---

#[test]
fn test_auth_backend_debug_impl() {
    // Covers lines 23-24 in user_store.rs
    let pool = create_test_pool();
    let backend = AuthBackend::new(pool);
    let debug_output = format!("{:?}", backend);
    assert!(debug_output.contains("Backend"));
    assert!(debug_output.contains("pool: \"<DbPool>\"")); // Check that pool is not printed directly
    println!("Debug output: {}", debug_output); // Optional: print for verification
}

#[tokio::test]
#[ignore] // Requires DB access via pool
async fn test_auth_backend_get_user_not_found() -> AnyhowResult<()> {
    // Covers lines 115-116 in user_store.rs
    let pool = create_test_pool();
    let backend = AuthBackend::new(pool.clone());
    let non_existent_user_id = Uuid::new_v4(); // Generate a random UUID

    info!(user_id = %non_existent_user_id, "Attempting to get non-existent user via AuthBackend");

    // Call get_user directly on the backend instance
    let result = backend.get_user(&non_existent_user_id).await;

    info!(user_id = %non_existent_user_id, ?result, "Result from AuthBackend::get_user");

    // Assert that the result is Ok(None)
    assert!(result.is_ok(), "get_user should return Ok even if user not found");
    let user_option = result.unwrap();
    assert!(user_option.is_none(), "get_user should return None for a non-existent user ID");

    Ok(())
    }
    
    // Remove UserCredentials import if no longer needed
    // use scribe_backend::models::users::UserCredentials;
    
    #[tokio::test]
#[ignore] // Requires DB access via pool
async fn test_auth_backend_authenticate_hashing_error() -> AnyhowResult<()> {
    // Covers lines 81, 83-84 in user_store.rs (Err(e) path in authenticate)
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let backend = AuthBackend::new(pool.clone());

    let username = format!("auth_backend_hash_err_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";
    let invalid_hash = "this_is_not_a_valid_bcrypt_hash";

    // 1. Insert user with a valid hash initially
    let user = run_db_op(&pool, {
        let username = username.clone();
        let email = email.clone();
        let password = password.to_string();
        move |conn| insert_test_user_direct(conn, &username, &email, &password) // Add email
    })
    .await
    .with_context(|| format!("Failed to insert test user '{}'/'{}'", username, email))?;
    guard.add_user(user.id);
    info!(user_id = %user.id, %username, %email, "Test user created for hashing error test");

    // 2. Manually update the hash in the DB to an invalid one
    let update_result = run_db_op(&pool, {
        let user_id = user.id;
        move |conn| {
            diesel::update(users::table.find(user_id))
                .set(users::password_hash.eq(invalid_hash))
                .execute(conn)
        }
    })
    .await;
    update_result.context("Failed to update user hash to invalid string")?;
    info!(user_id = %user.id, %username, "Updated password hash to invalid string in DB");

    // 3. Attempt to authenticate using the AuthBackend (using username as identifier)
    let payload = LoginPayload {
        identifier: username.clone(), // Use username as identifier
        password: Secret::new(password.to_string()),
    };

    info!(identifier = %username, "Attempting authentication via AuthBackend with invalid hash in DB");
    let auth_result = backend.authenticate(payload).await;
    info!(identifier = %username, ?auth_result, "Result from AuthBackend::authenticate");

    // 4. Assert that the error is HashingError
    assert!(auth_result.is_err(), "Authentication should fail with invalid hash in DB");
    match auth_result {
        Err(AuthError::HashingError) => {
            info!("Successfully caught expected AuthError::HashingError from AuthBackend::authenticate");
        }
        Err(e) => {
            panic!("Expected AuthError::HashingError, but got {:?}", e);
        }
        Ok(_) => {
            panic!("Expected an error during authentication, but got Ok");
        }
    }

    // Cleanup
    guard.cleanup().await?;
    Ok(())
}
