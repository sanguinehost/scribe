// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.
// Moved from backend/tests/helpers.rs to be accessible by inline tests.

// Make sure all necessary imports from the main crate and external crates are included.
use crate::{
    auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend}, // Use crate::auth and alias Backend
    config::Config,
    llm::gemini_client::build_gemini_client,
    models::{
        character_card::NewCharacter,
        characters::Character,
        chats::{ChatMessage, ChatSession, MessageRole, NewChatMessage, NewChatSession},
        users::{NewUser, User},
    },
    routes::{
        auth::{login_handler, logout_handler, me_handler, register_handler},
        characters::{get_character_handler, list_characters_handler, upload_character_handler},
        chat::chat_routes,
        health::health_check,
    },
    schema, // Use crate::schema
    state::AppState, // Use crate::state
    PgPool, // Use crate::PgPool
};
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use axum_login::{login_required, AuthManagerLayerBuilder};
use bcrypt;
use deadpool_diesel::postgres::{
    Manager as DeadpoolManager, Pool as DeadpoolPool, PoolConfig, Runtime as DeadpoolRuntime,
};
use diesel::prelude::*;
use diesel::RunQueryDsl;
use diesel::SelectableHelper;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use dotenvy::dotenv;
use std::env;
use std::net::TcpListener;
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer};
use tower_sessions::{Expiry, SessionManagerLayer};
use tower::ServiceExt;
use uuid::Uuid;

// Define the embedded migrations macro
// Ensure this path is correct relative to the crate root (src)
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Structure to hold information about the running test application.
#[derive(Clone)] // Clone needed because TestContext clones it
pub struct TestApp {
    pub address: String,
    pub router: Router, // The configured Axum router
    pub db_pool: PgPool,
    // Add other relevant fields, e.g., http client if needed for direct API calls
}

/// Sets up the application state and router for integration testing, WITHOUT spawning a server.
pub async fn spawn_app() -> TestApp {
    // Tracing initialization is handled by #[tracing_test::traced_test] on each test function
    dotenv().ok(); // Load .env for test environment variables

    // --- Database Setup ---
    let db_name = format!("test_db_{}", Uuid::new_v4());
    let base_db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for testing");
    let (main_db_url, _) = base_db_url
        .rsplit_once('/')
        .expect("Invalid DATABASE_URL format");

    let manager_default =
        DeadpoolManager::new(format!("{}/postgres", main_db_url), DeadpoolRuntime::Tokio1);
    let pool_default = DeadpoolPool::builder(manager_default)
        .max_size(1)
        .build()
        .expect("Failed to create default DB pool");
    let conn_default = pool_default
        .get()
        .await
        .expect("Failed to get default DB connection");

    let db_name_clone = db_name.clone();
    conn_default
        .interact(move |conn| {
            diesel::sql_query(format!("DROP DATABASE IF EXISTS \"{}\"", db_name_clone))
                .execute(conn)
                .expect("Failed to drop test DB");
            diesel::sql_query(format!("CREATE DATABASE \"{}\"", db_name_clone))
                .execute(conn)
                .expect("Failed to create test DB");
            Ok::<(), diesel::result::Error>(())
        })
        .await
        .expect("DB interaction failed")
        .expect("Failed to create test DB");

    // Use the original db_name here
    let test_db_url_unquoted = format!("{}/{}", main_db_url, db_name);
    let manager = DeadpoolManager::new(test_db_url_unquoted.clone(), DeadpoolRuntime::Tokio1);
    let pool_config = PoolConfig::default();
    let db_pool = DeadpoolPool::builder(manager)
        .config(pool_config)
        .build()
        .expect("Failed to create test DB pool");

    // Run migrations on the test database
    let conn = db_pool
        .get()
        .await
        .expect("Failed to get test DB connection for migration");
    conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ())) // Discard version info
        .await
        .expect("Migration interact task failed")
        .expect("Failed to run migrations on test DB");

    // --- Listener Setup ---
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://127.0.0.1:{}", port);
    // We get the address but don't actually use the listener to serve

    // --- Auth Setup ---
    let session_store = DieselSessionStore::new(db_pool.clone());
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Required for tests, SessionManagerLayer handles signing/encryption
        .with_same_site(cookie::SameSite::Lax) // Use cookie::SameSite
        .with_expiry(Expiry::OnInactivity(time::Duration::days(1)));

    let auth_backend = AuthBackend::new(db_pool.clone()); // Create backend instance
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer).build();

    // --- AppState ---
    let config = Arc::new(Config::load().expect("Failed to load test configuration"));
    // Build the AI client (requires GOOGLE_API_KEY in env for tests)
    let ai_client = Arc::new(
        build_gemini_client()
            .await
            .expect("Failed to build Gemini client for tests. Is GOOGLE_API_KEY set?"),
    );
    let app_state = AppState::new(db_pool.clone(), config, ai_client);

    // --- Router Setup (mirroring main.rs structure) ---
    // Note: Imports moved to top of file

    let protected_api_routes = Router::new()
        .route("/auth/me", axum::routing::get(me_handler))
        .route("/auth/logout", axum::routing::post(logout_handler))
        .nest(
            "/characters",
            Router::new()
                .route("/upload", axum::routing::post(upload_character_handler))
                .route("/", axum::routing::get(list_characters_handler))
                .route("/{id}", axum::routing::get(get_character_handler)),
        )
        .nest("/chats", chat_routes())
        .route_layer(login_required!(AuthBackend));

    let public_api_routes = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/auth/register", axum::routing::post(register_handler))
        .route("/auth/login", axum::routing::post(login_handler));

    let app_router = Router::new()
        .nest("/api", public_api_routes)
        .nest("/api", protected_api_routes)
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        .with_state(app_state);

    // --- DO NOT Run Server (in background) ---
    // The router will be called directly using oneshot

    TestApp {
        address, // Keep address for building request URIs
        router: app_router, // Return the router for direct calls via oneshot
        db_pool,
    }
}

// --- Database Helper Functions ---

pub async fn create_test_user(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> User {
    let hashed_password =
        bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

    let new_user = NewUser {
        username: username.to_string(),
        password_hash: hashed_password, // Assign String directly
    };

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for create_user");
    conn.interact(move |conn| {
        diesel::insert_into(schema::users::table)
            .values(&new_user)
            .get_result::<User>(conn)
            .expect("Failed to insert test user")
    })
    .await
    .expect("Interact failed for create_user")
}

pub async fn create_test_character(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
) -> Character {
    let new_character = NewCharacter {
        user_id,
        spec: "chara_card_v2".to_string(),
        spec_version: "2.0".to_string(),
        name: name.to_string(),
        description: Some(format!("Description for {}", name)),
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
        extensions: None,
    };

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for create_character");
    conn.interact(move |conn| {
        diesel::insert_into(schema::characters::table)
            .values(&new_character)
            .returning(Character::as_select())
            .get_result::<Character>(conn)
            .expect("Failed to insert test character")
    })
    .await
    .expect("Interact failed for create_character")
}

pub async fn create_test_chat_session(
    pool: &PgPool,
    user_id: Uuid,
    character_id: Uuid,
) -> ChatSession {
    let new_session = NewChatSession {
        user_id,
        character_id,
    };

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for create_chat_session");
    conn.interact(move |conn| {
        diesel::insert_into(schema::chat_sessions::table)
            .values(&new_session)
            .returning(ChatSession::as_returning())
            .get_result::<ChatSession>(conn)
            .expect("Failed to insert test chat session")
    })
    .await
    .expect("Interact failed for create_chat_session")
}

// Helper to fetch a chat session directly from DB (used for verification)
pub async fn get_chat_session_from_db(pool: &PgPool, session_id: Uuid) -> Option<ChatSession> {
    use crate::schema::chat_sessions::dsl::*; // Import dsl for filtering

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for get_chat_session");
    conn.interact(move |conn| {
        chat_sessions
            .filter(id.eq(session_id))
            .select(ChatSession::as_select())
            .first::<ChatSession>(conn)
            .optional() // Return Option<ChatSession>
            .expect("Failed to query test chat session") // Interact should handle Result
    })
    .await
    .expect("Interact failed for get_chat_session")
}

pub async fn create_test_chat_message(
    pool: &PgPool,
    session_id: Uuid,
    message_type: MessageRole,
    content: &str,
) -> ChatMessage {
    let new_message = NewChatMessage {
        session_id,
        message_type,
        content: content.to_string(),
    };

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for create_chat_message");
    conn.interact(move |conn| {
        diesel::insert_into(schema::chat_messages::table)
            .values(&new_message)
            .returning(ChatMessage::as_returning())
            .get_result::<ChatMessage>(conn)
            .expect("Failed to insert test chat message")
    })
    .await
    .expect("Interact failed for create_chat_message")
}

/// Creates a user, logs them in via API call, and returns the session cookie string and the user object.
pub async fn create_test_user_and_login(
    app: &TestApp, // Use TestApp which contains the router
    username: &str,
    password: &str,
) -> (String, User) {
    // 1. Create user directly in DB (simpler than API call)
    let user = create_test_user(&app.db_pool, username, password).await;

    // 2. Simulate login via API call to get the session cookie
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login") // Use the actual login route
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::json!({"username": username, "password": password}).to_string(),
        ))
        .unwrap();

    let response = app
        .router // Use router directly from TestApp
        .clone() // Clone the router to allow multiple uses
        .oneshot(login_request)
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Login request failed in helper"
    );

    // Extract the session cookie
    let session_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("No session cookie found after login")
        .to_str()
        .unwrap()
        .to_string();

    (session_cookie, user)
}

// --- Test Context & Request Extensions ---

/// Provides context for running integration tests, including app state and helper methods.
pub struct TestContext {
    pub app: TestApp, // Store the whole TestApp
    // Add other context if needed, e.g., pre-created users, characters
}

impl TestContext {
    /// Inserts a character directly into the database for test setup.
    pub async fn insert_character(&mut self, user_id: Uuid, name: &str) -> Character {
        create_test_character(&self.app.db_pool, user_id, name).await // Use pool from TestApp
    }

    /// Inserts a chat session directly into the database for test setup.
    pub async fn insert_chat_session(
        &mut self,
        user_id: Uuid,
        character_id: Uuid,
    ) -> ChatSession {
        create_test_chat_session(&self.app.db_pool, user_id, character_id).await // Use pool from TestApp
    }

    /// Inserts a chat message directly into the database for test setup.
    pub async fn insert_chat_message(
        &mut self,
        session_id: Uuid,
        message_type: MessageRole,
        content: &str,
    ) -> ChatMessage {
        create_test_chat_message(&self.app.db_pool, session_id, message_type, content).await // Use pool from TestApp
    }

    // Add other helper methods as needed, e.g., fetching data directly from DB
}

/// Sets up the test application and returns a TestContext.
pub async fn setup_test_app() -> TestContext {
    let test_app = spawn_app().await;
    TestContext {
        app: test_app, // Store the whole TestApp
    }
}
