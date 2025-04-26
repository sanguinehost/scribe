// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.

// Make sure all necessary imports from the main crate and external crates are included.
use crate::{
    auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend}, // Use crate::auth and alias Backend
    config::Config,
    // Ensure build_gemini_client is removed if present
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
    schema,
    state::AppState,
    PgPool,
    vector_db::qdrant_client::QdrantClientService, // Import QdrantClientService
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
use dotenvy::{dotenv}; // Removed var
use std::env;
use std::net::TcpListener;
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer};
use tower_sessions::{Expiry, SessionManagerLayer, cookie}; // Added cookie import here
use tower::ServiceExt;
use uuid::Uuid;
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use std::sync::Mutex; // Only import Mutex, not {Arc, Mutex}
use genai::ModelIden;
use genai::adapter::AdapterKind;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse, MessageContent, Usage};
use bigdecimal::BigDecimal;
// use chrono::{DateTime, Utc}; // Unused imports
use serde_json::Value;
use crate::llm::{AiClient, ChatStream, ChatStreamItem, EmbeddingClient}; // Add EmbeddingClient
use crate::errors::AppError;
use futures::stream::{self}; // Removed StreamExt, Add stream
// use std::pin::Pin; // Unused import
use genai::chat::{ChatStreamEvent, StreamChunk}; // Add import for chatstream types
// use std::path::PathBuf; // Unused import
// use axum::extract::FromRef; // Unused import
// use axum_login::{AuthUser}; // Unused import
use crate::services::embedding_pipeline::{EmbeddingPipelineServiceTrait, RetrievedChunk}; // Import RAG service trait and chunk struct

// Define the embedded migrations macro
// Ensure this path is correct relative to the crate root (src)
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Structure to hold information about the running test application.
#[derive(Clone)]
pub struct TestApp {
    pub address: String,
    pub router: Router,
    pub db_pool: PgPool,
    // Ensure mock clients fields exist
    pub mock_ai_client: Arc<MockAiClient>,
    pub mock_embedding_client: Arc<MockEmbeddingClient>, // Add mock embedding client
    pub mock_embedding_pipeline_service: Arc<MockEmbeddingPipelineService>, // Add mock RAG service
    pub qdrant_service: Arc<QdrantClientService>, // Add Qdrant service
    pub embedding_call_tracker: Arc<tokio::sync::Mutex<Vec<uuid::Uuid>>>, // Add tracker field
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
        .with_name("sid") // Use consistent cookie name
        .with_path("/")   // Set cookie path to root
        .with_expiry(Expiry::OnInactivity(time::Duration::days(1)));

    let auth_backend = AuthBackend::new(db_pool.clone()); // Create backend instance
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer).build();

    // --- AppState ---
    let config = Arc::new(Config::load().expect("Failed to load test configuration"));
    // Ensure Mock AI Client is instantiated
    let mock_ai_client = Arc::new(MockAiClient::new());
    // Ensure Mock Embedding Client is instantiated
    let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
    // Ensure Mock Embedding Pipeline Service is instantiated
    let mock_embedding_pipeline_service = Arc::new(MockEmbeddingPipelineService::new());
    // Create the real Qdrant service for tests (assuming Qdrant is running or mocked appropriately)
    // If Qdrant isn't available during unit/integration tests, this might need mocking too.
    let qdrant_service = Arc::new(
        QdrantClientService::new(config.clone())
            .await
            .expect("Failed to create QdrantClientService for test"),
    );

    // Ensure AppState is created with the mock clients, real Qdrant service,
    // and the tracker (only for test builds).
    let app_state = AppState::new(
        db_pool.clone(),
        config.clone(), // Clone config Arc for AppState
        mock_ai_client.clone(),
        mock_embedding_client.clone(), // Pass mock embedding client
        qdrant_service.clone(), // Pass the real Qdrant service
        mock_embedding_pipeline_service.clone(), // Pass mock RAG service
       );

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
        .with_state(app_state.clone());

    // --- DO NOT Run Server (in background) ---
    // The router will be called directly using oneshot

    TestApp {
        address,
        router: app_router,
        db_pool,
        // Ensure mock clients are stored
        mock_ai_client,
        mock_embedding_client, // Store mock embedding client
        mock_embedding_pipeline_service, // Store mock RAG service
        qdrant_service, // Store Qdrant service
        embedding_call_tracker: app_state.embedding_call_tracker.clone(),
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
            .returning(ChatSession::as_select()) // Use as_select() with returning
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
            .select(ChatSession::as_select()) // Explicitly select fields matching the struct
            .first::<ChatSession>(conn)
            .optional()
            .expect("Failed to query test chat session")
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

/// Helper to update chat settings directly in the DB for testing.
pub async fn update_test_chat_settings(
    pool: &PgPool,
    session_id: Uuid,
    new_system_prompt: Option<String>, // Renamed argument
    new_temperature: Option<BigDecimal>, // Renamed argument
    new_max_output_tokens: Option<i32>, // Renamed argument
) {
    use crate::schema::chat_sessions::dsl::*;
    use diesel::dsl::now;

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for update_test_chat_settings");

    conn.interact(move |conn| {
        diesel::update(chat_sessions.filter(id.eq(session_id)))
            .set((
                system_prompt.eq(new_system_prompt), // Use renamed argument
                temperature.eq(new_temperature), // Use renamed argument
                max_output_tokens.eq(new_max_output_tokens), // Use renamed argument
                updated_at.eq(now),
            ))
            .execute(conn)
            .expect("Failed to update test chat settings")
    })
    .await
    .expect("Interact failed for update_test_chat_settings");
}

/// Updated helper to update all chat settings including new generation params.
pub async fn update_all_chat_settings(
    pool: &PgPool,
    session_id: Uuid,
    new_system_prompt: Option<String>, // Renamed argument
    new_temperature: Option<BigDecimal>, // Renamed argument
    new_max_output_tokens: Option<i32>, // Renamed argument
    new_frequency_penalty: Option<BigDecimal>, // Renamed argument
    new_presence_penalty: Option<BigDecimal>, // Renamed argument
    new_top_k: Option<i32>, // Renamed argument
    new_top_p: Option<BigDecimal>, // Renamed argument
    new_repetition_penalty: Option<BigDecimal>, // Renamed argument
    new_min_p: Option<BigDecimal>, // Renamed argument
    new_top_a: Option<BigDecimal>, // Renamed argument
    new_seed: Option<i32>, // Renamed argument
    new_logit_bias: Option<Value>, // Renamed argument
) {
    use crate::schema::chat_sessions::dsl::*;
    use diesel::dsl::now;

    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for update_all_chat_settings");

    conn.interact(move |conn| {
        diesel::update(chat_sessions.filter(id.eq(session_id)))
            .set((
                system_prompt.eq(new_system_prompt), // Use renamed argument
                temperature.eq(new_temperature), // Use renamed argument
                max_output_tokens.eq(new_max_output_tokens), // Use renamed argument
                frequency_penalty.eq(new_frequency_penalty), // Use renamed argument
                presence_penalty.eq(new_presence_penalty), // Use renamed argument
                top_k.eq(new_top_k), // Use renamed argument
                top_p.eq(new_top_p), // Use renamed argument
                repetition_penalty.eq(new_repetition_penalty), // Use renamed argument
                min_p.eq(new_min_p), // Use renamed argument
                top_a.eq(new_top_a), // Use renamed argument
                seed.eq(new_seed), // Use renamed argument
                logit_bias.eq(new_logit_bias), // Use renamed argument
                updated_at.eq(now),
            ))
            .execute(conn)
            .expect("Failed to update all chat settings")
    })
    .await
    .expect("Interact failed for update_all_chat_settings");
}

/// Helper to get messages directly from DB for a specific session.
pub async fn get_chat_messages_from_db(pool: &PgPool, _session_id: Uuid) -> Vec<ChatMessage> { // Prefixed unused variable
    // Imports needed within this function scope
    use crate::schema::chat_messages::dsl::*;
    use crate::models::chats::ChatMessage; // Ensure ChatMessage model is in scope
    use diesel::prelude::*; // For .filter(), .select(), .order(), .load()

    let conn = pool.get().await.expect("Failed to get DB conn for get_chat_messages_from_db");
    conn.interact(move |conn| {
        chat_messages
            .filter(crate::schema::chat_messages::dsl::session_id.eq(session_id)) // Use dsl namespace
            .select(ChatMessage::as_select())
            .order(created_at.asc())
            .load::<ChatMessage>(conn)
            .expect("Failed to load chat messages in test helper")
    })
    .await.expect("Interact failed for get_chat_messages_from_db")
}

/// Helper to get chat session settings directly from DB.
pub async fn get_chat_session_settings(pool: &PgPool, session_id: Uuid) 
-> Option<(Option<String>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>, Option<BigDecimal>, Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<Value>)> {
    use crate::schema::chat_sessions::dsl::*;
    
    let conn = pool
        .get()
        .await
        .expect("Failed to get DB conn for get_chat_session_settings");

    conn.interact(move |conn| {
        chat_sessions
            .filter(id.eq(session_id))
            .select((
                system_prompt, 
                temperature, 
                max_output_tokens,
                frequency_penalty,
                presence_penalty,
                top_k,
                top_p,
                repetition_penalty,
                min_p,
                top_a,
                seed,
                logit_bias
            ))
            .first::<(
                Option<String>, 
                Option<BigDecimal>, 
                Option<i32>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<i32>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<i32>,
                Option<Value>
            )>(conn)
            .optional()
            .expect("Failed to query test chat session settings")
    })
    .await
    .expect("Interact failed for get_chat_session_settings")
}

/// Creates a user, logs them in via API call, and returns the session cookie string and the user object.
pub async fn create_test_user_and_login(
    app: &TestApp, // TestApp now includes mock_ai_client
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

    // Extract the session cookie with better error handling
    let response_headers = response.headers();
    
    // Log all headers to debug cookie issues
    tracing::debug!("Login response headers: {:?}", response_headers);
    
    // Look for Set-Cookie or set-cookie header (case-insensitive)
    let session_cookie = if let Some(cookie_header) = response_headers.get(header::SET_COOKIE) {
        cookie_header.to_str().unwrap().to_string()
    } else {
        // Try a fallback approach - iterate through headers to find any Set-Cookie variants
        let mut cookie_header_val = None;
        for (name, value) in response_headers.iter() {
            if name.as_str().to_lowercase() == "set-cookie" {
                cookie_header_val = Some(value.to_str().unwrap().to_string());
                break;
            }
        }
        
        cookie_header_val.expect("No session cookie found in response headers after login")
    };

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
    TestContext { app: test_app }
}

// --- Helpers needed by integration tests ---

// ** ADDED pub **
/// Helper function to create a deadpool pool for integration tests
pub fn create_test_pool() -> DeadpoolPool { // Removed <DeadpoolManager>
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = DeadpoolManager::new(&database_url, DeadpoolRuntime::Tokio1);
    DeadpoolPool::builder(manager)
        .build()
        .expect("Failed to create test DB pool.")
}

// ** ADDED pub **
/// Helper struct to manage test data cleanup for integration tests
pub struct TestDataGuard {
    pool: DeadpoolPool,
    user_ids: Vec<Uuid>,
    character_ids: Vec<Uuid>,
    // Add session IDs if needed for cleanup
    session_ids: Vec<Uuid>,
}

// ** ADDED pub to impl and methods **
impl TestDataGuard {
    pub fn new(pool: DeadpoolPool) -> Self { // Removed <DeadpoolManager>
        TestDataGuard {
            pool,
            user_ids: Vec::new(),
            character_ids: Vec::new(),
            session_ids: Vec::new(), // Initialize session IDs
        }
    }

    pub fn add_user(&mut self, user_id: Uuid) {
        self.user_ids.push(user_id);
    }

    pub fn add_character(&mut self, character_id: Uuid) {
        self.character_ids.push(character_id);
    }

    pub fn add_session(&mut self, session_id: Uuid) {
        self.session_ids.push(session_id);
    }


    // Explicit async cleanup function
    pub async fn cleanup(self) -> Result<(), anyhow::Error> {
        if self.character_ids.is_empty() && self.user_ids.is_empty() && self.session_ids.is_empty() {
             return Ok(());
        }
        tracing::debug!(user_ids = ?self.user_ids, character_ids = ?self.character_ids, session_ids = ?self.session_ids, "--- Cleaning up test data ---");

        let pool_clone = self.pool.clone(); // Use self.pool
        let obj = pool_clone.get().await.context("Failed to get DB connection for cleanup")?;

        let character_ids_to_delete = self.character_ids.clone();
        let user_ids_to_delete = self.user_ids.clone();
        let session_ids_to_delete = self.session_ids.clone();

        // Delete messages first (FK to sessions)
        if !session_ids_to_delete.is_empty() {
             obj.interact({
                let ids = session_ids_to_delete.clone(); // Clone for closure
                move |conn| {
                    diesel::delete(
                        schema::chat_messages::table.filter(schema::chat_messages::session_id.eq_any(ids))
                    )
                    .execute(conn)
                }
            }).await.map_err(|e| anyhow::anyhow!("Interact error deleting messages: {:?}", e))?
              .map_err(|e| anyhow::Error::new(e).context("DB error deleting messages"))?;
             tracing::debug!("Cleaned up messages for {} sessions.", session_ids_to_delete.len());
        }


        // Delete sessions (FK to users, characters)
        if !session_ids_to_delete.is_empty() {
             obj.interact(move |conn| {
                diesel::delete(
                    schema::chat_sessions::table.filter(schema::chat_sessions::id.eq_any(session_ids_to_delete))
                )
                .execute(conn)
            }).await.map_err(|e| anyhow::anyhow!("Interact error deleting sessions: {:?}", e))?
              .map_err(|e| anyhow::Error::new(e).context("DB error deleting sessions"))?;
             tracing::debug!("Cleaned up {} sessions.", self.session_ids.len());
        }

        // Delete characters (FK to users)
        if !character_ids_to_delete.is_empty() {
            obj.interact({ // Use block to manage clone lifetime
                let ids = character_ids_to_delete.clone();
                move |conn| {
                    diesel::delete(
                        schema::characters::table.filter(schema::characters::id.eq_any(ids))
                    )
                    .execute(conn)
                }
            }).await.map_err(|e| anyhow::anyhow!("Interact error deleting characters: {:?}", e))?
              .map_err(|e| anyhow::Error::new(e).context("DB error deleting characters"))?;
            tracing::debug!("Cleaned up {} characters.", self.character_ids.len());
        }

        // Delete users
        if !user_ids_to_delete.is_empty() {
            obj.interact(move |conn| {
                diesel::delete(schema::users::table.filter(schema::users::id.eq_any(user_ids_to_delete)))
                .execute(conn)
            }).await.map_err(|e| anyhow::anyhow!("Interact error deleting users: {:?}", e))?
              .map_err(|e| anyhow::Error::new(e).context("DB error deleting users"))?;
            tracing::debug!("Cleaned up {} users.", self.user_ids.len());
        }

        tracing::debug!("--- Cleanup complete ---");
        Ok(())
    }
}

// ** ADDED pub **
/// Helper function to initialize tracing safely for integration tests
pub fn ensure_tracing_initialized() {
    use std::sync::Once;
    use tracing_subscriber::{EnvFilter, fmt};
    static TRACING_INIT: Once = Once::new();
    TRACING_INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn,tower_http=debug".into());
        fmt().with_env_filter(filter).init();
    });
}


// --- Mock AI Client for Testing ---

/// Mock AI client for testing
#[derive(Clone)]
pub struct MockAiClient {
    // Store the last request received in a thread-safe manner
    last_request: Arc<Mutex<Option<ChatRequest>>>,
    // Store the last options received
    last_options: Arc<Mutex<Option<ChatOptions>>>,
    // Response for non-streaming calls
    response_to_return: Arc<Mutex<Result<ChatResponse, AppError>>>,
    // Stream items for streaming calls
    stream_to_return: Arc<Mutex<Option<Vec<ChatStreamItem>>>>,
}

impl MockAiClient {
    pub fn new() -> Self {
        Self {
            last_request: Arc::new(Mutex::new(None)),
            last_options: Arc::new(Mutex::new(None)),
            // Default to a simple OK response
            response_to_return: Arc::new(Mutex::new(Ok(ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "mock-model"),
                content: Some(MessageContent::Text("Mock AI response".to_string())),
                reasoning_content: None,
                usage: Usage::default(),
            }))),
            stream_to_return: Arc::new(Mutex::new(None)),
        }
    }

    /// Retrieves the last ChatRequest captured by the mock client.
    pub fn get_last_request(&self) -> Option<ChatRequest> {
        self.last_request.lock().unwrap().clone()
    }

    /// Retrieves the last ChatOptions captured by the mock client.
    pub fn get_last_options(&self) -> Option<ChatOptions> {
        self.last_options.lock().unwrap().clone()
    }

    /// Sets the non-streaming response that the mock client should return.
    pub fn set_response(&self, response: Result<ChatResponse, AppError>) {
        let mut lock = self.response_to_return.lock().unwrap();
        *lock = response;
    }

    /// Sets the stream items that the mock client should return for stream_chat.
    pub fn set_stream_response(&self, stream_items: Vec<ChatStreamItem>) {
        let mut lock = self.stream_to_return.lock().unwrap();
        *lock = Some(stream_items);
    }
}

#[async_trait]
impl AiClient for MockAiClient {
    async fn exec_chat(
        &self,
        _model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>, // Use ChatOptions
    ) -> Result<ChatResponse, AppError> {
        // Store the received request and options
        *self.last_request.lock().unwrap() = Some(request);
        *self.last_options.lock().unwrap() = config_override;

        // Simulate some processing delay if needed
        // tokio::time::sleep(Duration::from_millis(10)).await;

        // Clone the response to return
        self.response_to_return.lock().unwrap().clone()
    }

    async fn stream_chat(
        &self,
        _model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        // Store the received request and options
        *self.last_request.lock().unwrap() = Some(request);
        *self.last_options.lock().unwrap() = config_override;

        // Simulate some processing delay if needed
        // tokio::time::sleep(Duration::from_millis(10)).await;

        // Retrieve the stream items to return
        // Revert to manual reconstruction as ChatStreamEvent is not Clone
        let guard = self.stream_to_return.lock().unwrap();
        let stream_items = match &*guard {
            Some(items) => {
                // Manually create a new Vec since ChatStreamEvent is not Clone
                let mut new_items = Vec::with_capacity(items.len());
                for item in items {
                    // For each Result item, rebuild it with a new ChatStreamEvent
                    match item {
                        Ok(event) => {
                            match event {
                                ChatStreamEvent::Chunk(chunk) => {
                                    // Create a new chunk with same content
                                    new_items.push(Ok(ChatStreamEvent::Chunk(
                                        StreamChunk { content: chunk.content.clone() }
                                    )));
                                },
                                ChatStreamEvent::Start => {
                                    new_items.push(Ok(ChatStreamEvent::Start));
                                },
                                ChatStreamEvent::ReasoningChunk(chunk) => {
                                     new_items.push(Ok(ChatStreamEvent::ReasoningChunk(
                                        StreamChunk { content: chunk.content.clone() }
                                    )));
                                },
                                ChatStreamEvent::End(end_event) => {
                                    // StreamEnd is not Clone, use Default instead
                                    new_items.push(Ok(ChatStreamEvent::End(Default::default()))); 
                                },
                                // Handle other potential future ChatStreamEvent variants if necessary
                                // _ => { 
                                //     // Default handling or panic if unexpected event types appear
                                //     new_items.push(Err(AppError::InternalServerError("Unhandled mock stream event type".to_string())));
                                // }                                
                            }
                        },
                        Err(err) => {
                            // Create a new AppError (assuming AppError is Clone)
                            new_items.push(Err(err.clone()));
                        }
                    }
                }
                new_items
            },
            None => Vec::<ChatStreamItem>::new(), // Create empty Vec with correct type
        };
        drop(guard); // Release the mutex guard

        // Create a stream from the vector of items
        let stream = stream::iter(stream_items);
        let boxed_stream: ChatStream = Box::pin(stream);
        Ok(boxed_stream)
    }
}


// --- Mock Embedding Client for Testing ---

#[derive(Clone)]
pub struct MockEmbeddingClient {
    response_to_return: Arc<Mutex<Result<Vec<f32>, AppError>>>,
    calls: Arc<Mutex<Vec<(String, String)>>>, // Store (text, task_type) tuples
}

impl MockEmbeddingClient {
    pub fn new() -> Self {
        Self {
            response_to_return: Arc::new(Mutex::new(Ok(vec![0.1, 0.2, 0.3]))), // Default OK response
            calls: Arc::new(Mutex::new(Vec::new())), // Initialize with empty history
        }
    }

    pub fn set_response(&self, response: Result<Vec<f32>, AppError>) {
        let mut lock = self.response_to_return.lock().unwrap();
        *lock = response;
    }

    // Method to retrieve the call history
    pub fn get_calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }

    // Method to clear call history (optional, might be useful between test steps)
    // pub fn clear_calls(&self) {
    //     self.calls.lock().unwrap().clear();
    // }
}

#[async_trait]
impl EmbeddingClient for MockEmbeddingClient {
    async fn embed_content(
        &self,
        text: &str,
        task_type: &str,
    ) -> Result<Vec<f32>, AppError> {
        // Store the received text and task type in history
        self.calls.lock().unwrap().push((text.to_string(), task_type.to_string()));

        // Clone the response to return
        self.response_to_return.lock().unwrap().clone()
    }
}


// --- Mock Embedding Pipeline Service for Testing ---

#[derive(Clone)]
pub struct MockEmbeddingPipelineService {
    response_to_return: Arc<Mutex<Result<Vec<RetrievedChunk>, AppError>>>,
    last_chat_id: Arc<Mutex<Option<Uuid>>>,
    last_query_text: Arc<Mutex<Option<String>>>,
    last_limit: Arc<Mutex<Option<u64>>>,
}

impl MockEmbeddingPipelineService {
    pub fn new() -> Self {
        Self {
            response_to_return: Arc::new(Mutex::new(Ok(Vec::new()))), // Default empty vec
            last_chat_id: Arc::new(Mutex::new(None)),
            last_query_text: Arc::new(Mutex::new(None)),
            last_limit: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_response(&self, response: Result<Vec<RetrievedChunk>, AppError>) {
        let mut lock = self.response_to_return.lock().unwrap();
        *lock = response;
    }

    pub fn get_last_chat_id(&self) -> Option<Uuid> {
        self.last_chat_id.lock().unwrap().clone()
    }

    pub fn get_last_query_text(&self) -> Option<String> {
        self.last_query_text.lock().unwrap().clone()
    }

    pub fn get_last_limit(&self) -> Option<u64> {
        self.last_limit.lock().unwrap().clone()
    }
}

#[async_trait]
impl EmbeddingPipelineServiceTrait for MockEmbeddingPipelineService {
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>, // Use the state argument
        chat_id: Uuid,
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Record the arguments received
        *self.last_chat_id.lock().unwrap() = Some(chat_id);
        *self.last_query_text.lock().unwrap() = Some(query_text.to_string());
        *self.last_limit.lock().unwrap() = Some(limit);

        // --- ADDED: Call the actual embedding client from state ---
        let task_type = "RETRIEVAL_QUERY";
        let _embedding_vector = state // Use state
            .embedding_client // Access the client (should be the mock in tests)
            .embed_content(query_text, task_type)
            .await?;
        // We don't need the vector itself in the mock, just need to ensure the call happens
        // ---------------------------------------------------------

        // Simulate some processing delay if needed
        // tokio::time::sleep(Duration::from_millis(5)).await;

        // Return the pre-configured response
        self.response_to_return.lock().unwrap().clone()
    }
}

// --- AppState Builder for Tests ---

// Builder struct for AppState, making it easier to construct in tests
#[derive(Default)]
pub struct AppStateBuilder { // Make the builder public
    pool: Option<PgPool>,
    config: Option<Arc<Config>>,
    ai_client: Option<Arc<dyn AiClient + Send + Sync>>,
    mock_embedding_client: Option<Arc<MockEmbeddingClient>>,
    mock_embedding_pipeline_service: Option<Arc<MockEmbeddingPipelineService>>,
    qdrant_service: Option<Arc<QdrantClientService>>,
    embedding_call_tracker: Option<Arc<tokio::sync::Mutex<Vec<uuid::Uuid>>>>,
}

// Add the missing implementation block for the builder
impl AppStateBuilder { 
    // New function (constructor)
    pub fn new() -> Self { 
        Self::default()
    }

    // Methods to set optional fields
    pub fn with_pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_ai_client(mut self, client: Arc<dyn AiClient + Send + Sync>) -> Self {
        self.ai_client = Some(client);
        self
    }
    
    pub fn with_embedding_client(mut self, client: Arc<MockEmbeddingClient>) -> Self {
        self.mock_embedding_client = Some(client);
        self
    }

    pub fn with_embedding_pipeline_service(mut self, service: Arc<MockEmbeddingPipelineService>) -> Self {
        self.mock_embedding_pipeline_service = Some(service);
        self
    }
    
    pub fn with_qdrant_service(mut self, service: Arc<QdrantClientService>) -> Self {
        self.qdrant_service = Some(service);
        self
    }

    pub fn with_embedding_call_tracker(mut self, tracker: Arc<tokio::sync::Mutex<Vec<uuid::Uuid>>>) -> Self {
        self.embedding_call_tracker = Some(tracker);
        self
    }

    // Build method for simplified test setup (might need refinement)
    pub async fn build_for_test(self) -> Result<Arc<AppState>, String> {
        let config = self.config.unwrap_or_else(|| Arc::new(Config::load().expect("Test config load failed")));
        // For unit tests, we often don't need a real pool
        let pool = self.pool.unwrap_or_else(|| create_test_pool()); // Use helper to create a pool
        // Default to mock AI client if not provided
        let ai_client = self.ai_client.unwrap_or_else(|| Arc::new(MockAiClient::new()));
        // Default to mock embedding client
        let embedding_client = self.mock_embedding_client.unwrap_or_else(|| Arc::new(MockEmbeddingClient::new()));
        // Default to mock embedding pipeline service
        let embedding_pipeline_service = self.mock_embedding_pipeline_service.unwrap_or_else(|| Arc::new(MockEmbeddingPipelineService::new()));
        // Default to real Qdrant service (might fail if Qdrant not running).
        // This assumes config (e.g., QDRANT_URL) is available in the test environment.
        // Tests mocking the pipeline service won't actually use this Qdrant client.
        let qdrant_service = match self.qdrant_service {
            Some(service) => service,
            None => Arc::new(QdrantClientService::new_test_dummy()),
        };
        // Default tracker
        let tracker = self.embedding_call_tracker.unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(Vec::new())));
        
        // Construct the real AppState
        let state = AppState {
            pool,
            config,
            ai_client,
            embedding_client: embedding_client as Arc<dyn EmbeddingClient>, // Cast mock to trait object
            qdrant_service, // Assume type matches AppState field
            embedding_pipeline_service: embedding_pipeline_service as Arc<dyn EmbeddingPipelineServiceTrait>, // Cast mock to trait object
            embedding_call_tracker: tracker,
        };

        Ok(Arc::new(state))
    }
}

// --- End AppState Builder Implementation ---
