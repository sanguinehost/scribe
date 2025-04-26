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
        chats::{ChatMessage, ChatSession, MessageRole},
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
    vector_db::qdrant_client::QdrantClientService, // Import constants module alias
};
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use axum_login::{login_required, AuthManagerLayerBuilder};
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
use tower_cookies::{CookieManagerLayer};
use tower_sessions::{Expiry, SessionManagerLayer, cookie}; // Added cookie import here
use tower::ServiceExt;
use uuid::Uuid;
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse};
use bigdecimal::BigDecimal;
use serde_json::Value;
use crate::llm::{AiClient, ChatStream, EmbeddingClient}; // Add EmbeddingClient
use crate::errors::AppError;
use genai::chat::ChatStreamEvent; // Add import for chatstream types
use crate::services::embedding_pipeline::{EmbeddingPipelineServiceTrait, RetrievedChunk};
use qdrant_client::qdrant::{PointId, Filter, ScoredPoint};
use std::sync::{Arc, Mutex};
use tracing::warn;
use crate::vector_db::qdrant_client::{QdrantClientServiceTrait, PointStruct};

// --- START Placeholder Mock Definitions ---
// TODO: Implement proper mocks based on required functionality

#[derive(Clone)]
pub struct MockAiClient {
    // Add fields to store mock state, similar to previous mock impl
    // These need Arc<Mutex<...>> for thread safety if mock is shared across awaits
    last_request: std::sync::Arc<std::sync::Mutex<Option<ChatRequest>>>,
    last_options: std::sync::Arc<std::sync::Mutex<Option<ChatOptions>>>,
    response_to_return: std::sync::Arc<std::sync::Mutex<Result<ChatResponse, AppError>>>,
    stream_to_return: std::sync::Arc<std::sync::Mutex<Option<Vec<Result<ChatStreamEvent, AppError>>>>>,
}

impl MockAiClient {
    pub fn new() -> Self { 
        // Initialize fields with default values
        Self {
            last_request: Default::default(),
            last_options: Default::default(),
            // Default to a simple OK response
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(ChatResponse {
                model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"), // Placeholder iden
                provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
                content: Some(genai::chat::MessageContent::Text("Mock AI response".to_string())),
                reasoning_content: None,
                usage: Default::default(),
            }))),
            stream_to_return: Default::default(),
        }
    }

    // Add placeholder methods called by tests
    pub fn get_last_request(&self) -> Option<ChatRequest> {
        // TODO: Implement mock logic
        self.last_request.lock().unwrap().clone()
    }

    pub fn get_last_options(&self) -> Option<ChatOptions> {
        // TODO: Implement mock logic
        self.last_options.lock().unwrap().clone()
    }

    pub fn set_response(&self, response: Result<ChatResponse, AppError>) {
        // TODO: Implement mock logic
        *self.response_to_return.lock().unwrap() = response;
    }

    pub fn set_stream_response(&self, stream_items: Vec<Result<ChatStreamEvent, AppError>>) {
        // TODO: Implement mock logic
        *self.stream_to_return.lock().unwrap() = Some(stream_items);
    }
}

// Basic trait implementation to satisfy AppState::new
#[async_trait]
impl AiClient for MockAiClient {
    async fn exec_chat(&self, _model_name: &str, request: ChatRequest, config_override: Option<ChatOptions>) -> Result<ChatResponse, AppError> {
        *self.last_request.lock().unwrap() = Some(request);
        *self.last_options.lock().unwrap() = config_override;
        // TODO: Implement proper mock logic using stored response
        self.response_to_return.lock().unwrap().clone()
        // unimplemented!("MockAiClient exec_chat not implemented")
    }
    async fn stream_chat(&self, _model_name: &str, request: ChatRequest, config_override: Option<ChatOptions>) -> Result<ChatStream, AppError> {
        *self.last_request.lock().unwrap() = Some(request);
        *self.last_options.lock().unwrap() = config_override;

        // Manually reconstruct the stream items because ChatStreamEvent is not Clone
        let items = {
            let guard = self.stream_to_return.lock().unwrap();
            match &*guard {
                Some(item_results) => {
                    let mut new_items = Vec::with_capacity(item_results.len());
                    for item_result in item_results {
                        match item_result {
                            Ok(event) => {
                                // Rebuild the event based on its type
                                let new_event = match event {
                                    ChatStreamEvent::Chunk(chunk) => 
                                        ChatStreamEvent::Chunk(genai::chat::StreamChunk { content: chunk.content.clone() }),
                                    ChatStreamEvent::Start => ChatStreamEvent::Start,
                                    ChatStreamEvent::ReasoningChunk(chunk) => 
                                        ChatStreamEvent::ReasoningChunk(genai::chat::StreamChunk { content: chunk.content.clone() }),
                                    ChatStreamEvent::End(_end_event) => 
                                        ChatStreamEvent::End(Default::default()), // StreamEnd is not Clone, use Default
                                };
                                new_items.push(Ok(new_event));
                            },
                            Err(err) => {
                                // Clone the error (assuming AppError is Clone)
                                new_items.push(Err(err.clone()));
                            }
                        }
                    }
                    new_items
                },
                None => Vec::new(), // Return empty Vec if None
            }
        }; // Mutex guard is dropped here
        
        let stream = futures::stream::iter(items);
        Ok(Box::pin(stream) as ChatStream)
    }
}

#[derive(Clone)]
pub struct MockEmbeddingClient {
    response: Arc<Mutex<Option<Result<Vec<f32>, AppError>>>>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockEmbeddingClient {
    pub fn new() -> Self { 
        MockEmbeddingClient {
            response: Arc::new(Mutex::new(None)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_response(&self, response: Result<Vec<f32>, AppError>) {
        let mut lock = self.response.lock().unwrap();
        *lock = Some(response);
    }

    pub fn get_calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl EmbeddingClient for MockEmbeddingClient {
    async fn embed_content(&self, text: &str, task_type: &str) -> Result<Vec<f32>, AppError> {
        // Record the call
        self.calls.lock().unwrap().push((text.to_string(), task_type.to_string()));
        
        // Return the pre-set response or a default
        match self.response.lock().unwrap().clone() {
            Some(res) => res,
            None => {
                // Default behavior if no response is set
                Ok(vec![0.0; 768])
            }
        }
    }
}

#[derive(Clone, Debug)] // Added Clone, Debug
pub enum PipelineCall {
    RetrieveRelevantChunks {
        chat_id: Uuid,
        query_text: String,
        limit: u64,
    },
    // Add other calls if the mock needs to track more interactions
}

// Updated MockEmbeddingPipelineService
#[derive(Clone)] // Added Clone
pub struct MockEmbeddingPipelineService {
    retrieve_response: Arc<Mutex<Option<Result<Vec<RetrievedChunk>, AppError>>>>,
    calls: Arc<Mutex<Vec<PipelineCall>>>, // Track calls
}

impl MockEmbeddingPipelineService {
    pub fn new() -> Self {
        MockEmbeddingPipelineService {
            retrieve_response: Arc::new(Mutex::new(None)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_calls(&self) -> Vec<PipelineCall> {
        self.calls.lock().unwrap().clone()
    }

    pub fn set_retrieve_response(&self, response: Result<Vec<RetrievedChunk>, AppError>) {
        let mut lock = self.retrieve_response.lock().unwrap();
        *lock = Some(response);
    }
}

#[async_trait]
impl EmbeddingPipelineServiceTrait for MockEmbeddingPipelineService {
    async fn retrieve_relevant_chunks(&self, _state: Arc<AppState>, chat_id: Uuid, query_text: &str, limit: u64) -> Result<Vec<RetrievedChunk>, AppError> {
        // Record the call
        self.calls.lock().unwrap().push(PipelineCall::RetrieveRelevantChunks {
            chat_id,
            query_text: query_text.to_string(),
            limit,
        });

        // Return the pre-set response or a default
        let response = self.retrieve_response.lock().unwrap().take();
        match response {
            Some(res) => res,
            None => {
                // Default behavior if no response is set
                warn!("MockEmbeddingPipelineService::retrieve_relevant_chunks called without a pre-set response, returning Ok(vec![])");
                Ok(vec![])
            }
        }
    }
}

#[derive(Clone)]
pub struct MockQdrantClientService {
    upsert_response: Arc<Mutex<Option<Result<(), AppError>>>>,
    search_response: Arc<Mutex<Option<Result<Vec<ScoredPoint>, AppError>>>>,
    upsert_call_count: Arc<Mutex<usize>>,
    search_call_count: Arc<Mutex<usize>>,
    last_upsert_points: Arc<Mutex<Option<Vec<qdrant_client::qdrant::PointStruct>>>>,
    last_search_params: Arc<Mutex<Option<(Vec<f32>, u64, Option<Filter>)>>>,
}

impl MockQdrantClientService {
    pub fn new() -> Self {
        MockQdrantClientService {
            upsert_response: Arc::new(Mutex::new(None)),
            search_response: Arc::new(Mutex::new(None)),
            upsert_call_count: Arc::new(Mutex::new(0)),
            search_call_count: Arc::new(Mutex::new(0)),
            last_upsert_points: Arc::new(Mutex::new(None)),
            last_search_params: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_upsert_response(&self, response: Result<(), AppError>) {
        let mut lock = self.upsert_response.lock().unwrap();
        *lock = Some(response);
    }

    pub fn get_upsert_call_count(&self) -> usize {
        *self.upsert_call_count.lock().unwrap()
    }

    pub fn get_last_upsert_points(&self) -> Option<Vec<qdrant_client::qdrant::PointStruct>> {
        self.last_upsert_points.lock().unwrap().clone()
    }

    pub fn set_search_response(&self, response: Result<Vec<ScoredPoint>, AppError>) {
         let mut lock = self.search_response.lock().unwrap();
        *lock = Some(response);
    }

    pub fn get_search_call_count(&self) -> usize {
        *self.search_call_count.lock().unwrap()
    }

    pub fn get_last_search_params(&self) -> Option<(Vec<f32>, u64, Option<Filter>)> {
        self.last_search_params.lock().unwrap().clone()
    }

    pub async fn upsert_points(&self, points: Vec<qdrant_client::qdrant::PointStruct>) -> Result<(), AppError> {
        // Track call
        {
            let mut count = self.upsert_call_count.lock().unwrap();
            *count += 1;
            
            let mut last_points = self.last_upsert_points.lock().unwrap();
            *last_points = Some(points.clone());
        }
        
        // Return response
        let response = self.upsert_response.lock().unwrap().take();
        response.unwrap_or(Ok(()))
    }

    pub async fn search_points(&self, query_vector: Vec<f32>, limit: u64, filter: Option<Filter>) -> Result<Vec<ScoredPoint>, AppError> {
        // Track call
        {
            let mut count = self.search_call_count.lock().unwrap();
            *count += 1;
            
            let mut last_params = self.last_search_params.lock().unwrap();
            *last_params = Some((query_vector.clone(), limit, filter.clone()));
        }
        
        // Return response
        let response = self.search_response.lock().unwrap().take();
        response.unwrap_or(Ok(vec![]))
    }
}

// Implement the QdrantClientServiceTrait for MockQdrantClientService
#[async_trait]
impl QdrantClientServiceTrait for MockQdrantClientService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }

    async fn store_points(&self, points: Vec<PointStruct>) -> Result<(), AppError> {
        // Track call
        {
            let mut count = self.upsert_call_count.lock().unwrap();
            *count += 1;
            
            let mut last_points = self.last_upsert_points.lock().unwrap();
            *last_points = Some(points.clone());
        }
        
        // Return response
        let response = self.upsert_response.lock().unwrap().take();
        response.unwrap_or(Ok(()))
    }

    async fn search_points(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Track call
        {
            let mut count = self.search_call_count.lock().unwrap();
            *count += 1;
            
            let mut last_params = self.last_search_params.lock().unwrap();
            *last_params = Some((vector.clone(), limit, filter.clone()));
        }
        
        // Return response
        let response = self.search_response.lock().unwrap().take();
        response.unwrap_or(Ok(vec![]))
    }

    async fn retrieve_points(&self, _filter: Option<Filter>, _limit: u64) -> Result<Vec<ScoredPoint>, AppError> {
        // Use the search response for retrieve as well
        let response = self.search_response.lock().unwrap().take();
        response.unwrap_or(Ok(vec![]))
    }

    async fn delete_points(&self, _point_ids: Vec<PointId>) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }

    async fn update_collection_settings(&self) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }
}

// --- END Placeholder Mock Definitions ---

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

// --- Modules containing test helpers ---

pub mod db {
    // Re-import necessary types within the module
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness;
    // Import common types from super, explicitly add NewChatSession from crate::models
    use super::{PgPool, Uuid, DeadpoolManager, DeadpoolPool, DeadpoolRuntime, MIGRATIONS, User, NewUser, Character, NewCharacter, ChatSession, ChatMessage, MessageRole, schema, BigDecimal, Value, RunQueryDsl, SelectableHelper};
    use crate::models::chats::NewChatSession; // <<< Add this import
    use crate::models::chats::DbInsertableChatMessage;
    // Import specifics needed within this module
    use std::env;
    use dotenvy::dotenv;
    use bcrypt;
    // Removed duplicate diesel::SelectableHelper import
    

    /// Sets up a clean test database with migrations run.
    pub async fn setup_test_database(db_name_suffix: Option<&str>) -> PgPool {
        dotenv().ok(); // Load .env
        let db_name = format!(
            "test_db_{}_{}",
            db_name_suffix.unwrap_or("default"),
            Uuid::new_v4()
        );
        let base_db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for testing");
        let (main_db_url, _) = base_db_url.rsplit_once('/').expect("Invalid DATABASE_URL");

        // Create a connection pool to the default database (e.g., postgres) to create the test database
        let manager_default = DeadpoolManager::new(format!("{}/postgres", main_db_url), DeadpoolRuntime::Tokio1);
        let pool_default = DeadpoolPool::builder(manager_default).max_size(1).build().expect("Failed to create default DB pool");
        let conn_default = pool_default.get().await.expect("Failed to get default DB connection");

        // Drop and Create the test database
        let db_name_clone_drop = db_name.clone();
        let db_name_clone_create = db_name.clone();
        conn_default.interact(move |conn| {
            diesel::sql_query(format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", db_name_clone_drop)).execute(conn)?; // Added WITH (FORCE)
            diesel::sql_query(format!("CREATE DATABASE \"{}\"", db_name_clone_create)).execute(conn)?;        
            Ok::<(), diesel::result::Error>(())
        }).await.expect("DB interaction failed").expect("Failed to create test DB");

        // Create a connection pool to the newly created test database
        let test_db_url = format!("{}/{}", main_db_url, db_name);
        let manager = DeadpoolManager::new(test_db_url, DeadpoolRuntime::Tokio1);
        let pool = DeadpoolPool::builder(manager).build().expect("Failed to create test DB pool");

        // Run migrations on the test database
        let conn = pool.get().await.expect("Failed to get test DB connection for migration");
        conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
            .await.expect("Migration task failed").expect("Failed to run migrations");

        pool
    }

    pub async fn create_test_user(
        pool: &PgPool,
        username: &str,
        password: &str,
    ) -> User {
        let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash password");
        let new_user = NewUser {
            username: username.to_string(),
            password_hash: hashed_password,
        };
        let conn = pool.get().await.expect("Failed to get DB conn");
        conn.interact(move |conn| {
            diesel::insert_into(schema::users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result(conn)
        }).await.expect("Interact failed").expect("Failed to insert user")
    }

    pub async fn create_test_character(
        pool: &PgPool,
        user_id: Uuid,
        name: &str,
    ) -> Character {
        let new_char = NewCharacter {
            user_id,
            spec: "chara_card_v2".to_string(), // Field from models::character_card
            spec_version: "2.0".to_string(),  // Field from models::character_card
            name: name.to_string(),
            description: Some("Test description".to_string()),
            personality: Some("Test personality".to_string()),
            scenario: Some("Test scenario".to_string()),
            first_mes: Some("Test first message".to_string()),
            mes_example: Some("Test message example".to_string()),
            creator_notes: None,
            system_prompt: None,
            post_history_instructions: None,
            tags: None,
            creator: Some("Test Creator".to_string()),
            character_version: Some("1.0".to_string()),
            alternate_greetings: None,
            // Removed fields not in NewCharacter: character_id, avatar_uri
            nickname: None,
            creator_notes_multilingual: None,
            source: None,
            group_only_greetings: None,
            creation_date: None,
            modification_date: None,
            extensions: None,
        };
        let conn = pool.get().await.expect("Failed to get DB conn");
         conn.interact(move |conn| {
            diesel::insert_into(schema::characters::table)
                .values(&new_char)
                .returning(Character::as_returning())
                .get_result(conn)
        }).await.expect("Interact failed").expect("Failed to insert character")
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
        let conn = pool.get().await.expect("Failed to get DB conn");
        conn.interact(move |conn| {
            diesel::insert_into(schema::chat_sessions::table)
                .values(&new_session)
                .returning(ChatSession::as_returning())
                .get_result(conn)
        }).await.expect("Interact failed").expect("Failed to insert chat session")
    }
    
    pub async fn get_chat_session_from_db(pool: &PgPool, session_id: Uuid) -> Option<ChatSession> {
        use crate::schema::chat_sessions::dsl::*;
        let conn = pool.get().await.expect("Failed to get DB conn");
        conn.interact(move |conn| {
            chat_sessions
                .filter(id.eq(session_id))
                .select(ChatSession::as_select())
                .first(conn)
                .optional()
        }).await.expect("Interact failed").expect("Query failed")
    }

    pub async fn create_test_chat_message(
        pool: &PgPool,
        session_id: Uuid,
        user_id: Uuid,
        message_type: MessageRole,
        content: &str,
    ) -> ChatMessage {
        // Use DbInsertableChatMessage which includes user_id
        let new_message = DbInsertableChatMessage {
            chat_id: session_id,
            user_id,
            role: message_type,
            content: content.to_string(),
        };
        let conn = pool.get().await.expect("Failed to get DB conn");
        conn.interact(move |conn| {
            diesel::insert_into(schema::chat_messages::table)
                .values(&new_message)
                .returning(ChatMessage::as_returning())
                .get_result(conn)
        }).await.expect("Interact failed").expect("Failed to insert chat message")
    }
    
    pub async fn update_test_chat_settings(
        pool: &PgPool,
        session_id: Uuid,
        new_system_prompt: Option<String>,
        new_temperature: Option<BigDecimal>,
        new_max_output_tokens: Option<i32>,
    ) {
         use crate::schema::chat_sessions::dsl::*;
         let conn = pool.get().await.expect("Failed to get DB conn");
         conn.interact(move |conn| {
             diesel::update(chat_sessions.filter(id.eq(session_id)))
                 .set((
                     system_prompt.eq(new_system_prompt),
                     temperature.eq(new_temperature),
                     max_output_tokens.eq(new_max_output_tokens),
                 ))
                 .execute(conn)
         }).await.expect("Interact failed").expect("Failed to update settings");
    }
    
    pub async fn update_all_chat_settings(
        pool: &PgPool,
        session_id: Uuid,
        new_system_prompt: Option<String>,
        new_temperature: Option<BigDecimal>,
        new_max_output_tokens: Option<i32>,
        new_frequency_penalty: Option<BigDecimal>,
        new_presence_penalty: Option<BigDecimal>,
        new_top_k: Option<i32>,
        new_top_p: Option<BigDecimal>,
        new_repetition_penalty: Option<BigDecimal>,
        new_min_p: Option<BigDecimal>,
        new_top_a: Option<BigDecimal>,
        new_seed: Option<i32>,
        new_logit_bias: Option<Value>,
    ) {
         use crate::schema::chat_sessions::dsl::*;
         let conn = pool.get().await.expect("Failed to get DB conn");
         conn.interact(move |conn| {
             diesel::update(chat_sessions.filter(id.eq(session_id)))
                 .set((
                    system_prompt.eq(new_system_prompt),
                    temperature.eq(new_temperature),
                    max_output_tokens.eq(new_max_output_tokens),
                    frequency_penalty.eq(new_frequency_penalty),
                    presence_penalty.eq(new_presence_penalty),
                    top_k.eq(new_top_k),
                    top_p.eq(new_top_p),
                    repetition_penalty.eq(new_repetition_penalty),
                    min_p.eq(new_min_p),
                    top_a.eq(new_top_a),
                    seed.eq(new_seed),
                    logit_bias.eq(new_logit_bias),
                 ))
                 .execute(conn)
         }).await.expect("Interact failed").expect("Failed to update all settings");
    }

    pub async fn get_chat_messages_from_db(pool: &PgPool, _session_id: Uuid) -> Vec<ChatMessage> {
        use crate::schema::chat_messages::dsl::*;
        let conn = pool.get().await.expect("Failed to get DB conn");
        conn.interact(move |conn| {
            chat_messages
                .filter(session_id.eq(_session_id))
                .order(created_at.asc())
                .select(ChatMessage::as_select())
                .load::<ChatMessage>(conn)
        }).await.expect("Interact failed").expect("Query failed")
    }
    
    // Define the settings tuple type alias within the module as well if needed, or import it.
    type SettingsTuple = (
        Option<String>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>, 
        Option<BigDecimal>, Option<i32>, Option<BigDecimal>, Option<BigDecimal>, 
        Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<Value>
    );

    pub async fn get_chat_session_settings(pool: &PgPool, session_id: Uuid) -> Option<SettingsTuple> {
        use crate::schema::chat_sessions::dsl::*;
        let conn = pool.get().await.expect("Failed to get DB conn");
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
                    logit_bias,
                ))
                .first::<SettingsTuple>(conn)
                .optional()
        }).await.expect("Interact failed").expect("Query failed")
    }
}

// --- Auth Helper Functions ---

pub mod auth {
    // Import types from the parent module and db module
    use super::{TestApp, User, StatusCode, Method, Request, header, Body, ServiceExt};
    use super::db::create_test_user; // Import from db module
    use serde_json::json;
     // Import HeaderValue

    /// Creates a user and logs them in, returning the auth cookie and user object.
    pub async fn create_test_user_and_login(
        app: &TestApp, 
        username: &str,
        password: &str,
    ) -> (String, User) {
        let user = create_test_user(&app.db_pool, username, password).await;

        let login_payload = json!({
            "username": username,
            "password": password,
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/login")
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_vec(&login_payload).unwrap()))
            .unwrap();

        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "Login failed after user creation");

        // Extract the cookie
        let cookie_header = response.headers().get(header::SET_COOKIE).expect("No set-cookie header found");
        // Convert HeaderValue to str, handling potential errors
        let cookie_str = cookie_header.to_str().expect("Invalid characters in cookie header");
        // Simple parsing assuming single cookie: sid=...;
        let auth_cookie = cookie_str.split(';').next().expect("Cookie format error").to_string();

        (auth_cookie, user)
    }
}

// --- Test Context Struct and Impl ---

pub struct TestContext {
    pub app: TestApp, // Store the whole TestApp
    // Add other context if needed, e.g., pre-created users, characters
}

impl TestContext {
    /// Inserts a character directly into the database for test setup.
    pub async fn insert_character(&mut self, user_id: Uuid, name: &str) -> Character {
        db::create_test_character(&self.app.db_pool, user_id, name).await // Use pool from TestApp
    }

    /// Inserts a chat session directly into the database for test setup.
    pub async fn insert_chat_session(
        &mut self,
        user_id: Uuid,
        character_id: Uuid,
    ) -> ChatSession {
        db::create_test_chat_session(&self.app.db_pool, user_id, character_id).await // Use pool from TestApp
    }

    /// Inserts a chat message directly into the database for test setup.
    pub async fn insert_chat_message(
        &mut self,
        session_id: Uuid,
        user_id: Uuid,
        message_type: MessageRole,
        content: &str,
    ) -> ChatMessage {
        db::create_test_chat_message(&self.app.db_pool, session_id, user_id, message_type, content).await // Use pool from TestApp
    }

    // Add other helper methods as needed, e.g., fetching data directly from DB
}

/// Sets up the test application and returns a TestContext.
pub async fn setup_test_app() -> TestContext {
    let test_app = spawn_app().await;
    TestContext { app: test_app }
}

pub fn create_test_pool() -> DeadpoolPool {
     dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = DeadpoolManager::new(database_url, DeadpoolRuntime::Tokio1);
    DeadpoolPool::builder(manager).build().expect("Failed to create pool.")
}

// --- Test Data Cleanup Guard ---
pub struct TestDataGuard {
    pool: DeadpoolPool,
    user_ids: Vec<Uuid>,
    character_ids: Vec<Uuid>,
    // Add session IDs if needed for cleanup
    session_ids: Vec<Uuid>,
}

impl TestDataGuard {
    pub fn new(pool: DeadpoolPool) -> Self {
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

// --- Tracing Initializer ---
pub fn ensure_tracing_initialized() {
    use std::sync::Once;
    use tracing_subscriber::{EnvFilter, fmt};
    static TRACING_INIT: Once = Once::new();
    TRACING_INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn,tower_http=debug".into());
        fmt().with_env_filter(filter).init();
    });
}

// --- Mock Clients/Services (already pub structs/impls) ---
// ... MockAiClient, MockEmbeddingClient, MockEmbeddingPipelineService, MockQdrantClientService ...

// --- AppState Builder (already pub) ---
#[derive(Default)]
pub struct AppStateBuilder { /* ... existing fields ... */ 
    // Add fields if they were removed or keep as is if defined elsewhere
}
impl AppStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // Add placeholder builder methods used in tests
    pub fn with_config(self, _config: Arc<Config>) -> Self {
        // TODO: Store config if needed by builder logic
        self
    }

    pub fn with_ai_client(self, _client: Arc<dyn AiClient + Send + Sync>) -> Self {
        // TODO: Store client if needed
        self
    }

    // Accept trait object for EmbeddingClient
    pub fn with_embedding_client(self, _client: Arc<dyn EmbeddingClient + Send + Sync>) -> Self {
        // TODO: Store client if needed
        self
    }

    // Accept trait object for EmbeddingPipelineServiceTrait
    pub fn with_embedding_pipeline_service(self, _service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>) -> Self {
        // TODO: Store service if needed
        self
    }
    
    // Renamed based on embedding_pipeline tests usage
    // Keep concrete type for MockQdrantClientService as it's not a trait
    pub fn with_mock_qdrant_service(self, _service: Arc<MockQdrantClientService>) -> Self {
        // TODO: Store service if needed
        self
    }

    // Add placeholder build_for_test method
    pub async fn build_for_test(self) -> Result<Arc<AppState>, String> {
        // TODO: Implement proper AppState construction logic using stored fields
        // For now, create a default/dummy state to satisfy the call
        let pool = create_test_pool(); // Assuming create_test_pool helper exists
        let config = Arc::new(Config::default());
        let ai_client = Arc::new(MockAiClient::new());
        let embedding_client = Arc::new(MockEmbeddingClient::new());
        let qdrant_service = Arc::new(QdrantClientService::new_test_dummy()); // Use dummy Qdrant
        let embedding_pipeline_service = Arc::new(MockEmbeddingPipelineService::new());

        Ok(Arc::new(AppState {
            pool,
            config,
            ai_client,
            embedding_client: embedding_client as Arc<dyn EmbeddingClient + Send + Sync>,
            qdrant_service,
            embedding_pipeline_service: embedding_pipeline_service as Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
            embedding_call_tracker: Arc::new(tokio::sync::Mutex::new(Vec::new())), // Add default tracker
        }))
    }
}

// --- Docker Testcontainer Helpers ---
pub mod docker {
    // Add top-level testcontainers import
    
    // Qdrant feature not available in testcontainers-modules v0.11.6
    // use testcontainers_modules::qdrant::Qdrant;
    
     // Add sleep

    // Commented out doc comment as the function is also commented out
    // /// Runs Qdrant in a test container and returns the host port.
    // This function needs to be updated or removed as Qdrant module is not available
    /*
    pub async fn run_qdrant_container() -> u16 {
        info!("Starting Qdrant container for test...");
        let node = Qdrant::default() // This line will fail
            .start()
            .await
            .expect("Failed to start Qdrant container");
        sleep(Duration::from_secs(1)).await;
        let port = node.get_host_port_ipv4(6333).await.expect("Failed to get Qdrant port");
        info!("Qdrant container running on port {}", port);
        port
    }
    */
    // Potential stop function if needed, though testcontainers usually handle cleanup
    // pub async fn stop_qdrant_container(...) { ... }
}

// --- Qdrant Client Test Helpers ---
pub mod qdrant {
    // Remove super::tonic import as it's likely not needed for qdrant_client::Qdrant
    // use super::tonic;
    use qdrant_client::config::QdrantConfig;
    // Use the higher-level Qdrant client
    use qdrant_client::Qdrant;
    // Import needed protobuf types separately
    use qdrant_client::qdrant::{CreateCollection, VectorParams, Distance, VectorsConfig};
    use crate::vector_db::qdrant_client::{EMBEDDING_DIMENSION, DEFAULT_COLLECTION_NAME};
    use qdrant_client::qdrant::vectors_config::Config as QdrantVectorsConfig;
    use tracing::{info, warn};

    /// Sets up a Qdrant client connected to the test container and ensures the collection exists.
    // Change return type to the higher-level Qdrant client
    pub async fn setup_qdrant(port: u16) -> Qdrant {
        let client_config = QdrantConfig::from_url(&format!("http://localhost:{}", port));

        // Use Qdrant::new(config) as suggested by the compiler error
        let client = Qdrant::new(client_config)
            .expect("Failed to build Qdrant client");

        // Ensure collection exists - Methods might be slightly different on Qdrant vs QdrantClient
        let collection_name = DEFAULT_COLLECTION_NAME;
        // Use collection_exists method (assuming it exists on Qdrant)
        match client.collection_exists(collection_name).await {
            Ok(exists) => {
                if !exists {
                    info!("Creating Qdrant collection '{}' for test", collection_name);
                    if let Err(create_err) = client.create_collection(CreateCollection {
                        collection_name: collection_name.to_string(),
                        vectors_config: Some(VectorsConfig {
                            config: Some(QdrantVectorsConfig::Params(VectorParams {
                                size: EMBEDDING_DIMENSION, // Use constant
                                distance: Distance::Cosine.into(),
                                ..Default::default()
                            })),
                        }),
                        ..Default::default()
                    }).await {
                        if create_err.to_string().contains("already exists") {
                            warn!("Collection '{}' already exists (race condition?), continuing test.", collection_name);
                        } else {
                            panic!("Failed to create test collection '{}': {}", collection_name, create_err);
                        }
                    }
                } else {
                     info!("Qdrant collection '{}' already exists for test", collection_name);
                }
            },
            Err(e) => {
                 panic!("Failed to check collection info for '{}': {}", collection_name, e);
            }
        }
        client
    }
}

// --- Config Test Helpers ---
pub mod config {
    use crate::config::Config;
    
    use dotenvy::dotenv;
    use tracing::info;

    /// Initializes Config, potentially overriding with test-specific values.
    pub fn initialize_test_config(qdrant_port: Option<u16>) -> Config {
        dotenv().ok();
        let mut test_config = Config::load().expect("Failed to load base config for test initialization");
        
        // Override specific settings for tests
        if let Some(port) = qdrant_port {
            let qdrant_url = format!("http://localhost:{}", port);
            info!("Setting QDRANT_URL for test config: {}", qdrant_url);
            test_config.qdrant_url = Some(qdrant_url);
        }
        
        // Override other configs as needed (e.g., log level, ports)
        // test_config.log_level = "debug".to_string();

        test_config
    }
}

// ... rest of file (e.g., Mock Implementations if not already pub) ...
