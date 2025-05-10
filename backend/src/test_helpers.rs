// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.

// Make sure all necessary imports from the main crate and external crates are included.
use crate::errors::AppError;
use crate::llm::{AiClient, ChatStream, EmbeddingClient}; // Add EmbeddingClient
use crate::services::embedding_pipeline::{EmbeddingPipelineServiceTrait, RetrievedChunk};
// Removed unused: ChunkConfig, ChunkingMetric
use crate::vector_db::qdrant_client::{PointStruct, QdrantClientServiceTrait};
use crate::{
    PgPool, // This is deadpool_diesel::postgres::Pool
    auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend}, // Use crate::auth and alias Backend, Added RegisterPayload
    config::Config,
    // Ensure build_gemini_client is removed if present
    models::chats::ChatMessage,
    routes::{
        auth::{login_handler, logout_handler, me_handler, register_handler},
        characters::{get_character_handler, list_characters_handler, upload_character_handler},
        chat::chat_routes,
        health::health_check,
    },
    schema,
    state::AppState,
    vector_db::qdrant_client::QdrantClientService, // Import constants module alias
};
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use axum::Router;
use axum_login::{AuthManagerLayerBuilder, login_required};
use diesel::RunQueryDsl;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use dotenvy::dotenv; // Removed var
use genai::chat::ChatStreamEvent; // Add import for chatstream types
use genai::chat::{ChatOptions, ChatRequest, ChatResponse};
use qdrant_client::qdrant::{Filter, PointId, ScoredPoint};
use std::sync::{Arc, Mutex}; // Add Mutex import
use tokio::sync::Mutex as TokioMutex;
use tokio::net::TcpListener;
use tower_cookies::{CookieManagerLayer}; // Removed unused: Key as TowerCookieKey
use tower_sessions::{Expiry, SessionManagerLayer};
use tracing::warn;
use uuid::Uuid;
 // Changed from scribe_backend::auth
 // Changed from scribe_backend::models::users, User is already imported above
 // Changed from crate::models::characters
 // Changed from NewChatSession
// Removed: use scribe_backend::state::DbPool as PgPool; // This alias is redundant with crate::PgPool
 // Added for Secret type
// use crate::schema::chats; // REMOVE THIS LINE - it was line 68 approx
use std::fmt;
// REMOVE: use crate::models::chats as chats_model_schema; // This was an earlier attempt
 // Import SecretBox, SecretString for create_test_user

// --- START Placeholder Mock Definitions ---
// TODO: Implement proper mocks based on required functionality

#[derive(Clone)]
pub struct MockAiClient {
    // Add fields to store mock state, similar to previous mock impl
    // These need Arc<Mutex<...>> for thread safety if mock is shared across awaits
    last_request: std::sync::Arc<std::sync::Mutex<Option<ChatRequest>>>,
    last_options: std::sync::Arc<std::sync::Mutex<Option<ChatOptions>>>,
    response_to_return: std::sync::Arc<std::sync::Mutex<Result<ChatResponse, AppError>>>,
    stream_to_return:
        std::sync::Arc<std::sync::Mutex<Option<Vec<Result<ChatStreamEvent, AppError>>>>>,
    // Field to capture the messages sent to the stream_chat method
    last_received_messages:
        std::sync::Arc<std::sync::Mutex<Option<Vec<genai::chat::ChatMessage>>>>,
}

impl MockAiClient {
    pub fn new() -> Self {
        // Initialize fields with default values
        Self {
            last_request: Default::default(),
            last_options: Default::default(),
            // Default to a simple OK response
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(ChatResponse {
                model_iden: genai::ModelIden::new(
                    genai::adapter::AdapterKind::Gemini,
                    "mock-model",
                ), // Placeholder iden
                provider_model_iden: genai::ModelIden::new(
                    genai::adapter::AdapterKind::Gemini,
                    "mock-model",
                ),
                content: Some(genai::chat::MessageContent::Text(
                    "Mock AI response".to_string(),
                )),
                reasoning_content: None,
                usage: Default::default(),
            }))),
            stream_to_return: Default::default(),
            last_received_messages: Default::default(), // Initialize the new field
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

    // Method to retrieve the captured messages
    pub fn get_last_received_messages(&self) -> Option<Vec<genai::chat::ChatMessage>> {
        self.last_received_messages.lock().unwrap().clone()
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
    async fn exec_chat(
        &self,
        _model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatResponse, AppError> {
        *self.last_request.lock().unwrap() = Some(request.clone()); // Clone request
        *self.last_options.lock().unwrap() = config_override;
        // Capture messages for exec_chat as well, if needed, though stream_chat is primary for this task
        *self.last_received_messages.lock().unwrap() = Some(request.messages);
        // TODO: Implement proper mock logic using stored response
        self.response_to_return.lock().unwrap().clone()
        // unimplemented!("MockAiClient exec_chat not implemented")
    }
    async fn stream_chat(
        &self,
        _model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        *self.last_request.lock().unwrap() = Some(request.clone()); // Clone request before moving messages
        *self.last_options.lock().unwrap() = config_override;
        // Capture the incoming messages
        *self.last_received_messages.lock().unwrap() = Some(request.messages);

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
                                    ChatStreamEvent::Chunk(chunk) => {
                                        ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                            content: chunk.content.clone(),
                                        })
                                    }
                                    ChatStreamEvent::Start => ChatStreamEvent::Start,
                                    ChatStreamEvent::ReasoningChunk(chunk) => {
                                        ChatStreamEvent::ReasoningChunk(genai::chat::StreamChunk {
                                            content: chunk.content.clone(),
                                        })
                                    }
                                    ChatStreamEvent::End(_end_event) => {
                                        ChatStreamEvent::End(Default::default())
                                    } // StreamEnd is not Clone, use Default
                                };
                                new_items.push(Ok(new_event));
                            }
                            Err(err) => {
                                // Clone the error (assuming AppError is Clone)
                                new_items.push(Err(err.clone()));
                            }
                        }
                    }
                    new_items
                }
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
        self.calls
            .lock()
            .unwrap()
            .push((text.to_string(), task_type.to_string()));

        // Return the pre-set response or a default
        match self.response.lock().unwrap().clone() {
            Some(res) => res,
            None => {
                // Default behavior if no response is set
                warn!("MockEmbeddingClient response not set, returning default OK response."); // Keep warning
                Ok(vec![0.0; 768]) // Restore default Ok(...) behavior
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
    ProcessAndEmbedMessage {
        message_id: Uuid,
        session_id: Uuid,
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
    async fn process_and_embed_message(
        &self,
        _state: Arc<AppState>,
        message: ChatMessage,
    ) -> Result<(), AppError> {
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedMessage {
                message_id: message.id,
                session_id: message.session_id,
            });

        // For mock implementation, just return success
        Ok(())
    }

    async fn retrieve_relevant_chunks(
        &self,
        _state: Arc<AppState>,
        chat_id: Uuid,
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveRelevantChunks {
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
                warn!(
                    "MockEmbeddingPipelineService::retrieve_relevant_chunks called without a pre-set response, returning Ok(vec![])"
                );
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

    pub async fn upsert_points(
        &self,
        points: Vec<qdrant_client::qdrant::PointStruct>,
    ) -> Result<(), AppError> {
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

    pub async fn search_points(
        &self,
        query_vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
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

    async fn retrieve_points(
        &self,
        _filter: Option<Filter>,
        _limit: u64,
    ) -> Result<Vec<ScoredPoint>, AppError> {
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

// --- Tracing Initialization for Tests ---
use std::sync::Once;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter as TracingEnvFilter}; // Renamed for clarity

static TRACING_INIT: Once = Once::new();

// Helper function to ensure tracing is initialized (idempotent)
// Made public to be accessible from integration tests
pub fn ensure_tracing_initialized() {
    TRACING_INIT.call_once(|| {
        tracing_fmt()
            .with_env_filter(TracingEnvFilter::from_default_env())
            .try_init()
            .unwrap_or_else(|e| eprintln!("Failed to initialize tracing: {}", e));
    });
}
// --- End Tracing Initialization ---

/// Structure to hold information about the running test application.
#[derive(Clone)]
pub struct TestApp {
    pub address: String,
    pub router: Router,
    pub db_pool: PgPool,
    pub config: Arc<Config>, // Add config field
    // Store the actual AI client being used (could be real or mock)
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
    // Optionally store the mock client for tests that need mock-specific methods
    pub mock_ai_client: Option<Arc<MockAiClient>>,
    pub mock_embedding_client: Arc<MockEmbeddingClient>,
    pub mock_embedding_pipeline_service: Arc<MockEmbeddingPipelineService>,
    pub qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>, // Use trait object
    // Optionally store the mock Qdrant client for tests that need mock-specific methods
    pub mock_qdrant_service: Option<Arc<MockQdrantClientService>>,
    pub embedding_call_tracker: Arc<TokioMutex<Vec<uuid::Uuid>>>,
}

/// Spawns the application for testing.
/// Takes boolean flags to determine whether to use real AI and Qdrant clients.
/// Takes a boolean flag to determine whether to use a multi-threaded runtime.
pub async fn spawn_app(multi_thread: bool, use_real_ai: bool, use_real_qdrant: bool) -> TestApp {
    // Ensure tracing is initialized for tests
    ensure_tracing_initialized();

    // Load configuration
    dotenv().ok();
    let config = crate::config::Config::default();
    let config = Arc::new(config);

    // Setup Database Pool
    let db_pool = db::setup_test_database(Some("spawn_app")).await;

    // Setup Qdrant Service (Real or Mock)
    let (qdrant_service, mock_qdrant_service_opt): (
        Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        Option<Arc<MockQdrantClientService>>,
    ) = if use_real_qdrant {
        let real_qdrant_service = Arc::new(
            QdrantClientService::new(config.clone())
                .await
                .expect("Failed to create real QdrantClientService for testing"),
        );
        (real_qdrant_service, None)
    } else {
        let mock_q_service = Arc::new(MockQdrantClientService::new());
        (mock_q_service.clone(), Some(mock_q_service))
    };

    // Create AI Client (Real or Mock)
    let (ai_client, mock_ai_client_opt): (
        Arc<dyn AiClient + Send + Sync>,
        Option<Arc<MockAiClient>>,
    ) = if use_real_ai {
        let real_client = crate::llm::gemini_client::build_gemini_client()
            .await
            .expect("Failed to build real Gemini client for testing");
        (real_client, None)
    } else {
        let mock_client = Arc::new(MockAiClient::new());
        (mock_client.clone(), Some(mock_client))
    };

    // Setup Mock Clients (keep these as mocks for isolating other parts, unless specified otherwise)
    let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
    let mock_embedding_pipeline_service = Arc::new(MockEmbeddingPipelineService::new());

    // Create tracker for embedding calls
    let embedding_call_tracker = Arc::new(TokioMutex::new(Vec::new()));

    // Build AppState
    let app_state_inner = AppState {
        pool: db_pool.clone(),
        config: config.clone(),
        ai_client: ai_client.clone(),
        embedding_client: mock_embedding_client.clone(),
        embedding_pipeline_service: mock_embedding_pipeline_service.clone(),
        qdrant_service: qdrant_service.clone(), // This will be the real or mock service
        embedding_call_tracker: embedding_call_tracker.clone(),
    };
    // Create the Arc<AppState> after building the inner state
    let app_state = Arc::new(app_state_inner);

    // Session Management Setup
    let session_store = DieselSessionStore::new(db_pool.clone());
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("id")
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(tower_sessions::cookie::time::Duration::days(1)));

    // Auth Backend Setup
    let auth_backend = AuthBackend::new(db_pool.clone());
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_layer).build();

    // Build Router
    let app = Router::new()
        .route("/api/health", axum::routing::get(health_check))
        .route("/api/auth/register", axum::routing::post(register_handler))
        .route("/api/auth/login", axum::routing::post(login_handler))
        .route("/api/auth/logout", axum::routing::post(logout_handler))
        .route("/api/auth/me", axum::routing::get(me_handler))
        .route(
            "/api/characters",
            axum::routing::get(list_characters_handler)
                .post(upload_character_handler)
                .layer(login_required!(AuthBackend, login_url = "/api/auth/login")),
        )
        .route(
            "/api/characters/{id}",
            axum::routing::get(get_character_handler)
                .layer(login_required!(AuthBackend, login_url = "/api/auth/login")),
        )
        .nest("/api/chats", chat_routes())
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        .with_state(app_state.as_ref().clone());

    // Start the server on a random available port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random port");
    let addr = listener.local_addr().unwrap();
    let address = format!("http://{}", addr);
    println!("Test server running on {}", address);

    let app_for_server = app.clone();

    if multi_thread {
        tokio::spawn(async move {
            axum::serve(listener, app_for_server.into_make_service())
                .await
                .unwrap();
        });
    } else {
        tokio::task::spawn_local(async move {
            axum::serve(listener, app_for_server.into_make_service())
                .await
                .unwrap();
        });
    }

    TestApp {
        address,
        router: app,
        db_pool,
        config: config.clone(),
        ai_client,
        mock_ai_client: mock_ai_client_opt,
        mock_embedding_client,
        mock_embedding_pipeline_service,
        qdrant_service, // This is now correctly the real or mock service
        mock_qdrant_service: mock_qdrant_service_opt, // Store the Option<Arc<MockQdrantClientService>>
        embedding_call_tracker,
    }
}

// --- Modules containing test helpers ---

pub mod db {
    // Add a comprehensive set of imports needed within the db module
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness; // Keep only this one
    use crate::models::users::User; // User was already imported, ensure UserDbQuery is correct
     // Ensure this path is correct
    
    
    
    use crate::PgPool; // This should refer to the top-level crate::PgPool
    use uuid::Uuid;
    
    
    
     // For logging macros
    use std::env; // For DATABASE_URL reading in setup_test_database
    use dotenvy::dotenv; // For .env file loading
    use deadpool_diesel::postgres::{Manager as DeadpoolManager, Pool as DeadpoolPool, Runtime as DeadpoolRuntime};
    use super::MIGRATIONS; // Use super::MIGRATIONS since it's defined in the parent scope (test_helpers.rs)
    use crate::auth; // Changed from scribe_backend::auth
    use secrecy::SecretString; // Changed from Secret to SecretString
    use crate::auth::RegisterPayload; // Ensure RegisterPayload is imported

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

        // Drop and Create the test database
        let db_name_clone_drop = db_name.clone();
        let db_name_clone_create = db_name.clone();
        conn_default
            .interact(move |conn| {
                diesel::sql_query(format!(
                    "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                    db_name_clone_drop
                ))
                .execute(conn)?; // Added WITH (FORCE)
                diesel::sql_query(format!("CREATE DATABASE \"{}\"", db_name_clone_create))
                    .execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .await
            .expect("DB interaction failed")
            .expect("Failed to create test DB");

        // Create a connection pool to the newly created test database
        let test_db_url = format!("{}/{}", main_db_url, db_name);
        let manager = DeadpoolManager::new(test_db_url, DeadpoolRuntime::Tokio1);
        let pool = DeadpoolPool::builder(manager)
            .build()
            .expect("Failed to create test DB pool");

        // Run migrations on the test database
        let conn = pool
            .get()
            .await
            .expect("Failed to get test DB connection for migration");
        conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
            .await
            .expect("Migration task failed")
            .expect("Failed to run migrations");

        pool
    }

    pub async fn create_test_user(pool: &PgPool, username: &str, password_str: &str) -> User {
        let email = format!("{}@example.com", username);
        let plaintext_password = SecretString::from(password_str.to_string());

        // Hash the password for storage using the auth module's helper
        let password_hash = auth::hash_password(plaintext_password.clone())
            .await
            .expect("Failed to hash password in test_helper::create_test_user");

        let conn = pool.get().await.expect("Failed to get DB conn from pool in create_test_user");

        // Call the real auth::create_user function which handles KEK derivation and DEK encryption
        let user = conn
            .interact({
                let uname_clone = username.to_string(); // Clone for closure
                let mail_clone = email.clone();       // Clone for closure
                // Clone plaintext_password for KEK derivation inside create_user
                let p_password_for_payload = plaintext_password.clone(); 
                // password_hash is already a String, clone it for the closure
                let p_hash_for_storage_clone = password_hash.clone();

                move |conn_inner: &mut PgConnection| { // Specify conn_inner type
                    let register_payload = RegisterPayload {
                        username: uname_clone,
                        email: mail_clone,
                        password: p_password_for_payload,
                        recovery_phrase: None, // Test users generally don't need recovery by default
                    };
                    auth::create_user( // This refers to crate::auth::create_user
                        conn_inner,
                        register_payload,
                        p_hash_for_storage_clone,
                    )
                }
            })
            .await
            .expect("Interact call for create_user failed in test_helper")
            .expect("auth::create_user failed in test_helper");

        user // auth::create_user already returns a User
    }
} // This closes pub mod db

// --- Auth Helper Functions ---

// --- TestDataGuard for cleaning up test data ---
pub struct TestDataGuard {
    pool: PgPool, // Changed to PgPool type alias
    user_ids: Vec<Uuid>,
    character_ids: Vec<Uuid>, // Added for characters
    chat_ids: Vec<Uuid>,      // Added for chats/sessions
}

// Manual implementation of Debug for TestDataGuard
impl fmt::Debug for TestDataGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestDataGuard")
         .field("pool", &"PgPool // Omitted details for Debug") // PgPool itself is Debug, but we simplify here
         .field("user_ids", &self.user_ids)
         .field("character_ids", &self.character_ids)
         .field("chat_ids", &self.chat_ids)
         .finish()
    }
}

impl TestDataGuard {
    pub fn new(pool: PgPool) -> Self { // Changed to PgPool
        TestDataGuard {
            pool,
            user_ids: Vec::new(),
            character_ids: Vec::new(),
            chat_ids: Vec::new(),
        }
    }

    pub fn add_user(&mut self, user_id: Uuid) {
        self.user_ids.push(user_id);
    }

    pub fn add_character(&mut self, character_id: Uuid) {
        self.character_ids.push(character_id);
    }

    pub fn add_chat(&mut self, chat_id: Uuid) {
        self.chat_ids.push(chat_id);
    }
    
    // Adapted from auth_tests.rs and db_integration_tests.rs
    pub async fn cleanup(self) -> Result<(), anyhow::Error> {
        let conn = self.pool.get().await.context("Failed to get DB connection for cleanup")?;

        if !self.chat_ids.is_empty() {
            tracing::debug!(chat_ids = ?self.chat_ids, "Cleaning up test chats and messages");
            let chat_ids_clone = self.chat_ids.clone();
            let diesel_chat_op_result = conn.interact(move |conn_interaction| {
                diesel::delete(schema::chat_messages::table.filter(schema::chat_messages::session_id.eq_any(&chat_ids_clone)))
                    .execute(conn_interaction)?;
                diesel::delete(schema::chat_sessions::table.filter(schema::chat_sessions::id.eq_any(chat_ids_clone.clone())))
                    .execute(conn_interaction)
            }).await.map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_chat_op_result.context("Interact error cleaning up chats")?;
        }
        
        if !self.character_ids.is_empty() {
            tracing::debug!(character_ids = ?self.character_ids, "Cleaning up test characters");
            let character_ids_clone = self.character_ids.clone();
            let diesel_op_result_chars = conn.interact(move |conn_interaction| {
                diesel::delete(schema::characters::table.filter(schema::characters::id.eq_any(character_ids_clone)))
                    .execute(conn_interaction)
            }).await.map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_chars.context("Interact error cleaning up characters")?;
        }

        if !self.user_ids.is_empty() {
            tracing::debug!(user_ids = ?self.user_ids, "Cleaning up test users");
            let user_ids_clone = self.user_ids.clone();
            let diesel_op_result_users = conn.interact(move |conn_interaction| {
                diesel::delete(schema::users::table.filter(schema::users::id.eq_any(user_ids_clone)))
                    .execute(conn_interaction)
            }).await.map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_users.context("Interact error cleaning up users")?;
        }
        
        tracing::debug!("--- TestDataGuard cleanup complete ---");
        Ok(())
    }
}

impl Drop for TestDataGuard {
    fn drop(&mut self) {
        // Synchronous drop cannot call async cleanup.
        // Tests should call cleanup explicitly.
        // If user_ids is not empty, it means cleanup was not called.
        if !self.user_ids.is_empty() || !self.character_ids.is_empty() || !self.chat_ids.is_empty() {
            // Use a blocking spawn for the async cleanup task
            // This is not ideal for drop, but better than panicking or doing nothing.
            // Consider making cleanup explicit in all tests.
            let pool_clone = self.pool.clone();
            let user_ids_clone = self.user_ids.drain(..).collect::<Vec<_>>();
            let character_ids_clone = self.character_ids.drain(..).collect::<Vec<_>>();
            let chat_ids_clone = self.chat_ids.drain(..).collect::<Vec<_>>();

            if !user_ids_clone.is_empty() || !character_ids_clone.is_empty() || !chat_ids_clone.is_empty() {
                tracing::warn!("TestDataGuard dropped without explicit cleanup. Attempting synchronous cleanup (best effort).");
                tokio::task::block_in_place(move || { // Use block_in_place if in async context
                    tokio::runtime::Handle::current().block_on(async move {
                        let conn_result = pool_clone.get().await;
                        if let Ok(conn_obj) = conn_result { // conn_obj is Object
                            if !chat_ids_clone.is_empty() {
                                let chat_ids_c = chat_ids_clone.clone(); // clone for inner closure
                                
                                // Wrap the diesel operation in conn_obj.interact().await
                                let interact_result_chats = conn_obj.interact(move |actual_conn| {
                                    diesel::delete(schema::chat_sessions::table.filter(schema::chat_sessions::id.eq_any(chat_ids_c)))
                                        .execute(actual_conn) // Use &mut PgConnection from interact
                                }).await;

                                match interact_result_chats {
                                    Ok(Ok(_num_deleted_chats)) => {
                                        // Successfully deleted chats
                                    }
                                    Ok(Err(db_err_chats)) => {
                                        tracing::error!("TestDataGuard Drop: chat_sessions diesel cleanup failed: {:?}", db_err_chats);
                                    }
                                    Err(pool_err_chats) => { // This is deadpool::managed::PoolError
                                        tracing::error!("TestDataGuard Drop: chat_sessions interact pool error: {:?}", pool_err_chats);
                                    }
                                }
                            }
                            if !character_ids_clone.is_empty() {
                                let interact_result_chars = conn_obj.interact({
                                    // Clone for the inner closure, as conn is captured by interact already
                                    let char_ids_inner_clone = character_ids_clone.clone(); 
                                    move |c_conn| {
                                        diesel::delete(schema::characters::table.filter(schema::characters::id.eq_any(char_ids_inner_clone)))
                                            .execute(c_conn)
                                    }
                                }).await;

                                match interact_result_chars {
                                    Ok(diesel_result_chars) => {
                                        if let Err(e) = diesel_result_chars.context("Drop: Diesel error cleaning up characters") {
                                            tracing::error!("TestDataGuard Drop: Characters diesel cleanup failed: {:?}", e);
                                        }
                                    }
                                    Err(interact_err_chars) => {
                                        tracing::error!("TestDataGuard Drop: Characters interact cleanup failed. Raw: {:?}, Context: {}", interact_err_chars, "Drop: Interact error cleaning up characters");
                                    }
                                }
                            }
                            if !user_ids_clone.is_empty() {
                                let interact_result_users = conn_obj.interact({
                                    let user_ids_inner_clone = user_ids_clone.clone();
                                    move |c_conn| {
                                        diesel::delete(schema::users::table.filter(schema::users::id.eq_any(user_ids_inner_clone)))
                                            .execute(c_conn)
                                    }
                                }).await;

                                match interact_result_users {
                                    Ok(diesel_result_users) => {
                                        if let Err(e) = diesel_result_users.context("Drop: Diesel error cleaning up users") {
                                            tracing::error!("TestDataGuard Drop: Users diesel cleanup failed: {:?}", e);
                                        }
                                    }
                                    Err(interact_err_users) => {
                                        tracing::error!("TestDataGuard Drop: Users interact cleanup failed. Raw: {:?}, Context: {}", interact_err_users, "Drop: Interact error cleaning up users");
                                    }
                                }
                            }
                        } else {
                            tracing::error!("Failed to get DB connection in TestDataGuard drop for cleanup.");
                        }
                    });
                });
            }
        }
    }
}

pub fn db_specific_cleanup(conn: &mut PgConnection, test_data: &TestDataGuard) -> Result<(), anyhow::Error> {
    // Clean up chat messages first (if any, assuming chat_messages depend on chats)
    // Example: diesel::delete(schema::chat_messages::table.filter(...)).execute(conn)?;

    if !test_data.chat_ids.is_empty() {
        let chat_ids_clone = test_data.chat_ids.clone();
        diesel::delete(schema::chat_sessions::table.filter(schema::chat_sessions::id.eq_any(chat_ids_clone))).execute(conn)?;
    }
    // ... other cleanup like characters, users
    Ok(())
}
