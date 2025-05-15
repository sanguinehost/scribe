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
    models::users::AccountStatus,
    routes::{
        chat::chat_routes,
        health::health_check,
        characters,
        chats_api,
        documents_api::{document_routes},
        auth as auth_routes_module,
    },
    schema,
    state::AppState,
    vector_db::qdrant_client::QdrantClientService, // Import constants module alias
};
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use axum::{
    // body::HttpBody, // Removed boxed - Removed unused
    middleware::{self, Next},
    response::Response as AxumResponse, // Alias to avoid conflict if Response is used elsewhere
    Router,
};
use axum_login::{AuthManagerLayerBuilder, login_required, AuthSession};
use diesel::RunQueryDsl;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use dotenvy::dotenv; // Removed var
use genai::chat::ChatStreamEvent; // Add import for chatstream types
use futures::{TryStreamExt};
use genai::chat::{ChatOptions, ChatRequest, ChatResponse};
use genai::ModelIden; // Import ModelIden directly
use genai::adapter::AdapterKind; // Ensure AdapterKind is in scope
use qdrant_client::qdrant::{Filter, PointId, ScoredPoint};
use std::sync::{Arc, Mutex}; // Add Mutex import
use tokio::sync::Mutex as TokioMutex;
use tokio::net::TcpListener;
use tower_cookies::{CookieManagerLayer}; // Removed unused: Key as TowerCookieKey
use tower_sessions::{Expiry, SessionManagerLayer};
use tracing::{warn, instrument}; // Added instrument
use uuid::Uuid;
use std::fmt;
use crate::models::users::User as DbUser;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use crate::models::users::{User, SerializableSecretDek}; // Added SerializableSecretDek
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt; // For .oneshot
use serde_json::json;

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
    // model_name: String, // Removed unused
    // provider_model_name: String, // Removed unused
    // embedding_response: Arc<Mutex<Result<Vec<f32>, AppError>>>, // Removed unused
    // text_gen_response: Arc<Mutex<Result<String, AppError>>>, // Removed unused
}

impl MockAiClient {
    pub fn new() -> Self {
        // Initialize fields with default values
        Self {
            last_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_options: std::sync::Arc::new(std::sync::Mutex::new(None)),
            // Default to a simple OK response
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                content: Some(genai::chat::MessageContent::Text(
                    "Mock AI response".to_string(),
                )),
                reasoning_content: None,
                usage: Default::default(),
            }))),
            stream_to_return: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_received_messages: std::sync::Arc::new(std::sync::Mutex::new(None)),
            // model_name: "gemini/mock-model".to_string(), // Removed unused
            // provider_model_name: "gemini/mock-model".to_string(), // Removed unused
            // embedding_response: Arc::new(Mutex::new(Ok(vec![0.1, 0.2, 0.3]))), // Removed unused
            // text_gen_response: Arc::new(Mutex::new(Ok("Mock text generation response".to_string()))), // Removed unused
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

impl Default for MockAiClient {
    fn default() -> Self {
        Self::new()
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
                                    ChatStreamEvent::ToolCall(tool_call) => {
                                        // Assuming genai::chat::ToolCall is effectively cloneable by its fields
                                        ChatStreamEvent::ToolCall(genai::chat::ToolCall {
                                            call_id: tool_call.call_id.clone(),
                                            fn_name: tool_call.fn_name.clone(),
                                            fn_arguments: tool_call.fn_arguments.clone(),
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
        _session_dek: Option<&crate::auth::session_dek::SessionDek>, // Added session_dek parameter
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
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter}; // Alias fmt to avoid collision with std::fmt

static TRACING_INIT: Once = Once::new();

// Helper function to ensure tracing is initialized (idempotent)
// Made public to be accessible from integration tests
pub fn ensure_tracing_initialized() {
    // Use tracing_subscriber::fmt and EnvFilter directly, relying on RUST_LOG
    TRACING_INIT.call_once(|| {
        // Attempt to initialize from RUST_LOG, default to "info" if not set or invalid
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_fmt() // Use the aliased tracing_fmt
            .with_env_filter(filter)
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

#[instrument(skip_all, fields(uri = %req.uri()))]
async fn auth_log_wrapper(
    auth_session: AuthSession<AuthBackend>, // Extract AuthSession
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> AxumResponse {
    let user_present = auth_session.user.is_some();
    let original_uri = req.uri().clone(); // Clone URI before req is moved
    tracing::warn!(
        target: "auth_middleware_debug",
        uri = %original_uri, // Use cloned URI
        user_in_session = user_present,
        "ENTERING auth_log_wrapper for protected routes"
    );
    let res = next.run(req).await;
    tracing::warn!(
        target: "auth_middleware_debug",
        uri = %original_uri, // Use cloned URI
        status = %res.status(),
        user_in_session_after_next = user_present, // Log again to see if it changed (it shouldn't by next)
        "EXITING auth_log_wrapper for protected routes"
    );
    res
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
        match QdrantClientService::new(config.clone()).await {
            Ok(service) => {
                let real_qdrant_service = Arc::new(service);
                (real_qdrant_service, None)
            },
            Err(e) => {
                warn!("Failed to create real QdrantClientService for testing: {}. Falling back to mock.", e);
                let mock_q_service = Arc::new(MockQdrantClientService::new());
                (mock_q_service.clone(), Some(mock_q_service))
            }
        }
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

    // --- Router Setup (mimicking main.rs) ---

    let app_state_for_routes = app_state.as_ref().clone();

    // Define protected_api_routes (paths are relative to the eventual /api mount)
    // Start with a router that is explicitly Router<AppState> by nesting one component first.
    let mut protected_api_routes: Router<AppState> = Router::new()
        .nest(
            "/characters",
            characters::characters_router(app_state_for_routes.clone())
        );
    tracing::debug!(router = ?protected_api_routes, "Protected routes after /characters");

    // Restore other protected routes
    protected_api_routes = protected_api_routes.nest(
            "/chats",
            chat_routes(app_state_for_routes.clone())
        );
    tracing::debug!(router = ?protected_api_routes, "Protected routes after /chats (crate::routes::chat)");
    
    protected_api_routes = protected_api_routes.nest(
            "/chats-api", {
                tracing::debug!("spawn_app: nesting chats_api::chat_routes() under /chats-api");
                chats_api::chat_routes() // Assumes this returns Router<AppState>
            }
        );
    tracing::debug!(router = ?protected_api_routes, "Protected routes after /chats-api");

    protected_api_routes = protected_api_routes.nest(
            "/documents",
            document_routes() // Assumes this returns Router<AppState>
        );
    tracing::debug!(router = ?protected_api_routes, "Protected routes after /documents");
        
    // Apply route_layer at the end
    let protected_api_routes_final = protected_api_routes // Now contains all nested protected routes
        .layer(middleware::from_fn(auth_log_wrapper)) // Log first
        .layer(login_required!(AuthBackend));         // Then auth
    tracing::debug!(router = ?protected_api_routes_final, "Protected routes final (after login_required and auth_log_wrapper)");

    // Define public_api_routes (paths are relative to the eventual /api mount)
    let public_api_routes: Router<AppState> = Router::new()
        .route("/health", axum::routing::get(health_check))
        .merge(Router::new().nest("/auth", auth_routes_module::auth_routes()));

    // Combine public and protected routes under a single /api prefix
    // let api_router = Router::new()
    //     .merge(public_api_routes)
    //     .merge(protected_api_routes_final); // protected_api_routes_final already has login_required applied

    // Combine routers and add layers.
    // Apply CookieManagerLayer and auth_layer at the top level
    // so they run before routing into /api.
    // Temporarily bypass api_router and public_api_routes for this test.
    // Mount ONLY the protected_api_routes_final under /api.
    // auth_layer is crucial for login_required! to function.
    // Reverting to nesting the full api_router under /api
    // let api_router = Router::new()
    //     .merge(public_api_routes) // Ensure public_api_routes is defined
    //     .merge(protected_api_routes_final.clone());

    // Merge public and protected routes into a single api_router
    let api_router = Router::new()
        .merge(public_api_routes)
        .merge(protected_api_routes_final); // protected_api_routes_final already has login_required applied

    let app = Router::new()
        .nest("/api", api_router) // Nest the combined api_router under /api
        .layer(CookieManagerLayer::new()) // Manages cookies, must be before auth_layer
        .layer(auth_layer)                // Uses cookies to load session/user
        // Removed TraceLayer to avoid potential conflicts with global tracing setup
        .with_state(app_state.as_ref().clone()); // Provide AppState to all handlers
    tracing::debug!(router = ?app, "Final app router structure");

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
        tokio::spawn(async move {
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
    use diesel_migrations::MigrationHarness;
    use crate::models::users::UserDbQuery; // User was already imported, ensure UserDbQuery is correct
     // Import AppError
    
    
    
    use crate::PgPool; // This should refer to the top-level crate::PgPool
    use uuid::Uuid;
    
    
    
     // For logging macros
    use std::env; // For DATABASE_URL reading in setup_test_database
    use dotenvy::dotenv; // For .env file loading
    use deadpool_diesel::postgres::{Manager as DeadpoolManager, Pool as DeadpoolPool, Runtime as DeadpoolRuntime};
    use super::MIGRATIONS; // Use super::MIGRATIONS since it's defined in the parent scope (test_helpers.rs)
    use crate::auth::{self}; // Corrected: Added hash_password, auth for module items
     // Ensure RegisterPayload is imported
    use super::*; // To bring PgPool and DbUser etc. into scope
     // Keep if CryptoError is used directly, else it comes via crate::crypto
    use crate::models::users::{NewUser}; // Removed User as DbUser from here, already aliased DbUser at top
                                       // and UserDbQuery is imported above
    
    

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

    /// Creates a test user directly in the database.
    /// Note: This helper bypasses any application logic for user creation (e.g., sending emails).
    pub async fn create_test_user(
        pool: &PgPool,
        username: String,
        password_str: String,
    ) -> Result<DbUser, anyhow::Error> {
        let conn = pool.get().await?;
        let email = format!("{}@test.com", username); 

        let password_str_for_kek = password_str.clone(); // Clone for KEK derivation
        let username_clone_for_payload = username.clone(); // Clone for NewUser payload

        let password_hash = auth::hash_password(SecretString::from(password_str.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        let kek_salt = crate::crypto::generate_salt()
            .map_err(|e| anyhow::anyhow!("KEK salt generation failed: {}",e))?;

        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        let plaintext_dek_box: SecretBox<Vec<u8>> = crate::crypto::generate_dek()
            .context("DEK generation failed in create_test_user")?;

        let kek = crate::crypto::derive_kek(&SecretString::from(password_str_for_kek), &kek_salt)
            .map_err(|e| anyhow::anyhow!("KEK derivation failed: {}", e))?;

        let (encrypted_dek_bytes, dek_nonce_bytes) =
            crate::crypto::encrypt_gcm(plaintext_dek_box.expose_secret(), &kek) // expose_secret() on SecretBox<Vec<u8>> gives &Vec<u8>
                    .map_err(|e| anyhow::anyhow!("DEK encryption failed: {}", e))?;

        let new_user_payload = NewUser {
            username: username_clone_for_payload,
            password_hash,
            email,
            kek_salt,
            encrypted_dek: encrypted_dek_bytes,
            dek_nonce: dek_nonce_bytes,
            encrypted_dek_by_recovery: None, 
            recovery_kek_salt: None,        
            recovery_dek_nonce: None,
            role: crate::models::users::UserRole::User, // Using User enum variant exactly as in DB
            account_status: AccountStatus::Active, // Default to Active account status
        };

        let user_from_db: UserDbQuery = conn.interact(move |conn_actual| {
            diesel::insert_into(crate::schema::users::table)
                .values(new_user_payload) // new_user_payload is moved here
                .returning(UserDbQuery::as_returning()) 
                .get_result::<UserDbQuery>(conn_actual) 
        })
        .await
        .map_err(|interact_err| anyhow::anyhow!("DB interact error for create_test_user: {}", interact_err))??;
        
        // Convert to DbUser
        let mut user: DbUser = user_from_db.into();
        
        // IMPORTANT: Set the plaintext DEK on the User object directly.
        // This is what would happen in the normal login flow (verify_credentials -> authenticate).
        // Without this, the SessionDek extractor won't be able to access the DEK for encryption.
        
        // user.dek is Option<SerializableSecretDek(SecretBox<Vec<u8>>)>
        // plaintext_dek_box is SecretBox<Vec<u8>>
        user.dek = Some(SerializableSecretDek(plaintext_dek_box));
        
        Ok(user)
    }

    /// Creates a test character directly in the database.
    pub async fn create_test_character(
        pool: &PgPool,
        user_id: Uuid,
        name: String,
    ) -> Result<crate::models::characters::Character, anyhow::Error> {
        use crate::models::character_card::NewCharacter;
        use crate::models::characters::Character; // Already imported at top of file usually
        // use crate::schema::characters; // Already imported at top of file usually
        use chrono::Utc;

        let conn = pool.get().await?;
        let now = Utc::now();
        let name_clone_for_payload = name.clone(); // Clone for payload and error message
        let name_clone_for_error = name.clone();

        let new_character_payload = NewCharacter {
            user_id,
            name: name_clone_for_payload.clone(), 
            description: Some(format!("Test description for {}", name_clone_for_payload).into_bytes()),
            greeting: Some(format!("Test greeting for {}", name_clone_for_payload).into_bytes()),
            example_dialogue: Some(format!("Test example dialogue for {}", name_clone_for_payload).into_bytes()),
            visibility: Some("private".to_string()),
            character_version: Some("2.0".to_string()),
            spec: "test_spec_v2.0".to_string(),
            spec_version: "2.0".to_string(),
            persona: Some(format!("Test persona for {}", name_clone_for_payload).into_bytes()),
            world_scenario: Some(format!("Test world scenario for {}", name_clone_for_payload).into_bytes()),
            avatar: None,
            chat: None,
            created_at: Some(now),
            updated_at: Some(now),
            creation_date: Some(now),
            modification_date: Some(now),
            creator_notes_multilingual: None,
            nickname: None,
            personality: None,
            tags: None,
            greeting_nonce: None,
            definition: None,
            default_voice: None,
            extensions: None,
            category: None,
            definition_visibility: None,
            example_dialogue_nonce: None,
            favorite: None,
            first_message_visibility: None,
            migrated_from: None,
            model_prompt: None,
            model_prompt_visibility: None,
            persona_visibility: None,
            sharing_visibility: None,
            status: None,
            system_prompt_visibility: None,
            system_tags: None,
            token_budget: None,
            usage_hints: None,
            user_persona: None,
            user_persona_visibility: None,
            world_scenario_visibility: None,
            description_nonce: None,
            personality_nonce: None,
            scenario_nonce: None,
            first_mes_nonce: None,
            mes_example_nonce: None,
            creator_notes_nonce: None,
            system_prompt_nonce: None,
            persona_nonce: None,
            world_scenario_nonce: None,
            definition_nonce: None,
            model_prompt_nonce: None,
            user_persona_nonce: None,
            post_history_instructions_nonce: None,
            post_history_instructions: None,
            scenario: None,
            mes_example: None,
            first_mes: None,
            creator_notes: None,
            system_prompt: None,
            alternate_greetings: None,
            creator: None,
            source: None,
            group_only_greetings: None,
        };

        let character: Character = conn.interact(move |conn_actual| {
            diesel::insert_into(crate::schema::characters::table)
                .values(new_character_payload) // new_character_payload is moved here
                .returning(Character::as_returning())
                .get_result::<Character>(conn_actual)
        })
        .await
        .map_err(move |interact_err| anyhow::anyhow!("DB interact error for create_test_character '{}': {}", name_clone_for_error, interact_err))??;

        Ok(character)
    }
}

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
            let _pool_clone = self.pool.clone(); // Renamed pool_clone
            let user_ids_clone = self.user_ids.drain(..).collect::<Vec<_>>();
            let character_ids_clone = self.character_ids.drain(..).collect::<Vec<_>>();
            let chat_ids_clone = self.chat_ids.drain(..).collect::<Vec<_>>();

            if !user_ids_clone.is_empty() || !character_ids_clone.is_empty() || !chat_ids_clone.is_empty() {
                tracing::warn!("TestDataGuard dropped without explicit cleanup. Attempting synchronous cleanup (best effort).");
                // Temporarily commented out for debugging test panics
                /*
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
                */
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

pub async fn create_user_with_dek_in_session(
    app_router: &Router, // Pass the app router to make login requests
    pool: &PgPool,
    username: String,
    password_str: String,
    plaintext_dek: Option<SecretString>, // Option to allow no DEK for some tests
) -> Result<(User, String), anyhow::Error> { // Returns User and session cookie string
    // 1. Create user in DB
    let created_user_db_record = crate::auth::user_store::create_user_in_db(
        pool,
        &username,
        &password_str,
        &username, // email can be same as username for test
        // For DEK related fields, create_user_in_db would handle generating them if plaintext_dek is provided
        // or it takes them pre-encrypted. This part depends on create_user_in_db's signature.
        // Assuming create_user_in_db handles KEK salt, encrypted DEK, nonce from plaintext_dek if provided.
        // For simplicity, let's assume create_user_in_db now takes plaintext_dek and handles it internally.
        plaintext_dek.clone(), // Pass a clone if create_user_in_db needs owned Option<SecretString>
    ).await.context("Failed to create user in DB for session test")?;

    // 2. Perform login to get session cookie
    let login_payload = json!({
        "identifier": username,
        "password": password_str
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))
        .unwrap();

    let response = app_router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Login request failed");

    let actual_cookie_value = response
        .headers()
        .get("set-cookie")
        .ok_or_else(|| anyhow::anyhow!("No set-cookie header found after login"))?
        .to_str()?
        .to_string();
    
    // 3. Construct mock_user_for_assertion (this is the User struct, not UserDbQuery)
    let mut mock_user_for_assertion = User::from(created_user_db_record.clone()); // Use the DB record from step 1
    if let Some(pt_dek_string) = plaintext_dek { // Use the original plaintext_dek passed to function
        let dek_bytes = pt_dek_string.expose_secret().as_bytes().to_vec();
        let secret_box = SecretBox::new(Box::new(dek_bytes));
        mock_user_for_assertion.dek = Some(SerializableSecretDek(secret_box));
    } else {
        mock_user_for_assertion.dek = None;
    }

    // 4. Return User and cookie
    Ok((mock_user_for_assertion, actual_cookie_value)) // Use the cookie from step 2
}

// Helper structs and functions for testing SSE
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedSseEvent {
    pub event: Option<String>, // Name of the event (e.g., "content", "error")
    pub data: String,          // Raw data string
                               // Not parsing id or retry for now
}

// Revised helper to parse full SSE events
pub async fn collect_full_sse_events(body: axum::body::Body) -> Vec<ParsedSseEvent> {
    let mut events = Vec::new();
    let mut current_event_name: Option<String> = None;
    let mut current_data_lines: Vec<String> = Vec::new();

    let stream = body.into_data_stream();

    stream
        .try_for_each(|buf| {
            let chunk_str = match std::str::from_utf8(&buf) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("SSE stream chunk is not valid UTF-8: {}", e);
                    // Depending on strictness, could return an error or skip the chunk
                    return futures::future::ready(Ok(())); // Skip malformed chunk
                }
            };
            
            for line in chunk_str.lines() {
                if line.is_empty() { // End of an event
                    if !current_data_lines.is_empty() { // Only push if there's data
                        events.push(ParsedSseEvent {
                            event: current_event_name.clone(),
                            data: current_data_lines.join("\n"), // Data can be multi-line
                        });
                        current_data_lines.clear();
                        // SSE spec: event name persists for subsequent data-only lines until next event: line or blank line.
                        // However, for simplicity here, we reset it as each 'event:' line should precede its 'data:'
                        // Axum's Event::default().data() does not set an event name, so current_event_name remains None.
                        // If an Event::event("name").data() is used, current_event_name would be Some("name").
                        // After a full event (blank line), the next event starts fresh. If it has no 'event:' line, it's a default 'message' event.
                        // So, resetting current_event_name to None is correct for default handling of subsequent unnamed events.
                        current_event_name = None; 
                    } else if current_event_name.is_some() {
                        // Handle event with name but no data, e.g. event: foo
                        events.push(ParsedSseEvent {
                            event: current_event_name.clone(),
                            data: String::new(),
                        });
                        current_event_name = None;
                    }
                } else if let Some(name) = line.strip_prefix("event:") {
                    current_event_name = Some(name.trim().to_string());
                } else if let Some(data_content) = line.strip_prefix("data:") {
                    current_data_lines.push(data_content.trim().to_string());
                }
                // Ignoring id: and retry: for now
            }
            futures::future::ready(Ok(()))
        })
        .await
        .expect("Failed to read SSE stream");

    // Handle any trailing event data if the stream ends without a blank line
    if !current_data_lines.is_empty() {
        events.push(ParsedSseEvent {
            event: current_event_name,
            data: current_data_lines.join("\n"),
        });
    }
    events
}
