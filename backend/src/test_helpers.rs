// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.

// Make sure all necessary imports from the main crate and external crates are included.
use crate::errors::AppError;
use crate::llm::{AiClient, ChatStream, EmbeddingClient}; // Add EmbeddingClient
use crate::services::embedding_pipeline::{EmbeddingPipelineServiceTrait, RetrievedChunk};
// Unused ChunkConfig, ChunkingMetric were previously noted as removed.
use crate::models::users::User as DbUser;
use crate::models::users::{SerializableSecretDek, User}; // Added SerializableSecretDek
use crate::vector_db::qdrant_client::{PointStruct, QdrantClientServiceTrait};
use crate::{
PgPool, // This is deadpool_diesel::postgres::Pool
auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend}, // Use crate::auth and alias Backend, Added RegisterPayload
config::Config,
// Ensure build_gemini_client is removed if present
models::chats::{ChatMessage, UpdateChatSettingsRequest}, // Added UpdateChatSettingsRequest
models::users::AccountStatus,
routes::{
    auth as auth_routes_module, characters, chat::chat_routes, chats,
    documents::document_routes, health::health_check, user_persona_routes,
},
schema,
state::AppState,
services::chat_override_service::ChatOverrideService, // <<< ENSURED IMPORT
services::encryption_service::EncryptionService, // <<< ENSURED IMPORT
services::gemini_token_client::GeminiTokenClient,
services::hybrid_token_counter::HybridTokenCounter,
services::tokenizer_service::TokenizerService,
// text_processing::chunking::{ChunkConfig, ChunkingMetric}, // Removed unused imports
services::user_persona_service::UserPersonaService, // <<< ADDED THIS IMPORT
vector_db::qdrant_client::QdrantClientService, // Import constants module alias
};
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use axum::{
Router,
middleware::{self, Next},
response::Response as AxumResponse, // Alias to avoid conflict if Response is used elsewhere
routing::get, // <<< ADD THIS IMPORT
};
use axum::{
body::Body,
http::{Request, StatusCode}, // Removed unused Method, header
};
use axum_login::{AuthManagerLayerBuilder, AuthSession}; // Removed unused login_required
use diesel::RunQueryDsl;
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, embed_migrations};
use dotenvy::dotenv; // Removed var
use futures::TryStreamExt;
use genai::ModelIden; // Import ModelIden directly
use genai::adapter::AdapterKind; // Ensure AdapterKind is in scope
use genai::chat::ChatStreamEvent; // Add import for chatstream types
use genai::chat::{ChatOptions, ChatRequest, ChatResponse};
// use http_body_util::BodyExt; // Removed unused import
use mime; // Added for mime::APPLICATION_JSON
use qdrant_client::qdrant::{Filter, PointId, ScoredPoint};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::fmt;
use std::sync::{Arc, Mutex}; // Add Mutex import
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt; // For .oneshot
use tower_cookies::CookieManagerLayer; // Removed unused: Key as TowerCookieKey
use tower_sessions::{Expiry, SessionManagerLayer, cookie::Key as TowerSessionKey, cookie::SameSite}; // Added SameSite
use tracing::{debug, instrument, warn}; // Added debug
use uuid::Uuid;
use hex; // Added for hex::decode
use time; // For time::Duration for session expiry
use reqwest;

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
    last_received_messages: std::sync::Arc<std::sync::Mutex<Option<Vec<genai::chat::ChatMessage>>>>,
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

    #[allow(dead_code)]
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
        let opt_response = self.search_response.lock().unwrap().take();
        tracing::info!(
            target: "mock_qdrant_search",
            "MockQdrantClientService::search_points (trait): taken response option is: {:?}",
            opt_response.as_ref().map(|res| match res {
                Ok(v) => format!("Ok(len={})", v.len()),
                Err(e) => format!("Err({})", e)
            })
        );
        let result_to_return = opt_response.unwrap_or(Ok(vec![]));
        tracing::info!(
            target: "mock_qdrant_search",
            "MockQdrantClientService::search_points (trait): result_to_return is: {:?}",
            match &result_to_return {
                Ok(v) => format!("Ok(len={})", v.len()),
                Err(e) => format!("Err({})", e)
            }
        );
        result_to_return
    }

    #[allow(dead_code)]
    async fn retrieve_points(
        &self,
        _filter: Option<Filter>,
        _limit: u64,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Use the search response for retrieve as well
        let response = self.search_response.lock().unwrap().take();
        response.unwrap_or(Ok(vec![]))
    }

    #[allow(dead_code)]
    async fn delete_points(&self, _point_ids: Vec<PointId>) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }

    #[allow(dead_code)]
    async fn update_collection_settings(&self) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
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
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt}; // Alias fmt to avoid collision with std::fmt

static TRACING_INIT: Once = Once::new();

// Helper function to ensure tracing is initialized (idempotent)
// Made public to be accessible from integration tests
pub fn ensure_tracing_initialized() {
    // Use tracing_subscriber::fmt and EnvFilter directly, relying on RUST_LOG
    TRACING_INIT.call_once(|| {
        // Attempt to initialize from RUST_LOG, default to "info" if not set or invalid
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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
    pub user_persona_service: Arc<UserPersonaService>, // <<< ADDED THIS FIELD
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

#[instrument(skip_all, fields(multi_thread, use_real_ai, use_real_qdrant))]
pub async fn spawn_app(multi_thread: bool, use_real_ai: bool, use_real_qdrant: bool) -> TestApp {
    ensure_tracing_initialized();
    dotenv().ok();

    let test_db_name_suffix = if multi_thread {
        Some(Uuid::new_v4().to_string()) // Ensure it's String for suffix
    } else {
        None
    };
    let pool: PgPool = db::setup_test_database(test_db_name_suffix.as_deref()).await;

    let mut config_loader = Config::load().expect("Failed to load test configuration");
    if let Some(ref suffix) = test_db_name_suffix {
        config_loader.database_url = Some(format!(
            "{}_{}",
            config_loader.database_url.unwrap_or_else(|| "postgres://user:pass@localhost/testdb".to_string()), // Provide a default if None
            suffix
        ));
    }
    config_loader.port = 0; 
    let config_arc = Arc::new(config_loader);

    let (ai_client_for_state, mock_ai_client_for_test_app): (
        Arc<dyn AiClient + Send + Sync>,
        Option<Arc<MockAiClient>>,
    ) = if use_real_ai {
        let real_ai_client = crate::llm::gemini_client::build_gemini_client()
            .await
            .expect("Failed to build real AI client for test");
        (Arc::new(real_ai_client), None)
    } else {
        let mock_client = Arc::new(MockAiClient::new());
        (mock_client.clone() as Arc<dyn AiClient + Send + Sync>, Some(mock_client))
    };

    let mock_embedding_client_instance = Arc::new(MockEmbeddingClient::new());
    let embedding_client_for_state =
        mock_embedding_client_instance.clone() as Arc<dyn EmbeddingClient + Send + Sync>;

    let (qdrant_service_for_state, mock_qdrant_service_for_test_app): (
        Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        Option<Arc<MockQdrantClientService>>,
    ) = if use_real_qdrant {
        let real_qdrant_service = QdrantClientService::new(config_arc.clone())
            .await
            .expect("Failed to create real Qdrant client for test");
        (Arc::new(real_qdrant_service) as Arc<dyn QdrantClientServiceTrait + Send + Sync>, None)
    } else {
        let mock_qdrant = Arc::new(MockQdrantClientService::new());
        (mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>, Some(mock_qdrant))
    };
    
    // Embedding Pipeline Service (use real one for tests that might need it, or mock)
    // For now, using the mock. If a real one is needed, it should be conditional like AI/Qdrant.
    let mock_embedding_pipeline_service_instance = Arc::new(MockEmbeddingPipelineService::new());
    let embedding_pipeline_service_for_state = mock_embedding_pipeline_service_instance.clone()
        as Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>;

    let tokenizer_model_path = config_arc
        .tokenizer_model_path
        .as_ref()
        .cloned()
        .expect("Tokenizer model path not set in config for tests");
    let tokenizer_service =
        TokenizerService::new(&tokenizer_model_path).expect("Failed to load tokenizer model for tests");

    let gemini_token_client_for_test = config_arc.gemini_api_key.as_ref().map(|api_key_string|
        GeminiTokenClient::new(api_key_string.clone()) 
    );

    let token_counter_default_model_for_test = config_arc
        .token_counter_default_model
        .as_ref()
        .cloned()
        .expect("Token counter default model not set in config for tests");

    let hybrid_token_counter = HybridTokenCounter::new(
        tokenizer_service,
        gemini_token_client_for_test, // This is Option<GeminiTokenClient>
        token_counter_default_model_for_test,
    );
    let hybrid_token_counter_arc = Arc::new(hybrid_token_counter);

    let encryption_service_arc = Arc::new(EncryptionService::new());
    let chat_override_service_arc = Arc::new(ChatOverrideService::new(pool.clone(), encryption_service_arc.clone()));
    let user_persona_service_arc = Arc::new(UserPersonaService::new(pool.clone(), encryption_service_arc.clone())); // <<< ADDED THIS

    let app_state_inner = AppState::new(
        pool.clone(),
        config_arc.clone(),
        ai_client_for_state.clone(),
        embedding_client_for_state.clone(), // Cloned
        qdrant_service_for_state.clone(),   // Cloned
        embedding_pipeline_service_for_state.clone(), // Cloned
        chat_override_service_arc.clone(), // Cloned
        user_persona_service_arc.clone(), // <<< ADDED THIS ARGUMENT
        hybrid_token_counter_arc.clone(), // Cloned
    );

    let session_store = DieselSessionStore::new(pool.clone());
    let secret_key_hex_str: &String = config_arc.cookie_signing_key.as_ref()
        .expect("COOKIE_SIGNING_KEY must be set for tests");
    let key_bytes = hex::decode(secret_key_hex_str.as_bytes()) // .as_bytes() on String
        .expect("Invalid COOKIE_SIGNING_KEY format in test config (must be hex)");
    let _signing_key = TowerSessionKey::from(&key_bytes);

    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(config_arc.session_cookie_secure)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    let auth_backend = AuthBackend::new(pool.clone());
    let auth_layer = AuthManagerLayerBuilder::new(auth_backend, session_manager_layer.clone()).build();
    
    let listener = TcpListener::bind(format!("127.0.0.1:{}", config_arc.port))
        .await
        .expect("Failed to bind to random port for test server");
    let local_addr = listener.local_addr().expect("Failed to get local address");
    let app_address = format!("http://{}", local_addr);

    debug!("Test app address: {}", app_address);

    let embedding_call_tracker_for_state = app_state_inner.embedding_call_tracker.clone();

    // Corrected Router Setup for Tests
    let public_api_routes_for_test = Router::new()
        .route("/health", get(health_check))
        .merge(Router::new().nest("/auth", auth_routes_module::auth_routes())); // Align with main.rs

    let protected_api_routes_for_test = Router::new()
        .nest("/characters", characters::characters_router(app_state_inner.clone()))
        .nest("/chat", chat_routes(app_state_inner.clone()))
        .nest("/chats", chats::chat_routes()) // Assuming this returns Router<AppState> or is already stateful
        .nest("/documents", document_routes()) // Assuming this returns Router<AppState> or is already stateful
        .nest("/personas", user_persona_routes::user_personas_router(app_state_inner.clone())) // Add persona routes
        .route_layer(middleware::from_fn_with_state(app_state_inner.clone(), auth_log_wrapper));

    // Combine public and protected routes before nesting under /api
    let all_api_routes = Router::new()
        .merge(public_api_routes_for_test) // Contains /health, /auth/*
        .merge(protected_api_routes_for_test); // Re-enabled protected routes

    let router_for_server = Router::new() // Renamed to avoid conflict with router field in TestApp
        .nest("/api", all_api_routes) // Nest all combined API routes under /api
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        .with_state(app_state_inner.clone());

    let router_for_test_app = router_for_server.clone(); // Clone before moving

    tokio::spawn(async move {
        axum::serve(listener, router_for_server.into_make_service()) // Use router_for_server
            .await
            .expect("Test server failed");
    });

    TestApp {
        address: app_address,
        router: router_for_test_app, // Use the cloned router
                               // Direct reqwest calls are made to `app_address`.
                               // Keeping it to satisfy struct, but should ideally be removed or used consistently.
        db_pool: pool,
        config: config_arc,
        ai_client: ai_client_for_state,
        mock_ai_client: mock_ai_client_for_test_app,
        mock_embedding_client: mock_embedding_client_instance,
        mock_embedding_pipeline_service: mock_embedding_pipeline_service_instance,
        qdrant_service: qdrant_service_for_state,
        mock_qdrant_service: mock_qdrant_service_for_test_app,
        user_persona_service: user_persona_service_arc, // <<< ADDED THIS INITIALIZATION
        embedding_call_tracker: embedding_call_tracker_for_state,
    }
}

// --- Modules containing test helpers ---

pub mod db {
    // Add a comprehensive set of imports needed within the db module
    use crate::models::users::UserDbQuery;
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness; // User was already imported, ensure UserDbQuery is correct
    // Import AppError

    use crate::PgPool; // This should refer to the top-level crate::PgPool
    use uuid::Uuid;

    // For logging macros
    use super::MIGRATIONS; // Use super::MIGRATIONS since it's defined in the parent scope (test_helpers.rs)
    use crate::auth::{self};
    use deadpool_diesel::postgres::{
        Manager as DeadpoolManager, Pool as DeadpoolPool, Runtime as DeadpoolRuntime,
    };
    use dotenvy::dotenv; // For .env file loading
    use std::env; // For DATABASE_URL reading in setup_test_database // Corrected: Added hash_password, auth for module items
    // Ensure RegisterPayload is imported
    use super::*; // To bring PgPool and DbUser etc. into scope
    // Keep if CryptoError is used directly, else it comes via crate::crypto
    use crate::models::users::NewUser; // Removed User as DbUser from here, already aliased DbUser at top
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
            .map_err(|e| anyhow::anyhow!("KEK salt generation failed: {}", e))?;

        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        let plaintext_dek_box: SecretBox<Vec<u8>> =
            crate::crypto::generate_dek().context("DEK generation failed in create_test_user")?;

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
            account_status: AccountStatus::Active,      // Default to Active account status
        };

        let user_from_db: UserDbQuery = conn
            .interact(move |conn_actual| {
                diesel::insert_into(crate::schema::users::table)
                    .values(new_user_payload) // new_user_payload is moved here
                    .returning(UserDbQuery::as_returning())
                    .get_result::<UserDbQuery>(conn_actual)
            })
            .await
            .map_err(|interact_err| {
                anyhow::anyhow!("DB interact error for create_test_user: {}", interact_err)
            })??;

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
            description: Some(
                format!("Test description for {}", name_clone_for_payload).into_bytes(),
            ),
            greeting: Some(format!("Test greeting for {}", name_clone_for_payload).into_bytes()),
            example_dialogue: Some(
                format!("Test example dialogue for {}", name_clone_for_payload).into_bytes(),
            ),
            visibility: Some("private".to_string()),
            character_version: Some("2.0".to_string()),
            spec: "test_spec_v2.0".to_string(),
            spec_version: "2.0".to_string(),
            persona: Some(format!("Test persona for {}", name_clone_for_payload).into_bytes()),
            world_scenario: Some(
                format!("Test world scenario for {}", name_clone_for_payload).into_bytes(),
            ),
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

        let character: Character = conn
            .interact(move |conn_actual| {
                diesel::insert_into(crate::schema::characters::table)
                    .values(new_character_payload) // new_character_payload is moved here
                    .returning(Character::as_returning())
                    .get_result::<Character>(conn_actual)
            })
            .await
            .map_err(move |interact_err| {
                anyhow::anyhow!(
                    "DB interact error for create_test_character '{}': {}",
                    name_clone_for_error,
                    interact_err
                )
            })??;

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
    pub fn new(pool: PgPool) -> Self {
        // Changed to PgPool
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
        let conn = self
            .pool
            .get()
            .await
            .context("Failed to get DB connection for cleanup")?;

        if !self.chat_ids.is_empty() {
            tracing::debug!(chat_ids = ?self.chat_ids, "Cleaning up test chats and messages");
            let chat_ids_clone = self.chat_ids.clone();
            let diesel_chat_op_result = conn
                .interact(move |conn_interaction| {
                    diesel::delete(
                        schema::chat_messages::table
                            .filter(schema::chat_messages::session_id.eq_any(&chat_ids_clone)),
                    )
                    .execute(conn_interaction)?;
                    diesel::delete(
                        schema::chat_sessions::table
                            .filter(schema::chat_sessions::id.eq_any(chat_ids_clone.clone())),
                    )
                    .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_chat_op_result.context("Interact error cleaning up chats")?;
        }

        if !self.character_ids.is_empty() {
            tracing::debug!(character_ids = ?self.character_ids, "Cleaning up test characters");
            let character_ids_clone = self.character_ids.clone();
            let diesel_op_result_chars = conn
                .interact(move |conn_interaction| {
                    diesel::delete(
                        schema::characters::table
                            .filter(schema::characters::id.eq_any(character_ids_clone)),
                    )
                    .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_chars.context("Interact error cleaning up characters")?;
        }

        if !self.user_ids.is_empty() {
            tracing::debug!(user_ids = ?self.user_ids, "Cleaning up test users");
            let user_ids_clone = self.user_ids.clone();
            let diesel_op_result_users = conn
                .interact(move |conn_interaction| {
                    diesel::delete(
                        schema::users::table.filter(schema::users::id.eq_any(user_ids_clone)),
                    )
                    .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
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
        if !self.user_ids.is_empty() || !self.character_ids.is_empty() || !self.chat_ids.is_empty()
        {
            // Use a blocking spawn for the async cleanup task
            // This is not ideal for drop, but better than panicking or doing nothing.
            // Consider making cleanup explicit in all tests.
            let _pool_clone = self.pool.clone(); // Renamed pool_clone
            let user_ids_clone = self.user_ids.drain(..).collect::<Vec<_>>();
            let character_ids_clone = self.character_ids.drain(..).collect::<Vec<_>>();
            let chat_ids_clone = self.chat_ids.drain(..).collect::<Vec<_>>();

            if !user_ids_clone.is_empty()
                || !character_ids_clone.is_empty()
                || !chat_ids_clone.is_empty()
            {
                tracing::warn!(
                    "TestDataGuard dropped without explicit cleanup. Attempting synchronous cleanup (best effort)."
                );
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

pub fn db_specific_cleanup(
    conn: &mut PgConnection,
    test_data: &TestDataGuard,
) -> Result<(), anyhow::Error> {
    // Clean up chat messages first (if any, assuming chat_messages depend on chats)
    // Example: diesel::delete(schema::chat_messages::table.filter(...)).execute(conn)?;

    if !test_data.chat_ids.is_empty() {
        let chat_ids_clone = test_data.chat_ids.clone();
        diesel::delete(
            schema::chat_sessions::table.filter(schema::chat_sessions::id.eq_any(chat_ids_clone)),
        )
        .execute(conn)?;
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
) -> Result<(User, String), anyhow::Error> {
    // Returns User and session cookie string
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
    )
    .await
    .context("Failed to create user in DB for session test")?;

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
    if let Some(pt_dek_string) = plaintext_dek {
        // Use the original plaintext_dek passed to function
        let dek_bytes = pt_dek_string.expose_secret().as_bytes().to_vec();
        let secret_box = SecretBox::new(Box::new(dek_bytes));
        mock_user_for_assertion.dek = Some(SerializableSecretDek(secret_box));
    } else {
        mock_user_for_assertion.dek = None;
    }

    // 4. Return User and cookie
    Ok((mock_user_for_assertion, actual_cookie_value)) // Use the cookie from step 2
}

// Helper function for API-based login
pub async fn login_user_via_api(test_app: &TestApp, username: &str, password: &str) -> String {
    let login_payload = json!({
        "identifier": username,
        "password": password
    });

    // Create a new reqwest client for each call, or pass one in TestApp
    let client = reqwest::Client::builder()
        .cookie_store(true) // Enable cookie store for this client
        .build()
        .expect("Failed to build reqwest client for login");

    let login_url = format!("{}/api/auth/login", test_app.address);

    let response = client
        .post(&login_url)
        .json(&login_payload)
        .send()
        .await
        .expect("Login request failed to send");

    if response.status() != reqwest::StatusCode::OK {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_else(|e| format!("Failed to read error body: {}", e));
        panic!(
            "API login failed for user '{}'. Status: {}. URL: {}. Body: {}",
            username, status, login_url, body_text
        );
    }

    // Extract the session cookie
    response
        .cookies()
        .find(|c| c.name() == "id") // Assuming session cookie name is "id"
        .map(|c| format!("{}={}", c.name(), c.value()))
        .unwrap_or_else(|| {
            let headers_debug = format!("{:?}", response.headers());
            panic!(
                "Session cookie 'id' not found in login response for user {}. URL: {}. Headers: {}",
                username, login_url, headers_debug
            )
        })
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
                if line.is_empty() {
                    // End of an event
                    if !current_data_lines.is_empty() {
                        // Only push if there's data
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

// Helper to assert the history sent to the mock AI client
pub fn assert_ai_history(
    test_app: &TestApp,
    expected_history: Vec<(&str, &str)>, // (Role, Content)
) {
    let last_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    let mut history_start_index = 0;
    if let Some(first_msg) = last_request.messages.first() {
        if matches!(first_msg.role, genai::chat::ChatRole::System) {
            history_start_index = 1;
            debug!("[DEBUG] System prompt detected, starting history comparison from index 1.");
        }
    }
    let history_end_index = last_request.messages.len().saturating_sub(1);
    let history_start_index = history_start_index.min(history_end_index);
    let history_sent_to_ai = &last_request.messages[history_start_index..history_end_index];

    println!(
        "\n[DEBUG] All messages sent to AI client (including system prompt and current prompt):"
    );
    for (i, msg) in last_request.messages.iter().enumerate() {
        let role_str = match msg.role {
            genai::chat::ChatRole::User => "User",
            genai::chat::ChatRole::Assistant => "Assistant",
            genai::chat::ChatRole::System => "System",
            _ => "Unknown",
        };
        let content = match &msg.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => "<non-text content>",
        };
        println!("  [{}] {}: {}", i, role_str, content);
    }

    println!(
        "\n[DEBUG] Comparing {} expected messages against {} actual messages in history (excluding current prompt)",
        expected_history.len(),
        history_sent_to_ai.len()
    );

    assert_eq!(
        history_sent_to_ai.len(),
        expected_history.len(),
        "Number of history messages sent to AI mismatch. Actual: {:?}, Expected: {:?}",
        history_sent_to_ai
            .iter()
            .map(|m| (
                format!("{:?}", m.role),
                if let genai::chat::MessageContent::Text(t) = &m.content {
                    t.clone()
                } else {
                    "".to_string()
                }
            ))
            .collect::<Vec<_>>(),
        expected_history
    );

    for (i, expected) in expected_history.iter().enumerate() {
        let actual = &history_sent_to_ai[i];
        let (expected_role_str, expected_content) = expected;

        let actual_role_str = match actual.role {
            genai::chat::ChatRole::User => "User",
            genai::chat::ChatRole::Assistant => "Assistant",
            genai::chat::ChatRole::System => "System",
            _ => panic!("Unexpected role in AI history: {:?}", actual.role),
        };
        let actual_content = match &actual.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => panic!(
                "Expected text content in AI history, got: {:?}",
                actual.content
            ),
        };

        println!(
            "[DEBUG] Compare message {}: Expected {}:'{}' vs Actual {}:'{}'",
            i, expected_role_str, expected_content, actual_role_str, actual_content
        );

        assert_eq!(
            actual_role_str, *expected_role_str,
            "Role mismatch at index {}",
            i
        );
        assert_eq!(
            actual_content, *expected_content,
            "Content mismatch at index {}",
            i
        );
    }
}

// Helper to set history management settings via API
pub async fn set_history_settings(
    test_app: &TestApp,
    session_id: Uuid,
    auth_cookie: &str,
    strategy: Option<String>,
    limit: Option<i32>,
) -> anyhow::Result<()> {
    let payload = UpdateChatSettingsRequest {
        history_management_strategy: strategy,
        history_management_limit: limit,
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        model_name: None,
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };

    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/api/chat/{}/settings", test_app.address, session_id))
        .header(reqwest::header::COOKIE, auth_cookie)
        .header(reqwest::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .json(&payload)
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Failed to set history settings via API"
    );
    // Ensure body is consumed to prevent issues, but we don't need to parse it here.
    let _ = response.bytes().await?;
    Ok(())
}
