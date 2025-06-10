// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.

// Make sure all necessary imports from the main crate and external crates are included.
use crate::errors::AppError;
use crate::llm::{AiClient, BatchEmbeddingContentRequest, ChatStream, EmbeddingClient}; // Add EmbeddingClient and BatchEmbeddingContentRequest
use crate::services::embedding_pipeline::{
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait, LorebookEntryParams, RetrievedChunk,
}; // Added EmbeddingPipelineService
use crate::text_processing::chunking::ChunkConfig;
use genai::chat::Usage; // Added ChunkConfig
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
        auth as auth_routes_module,
        characters,
        chat::chat_routes,
        chats,
        documents::document_routes,
        health::health_check,
        lorebook_routes, // Added lorebook_routes
        user_persona_routes,
        user_settings_routes,
    },
    schema,
    services::chat_override_service::ChatOverrideService, // <<< ENSURED IMPORT
    services::encryption_service::EncryptionService,      // <<< ENSURED IMPORT
    services::file_storage_service::FileStorageService,   // <<< ADDED THIS IMPORT
    services::gemini_token_client::GeminiTokenClient,
    services::hybrid_token_counter::HybridTokenCounter,
    services::tokenizer_service::TokenizerService,
    services::user_persona_service::UserPersonaService, // <<< ADDED THIS IMPORT
    state::{AppState, AppStateServices},
    vector_db::qdrant_client::QdrantClientService, // Import constants module alias
};
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use axum::{
    Router,
    middleware::{self, Next},
    response::Response as AxumResponse, // Alias to avoid conflict if Response is used elsewhere
    routing::get,                       // <<< ADD THIS IMPORT
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
use genai::chat::{ChatOptions, ChatRequest, ChatResponse, StreamEnd};
// use http_body_util::BodyExt; // Removed unused import
use mime; // Added for mime::APPLICATION_JSON
use qdrant_client::qdrant::{Filter, PointId, ScoredPoint};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::collections::VecDeque; // Added for MockQdrantClientService response queue
use std::fmt;
use std::sync::{Arc, Mutex}; // Add Mutex import
use tokio::net::TcpListener;
// use tokio::sync::Mutex as TokioMutex; // Removed unused import
use hex; // Added for hex::decode
use http_body_util::BodyExt; // For collect() on Body
use reqwest;
use rustls;
use time; // For time::Duration for session expiry
use tower::ServiceExt; // For .oneshot
use tower_cookies::CookieManagerLayer; // Removed unused: Key as TowerCookieKey
use tower_sessions::{
    Expiry, SessionManagerLayer, cookie::Key as TowerSessionKey, cookie::SameSite,
}; // Added SameSite
use tracing::{debug, instrument, warn}; // Added debug
use uuid::Uuid; // Added for CryptoProvider

// Type aliases for complex test types
type EmbeddingResponse = Arc<Mutex<Option<Result<Vec<f32>, AppError>>>>;
type EmbeddingResponseSequence = Arc<Mutex<VecDeque<Result<Vec<f32>, AppError>>>>;
type BatchEmbeddingResponse = Arc<Mutex<Option<Result<Vec<Vec<f32>>, AppError>>>>;
type EmbeddingCalls = Arc<Mutex<Vec<(String, String, Option<String>)>>>;
type BatchEmbeddingCalls = Arc<Mutex<Vec<Vec<(String, String, Option<String>)>>>>;
type SearchParams = Arc<Mutex<Option<(Vec<f32>, u64, Option<Filter>)>>>;
type SearchResponseQueue = Arc<Mutex<VecDeque<Result<Vec<ScoredPoint>, AppError>>>>;
type ChatEventStream =
    std::sync::Arc<std::sync::Mutex<Option<Vec<Result<ChatStreamEvent, AppError>>>>>;
type RetrievalResponseQueue = Arc<Mutex<VecDeque<Result<Vec<RetrievedChunk>, AppError>>>>;

#[derive(Clone)]
pub struct MockAiClient {
    // Add fields to store mock state, similar to previous mock impl
    // These need Arc<Mutex<...>> for thread safety if mock is shared across awaits
    last_request: std::sync::Arc<std::sync::Mutex<Option<ChatRequest>>>,
    last_options: std::sync::Arc<std::sync::Mutex<Option<ChatOptions>>>,
    response_to_return: std::sync::Arc<std::sync::Mutex<Result<ChatResponse, AppError>>>,
    stream_to_return: ChatEventStream,
    // Field to capture the messages sent to the stream_chat method
    last_received_messages: std::sync::Arc<std::sync::Mutex<Option<Vec<genai::chat::ChatMessage>>>>,
    // model_name: String, // Removed unused
    // provider_model_name: String, // Removed unused
    // embedding_response: Arc<Mutex<Result<Vec<f32>, AppError>>>, // Removed unused
    // text_gen_response: Arc<Mutex<Result<String, AppError>>>, // Removed unused
}

impl MockAiClient {
    #[must_use]
    pub fn new() -> Self {
        // Initialize fields with default values
        Self {
            last_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_options: std::sync::Arc::new(std::sync::Mutex::new(None)),
            // Default to a simple OK response
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    "Mock AI response".to_string(),
                )],
                reasoning_content: None,
                usage: Usage::default(),
            }))),
            stream_to_return: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_received_messages: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    // Add placeholder methods called by tests
    /// Gets the last request sent to the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_last_request(&self) -> Option<ChatRequest> {
        // TODO: Implement mock logic
        self.last_request.lock().unwrap().clone()
    }

    /// Gets the last options sent to the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_last_options(&self) -> Option<ChatOptions> {
        // TODO: Implement mock logic
        self.last_options.lock().unwrap().clone()
    }

    // Method to retrieve the captured messages
    /// Gets the last received messages from the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_last_received_messages(&self) -> Option<Vec<genai::chat::ChatMessage>> {
        self.last_received_messages.lock().unwrap().clone()
    }

    /// Sets the response for the mock AI client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_response(&self, response: Result<ChatResponse, AppError>) {
        // TODO: Implement mock logic
        *self.response_to_return.lock().unwrap() = response;
    }

    /// Sets the stream response for the mock AI client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
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
            (*guard).as_ref().map_or_else(Vec::new, |item_results| {
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
                                // ChatStreamEvent::ToolCall(tool_call) => { // Commented out as ToolCall is not expected from Gemini Streamer
                                //     // Assuming genai::chat::ToolCall is effectively cloneable by its fields
                                //     ChatStreamEvent::ToolCall(genai::chat::ToolCall {
                                //         call_id: tool_call.call_id.clone(),
                                //         fn_name: tool_call.fn_name.clone(),
                                //         fn_arguments: tool_call.fn_arguments.clone(),
                                //     })
                                // }
                                ChatStreamEvent::End(_end_event) => {
                                    ChatStreamEvent::End(StreamEnd::default())
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
            })
        }; // Mutex guard is dropped here

        let stream = futures::stream::iter(items);
        Ok(Box::pin(stream) as ChatStream)
    }
}

#[derive(Clone)]
pub struct MockEmbeddingClient {
    response: EmbeddingResponse,
    response_sequence: EmbeddingResponseSequence, // For sequential responses
    batch_response: BatchEmbeddingResponse,       // For batch_embed_contents
    calls: EmbeddingCalls,                        // Added Option<String> for title
    batch_calls: BatchEmbeddingCalls, // For batch_embed_contents calls, storing Vec of batches, each batch is Vec of (text, task_type, title)
}

impl Default for MockEmbeddingClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEmbeddingClient {
    #[must_use]
    pub fn new() -> Self {
        Self {
            response: Arc::new(Mutex::new(None)),
            response_sequence: Arc::new(Mutex::new(VecDeque::new())),
            batch_response: Arc::new(Mutex::new(None)),
            calls: Arc::new(Mutex::new(Vec::new())),
            batch_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Sets the single embedding response for the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_response(&self, response: Result<Vec<f32>, AppError>) {
        let mut lock = self.response.lock().unwrap();
        *lock = Some(response);
    }

    /// Sets the batch embedding response for the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_batch_response(&self, response: Result<Vec<Vec<f32>>, AppError>) {
        let mut lock = self.batch_response.lock().unwrap();
        *lock = Some(response);
    }

    /// Sets a sequence of embedding responses for the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_responses_sequence(&self, responses: Vec<Result<Vec<f32>, AppError>>) {
        let mut queue = self.response_sequence.lock().unwrap();
        queue.clear();
        for response in responses {
            queue.push_back(response);
        }
    }

    /// Gets all embedding calls made to the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_calls(&self) -> Vec<(String, String, Option<String>)> {
        self.calls.lock().unwrap().clone()
    }

    /// Gets all batch embedding calls made to the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_batch_calls(&self) -> Vec<Vec<(String, String, Option<String>)>> {
        self.batch_calls.lock().unwrap().clone()
    }

    /// Clears all recorded calls for the mock client
    ///
    /// # Panics
    ///
    /// Panics if any mutex lock is poisoned
    pub fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
        self.batch_calls.lock().unwrap().clear();
    }
}

#[async_trait]
impl EmbeddingClient for MockEmbeddingClient {
    async fn embed_content(
        &self,
        text: &str,
        task_type: &str,
        title: Option<&str>,
    ) -> Result<Vec<f32>, AppError> {
        // Record the call
        self.calls.lock().unwrap().push((
            text.to_string(),
            task_type.to_string(),
            title.map(String::from),
        ));

        // Try to get response from sequence first
        let mut sequence_guard = self.response_sequence.lock().unwrap();
        if let Some(res_from_sequence) = sequence_guard.pop_front() {
            return res_from_sequence;
        }
        // Drop guard to release lock before potentially locking self.response
        drop(sequence_guard);

        // If sequence is empty, try the single response
        let value = self.response.lock().unwrap().clone();
        value.unwrap_or_else(|| {
            // Default behavior if no response is set
            warn!(
                "MockEmbeddingClient response and sequence not set, returning default OK response."
            ); // Keep warning
            Ok(vec![0.0; 768]) // Restore default Ok(...) behavior
        })
    }

    async fn batch_embed_contents(
        &self,
        requests: Vec<BatchEmbeddingContentRequest<'_>>,
    ) -> Result<Vec<Vec<f32>>, AppError> {
        // Record the call
        let current_batch_owned: Vec<(String, String, Option<String>)> = requests
            .into_iter()
            .map(|req| {
                (
                    req.text.to_string(),
                    req.task_type.to_string(),
                    None, // Title field removed from BatchEmbeddingContentRequest
                )
            })
            .collect();
        self.batch_calls.lock().unwrap().push(current_batch_owned);

        // Return the pre-set response or a default
        let value = self.batch_response.lock().unwrap().clone();
        value.unwrap_or_else(|| {
            warn!(
                "MockEmbeddingClient batch_response not set, returning default Ok(vec![]) response."
            );
            Ok(Vec::new()) // Default to empty vec of embeddings
        })
    }
}

#[derive(Clone, Debug)] // Added Clone, Debug
pub enum PipelineCall {
    RetrieveRelevantChunks {
        user_id: Uuid,                             // Renamed from chat_id
        session_id_for_chat_history: Option<Uuid>, // New field - Updated to Option<Uuid>
        query_text: String,
        limit: u64,
        active_lorebook_ids_for_search: Option<Vec<Uuid>>, // New field
    },
    ProcessAndEmbedMessage {
        message_id: Uuid,
        session_id: Uuid,
    },
    ProcessAndEmbedLorebookEntry {
        original_lorebook_entry_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        decrypted_content: String,
        decrypted_title: Option<String>,
        decrypted_keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
    },
}

// Updated MockEmbeddingPipelineService
#[derive(Clone)] // Added Clone
pub struct MockEmbeddingPipelineService {
    retrieve_response_queue: RetrievalResponseQueue,
    calls: Arc<Mutex<Vec<PipelineCall>>>, // Track calls
}

impl Default for MockEmbeddingPipelineService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEmbeddingPipelineService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            retrieve_response_queue: Arc::new(Mutex::new(VecDeque::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Gets all pipeline calls made to the mock service
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    #[must_use]
    pub fn get_calls(&self) -> Vec<PipelineCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Sets the retrieve response for the mock service
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_retrieve_response(&self, response: Result<Vec<RetrievedChunk>, AppError>) {
        let mut queue = self.retrieve_response_queue.lock().unwrap();
        queue.clear();
        queue.push_back(response);
    }

    /// Adds a retrieve response to the queue for the mock service
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn add_retrieve_response(&self, response: Result<Vec<RetrievedChunk>, AppError>) {
        self.retrieve_response_queue
            .lock()
            .unwrap()
            .push_back(response);
    }

    /// Sets a sequence of retrieve responses for the mock service
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_retrieve_responses_sequence(
        &self,
        responses: Vec<Result<Vec<RetrievedChunk>, AppError>>,
    ) {
        let mut queue = self.retrieve_response_queue.lock().unwrap();
        queue.clear();
        for response in responses {
            queue.push_back(response);
        }
    }

    /// Clears all recorded calls for the mock service
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
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

    async fn process_and_embed_lorebook_entry(
        &self,
        _state: Arc<AppState>,
        params: LorebookEntryParams,
    ) -> Result<(), AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedLorebookEntry {
                original_lorebook_entry_id: params.original_lorebook_entry_id,
                lorebook_id: params.lorebook_id,
                user_id: params.user_id,
                decrypted_content: params.decrypted_content,
                decrypted_title: params.decrypted_title,
                decrypted_keywords: params.decrypted_keywords,
                is_enabled: params.is_enabled,
                is_constant: params.is_constant,
            });
        Ok(())
    }

    async fn retrieve_relevant_chunks(
        &self,
        _state: Arc<AppState>,
        user_id: Uuid,                                     // New parameter
        session_id_for_chat_history: Option<Uuid>, // New parameter - Updated to Option<Uuid>
        active_lorebook_ids_for_search: Option<Vec<Uuid>>, // New parameter
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveRelevantChunks {
                user_id,
                session_id_for_chat_history, // This is Option<Uuid>
                query_text: query_text.to_string(), // Corrected order
                limit,                       // Corrected order
                active_lorebook_ids_for_search, // Corrected order
            });

        // Return the next response from the queue
        let mut queue = self.retrieve_response_queue.lock().unwrap();
        queue.pop_front().map_or_else(|| {
            // It's important for tests to set up responses correctly.
            // Panicking here makes it clear if a response was expected but not provided.
            panic!(
                "MockEmbeddingPipelineService::retrieve_relevant_chunks called but no more responses were queued. Ensure your test sets up enough responses."
            );
        }, |response| response)
    }

    async fn delete_lorebook_entry_chunks(
        &self,
        _state: Arc<AppState>,
        original_lorebook_entry_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        tracing::info!(
            target: "mock_embedding_pipeline",
            "MockEmbeddingPipelineService::delete_lorebook_entry_chunks called for entry_id: {}, user_id: {}",
            original_lorebook_entry_id, user_id
        );
        // In a real scenario, this would interact with Qdrant via QdrantClientService
        // For the mock, we just log and return Ok.
        // If tests need to verify this was called, they can check logs or add to `self.calls`.
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockQdrantClientService {
    upsert_response: Arc<Mutex<Option<Result<(), AppError>>>>,
    search_response: SearchResponseQueue,
    upsert_call_count: Arc<Mutex<usize>>,
    search_call_count: Arc<Mutex<usize>>,
    last_upsert_points: Arc<Mutex<Option<Vec<qdrant_client::qdrant::PointStruct>>>>,
    last_search_params: SearchParams,
    calls_delete_points_by_filter: Arc<Mutex<Vec<Filter>>>, // New field to track delete_points_by_filter calls
}

impl Default for MockQdrantClientService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockQdrantClientService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            upsert_response: Arc::new(Mutex::new(None)),
            search_response: Arc::new(Mutex::new(VecDeque::new())), // Initialize with an empty VecDeque
            upsert_call_count: Arc::new(Mutex::new(0)),
            search_call_count: Arc::new(Mutex::new(0)),
            last_upsert_points: Arc::new(Mutex::new(None)),
            last_search_params: Arc::new(Mutex::new(None)),
            calls_delete_points_by_filter: Arc::new(Mutex::new(Vec::new())), // Initialize
        }
    }

    /// Gets all delete_points_by_filter calls made to the mock client
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned
    #[must_use]
    pub fn get_delete_points_by_filter_calls(&self) -> Vec<Filter> {
        self.calls_delete_points_by_filter.lock().unwrap().clone()
    }

    /// Sets the response for the next upsert operation
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_upsert_response(&self, response: Result<(), AppError>) {
        let mut lock = self.upsert_response.lock().unwrap();
        *lock = Some(response);
    }

    /// Gets the number of upsert calls made
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    #[must_use]
    pub fn get_upsert_call_count(&self) -> usize {
        *self.upsert_call_count.lock().unwrap()
    }

    /// Gets the points from the last upsert operation
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    #[must_use]
    pub fn get_last_upsert_points(&self) -> Option<Vec<qdrant_client::qdrant::PointStruct>> {
        self.last_upsert_points.lock().unwrap().clone()
    }

    /// Sets a single search response
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_search_response(&self, response: Result<Vec<ScoredPoint>, AppError>) {
        let mut queue = self.search_response.lock().unwrap();
        queue.clear();
        queue.push_back(response);
    }

    /// Adds a search response to the queue
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn add_search_response(&self, response: Result<Vec<ScoredPoint>, AppError>) {
        self.search_response.lock().unwrap().push_back(response);
    }

    /// Sets a sequence of search responses
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_search_responses_sequence(
        &self,
        responses: Vec<Result<Vec<ScoredPoint>, AppError>>,
    ) {
        let mut queue = self.search_response.lock().unwrap();
        queue.clear();
        for response in responses {
            queue.push_back(response);
        }
    }

    /// Returns the number of search calls made to this mock client.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_search_call_count(&self) -> usize {
        *self.search_call_count.lock().unwrap()
    }

    /// Gets the parameters from the last search operation
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    #[must_use]
    pub fn get_last_search_params(&self) -> Option<(Vec<f32>, u64, Option<Filter>)> {
        self.last_search_params.lock().unwrap().clone()
    }

    /// Upserts points in the mock implementation
    ///
    /// # Errors
    ///
    /// Returns any error configured via `set_upsert_response`, or `Ok(())` if no error is configured
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn upsert_points(
        &self,
        points: Vec<qdrant_client::qdrant::PointStruct>,
    ) -> Result<(), AppError> {
        // Track call
        {
            *self.upsert_call_count.lock().unwrap() += 1;
            *self.last_upsert_points.lock().unwrap() = Some(points);
        }

        // Return response
        let response = self.upsert_response.lock().unwrap().take();
        response.unwrap_or(Ok(()))
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
            *self.upsert_call_count.lock().unwrap() += 1;
            *self.last_upsert_points.lock().unwrap() = Some(points);
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
            *self.search_call_count.lock().unwrap() += 1;

            let mut last_params = self.last_search_params.lock().unwrap();
            *last_params = Some((vector, limit, filter));
        }

        // Return response
        let mut queue = self.search_response.lock().unwrap();
        queue.pop_front().map_or_else(|| {
            // It's okay for retrieve_points to return empty if not specifically set up,
            // as it might be called unexpectedly in some test flows.
            // However, for search_points, we want to be strict.
            // This branch should ideally not be hit if tests correctly set up responses.
            // For safety in tests that might not set up enough, we could panic or return a specific error.
            // For now, keeping the warn and returning empty Ok to match previous behavior for un-queued calls.
            warn!(
                "MockQdrantClientService::search_points (trait) called but no response was queued. Returning Ok(vec![])."
            );
            Ok(vec![])
        }, |response_result| {
            // Apply the limit to the Ok variant
            match response_result {
                Ok(mut points) => {
                    points.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                    Ok(points)
                }
                Err(e) => Err(e), // Pass through errors
            }
        })
    }

    async fn retrieve_points(
        &self,
        _filter: Option<Filter>,
        _limit: u64,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Use the search response for retrieve as well
        let mut queue = self.search_response.lock().unwrap();
        queue.pop_front().map_or_else(|| {
            warn!(
                "MockQdrantClientService::retrieve_points (trait) called but no response was queued. Returning Ok(vec![])."
            );
            Ok(vec![])
        }, |response| response)
    }

    async fn delete_points(&self, _point_ids: Vec<PointId>) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }

    async fn update_collection_settings(&self) -> Result<(), AppError> {
        Ok(()) // Just return success for the mock
    }

    async fn delete_points_by_filter(&self, filter: Filter) -> Result<(), AppError> {
        // Record the call
        self.calls_delete_points_by_filter
            .lock()
            .unwrap()
            .push(filter);
        Ok(())
    }

    async fn get_point_by_id(
        &self,
        point_id: PointId,
    ) -> Result<Option<qdrant_client::qdrant::RetrievedPoint>, AppError> {
        // For the mock, we don't have a sophisticated way to store/retrieve individual points yet.
        // We can extend this if tests need to verify specific point retrieval.
        // For now, let's log the call and return Ok(None) or a pre-set response if we add one.
        tracing::info!(
            target: "mock_qdrant_client",
            "MockQdrantClientService::get_point_by_id called with point_id: {:?}",
            point_id.point_id_options
        );
        // If you need to test retrieval, you'd add a field to MockQdrantClientService
        // like `point_to_return: Arc<Mutex<Option<Result<Option<RetrievedPoint>, AppError>>>>`
        // and set it in your tests.
        // For now, returning Ok(None) to satisfy the trait.
        Ok(None)
    }
}

// --- END Placeholder Mock Definitions ---

pub struct TestAppStateBuilder {
    db_pool: PgPool,
    config: Arc<Config>,
    ai_client: Arc<dyn AiClient + Send + Sync>,
    embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
    qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    embedding_pipeline_service: Option<Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>>,
    chat_override_service: Option<Arc<ChatOverrideService>>,
    user_persona_service: Option<Arc<UserPersonaService>>,
    token_counter: Option<Arc<HybridTokenCounter>>,
    lorebook_service: Option<Arc<crate::services::lorebook_service::LorebookService>>, // Fully qualify
    auth_backend: Arc<AuthBackend>, // Add auth_backend to builder
}

impl TestAppStateBuilder {
    #[must_use]
    pub fn new(
        db_pool: PgPool,
        config: Arc<Config>,
        ai_client: Arc<dyn AiClient + Send + Sync>,
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        auth_backend: Arc<AuthBackend>,
    ) -> Self {
        Self {
            db_pool,
            config,
            ai_client,
            embedding_client,
            qdrant_service,
            embedding_pipeline_service: None,
            chat_override_service: None,
            user_persona_service: None,
            token_counter: None,
            lorebook_service: None,
            auth_backend,
        }
    }

    #[must_use]
    pub fn with_embedding_pipeline_service(
        mut self,
        service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>,
    ) -> Self {
        self.embedding_pipeline_service = Some(service);
        self
    }

    #[must_use]
    pub fn with_chat_override_service(mut self, service: Arc<ChatOverrideService>) -> Self {
        self.chat_override_service = Some(service);
        self
    }

    #[must_use]
    pub fn with_user_persona_service(mut self, service: Arc<UserPersonaService>) -> Self {
        self.user_persona_service = Some(service);
        self
    }

    #[must_use]
    pub fn with_token_counter(mut self, counter: Arc<HybridTokenCounter>) -> Self {
        self.token_counter = Some(counter);
        self
    }

    #[must_use]
    pub fn with_lorebook_service(
        mut self,
        service: Arc<crate::services::lorebook_service::LorebookService>, // Fully qualify
    ) -> Self {
        self.lorebook_service = Some(service);
        self
    }

    /// Build the `AppState` instance
    ///
    /// # Panics
    ///
    /// Panics if the tokenizer model cannot be loaded from the expected path
    #[must_use]
    pub fn build(self) -> AppState {
        let encryption_service = Arc::new(EncryptionService::new());

        let embedding_pipeline_service = self.embedding_pipeline_service.unwrap_or_else(|| {
            // Correctly derive ChunkConfig from the main Config
            let chunk_config = ChunkConfig::from(self.config.as_ref());
            // EmbeddingPipelineService::new only takes chunk_config
            Arc::new(EmbeddingPipelineService::new(chunk_config))
        });

        let chat_override_service = self.chat_override_service.unwrap_or_else(|| {
            Arc::new(ChatOverrideService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ))
        });

        let user_persona_service = self.user_persona_service.unwrap_or_else(|| {
            Arc::new(UserPersonaService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ))
        });

        let token_counter = self.token_counter.unwrap_or_else(|| {
            let tokenizer_model_path = self.config.tokenizer_model_path.clone();
            let tokenizer_service = TokenizerService::new(&tokenizer_model_path)
                .expect("Failed to load tokenizer model for TestAppStateBuilder");

            let gemini_token_client = self
                .config
                .gemini_api_key
                .as_ref()
                .map(|api_key| GeminiTokenClient::new(api_key.clone()));

            let default_model = self.config.token_counter_default_model.clone();

            Arc::new(HybridTokenCounter::new(
                tokenizer_service,
                gemini_token_client,
                default_model,
            ))
        });

        let lorebook_service = self.lorebook_service.unwrap_or_else(|| {
            Arc::new(crate::services::lorebook_service::LorebookService::new(
                // Fully qualify
                self.db_pool.clone(),
                encryption_service.clone(),
                self.qdrant_service.clone(),
            ))
        });

        let services = AppStateServices {
            ai_client: self.ai_client,
            embedding_client: self.embedding_client,
            qdrant_service: self.qdrant_service,
            embedding_pipeline_service,
            chat_override_service,
            user_persona_service,
            token_counter,
            encryption_service,
            lorebook_service,
            auth_backend: self.auth_backend,
            file_storage_service: Arc::new(FileStorageService::new("./test_uploads").unwrap()),
            email_service: Arc::new(crate::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            )),
        };

        AppState::new(self.db_pool, self.config, services)
    }
}

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
            .unwrap_or_else(|e| eprintln!("Failed to initialize tracing: {e}"));
    });
}

// --- Rustls Crypto Provider Initialization for Tests ---
static RUSTLS_PROVIDER_INIT: Once = Once::new();

// Helper function to ensure rustls default crypto provider is installed (idempotent)
// Made public to be accessible from integration tests.
pub fn ensure_rustls_provider_installed() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => tracing::info!("Successfully installed rustls default crypto provider for tests."),
            Err(e) => {
                // install_default() panics if called more than once when a provider is already installed.
                // call_once ensures this block runs only once, so a panic here means a genuine failure.
                // If try_install_default() were used, we might log an info! if it returned an error
                // indicating it was already installed by someone else.
                tracing::error!("Failed to install rustls default crypto provider: {:?}. This might cause TLS handshake errors in tests.", e);
                // Depending on strictness, we might panic here.
                // For now, let it proceed and potentially fail later if TLS is actually used and needs it.
            }
        }
    });
}
// --- End Rustls Crypto Provider Initialization ---

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
    // user_persona_service field removed as per plan
    // embedding_call_tracker field removed as per plan
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
    spawn_app_with_options(multi_thread, use_real_ai, use_real_qdrant, false).await
}

#[instrument(
    skip_all,
    fields(
        multi_thread,
        use_real_ai,
        use_real_qdrant,
        use_real_embedding_pipeline
    )
)]
pub async fn spawn_app_with_options(
    multi_thread: bool,
    use_real_ai: bool,
    use_real_qdrant: bool,
    use_real_embedding_pipeline: bool,
) -> TestApp {
    ensure_tracing_initialized();
    ensure_rustls_provider_installed(); // Ensure rustls crypto provider is set up
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
            config_loader
                .database_url
                .unwrap_or_else(|| "postgres://user:pass@localhost/testdb".to_string()), // Provide a default if None
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
            .expect("Failed to build real AI client for test");
        (Arc::new(real_ai_client), None)
    } else {
        let mock_client = Arc::new(MockAiClient::new());
        (
            mock_client.clone() as Arc<dyn AiClient + Send + Sync>,
            Some(mock_client),
        )
    };

    // Determine EmbeddingClient and EmbeddingPipelineService based on use_real_qdrant (acting as use_real_embedding_components)
    let embedding_client_for_state: Arc<dyn EmbeddingClient + Send + Sync>;
    // Initialize these directly as TestApp expects non-optional Arcs.
    let mock_embedding_client_for_test_app = Arc::new(MockEmbeddingClient::new());
    let mock_embedding_pipeline_service_for_test_app =
        Arc::new(MockEmbeddingPipelineService::new());

    let (qdrant_service_for_state, mock_qdrant_service_for_test_app): (
        Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        Option<Arc<MockQdrantClientService>>,
    ) = if use_real_qdrant {
        // This flag now also controls embedding components
        let real_qdrant_service = QdrantClientService::new(config_arc.clone())
            .await
            .expect("Failed to create real Qdrant client for test");
        (
            Arc::new(real_qdrant_service) as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            None,
        )
    } else {
        let mock_qdrant = Arc::new(MockQdrantClientService::new());
        (
            mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            Some(mock_qdrant),
        )
    };

    // Create auth_backend early so it can be shared
    // IMPORTANT: We wrap AuthBackend in Arc to ensure the same instance is shared
    // This is critical for the DEK cache to work properly across requests
    let auth_backend = Arc::new(AuthBackend::new(pool.clone()));

    let mut builder; // Declare builder without initializing

    if use_real_qdrant {
        // If true, use real embedding client and pipeline for AppState
        let real_embedding_client =
            crate::llm::gemini_embedding_client::build_gemini_embedding_client(config_arc.clone())
                .expect("Failed to build real Gemini embedding client for test");
        embedding_client_for_state = Arc::new(real_embedding_client);

        // mock_embedding_client_for_test_app and mock_embedding_pipeline_service_for_test_app are already initialized.
        // AppState will use the real embedding pipeline service (created by builder if not specified).

        // Initialize builder with the real embedding client for AppState
        builder = TestAppStateBuilder::new(
            pool.clone(),
            config_arc.clone(),
            ai_client_for_state.clone(),
            embedding_client_for_state.clone(), // Pass the real one for AppState
            qdrant_service_for_state.clone(),
            auth_backend.clone(),
        );
        // Only use real embedding pipeline if explicitly requested
        if !use_real_embedding_pipeline {
            builder = builder.with_embedding_pipeline_service(
                mock_embedding_pipeline_service_for_test_app.clone(),
            );
        }
    } else {
        // Use mock embedding client and pipeline for AppState
        // Set embedding_client_for_state to the mock one (which is also stored in TestApp)
        embedding_client_for_state =
            mock_embedding_client_for_test_app.clone() as Arc<dyn EmbeddingClient + Send + Sync>;

        // Re-initialize builder with the mock embedding client for AppState
        builder = TestAppStateBuilder::new(
            pool.clone(),
            config_arc.clone(),
            ai_client_for_state.clone(),
            embedding_client_for_state.clone(), // Pass the mock one for AppState
            qdrant_service_for_state.clone(),
            auth_backend.clone(),
        );

        // Configure builder with the mock pipeline service for AppState
        // This mock_embedding_pipeline_service_for_test_app is the one initialized earlier.
        builder = builder
            .with_embedding_pipeline_service(mock_embedding_pipeline_service_for_test_app.clone());
    }

    let app_state_inner = builder.build();

    let session_store = DieselSessionStore::new(pool.clone());
    let secret_key_hex_str: &String = config_arc
        .cookie_signing_key
        .as_ref()
        .expect("COOKIE_SIGNING_KEY must be set for tests");
    let key_bytes =
        hex::decode(secret_key_hex_str.as_bytes()) // .as_bytes() on String
            .expect("Invalid COOKIE_SIGNING_KEY format in test config (must be hex)");
    let _signing_key = TowerSessionKey::from(&key_bytes);

    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(config_arc.session_cookie_secure)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    // AuthManagerLayerBuilder needs the backend directly, it will handle cloning internally
    let auth_layer =
        AuthManagerLayerBuilder::new((*auth_backend).clone(), session_manager_layer.clone())
            .build();

    let listener = TcpListener::bind(format!("127.0.0.1:{}", config_arc.port))
        .await
        .expect("Failed to bind to random port for test server");
    let local_addr = listener.local_addr().expect("Failed to get local address");
    let app_address = format!("http://{local_addr}");

    debug!("Test app address: {}", app_address);

    // embedding_call_tracker_for_state is no longer needed here as TestApp won't store it.
    // It's accessible via app_state_inner.embedding_call_tracker if necessary.

    // Corrected Router Setup for Tests
    let public_api_routes_for_test = Router::new()
        .route("/health", get(health_check))
        .merge(Router::new().nest("/auth", auth_routes_module::auth_routes())); // Align with main.rs

    let protected_api_routes_for_test = Router::new()
        .nest(
            "/characters",
            characters::characters_router(app_state_inner.clone()),
        )
        .nest("/chat", chat_routes(app_state_inner.clone()))
        .nest("/chats", chats::chat_routes()) // Assuming this returns Router<AppState> or is already stateful
        .nest("/documents", document_routes()) // Assuming this returns Router<AppState> or is already stateful
        .nest(
            "/personas",
            user_persona_routes::user_personas_router(app_state_inner.clone()),
        ) // Add persona routes
        .nest(
            "/user-settings",
            user_settings_routes::user_settings_routes(app_state_inner.clone()),
        ) // Add user settings routes
        .nest("/", lorebook_routes::lorebook_routes()) // Align with main.rs: Nest lorebook routes under /
        .route_layer(middleware::from_fn_with_state(
            app_state_inner.clone(),
            auth_log_wrapper,
        ));

    // Combine public and protected routes before nesting under /api
    let all_api_routes = Router::new()
        .merge(public_api_routes_for_test) // Contains /health, /auth/*
        .merge(protected_api_routes_for_test); // Re-enabled protected routes

    let router_for_server = Router::new() // Renamed to avoid conflict with router field in TestApp
        .nest("/api", all_api_routes) // Nest all combined API routes under /api
        .layer(CookieManagerLayer::new())
        .layer(auth_layer) // Re-enabled auth layer
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
        mock_embedding_client: mock_embedding_client_for_test_app.clone(),
        mock_embedding_pipeline_service: mock_embedding_pipeline_service_for_test_app.clone(),
        qdrant_service: qdrant_service_for_state,
        mock_qdrant_service: mock_qdrant_service_for_test_app,
        // user_persona_service and embedding_call_tracker removed from TestApp instantiation
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
    use super::{
        AccountStatus, Context, DbUser, ExposeSecret, SecretBox, SecretString,
        SerializableSecretDek,
    };
    // Keep if CryptoError is used directly, else it comes via crate::crypto
    use crate::models::users::NewUser; // Removed User as DbUser from here, already aliased DbUser at top
    // and UserDbQuery is imported above

    /// Sets up a clean test database with migrations run.
    ///
    /// # Panics
    ///
    /// Panics if the `DATABASE_URL` environment variable is not set
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
            DeadpoolManager::new(format!("{main_db_url}/postgres"), DeadpoolRuntime::Tokio1);
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
                    "DROP DATABASE IF EXISTS \"{db_name_clone_drop}\" WITH (FORCE)"
                ))
                .execute(conn)?; // Added WITH (FORCE)
                diesel::sql_query(format!("CREATE DATABASE \"{db_name_clone_create}\""))
                    .execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .await
            .expect("DB interaction failed")
            .expect("Failed to create test DB");

        // Create a connection pool to the newly created test database
        let test_db_url = format!("{main_db_url}/{db_name}");
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
    /// Creates a test user in the database
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails
    pub async fn create_test_user(
        pool: &PgPool,
        username: String,
        password_str: String,
    ) -> Result<DbUser, anyhow::Error> {
        let conn = pool.get().await?;
        let email = format!("{username}@test.com");

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

    /// Creates a test user with pending account status (for email verification tests)
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails
    pub async fn create_pending_test_user(
        pool: &PgPool,
        username: String,
        password_str: String,
    ) -> Result<DbUser, anyhow::Error> {
        let conn = pool.get().await?;
        let email = format!("{username}@test.com");

        let password_str_for_kek = password_str.clone(); // Clone for KEK derivation
        let username_clone_for_payload = username.clone(); // Clone for NewUser payload

        let password_hash = auth::hash_password(SecretString::from(password_str.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        let kek_salt = crate::crypto::generate_salt()
            .map_err(|e| anyhow::anyhow!("KEK salt generation failed: {}", e))?;

        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        let plaintext_dek_box: SecretBox<Vec<u8>> =
            crate::crypto::generate_dek().context("DEK generation failed in create_pending_test_user")?;

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
            account_status: AccountStatus::Pending,      // Set to Pending for email verification
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
                anyhow::anyhow!("DB interact error for create_pending_test_user: {}", interact_err)
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
    /// Creates a test character in the database
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails
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
                format!("Test description for {name_clone_for_payload}").into_bytes(),
            ),
            greeting: Some(format!("Test greeting for {name_clone_for_payload}").into_bytes()),
            example_dialogue: Some(
                format!("Test example dialogue for {name_clone_for_payload}").into_bytes(),
            ),
            visibility: Some("private".to_string()),
            character_version: Some("2.0".to_string()),
            spec: "test_spec_v2.0".to_string(),
            spec_version: "2.0".to_string(),
            persona: Some(format!("Test persona for {name_clone_for_payload}").into_bytes()),
            world_scenario: Some(
                format!("Test world scenario for {name_clone_for_payload}").into_bytes(),
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
            fav: None,
            world: None,
            creator_comment: None,
            creator_comment_nonce: None,
            depth_prompt: None,
            depth_prompt_depth: None,
            depth_prompt_role: None,
            talkativeness: None,
            depth_prompt_ciphertext: None,
            depth_prompt_nonce: None,
            world_ciphertext: None,
            world_nonce: None,
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
    character_ids: Vec<Uuid>,    // Added for characters
    chat_ids: Vec<Uuid>,         // Added for chats/sessions
    user_persona_ids: Vec<Uuid>, // Added for user personas
    lorebook_ids: Vec<Uuid>,     // Added for lorebooks
}

// Manual implementation of Debug for TestDataGuard
impl fmt::Debug for TestDataGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestDataGuard")
            .field("pool", &"PgPool // Omitted details for Debug") // PgPool itself is Debug, but we simplify here
            .field("user_ids", &self.user_ids)
            .field("character_ids", &self.character_ids)
            .field("chat_ids", &self.chat_ids)
            .field("user_persona_ids", &self.user_persona_ids)
            .field("lorebook_ids", &self.lorebook_ids)
            .finish()
    }
}

impl TestDataGuard {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        // Changed to PgPool
        Self {
            pool,
            user_ids: Vec::new(),
            character_ids: Vec::new(),
            chat_ids: Vec::new(),
            user_persona_ids: Vec::new(),
            lorebook_ids: Vec::new(),
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

    pub fn add_user_persona(&mut self, user_persona_id: Uuid) {
        self.user_persona_ids.push(user_persona_id);
    }

    pub fn add_lorebook(&mut self, lorebook_id: Uuid) {
        self.lorebook_ids.push(lorebook_id);
    }

    /// Adapted from `auth_tests.rs` and `db_integration_tests.rs`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection cannot be obtained
    /// - Any of the database deletion operations fail
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

        if !self.user_persona_ids.is_empty() {
            tracing::debug!(user_persona_ids = ?self.user_persona_ids, "Cleaning up test user personas");
            let user_persona_ids_clone = self.user_persona_ids.clone();
            let diesel_op_result_personas = conn
                .interact(move |conn_interaction| {
                    diesel::delete(
                        schema::user_personas::table
                            .filter(schema::user_personas::id.eq_any(user_persona_ids_clone)),
                    )
                    .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_personas.context("Interact error cleaning up user personas")?;
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

        if !self.lorebook_ids.is_empty() {
            tracing::debug!(lorebook_ids = ?self.lorebook_ids, "Cleaning up test lorebooks");
            let lorebook_ids_clone = self.lorebook_ids.clone();
            let diesel_op_result_lorebooks = conn
                .interact(move |conn_interaction| {
                    // First delete lorebook entries
                    diesel::delete(
                        schema::lorebook_entries::table.filter(
                            schema::lorebook_entries::lorebook_id.eq_any(&lorebook_ids_clone),
                        ),
                    )
                    .execute(conn_interaction)?;
                    // Then delete lorebooks
                    diesel::delete(
                        schema::lorebooks::table
                            .filter(schema::lorebooks::id.eq_any(lorebook_ids_clone)),
                    )
                    .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_lorebooks.context("Interact error cleaning up lorebooks")?;
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
        if !self.user_ids.is_empty()
            || !self.character_ids.is_empty()
            || !self.chat_ids.is_empty()
            || !self.user_persona_ids.is_empty()
            || !self.lorebook_ids.is_empty()
        {
            // Use a blocking spawn for the async cleanup task
            // This is not ideal for drop, but better than panicking or doing nothing.
            // Consider making cleanup explicit in all tests.
            let _pool_clone = self.pool.clone(); // Renamed pool_clone
            let has_cleanup_needed = !self.user_ids.is_empty()
                || !self.character_ids.is_empty()
                || !self.chat_ids.is_empty()
                || !self.user_persona_ids.is_empty();

            let _user_ids_clone = self.user_ids.drain(..).collect::<Vec<_>>();
            let _character_ids_clone = self.character_ids.drain(..).collect::<Vec<_>>();
            let _chat_ids_clone = self.chat_ids.drain(..).collect::<Vec<_>>();
            let _user_persona_ids_clone = self.user_persona_ids.drain(..).collect::<Vec<_>>();

            if has_cleanup_needed {
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
                            if !user_persona_ids_clone.is_empty() {
                                let persona_ids_c = user_persona_ids_clone.clone();
                                let interact_result_personas = conn_obj.interact(move |actual_conn| {
                                    diesel::delete(schema::user_personas::table.filter(schema::user_personas::id.eq_any(persona_ids_c)))
                                        .execute(actual_conn)
                                }).await;
                                match interact_result_personas {
                                    Ok(Ok(_num_deleted_personas)) => {}
                                    Ok(Err(db_err_personas)) => {
                                        tracing::error!("TestDataGuard Drop: user_personas diesel cleanup failed: {:?}", db_err_personas);
                                    }
                                    Err(pool_err_personas) => {
                                        tracing::error!("TestDataGuard Drop: user_personas interact pool error: {:?}", pool_err_personas);
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

/// Performs database cleanup for test data
///
/// # Errors
///
/// Returns an error if any of the database deletion operations fail
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

/// Creates a user and returns the user with a session cookie string
///
/// # Errors
///
/// Returns an error if:
/// - User creation in the database fails
/// - Login request fails
/// - Session extraction from response fails
///
/// # Panics
///
/// Panics if:
/// - The HTTP request cannot be built (malformed URL or headers)
/// - The app router fails to process the request
/// - The login response doesn't have the expected status code
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

/// Helper function for router-based login (for tests that use router.oneshot)
///
/// # Panics
///
/// Panics if:
/// - The login payload cannot be serialized to JSON
/// - The HTTP request cannot be built (malformed URL or headers)
/// - The router fails to process the request
/// - The response doesn't contain a valid session cookie
pub async fn login_user_via_router(router: &Router, username: &str, password: &str) -> String {
    let login_payload = json!({
        "identifier": username,
        "password": password
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&login_payload).expect("Failed to serialize login payload"),
        ))
        .expect("Failed to build login request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Login request failed");

    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes();
        let body_text = String::from_utf8_lossy(&body);
        panic!("Router login failed for user '{username}'. Status: {status}. Body: {body_text}");
    }

    // Extract the session cookie from headers
    response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .map_or_else(
            || panic!("Session cookie not found in login response for user {username}"),
            str::to_string,
        )
}

/// Helper function for API-based login.
///
/// # Panics
///
/// Panics if the reqwest client cannot be built or login fails.
pub async fn login_user_via_api(
    test_app: &TestApp,
    username: &str,
    password: &str,
) -> (reqwest::Client, String) {
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
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|e| format!("Failed to read error body: {e}"));
        panic!(
            "API login failed for user '{username}'. Status: {status}. URL: {login_url}. Body: {body_text}"
        );
    }

    // Extract the session cookie
    let session_cookie_string = response
        .cookies()
        .find(|c| c.name() == "id") // Assuming session cookie name is "id"
        .map_or_else(|| {
            let headers_debug = format!("{:?}", response.headers());
            panic!(
                "Session cookie 'id' not found in login response for user {username}. URL: {login_url}. Headers: {headers_debug}"
            )
        }, |c| format!("{}={}", c.name(), c.value()));
    (client, session_cookie_string)
}

// Helper structs and functions for testing SSE
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedSseEvent {
    pub event: Option<String>, // Name of the event (e.g., "content", "error")
    pub data: String,          // Raw data string
                               // Not parsing id or retry for now
}

/// Collects and parses SSE events from an HTTP response body.
///
/// # Panics
///
/// Panics if the SSE stream cannot be read or contains invalid UTF-8.
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

/// Helper to assert the history sent to the mock AI client
///
/// # Panics
///
/// Panics if:
/// - Mock AI client is not present in the test app
/// - Mock AI client did not receive a request
/// - Expected history doesn't match the actual history sent to AI
pub fn assert_ai_history(
    test_app: &TestApp,
    expected_history: &[(&str, &str)], // (Role, Content)
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
            genai::chat::ChatRole::Tool => "Tool",
        };
        let content = match &msg.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => "<non-text content>",
        };
        println!("  [{i}] {role_str}: {content}");
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
                    String::new()
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
            genai::chat::ChatRole::Tool => {
                panic!("Unexpected role in AI history: {:?}", actual.role)
            }
        };
        let actual_content = match &actual.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => panic!(
                "Expected text content in AI history, got: {:?}",
                actual.content
            ),
        };

        println!(
            "[DEBUG] Compare message {i}: Expected {expected_role_str}:'{expected_content}' vs Actual {actual_role_str}:'{actual_content}'"
        );

        assert_eq!(
            actual_role_str, *expected_role_str,
            "Role mismatch at index {i}"
        );
        assert_eq!(
            actual_content, *expected_content,
            "Content mismatch at index {i}"
        );
    }
}

// Helper to set history management settings via API
/// Sets history settings for a chat session via API
///
/// # Errors
///
/// Returns an error if:
/// - HTTP request fails
/// - Server returns a non-OK status
/// - Response parsing fails
///
/// # Panics
///
/// Panics if the API response status is not OK
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
        seed: None,
        stop_sequences: None,
        model_name: None,
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };

    let client = reqwest::Client::new();
    let response = client
        .put(format!(
            "{}/api/chat/{}/settings",
            test_app.address, session_id
        ))
        .header(reqwest::header::COOKIE, auth_cookie)
        .header(
            reqwest::header::CONTENT_TYPE,
            mime::APPLICATION_JSON.as_ref(),
        )
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
