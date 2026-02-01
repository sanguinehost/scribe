// backend/src/test_helpers.rs
// Contains helper functions and structs for integration testing within the src directory.

// Payment test helpers (only with payment feature)
#[cfg(feature = "payment")]
pub mod payment_test_helpers;

use crate::db::DbId;
#[cfg(feature = "sqlite-backend")]
use crate::db::SqliteInteractExt;
use std::fmt;
use std::net::SocketAddr;

// Make sure all necessary imports from the main crate and external crates are included.
use crate::errors::AppError;
use crate::llm::{
    AiClient, BatchEmbeddingContentRequest, EmbeddingClient, RigChatResponse, RigCompletionRequest,
    RigStreamEvent, UnifiedEmbeddingModel,
};
use crate::services::embeddings::{
    metadata::{CognitiveFactMetadata, EntityMetadata, OpinionMetadata},
    EmbeddingPipelineService, EmbeddingPipelineServiceTrait, LorebookEntryParams, RetrievedChunk,
}; // Added EmbeddingPipelineService
use crate::text_processing::chunking::ChunkConfig;
// Unused ChunkConfig, ChunkingMetric were previously noted as removed.
use crate::models::users::User as DbUser;
use crate::models::users::{SerializableSecretDek, User}; // Added SerializableSecretDek
use crate::vector_db::QdrantClientServiceTrait;
use crate::{
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
        chronicles,
        game_state,        // Added game_state
        generation_routes, // Added generation_routes
        health::health_check,
        lorebook_routes,           // Added lorebook_routes
        payment as payment_routes, // Added payment_routes
        template_preferences_routes,
        user_persona_routes,
        user_settings_routes,
    },
    schema,
    services::chat_override_service::ChatOverrideService, // <<< ENSURED IMPORT
    services::chronicle_service::ChronicleService,        // <<< ADDED THIS IMPORT
    services::encryption_service::EncryptionService,      // <<< ENSURED IMPORT
    services::hybrid_token_counter::HybridTokenCounter,
    services::narrative_intelligence_service::NarrativeIntelligenceService, // <<< ADDED THIS IMPORT
    services::token_client::TokenClient,
    services::tokenizer_service::TokenizerService,
    services::user_persona_service::UserPersonaService, // <<< ADDED THIS IMPORT
    state::{AppState, AppStateServices},
    vector_db::VectorServiceTrait, // Import constants module alias
};
use qdrant_client::qdrant::PointStruct;

#[cfg(feature = "embedded-vector")]
pub use crate::vector_db::LanceDbClient;
#[cfg(feature = "remote-vector")]
pub use crate::vector_db::QdrantClientService;

// Conditionally import documents module (PostgreSQL only)
#[cfg(feature = "postgres-backend")]
use crate::routes::documents::document_routes;

// Conditionally import pool type (PostgreSQL only - test_helpers currently PostgreSQL-only)
use anyhow::Context; // Added for TestDataGuard cleanup
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::Request as AxumRequest,
    http::{Request, StatusCode}, // Removed unused Method, header
};
use axum::{
    middleware::{self, Next},
    response::Response as AxumResponse, // Alias to avoid conflict if Response is used elsewhere
    routing::get,                       // <<< ADD THIS IMPORT
    Router,
};
use axum_login::{login_required, AuthManagerLayerBuilder, AuthSession};
use diesel::prelude::*;
use diesel::RunQueryDsl;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
// Removed var
use futures::TryStreamExt;
// use http_body_util::BodyExt; // Removed unused import
use mime; // Added for mime::APPLICATION_JSON
use qdrant_client::qdrant::{Filter, PointId, ScoredPoint};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::collections::VecDeque; // Added for MockQdrantClientService response queue
use std::sync::{Arc, Mutex}; // Add Mutex import
use tokio::net::TcpListener;
// use tokio::sync::Mutex as TokioMutex; // Removed unused import
use crate::db::DbPool;
use hex; // Added for hex::decode
use http_body_util::BodyExt; // For collect() on Body
use reqwest;
use rustls;
use time; // For time::Duration for session expiry
use tower::ServiceExt; // For .oneshot
use tower_cookies::CookieManagerLayer; // Removed unused: Key as TowerCookieKey
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor, GovernorLayer,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tower_sessions::{
    cookie::Key as TowerSessionKey, cookie::SameSite, Expiry, SessionManagerLayer,
}; // Added SameSite
use tracing::{debug, instrument, warn}; // Added debug
                                        // Added for CryptoProvider // Added for backend-agnostic database types

#[cfg(feature = "local-llm")]
use crate::llm::llamacpp::{LlamaCppConfig, LlamaCppServerManager, ModelManager};
#[cfg(feature = "local-llm")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "local-llm")]
use std::sync::Arc as StdArc;

// Type aliases for complex test types
type EmbeddingResponse = Arc<Mutex<Option<Result<Vec<f32>, AppError>>>>;
type EmbeddingResponseSequence = Arc<Mutex<VecDeque<Result<Vec<f32>, AppError>>>>;
type BatchEmbeddingResponse = Arc<Mutex<Option<Result<Vec<Vec<f32>>, AppError>>>>;
type EmbeddingCalls = Arc<Mutex<Vec<(String, String, Option<String>)>>>;
type BatchEmbeddingCalls = Arc<Mutex<Vec<Vec<(String, String, Option<String>)>>>>;
type SearchParamsType = Option<(Vec<f32>, u64, Option<Filter>)>;
type SearchParams = Arc<Mutex<SearchParamsType>>;
type SearchResponseQueue = Arc<Mutex<VecDeque<Result<Vec<ScoredPoint>, AppError>>>>;
type ChatEventStream =
    std::sync::Arc<std::sync::Mutex<Option<Vec<Result<RigStreamEvent, AppError>>>>>;
type RetrievalResponseQueue = Arc<Mutex<VecDeque<Result<Vec<RetrievedChunk>, AppError>>>>;
type FactResponseQueue = Arc<Mutex<VecDeque<Result<Vec<(f32, CognitiveFactMetadata)>, AppError>>>>;
type OpinionResponseQueue = Arc<Mutex<VecDeque<Result<Vec<(f32, OpinionMetadata)>, AppError>>>>;

#[derive(Clone)]
pub struct MockAiClient {
    last_request: std::sync::Arc<std::sync::Mutex<Option<RigCompletionRequest>>>,
    response_to_return: std::sync::Arc<std::sync::Mutex<Result<RigChatResponse, AppError>>>,
    stream_to_return: ChatEventStream,
    last_received_messages: std::sync::Arc<std::sync::Mutex<Option<Vec<rig::message::Message>>>>,
}

impl MockAiClient {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(RigChatResponse {
                content: "Mock AI response".to_string(),
                prompt_tokens: Some(20),
                completion_tokens: Some(10),
                total_tokens: Some(30),
                reasoning_content: None,
            }))),
            stream_to_return: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_received_messages: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Create a new MockAiClient with a specific response text
    #[must_use]
    pub fn new_with_response(response_text: String) -> Self {
        let completion_tokens = ((response_text.len() as f64 / 4.0).ceil() as u64).max(1);
        let prompt_tokens = 15;

        Self {
            last_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Ok(RigChatResponse {
                content: response_text,
                prompt_tokens: Some(prompt_tokens),
                completion_tokens: Some(completion_tokens),
                total_tokens: Some(prompt_tokens + completion_tokens),
                reasoning_content: None,
            }))),
            stream_to_return: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_received_messages: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Create a new MockAiClient that returns an error
    #[must_use]
    pub fn new_with_error(error: AppError) -> Self {
        Self {
            last_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
            response_to_return: std::sync::Arc::new(std::sync::Mutex::new(Err(error))),
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
    pub fn get_last_request(&self) -> Option<RigCompletionRequest> {
        self.last_request.lock().unwrap().clone()
    }

    // Method to retrieve the captured messages
    #[must_use]
    pub fn get_last_received_messages(&self) -> Option<Vec<rig::message::Message>> {
        self.last_received_messages.lock().unwrap().clone()
    }

    /// Sets the response for the mock AI client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_response(&self, response: Result<RigChatResponse, AppError>) {
        *self.response_to_return.lock().unwrap() = response;
    }

    /// Sets the stream response for the mock AI client
    ///
    /// # Panics
    ///
    /// Panics if the mutex lock is poisoned
    pub fn set_stream_response(&self, stream_items: Vec<Result<RigStreamEvent, AppError>>) {
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
    async fn completion(
        &self,
        req: RigCompletionRequest,
    ) -> Result<RigChatResponse, anyhow::Error> {
        *self.last_request.lock().unwrap() = Some(req.clone());

        // Capture history including the current prompt
        let mut full_history = req.history.clone();
        full_history.push(rig::message::Message::User {
            content: rig::one_or_many::OneOrMany::one(rig::message::UserContent::text(
                req.prompt.clone(),
            )),
        });
        *self.last_received_messages.lock().unwrap() = Some(full_history);

        self.response_to_return
            .lock()
            .unwrap()
            .clone()
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn completion_stream(
        &self,
        req: RigCompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<RigStreamEvent, anyhow::Error>> + Send>,
        >,
        anyhow::Error,
    > {
        *self.last_request.lock().unwrap() = Some(req.clone());

        // Capture history including the current prompt
        let mut full_history = req.history.clone();
        full_history.push(rig::message::Message::User {
            content: rig::one_or_many::OneOrMany::one(rig::message::UserContent::text(
                req.prompt.clone(),
            )),
        });
        *self.last_received_messages.lock().unwrap() = Some(full_history);

        let items = {
            let guard = self.stream_to_return.lock().unwrap();
            (*guard).as_ref().map_or_else(Vec::new, |item_results| {
                item_results
                    .iter()
                    .map(|res| res.clone().map_err(|e| anyhow::anyhow!(e)))
                    .collect()
            })
        };

        let stream = futures::stream::iter(items);
        Ok(Box::pin(stream))
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
        user_id: crate::db::DbId,                             // Renamed from chat_id
        session_id_for_chat_history: Option<crate::db::DbId>, // New field - Updated to Option<crate::db::DbId>
        active_lorebook_ids_for_search: Option<Vec<crate::db::DbId>>, // New field
        chronicle_id_for_search: Option<crate::db::DbId>,     // New field for chronicle search
        query_text: String,
        limit: u64,
        max_game_time_day: Option<i64>,
    },
    ProcessAndEmbedMessage {
        message_id: crate::db::DbId,
        session_id: crate::db::DbId,
    },
    ProcessAndEmbedLorebookEntry {
        original_lorebook_entry_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
        user_id: crate::db::DbId,
        decrypted_content: String,
        decrypted_title: Option<String>,
        decrypted_keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
    },
    ProcessAndEmbedChronicleEvent {
        event_id: crate::db::DbId,
    },
    DeleteChronicleEventChunks {
        event_id: crate::db::DbId,
        user_id: crate::db::DbId,
    },
    DeleteChronicleEventsByChronicleId {
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
    },
    ProcessAndEmbedEntity {
        user_id: crate::db::DbId,
        entity_name: String,
        entity_name_hash: String,
        message_variant_id: Option<crate::db::DbId>,
    },
    RetrieveSimilarEntities {
        user_id: crate::db::DbId,
        entity_name: String,
        limit: u64,
        active_variant_id: Option<crate::db::DbId>,
    },
    ProcessAndEmbedOpinion {
        user_id: crate::db::DbId,
        opinion_id: crate::db::DbId,
        opinion_text: String,
        message_variant_id: Option<crate::db::DbId>,
    },
    RetrieveSimilarOpinions {
        user_id: crate::db::DbId,
        opinion_text: String,
        limit: u64,
        active_variant_id: Option<crate::db::DbId>,
    },
    DeleteOpinionVector {
        opinion_id: crate::db::DbId,
        user_id: crate::db::DbId,
    },
    ProcessAndEmbedCognitiveFact {
        user_id: crate::db::DbId,
        fact_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        fact_text: String,
        game_time: Option<serde_json::Value>,
        message_variant_id: Option<crate::db::DbId>,
    },
    RetrieveSimilarFacts {
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        query: String,
        limit: u64,
        max_game_time_day: Option<i64>,
        active_variant_id: Option<crate::db::DbId>,
    },
}

// Updated MockEmbeddingPipelineService
#[derive(Clone)] // Added Clone
pub struct MockEmbeddingPipelineService {
    retrieve_response_queue: RetrievalResponseQueue,
    fact_response_queue: FactResponseQueue,
    opinion_response_queue: OpinionResponseQueue,
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
            fact_response_queue: Arc::new(Mutex::new(VecDeque::new())),
            opinion_response_queue: Arc::new(Mutex::new(VecDeque::new())),
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

    /// Sets a sequence of fact responses for the mock service
    pub fn set_fact_responses_sequence(
        &self,
        responses: Vec<Result<Vec<(f32, CognitiveFactMetadata)>, AppError>>,
    ) {
        let mut queue = self.fact_response_queue.lock().unwrap();
        queue.clear();
        for response in responses {
            queue.push_back(response);
        }
    }

    /// Sets a sequence of opinion responses for the mock service
    pub fn set_opinion_responses_sequence(
        &self,
        responses: Vec<Result<Vec<(f32, OpinionMetadata)>, AppError>>,
    ) {
        let mut queue = self.opinion_response_queue.lock().unwrap();
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
        user_id: crate::db::DbId, // New parameter
        session_id_for_chat_history: Option<crate::db::DbId>, // New parameter - Updated to Option<crate::db::DbId>
        active_lorebook_ids_for_search: Option<Vec<crate::db::DbId>>, // New parameter
        chronicle_id_for_search: Option<crate::db::DbId>,     // New parameter for chronicle search
        query_text: &str,
        limit: u64,
        max_game_time_day: Option<i64>,
        _session_dek: Option<&crate::auth::SessionDek>, // DEK for decryption
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveRelevantChunks {
                user_id,
                session_id_for_chat_history, // This is Option<crate::db::DbId>
                active_lorebook_ids_for_search, // Corrected order
                chronicle_id_for_search,
                query_text: query_text.to_string(), // Corrected order
                limit,                              // Corrected order
                max_game_time_day,
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

    async fn delete_message_chunks(
        &self,
        _state: Arc<AppState>,
        message_ids: Vec<crate::db::DbId>,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        tracing::info!(
            target: "mock_embedding_pipeline",
            "MockEmbeddingPipelineService::delete_message_chunks called for {} messages, user_id: {}",
            message_ids.len(), user_id
        );
        // In a real scenario, this would interact with Qdrant via QdrantClientService
        // For the mock, we just log and return Ok.
        // If tests need to verify this was called, they can check logs or add to `self.calls`.
        Ok(())
    }

    async fn delete_lorebook_entry_chunks(
        &self,
        _state: Arc<AppState>,
        original_lorebook_entry_id: crate::db::DbId,
        user_id: crate::db::DbId,
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

    async fn process_and_embed_chronicle_event(
        &self,
        _state: Arc<AppState>,
        event: crate::models::chronicle_event::ChronicleEvent,
        _session_dek: Option<&crate::auth::session_dek::SessionDek>,
    ) -> Result<(), AppError> {
        tracing::info!(
            target: "mock_embedding_pipeline",
            "MockEmbeddingPipelineService::process_and_embed_chronicle_event called for event_id: {}",
            event.id
        );
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedChronicleEvent { event_id: event.id });
        Ok(())
    }

    async fn delete_chronicle_event_chunks(
        &self,
        _state: Arc<AppState>,
        event_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        tracing::info!(
            target: "mock_embedding_pipeline",
            "MockEmbeddingPipelineService::delete_chronicle_event_chunks called for event_id: {}, user_id: {}",
            event_id, user_id
        );
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::DeleteChronicleEventChunks { event_id, user_id });
        Ok(())
    }

    async fn delete_chronicle_events_by_chronicle_id(
        &self,
        _state: Arc<AppState>,
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        tracing::info!(
            target: "mock_embedding_pipeline",
            "MockEmbeddingPipelineService::delete_chronicle_events_by_chronicle_id called for chronicle_id: {}, user_id: {}",
            chronicle_id, user_id
        );
        // Record the call
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::DeleteChronicleEventsByChronicleId {
                chronicle_id,
                user_id,
            });
        Ok(())
    }

    async fn process_and_embed_entity(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        entity_name: &str,
        entity_name_hash: &str,
        message_variant_id: Option<crate::db::DbId>,
    ) -> Result<(), AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedEntity {
                user_id,
                entity_name: entity_name.to_string(),
                entity_name_hash: entity_name_hash.to_string(),
                message_variant_id,
            });
        Ok(())
    }

    async fn retrieve_similar_entities(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        entity_name: &str,
        limit: u64,
        active_variant_id: Option<crate::db::DbId>,
    ) -> Result<Vec<(f32, EntityMetadata)>, AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveSimilarEntities {
                user_id,
                entity_name: entity_name.to_string(),
                limit,
                active_variant_id,
            });
        Ok(vec![])
    }

    async fn process_and_embed_opinion(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        opinion_id: crate::db::DbId,
        opinion_text: &str,
        message_variant_id: Option<crate::db::DbId>,
    ) -> Result<(), AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedOpinion {
                user_id,
                opinion_id,
                opinion_text: opinion_text.to_string(),
                message_variant_id,
            });
        Ok(())
    }

    async fn retrieve_similar_opinions(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        opinion_text: &str,
        limit: u64,
        active_variant_id: Option<crate::db::DbId>,
    ) -> Result<Vec<(f32, OpinionMetadata)>, AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveSimilarOpinions {
                user_id,
                opinion_text: opinion_text.to_string(),
                limit,
                active_variant_id,
            });

        let mut queue = self.opinion_response_queue.lock().unwrap();
        queue.pop_front().unwrap_or(Ok(vec![]))
    }

    async fn delete_opinion_vector(
        &self,
        _state: Arc<AppState>,
        opinion_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::DeleteOpinionVector {
                opinion_id,
                user_id,
            });
        Ok(())
    }

    async fn process_and_embed_cognitive_fact(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        fact_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        fact_text: &str,
        game_time: Option<serde_json::Value>,
        message_variant_id: Option<crate::db::DbId>,
    ) -> Result<(), AppError> {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::ProcessAndEmbedCognitiveFact {
                user_id,
                fact_id,
                chronicle_id,
                fact_text: fact_text.to_string(),
                game_time,
                message_variant_id,
            });
        Ok(())
    }

    async fn retrieve_similar_facts(
        &self,
        _state: Arc<AppState>,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        query: &str,
        limit: u64,
        max_game_time_day: Option<i64>,
        active_variant_id: Option<crate::db::DbId>,
    ) -> Result<
        Vec<(
            f32,
            crate::services::embeddings::metadata::CognitiveFactMetadata,
        )>,
        AppError,
    > {
        self.calls
            .lock()
            .unwrap()
            .push(PipelineCall::RetrieveSimilarFacts {
                user_id,
                chronicle_id,
                query: query.to_string(),
                limit,
                max_game_time_day,
                active_variant_id,
            });

        let mut queue = self.fact_response_queue.lock().unwrap();
        queue.pop_front().unwrap_or(Ok(vec![]))
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
    pub search_params_history: Arc<Mutex<Vec<SearchParamsType>>>, // New field
    calls_delete_points_by_filter: Arc<Mutex<Vec<Filter>>>, // New field to track delete_points_by_filter calls
    pub last_added_documents: Arc<Mutex<Vec<serde_json::Value>>>,
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
            search_params_history: Arc::new(Mutex::new(Vec::new())),
            calls_delete_points_by_filter: Arc::new(Mutex::new(Vec::new())), // Initialize
            last_added_documents: Arc::new(Mutex::new(Vec::new())),
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

    async fn store_points_to_collection(
        &self,
        _collection_name: &str,
        points: Vec<PointStruct>,
    ) -> Result<(), AppError> {
        self.store_points(points).await
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

    async fn search_points_in_collection(
        &self,
        _collection_name: &str,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        self.search_points(vector, limit, filter).await
    }

    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Just delegate to search_points for the mock, ignoring threshold
        self.search_points(vector, limit, filter).await
    }

    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        _text_query: Option<String>,
        _text_fields: Vec<String>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // For mock, just use vector search if vector is provided, otherwise return empty
        if let Some(v) = vector {
            self.search_points(v, limit, filter).await
        } else {
            Ok(vec![])
        }
    }

    async fn retrieve_points(
        &self,
        _filter: Option<Filter>,
        _limit: u64,
        _offset: Option<u64>,
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

    async fn delete_points_from_collection(
        &self,
        _collection_name: &str,
        _points: Vec<PointId>,
    ) -> Result<(), AppError> {
        Ok(())
    }

    async fn delete_points_by_filter_from_collection(
        &self,
        _collection_name: &str,
        filter: Filter,
    ) -> Result<(), AppError> {
        self.delete_points_by_filter(filter).await
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

    async fn health_check(&self) -> Result<(), AppError> {
        // Mock health check always returns Ok
        tracing::info!(
            target: "mock_qdrant_client",
            "MockQdrantClientService::health_check called - returning Ok(())"
        );
        Ok(())
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        // Mock optimization always returns Ok
        tracing::info!(
            target: "mock_qdrant_client",
            "MockQdrantClientService::optimize_collection called - returning Ok(())"
        );
        Ok(())
    }

    async fn delete_by_id(&self, _id: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn ensure_collection_exists_named(&self, _collection_name: &str) -> Result<(), AppError> {
        Ok(())
    }
}

// Implement the VectorServiceTrait for MockQdrantClientService
#[async_trait]
impl VectorServiceTrait for MockQdrantClientService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn ensure_collection_exists_named(&self, _collection_name: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn add_document(&self, document: serde_json::Value) -> Result<(), AppError> {
        *self.upsert_call_count.lock().unwrap() += 1;
        self.last_added_documents.lock().unwrap().push(document);
        let mut response = self.upsert_response.lock().unwrap();
        if let Some(res) = response.take() {
            res
        } else {
            Ok(())
        }
    }

    async fn add_documents(&self, documents: Vec<serde_json::Value>) -> Result<(), AppError> {
        *self.upsert_call_count.lock().unwrap() += 1;
        self.last_added_documents.lock().unwrap().extend(documents);
        let mut response = self.upsert_response.lock().unwrap();
        if let Some(res) = response.take() {
            res
        } else {
            Ok(())
        }
    }

    async fn add_document_to_collection(
        &self,
        _collection_name: &str,
        document: serde_json::Value,
    ) -> Result<(), AppError> {
        *self.upsert_call_count.lock().unwrap() += 1;
        self.last_added_documents.lock().unwrap().push(document);
        let mut response = self.upsert_response.lock().unwrap();
        if let Some(res) = response.take() {
            res
        } else {
            Ok(())
        }
    }

    async fn search_values(
        &self,
        _query: &str,
        limit: usize,
        filter: Option<qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<(f32, serde_json::Value)>, AppError> {
        // Track call (using dummy vector for tracking)
        {
            *self.search_call_count.lock().unwrap() += 1;
            let mut last_params = self.last_search_params.lock().unwrap();
            let params = Some((vec![0.0; 1536], limit as u64, filter));
            *last_params = params.clone();
            self.search_params_history.lock().unwrap().push(params);
        }

        // Return response from queue
        let mut queue = self.search_response.lock().unwrap();
        if let Some(points_result) = queue.pop_front() {
            match points_result {
                Ok(points) => {
                    let results = points
                        .into_iter()
                        .take(limit)
                        .map(|p| {
                            let score = p.score;
                            let payload =
                                serde_json::to_value(p.payload).unwrap_or(serde_json::Value::Null);
                            (score, payload)
                        })
                        .collect();
                    Ok(results)
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(vec![])
        }
    }

    async fn delete_by_filter(
        &self,
        filter: qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError> {
        // Record the call
        self.calls_delete_points_by_filter
            .lock()
            .unwrap()
            .push(filter);
        Ok(())
    }

    async fn retrieve_points(
        &self,
        filter: Option<qdrant_client::qdrant::Filter>,
        limit: u64,
        _offset: Option<u64>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Track call
        {
            *self.search_call_count.lock().unwrap() += 1;
            let mut last_params = self.last_search_params.lock().unwrap();
            let params = Some((vec![0.0; 1536], limit, filter));
            *last_params = params.clone();
            self.search_params_history.lock().unwrap().push(params);
        }

        // Return response from queue
        let mut queue = self.search_response.lock().unwrap();
        queue
            .pop_front()
            .map(|res| res.map(|points| points.into_iter().take(limit as usize).collect()))
            .unwrap_or(Ok(vec![]))
    }

    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Track call
        {
            *self.search_call_count.lock().unwrap() += 1;
            let mut last_params = self.last_search_params.lock().unwrap();
            let params = Some((vector, limit, filter));
            *last_params = params.clone();
            self.search_params_history.lock().unwrap().push(params);
        }

        // Return response from queue
        let mut queue = self.search_response.lock().unwrap();
        queue
            .pop_front()
            .map(|res| res.map(|points| points.into_iter().take(limit as usize).collect()))
            .unwrap_or(Ok(vec![]))
    }

    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        _text_query: Option<String>,
        _text_fields: Vec<String>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Track call
        {
            *self.search_call_count.lock().unwrap() += 1;
            let mut last_params = self.last_search_params.lock().unwrap();
            let params = Some((vector.unwrap_or_else(|| vec![0.0; 1536]), limit, filter));
            *last_params = params.clone();
            self.search_params_history.lock().unwrap().push(params);
        }

        // Return response from queue
        let mut queue = self.search_response.lock().unwrap();
        queue
            .pop_front()
            .map(|res| res.map(|points| points.into_iter().take(limit as usize).collect()))
            .unwrap_or(Ok(vec![]))
    }

    async fn delete_points(
        &self,
        _ids: Vec<qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError> {
        Ok(())
    }

    async fn delete_by_id(&self, _id: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        Ok(())
    }
}

// --- END Placeholder Mock Definitions ---

pub struct TestAppStateBuilder {
    db_pool: DbPool,
    config: Arc<Config>,
    ai_client: Arc<dyn AiClient + Send + Sync>,
    embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
    qdrant_service: Arc<dyn crate::vector_db::VectorServiceTrait>,
    embedding_pipeline_service: Option<Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>>,
    chat_override_service: Option<Arc<ChatOverrideService>>,
    user_persona_service: Option<Arc<UserPersonaService>>,
    token_counter: Option<Arc<HybridTokenCounter>>,
    lorebook_service: Option<Arc<crate::services::lorebook::LorebookService>>, // Fully qualify
    auth_backend: Arc<AuthBackend>, // Add auth_backend to builder
    token_service: Option<Arc<crate::auth::TokenService>>, // Add token_service field
    recall_pipeline: Option<Arc<crate::services::cognitive::RecallPipeline>>,
}

impl TestAppStateBuilder {
    #[must_use]
    pub fn new(
        db_pool: DbPool,
        config: Arc<Config>,
        ai_client: Arc<dyn AiClient + Send + Sync>,
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        qdrant_service: Arc<dyn crate::vector_db::VectorServiceTrait>,
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
            token_service: None, // Initialize token_service field
            recall_pipeline: None,
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

    pub fn with_lorebook_service(
        mut self,
        service: Arc<crate::services::lorebook::LorebookService>, // Fully qualify
    ) -> Self {
        self.lorebook_service = Some(service);
        self
    }

    #[must_use]
    pub fn with_recall_pipeline(
        mut self,
        pipeline: Arc<crate::services::cognitive::RecallPipeline>,
    ) -> Self {
        self.recall_pipeline = Some(pipeline);
        self
    }

    /// Build the `AppState` instance
    ///
    /// # Panics
    ///
    /// Panics if the tokenizer model cannot be loaded from the expected path
    #[must_use]
    #[allow(clippy::double_must_use)]
    pub async fn build(self) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
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
                .map(|api_key| TokenClient::new(api_key.clone()));

            let default_model = self.config.token_counter_default_model.clone();

            Arc::new(HybridTokenCounter::new(
                tokenizer_service,
                gemini_token_client,
                default_model,
            ))
        });

        let lorebook_service = self.lorebook_service.unwrap_or_else(|| {
            Arc::new(crate::services::lorebook::LorebookService::new(
                // Fully qualify
                self.db_pool.clone(),
                encryption_service.clone(),
                self.qdrant_service.clone(),
            ))
        });

        // Create chronicle service for narrative intelligence
        let chronicle_service = Arc::new(ChronicleService::new(
            self.db_pool.clone(),
            self.ai_client.clone(),
        ));

        // NOTE: NarrativeIntelligenceService creation is deferred until after AppState is built
        // due to circular dependency (service needs AppState, but AppState is built from services)

        // Create AI client factory for testing
        let ai_client_factory = Arc::new(crate::services::ai_client_factory::AiClientFactory::new(
            self.db_pool.clone(),
            self.config.clone(),
            self.ai_client.clone(), // Use test AI client as fallback
        ));

        // Initialize token service for JWT authentication tests
        let token_service = self.token_service.unwrap_or_else(|| {
            // Use a hardcoded test JWT secret for tests
            let jwt_secret = "test_jwt_secret_for_tests_only_not_production_use".to_string();
            Arc::new(crate::auth::TokenService::new(&jwt_secret))
        });

        let recall_pipeline = self.recall_pipeline.unwrap_or_else(|| {
            Arc::new(crate::services::cognitive::RecallPipeline::new(
                self.db_pool.clone(),
            ))
        });

        let character_service =
            Arc::new(crate::services::character_service::CharacterService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ));

        let services = AppStateServices {
            ai_client: self.ai_client,
            embedding_client: self.embedding_client,
            qdrant_service: self.qdrant_service,
            embedding_pipeline_service,
            chat_override_service,
            user_persona_service,
            character_service,
            token_counter,
            encryption_service,
            lorebook_service,
            auth_backend: self.auth_backend,
            email_service: crate::services::email_service::create_email_service(
                "development",
                "http://localhost:3000".to_string(),
                None,
            )
            .await?,
            ai_client_factory,
            rate_limiter: Arc::new(crate::middleware::llm_security::LlmRateLimiter::new(
                10, 100,
            )), // Test rate limiter
            recall_pipeline,
            token_service: Some(token_service), // Use initialized token service for JWT tests
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None, // Not used in tests
            #[cfg(feature = "local-llm")]
            security_audit_logger: None, // Not used in tests
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None, // Not used in tests
                                                // narrative_intelligence_service will be added after AppState is built
        };

        let mut app_state = AppState::new(self.db_pool, self.config, services);

        // Now create the narrative intelligence service with the fully constructed AppState
        let narrative_intelligence_service =
            Arc::new(NarrativeIntelligenceService::for_development_with_deps(
                app_state.ai_client.clone(),
                chronicle_service,
                app_state.lorebook_service.clone(),
                app_state.qdrant_service.clone(),
                app_state.embedding_client.clone(),
                Arc::new(app_state.clone()),
            ));

        // Set the narrative intelligence service
        app_state.set_narrative_intelligence_service(narrative_intelligence_service);

        Ok(app_state)
    }
}

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
    pub db_pool: DbPool,
    pub test_db_name: Option<String>, // Test database name for cleanup
    pub config: Arc<Config>,          // Add config field
    // Store the actual AI client being used (could be real or mock)
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
    // Optionally store the mock client for tests that need mock-specific methods
    pub mock_ai_client: Option<Arc<MockAiClient>>,
    pub mock_embedding_client: Arc<MockEmbeddingClient>,
    pub mock_embedding_pipeline_service: Arc<MockEmbeddingPipelineService>,
    pub qdrant_service: Arc<dyn crate::vector_db::VectorServiceTrait>, // Use trait object
    // Optionally store the mock Qdrant client for tests that need mock-specific methods
    pub mock_qdrant_service: Option<Arc<MockQdrantClientService>>,
    // user_persona_service field removed as per plan
    // embedding_call_tracker field removed as per plan
    pub recall_pipeline: Arc<crate::services::cognitive::RecallPipeline>,
    pub state: Arc<AppState>, // Added state field
}

/// TestAppGuard - Automatic cleanup wrapper for TestApp
///
/// This guard wraps TestApp and automatically cleans up the test database when it goes out of scope.
/// It implements Deref<Target = TestApp> so all existing test code works transparently without changes.
///
/// # How It Works
///
/// - Uses Arc internally to track the last reference
/// - When dropped, uses tokio::runtime::Handle to run async cleanup
/// - Cleans up the test database automatically
/// - No manual .cleanup().await calls needed
///
/// # Usage
///
/// ```rust,ignore
/// #[tokio::test]
/// async fn test_example() {
///     let test_app = test_helpers::spawn_app(true, false, false).await;
///     // test_app is TestAppGuard, but works like TestApp due to Deref
///     let pool = &test_app.db_pool;
///     // ... test code ...
/// } // Automatic cleanup happens here when test_app is dropped
/// ```
#[derive(Clone)]
pub struct TestAppGuard {
    inner: Arc<TestApp>,
    test_db_name: Option<String>,
    cleanup_done: Arc<std::sync::atomic::AtomicBool>,
}

impl TestAppGuard {
    /// Create a new TestAppGuard from a TestApp
    fn new(test_app: TestApp) -> Self {
        let test_db_name = test_app.test_db_name.clone();
        Self {
            inner: Arc::new(test_app),
            test_db_name,
            cleanup_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Cleanup the test database
    #[cfg(feature = "postgres-backend")]
    async fn cleanup_database(db_name: &str) -> Result<(), anyhow::Error> {
        use deadpool_diesel::postgres::Manager as DeadpoolManager;
        use deadpool_diesel::postgres::Pool as DeadpoolPool;
        use deadpool_diesel::Runtime as DeadpoolRuntime;
        use std::env;

        tracing::debug!(db_name = %db_name, "Dropping test database from TestAppGuard");

        let base_db_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
        let (main_db_url, _) = base_db_url
            .rsplit_once('/')
            .context("Invalid DATABASE_URL")?;

        let manager_default =
            DeadpoolManager::new(format!("{main_db_url}/postgres"), DeadpoolRuntime::Tokio1);
        let pool_default = DeadpoolPool::builder(manager_default)
            .max_size(1)
            .build()
            .context("Failed to create default DB pool")?;

        let conn_default = pool_default
            .get()
            .await
            .context("Failed to get default DB connection")?;

        let db_name_clone = db_name.to_string();
        conn_default
            .interact(move |conn| {
                diesel::sql_query(format!(
                    "DROP DATABASE IF EXISTS \"{db_name_clone}\" WITH (FORCE)"
                ))
                .execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
            .context("Failed to drop test database")?;

        tracing::debug!(db_name = %db_name, "Test database dropped successfully from TestAppGuard");
        Ok(())
    }

    /// Cleanup the test database (SQLite version - no-op for in-memory databases)
    #[cfg(feature = "sqlite-backend")]
    async fn cleanup_database(_db_name: &str) -> Result<(), anyhow::Error> {
        tracing::debug!(db_name = %_db_name, "SQLite in-memory database cleanup (no-op)");
        // SQLite in-memory databases are automatically cleaned up when connections are dropped
        Ok(())
    }
}

impl std::ops::Deref for TestAppGuard {
    type Target = TestApp;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for TestAppGuard {
    fn drop(&mut self) {
        // Only cleanup if this is the last reference and cleanup hasn't been done
        if Arc::strong_count(&self.inner) == 1 {
            if let Some(ref db_name) = self.test_db_name {
                // Check if cleanup was already done
                if !self
                    .cleanup_done
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    // Get the current tokio runtime handle
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let db_name_clone = db_name.clone();
                        // Spawn a blocking task to run the async cleanup
                        handle.spawn(async move {
                            if let Err(e) = Self::cleanup_database(&db_name_clone).await {
                                tracing::error!(
                                    db_name = %db_name_clone,
                                    error = %e,
                                    "Failed to cleanup test database in TestAppGuard::drop"
                                );
                            }
                        });
                    } else {
                        tracing::warn!(
                            db_name = %db_name,
                            "Cannot cleanup test database: no tokio runtime available"
                        );
                    }
                }
            }
        }
    }
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

async fn test_request_logging_middleware(req: AxumRequest, next: Next) -> AxumResponse {
    tracing::info!(target: "test_router_debug", "TEST ROUTER: Method={}, URI={}", req.method(), req.uri());
    next.run(req).await
}

#[instrument(skip_all, fields(multi_thread, use_real_ai, use_real_qdrant))]
pub async fn spawn_app(
    multi_thread: bool,
    use_real_ai: bool,
    use_real_qdrant: bool,
) -> TestAppGuard {
    spawn_app_with_options(multi_thread, use_real_ai, use_real_qdrant, false).await
}

/// Spawn app with permissive rate limiting for tests that make many sequential requests
pub async fn spawn_app_permissive_rate_limiting(
    multi_thread: bool,
    use_real_ai: bool,
    use_real_qdrant: bool,
) -> TestAppGuard {
    spawn_app_with_rate_limiting_options(multi_thread, use_real_ai, use_real_qdrant, false, 100, 50)
        .await
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
) -> TestAppGuard {
    spawn_app_with_rate_limiting_options(
        multi_thread,
        use_real_ai,
        use_real_qdrant,
        use_real_embedding_pipeline,
        2,
        5,
    )
    .await
}

#[instrument(
    skip_all,
    fields(
        multi_thread,
        use_real_ai,
        use_real_qdrant,
        use_real_embedding_pipeline,
        rate_limit_per_second,
        rate_limit_burst_size
    )
)]
pub async fn spawn_app_with_rate_limiting_options(
    _multi_thread: bool,
    use_real_ai: bool,
    use_real_qdrant: bool,
    use_real_embedding_pipeline: bool,
    rate_limit_per_second: u64,
    rate_limit_burst_size: u32,
) -> TestAppGuard {
    ensure_tracing_initialized();
    ensure_rustls_provider_installed(); // Ensure rustls crypto provider is set up

    // Load .env from project root (one directory up from backend/)
    let project_root = std::env::current_dir()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from(".."));
    dotenvy::from_path(project_root.join(".env")).ok();

    // Ensure COOKIE_SIGNING_KEY is set for tests
    if std::env::var("COOKIE_SIGNING_KEY").is_err() {
        // 64 bytes (128 hex chars) dummy key for tests
        std::env::set_var(
            "COOKIE_SIGNING_KEY",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
    }

    // PostgreSQL: Create unique test database per test (if multi-threaded)
    #[cfg(feature = "postgres-backend")]
    let (pool, test_db_name) = {
        let test_db_name_suffix = if _multi_thread {
            Some(DbId::new().to_string()) // Ensure it's String for suffix
        } else {
            None
        };
        db::setup_test_database(test_db_name_suffix.as_deref()).await
    };

    // SQLite: Use in-memory database for tests
    #[cfg(feature = "sqlite-backend")]
    let (pool, test_db_name) = {
        use diesel::r2d2::{ConnectionManager, Pool};
        use diesel_migrations::MigrationHarness;

        let database_url = format!(
            "file:memdb{}?mode=memory&cache=shared&busy_timeout=5000",
            DbId::new()
        );

        // Customizer to set busy_timeout
        #[derive(Debug)]
        struct SqliteConnectionCustomizer;

        impl diesel::r2d2::CustomizeConnection<crate::db::DbConnection, diesel::r2d2::Error>
            for SqliteConnectionCustomizer
        {
            fn on_acquire(
                &self,
                conn: &mut crate::db::DbConnection,
            ) -> Result<(), diesel::r2d2::Error> {
                use diesel::connection::SimpleConnection;
                conn.batch_execute("PRAGMA busy_timeout = 5000;")
                    .map_err(diesel::r2d2::Error::QueryError)
            }
        }

        let manager = ConnectionManager::<crate::db::DbConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(5)
            .connection_customizer(Box::new(SqliteConnectionCustomizer))
            .build(manager)
            .expect("Failed to create SQLite test pool");

        // Run migrations on in-memory database
        let mut conn = pool.get().expect("Failed to get connection for migrations");
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations_sqlite");
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run SQLite migrations");

        (pool, String::new()) // SQLite uses in-memory, no real database name
    };

    let mut config_loader = Config::load().expect("Failed to load test configuration");

    // PostgreSQL-specific database URL configuration
    #[cfg(feature = "postgres-backend")]
    {
        // Note: For PostgreSQL, the database_url is already set by setup_test_database
        // This is kept for potential future configuration needs
    }

    // SQLite-specific database URL configuration
    #[cfg(feature = "sqlite-backend")]
    {
        config_loader.database_url = Some(":memory:".to_string());
    }

    config_loader.port = 0;

    // Enable credit system for integration tests
    #[cfg(feature = "payment")]
    {
        config_loader.payment.credits_enabled = true;
    }

    let config_arc = Arc::new(config_loader);

    let (ai_client_for_state, mock_ai_client_for_test_app): (
        Arc<dyn AiClient + Send + Sync>,
        Option<Arc<MockAiClient>>,
    ) = if use_real_ai {
        let api_key =
            std::env::var("GEMINI_API_KEY").unwrap_or_else(|_| "test-api-key".to_string());
        let real_ai_client = crate::llm::rig_client::RigClient::new(Some(api_key), None);
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
        Arc<dyn crate::vector_db::VectorServiceTrait>,
        Option<Arc<MockQdrantClientService>>,
    ) = if use_real_qdrant {
        // This flag now also controls embedding components
        let real_embedding_client =
            crate::llm::cloud_embedding_client::build_cloud_embedding_client(config_arc.clone())
                .expect("Failed to build real Cloud embedding client for test");
        let embedding_model = UnifiedEmbeddingModel::Cloud(real_embedding_client);

        let real_vector_service =
            crate::vector_db::create_vector_service(config_arc.clone(), embedding_model)
                .await
                .expect("Failed to create real vector service for test");
        (real_vector_service, None)
    } else {
        let mock_qdrant = Arc::new(MockQdrantClientService::new());
        (
            mock_qdrant.clone() as Arc<dyn crate::vector_db::VectorServiceTrait>,
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
            crate::llm::cloud_embedding_client::build_cloud_embedding_client(config_arc.clone())
                .expect("Failed to build real Cloud embedding client for test");
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

    let app_state_inner = builder
        .build()
        .await
        .expect("Failed to build test app state");

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

    // Health endpoint - not rate limited for monitoring purposes (matches production)
    let health_routes_for_test = Router::new()
        .route("/api/health", get(health_check))
        .with_state(app_state_inner.clone());

    #[allow(unused_mut)]
    let mut protected_api_routes_for_test = Router::new()
        .nest(
            "/characters",
            characters::characters_router(app_state_inner.clone()),
        )
        .nest(
            "/chat",
            chat_routes(app_state_inner.clone()).merge(game_state::router(app_state_inner.clone())),
        )
        .nest("/chats", chats::chat_routes()) // Assuming this returns Router<AppState> or is already stateful
        .nest(
            "/chronicles",
            chronicles::create_chronicles_router(app_state_inner.clone()),
        ); // Add chronicles routes

    // Conditionally add documents routes (PostgreSQL only)
    #[cfg(feature = "postgres-backend")]
    {
        protected_api_routes_for_test =
            protected_api_routes_for_test.nest("/documents", document_routes());
        // Assuming this returns Router<AppState> or is already stateful
    }

    let protected_api_routes_for_test = protected_api_routes_for_test
        .nest("/generation", generation_routes::router()) // AI generation routes
        .nest(
            "/personas",
            user_persona_routes::user_personas_router(app_state_inner.clone()),
        ) // Add persona routes
        .nest(
            "/user-settings",
            user_settings_routes::user_settings_routes(app_state_inner.clone()),
        ) // Add user settings routes
        .nest(
            "/template-preferences",
            template_preferences_routes::template_preferences_routes(app_state_inner.clone()),
        ) // Add template preferences routes
        .nest("/payment", payment_routes::payment_routes()) // Add payment routes
        .merge(lorebook_routes::lorebook_routes()) // Align with main.rs: Nest lorebook routes under /
        .route_layer(middleware::from_fn_with_state(
            app_state_inner.clone(),
            auth_log_wrapper,
        ))
        .route_layer(login_required!(AuthBackend)); // Apply authentication enforcement like in production

    // Webhook routes (no authentication, no rate limiting - signature verified in handler)
    #[cfg(feature = "payment")]
    let webhook_routes_for_test = Router::new()
        .nest("/api/payment", payment_routes::payment_webhook_routes()) // Webhook routes under /api/payment
        .with_state(app_state_inner.clone());

    #[cfg(not(feature = "payment"))]
    let webhook_routes_for_test = Router::new();

    // Rate-limited API routes (both auth and protected routes)
    let rate_limited_api_routes = Router::new()
        .nest("/auth", auth_routes_module::auth_routes()) // Auth routes under /api/auth
        .merge(protected_api_routes_for_test) // Protected routes under /api
        .layer(GovernorLayer::new(std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .per_second(rate_limit_per_second)
                .burst_size(rate_limit_burst_size)
                // Use GlobalKeyExtractor for tests (doesn't require ConnectInfo)
                .key_extractor(GlobalKeyExtractor)
                .finish()
                .unwrap(),
        )));

    let router_for_server = Router::new() // Renamed to avoid conflict with router field in TestApp
        .merge(health_routes_for_test) // Health endpoint not rate limited
        .merge(webhook_routes_for_test) // Webhook routes without auth
        .nest("/api", rate_limited_api_routes) // All other API routes are rate limited
        .layer(CookieManagerLayer::new())
        .layer(auth_layer) // Re-enabled auth layer
        .with_state(app_state_inner.clone())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        )
        .layer(axum::middleware::from_fn(test_request_logging_middleware));

    let router_for_test_app = router_for_server.clone(); // Clone for test app

    tokio::spawn(async move {
        axum::serve(
            listener,
            router_for_server.into_make_service_with_connect_info::<SocketAddr>(),
        ) // Use router_for_server
        .await
        .expect("Test server failed");
    });

    let test_app = TestApp {
        address: app_address,
        router: router_for_test_app, // Use the cloned router
        // Direct reqwest calls are made to `app_address`.
        // Keeping it to satisfy struct, but should ideally be removed or used consistently.
        db_pool: pool,
        test_db_name: Some(test_db_name), // Store test database name for cleanup
        config: config_arc,
        ai_client: ai_client_for_state,
        mock_ai_client: mock_ai_client_for_test_app,
        mock_embedding_client: mock_embedding_client_for_test_app.clone(),
        mock_embedding_pipeline_service: mock_embedding_pipeline_service_for_test_app.clone(),
        qdrant_service: qdrant_service_for_state,
        mock_qdrant_service: mock_qdrant_service_for_test_app,
        recall_pipeline: app_state_inner.recall_pipeline.clone(),
        state: Arc::new(app_state_inner.clone()), // Populate state field
    };

    // Wrap in TestAppGuard for automatic cleanup
    TestAppGuard::new(test_app)
}

// --- Modules containing test helpers ---

pub mod db {
    // Add a comprehensive set of imports needed within the db module
    use crate::models::users::UserDbQuery;
    #[cfg(feature = "postgres-backend")]
    use diesel::RunQueryDsl;
    use diesel_migrations::MigrationHarness;
    // Import AppError

    use crate::db::DbPool; // Backend-agnostic pool type
    #[cfg(feature = "postgres-backend")]
    use crate::db::MIGRATIONS;
    use crate::db::{DbId, DbTimestamp}; // Import unified types
    use crate::models::chats::{DbInsertableChatMessage, MessageRole};

    // PostgreSQL-specific imports
    #[cfg(feature = "postgres-backend")]
    use crate::PgPool;

    // SQLite-specific imports

    // For logging macros
    // Use super::MIGRATIONS since it's defined in the parent scope (test_helpers.rs)
    use crate::auth::{self};
    #[cfg(feature = "postgres-backend")]
    use deadpool_diesel::postgres::{
        Manager as DeadpoolManager, Pool as DeadpoolPool, Runtime as DeadpoolRuntime,
    };
    // For .env file loading
    // use std::env; // For DATABASE_URL reading in setup_test_database // Corrected: Added hash_password, auth for module items
    // Ensure RegisterPayload is imported
    use super::{
        AccountStatus, Context, DbUser, ExposeSecret, SecretBox, SecretString,
        SerializableSecretDek,
    };
    // Keep if CryptoError is used directly, else it comes via crate::crypto
    use crate::models::users::NewUser; // Removed User as DbUser from here, already aliased DbUser at top
                                       // and UserDbQuery is imported above

    /// Creates a test database pool (backend-agnostic).
    ///
    /// For PostgreSQL: Creates a new test database with migrations.
    /// For SQLite: Creates an in-memory database with migrations.
    ///
    /// Returns (pool, test_db_name) for PostgreSQL, (pool, "") for SQLite.
    pub async fn create_test_pool(_db_name_suffix: Option<&str>) -> (DbPool, String) {
        #[cfg(feature = "postgres-backend")]
        {
            setup_test_database(_db_name_suffix).await
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::r2d2::{ConnectionManager, Pool};

            let database_url = format!(
                "file:memdb{}?mode=memory&cache=shared&busy_timeout=5000",
                DbId::new()
            );

            // Customizer to set busy_timeout
            #[derive(Debug)]
            struct SqliteConnectionCustomizer;

            impl diesel::r2d2::CustomizeConnection<crate::db::DbConnection, diesel::r2d2::Error>
                for SqliteConnectionCustomizer
            {
                fn on_acquire(
                    &self,
                    conn: &mut crate::db::DbConnection,
                ) -> Result<(), diesel::r2d2::Error> {
                    use diesel::connection::SimpleConnection;
                    conn.batch_execute("PRAGMA busy_timeout = 5000;")
                        .map_err(diesel::r2d2::Error::QueryError)
                }
            }

            let manager = ConnectionManager::<crate::db::DbConnection>::new(database_url);
            let pool = Pool::builder()
                .max_size(5)
                .connection_customizer(Box::new(SqliteConnectionCustomizer))
                .build(manager)
                .expect("Failed to create SQLite test pool");

            // Run migrations
            let mut conn = pool.get().expect("Failed to get connection for migrations");
            const MIGRATIONS: diesel_migrations::EmbeddedMigrations =
                diesel_migrations::embed_migrations!("migrations_sqlite");
            conn.run_pending_migrations(MIGRATIONS)
                .expect("Failed to run SQLite migrations");

            (pool, String::new())
        }
    }

    /// Sets up a clean test database with migrations run (PostgreSQL only).
    ///
    /// # Panics
    ///
    /// Panics if the `DATABASE_URL` environment variable is not set
    #[cfg(feature = "postgres-backend")]
    pub async fn setup_test_database(db_name_suffix: Option<&str>) -> (PgPool, String) {
        // Load .env from project root (one directory up from backend/)
        let project_root = std::env::current_dir()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from(".."));
        dotenvy::from_path(project_root.join(".env")).ok();
        let db_name = format!(
            "test_db_{}_{}",
            db_name_suffix.unwrap_or("default"),
            DbId::new()
        );
        let base_db_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for testing");
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
            .unwrap_or_else(|e| panic!("Failed to get default DB connection: {}", e));

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
        #[cfg(feature = "postgres-backend")]
        {
            let conn = crate::db::get_conn(&pool)
                .await
                .expect("Failed to get test DB connection for migration");
            conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
                .await
                .expect("Migration task failed")
                .expect("Failed to run migrations");
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            let mut conn = pool.get().expect("Failed to get connection for migrations");
            const MIGRATIONS: diesel_migrations::EmbeddedMigrations =
                diesel_migrations::embed_migrations!("migrations_sqlite");
            conn.run_pending_migrations(MIGRATIONS)
                .expect("Failed to run SQLite migrations");
        }

        (pool, db_name)
    }

    /// Creates a test user directly in the database.
    /// Note: This helper bypasses any application logic for user creation (e.g., sending emails).
    /// Creates a test user in the database
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails
    pub async fn create_test_user(
        pool: &DbPool,
        username: String,
        password_str: String,
    ) -> Result<DbUser, anyhow::Error> {
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

        // Generate UUID for both backends (required for SQLite, overrides DEFAULT for PostgreSQL)
        let user_id = crate::db::DbId::new();

        let new_user_payload = NewUser {
            id: user_id,
            username: username_clone_for_payload,
            password_hash,
            email,
            kek_salt,
            encrypted_dek: crate::db::DbBlob::from(encrypted_dek_bytes),
            dek_nonce: crate::db::DbBlob::from(dek_nonce_bytes),
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
            role: crate::models::users::UserRole::User, // Using User enum variant exactly as in DB
            account_status: AccountStatus::Active,      // Default to Active account status
            total_prompt_tokens: crate::db::DbBigInt::from(0),
            total_completion_tokens: crate::db::DbBigInt::from(0),
            total_token_cost_cents: crate::db::DbBigInt::from(0),
            tokens_last_reset_at: None,
            token_usage_updated_at: crate::db::DbTimestamp::now(),
        };

        #[cfg(feature = "postgres-backend")]
        let user_from_db: UserDbQuery = {
            let conn = crate::db::get_conn(pool)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?;

            conn.interact(move |conn_actual| {
                use diesel::{RunQueryDsl, SelectableHelper}; // Added SelectableHelper
                diesel::insert_into(crate::schema::users::table)
                    .values(new_user_payload)
                    .returning(UserDbQuery::as_returning())
                    .get_result(conn_actual)
            })
            .await
            .map_err(|interact_err| {
                anyhow::anyhow!("DB interact error for create_test_user: {}", interact_err)
            })??
        };

        #[cfg(feature = "sqlite-backend")]
        let user_from_db: UserDbQuery = {
            use diesel::prelude::*;
            let username_for_query = new_user_payload.username.clone();

            crate::db::with_conn(&pool, move |conn_actual| {
                diesel::insert_into(crate::schema::users::table)
                    .values(&new_user_payload)
                    .execute(conn_actual)
                    .map_err(|e| {
                        crate::errors::AppError::DatabaseQueryError(format!(
                            "Failed to insert user: {}",
                            e
                        ))
                    })?;

                // Query back using username (unique key)
                crate::schema::users::table
                    .filter(crate::schema::users::username.eq(username_for_query))
                    .first::<UserDbQuery>(conn_actual)
                    .map_err(|e| {
                        crate::errors::AppError::DatabaseQueryError(format!(
                            "Failed to query user after insert: {}",
                            e
                        ))
                    })
            })
            .await?
        };

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
        pool: &DbPool,
        username: String,
        password_str: String,
    ) -> Result<DbUser, anyhow::Error> {
        let email = format!("{username}@test.com");

        let password_str_for_kek = password_str.clone(); // Clone for KEK derivation
        let username_clone_for_payload = username.clone(); // Clone for NewUser payload

        let password_hash = auth::hash_password(SecretString::from(password_str.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        let kek_salt = crate::crypto::generate_salt()
            .map_err(|e| anyhow::anyhow!("KEK salt generation failed: {}", e))?;

        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        let plaintext_dek_box: SecretBox<Vec<u8>> = crate::crypto::generate_dek()
            .context("DEK generation failed in create_pending_test_user")?;

        let kek = crate::crypto::derive_kek(&SecretString::from(password_str_for_kek), &kek_salt)
            .map_err(|e| anyhow::anyhow!("KEK derivation failed: {}", e))?;

        let (encrypted_dek_bytes, dek_nonce_bytes) =
            crate::crypto::encrypt_gcm(plaintext_dek_box.expose_secret(), &kek) // expose_secret() on SecretBox<Vec<u8>> gives &Vec<u8>
                .map_err(|e| anyhow::anyhow!("DEK encryption failed: {}", e))?;

        // Generate UUID for both backends (required for SQLite, overrides DEFAULT for PostgreSQL)
        let user_id = crate::db::DbId::new();

        let new_user_payload = NewUser {
            id: user_id,
            username: username_clone_for_payload,
            password_hash,
            email,
            kek_salt,
            encrypted_dek: crate::db::DbBlob::from(encrypted_dek_bytes),
            dek_nonce: crate::db::DbBlob::from(dek_nonce_bytes),
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
            role: crate::models::users::UserRole::User, // Using User enum variant exactly as in DB
            account_status: AccountStatus::Pending,     // Set to Pending for email verification
            total_prompt_tokens: crate::db::DbBigInt::from(0),
            total_completion_tokens: crate::db::DbBigInt::from(0),
            total_token_cost_cents: crate::db::DbBigInt::from(0),
            tokens_last_reset_at: None,
            token_usage_updated_at: crate::db::DbTimestamp::now(),
        };

        #[cfg(feature = "postgres-backend")]
        let user_from_db: UserDbQuery = {
            let conn = crate::db::get_conn(pool)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?;

            conn.interact(move |conn_actual| {
                use diesel::{RunQueryDsl, SelectableHelper};
                diesel::insert_into(crate::schema::users::table)
                    .values(new_user_payload)
                    .returning(UserDbQuery::as_returning())
                    .get_result(conn_actual)
            })
            .await
            .map_err(|interact_err| {
                anyhow::anyhow!(
                    "DB interact error for create_pending_test_user: {}",
                    interact_err
                )
            })??
        };

        #[cfg(feature = "sqlite-backend")]
        let user_from_db: UserDbQuery = {
            use diesel::prelude::*;
            let username_for_query = new_user_payload.username.clone();

            crate::db::with_conn(&pool, move |conn_actual| {
                diesel::insert_into(crate::schema::users::table)
                    .values(&new_user_payload)
                    .execute(conn_actual)
                    .map_err(|e| {
                        crate::errors::AppError::DatabaseQueryError(format!(
                            "Failed to insert pending user: {}",
                            e
                        ))
                    })?;

                // Query back using username (unique key)
                crate::schema::users::table
                    .filter(crate::schema::users::username.eq(username_for_query))
                    .first::<UserDbQuery>(conn_actual)
                    .map_err(|e| {
                        crate::errors::AppError::DatabaseQueryError(format!(
                            "Failed to query pending user after insert: {}",
                            e
                        ))
                    })
            })
            .await?
        };

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
        pool: &DbPool,
        user_id: crate::db::DbId,
        name: String,
    ) -> Result<crate::models::characters::Character, anyhow::Error> {
        use crate::models::character_card::NewCharacter;
        use crate::models::characters::Character; // Already imported at top of file usually
                                                  // use crate::schema::characters; // Already imported at top of file usually
        use crate::models::OptionalStringArray;

        #[cfg(feature = "postgres-backend")]
        let _conn = crate::db::get_conn(pool).await?;
        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        let _conn = pool.get()?;
        let now = DbTimestamp::now();
        let name_clone_for_payload = name.clone(); // Clone for payload and error message

        let new_character_payload = NewCharacter {
            id: Some(crate::db::DbId::new()),
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
            #[cfg(feature = "postgres-backend")]
            created_at: Some(now),
            #[cfg(feature = "postgres-backend")]
            updated_at: Some(now),
            #[cfg(feature = "sqlite-backend")]
            created_at: now,
            #[cfg(feature = "sqlite-backend")]
            updated_at: now,
            creation_date: Some(now),
            modification_date: Some(now),
            creator_notes_multilingual: None,
            nickname: None,
            personality: None,
            tags: OptionalStringArray::default(),
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
            system_tags: OptionalStringArray::default(),
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
            alternate_greetings: OptionalStringArray::default(),
            creator: None,
            source: OptionalStringArray::default(),
            group_only_greetings: OptionalStringArray::default(),
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

        let _name_clone_for_second_error = name_clone_for_payload.clone();
        let character = {
            #[cfg(feature = "postgres-backend")]
            {
                let conn = crate::db::get_conn(pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?;

                conn.interact(move |conn_actual| {
                    use diesel::prelude::*;
                    diesel::insert_into(crate::schema::characters::table)
                        .values(new_character_payload)
                        .returning(Character::as_returning())
                        .get_result(conn_actual)
                })
                .await
                .map_err(move |interact_err| {
                    anyhow::anyhow!(
                        "DB interact error for create_test_character '{}': {}",
                        name_clone_for_payload,
                        interact_err
                    )
                })??
            }

            #[cfg(feature = "sqlite-backend")]
            {
                crate::db::with_conn_immediate(pool, move |conn_actual| {
                    use diesel::prelude::*;
                    let name_for_query = new_character_payload.name.clone();
                    diesel::insert_into(crate::schema::characters::table)
                        .values(new_character_payload)
                        .execute(conn_actual)?;

                    // Query back the inserted row by name (unique for test data)
                    crate::schema::characters::table
                        .filter(crate::schema::characters::name.eq(name_for_query))
                        .order_by(crate::schema::characters::created_at.desc())
                        .select(Character::as_select())
                        .first(conn_actual)
                        .map_err(|e| crate::errors::AppError::DatabaseQueryError(e.to_string()))
                })
                .await
                .map_err(move |interact_err| {
                    anyhow::anyhow!(
                        "DB interact error for create_test_character '{}': {}",
                        name_clone_for_payload,
                        interact_err
                    )
                })?
            }
        };

        Ok(character)
    }

    /// Unified helper to create a DbInsertableChatMessage that works for both backends.
    #[allow(clippy::too_many_arguments)]
    pub fn create_test_message(
        id: DbId,
        chat_id: DbId,
        user_id: DbId,
        msg_type: MessageRole,
        content: Vec<u8>,
        content_nonce: Option<Vec<u8>>,
        model_name: String,
        created_at: DbTimestamp,
        updated_at: DbTimestamp,
    ) -> DbInsertableChatMessage {
        #[cfg(feature = "postgres-backend")]
        {
            DbInsertableChatMessage::new(
                chat_id,
                user_id,
                msg_type,
                content,
                content_nonce,
                model_name,
            )
            .with_id(id)
            .with_created_at(created_at)
            .with_updated_at(updated_at)
        }

        #[cfg(feature = "sqlite-backend")]
        {
            DbInsertableChatMessage::new(
                chat_id,
                user_id,
                msg_type,
                content,
                content_nonce,
                model_name,
            )
            .with_id(id)
            .with_created_at(created_at)
            .with_updated_at(updated_at)
        }
    }
}

// --- Auth Helper Functions ---

/// TestDataGuard - RAII-style cleanup for test data
///
/// This guard tracks test resources (users, characters, chats, personas, lorebooks) within tests.
/// **Test databases are now cleaned up automatically** by TestAppGuard, so you don't need to
/// worry about database cleanup when using TestDataGuard.
///
/// # Typical Usage Pattern
///
/// ```rust,ignore
/// #[tokio::test]
/// async fn test_example() {
///     let test_app = test_helpers::spawn_app(true, false, false).await;
///     let mut guard = test_helpers::TestDataGuard::new(
///         test_app.db_pool.clone(),
///         test_app.test_db_name.clone()
///     );
///
///     // Track test resources
///     guard.add_user_id(user.id);
///     guard.add_character_id(character.id);
///
///     // ... test code ...
///
///     // Optional: Explicit cleanup for table data
///     guard.cleanup().await.expect("Cleanup failed");
/// }
/// ```
///
/// # Automatic Database Cleanup
///
/// - Test databases are automatically cleaned up by TestAppGuard when it goes out of scope
/// - TestDataGuard focuses on cleaning up rows in tables (users, characters, chats, etc.)
/// - You can still call `.cleanup().await` explicitly if you need early cleanup
///
/// # What Gets Cleaned Up
///
/// - User records
/// - Character records
/// - Chat session records
/// - User persona records
/// - Lorebook records
///
/// Note: The test database itself is cleaned up automatically by TestAppGuard.
pub struct TestDataGuard {
    pool: DbPool,
    test_db_name: Option<String>,
    user_ids: Vec<crate::db::DbId>,
    character_ids: Vec<crate::db::DbId>,
    chat_ids: Vec<crate::db::DbId>,
    user_persona_ids: Vec<crate::db::DbId>,
    lorebook_ids: Vec<crate::db::DbId>,
}

// Manual implementation of Debug for TestDataGuard
impl fmt::Debug for TestDataGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestDataGuard")
            .field("pool", &"PgPool // Omitted details for Debug") // PgPool itself is Debug, but we simplify here
            .field("test_db_name", &self.test_db_name)
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
    pub fn new(pool: DbPool, test_db_name: Option<String>) -> Self {
        // Changed to PgPool and added test_db_name parameter
        Self {
            pool,
            test_db_name,
            user_ids: Vec::new(),
            character_ids: Vec::new(),
            chat_ids: Vec::new(),
            user_persona_ids: Vec::new(),
            lorebook_ids: Vec::new(),
        }
    }

    pub fn add_user(&mut self, user_id: crate::db::DbId) {
        self.user_ids.push(user_id);
    }

    pub fn add_character(&mut self, character_id: crate::db::DbId) {
        self.character_ids.push(character_id);
    }

    pub fn add_chat(&mut self, chat_id: crate::db::DbId) {
        self.chat_ids.push(chat_id);
    }

    pub fn add_user_persona(&mut self, user_persona_id: crate::db::DbId) {
        self.user_persona_ids.push(user_persona_id);
    }

    pub fn add_lorebook(&mut self, lorebook_id: crate::db::DbId) {
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
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.pool)
            .await
            .context("Failed to get DB connection for cleanup")?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&self.pool)
            .await
            .context("Failed to get DB connection for cleanup")?;

        if !self.chat_ids.is_empty() {
            tracing::debug!(chat_ids = ?self.chat_ids, "Cleaning up test chats and messages");
            let chat_ids_clone = self.chat_ids.clone();
            let diesel_chat_op_result = conn
                .interact(move |conn_interaction| {
                    #[cfg(feature = "postgres-backend")]
                    let id_values: Vec<uuid::Uuid> =
                        chat_ids_clone.iter().map(|id| id.into_uuid()).collect();
                    #[cfg(feature = "sqlite-backend")]
                    let id_values: Vec<String> =
                        chat_ids_clone.iter().map(|id| id.to_string()).collect();

                    diesel::delete(schema::chat_messages::table)
                        .filter(schema::chat_messages::session_id.eq_any(&id_values))
                        .execute(conn_interaction)?;
                    diesel::delete(schema::chat_sessions::table)
                        .filter(schema::chat_sessions::id.eq_any(&id_values))
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
                    #[cfg(feature = "postgres-backend")]
                    let id_values: Vec<uuid::Uuid> = user_persona_ids_clone
                        .iter()
                        .map(|id| id.into_uuid())
                        .collect();
                    #[cfg(feature = "sqlite-backend")]
                    let id_values: Vec<String> = user_persona_ids_clone
                        .iter()
                        .map(|id| id.to_string())
                        .collect();

                    diesel::delete(schema::user_personas::table)
                        .filter(schema::user_personas::id.eq_any(&id_values))
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
                    #[cfg(feature = "postgres-backend")]
                    let id_values: Vec<uuid::Uuid> = character_ids_clone
                        .iter()
                        .map(|id| id.into_uuid())
                        .collect();
                    #[cfg(feature = "sqlite-backend")]
                    let id_values: Vec<String> = character_ids_clone
                        .iter()
                        .map(|id| id.to_string())
                        .collect();

                    diesel::delete(schema::characters::table)
                        .filter(schema::characters::id.eq_any(&id_values))
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
                    #[cfg(feature = "postgres-backend")]
                    let id_values: Vec<uuid::Uuid> =
                        lorebook_ids_clone.iter().map(|id| id.into_uuid()).collect();
                    #[cfg(feature = "sqlite-backend")]
                    let id_values: Vec<String> =
                        lorebook_ids_clone.iter().map(|id| id.to_string()).collect();

                    // First delete lorebook entries
                    diesel::delete(schema::lorebook_entries::table)
                        .filter(schema::lorebook_entries::lorebook_id.eq_any(&id_values))
                        .execute(conn_interaction)?;
                    // Then delete lorebooks
                    diesel::delete(schema::lorebooks::table)
                        .filter(schema::lorebooks::id.eq_any(&id_values))
                        .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_lorebooks.context("Interact error cleaning up lorebooks")?;
        }

        if !self.user_ids.is_empty() {
            tracing::debug!(user_count = self.user_ids.len(), "Cleaning up test users");
            let user_ids_clone = self.user_ids.clone();
            let diesel_op_result_users = conn
                .interact(move |conn_interaction| {
                    #[cfg(feature = "postgres-backend")]
                    let id_values: Vec<uuid::Uuid> =
                        user_ids_clone.iter().map(|id| id.into_uuid()).collect();
                    #[cfg(feature = "sqlite-backend")]
                    let id_values: Vec<String> =
                        user_ids_clone.iter().map(|id| id.to_string()).collect();

                    diesel::delete(schema::users::table)
                        .filter(schema::users::id.eq_any(&id_values))
                        .execute(conn_interaction)
                })
                .await
                .map_err(|e_interact| anyhow::anyhow!(e_interact.to_string()))?;
            diesel_op_result_users.context("Interact error cleaning up users")?;
        }

        // Clean up test database if present
        if let Some(ref db_name) = self.test_db_name {
            self.cleanup_database(db_name).await?;
        }

        tracing::debug!("--- TestDataGuard cleanup complete ---");
        Ok(())
    }

    /// Drops the test database
    ///
    /// # Errors
    ///
    /// Returns an error if database cannot be dropped
    #[cfg(feature = "postgres-backend")]
    async fn cleanup_database(&self, db_name: &str) -> Result<(), anyhow::Error> {
        use deadpool_diesel::postgres::Manager as DeadpoolManager;
        use deadpool_diesel::postgres::Pool as DeadpoolPool;
        use deadpool_diesel::Runtime as DeadpoolRuntime;
        use std::env;

        tracing::debug!(db_name = %db_name, "Dropping test database");

        let base_db_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
        let (main_db_url, _) = base_db_url
            .rsplit_once('/')
            .context("Invalid DATABASE_URL")?;

        // Connect to the default postgres database to drop the test database
        let manager_default =
            DeadpoolManager::new(format!("{main_db_url}/postgres"), DeadpoolRuntime::Tokio1);
        let pool_default = DeadpoolPool::builder(manager_default)
            .max_size(1)
            .build()
            .context("Failed to create default DB pool")?;

        let conn_default = pool_default
            .get()
            .await
            .context("Failed to get default DB connection")?;

        let db_name_clone = db_name.to_string();
        conn_default
            .interact(move |conn| {
                diesel::sql_query(format!(
                    "DROP DATABASE IF EXISTS \"{db_name_clone}\" WITH (FORCE)"
                ))
                .execute(conn)?;
                Ok::<(), diesel::result::Error>(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
            .context("Failed to drop test database")?;

        tracing::debug!(db_name = %db_name, "Test database dropped successfully");
        Ok(())
    }

    /// Cleanup the test database (SQLite version - no-op for in-memory databases)
    #[cfg(feature = "sqlite-backend")]
    async fn cleanup_database(&self, _db_name: &str) -> Result<(), anyhow::Error> {
        tracing::debug!(db_name = %_db_name, "SQLite in-memory database cleanup (no-op)");
        // SQLite in-memory databases are automatically cleaned up when connections are dropped
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
            || self.test_db_name.is_some()
        {
            tracing::warn!(
                "TestDataGuard dropped without explicit cleanup. Database cleanup should be called explicitly via cleanup().await."
            );

            // Note: We cannot call async cleanup_database from Drop as it's synchronous.
            // Tests should explicitly call the async cleanup() method.
            // This warning helps identify tests that aren't cleaning up properly.
            if let Some(ref db_name) = self.test_db_name {
                tracing::warn!(
                    test_db = %db_name,
                    "Test database will remain until manual cleanup. Please call .cleanup().await explicitly."
                );
            }
        }
    }
}

/// Performs database cleanup for test data
///
/// # Errors
///
/// Returns an error if any of the database deletion operations fail
#[cfg(feature = "postgres-backend")]
pub fn db_specific_cleanup(
    conn: &mut PgConnection,
    test_data: &TestDataGuard,
) -> Result<(), anyhow::Error> {
    // Clean up chat messages first (if any, assuming chat_messages depend on chats)
    // Example: diesel::delete(schema::chat_messages::table.filter(...)).execute(conn)?;

    if !test_data.chat_ids.is_empty() {
        let chat_ids_clone = test_data.chat_ids.clone();
        #[cfg(feature = "postgres-backend")]
        let id_values: Vec<uuid::Uuid> = chat_ids_clone.iter().map(|id| id.into_uuid()).collect();
        #[cfg(feature = "sqlite-backend")]
        let id_values: Vec<String> = chat_ids_clone.iter().map(|id| id.to_string()).collect();

        diesel::delete(schema::chat_sessions::table)
            .filter(schema::chat_sessions::id.eq_any(&id_values))
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
    pool: &DbPool,
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

    let history_sent_to_ai = &last_request.history;

    println!("\n[DEBUG] All messages sent to AI client (excluding preamble and current prompt):");
    if let Some(preamble) = &last_request.preamble {
        println!("  [Preamble] System: {}", preamble);
    }
    for (i, msg) in history_sent_to_ai.iter().enumerate() {
        let (role_str, content) = match msg {
            rig::message::Message::User { content } => {
                let text = content
                    .iter()
                    .map(|c| match c {
                        rig::message::UserContent::Text(t) => t.text.clone(),
                        _ => "".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                ("User", text)
            }
            rig::message::Message::Assistant { content, .. } => {
                let text = content
                    .iter()
                    .map(|c| match c {
                        rig::message::AssistantContent::Text(t) => t.text.clone(),
                        _ => "".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                ("Assistant", text)
            }
        };
        println!("  [{i}] {role_str}: {content}");
    }
    println!("  [Current] User: {}", last_request.prompt);

    println!(
        "\n[DEBUG] Comparing {} expected messages against {} actual messages in history",
        expected_history.len(),
        history_sent_to_ai.len()
    );

    assert_eq!(
        history_sent_to_ai.len(),
        expected_history.len(),
        "Number of history messages sent to AI mismatch."
    );

    for (i, expected) in expected_history.iter().enumerate() {
        let actual = &history_sent_to_ai[i];
        let (expected_role_str, expected_content) = expected;

        let (actual_role_str, actual_content) = match actual {
            rig::message::Message::User { content } => {
                let text = content
                    .iter()
                    .map(|c| match c {
                        rig::message::UserContent::Text(t) => t.text.clone(),
                        _ => "".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                ("User", text)
            }
            rig::message::Message::Assistant { content, .. } => {
                let text = content
                    .iter()
                    .map(|c| match c {
                        rig::message::AssistantContent::Text(t) => t.text.clone(),
                        _ => "".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                ("Assistant", text)
            }
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
    session_id: crate::db::DbId,
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
        model_provider: None,
        enable_code_execution: None,
        thinking_budget: None,
        chronicle_id: None,
        agent_mode: None,
        active_custom_persona_id: None,
        prompt_template_id: None,
        game_master_mode_enabled: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        logit_bias: None,
        thinking_level: None,
        rag_chronicles_limit: None,
        rag_lorebooks_limit: None,
        rag_older_chat_limit: None,
        rag_cognitive_context_limit: None,
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

impl TestApp {
    /// Create an AppState instance for testing
    pub async fn create_app_state(&self) -> Arc<AppState> {
        let encryption_service =
            Arc::new(crate::services::encryption_service::EncryptionService::new());
        let lorebook_service = Arc::new(crate::services::lorebook::LorebookService::new(
            self.db_pool.clone(),
            encryption_service.clone(),
            self.qdrant_service.clone(),
        ));

        // Create auth_backend for this AppState
        let auth_backend = Arc::new(crate::auth::user_store::Backend::new(self.db_pool.clone()));

        // Create email service for testing
        let email_service = crate::services::email_service::create_email_service(
            "development",
            "http://localhost:3000".to_string(),
            None,
        )
        .await
        .expect("Failed to create email service for test");

        // Create AI client factory for testing
        let ai_client_factory = Arc::new(crate::services::ai_client_factory::AiClientFactory::new(
            self.db_pool.clone(),
            self.config.clone(),
            self.ai_client.clone(), // Use test AI client as fallback
        ));

        let character_service =
            Arc::new(crate::services::character_service::CharacterService::new(
                self.db_pool.clone(),
                encryption_service.clone(),
            ));

        let services = crate::state::AppStateServices {
            ai_client: self.ai_client.clone(),
            embedding_client: self.mock_embedding_client.clone()
                as Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: self.qdrant_service.clone(),
            embedding_pipeline_service: self.mock_embedding_pipeline_service.clone()
                as Arc<
                    dyn crate::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync,
                >,
            chat_override_service: Arc::new(
                crate::services::chat_override_service::ChatOverrideService::new(
                    self.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            user_persona_service: Arc::new(
                crate::services::user_persona_service::UserPersonaService::new(
                    self.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            character_service,
            token_counter: Arc::new(
                crate::services::hybrid_token_counter::HybridTokenCounter::new(
                    crate::services::tokenizer_service::TokenizerService::new(
                        &self.config.tokenizer_model_path,
                    )
                    .unwrap_or_else(|_| panic!("Failed to create tokenizer for test")),
                    None,
                    "gemini-2.5-pro",
                ),
            ),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend,
            email_service,
            ai_client_factory,
            rate_limiter: Arc::new(crate::middleware::llm_security::LlmRateLimiter::new(
                10, 100,
            )), // Test rate limiter
            recall_pipeline: self.recall_pipeline.clone(),
            token_service: None, // Not available in this test context
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None, // Not used in tests
            #[cfg(feature = "local-llm")]
            security_audit_logger: None, // Not used in tests
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None, // Not used in tests
        };

        Arc::new(AppState::new(
            self.db_pool.clone(),
            self.config.clone(),
            services,
        ))
    }
}

// --- LLM Server Test Helpers ---

#[cfg(feature = "local-llm")]
pub mod llm_server {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;
    use tracing::{debug, error, info, warn};

    /// Configuration for the LLM test server
    #[derive(Debug, Clone)]
    pub struct LlmServerConfig {
        pub model_path: String,
        pub host: String,
        pub port: u16,
        pub context_size: u32,
        pub gpu_layers: u32,
        pub threads: u8,
        pub timeout_seconds: u32,
    }

    impl Default for LlmServerConfig {
        fn default() -> Self {
            Self {
                model_path: "/home/socol/Workspace/sanguine-scribe/models/gpt-oss-20b-Q4_K_M.gguf"
                    .to_string(),
                host: "127.0.0.1".to_string(),
                port: 11435,
                context_size: 131072, // 128K tokens
                gpu_layers: 999,      // Try to use all GPU layers
                threads: 8,
                timeout_seconds: 30,
            }
        }
    }

    /// RAII guard for automatic LLM server cleanup
    pub struct LlmServerTestGuard {
        process: Option<Child>,
        config: LlmServerConfig,
    }

    impl LlmServerTestGuard {
        /// Start a new LLM server instance for testing
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The llama-server executable cannot be found
        /// - The server fails to start
        /// - The server doesn't respond within the timeout period
        pub async fn start() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let config = LlmServerConfig::default();
            Self::start_with_config(config).await
        }

        /// Start LLM server with custom configuration
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The llama-server executable cannot be found
        /// - The server fails to start
        /// - The server doesn't respond within the timeout period
        pub async fn start_with_config(
            config: LlmServerConfig,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            // Check if model file exists
            if !std::path::Path::new(&config.model_path).exists() {
                return Err(format!("Model file not found: {}", config.model_path).into());
            }

            info!("Starting LLM server with model: {}", config.model_path);

            // First, try to stop any existing server on the port
            let _ = stop_server_on_port(config.port).await;

            // Start the llama-server process
            let mut command =
                Command::new("/home/socol/Workspace/llama.cpp/build/bin/llama-server");
            command
                .arg("--model")
                .arg(&config.model_path)
                .arg("--host")
                .arg(&config.host)
                .arg("--port")
                .arg(&config.port.to_string())
                .arg("--ctx-size")
                .arg(&config.context_size.to_string())
                .arg("--n-gpu-layers")
                .arg(&config.gpu_layers.to_string())
                .arg("--threads")
                .arg(&config.threads.to_string())
                .arg("--log-disable") // Disable verbose logging during tests
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            debug!("Starting llama-server with command: {:?}", command);

            let mut process = command.spawn()
                .map_err(|e| format!("Failed to spawn llama-server: {}. Make sure /home/socol/Workspace/llama.cpp/build/bin/llama-server exists and is executable", e))?;

            // Wait for the server to be ready
            let server_url = format!("http://{}:{}", config.host, config.port);
            let start_time = Instant::now();
            let timeout = Duration::from_secs(config.timeout_seconds as u64);

            info!("Waiting for LLM server to be ready at {}...", server_url);

            while start_time.elapsed() < timeout {
                // Check if process is still running
                match process.try_wait() {
                    Ok(Some(status)) => {
                        return Err(format!(
                            "LLM server process exited early with status: {}",
                            status
                        )
                        .into());
                    }
                    Ok(None) => {
                        // Process is still running, continue checking
                    }
                    Err(e) => {
                        return Err(format!("Failed to check process status: {}", e).into());
                    }
                }

                // Try to connect to the server
                if let Ok(response) = reqwest::get(&format!("{}/health", server_url)).await {
                    if response.status().is_success() {
                        info!("LLM server is ready at {}", server_url);
                        return Ok(Self {
                            process: Some(process),
                            config,
                        });
                    }
                }

                // Wait a bit before trying again
                sleep(Duration::from_millis(500)).await;
            }

            // Timeout reached, kill the process
            if let Err(e) = process.kill() {
                warn!("Failed to kill LLM server process after timeout: {}", e);
            }

            Err(format!(
                "LLM server failed to start within {} seconds",
                config.timeout_seconds
            )
            .into())
        }

        /// Get the server URL
        pub fn server_url(&self) -> String {
            format!("http://{}:{}", self.config.host, self.config.port)
        }

        /// Get the server configuration
        pub fn config(&self) -> &LlmServerConfig {
            &self.config
        }
    }

    impl Drop for LlmServerTestGuard {
        fn drop(&mut self) {
            if let Some(mut process) = self.process.take() {
                info!("Stopping LLM server...");

                // Try graceful shutdown first
                if let Err(e) = process.kill() {
                    warn!("Failed to terminate LLM server gracefully: {}", e);

                    // Force kill if graceful shutdown fails
                    if let Err(e) = process.kill() {
                        error!("Failed to kill LLM server process: {}", e);
                    }
                }

                // Wait for process to exit (with timeout)
                let start_time = Instant::now();
                let timeout = Duration::from_secs(5);

                while start_time.elapsed() < timeout {
                    match process.try_wait() {
                        Ok(Some(_)) => {
                            info!("LLM server stopped successfully");
                            return;
                        }
                        Ok(None) => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            warn!("Error checking process status during shutdown: {}", e);
                            break;
                        }
                    }
                }

                warn!("LLM server did not stop within timeout, may still be running");
            }
        }
    }

    /// Start a test LLM server with default configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start
    pub async fn start_test_llm_server(
    ) -> Result<LlmServerTestGuard, Box<dyn std::error::Error + Send + Sync>> {
        LlmServerTestGuard::start().await
    }

    /// Stop any LLM server running on the specified port
    ///
    /// # Errors
    ///
    /// Returns an error if the process lookup or termination fails
    pub async fn stop_server_on_port(
        port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try to find and kill any process using the port
        let output = Command::new("lsof")
            .arg("-ti")
            .arg(format!(":{}", port))
            .output();

        match output {
            Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    info!(
                        "Found process {} using port {}, attempting to terminate",
                        pid, port
                    );

                    // Try SIGTERM first
                    let kill_result = Command::new("kill").arg(pid.to_string()).output();

                    match kill_result {
                        Ok(output) if output.status.success() => {
                            info!("Successfully terminated process {} on port {}", pid, port);

                            // Give it a moment to shut down
                            sleep(Duration::from_millis(1000)).await;
                        }
                        _ => {
                            warn!(
                                "Failed to terminate process {} gracefully, trying SIGKILL",
                                pid
                            );

                            // Force kill
                            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).output();

                            sleep(Duration::from_millis(1000)).await;
                        }
                    }
                }
            }
            _ => {
                debug!("No process found using port {}", port);
            }
        }

        Ok(())
    }

    /// Check if LLM server is running on the specified port
    ///
    /// # Errors
    ///
    /// Returns an error if the health check fails
    pub async fn is_llm_server_running(
        host: &str,
        port: u16,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let health_url = format!("http://{}:{}/health", host, port);

        match reqwest::get(&health_url).await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Ensure LLM server is running, start it if needed
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be started
    pub async fn ensure_llm_server_running(
    ) -> Result<Option<LlmServerTestGuard>, Box<dyn std::error::Error + Send + Sync>> {
        let config = LlmServerConfig::default();

        if is_llm_server_running(&config.host, config.port).await? {
            info!(
                "LLM server is already running at {}:{}",
                config.host, config.port
            );
            Ok(None) // Server is already running, no guard needed
        } else {
            info!("LLM server is not running, starting it...");
            let guard = LlmServerTestGuard::start().await?;
            Ok(Some(guard))
        }
    }
}

#[cfg(not(feature = "local-llm"))]
pub mod llm_server {
    //! Placeholder module when local-llm feature is not enabled

    #[derive(Debug)]
    pub struct LlmServerTestGuard;

    impl LlmServerTestGuard {
        pub async fn start() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            Err("local-llm feature not enabled".into())
        }

        pub fn server_url(&self) -> String {
            "http://localhost:11435".to_string()
        }
    }

    pub async fn start_test_llm_server(
    ) -> Result<LlmServerTestGuard, Box<dyn std::error::Error + Send + Sync>> {
        LlmServerTestGuard::start().await
    }

    pub async fn stop_server_on_port(
        _port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn is_llm_server_running(
        _host: &str,
        _port: u16,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }

    pub async fn ensure_llm_server_running(
    ) -> Result<Option<LlmServerTestGuard>, Box<dyn std::error::Error + Send + Sync>> {
        Err("local-llm feature not enabled".into())
    }
}
