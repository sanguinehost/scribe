//! Narrative Intelligence Service - Main orchestrator for the agentic narrative layer
//! 
//! This service follows the "Everything as a Tool" principle and implements the 4-step
//! agentic workflow: Triage → Retrieve → Plan → Execute
//!
//! Design for scale: Currently handles 1:1 chat processing but architected to eventually
//! handle thousands/millions of events via batch processing and event queues.

use std::sync::Arc;
use tracing::{info, warn, error, instrument};
use uuid::Uuid;
use serde_json::Value;
use tokio::sync::Semaphore;
use backoff::{ExponentialBackoff, Error as BackoffError};

use crate::{
    auth::session_dek::SessionDek,
    errors::AppError,
    llm::{AiClient, EmbeddingClient},
    models::{chats::ChatMessage, users::{User, UserDbQuery}},
    schema::users::dsl as users_dsl,
    services::{
        agentic::{NarrativeAgentRunner, AgenticNarrativeFactory, UserPersonaContext},
        ChronicleService, LorebookService,
        embeddings::RetrievedChunk,
    },
    state::AppState,
    vector_db::qdrant_client::QdrantClientServiceTrait,
};

use diesel::{QueryDsl, RunQueryDsl, OptionalExtension, ExpressionMethods};

/// Result of narrative intelligence processing
#[derive(Debug, Clone)]
pub struct NarrativeProcessingResult {
    /// Whether the conversation was deemed significant for narrative processing
    pub is_significant: bool,
    /// Confidence score of the significance analysis (0.0 - 1.0)
    pub confidence: f64,
    /// Any narrative insights or context that should be injected into the prompt
    pub narrative_insights: Vec<String>,
    /// Additional RAG context items discovered through narrative analysis
    pub additional_context: Vec<RetrievedChunk>,
    /// Number of chronicle events created (if any)
    pub events_created: usize,
    /// Number of lorebook entries created (if any)
    pub entries_created: usize,
    /// Processing time for monitoring
    pub processing_time_ms: u64,
}

/// Data for chronicle events that need to be inserted in chronological order
#[derive(Debug, Clone)]
pub struct EventDataToInsert {
    /// Event type following Ars Fabula taxonomy
    pub event_type: String,
    /// Human-readable summary of the event
    pub summary: String,
    /// Structured event data including actors, causality, etc.
    pub event_data: Option<Value>,
}

/// Result from processing a batch without inserting events
#[derive(Debug, Clone)]
pub struct BatchEventData {
    /// Index of this batch in the overall sequence
    pub batch_index: usize,
    /// Events that should be created for this batch
    pub events: Vec<EventDataToInsert>,
    /// Whether this batch was deemed significant
    pub is_significant: bool,
    /// Confidence score
    pub confidence: f64,
    /// Processing time
    pub processing_time_ms: u64,
}

impl Default for NarrativeProcessingResult {
    fn default() -> Self {
        Self {
            is_significant: false,
            confidence: 0.0,
            narrative_insights: Vec::new(),
            additional_context: Vec::new(),
            events_created: 0,
            entries_created: 0,
            processing_time_ms: 0,
        }
    }
}

/// Configuration for narrative intelligence processing
#[derive(Debug, Clone)]
pub struct NarrativeProcessingConfig {
    /// Enable/disable narrative processing entirely
    pub enabled: bool,
    /// Minimum confidence threshold for processing (0.0 - 1.0)
    pub min_confidence_threshold: f64,
    /// Maximum number of recent messages to analyze
    pub max_messages_to_analyze: usize,
    /// Enable asynchronous processing (for future scale)
    pub async_processing: bool,
    /// Batch size for future event processing
    pub batch_size: usize,
}

impl Default for NarrativeProcessingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_threshold: 0.7,
            max_messages_to_analyze: 10,
            async_processing: false, // Start with synchronous for 1:1 chat
            batch_size: 100, // For future use
        }
    }
}

/// Main service for narrative intelligence processing
/// 
/// This service orchestrates the agentic workflow and integrates with the chat processing loop.
/// It's designed to be flexible and scalable for future high-volume event processing.
pub struct NarrativeIntelligenceService {
    /// The agentic narrative runner that executes the 4-step workflow
    narrative_runner: NarrativeAgentRunner,
    /// Configuration for processing behavior
    config: NarrativeProcessingConfig,
    /// App state for accessing services like UserPersonaService
    app_state: Arc<AppState>,
    /// Semaphore to limit concurrent AI API calls globally
    api_call_semaphore: Arc<Semaphore>,
}

impl NarrativeIntelligenceService {
    /// Create a new narrative intelligence service with individual dependencies (no circular dependency)
    pub fn new_with_deps(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        app_state: Arc<AppState>,
        config: Option<NarrativeProcessingConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        // Create the agentic system using the factory
        // For development setup, always use dev config regardless of enabled status
        let workflow_config = Some(AgenticNarrativeFactory::create_dev_config());
        
        let narrative_runner = AgenticNarrativeFactory::create_system_with_deps(
            ai_client,
            chronicle_service,
            lorebook_service,
            qdrant_service,
            embedding_client,
            app_state.clone(),
            workflow_config,
        );
        
        info!("Narrative Intelligence Service initialized with config: {:?}", config);
        
        Self {
            narrative_runner,
            config,
            app_state,
            api_call_semaphore: Arc::new(Semaphore::new(50)), // Limit to 50 concurrent AI calls globally
        }
    }

    /// Create a new narrative intelligence service
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
        config: Option<NarrativeProcessingConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        // Create the agentic system using the factory
        // Use appropriate config based on the intended use
        let workflow_config = if config.enabled {
            Some(AgenticNarrativeFactory::create_production_config())
        } else {
            Some(AgenticNarrativeFactory::create_dev_config())
        };
        
        let narrative_runner = AgenticNarrativeFactory::create_system(
            ai_client,
            chronicle_service,
            lorebook_service,
            app_state.clone(),
            workflow_config,
        );
        
        info!("Narrative Intelligence Service initialized with config: {:?}", config);
        
        Self {
            narrative_runner,
            config,
            app_state,
            api_call_semaphore: Arc::new(Semaphore::new(50)), // Limit to 50 concurrent AI calls globally
        }
    }

    /// Main entry point for narrative processing during chat generation
    /// 
    /// This is called from the chat processing loop and follows the flexible architecture:
    /// - Handles 1:1 chat processing now
    /// - Can be extended for batch processing later
    /// - Non-blocking and error-resilient
    #[instrument(skip(self, recent_messages, session_dek), fields(
        user_id = %user_id,
        session_id = %session_id,
        chronicle_id = ?chronicle_id,
        message_count = recent_messages.len()
    ))]
    pub async fn process_conversation_context(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Option<Uuid>,
        recent_messages: &[ChatMessage],
        existing_rag_context: &[RetrievedChunk],
        session_dek: &SessionDek,
    ) -> Result<NarrativeProcessingResult, AppError> {
        let start_time = std::time::Instant::now();
        
        // Early return if disabled
        if !self.config.enabled {
            return Ok(NarrativeProcessingResult::default());
        }
        
        // Limit the number of messages we analyze
        let messages_to_analyze = if recent_messages.len() > self.config.max_messages_to_analyze {
            &recent_messages[recent_messages.len() - self.config.max_messages_to_analyze..]
        } else {
            recent_messages
        };
        
        info!(
            "Processing narrative context for {} messages, {} existing RAG items",
            messages_to_analyze.len(),
            existing_rag_context.len()
        );
        
        // Retrieve user's persona context for narrative intelligence
        let persona_context = self.get_user_persona_context(user_id, session_dek).await.ok();
        
        // Execute the agentic workflow with exponential backoff
        match self.execute_with_backoff(|| async {
            // Acquire AI permit before making any AI calls
            let _ai_permit = self.api_call_semaphore.acquire().await
                .map_err(|_| AppError::ServiceUnavailable("Too many concurrent AI calls".to_string()))?;
            
            self.narrative_runner.process_narrative_event(
                user_id,
                session_id,
                chronicle_id,
                messages_to_analyze,
                session_dek,
                persona_context.clone(),
            ).await
        }).await {
            Ok(workflow_result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                
                let result = NarrativeProcessingResult {
                    is_significant: workflow_result.triage_result.is_significant,
                    confidence: workflow_result.triage_result.confidence as f64,
                    narrative_insights: self.extract_narrative_insights(&workflow_result.execution_results),
                    additional_context: Vec::new(), // Could extract from knowledge search results
                    events_created: self.count_successful_events(&workflow_result.execution_results),
                    entries_created: self.count_successful_entries(&workflow_result.execution_results),
                    processing_time_ms: processing_time,
                };
                
                info!(
                    "Narrative processing completed: significant={}, confidence={:.2}, events={}, entries={}, time={}ms",
                    result.is_significant,
                    result.confidence,
                    result.events_created,
                    result.entries_created,
                    result.processing_time_ms
                );
                
                Ok(result)
            },
            Err(e) => {
                error!("Narrative processing failed: {}", e);
                // Don't fail the chat generation, just log and return empty result
                warn!("Continuing chat generation without narrative processing");
                Ok(NarrativeProcessingResult::default())
            }
        }
    }
    
    /// Process a batch of chat messages for re-chronicling
    /// 
    /// This method processes historical chat messages to extract chronicle events.
    /// It's designed specifically for the re-chronicle feature.
    pub async fn process_chat_history_batch(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
    ) -> Result<NarrativeProcessingResult, AppError> {
        if messages.is_empty() {
            return Ok(NarrativeProcessingResult::default());
        }
        
        info!(
            "Processing chat history batch for user {}: {} messages",
            user_id,
            messages.len()
        );
        
        let start_time = std::time::Instant::now();
        
        // Retrieve user's persona context for narrative intelligence
        let persona_context = self.get_user_persona_context(user_id, session_dek).await.ok();
        
        // Execute the agentic workflow for this batch of messages with exponential backoff
        match self.execute_with_backoff(|| async {
            // Acquire AI permit before making any AI calls
            let _ai_permit = self.api_call_semaphore.acquire().await
                .map_err(|_| AppError::ServiceUnavailable("Too many concurrent AI calls".to_string()))?;
            
            self.narrative_runner.process_narrative_event(
                user_id,
                session_id,
                chronicle_id,
                &messages,
                session_dek,
                persona_context.clone(),
            ).await
        }).await {
            Ok(workflow_result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                
                let result = NarrativeProcessingResult {
                    is_significant: workflow_result.triage_result.is_significant,
                    confidence: workflow_result.triage_result.confidence as f64,
                    narrative_insights: self.extract_narrative_insights(&workflow_result.execution_results),
                    additional_context: Vec::new(),
                    events_created: self.count_successful_events(&workflow_result.execution_results),
                    entries_created: self.count_successful_entries(&workflow_result.execution_results),
                    processing_time_ms: processing_time,
                };
                
                info!(
                    "Chat history batch processing completed: significant={}, confidence={:.2}, events={}, entries={}, time={}ms",
                    result.is_significant,
                    result.confidence,
                    result.events_created,
                    result.entries_created,
                    result.processing_time_ms
                );
                
                Ok(result)
            },
            Err(e) => {
                error!("Chat history batch processing failed: {}", e);
                // Don't fail the re-chronicle operation entirely
                warn!("Continuing with next batch despite failure");
                Ok(NarrativeProcessingResult::default())
            }
        }
    }

    /// Process a batch of chat messages and return event data without inserting into database
    /// 
    /// This method is designed for ordered async processing where we need to collect
    /// event data from multiple batches and insert them in proper chronological order.
    pub async fn process_chat_history_batch_dry_run(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
        batch_index: usize,
    ) -> Result<BatchEventData, AppError> {
        if messages.is_empty() {
            return Ok(BatchEventData {
                batch_index,
                events: Vec::new(),
                is_significant: false,
                confidence: 0.0,
                processing_time_ms: 0,
            });
        }
        
        info!(
            "Processing chat history batch (dry-run) for user {}: {} messages, batch_index={}",
            user_id,
            messages.len(),
            batch_index
        );
        
        let start_time = std::time::Instant::now();
        
        // Retrieve user's persona context for narrative intelligence
        let persona_context = self.get_user_persona_context(user_id, session_dek).await.ok();
        
        // Execute the agentic workflow in dry-run mode with exponential backoff
        match self.execute_with_backoff(|| async {
            // Acquire AI permit before making any AI calls
            let _ai_permit = self.api_call_semaphore.acquire().await
                .map_err(|_| AppError::ServiceUnavailable("Too many concurrent AI calls".to_string()))?;
            
            self.narrative_runner.process_narrative_event_dry_run(
                user_id,
                session_id,
                chronicle_id,
                &messages,
                session_dek,
                persona_context.clone(),
            ).await
        }).await {
            Ok(workflow_result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                
                // Extract event data from workflow results without inserting
                let events = self.extract_event_data_from_workflow(&workflow_result.execution_results, user_id, chronicle_id, session_dek)?;
                
                let result = BatchEventData {
                    batch_index,
                    events,
                    is_significant: workflow_result.triage_result.is_significant,
                    confidence: workflow_result.triage_result.confidence as f64,
                    processing_time_ms: processing_time,
                };
                
                info!(
                    "Chat history batch dry-run completed: batch_index={}, significant={}, confidence={:.2}, events={}, time={}ms",
                    batch_index,
                    result.is_significant,
                    result.confidence,
                    result.events.len(),
                    result.processing_time_ms
                );
                
                Ok(result)
            },
            Err(e) => {
                error!("Chat history batch dry-run processing failed: {}", e);
                // Return empty batch data on failure
                Ok(BatchEventData {
                    batch_index,
                    events: Vec::new(),
                    is_significant: false,
                    confidence: 0.0,
                    processing_time_ms: start_time.elapsed().as_millis() as u64,
                })
            }
        }
    }

    /// Future method for batch processing (game events, etc.)
    /// 
    /// This demonstrates the scalable architecture - same tools, different orchestration
    #[allow(dead_code)]
    pub async fn process_event_batch(
        &self,
        _events: Vec<Value>, // Generic events from game/API
        _batch_config: Option<Value>,
    ) -> Result<Vec<NarrativeProcessingResult>, AppError> {
        // TODO: Implement for future game integration
        // This would:
        // 1. Batch events into chunks
        // 2. Process each chunk through the same 4-step workflow
        // 3. Use async processing queues
        // 4. Return aggregated results
        
        warn!("Batch processing not yet implemented - designed for future game integration");
        Ok(Vec::new())
    }
    
    /// Check if narrative processing should be enabled for this session
    /// 
    /// This allows for flexible configuration per user/session/chronicle
    #[allow(dead_code)]
    pub fn should_process_session(
        &self,
        _user_id: Uuid,
        _session_id: Uuid,
        _chronicle_id: Option<Uuid>,
    ) -> bool {
        // TODO: Add per-user/session configuration
        // For now, just use global config
        self.config.enabled
    }
    
    /// Extract narrative insights from tool execution results
    fn extract_narrative_insights(&self, execution_results: &[Value]) -> Vec<String> {
        let mut insights = Vec::new();
        
        for result in execution_results {
            if let Some(success) = result.get("success").and_then(|v| v.as_bool()) {
                if success {
                    if let Some(summary) = result.get("summary").and_then(|v| v.as_str()) {
                        insights.push(format!("Created: {}", summary));
                    }
                }
            }
        }
        
        insights
    }
    
    /// Count successful chronicle event creations
    fn count_successful_events(&self, execution_results: &[Value]) -> usize {
        execution_results
            .iter()
            .filter(|result| {
                result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) &&
                result.get("event_id").is_some()
            })
            .count()
    }
    
    /// Count successful lorebook entry creations
    fn count_successful_entries(&self, execution_results: &[Value]) -> usize {
        execution_results
            .iter()
            .filter(|result| {
                result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) &&
                result.get("entry_id").is_some()
            })
            .count()
    }

    /// Extract event data from workflow execution results without inserting into database
    fn extract_event_data_from_workflow(
        &self,
        execution_results: &[Value],
        _user_id: Uuid,
        _chronicle_id: Option<Uuid>,
        _session_dek: &SessionDek,
    ) -> Result<Vec<EventDataToInsert>, AppError> {
        let mut events = Vec::new();
        
        for result in execution_results {
            // Only process successful chronicle event creations
            if let Some(success) = result.get("success").and_then(|v| v.as_bool()) {
                if success && result.get("event_type").is_some() {
                    // Extract event data from the successful result
                    if let (Some(event_type), Some(summary)) = (
                        result.get("event_type").and_then(|v| v.as_str()),
                        result.get("summary").and_then(|v| v.as_str())
                    ) {
                        // Extract additional event data if present
                        let event_data = result.get("event_data").cloned();
                        
                        events.push(EventDataToInsert {
                            event_type: event_type.to_string(),
                            summary: summary.to_string(),
                            event_data,
                        });
                    }
                }
            }
        }
        
        Ok(events)
    }
}

/// Factory functions for creating narrative intelligence service
impl NarrativeIntelligenceService {
    /// Create service for development/testing with individual dependencies
    pub fn for_development_with_deps(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        app_state: Arc<AppState>,
    ) -> Self {
        let config = NarrativeProcessingConfig {
            enabled: true,
            min_confidence_threshold: 0.5, // Lower threshold for dev
            max_messages_to_analyze: 5,
            async_processing: false,
            batch_size: 10,
        };
        
        Self::new_with_deps(ai_client, chronicle_service, lorebook_service, qdrant_service, embedding_client, app_state, Some(config))
    }
    
    /// Create service for production with individual dependencies
    pub fn for_production_with_deps(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        app_state: Arc<AppState>,
    ) -> Self {
        let config = NarrativeProcessingConfig::default();
        Self::new_with_deps(ai_client, chronicle_service, lorebook_service, qdrant_service, embedding_client, app_state, Some(config))
    }

    /// Create service for development/testing
    pub fn for_development(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
    ) -> Self {
        let config = NarrativeProcessingConfig {
            enabled: true,
            min_confidence_threshold: 0.5, // Lower threshold for dev
            max_messages_to_analyze: 5,
            async_processing: false,
            batch_size: 10,
        };
        
        Self::new(ai_client, chronicle_service, lorebook_service, app_state, Some(config))
    }
    
    /// Create service for production
    pub fn for_production(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
    ) -> Self {
        let config = NarrativeProcessingConfig::default();
        Self::new(ai_client, chronicle_service, lorebook_service, app_state, Some(config))
    }

    /// Execute a function with exponential backoff retry logic
    /// 
    /// This wraps AI service calls to provide resiliency against transient failures.
    async fn execute_with_backoff<F, Fut, T>(&self, operation: F) -> Result<T, AppError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, AppError>>,
    {
        let backoff_config = ExponentialBackoff {
            max_elapsed_time: Some(std::time::Duration::from_secs(30)), // 30 second timeout
            max_interval: std::time::Duration::from_secs(5), // Max 5 seconds between retries
            ..ExponentialBackoff::default()
        };
        
        let result = backoff::future::retry(backoff_config, || async {
            match operation().await {
                Ok(value) => Ok(value),
                Err(e) => {
                    // Determine if this error is retryable
                    match &e {
                        AppError::ServiceUnavailable(_) | 
                        AppError::BadGateway(_) |
                        AppError::InternalServerErrorGeneric(_) => {
                            warn!("Retryable AI service error: {}", e);
                            Err(BackoffError::transient(e))
                        },
                        _ => {
                            // Non-retryable errors (authentication, validation, etc.)
                            error!("Non-retryable AI service error: {}", e);
                            Err(BackoffError::permanent(e))
                        }
                    }
                }
            }
        }).await;

        result
    }

    /// Retrieve the user's current persona context for narrative intelligence
    async fn get_user_persona_context(
        &self,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<UserPersonaContext, AppError> {
        // Get the user from the database to access their default_persona_id
        let pool = self.app_state.pool.clone();
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
            
        let user_db = conn
            .interact(move |db_conn| {
                users_dsl::users
                    .filter(users_dsl::id.eq(user_id))
                    .first::<UserDbQuery>(db_conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for get_user_persona_context: {e}"
                ))
            })??;
            
        let user = match user_db {
            Some(user_db) => User::from(user_db),
            None => return Err(AppError::NotFound(format!("User with ID {user_id} not found"))),
        };
        
        // If the user has a default persona, retrieve it
        if let Some(default_persona_id) = user.default_persona_id {
            let persona_data = self.app_state.user_persona_service
                .get_user_persona(&user, Some(&session_dek.0), default_persona_id)
                .await?;
            
            Ok(UserPersonaContext::from(persona_data))
        } else {
            // User has no default persona set
            Err(AppError::NotFound("User has no default persona set".to_string()))
        }
    }
}