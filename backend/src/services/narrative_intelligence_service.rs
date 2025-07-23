//! Narrative Intelligence Service V3 - Flash-Integrated Orchestrator
//!
//! This is the main orchestrator for the agentic narrative layer, implementing the 4-step
//! agentic workflow: Triage → Retrieve → Plan → Execute using Flash/Flash-Lite integration
//! 
//! Following Epic 1, Task 1.0.1 of the Living World Implementation Roadmap:
//! - Uses Flash/Flash-Lite abstraction for all AI calls
//! - Implements AI-driven narrative triage using intelligent analysis
//! - Follows the Prompt Orchestration Engine philosophy  
//! - Maintains security-first design with SessionDek integration
//! - Replaces hardcoded narrative triage prompts with Flash-Lite

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;
use secrecy::ExposeSecret;

use crate::{
    auth::session_dek::SessionDek,
    errors::AppError,
    models::chats::{ChatMessage, MessageRole},
    services::{
        agentic::{NarrativeAgentRunner, AgenticNarrativeFactory},
        embeddings::RetrievedChunk,
    },
    state::AppState,
};

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

/// Data for chronicle events that need to be inserted in chronological order
#[derive(Debug, Clone)]
pub struct EventDataToInsert {
    /// Event type following Ars Fabula taxonomy
    pub event_type: String,
    /// Human-readable summary of the event
    pub summary: String,
    /// Structured event data including actors, causality, etc.
    pub event_data: Option<Value>,
    /// Timestamp of the original chat message that led to this event
    pub timestamp: DateTime<Utc>,
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

/// Configuration for narrative intelligence processing
#[derive(Debug, Clone)]
pub struct NarrativeProcessingConfig {
    /// Enable/disable narrative processing entirely
    pub enabled: bool,
    /// Minimum confidence threshold for processing (0.0 - 1.0)
    pub min_confidence_threshold: f64,
    /// Maximum number of concurrent processing jobs
    pub max_concurrent_jobs: usize,
    /// Enable Flash cost optimizations
    pub enable_cost_optimizations: bool,
}

impl Default for NarrativeProcessingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_threshold: 0.6,
            max_concurrent_jobs: 3,
            enable_cost_optimizations: true,
        }
    }
}

/// Flash-integrated Narrative Intelligence Service
/// 
/// This service orchestrates the 4-step agentic workflow using Flash/Flash-Lite:
/// 1. Triage - Flash-Lite determines narrative significance
/// 2. Retrieve - Context assembly with Flash-enhanced queries  
/// 3. Plan - Flash generates action plans for world state updates
/// 4. Execute - Coordinated tool execution with Flash validation
pub struct NarrativeIntelligenceService {
    /// Core agent runner with Flash integration
    agent_runner: Arc<NarrativeAgentRunner>,
    /// Application state for service access
    app_state: Arc<AppState>,
    /// Processing configuration
    config: NarrativeProcessingConfig,
}

impl NarrativeIntelligenceService {
    /// Create a new service instance for production use
    pub fn new(
        app_state: Arc<AppState>,
        config: Option<NarrativeProcessingConfig>,
    ) -> Result<Self, AppError> {
        let config = config.unwrap_or_default();
        
        // Create workflow configuration from app config
        let workflow_config = AgenticNarrativeFactory::create_config_from_app_config(&app_state.config);

        // Create agent runner with complete agentic system
        let agent_runner = Arc::new(
            AgenticNarrativeFactory::create_system(
                app_state.ai_client.clone(),
                app_state.chronicle_service.clone(),
                app_state.lorebook_service.clone(),
                app_state.clone(),
                Some(workflow_config),
            )
        );

        info!(
            "Narrative Intelligence Service initialized with Flash integration, config: {:?}",
            config
        );

        Ok(Self {
            agent_runner,
            app_state,
            config,
        })
    }

    /// Create a development instance with individual dependencies (no circular dependency)
    pub fn for_development_with_deps(
        app_state: Arc<AppState>,
        config: Option<NarrativeProcessingConfig>,
    ) -> Result<Self, AppError> {
        let config = config.unwrap_or_default();
        
        // Create workflow configuration from app config for development
        let mut workflow_config = AgenticNarrativeFactory::create_config_from_app_config(&app_state.config);
        workflow_config.max_tool_executions = 15; // Higher limit for development
        workflow_config.enable_cost_optimizations = config.enable_cost_optimizations;

        // Create agent runner with individual dependencies to avoid circular dependency
        let agent_runner = Arc::new(
            AgenticNarrativeFactory::create_system_with_deps(
                app_state.ai_client.clone(),
                app_state.chronicle_service.clone(),
                app_state.lorebook_service.clone(),
                app_state.qdrant_service.clone(),
                app_state.embedding_client.clone(),
                app_state.clone(),
                Some(workflow_config),
            )
        );

        info!(
            "Narrative Intelligence Service initialized for development with Flash integration"
        );

        Ok(Self {
            agent_runner,
            app_state,
            config,
        })
    }

    /// Process a batch of chat messages using Flash-powered agentic workflow
    /// 
    /// This is the main entry point that orchestrates the 4-step process:
    /// 1. Flash-Lite triage for significance analysis
    /// 2. Context retrieval with Flash-enhanced queries
    /// 3. Flash planning for world state updates  
    /// 4. Tool execution with Flash validation
    #[instrument(skip(self, messages, session_dek))]
    pub async fn process_narrative_batch(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
    ) -> Result<NarrativeProcessingResult, AppError> {
        if !self.config.enabled {
            debug!("Narrative intelligence processing disabled");
            return Ok(NarrativeProcessingResult::default());
        }

        if messages.is_empty() {
            warn!("Empty message batch provided for narrative processing");
            return Ok(NarrativeProcessingResult::default());
        }

        let start_time = std::time::Instant::now();
        
        info!(
            "Starting Flash-powered narrative processing for user {} with {} messages",
            user_id,
            messages.len()
        );

        // Construct narrative content from messages
        // Decrypt and convert content to string
        let mut narrative_parts = Vec::new();
        for msg in &messages {
            // Decrypt content if needed
            let decrypted = if let Some(nonce) = &msg.content_nonce {
                let decrypted_box = crate::crypto::decrypt_gcm(&msg.content, nonce, &session_dek.0)
                    .map_err(|e| AppError::DecryptionError(format!("Failed to decrypt message: {}", e)))?;
                decrypted_box.expose_secret().clone()
            } else {
                msg.content.clone()
            };
            
            // Convert to string
            let content_str = String::from_utf8(decrypted)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in message: {}", e)))?;
            narrative_parts.push(content_str);
        }
        let narrative_content = narrative_parts.join("\n\n");

        // Step 1: Flash-Lite Triage - Determine narrative significance
        let triage_result = self.perform_flash_triage(
            user_id,
            chronicle_id,
            &narrative_content,
            session_dek,
        ).await?;

        if !triage_result.is_significant || triage_result.confidence < self.config.min_confidence_threshold {
            info!(
                "Content deemed not significant (confidence: {:.2}), skipping processing",
                triage_result.confidence
            );
            return Ok(NarrativeProcessingResult {
                is_significant: false,
                confidence: triage_result.confidence,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
                ..Default::default()
            });
        }

        // Step 2-4: Execute full agentic workflow using agent runner
        let narrative_messages: Vec<ChatMessage> = messages.clone();
        let agent_result = self.agent_runner.process_narrative_content(
            &narrative_messages,
            session_dek,
            user_id,
            Some(chronicle_id),
            None, // persona_context - will be enhanced later
            false, // is_re_chronicle
            &narrative_content,
        ).await?;

        let processing_time = start_time.elapsed().as_millis() as u64;
        
        // Parse agent runner response
        let events_created = agent_result
            .get("execution")
            .and_then(|exec| exec.get("events_created"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
            
        let entries_created = agent_result
            .get("execution")
            .and_then(|exec| exec.get("lorebook_entries_created"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let final_confidence = agent_result
            .get("triage")
            .and_then(|triage| triage.get("confidence"))
            .and_then(|v| v.as_f64())
            .unwrap_or(triage_result.confidence);

        info!(
            "Flash narrative processing completed in {}ms: {} events, {} entries",
            processing_time,
            events_created,
            entries_created
        );

        Ok(NarrativeProcessingResult {
            is_significant: true,
            confidence: final_confidence,
            narrative_insights: vec![], // TODO: Extract from agent_result
            additional_context: vec![], // TODO: Extract from agent_result  
            events_created,
            entries_created,
            processing_time_ms: processing_time,
        })
    }

    /// Step 1: Perform Flash-Lite powered triage analysis
    /// 
    /// This creates a minimal message set to test narrative significance
    async fn perform_flash_triage(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        content: &str,
        session_dek: &SessionDek,
    ) -> Result<TriageResult, AppError> {
        debug!("Performing Flash-Lite significance triage");

        // Create a minimal ChatMessage for triage analysis
        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(), // Temporary session for triage
            message_type: MessageRole::User,
            content: content.as_bytes().to_vec(),
            content_nonce: None,
            created_at: chrono::Utc::now(),
            user_id,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "triage".to_string(),
        };

        // Use the agent runner for triage with dry-run
        let result = self.agent_runner.process_narrative_event_dry_run_with_options(
            &[test_message],
            session_dek,
            user_id,
            Some(chronicle_id),
            false, // is_re_chronicle
            content,
        ).await?;

        // Extract triage information from the response
        let is_significant = result
            .get("triage")
            .and_then(|t| t.get("is_significant"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let confidence = result
            .get("triage")
            .and_then(|t| t.get("confidence"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let reasoning = result
            .get("triage")
            .and_then(|t| t.get("reasoning"))
            .and_then(|v| v.as_str())
            .unwrap_or("Flash-Lite analysis")
            .to_string();

        Ok(TriageResult {
            is_significant,
            confidence,
            reasoning,
        })
    }

    /// Process narrative content without inserting events (for batch analysis)
    #[instrument(skip(self, messages, session_dek))]
    pub async fn analyze_batch_without_insert(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
        batch_index: usize,
    ) -> Result<BatchEventData, AppError> {
        let start_time = std::time::Instant::now();
        
        if messages.is_empty() {
            return Ok(BatchEventData {
                batch_index,
                events: Vec::new(),
                is_significant: false,
                confidence: 0.0,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        // Decrypt and convert content to string
        let mut narrative_parts = Vec::new();
        for msg in &messages {
            // Decrypt content if needed
            let decrypted = if let Some(nonce) = &msg.content_nonce {
                let decrypted_box = crate::crypto::decrypt_gcm(&msg.content, nonce, &session_dek.0)
                    .map_err(|e| AppError::DecryptionError(format!("Failed to decrypt message: {}", e)))?;
                decrypted_box.expose_secret().clone()
            } else {
                msg.content.clone()
            };
            
            // Convert to string
            let content_str = String::from_utf8(decrypted)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in message: {}", e)))?;
            narrative_parts.push(content_str);
        }
        let narrative_content = narrative_parts.join("\n\n");

        // Perform Flash-Lite triage
        let triage_result = self.perform_flash_triage(
            user_id,
            chronicle_id,
            &narrative_content,
            session_dek,
        ).await?;

        let processing_time = start_time.elapsed().as_millis() as u64;

        if !triage_result.is_significant {
            return Ok(BatchEventData {
                batch_index,
                events: Vec::new(),
                is_significant: false,
                confidence: triage_result.confidence,
                processing_time_ms: processing_time,
            });
        }

        // Extract events data without inserting using Flash analysis
        let events_data = self.extract_events_data_with_flash(
            user_id,
            &narrative_content,
            session_dek,
        ).await?;

        Ok(BatchEventData {
            batch_index,
            events: events_data,
            is_significant: true,
            confidence: triage_result.confidence,
            processing_time_ms: processing_time,
        })
    }

    /// Extract event data using Flash analysis without database insertion
    #[allow(unused_variables)]
    async fn extract_events_data_with_flash(
        &self,
        user_id: Uuid,
        content: &str,
        session_dek: &SessionDek,  // TODO: Use for encrypting extracted event data
    ) -> Result<Vec<EventDataToInsert>, AppError> {
        debug!("Extracting event data using Flash analysis");

        // For now, return empty events - this will be enhanced when we implement
        // the full Flash-powered event extraction in the narrative tools
        // TODO: Implement full event extraction using the narrative tools
        warn!("Event extraction not yet fully implemented - returning empty events");
        Ok(vec![])
    }

    /// Process chat history batch with execution (for re-chronicle endpoint)
    /// This method processes batches for the chronicle endpoint and returns BatchEventData
    #[instrument(skip(self, messages, session_dek))]
    pub async fn process_chat_history_batch_with_execution(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
        batch_idx: usize,
        exclude_persona_context: bool,
        extraction_model: Option<String>,
    ) -> Result<BatchEventData, AppError> {
        // Use the chronicle_id or generate a temporary one
        let chronicle_id = chronicle_id.unwrap_or_else(Uuid::new_v4);
        
        // Delegate to analyze_batch_without_insert which returns BatchEventData
        self.analyze_batch_without_insert(
            user_id,
            chronicle_id,
            messages,
            session_dek,
            batch_idx,
        ).await
    }

    /// Process conversation context (for chat generation)
    /// This method processes ongoing conversations and returns narrative insights
    #[instrument(skip(self, messages, rag_context, session_dek))]
    pub async fn process_conversation_context(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Option<Uuid>,
        messages: &[ChatMessage],
        rag_context: &serde_json::Value, // Using generic JSON for RAG context
        session_dek: &SessionDek,
    ) -> Result<NarrativeProcessingResult, AppError> {
        let chronicle_id = chronicle_id.unwrap_or_else(Uuid::new_v4);
        
        // Convert to owned vec for processing
        let messages_vec: Vec<ChatMessage> = messages.to_vec();
        
        // Process the narrative batch
        self.process_narrative_batch(
            user_id,
            chronicle_id,
            messages_vec,
            session_dek,
        ).await
    }
}

/// Internal triage result structure
#[derive(Debug)]
struct TriageResult {
    is_significant: bool,
    confidence: f64,
    reasoning: String,
}