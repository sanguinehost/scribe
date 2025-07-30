use std::sync::Arc;
use tracing::{info, instrument, debug, warn};
use uuid::Uuid;
use serde_json::json;

use crate::{
    errors::AppError,
    services::{
        ChronicleService,
        agentic::{
            tools::{ToolParams, ToolResult},
            unified_tool_registry::{UnifiedToolRegistry, AgentType as RegistryAgentType, ExecutionContext},
            shared_context::{SharedAgentContext, AgentType},
        },
    },
    auth::session_dek::SessionDek,
};

/// ChroniclerAgent - Dedicated agent for chronicle event creation
/// 
/// This agent is responsible for:
/// 1. Analyzing narrative content for significant events
/// 2. Creating structured chronicle events from unstructured narrative
/// 3. Maintaining temporal consistency in event sequences
/// 4. Ensuring proper event categorization and metadata
/// 
/// The ChroniclerAgent does NOT create entities - that's the responsibility
/// of other agents in the orchestration pipeline.
#[derive(Clone)]
pub struct ChroniclerAgent {
    chronicle_service: Arc<ChronicleService>,
    shared_context: Arc<SharedAgentContext>,
}

impl ChroniclerAgent {
    /// Create a new ChroniclerAgent instance
    pub fn new(
        chronicle_service: Arc<ChronicleService>,
        shared_context: Arc<SharedAgentContext>,
    ) -> Self {
        info!("ChroniclerAgent created with access to chronicle event tools");
        
        Self {
            chronicle_service,
            shared_context,
        }
    }
    
    /// Process narrative content to extract and create chronicle events
    #[instrument(
        name = "chronicler_agent_process_narrative",
        skip(self, session_dek),
        fields(
            user_id = %user_id,
            chronicle_id = %chronicle_id,
            content_length = narrative_content.len()
        )
    )]
    pub async fn process_narrative(
        &self,
        narrative_content: &str,
        chronicle_id: Uuid,
        user_id: Uuid,
        session_dek: &SessionDek,
        context: Option<serde_json::Value>,
    ) -> Result<ChronicleProcessingResult, AppError> {
        info!("ChroniclerAgent processing narrative for chronicle {}", chronicle_id);
        
        let start_time = std::time::Instant::now();
        let mut events_created = Vec::new();
        let mut total_tokens_used = 0u32;
        
        // Step 1: Analyze text significance
        let significance_result = self.analyze_narrative_significance(
            narrative_content,
            user_id,
            session_dek,
            context.clone(),
        ).await?;
        
        if !significance_result.is_significant {
            debug!("Narrative not significant enough for chronicle event creation");
            return Ok(ChronicleProcessingResult {
                events_created,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
                total_tokens_used,
                confidence_score: significance_result.confidence,
            });
        }
        
        // Step 2: Extract temporal events
        let temporal_events = self.extract_temporal_events(
            narrative_content,
            user_id,
            session_dek,
            context.clone(),
        ).await?;
        
        total_tokens_used += temporal_events.len() as u32 * 50; // Estimate
        
        // Step 3: Create chronicle events for each extracted temporal event
        for temporal_event in temporal_events {
            match self.create_chronicle_event_from_temporal(
                &temporal_event,
                chronicle_id,
                user_id,
                session_dek,
            ).await {
                Ok(event_id) => {
                    events_created.push(event_id);
                    info!("Created chronicle event {} for temporal event", event_id);
                }
                Err(e) => {
                    warn!("Failed to create chronicle event: {}", e);
                }
            }
        }
        
        // Step 4: Store processing metrics in shared context
        let processing_time_ms = start_time.elapsed().as_millis() as u64;
        if let Err(e) = self.store_processing_metrics(
            user_id,
            chronicle_id,
            events_created.len(),
            processing_time_ms,
            total_tokens_used,
            session_dek,
        ).await {
            warn!("Failed to store chronicler metrics: {}", e);
        }
        
        Ok(ChronicleProcessingResult {
            events_created,
            processing_time_ms,
            total_tokens_used,
            confidence_score: significance_result.confidence,
        })
    }
    
    /// Analyze narrative significance using the dedicated tool
    async fn analyze_narrative_significance(
        &self,
        narrative_content: &str,
        user_id: Uuid,
        session_dek: &SessionDek,
        context: Option<serde_json::Value>,
    ) -> Result<SignificanceAnalysis, AppError> {
        let params = json!({
            "user_id": user_id.to_string(),
            "text": narrative_content,
            "context": context,
        });
        
        let result = self.execute_tool("analyze_text_significance", &params, session_dek, user_id).await?;
        
        Ok(SignificanceAnalysis {
            is_significant: result.get("is_significant")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            confidence: result.get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0) as f32,
            reasoning: result.get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("No reasoning provided")
                .to_string(),
        })
    }
    
    /// Extract temporal events from narrative
    async fn extract_temporal_events(
        &self,
        narrative_content: &str,
        user_id: Uuid,
        session_dek: &SessionDek,
        context: Option<serde_json::Value>,
    ) -> Result<Vec<TemporalEvent>, AppError> {
        let params = json!({
            "user_id": user_id.to_string(),
            "text": narrative_content,
            "context": context,
            "max_events": 10,
        });
        
        let result = self.execute_tool("extract_temporal_events", &params, session_dek, user_id).await?;
        
        let events_value = result.get("events")
            .ok_or_else(|| AppError::InternalServerErrorGeneric("No events in extraction result".to_string()))?;
        
        let events_array = events_value.as_array()
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Events field is not an array".to_string()))?;
        
        let mut temporal_events = Vec::new();
        for event_value in events_array {
            if let (Some(event_type), Some(description)) = (
                event_value.get("event_type").and_then(|v| v.as_str()),
                event_value.get("description").and_then(|v| v.as_str())
            ) {
                temporal_events.push(TemporalEvent {
                    event_type: event_type.to_string(),
                    description: description.to_string(),
                    timestamp: event_value.get("timestamp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    metadata: event_value.get("metadata").cloned(),
                });
            }
        }
        
        Ok(temporal_events)
    }
    
    /// Create a chronicle event from a temporal event
    async fn create_chronicle_event_from_temporal(
        &self,
        temporal_event: &TemporalEvent,
        chronicle_id: Uuid,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<Uuid, AppError> {
        let params = json!({
            "user_id": user_id.to_string(),
            "chronicle_id": chronicle_id.to_string(),
            "event_type": temporal_event.event_type,
            "event_description": temporal_event.description,
            "event_metadata": temporal_event.metadata,
            "event_timestamp": temporal_event.timestamp,
        });
        
        let result = self.execute_tool("create_chronicle_event", &params, session_dek, user_id).await?;
        
        let event_id_str = result.get("event_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InternalServerErrorGeneric("No event_id in creation result".to_string()))?;
        
        Uuid::parse_str(event_id_str)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid event_id format: {}", e)))
    }
    
    /// Execute a tool through the unified registry
    async fn execute_tool(
        &self,
        tool_name: &str,
        params: &ToolParams,
        session_dek: &SessionDek,
        user_id: Uuid,
    ) -> Result<ToolResult, AppError> {
        let execution_context = ExecutionContext {
            request_id: Uuid::new_v4(),
            agent_capabilities: vec![
                "chronicle_write".to_string(),
                "narrative_analysis".to_string(),
            ],
            user_id,
            session_id: None,
            parent_tool: None,
        };
        
        UnifiedToolRegistry::execute_tool(
            RegistryAgentType::Chronicler,
            tool_name,
            params,
            session_dek,
            execution_context,
        ).await.map_err(|e| AppError::InternalServerErrorGeneric(format!("Tool execution failed: {}", e)))
    }
    
    /// Store processing metrics in shared context
    async fn store_processing_metrics(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        events_created_count: usize,
        processing_time_ms: u64,
        total_tokens_used: u32,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let metrics = json!({
            "chronicle_id": chronicle_id,
            "events_created": events_created_count,
            "processing_time_ms": processing_time_ms,
            "tokens_used": total_tokens_used,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        self.shared_context.store_performance_metrics(
            user_id,
            chronicle_id, // Using chronicle_id as session_id for tracking
            AgentType::Chronicler,
            metrics,
            session_dek,
        ).await
    }
}

/// Result of chronicle processing
#[derive(Debug, Clone)]
pub struct ChronicleProcessingResult {
    pub events_created: Vec<Uuid>,
    pub processing_time_ms: u64,
    pub total_tokens_used: u32,
    pub confidence_score: f32,
}

/// Significance analysis result
#[derive(Debug, Clone)]
struct SignificanceAnalysis {
    pub is_significant: bool,
    pub confidence: f32,
    pub reasoning: String,
}

/// Temporal event extracted from narrative
#[derive(Debug, Clone)]
struct TemporalEvent {
    pub event_type: String,
    pub description: String,
    pub timestamp: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

// Future enhancements:
// 1. Batch processing for multiple narrative segments
// 2. Event deduplication to prevent duplicate chronicles
// 3. Temporal ordering validation
// 4. Cross-chronicle consistency checks
// 5. Event categorization and tagging system