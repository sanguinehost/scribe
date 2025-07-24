// backend/src/services/agentic/tools/chronicle_tools.rs
//
// Chronicle integration tools for accessing historical narrative data
// Enables the Orchestrator to query past events and maintain continuity

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, warn, instrument};
use chrono::{DateTime, Utc};

use crate::{
    services::{
        ChronicleService,
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        agentic::unified_tool_registry::{
            SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
            ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
        },
    },
    models::{
        ChronicleEvent,
        chronicle_event::EventFilter,
    },
    errors::AppError,
    auth::session_dek::SessionDek,
    state::AppState,
};

/// Tool for querying chronicle events
#[derive(Clone)]
pub struct QueryChronicleEventsTool {
    chronicle_service: Arc<ChronicleService>,
    app_state: Arc<AppState>,
}

impl QueryChronicleEventsTool {
    pub fn new(chronicle_service: Arc<ChronicleService>, app_state: Arc<AppState>) -> Self {
        Self { chronicle_service, app_state }
    }
    
    /// Query events based on different criteria
    async fn query_events(
        &self,
        user_id: Uuid,
        query: &ChronicleQuery,
        session_dek: &SessionDek,
    ) -> Result<Vec<ChronicleEventInfo>, ToolError> {
        match query {
            ChronicleQuery::ByEntity { entity_id } => {
                let entity_uuid = Uuid::parse_str(entity_id)
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;
                
                // Get all user's chronicles first
                let chronicles = self.chronicle_service
                    .get_user_chronicles(user_id)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;
                
                let mut all_events = Vec::new();
                
                // Search through all chronicles for events mentioning this entity
                for chronicle in chronicles {
                    let events = self.chronicle_service
                        .get_chronicle_events(
                            user_id, 
                            chronicle.id,
                            EventFilter::default()
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    // Filter events that mention the entity in event_data
                    for event in events {
                        if let Some(event_data) = &event.event_data {
                            if let Some(entities) = event_data.get("entities").and_then(|v| v.as_array()) {
                                if entities.iter().any(|e| e.as_str() == Some(&entity_id)) {
                                    all_events.push(self.event_to_info(event, session_dek)?);
                                }
                            }
                        }
                    }
                }
                
                Ok(all_events)
            },
            
            ChronicleQuery::ByTimeRange { start, end } => {
                // Get all user's chronicles first
                let chronicles = self.chronicle_service
                    .get_user_chronicles(user_id)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;
                
                let mut all_events = Vec::new();
                
                // Get events from all chronicles and filter by time
                for chronicle in chronicles {
                    let events = self.chronicle_service
                        .get_chronicle_events(
                            user_id, 
                            chronicle.id,
                            EventFilter::default()
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    for event in events {
                        let in_range = match (start, end) {
                            (Some(s), Some(e)) => event.timestamp_iso8601 >= *s && event.timestamp_iso8601 <= *e,
                            (Some(s), None) => event.timestamp_iso8601 >= *s,
                            (None, Some(e)) => event.timestamp_iso8601 <= *e,
                            (None, None) => true,
                        };
                        
                        if in_range {
                            all_events.push(self.event_to_info(event, session_dek)?);
                        }
                    }
                }
                
                // Sort by timestamp descending
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(100);
                
                Ok(all_events)
            },
            
            ChronicleQuery::ByEventType { event_type } => {
                // Event type is just a string in the ChronicleEvent model
                
                // Get all user's chronicles
                let chronicles = self.chronicle_service
                    .get_user_chronicles(user_id)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;
                
                let mut all_events = Vec::new();
                
                // Filter events by type
                for chronicle in chronicles {
                    let events = self.chronicle_service
                        .get_chronicle_events(
                            user_id, 
                            chronicle.id,
                            EventFilter {
                                event_type: Some(event_type.clone()),
                                ..Default::default()
                            }
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    for event in events {
                        all_events.push(self.event_to_info(event, session_dek)?);
                    }
                }
                
                // Sort by timestamp descending and limit
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(100);
                
                Ok(all_events)
            },
            
            ChronicleQuery::ByLocation { location_id } => {
                let location_uuid = Uuid::parse_str(location_id)
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid location_id: {}", e)))?;
                
                // Get all user's chronicles
                let chronicles = self.chronicle_service
                    .get_user_chronicles(user_id)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;
                
                let mut all_events = Vec::new();
                
                // Search through all chronicles for events at this location
                for chronicle in chronicles {
                    let events = self.chronicle_service
                        .get_chronicle_events(
                            user_id, 
                            chronicle.id,
                            EventFilter::default()
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    // Filter events that mention the location in metadata
                    for event in events {
                        if event.event_data.as_ref().and_then(|data| data.get("location")).and_then(|v| v.as_str()) == Some(&location_id) {
                            all_events.push(self.event_to_info(event, session_dek)?);
                        }
                    }
                }
                
                // Sort by timestamp descending and limit
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(100);
                
                Ok(all_events)
            },
            
            ChronicleQuery::RecentEvents { limit } => {
                // Get all user's chronicles
                let chronicles = self.chronicle_service
                    .get_user_chronicles(user_id)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;
                
                let mut all_events = Vec::new();
                
                // Get events from all chronicles
                for chronicle in chronicles {
                    let events = self.chronicle_service
                        .get_chronicle_events(
                            user_id, 
                            chronicle.id,
                            EventFilter::default()
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    for event in events {
                        all_events.push(self.event_to_info(event, session_dek)?);
                    }
                }
                
                // Sort by timestamp descending and take limit
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(*limit);
                
                Ok(all_events)
            },
        }
    }
    
    /// Convert ChronicleEvent to simplified info structure with decryption
    fn event_to_info(&self, event: ChronicleEvent, session_dek: &SessionDek) -> Result<ChronicleEventInfo, ToolError> {
        let metadata = event.event_data.clone().unwrap_or_default();
        
        // Decrypt the summary if encrypted, fallback to plain summary
        let decrypted_summary = if let (Some(encrypted_summary), Some(nonce)) = 
            (&event.summary_encrypted, &event.summary_nonce) {
            
            // Decrypt the summary using session_dek
            match self.app_state.encryption_service.decrypt(encrypted_summary, nonce, session_dek.expose_bytes()) {
                Ok(decrypted_bytes) => {
                    String::from_utf8_lossy(&decrypted_bytes).to_string()
                },
                Err(e) => {
                    warn!("Failed to decrypt chronicle event summary for event {}: {}", event.id, e);
                    // Fallback to plain summary if decryption fails
                    event.summary.clone()
                }
            }
        } else {
            // Use plain summary if no encrypted version exists
            event.summary.clone()
        };
        
        Ok(ChronicleEventInfo {
            id: event.id,
            title: decrypted_summary.clone(),
            content: decrypted_summary,
            event_type: event.event_type,
            timestamp: event.timestamp_iso8601,
            participants: metadata.get("participants")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect())
                .unwrap_or_default(),
            location: metadata.get("location")
                .and_then(|v| v.as_str())
                .map(String::from),
            metadata,
        })
    }
}

/// Input parameters for chronicle queries
#[derive(Debug, Deserialize)]
pub struct QueryChronicleInput {
    /// User ID performing the query
    pub user_id: String,
    /// The query to execute
    pub query: ChronicleQuery,
}

/// Types of chronicle queries
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ChronicleQuery {
    /// Get events for a specific entity
    ByEntity { entity_id: String },
    /// Get events in a time range
    ByTimeRange { 
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    },
    /// Get events by type
    ByEventType { event_type: String },
    /// Get events at a location
    ByLocation { location_id: String },
    /// Get most recent events
    RecentEvents { limit: usize },
}

/// Chronicle event information
#[derive(Debug, Serialize)]
pub struct ChronicleEventInfo {
    pub id: Uuid,
    pub title: String,
    pub content: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub participants: Vec<String>,
    pub location: Option<String>,
    pub metadata: JsonValue,
}

/// Output from chronicle query
#[derive(Debug, Serialize)]
pub struct QueryChronicleOutput {
    pub events: Vec<ChronicleEventInfo>,
    pub total_found: usize,
    pub query_type: String,
}

#[async_trait]
impl ScribeTool for QueryChronicleEventsTool {
    fn name(&self) -> &'static str {
        "query_chronicle_events"
    }
    
    fn description(&self) -> &'static str {
        "Query historical chronicle events by entity, time range, event type, or location. \
         Provides access to the narrative history and past events."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the query"
                },
                "query": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByEntity" },
                                "entity_id": { 
                                    "type": "string", 
                                    "description": "Entity UUID to get events for" 
                                }
                            },
                            "required": ["type", "entity_id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByTimeRange" },
                                "start": { 
                                    "type": "string",
                                    "format": "date-time",
                                    "description": "Start time (ISO 8601)" 
                                },
                                "end": { 
                                    "type": "string",
                                    "format": "date-time",
                                    "description": "End time (ISO 8601)" 
                                }
                            },
                            "required": ["type"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByEventType" },
                                "event_type": { 
                                    "type": "string",
                                    "enum": ["character_event", "world_event", "narrative_event"],
                                    "description": "Type of events to query" 
                                }
                            },
                            "required": ["type", "event_type"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByLocation" },
                                "location_id": { 
                                    "type": "string", 
                                    "description": "Location entity UUID" 
                                }
                            },
                            "required": ["type", "location_id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "RecentEvents" },
                                "limit": { 
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 100,
                                    "default": 10,
                                    "description": "Number of recent events to retrieve" 
                                }
                            },
                            "required": ["type", "limit"]
                        }
                    ]
                }
            },
            "required": ["user_id", "query"]
        })
    }
    
    #[instrument(skip(self, params, session_dek), fields(tool = "query_chronicle_events"))]
    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: QueryChronicleInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("Querying chronicle for user {} with query: {:?}", user_id, input.query);
        
        let query_type = match &input.query {
            ChronicleQuery::ByEntity { .. } => "ByEntity",
            ChronicleQuery::ByTimeRange { .. } => "ByTimeRange",
            ChronicleQuery::ByEventType { .. } => "ByEventType",
            ChronicleQuery::ByLocation { .. } => "ByLocation",
            ChronicleQuery::RecentEvents { .. } => "RecentEvents",
        };
        
        let events = self.query_events(user_id, &input.query, session_dek).await?;
        let total_found = events.len();
        
        let output = QueryChronicleOutput {
            events,
            total_found,
            query_type: query_type.to_string(),
        };
        
        Ok(serde_json::to_value(output)?)
    }
}

#[async_trait]
impl SelfRegisteringTool for QueryChronicleEventsTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "query".to_string(),
                target: "chronicle events".to_string(),
                context: Some("historical data".to_string()),
            },
            ToolCapability {
                action: "retrieve".to_string(),
                target: "narrative history".to_string(),
                context: Some("temporal context".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to retrieve historical chronicle events for context, continuity, \
         or understanding past narrative developments. Supports queries by entity, time range, \
         event type, location, or recent events.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for creating new events (use narrative generation tools instead), \
         modifying existing events, or for real-time event streaming.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Get character's recent history".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": {
                        "type": "ByEntity",
                        "entity_id": "456e7890-e12b-34c5-a789-012345678901"
                    }
                }),
                expected_output: "List of chronicle events involving the specified character".to_string(),
            },
            ToolExample {
                scenario: "Find events in a time period".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": {
                        "type": "ByTimeRange",
                        "start": "2024-01-01T00:00:00Z",
                        "end": "2024-01-31T23:59:59Z"
                    }
                }),
                expected_output: "All chronicle events within the specified date range".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
                AgentType::Perception,
            ],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only access to chronicles
                allowed_scopes: vec!["chronicle".to_string(), "history".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 40,
            execution_time: ExecutionTime::Fast, // Direct DB queries
            external_calls: false,
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec!["chronicle_service".to_string()]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "chronicle".to_string(),
            "history".to_string(),
            "query".to_string(),
            "narrative".to_string(),
            "temporal".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "event_id": {"type": "string"},
                            "chronicle_id": {"type": "string"},
                            "event_type": {"type": "string"},
                            "content": {"type": "string"},
                            "metadata": {"type": "object"},
                            "participants": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "location_id": {"type": ["string", "null"]},
                            "timestamp": {"type": "string", "format": "date-time"},
                            "significance": {"type": ["string", "null"]},
                            "visibility": {"type": "string"}
                        },
                        "required": ["event_id", "chronicle_id", "event_type", "content", "timestamp"]
                    },
                    "description": "List of chronicle events matching the query"
                },
                "total_found": {
                    "type": "integer",
                    "description": "Total number of events found"
                },
                "query_type": {
                    "type": "string",
                    "description": "Type of query that was executed"
                }
            },
            "required": ["events", "total_found", "query_type"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "CHRONICLE_NOT_FOUND".to_string(),
                description: "No chronicle found for the specified user".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "INVALID_QUERY".to_string(),
                description: "The query parameters are invalid or malformed".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "QUERY_FAILED".to_string(),
                description: "Failed to execute the chronicle query".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// Register chronicle tools with the unified registry
pub fn register_chronicle_tools(chronicle_service: Arc<ChronicleService>, app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let query_tool = Arc::new(QueryChronicleEventsTool::new(chronicle_service, app_state)) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(query_tool)?;
    
    tracing::info!("Registered 1 chronicle tool with unified registry");
    Ok(())
}

