// backend/src/services/agentic/tools/chronicle_tools.rs
//
// Chronicle integration tools for accessing historical narrative data
// Enables the Orchestrator to query past events and maintain continuity

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument};
use chrono::{DateTime, Utc};

use crate::{
    services::{
        ChronicleService,
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    },
    models::{
        ChronicleEvent,
        chronicle::EventType,
        chronicle_event::EventFilter,
    },
    errors::AppError,
};

/// Tool for querying chronicle events
#[derive(Clone)]
pub struct QueryChronicleEventsTool {
    chronicle_service: Arc<ChronicleService>,
}

impl QueryChronicleEventsTool {
    pub fn new(chronicle_service: Arc<ChronicleService>) -> Self {
        Self { chronicle_service }
    }
    
    /// Query events based on different criteria
    async fn query_events(
        &self,
        user_id: Uuid,
        query: &ChronicleQuery,
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
                    
                    // Filter events that mention the entity in metadata
                    for event in events {
                        if let Some(entities) = event.metadata.get("entities").and_then(|v| v.as_array()) {
                            if entities.iter().any(|e| e.as_str() == Some(&entity_id)) {
                                all_events.push(Self::event_to_info(event));
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
                            (Some(s), Some(e)) => event.timestamp >= *s && event.timestamp <= *e,
                            (Some(s), None) => event.timestamp >= *s,
                            (None, Some(e)) => event.timestamp <= *e,
                            (None, None) => true,
                        };
                        
                        if in_range {
                            all_events.push(Self::event_to_info(event));
                        }
                    }
                }
                
                // Sort by timestamp descending
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(100);
                
                Ok(all_events)
            },
            
            ChronicleQuery::ByEventType { event_type } => {
                // Parse event type
                let evt_type = match event_type.as_str() {
                    "character_event" => EventType::CharacterEvent,
                    "world_event" => EventType::WorldEvent,
                    "narrative_event" => EventType::NarrativeEvent,
                    _ => return Err(ToolError::InvalidParams(format!("Invalid event type: {}", event_type))),
                };
                
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
                                event_type: Some(evt_type.clone()),
                                ..Default::default()
                            }
                        )
                        .await
                        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;
                    
                    all_events.extend(events.into_iter().map(Self::event_to_info));
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
                        if event.metadata.get("location").and_then(|v| v.as_str()) == Some(&location_id) {
                            all_events.push(Self::event_to_info(event));
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
                    
                    all_events.extend(events.into_iter().map(Self::event_to_info));
                }
                
                // Sort by timestamp descending and take limit
                all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                all_events.truncate(*limit);
                
                Ok(all_events)
            },
        }
    }
    
    /// Convert ChronicleEvent to simplified info structure
    fn event_to_info(event: ChronicleEvent) -> ChronicleEventInfo {
        ChronicleEventInfo {
            id: event.id,
            title: event.title,
            content: event.content,
            event_type: format!("{:?}", event.event_type),
            timestamp: event.timestamp,
            participants: event.metadata.get("participants")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect())
                .unwrap_or_default(),
            location: event.metadata.get("location")
                .and_then(|v| v.as_str())
                .map(String::from),
            metadata: event.metadata,
        }
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
    
    #[instrument(skip(self, params), fields(tool = "query_chronicle_events"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
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
        
        let events = self.query_events(user_id, &input.query).await?;
        let total_found = events.len();
        
        let output = QueryChronicleOutput {
            events,
            total_found,
            query_type: query_type.to_string(),
        };
        
        Ok(ToolResult::Success(serde_json::to_value(output)?))
    }
}

