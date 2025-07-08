// backend/src/services/agentic_state_update_service.rs
//
// Agentic State Update Service
//
// This service analyzes assembled context from the agentic pipeline and updates
// the ECS world state to reflect the current narrative situation. It bridges
// the gap between context retrieval and context application, ensuring the world
// state stays synchronized with the narrative understanding.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use tracing::{info, debug, warn, instrument};
use chrono::{DateTime, Utc};

use crate::{
    PgPool,
    errors::AppError,
    llm::AiClient,
    services::{
        context_assembly_engine::{AssembledContext, QueryExecutionResult},
        ecs_entity_manager::{EcsEntityManager, ComponentUpdate, ComponentOperation},
        query_strategy_planner::QueryStrategy,
    },
    models::ecs::{
        SpatialComponent, PositionComponent, RelationshipsComponent, 
        TemporalComponent, GameTime, Relationship, RelationshipCategory,
    },
};

/// Configuration for state update behavior
#[derive(Debug, Clone)]
pub struct StateUpdateConfig {
    /// Whether to perform entity location updates
    pub update_spatial_state: bool,
    /// Whether to update relationship components
    pub update_relationships: bool,
    /// Whether to create activity timestamps
    pub update_temporal_state: bool,
    /// Maximum entities to update in a single operation
    pub max_entities_per_update: usize,
    /// Confidence threshold for applying updates
    pub confidence_threshold: f32,
}

impl Default for StateUpdateConfig {
    fn default() -> Self {
        Self {
            update_spatial_state: true,
            update_relationships: true,
            update_temporal_state: true,
            max_entities_per_update: 20,
            confidence_threshold: 0.7,
        }
    }
}

/// Results of state update analysis and operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateResult {
    /// Entities that were updated
    pub entities_updated: Vec<Uuid>,
    /// Spatial updates applied
    pub spatial_updates: Vec<SpatialUpdateSummary>,
    /// Relationship updates applied
    pub relationship_updates: Vec<RelationshipUpdateSummary>,
    /// Temporal updates applied
    pub temporal_updates: Vec<TemporalUpdateSummary>,
    /// Total processing time in milliseconds
    pub processing_time_ms: u64,
    /// Confidence in the updates applied
    pub confidence: f32,
    /// Whether AI inference was used
    pub used_ai_inference: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialUpdateSummary {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub location: String,
    pub position: Option<(f64, f64)>,
    pub contained_in: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipUpdateSummary {
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub created: bool, // true if new, false if updated
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalUpdateSummary {
    pub entity_id: Uuid,
    pub activity_type: String,
    pub timestamp: DateTime<Utc>,
}

/// Analysis of spatial context from assembled results
#[derive(Debug, Clone)]
struct SpatialAnalysis {
    /// Primary location mentioned in the context
    pub primary_location: Option<String>,
    /// Entities that should be in this location
    pub entities_in_location: Vec<(Uuid, String)>,
    /// Nested spatial relationships (e.g., characters in ship)
    pub spatial_containment: HashMap<String, Vec<String>>,
    /// Confidence in spatial analysis
    pub confidence: f32,
}

/// Analysis of relationship context from assembled results
#[derive(Debug, Clone)]
struct RelationshipAnalysis {
    /// Detected relationships between entities
    pub relationships: Vec<DetectedRelationship>,
    /// Confidence in relationship analysis
    pub confidence: f32,
}

#[derive(Debug, Clone)]
struct DetectedRelationship {
    pub from_entity: String,
    pub to_entity: String,
    pub relationship_type: String,
    pub strength: f32,
    pub evidence: String, // Why we think this relationship exists
}

/// Service for updating ECS state based on agentic context analysis
pub struct AgenticStateUpdateService {
    ai_client: Arc<dyn AiClient>,
    entity_manager: Arc<EcsEntityManager>,
    config: StateUpdateConfig,
}

impl AgenticStateUpdateService {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        entity_manager: Arc<EcsEntityManager>,
    ) -> Self {
        Self {
            ai_client,
            entity_manager,
            config: StateUpdateConfig::default(),
        }
    }

    pub fn with_config(
        ai_client: Arc<dyn AiClient>,
        entity_manager: Arc<EcsEntityManager>,
        config: StateUpdateConfig,
    ) -> Self {
        Self {
            ai_client,
            entity_manager,
            config,
        }
    }

    /// Main entry point: analyze context and update world state
    #[instrument(skip(self, assembled_context), fields(
        strategy = ?assembled_context.strategy_used,
        results_count = assembled_context.results.len(),
        user_id = %user_id
    ))]
    pub async fn update_world_state(
        &self,
        assembled_context: &AssembledContext,
        user_query: &str,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
    ) -> Result<StateUpdateResult, AppError> {
        let start_time = std::time::Instant::now();
        let mut result = StateUpdateResult {
            entities_updated: Vec::new(),
            spatial_updates: Vec::new(),
            relationship_updates: Vec::new(),
            temporal_updates: Vec::new(),
            processing_time_ms: 0,
            confidence: 0.0,
            used_ai_inference: false,
        };

        debug!("Starting world state update analysis");

        // Phase 1: Analyze context for spatial information
        let spatial_analysis = if self.config.update_spatial_state {
            self.analyze_spatial_context(assembled_context, user_query).await?
        } else {
            SpatialAnalysis {
                primary_location: None,
                entities_in_location: Vec::new(),
                spatial_containment: HashMap::new(),
                confidence: 0.0,
            }
        };

        // Phase 2: Analyze context for relationship information
        let relationship_analysis = if self.config.update_relationships {
            self.analyze_relationship_context(assembled_context, user_query).await?
        } else {
            RelationshipAnalysis {
                relationships: Vec::new(),
                confidence: 0.0,
            }
        };

        // Calculate overall confidence
        result.confidence = (spatial_analysis.confidence + relationship_analysis.confidence) / 2.0;

        // Only proceed with updates if confidence is above threshold
        if result.confidence < self.config.confidence_threshold {
            warn!("State update confidence {:.2} below threshold {:.2}, skipping updates", 
                  result.confidence, self.config.confidence_threshold);
            result.processing_time_ms = start_time.elapsed().as_millis() as u64;
            return Ok(result);
        }

        // Phase 3: Apply spatial updates
        if self.config.update_spatial_state && spatial_analysis.confidence > self.config.confidence_threshold {
            let spatial_updates = self.apply_spatial_updates(
                &spatial_analysis,
                user_id,
                chronicle_id,
            ).await?;
            
            result.spatial_updates = spatial_updates;
            for update in &result.spatial_updates {
                if !result.entities_updated.contains(&update.entity_id) {
                    result.entities_updated.push(update.entity_id);
                }
            }
        }

        // Phase 4: Apply relationship updates
        if self.config.update_relationships && relationship_analysis.confidence > self.config.confidence_threshold {
            let relationship_updates = self.apply_relationship_updates(
                &relationship_analysis,
                user_id,
                chronicle_id,
            ).await?;
            
            result.relationship_updates = relationship_updates;
            for update in &result.relationship_updates {
                if !result.entities_updated.contains(&update.from_entity_id) {
                    result.entities_updated.push(update.from_entity_id);
                }
                if !result.entities_updated.contains(&update.to_entity_id) {
                    result.entities_updated.push(update.to_entity_id);
                }
            }
        }

        // Phase 5: Apply temporal updates (activity timestamps)
        if self.config.update_temporal_state {
            let temporal_updates = self.apply_temporal_updates(
                &result.entities_updated,
                user_id,
                chronicle_id,
            ).await?;
            
            result.temporal_updates = temporal_updates;
        }

        result.processing_time_ms = start_time.elapsed().as_millis() as u64;
        result.used_ai_inference = spatial_analysis.confidence > 0.0 || relationship_analysis.confidence > 0.0;

        info!("World state update completed: {} entities updated, {:.2} confidence, {}ms", 
              result.entities_updated.len(), result.confidence, result.processing_time_ms);

        Ok(result)
    }

    /// Analyze assembled context for spatial information
    async fn analyze_spatial_context(
        &self,
        assembled_context: &AssembledContext,
        user_query: &str,
    ) -> Result<SpatialAnalysis, AppError> {
        let mut primary_location = None;
        let mut entities_in_location = Vec::new();
        let mut spatial_containment = HashMap::new();
        let mut confidence = 0.0;

        // Look for spatial information in query results
        for result in &assembled_context.results {
            match result {
                QueryExecutionResult::SpatialEntities(spatial_result) => {
                    primary_location = Some(spatial_result.location_name.clone());
                    confidence = 0.9; // High confidence from explicit spatial query
                    
                    for entity in &spatial_result.entities {
                        entities_in_location.push((entity.entity_id, entity.name.clone()));
                    }
                }
                QueryExecutionResult::EntityCurrentState(state_result) => {
                    // Look for location information in entity states
                    for entity_name in &state_result.entity_names {
                        // In a real implementation, we'd check the current_states for location info
                        // For now, we'll use a simple heuristic
                        confidence = std::cmp::max(confidence as u32, 60) as f32 / 100.0;
                    }
                }
                QueryExecutionResult::ActiveEntities(active_result) => {
                    // Active entities might indicate current location context
                    for entity in &active_result.entities {
                        if let Some(location) = &entity.current_location {
                            if primary_location.is_none() {
                                primary_location = Some(location.clone());
                            }
                            entities_in_location.push((entity.entity_id, entity.name.clone()));
                        }
                    }
                    confidence = std::cmp::max(confidence as u32, 50) as f32 / 100.0;
                }
                _ => {} // Other result types don't provide spatial context
            }
        }

        // Use AI inference if we have some spatial hints but need more analysis
        if confidence > 0.3 && confidence < 0.8 {
            match self.infer_spatial_context_with_ai(assembled_context, user_query).await {
                Ok((ai_location, ai_entities, ai_confidence)) => {
                    if ai_confidence > confidence {
                        primary_location = ai_location;
                        entities_in_location = ai_entities;
                        confidence = ai_confidence;
                    }
                }
                Err(e) => {
                    warn!("AI spatial inference failed: {}", e);
                }
            }
        }

        Ok(SpatialAnalysis {
            primary_location,
            entities_in_location,
            spatial_containment,
            confidence,
        })
    }

    /// Use AI to infer spatial context from assembled data
    async fn infer_spatial_context_with_ai(
        &self,
        assembled_context: &AssembledContext,
        user_query: &str,
    ) -> Result<(Option<String>, Vec<(Uuid, String)>, f32), AppError> {
        let context_summary = self.build_context_summary_for_ai(assembled_context);
        
        let prompt = format!(r#"Analyze this narrative context and determine the primary location where the action is taking place, and which entities are present there.

User Query: "{}"

Context Summary:
{}

Respond with a JSON object:
{{
    "primary_location": "location name or null",
    "entities_present": [
        {{"entity_id": "uuid", "entity_name": "name"}}
    ],
    "confidence": 0.0-1.0,
    "reasoning": "explanation of analysis"
}}

Focus on:
1. Explicit location mentions in the query or context
2. Entities that would logically be together
3. Spatial relationships (inside, on, at, etc.)
4. Current narrative focus

If the location is unclear or entities are not co-located, use confidence < 0.7."#, 
            user_query, context_summary);

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(500)
            .with_temperature(0.1); // Low temperature for consistent analysis

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17",
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_spatial_inference_response(&response_text)
    }

    /// Parse AI response for spatial inference
    fn parse_spatial_inference_response(
        &self,
        response: &str,
    ) -> Result<(Option<String>, Vec<(Uuid, String)>, f32), AppError> {
        let json_value: serde_json::Value = serde_json::from_str(response.trim())
            .map_err(|e| AppError::SerializationError(format!("Failed to parse spatial inference JSON: {}", e)))?;

        let primary_location = json_value["primary_location"]
            .as_str()
            .map(|s| s.to_string());

        let mut entities_present = Vec::new();
        if let Some(entities_array) = json_value["entities_present"].as_array() {
            for entity_obj in entities_array {
                if let (Some(id_str), Some(name)) = (
                    entity_obj["entity_id"].as_str(),
                    entity_obj["entity_name"].as_str(),
                ) {
                    if let Ok(entity_id) = Uuid::parse_str(id_str) {
                        entities_present.push((entity_id, name.to_string()));
                    }
                }
            }
        }

        let confidence = json_value["confidence"]
            .as_f64()
            .unwrap_or(0.5) as f32;

        Ok((primary_location, entities_present, confidence))
    }

    /// Analyze assembled context for relationship information using AI inference
    async fn analyze_relationship_context(
        &self,
        assembled_context: &AssembledContext,
        user_query: &str,
    ) -> Result<RelationshipAnalysis, AppError> {
        // First collect explicit relationship data
        let mut explicit_relationships = Vec::new();
        let mut has_explicit_data = false;

        for result in &assembled_context.results {
            match result {
                QueryExecutionResult::EntityRelationships(rel_result) => {
                    has_explicit_data = true;
                    for relationship in &rel_result.relationships {
                        explicit_relationships.push(DetectedRelationship {
                            from_entity: relationship.from_entity.clone(),
                            to_entity: relationship.to_entity.clone(),
                            relationship_type: relationship.relationship_type.clone(),
                            strength: relationship.strength,
                            evidence: "Explicit relationship query result".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        // If we have explicit relationship data with high confidence, use it
        if has_explicit_data {
            return Ok(RelationshipAnalysis {
                relationships: explicit_relationships,
                confidence: 0.9,
            });
        }

        // Otherwise, use AI to infer relationships from the assembled context
        self.infer_relationships_with_ai(assembled_context, user_query).await
    }

    /// Use AI to infer relationships from assembled context
    async fn infer_relationships_with_ai(
        &self,
        assembled_context: &AssembledContext,
        user_query: &str,
    ) -> Result<RelationshipAnalysis, AppError> {
        let context_summary = self.build_context_summary_for_ai(assembled_context);
        
        let prompt = format!(r#"Analyze this narrative context and determine what relationships exist between entities, and how those relationships might have changed based on recent events.

User Query: "{}"

Context Summary:
{}

Respond with a JSON object:
{{
    "relationships": [
        {{
            "from_entity": "entity name",
            "to_entity": "entity name", 
            "relationship_type": "family|friend|romantic|enemy|professional|neutral",
            "strength": 0.0-1.0,
            "evidence": "why you think this relationship exists",
            "changed": true/false,
            "change_reason": "why the relationship changed (if changed=true)"
        }}
    ],
    "confidence": 0.0-1.0,
    "reasoning": "explanation of analysis"
}}

Focus on:
1. Explicit mentions of relationships in the context
2. Interactions that suggest relationship dynamics
3. Emotional context and dialogue patterns
4. Recent events that might change relationships
5. Family, friendship, romantic, or adversarial indicators

Only include relationships you're confident about (>0.5 strength). Use confidence < 0.7 if the relationship context is unclear."#, 
            user_query, context_summary);

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(800)
            .with_temperature(0.1); // Low temperature for consistent analysis

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17",
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_relationship_inference_response(&response_text)
    }

    /// Parse AI response for relationship inference
    fn parse_relationship_inference_response(
        &self,
        response: &str,
    ) -> Result<RelationshipAnalysis, AppError> {
        let json_value: serde_json::Value = serde_json::from_str(response.trim())
            .map_err(|e| AppError::SerializationError(format!("Failed to parse relationship inference JSON: {}", e)))?;

        let mut relationships = Vec::new();
        if let Some(relationships_array) = json_value["relationships"].as_array() {
            for rel_obj in relationships_array {
                if let (Some(from_entity), Some(to_entity), Some(rel_type)) = (
                    rel_obj["from_entity"].as_str(),
                    rel_obj["to_entity"].as_str(),
                    rel_obj["relationship_type"].as_str(),
                ) {
                    let strength = rel_obj["strength"].as_f64().unwrap_or(0.5) as f32;
                    let evidence = rel_obj["evidence"].as_str().unwrap_or("AI inference").to_string();

                    relationships.push(DetectedRelationship {
                        from_entity: from_entity.to_string(),
                        to_entity: to_entity.to_string(),
                        relationship_type: rel_type.to_string(),
                        strength,
                        evidence,
                    });
                }
            }
        }

        let confidence = json_value["confidence"]
            .as_f64()
            .unwrap_or(0.5) as f32;

        Ok(RelationshipAnalysis {
            relationships,
            confidence,
        })
    }

    /// Apply spatial updates to the ECS system
    async fn apply_spatial_updates(
        &self,
        spatial_analysis: &SpatialAnalysis,
        user_id: Uuid,
        _chronicle_id: Option<Uuid>,
    ) -> Result<Vec<SpatialUpdateSummary>, AppError> {
        let mut updates = Vec::new();

        if let Some(location) = &spatial_analysis.primary_location {
            for (entity_id, entity_name) in &spatial_analysis.entities_in_location {
                // Create spatial component update
                let spatial_component = SpatialComponent {
                    spatial_type: crate::models::ecs::SpatialType::Containable {
                        size: crate::models::ecs::SpatialSize::Medium,
                        requires: Vec::new(),
                    },
                    constraints: crate::models::ecs::SpatialConstraints {
                        allow_multiple_locations: false,
                        movable: true,
                        rules: Vec::new(),
                    },
                    metadata: {
                        let mut metadata = HashMap::new();
                        metadata.insert("location".to_string(), serde_json::json!(location.clone()));
                        metadata.insert("updated_at".to_string(), serde_json::json!(chrono::Utc::now()));
                        metadata
                    },
                };

                let component_update = ComponentUpdate {
                    entity_id: *entity_id,
                    component_type: "Spatial".to_string(),
                    component_data: serde_json::to_value(&spatial_component)
                        .map_err(|e| AppError::SerializationError(e.to_string()))?,
                    operation: ComponentOperation::Update, // Update or create
                };

                match self.entity_manager.update_components(
                    user_id,
                    *entity_id,
                    vec![component_update],
                ).await {
                    Ok(_) => {
                        updates.push(SpatialUpdateSummary {
                            entity_id: *entity_id,
                            entity_name: entity_name.clone(),
                            location: location.clone(),
                            position: None, // Could be enhanced with position calculation
                            contained_in: None,
                        });
                        
                        debug!("Updated spatial component for entity {} in location {}", 
                               entity_name, location);
                    }
                    Err(e) => {
                        warn!("Failed to update spatial component for entity {}: {}", 
                              entity_name, e);
                    }
                }
            }
        }

        Ok(updates)
    }

    /// Apply relationship updates to the ECS system
    async fn apply_relationship_updates(
        &self,
        relationship_analysis: &RelationshipAnalysis,
        user_id: Uuid,
        _chronicle_id: Option<Uuid>,
    ) -> Result<Vec<RelationshipUpdateSummary>, AppError> {
        let mut updates = Vec::new();

        // Group relationships by source entity
        let mut entity_relationships: HashMap<String, Vec<&DetectedRelationship>> = HashMap::new();
        for rel in &relationship_analysis.relationships {
            entity_relationships
                .entry(rel.from_entity.clone())
                .or_insert_with(Vec::new)
                .push(rel);
        }

        for (entity_name, relationships) in entity_relationships {
            // In a real implementation, we'd look up entity_id by name
            // For now, we'll use a placeholder approach
            let entity_id = Uuid::new_v4(); // This should be looked up from the entity registry

            let mut relationship_components = Vec::new();
            for rel in relationships {
                let to_entity_id = Uuid::new_v4(); // This should also be looked up
                
                let relationship = Relationship {
                    target_entity_id: to_entity_id,
                    relationship_type: rel.relationship_type.clone(),
                    trust: if rel.relationship_type.to_lowercase().contains("enemy") { 0.1 } else { rel.strength },
                    affection: if rel.relationship_type.to_lowercase().contains("romantic") { rel.strength } else { 0.5 },
                    metadata: {
                        let mut metadata = HashMap::new();
                        metadata.insert("evidence".to_string(), serde_json::json!(rel.evidence));
                        metadata.insert("detected_at".to_string(), serde_json::json!(chrono::Utc::now()));
                        metadata.insert("category".to_string(), serde_json::json!(self.map_relationship_type(&rel.relationship_type).as_str()));
                        metadata
                    },
                };

                relationship_components.push(relationship);

                updates.push(RelationshipUpdateSummary {
                    from_entity_id: entity_id,
                    to_entity_id,
                    relationship_type: rel.relationship_type.clone(),
                    strength: rel.strength,
                    created: true, // In a real implementation, we'd check if it exists
                });
            }

            // Create relationships component
            let relationships_component = RelationshipsComponent {
                relationships: relationship_components,
            };

            let component_update = ComponentUpdate {
                entity_id,
                component_type: "Relationships".to_string(),
                component_data: serde_json::to_value(&relationships_component)
                    .map_err(|e| AppError::SerializationError(e.to_string()))?,
                operation: ComponentOperation::Update,
            };

            match self.entity_manager.update_components(
                user_id,
                entity_id,
                vec![component_update],
            ).await {
                Ok(_) => {
                    debug!("Updated relationships component for entity {}", entity_name);
                }
                Err(e) => {
                    warn!("Failed to update relationships component for entity {}: {}", 
                          entity_name, e);
                }
            }
        }

        Ok(updates)
    }

    /// Apply temporal updates (activity timestamps)
    async fn apply_temporal_updates(
        &self,
        entity_ids: &[Uuid],
        user_id: Uuid,
        _chronicle_id: Option<Uuid>,
    ) -> Result<Vec<TemporalUpdateSummary>, AppError> {
        let mut updates = Vec::new();
        let now = GameTime::now();

        for &entity_id in entity_ids {
            let temporal_component = TemporalComponent {
                created_at: now.clone(),
                destroyed_at: None,
                last_modified: now.clone(),
                time_scale: 1.0, // Normal time flow
            };

            let component_update = ComponentUpdate {
                entity_id,
                component_type: "Temporal".to_string(),
                component_data: serde_json::to_value(&temporal_component)
                    .map_err(|e| AppError::SerializationError(e.to_string()))?,
                operation: ComponentOperation::Update,
            };

            match self.entity_manager.update_components(
                user_id,
                entity_id,
                vec![component_update],
            ).await {
                Ok(_) => {
                    updates.push(TemporalUpdateSummary {
                        entity_id,
                        activity_type: "narrative_reference".to_string(),
                        timestamp: chrono::Utc::now(),
                    });
                    
                    debug!("Updated temporal component for entity {}", entity_id);
                }
                Err(e) => {
                    warn!("Failed to update temporal component for entity {}: {}", entity_id, e);
                }
            }
        }

        Ok(updates)
    }

    /// Map relationship type string to RelationshipCategory
    /// Uses AI-informed categories since the AI already provides structured relationship types
    fn map_relationship_type(&self, relationship_type: &str) -> RelationshipCategory {
        match relationship_type.to_lowercase().as_str() {
            "family" => RelationshipCategory::Social, // Family relationships are social
            "friend" => RelationshipCategory::Social,
            "romantic" => RelationshipCategory::Social, // Romantic relationships are social
            "enemy" => RelationshipCategory::Social, // Even enemies are social relationships
            "professional" => RelationshipCategory::Social, // Professional relationships are social
            "neutral" => RelationshipCategory::Social,
            "spatial" => RelationshipCategory::Spatial, // Location-based
            "causal" => RelationshipCategory::Causal, // Cause-effect
            "ownership" => RelationshipCategory::Ownership, // Possession
            "temporal" => RelationshipCategory::Temporal, // Time-based
            _ => RelationshipCategory::Social, // Default fallback for any other AI-generated types
        }
    }

    /// Build a summary of assembled context for AI analysis
    fn build_context_summary_for_ai(&self, assembled_context: &AssembledContext) -> String {
        let mut summary = String::new();
        
        summary.push_str(&format!("Strategy: {:?}\n", assembled_context.strategy_used));
        summary.push_str(&format!("Total Results: {}\n\n", assembled_context.results.len()));

        for (i, result) in assembled_context.results.iter().enumerate() {
            summary.push_str(&format!("Result {}: ", i + 1));
            
            match result {
                QueryExecutionResult::EntityCurrentState(r) => {
                    summary.push_str(&format!("EntityCurrentState for: {}\n", r.entity_names.join(", ")));
                }
                QueryExecutionResult::SpatialEntities(r) => {
                    summary.push_str(&format!("SpatialEntities at {}: {} entities\n", 
                                            r.location_name, r.entities.len()));
                }
                QueryExecutionResult::EntityRelationships(r) => {
                    summary.push_str(&format!("EntityRelationships for {}: {} relationships\n", 
                                            r.entity_names.join(", "), r.relationships.len()));
                }
                QueryExecutionResult::ActiveEntities(r) => {
                    summary.push_str(&format!("ActiveEntities: {} entities (threshold: {})\n", 
                                            r.entities.len(), r.activity_threshold));
                }
                QueryExecutionResult::NarrativeThreads(r) => {
                    summary.push_str(&format!("NarrativeThreads: {} threads of types {:?}\n", 
                                            r.threads.len(), r.thread_types));
                }
                _ => {
                    summary.push_str("Other query result\n");
                }
            }
        }

        summary
    }
}