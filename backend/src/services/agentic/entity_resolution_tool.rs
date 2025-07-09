//! Enhanced Entity Resolution Tool
//!
//! This tool provides sophisticated entity identity resolution with:
//! - Deep contextual understanding from narrative
//! - Semantic similarity matching via vector embeddings
//! - Persistent identity across mentions
//! - Rich component extraction from narrative context
//! - Multi-stage validation and reconciliation

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    services::ecs_entity_manager::{ComponentUpdate, ComponentOperation, EntityQueryResult},
    state::AppState,
};

use super::tools::{ScribeTool, ToolError, ToolParams, ToolResult};

/// Rich context extracted from narrative text
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NarrativeContext {
    pub entities: Vec<NarrativeEntity>,
    pub spatial_context: SpatialContext,
    pub temporal_context: TemporalContext,
    pub social_context: SocialContext,
    pub actions_and_events: Vec<NarrativeAction>,
}

/// Entity with rich context information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NarrativeEntity {
    pub name: String,
    pub entity_type: String,
    pub description: String,
    pub properties: Vec<String>,
}

/// Spatial context information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpatialContext {
    pub primary_location: Option<String>,
    pub secondary_locations: Vec<String>,
    pub spatial_relationships: Vec<SpatialRelationship>,
}

/// Relationship between entities in space
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpatialRelationship {
    pub entity1: String,
    pub relationship: String,
    pub entity2: String,
}

/// Temporal context information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemporalContext {
    pub time_indicators: Vec<String>,
    pub sequence_markers: Vec<String>,
    pub duration_hints: Vec<String>,
}

/// Social context information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SocialContext {
    pub relationships: Vec<SocialRelationship>,
    pub social_dynamics: Vec<String>,
    pub emotional_tone: String,
}

/// Relationship between entities socially
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SocialRelationship {
    pub entity1: String,
    pub relationship: String,
    pub entity2: String,
}

/// Action or event in the narrative
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NarrativeAction {
    pub action: String,
    pub agent: Option<String>,
    pub target: Option<String>,
    pub context: Option<String>,
}

/// Data structures for multi-stage processing (Task 2.3)

/// Represents an existing entity in the database
#[derive(Debug, Clone)]
pub struct ExistingEntity {
    pub entity_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub entity_type: String,
    pub context: Option<String>,
}

/// Result of Stage 1: Extraction
#[derive(Debug, Clone)]
pub struct ExtractionStageResult {
    pub narrative_context: NarrativeContext,
    pub extracted_entity_names: Vec<String>,
    pub original_text: String,
}

/// A resolved entity (can be existing or new)
#[derive(Debug, Clone)]
pub struct ResolvedEntity {
    pub entity_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub entity_type: String,
    pub is_new: bool,
    pub confidence: f32,
    pub context: Option<String>,
    pub properties: Vec<String>,
}

/// Result of Stage 2: Resolution
#[derive(Debug, Clone)]
pub struct ResolutionStageResult {
    pub resolved_entities: Vec<ResolvedEntity>,
    pub new_entities: Vec<ResolvedEntity>,
}

/// A structured entity with component suggestions
#[derive(Debug, Clone)]
pub struct StructuredEntity {
    pub entity_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub entity_type: String,
    pub is_new: bool,
    pub confidence: f32,
    pub context: Option<String>,
    pub properties: Vec<String>,
    pub suggested_components: Vec<String>,
}

/// Relationship between entities
#[derive(Debug, Clone)]
pub struct EntityRelationship {
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub context: String,
}

/// Result of Stage 3: Structure
#[derive(Debug, Clone)]
pub struct StructureStageResult {
    pub structured_entities: Vec<StructuredEntity>,
    pub relationships: Vec<EntityRelationship>,
}

/// Final resolved entity with full context
#[derive(Debug, Clone)]
pub struct FinalResolvedEntity {
    pub entity_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub entity_type: String,
    pub is_new: bool,
    pub confidence: f32,
    pub context: Option<String>,
    pub properties: Vec<String>,
    pub components: Vec<String>,
}

/// Processing metadata for the multi-stage result
#[derive(Debug, Clone)]
pub struct ProcessingMetadata {
    pub total_entities_processed: usize,
    pub new_entities_created: usize,
    pub relationships_identified: usize,
    pub confidence_average: f32,
}

/// Final result of the multi-stage processing
#[derive(Debug, Clone)]
pub struct MultiStageResolutionResult {
    pub resolved_entities: Vec<FinalResolvedEntity>,
    pub relationships: Vec<EntityRelationship>,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>,
    pub processing_metadata: ProcessingMetadata,
}

/// Result of actor resolution, including rich context
#[derive(Debug, Clone)]
pub struct ActorResolutionResult {
    pub resolved_actors: Value,
    pub narrative_context: NarrativeContext,
}

/// Enhanced entity resolution tool with multi-stage processing
pub struct EntityResolutionTool {
    app_state: Arc<AppState>,
}

impl EntityResolutionTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Performance monitoring helper
    fn start_timer(operation: &str) -> std::time::Instant {
        let start = std::time::Instant::now();
        debug!("PERF: Starting {}", operation);
        start
    }
    
    /// Performance monitoring helper
    fn end_timer(start: std::time::Instant, operation: &str) {
        let elapsed = start.elapsed();
        if elapsed.as_secs_f32() > 0.5 {
            warn!("PERF: {} took {:.2}s (exceeds 500ms threshold)", operation, elapsed.as_secs_f32());
        } else {
            debug!("PERF: {} completed in {:.2}ms", operation, elapsed.as_millis());
        }
    }

    /// Extract entity names from narrative text (Task 1.2)
    /// OPTIMIZED: Reduced prompt size and added performance monitoring
    pub async fn extract_entity_names(
        &self,
        narrative_text: &str,
    ) -> Result<Vec<String>, ToolError> {
        let timer = Self::start_timer("extract_entity_names");
        debug!("Extracting entity names from narrative: {}", narrative_text);
        
        // OPTIMIZATION: Shorter prompt for faster processing
        let system_prompt = r#"Extract entity names. Return JSON array only. Examples: ["Sol"], ["Borga", "Ssk"]"#;
        
        let user_prompt = format!("Extract names from: {}", narrative_text);
        
        // Call AI for entity name extraction
        let ai_timer = Self::start_timer("AI_entity_extraction");
        let ai_response = self.call_ai_for_extraction(&system_prompt, &user_prompt).await?;
        Self::end_timer(ai_timer, "AI_entity_extraction");
        
        // Parse response
        let entity_names = self.parse_entity_names_response(&ai_response)?;
        
        info!("Extracted {} entity names: {:?}", entity_names.len(), entity_names);
        Self::end_timer(timer, "extract_entity_names");
        Ok(entity_names)
    }

    /// Extract rich context information from narrative text (Task 2.2)
    pub async fn extract_narrative_context(
        &self,
        narrative_text: &str,
    ) -> Result<NarrativeContext, ToolError> {
        debug!("Extracting rich context from narrative: {}", narrative_text);
        
        let system_prompt = r#"You are an expert narrative context analyzer. Extract comprehensive context information from the narrative text.

Return a JSON object with the following structure:
{
  "entities": [
    {
      "name": "entity_name",
      "type": "CHARACTER|LOCATION|ITEM|ORGANIZATION|CONCEPT",
      "description": "brief description",
      "properties": ["property1", "property2"]
    }
  ],
  "spatial_context": {
    "primary_location": "main location name",
    "secondary_locations": ["other locations mentioned"],
    "spatial_relationships": [
      {"entity1": "A", "relationship": "inside|near|above|below|adjacent", "entity2": "B"}
    ]
  },
  "temporal_context": {
    "time_indicators": ["now", "morning", "yesterday", "3 hours ago"],
    "sequence_markers": ["first", "then", "finally", "simultaneously"],
    "duration_hints": ["briefly", "for hours", "all day"]
  },
  "social_context": {
    "relationships": [
      {"entity1": "A", "relationship": "friend|enemy|subordinate|superior|stranger", "entity2": "B"}
    ],
    "social_dynamics": ["tension", "cooperation", "hierarchy", "conflict"],
    "emotional_tone": "neutral|positive|negative|tense|friendly|hostile"
  },
  "actions_and_events": [
    {
      "action": "action_verb",
      "agent": "who performed it",
      "target": "what was affected",
      "context": "additional context"
    }
  ]
}

Be thorough but concise. Extract all relevant context that would help understand the narrative scene."#;
        
        let user_prompt = format!("Extract comprehensive context from this narrative:\n\n{}", narrative_text);
        
        // Call AI for context extraction
        let ai_response = self.call_ai_for_extraction(&system_prompt, &user_prompt).await?;
        
        // Parse response
        let context = self.parse_narrative_context_response(&ai_response)?;
        
        info!("Extracted narrative context with {} entities, {} spatial relationships, {} social relationships", 
            context.entities.len(), 
            context.spatial_context.spatial_relationships.len(),
            context.social_context.relationships.len());
        
        Ok(context)
    }

    /// Call AI for entity name extraction
    async fn call_ai_for_extraction(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, ToolError> {
        use genai::chat::{
            ChatOptions as GenAiChatOptions, ChatRole, MessageContent, 
            ChatMessage as GenAiChatMessage, HarmBlockThreshold, HarmCategory, SafetySetting
        };
        
        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_prompt.to_string()),
            options: None,
        };
        
        let mut chat_options = GenAiChatOptions::default();
        chat_options = chat_options.with_temperature(0.1); // Low temperature for consistency
        chat_options = chat_options.with_max_tokens(2048);
        
        // Safety settings for roleplay content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        chat_options = chat_options.with_safety_settings(safety_settings);
        
        let chat_req = genai::chat::ChatRequest::new(vec![user_message]).with_system(system_prompt);
        
        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_req, Some(chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Entity extraction AI call failed: {}", e)))?;
        
        Ok(response.first_content_text_as_str().unwrap_or_default().to_string())
    }

    /// Parse entity names from AI response
    fn parse_entity_names_response(&self, ai_response: &str) -> Result<Vec<String>, ToolError> {
        // Extract JSON from potential markdown code blocks
        let json_content = if let Some(start) = ai_response.find("```json") {
            let content = &ai_response[start + 7..];
            if let Some(end) = content.find("```") {
                &content[..end]
            } else {
                content
            }
        } else if let Some(start) = ai_response.find("[") {
            let content = &ai_response[start..];
            if let Some(end) = content.rfind("]") {
                &content[..end + 1]
            } else {
                content
            }
        } else {
            ai_response
        }.trim();
        
        let parsed: Value = serde_json::from_str(json_content)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse entity names JSON: {}", e)))?;
        
        let entity_names = parsed.as_array()
            .ok_or_else(|| ToolError::ExecutionFailed("Response is not a JSON array".to_string()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        Ok(entity_names)
    }

    /// Parse narrative context from AI response
    fn parse_narrative_context_response(&self, ai_response: &str) -> Result<NarrativeContext, ToolError> {
        // Extract JSON from potential markdown code blocks
        let json_content = if let Some(start) = ai_response.find("```json") {
            let content = &ai_response[start + 7..];
            if let Some(end) = content.find("```") {
                &content[..end]
            } else {
                content
            }
        } else if let Some(start) = ai_response.find("{") {
            let content = &ai_response[start..];
            if let Some(end) = content.rfind("}") {
                &content[..end + 1]
            } else {
                content
            }
        } else {
            ai_response
        }.trim();
        
        let parsed: Value = serde_json::from_str(json_content)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse narrative context JSON: {}", e)))?;
        
        // Parse entities
        let entities = parsed.get("entities")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity| {
                let name = entity.get("name")?.as_str()?.to_string();
                let entity_type = entity.get("type")?.as_str()?.to_string();
                let description = entity.get("description")?.as_str()?.to_string();
                let properties = entity.get("properties")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|p| p.as_str().map(|s| s.to_string()))
                    .collect();
                
                Some(NarrativeEntity {
                    name,
                    entity_type,
                    description,
                    properties,
                })
            })
            .collect();
        
        // Parse spatial context
        let spatial_context = parsed.get("spatial_context")
            .map(|sc| {
                let primary_location = sc.get("primary_location")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                    
                let secondary_locations = sc.get("secondary_locations")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|l| l.as_str().map(|s| s.to_string()))
                    .collect();
                
                let spatial_relationships = sc.get("spatial_relationships")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|rel| {
                        let entity1 = rel.get("entity1")?.as_str()?.to_string();
                        let relationship = rel.get("relationship")?.as_str()?.to_string();
                        let entity2 = rel.get("entity2")?.as_str()?.to_string();
                        
                        Some(SpatialRelationship {
                            entity1,
                            relationship,
                            entity2,
                        })
                    })
                    .collect();
                
                SpatialContext {
                    primary_location,
                    secondary_locations,
                    spatial_relationships,
                }
            })
            .unwrap_or_else(|| SpatialContext {
                primary_location: None,
                secondary_locations: vec![],
                spatial_relationships: vec![],
            });
        
        // Parse temporal context
        let temporal_context = parsed.get("temporal_context")
            .map(|tc| {
                let time_indicators = tc.get("time_indicators")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|t| t.as_str().map(|s| s.to_string()))
                    .collect();
                
                let sequence_markers = tc.get("sequence_markers")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect();
                
                let duration_hints = tc.get("duration_hints")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                    .collect();
                
                TemporalContext {
                    time_indicators,
                    sequence_markers,
                    duration_hints,
                }
            })
            .unwrap_or_else(|| TemporalContext {
                time_indicators: vec![],
                sequence_markers: vec![],
                duration_hints: vec![],
            });
        
        // Parse social context
        let social_context = parsed.get("social_context")
            .map(|sc| {
                let relationships = sc.get("relationships")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|rel| {
                        let entity1 = rel.get("entity1")?.as_str()?.to_string();
                        let relationship = rel.get("relationship")?.as_str()?.to_string();
                        let entity2 = rel.get("entity2")?.as_str()?.to_string();
                        
                        Some(SocialRelationship {
                            entity1,
                            relationship,
                            entity2,
                        })
                    })
                    .collect();
                
                let social_dynamics = sc.get("social_dynamics")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                    .collect();
                
                let emotional_tone = sc.get("emotional_tone")
                    .and_then(|v| v.as_str())
                    .unwrap_or("neutral")
                    .to_string();
                
                SocialContext {
                    relationships,
                    social_dynamics,
                    emotional_tone,
                }
            })
            .unwrap_or_else(|| SocialContext {
                relationships: vec![],
                social_dynamics: vec![],
                emotional_tone: "neutral".to_string(),
            });
        
        // Parse actions and events
        let actions_and_events = parsed.get("actions_and_events")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|action| {
                let action_verb = action.get("action")?.as_str()?.to_string();
                let agent = action.get("agent")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let target = action.get("target")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let context = action.get("context")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                Some(NarrativeAction {
                    action: action_verb,
                    agent,
                    target,
                    context,
                })
            })
            .collect();
        
        Ok(NarrativeContext {
            entities,
            spatial_context,
            temporal_context,
            social_context,
            actions_and_events,
        })
    }

    /// Multi-stage entity resolution (Task 2.3)
    /// 
    /// This method implements a sophisticated multi-stage pipeline:
    /// 1. Extract: Get entities and rich context from narrative
    /// 2. Resolve: Match entities to existing ones or mark as new
    /// 3. Structure: Create formal entity structures with relationships
    /// 4. Assemble: Build final resolved entity list with full context
    /// Multi-stage entity resolution (Task 2.3)
    /// OPTIMIZED: Added performance monitoring and parallel processing potential
    pub async fn resolve_entities_multistage(
        &self,
        narrative_text: &str,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        existing_entities: &[ExistingEntity],
    ) -> Result<MultiStageResolutionResult, ToolError> {
        let total_timer = Self::start_timer("resolve_entities_multistage_TOTAL");
        debug!("Starting multi-stage entity resolution for user: {}", user_id);
        
        // OPTIMIZATION: Early return for empty text
        if narrative_text.trim().is_empty() {
            debug!("Empty narrative text, returning empty result");
            return Ok(MultiStageResolutionResult {
                resolved_entities: vec![],
                relationships: vec![],
                user_id,
                chronicle_id,
                processing_metadata: ProcessingMetadata {
                    total_entities_processed: 0,
                    new_entities_created: 0,
                    relationships_identified: 0,
                    confidence_average: 1.0,
                },
            });
        }
        
        // Stage 1: Extract entities and context from narrative
        let stage1_timer = Self::start_timer("Stage1_extraction");
        let extraction_result = self.extract_stage(narrative_text).await?;
        Self::end_timer(stage1_timer, "Stage1_extraction");
        debug!("Stage 1 complete: extracted {} entities", extraction_result.narrative_context.entities.len());
        
        // Stage 2: Resolve entities against existing database
        let stage2_timer = Self::start_timer("Stage2_resolution");
        let resolution_result = self.resolve_stage(&extraction_result, existing_entities).await?;
        Self::end_timer(stage2_timer, "Stage2_resolution");
        debug!("Stage 2 complete: resolved {} entities", resolution_result.resolved_entities.len());
        
        // Stage 3: Structure entities with relationships and components
        let stage3_timer = Self::start_timer("Stage3_structure");
        let structure_result = self.structure_stage(&resolution_result, &extraction_result).await?;
        Self::end_timer(stage3_timer, "Stage3_structure");
        debug!("Stage 3 complete: structured {} entities with {} relationships", 
            structure_result.structured_entities.len(), structure_result.relationships.len());
        
        // Stage 4: Assemble final result with full context
        let stage4_timer = Self::start_timer("Stage4_assembly");
        let final_result = self.assemble_stage(&structure_result, user_id, chronicle_id).await?;
        Self::end_timer(stage4_timer, "Stage4_assembly");
        debug!("Stage 4 complete: assembled {} final entities", final_result.resolved_entities.len());
        
        Self::end_timer(total_timer, "resolve_entities_multistage_TOTAL");
        Ok(final_result)
    }
    
    /// Stage 1: Extract entities and context from narrative
    /// OPTIMIZED: Parallel extraction of context and names
    async fn extract_stage(&self, narrative_text: &str) -> Result<ExtractionStageResult, ToolError> {
        // OPTIMIZATION: Run both extractions in parallel
        let context_future = self.extract_narrative_context(narrative_text);
        let names_future = self.extract_entity_names(narrative_text);
        
        // Wait for both results
        let (context_result, names_result) = tokio::join!(context_future, names_future);
        
        // Handle results
        let context = context_result?;
        let entity_names = names_result.unwrap_or_else(|e| {
            warn!("Failed to extract entity names separately: {}", e);
            // Fallback to names from context
            context.entities.iter()
                .map(|e| e.name.clone())
                .collect()
        });
        
        Ok(ExtractionStageResult {
            narrative_context: context,
            extracted_entity_names: entity_names,
            original_text: narrative_text.to_string(),
        })
    }
    
    /// Stage 2: Resolve entities against existing database
    async fn resolve_stage(
        &self,
        extraction: &ExtractionStageResult,
        existing_entities: &[ExistingEntity],
    ) -> Result<ResolutionStageResult, ToolError> {
        let mut resolved_entities = Vec::new();
        let mut new_entities = Vec::new();
        
        // Process entities from rich context first
        for narrative_entity in &extraction.narrative_context.entities {
            // Check if this entity has already been processed in this session
            let already_in_resolved = resolved_entities.iter().any(|e: &ResolvedEntity| e.name.eq_ignore_ascii_case(&narrative_entity.name));
            let already_in_new = new_entities.iter().any(|e: &ResolvedEntity| e.name.eq_ignore_ascii_case(&narrative_entity.name));
            
            if already_in_resolved || already_in_new {
                debug!("Entity '{}' already processed in this session, skipping", narrative_entity.name);
                continue;
            }

            match self.find_matching_entity(&narrative_entity.name, existing_entities) {
                Some(existing) => {
                    debug!("Matched entity '{}' to existing UUID: {}", narrative_entity.name, existing.entity_id);
                    resolved_entities.push(ResolvedEntity {
                        entity_id: existing.entity_id,
                        name: narrative_entity.name.clone(),
                        display_name: existing.display_name.clone(),
                        entity_type: narrative_entity.entity_type.clone(),
                        is_new: false,
                        confidence: 0.9, // High confidence for rich context matches
                        context: Some(narrative_entity.description.clone()),
                        properties: narrative_entity.properties.clone(),
                    });
                }
                None => {
                    debug!("Creating new entity for '{}'", narrative_entity.name);
                    new_entities.push(ResolvedEntity {
                        entity_id: Uuid::new_v4(),
                        name: narrative_entity.name.clone(),
                        display_name: narrative_entity.name.clone(),
                        entity_type: narrative_entity.entity_type.clone(),
                        is_new: true,
                        confidence: 0.8,
                        context: Some(narrative_entity.description.clone()),
                        properties: narrative_entity.properties.clone(),
                    });
                }
            }
        }
        
        // Process any additional entity names not in rich context
        for entity_name in &extraction.extracted_entity_names {
            // Use case-insensitive comparison for consistency
            if !resolved_entities.iter().any(|e: &ResolvedEntity| e.name.eq_ignore_ascii_case(entity_name)) &&
               !new_entities.iter().any(|e: &ResolvedEntity| e.name.eq_ignore_ascii_case(entity_name)) {
                match self.find_matching_entity(entity_name, existing_entities) {
                    Some(existing) => {
                        debug!("Matched additional entity '{}' to existing UUID: {}", entity_name, existing.entity_id);
                        resolved_entities.push(ResolvedEntity {
                            entity_id: existing.entity_id,
                            name: entity_name.clone(),
                            display_name: existing.display_name.clone(),
                            entity_type: "UNKNOWN".to_string(),
                            is_new: false,
                            confidence: 0.6, // Lower confidence for name-only matches
                            context: None,
                            properties: vec![],
                        });
                    }
                    None => {
                        debug!("Creating new entity for additional name '{}'", entity_name);
                        new_entities.push(ResolvedEntity {
                            entity_id: Uuid::new_v4(),
                            name: entity_name.clone(),
                            display_name: entity_name.clone(),
                            entity_type: "UNKNOWN".to_string(),
                            is_new: true,
                            confidence: 0.5,
                            context: None,
                            properties: vec![],
                        });
                    }
                }
            }
        }
        
        Ok(ResolutionStageResult {
            resolved_entities,
            new_entities,
        })
    }
    
    /// Stage 3: Structure entities with relationships and components
    async fn structure_stage(
        &self,
        resolution: &ResolutionStageResult,
        extraction: &ExtractionStageResult,
    ) -> Result<StructureStageResult, ToolError> {
        let mut structured_entities = Vec::new();
        let mut relationships = Vec::new();
        
        // Combine resolved and new entities
        let all_entities: Vec<_> = resolution.resolved_entities.iter()
            .chain(resolution.new_entities.iter())
            .collect();
        
        // Create structured entities with component suggestions
        for entity in &all_entities {
            let components = self.suggest_components(entity, &extraction.narrative_context);
            
            structured_entities.push(StructuredEntity {
                entity_id: entity.entity_id,
                name: entity.name.clone(),
                display_name: entity.display_name.clone(),
                entity_type: entity.entity_type.clone(),
                is_new: entity.is_new,
                confidence: entity.confidence,
                context: entity.context.clone(),
                properties: entity.properties.clone(),
                suggested_components: components,
            });
        }
        
        // Extract relationships from context
        for spatial_rel in &extraction.narrative_context.spatial_context.spatial_relationships {
            if let (Some(entity1), Some(entity2)) = (
                self.find_entity_by_name(&spatial_rel.entity1, &all_entities),
                self.find_entity_by_name(&spatial_rel.entity2, &all_entities),
            ) {
                relationships.push(EntityRelationship {
                    from_entity_id: entity1.entity_id,
                    to_entity_id: entity2.entity_id,
                    relationship_type: format!("spatial_{}", spatial_rel.relationship),
                    strength: 0.7,
                    context: "spatial".to_string(),
                });
            }
        }
        
        for social_rel in &extraction.narrative_context.social_context.relationships {
            if let (Some(entity1), Some(entity2)) = (
                self.find_entity_by_name(&social_rel.entity1, &all_entities),
                self.find_entity_by_name(&social_rel.entity2, &all_entities),
            ) {
                relationships.push(EntityRelationship {
                    from_entity_id: entity1.entity_id,
                    to_entity_id: entity2.entity_id,
                    relationship_type: format!("social_{}", social_rel.relationship),
                    strength: 0.8,
                    context: "social".to_string(),
                });
            }
        }
        
        Ok(StructureStageResult {
            structured_entities,
            relationships,
        })
    }
    
    /// Stage 4: Assemble final result with full context
    async fn assemble_stage(
        &self,
        structure: &StructureStageResult,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
    ) -> Result<MultiStageResolutionResult, ToolError> {
        let resolved_entities = structure.structured_entities.iter()
            .map(|se| FinalResolvedEntity {
                entity_id: se.entity_id,
                name: se.name.clone(),
                display_name: se.display_name.clone(),
                entity_type: se.entity_type.clone(),
                is_new: se.is_new,
                confidence: se.confidence,
                context: se.context.clone(),
                properties: se.properties.clone(),
                components: se.suggested_components.clone(),
            })
            .collect();
        
        Ok(MultiStageResolutionResult {
            resolved_entities,
            relationships: structure.relationships.clone(),
            user_id,
            chronicle_id,
            processing_metadata: ProcessingMetadata {
                total_entities_processed: structure.structured_entities.len(),
                new_entities_created: structure.structured_entities.iter().filter(|e| e.is_new).count(),
                relationships_identified: structure.relationships.len(),
                confidence_average: structure.structured_entities.iter()
                    .map(|e| e.confidence)
                    .sum::<f32>() / structure.structured_entities.len() as f32,
            },
        })
    }
    
    /// Helper methods for multi-stage processing
    fn find_matching_entity<'a>(&self, name: &str, existing_entities: &'a [ExistingEntity]) -> Option<&'a ExistingEntity> {
        debug!("Looking for existing entity matching name: '{}' among {} existing entities", name, existing_entities.len());
        for entity in existing_entities {
            debug!("  Checking against existing entity: '{}' (display: '{}', aliases: {:?})", 
                entity.name, entity.display_name, entity.aliases);
        }
        
        let found = existing_entities.iter().find(|e| 
            e.name.eq_ignore_ascii_case(name) || 
            e.display_name.eq_ignore_ascii_case(name) ||
            e.aliases.iter().any(|alias| alias.eq_ignore_ascii_case(name))
        );
        
        if let Some(matched) = found {
            debug!("FOUND MATCH: '{}' matches existing entity '{}' (UUID: {})", name, matched.name, matched.entity_id);
        } else {
            debug!("NO MATCH FOUND: '{}' will be created as new entity", name);
        }
        
        found
    }
    
    fn find_entity_by_name<'a>(&self, name: &str, entities: &'a [&ResolvedEntity]) -> Option<&'a ResolvedEntity> {
        entities.iter().find(|e| e.name.eq_ignore_ascii_case(name)).copied()
    }
    
    fn suggest_components(&self, entity: &ResolvedEntity, context: &NarrativeContext) -> Vec<String> {
        let mut components = vec!["Name".to_string()];
        
        match entity.entity_type.as_str() {
            "CHARACTER" => {
                components.extend_from_slice(&["Health".to_string(), "Position".to_string(), "Relationships".to_string()]);
            }
            "LOCATION" => {
                components.extend_from_slice(&["Position".to_string(), "Description".to_string()]);
            }
            "ITEM" => {
                components.extend_from_slice(&["Description".to_string(), "Properties".to_string()]);
            }
            "ORGANIZATION" => {
                components.extend_from_slice(&["Description".to_string(), "Relationships".to_string()]);
            }
            _ => {
                // Default components for unknown types
                components.extend_from_slice(&["Position".to_string(), "Description".to_string()]);
            }
        }
        
        // Add context-specific components
        if !context.spatial_context.spatial_relationships.is_empty() {
            components.push("SpatialRelationships".to_string());
        }
        
        if !context.social_context.relationships.is_empty() {
            components.push("SocialRelationships".to_string());
        }
        
        components.sort();
        components.dedup();
        components
    }
}

#[async_trait]
impl ScribeTool for EntityResolutionTool {
    fn name(&self) -> &'static str {
        "resolve_entities"
    }

    fn description(&self) -> &'static str {
        "Resolves entity names from narrative text to existing entities or creates new ones with rich component data extracted from context."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user"
                },
                "chronicle_id": {
                    "type": "string",
                    "description": "The UUID of the chronicle (optional)"
                },
                "narrative_text": {
                    "type": "string",
                    "description": "The narrative text containing entity references"
                },
                "entity_names": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Array of entity names to resolve"
                },
                "existing_entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "name": {"type": "string"},
                            "display_name": {"type": "string"},
                            "aliases": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "entity_type": {"type": "string"},
                            "context": {"type": "string"}
                        }
                    },
                    "description": "Array of existing entities to match against"
                }
            },
            "required": ["user_id", "narrative_text", "entity_names"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing entity resolution tool with params: {}", params);

        // Extract parameters
        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let chronicle_id = params.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let narrative_text = params.get("narrative_text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("narrative_text is required".to_string()))?;

        let entity_names = params.get("entity_names")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ToolError::InvalidParams("entity_names is required".to_string()))?;

        let empty_entities = vec![];
        let existing_entities = params.get("existing_entities")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_entities);

        // Get existing entities from the database if chronicle_id is provided
        let mut db_entities = Vec::new();
        if let Some(chron_id) = chronicle_id {
            debug!("Fetching existing entities for chronicle {}", chron_id);
            match self.app_state.ecs_entity_manager
                .get_entities_by_chronicle(user_id, chron_id, Some(50))
                .await
            {
                Ok(entities) => {
                    for entity in entities {
                        // Find the Name component
                        if let Some(name_component) = entity.components.iter().find(|c| c.component_type == "Name") {
                            let name = name_component.component_data.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
                            let display_name = name_component.component_data.get("display_name").and_then(|n| n.as_str()).unwrap_or(name);
                            let aliases: Vec<String> = name_component.component_data.get("aliases")
                                .and_then(|a| a.as_array())
                                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                                .unwrap_or_default();

                            db_entities.push(json!({
                                "entity_id": entity.entity.id.to_string(),
                                "name": name,
                                "display_name": display_name,
                                "aliases": aliases,
                                "entity_type": entity.entity.archetype_signature,
                                "context": format!("Existing entity from chronicle {}", chron_id)
                            }));
                        }
                    }
                    debug!("Found {} existing entities in database", db_entities.len());
                }
                Err(e) => {
                    warn!("Failed to fetch existing entities: {}", e);
                }
            }
        }

        // Combine provided existing entities with database entities
        let mut all_existing_entities = existing_entities.clone();
        all_existing_entities.extend(db_entities);

        // Create AI prompt for entity resolution
        let system_prompt = r#"You are an expert entity resolution system for a narrative game. Your task is to:

1. **Resolve entity names** from narrative text to existing entities OR create new ones
2. **Extract rich component data** from the narrative context
3. **Use semantic understanding** to match entities correctly

For each entity name, you must:
- Check if it matches an existing entity (exact match, alias, or semantic similarity)
- If it matches: return the existing entity_id with updated component data
- If it doesn't match: create a new entity with a new UUID and rich components

Extract these components from narrative context:
- **Name**: The entity's name, display name, and aliases
- **Position**: Location, coordinates, or spatial context
- **Health**: Current health, max health, injuries, or physical state
- **Relationships**: Social connections, trust, affection, or conflicts mentioned
- **Attributes**: Any other relevant game attributes (inventory, skills, etc.)

Be semantically smart:
- "John the merchant" ≠ "John the guard" (different entities)
- "Captain Smith" could be "Smith" or "the Captain" (same entity)
- "the wounded soldier" might be "Private Johnson" (same entity)

Output format: Return a JSON object with resolved entities and their component data."#;

        let entity_names_str: Vec<String> = entity_names.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        let user_prompt = format!(
            r#"Narrative text: "{}"

Entity names to resolve: {:?}

Existing entities: {}

For each entity name, resolve it to an existing entity or create a new one. Extract rich component data from the narrative context.

**IMPORTANT RULES:**
1. If "is_new": true, set "entity_id" to "new-entity" (system will generate fresh UUID)
2. If "is_new": false, use the exact entity_id from the existing entities list
3. Only mark as existing if you're confident it's the same entity (not just similar name)
4. When in doubt, create a new entity rather than risk data corruption

Return JSON in this format:
{{
  "resolved_entities": [
    {{
      "input_name": "entity name from input",
      "entity_id": "existing-uuid-from-list-or-new-entity",
      "is_new": true/false,
      "confidence": 0.0-1.0,
      "components": {{
        "Name": {{
          "name": "canonical name",
          "display_name": "display name",
          "aliases": ["alias1", "alias2"]
        }},
        "Position": {{
          "x": 0.0,
          "y": 0.0,
          "z": 0.0,
          "zone": "location or zone name"
        }},
        "Health": {{
          "current": 100,
          "max": 100,
          "regeneration_rate": 1.0
        }},
        "Relationships": {{
          "relationships": []
        }}
      }}
    }}
  ]
}}"#,
            narrative_text,
            entity_names_str,
            serde_json::to_string_pretty(&all_existing_entities).unwrap_or_default()
        );

        // Call Flash-Lite for entity resolution
        debug!("Calling Flash-Lite for entity resolution");
        
        use genai::chat::{
            ChatOptions as GenAiChatOptions, HarmBlockThreshold, HarmCategory, SafetySetting,
            ChatRole, MessageContent, ChatMessage as GenAiChatMessage
        };
        
        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_prompt),
            options: None,
        };

        let mut genai_chat_options = GenAiChatOptions::default();
        genai_chat_options = genai_chat_options.with_temperature(0.3); // Medium temp for creative entity resolution
        genai_chat_options = genai_chat_options.with_max_tokens(4096);
        
        // Add safety settings
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        genai_chat_options = genai_chat_options.with_safety_settings(safety_settings);

        let chat_req = genai::chat::ChatRequest::new(vec![user_message]).with_system(system_prompt);
        
        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_req, Some(genai_chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Entity resolution AI call failed: {}", e)))?;

        let ai_response = response.first_content_text_as_str().unwrap_or_default();
        debug!("Flash-Lite response: {}", ai_response);

        // Parse the AI response, safely extracting content from markdown code blocks.
        // This handles cases where the response is truncated and the closing ``` is missing.
        let cleaned_content = if let Some(start_pos) = ai_response.find("```json") {
            let content_after_start = &ai_response[start_pos + "```json".len()..];
            if let Some(end_pos) = content_after_start.rfind("```") {
                &content_after_start[..end_pos]
            } else {
                content_after_start // Assume truncated response, take the rest of the string.
            }
        } else if let Some(start_pos) = ai_response.find("```") {
            let content_after_start = &ai_response[start_pos + "```".len()..];
            if let Some(end_pos) = content_after_start.rfind("```") {
                &content_after_start[..end_pos]
            } else {
                content_after_start // Assume truncated response.
            }
        } else {
            ai_response // No code block found, use the whole response.
        }
        .trim();

        let resolution_result: Value = serde_json::from_str(cleaned_content)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        let resolved_entities = resolution_result
            .get("resolved_entities")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ToolError::ExecutionFailed(
                    "AI response missing 'resolved_entities' array".to_string(),
                )
            })?;

        self.process_resolved_entities(user_id, chronicle_id, resolved_entities)
            .await
    }
}

impl EntityResolutionTool {
    /// Processes the resolved entities after a successful AI call.
    /// This logic is extracted to be used after the retry loop.
    async fn process_resolved_entities(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        resolved_entities: &[Value],
    ) -> Result<ToolResult, ToolError> {
        // Process each resolved entity
        let mut results = Vec::new();
        for entity in resolved_entities {
            let entity_id_str = entity
                .get("entity_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ToolError::ExecutionFailed("Missing entity_id in AI response".to_string())
                })?;

            let ai_is_new = entity.get("is_new").and_then(|v| v.as_bool()).unwrap_or(true);

            // Fix: Generate entity ID based on AI's intention, not blindly trusting AI's UUID
            let entity_id = if ai_is_new || entity_id_str == "new-entity" {
                // For new entities, always generate a fresh UUID
                let new_id = Uuid::new_v4();
                debug!("Generating new entity ID {} for '{}' (AI marked as new: {})", 
                       new_id, entity.get("input_name").and_then(|n| n.as_str()).unwrap_or("unknown"), ai_is_new);
                new_id
            } else {
                // For existing entities, try to parse the provided UUID
                match Uuid::parse_str(entity_id_str) {
                    Ok(uuid) => {
                        debug!("Using existing entity ID {} for '{}' (AI marked as existing)", 
                               uuid, entity.get("input_name").and_then(|n| n.as_str()).unwrap_or("unknown"));
                        uuid
                    },
                    Err(_) => {
                        warn!("AI provided invalid UUID '{}' for existing entity '{}', generating new UUID", 
                              entity_id_str, entity.get("input_name").and_then(|n| n.as_str()).unwrap_or("unknown"));
                        Uuid::new_v4()
                    }
                }
            };

            let confidence = entity
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);

            let components = entity.get("components").cloned().unwrap_or_else(|| json!({}));

            // Enhanced entity lifecycle decision logic
            let is_new = self
                .determine_entity_lifecycle_action(
                    entity_id,
                    user_id,
                    &ai_is_new,
                    confidence,
                    &components,
                    chronicle_id,
                )
                .await?;

            // Create or update the entity in the database
            if is_new {
                debug!("Creating new entity: {}", entity_id);

                // Determine archetype from components
                let mut archetype_parts = Vec::new();
                if components.get("Name").is_some() {
                    archetype_parts.push("Name");
                }
                if components.get("Position").is_some() {
                    archetype_parts.push("Position");
                }
                if components.get("Health").is_some() {
                    archetype_parts.push("Health");
                }
                if components.get("Relationships").is_some() {
                    archetype_parts.push("Relationships");
                }

                let archetype = if archetype_parts.is_empty() {
                    "Name|Position".to_string()
                } else {
                    archetype_parts.join("|")
                };

                // Create the entity
                match self
                    .app_state
                    .ecs_entity_manager
                    .create_entity(user_id, Some(entity_id), archetype.clone(), vec![])
                    .await
                {
                    Ok(_) => {
                        debug!("Created entity {} with archetype {}", entity_id, archetype);

                        // Add components
                        let mut component_updates = Vec::new();
                        if let Some(comp_obj) = components.as_object() {
                            for (component_type, component_data) in comp_obj {
                                component_updates.push(ComponentUpdate {
                                    entity_id,
                                    component_type: component_type.clone(),
                                    component_data: component_data.clone(),
                                    operation: ComponentOperation::Add,
                                });
                            }
                        }

                        if !component_updates.is_empty() {
                            match self
                                .app_state
                                .ecs_entity_manager
                                .update_components(user_id, entity_id, component_updates)
                                .await
                            {
                                Ok(_) => debug!(
                                    "Added {} components to entity {}",
                                    components.as_object().unwrap().len(),
                                    entity_id
                                ),
                                Err(e) => warn!(
                                    "Failed to add components to entity {}: {}",
                                    entity_id, e
                                ),
                            }
                        }

                        // Add ChronicleSource component if chronicle_id is provided
                        if let Some(chron_id) = chronicle_id {
                            let chronicle_source = json!({
                                "chronicle_id": chron_id,
                                "first_mentioned": chrono::Utc::now().to_rfc3339(),
                                "entity_id": entity_id
                            });

                            let chronicle_update = ComponentUpdate {
                                entity_id,
                                component_type: "ChronicleSource".to_string(),
                                component_data: chronicle_source,
                                operation: ComponentOperation::Add,
                            };

                            match self
                                .app_state
                                .ecs_entity_manager
                                .update_components(user_id, entity_id, vec![chronicle_update])
                                .await
                            {
                                Ok(_) => debug!(
                                    "Added ChronicleSource component to entity {}",
                                    entity_id
                                ),
                                Err(e) => warn!(
                                    "Failed to add ChronicleSource component to entity {}: {}",
                                    entity_id, e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to create entity {}: {}", entity_id, e);
                        return Err(ToolError::ExecutionFailed(format!(
                            "Failed to create entity: {}",
                            e
                        )));
                    }
                }
            } else {
                debug!("Updating existing entity: {}", entity_id);

                // Update components for existing entity
                let mut component_updates = Vec::new();
                if let Some(comp_obj) = components.as_object() {
                    for (component_type, component_data) in comp_obj {
                        component_updates.push(ComponentUpdate {
                            entity_id,
                            component_type: component_type.clone(),
                            component_data: component_data.clone(),
                            operation: ComponentOperation::Update,
                        });
                    }
                }

                if !component_updates.is_empty() {
                    match self
                        .app_state
                        .ecs_entity_manager
                        .update_components(user_id, entity_id, component_updates)
                        .await
                    {
                        Ok(_) => debug!(
                            "Updated {} components for entity {}",
                            components.as_object().unwrap().len(),
                            entity_id
                        ),
                        Err(e) => {
                            warn!("Failed to update components for entity {}: {}", entity_id, e)
                        }
                    }
                }
            }

            results.push(json!({
                "input_name": entity.get("input_name"),
                "entity_id": entity_id.to_string(),
                "is_new": is_new,
                "confidence": entity.get("confidence").unwrap_or(&json!(1.0)),
                "components": components
            }));
        }

        info!(
            "Entity resolution completed: {} entities processed",
            results.len()
        );

        Ok(json!({
            "success": true,
            "resolved_entities": results,
            "total_processed": results.len()
        }))
    }
}

impl EntityResolutionTool {
    /// Enhanced entity lifecycle decision logic with validation and consistency checks
    /// 
    /// This method implements Phase 2.1: Entity Update vs Create Decision Logic
    /// - Validates AI decisions against database state
    /// - Handles edge cases like duplicate entities
    /// - Enforces consistency rules for entity lifecycle
    async fn determine_entity_lifecycle_action(
        &self,
        entity_id: Uuid,
        user_id: Uuid,
        ai_is_new: &bool,
        confidence: f64,
        components: &Value,
        chronicle_id: Option<Uuid>,
    ) -> Result<bool, ToolError> {
        // Step 1: Check if entity already exists in database
        let existing_entity = self.app_state.ecs_entity_manager
            .get_entity(user_id, entity_id)
            .await;

        match existing_entity {
            Ok(Some(entity)) => {
                // Entity exists in database
                if *ai_is_new {
                    // AI says new but entity exists - this is a consistency error
                    warn!("AI marked entity {} as new but it already exists in database. Forcing update.", entity_id);
                    
                    // Validate that the existing entity is compatible with new components
                    if let Err(e) = self.validate_entity_compatibility(&entity, components).await {
                        error!("Entity compatibility validation failed for existing entity {}: {}", entity_id, e);
                        // Log the existing entity name for debugging
                        if let Some(name_comp) = entity.components.iter().find(|c| c.component_type == "Name") {
                            if let Some(existing_name) = name_comp.component_data.get("name").and_then(|n| n.as_str()) {
                                error!("Existing entity {} has name '{}' which conflicts with new entity request", entity_id, existing_name);
                            }
                        }
                        return Err(ToolError::ExecutionFailed(format!("Failed to resolve entity names: Tool execution failed: Entity compatibility validation failed: {}", e)));
                    }
                    
                    // Force update instead of create
                    return Ok(false);
                } else {
                    // AI says update and entity exists - validate it's the right entity
                    if confidence < 0.8 {
                        warn!("Low confidence ({}) for entity update {}. Proceeding with caution.", confidence, entity_id);
                    }
                    
                    // Validate compatibility before update
                    if let Err(e) = self.validate_entity_compatibility(&entity, components).await {
                        error!("Entity compatibility validation failed: {}", e);
                        return Err(ToolError::ExecutionFailed(format!("Failed to resolve entity names: Tool execution failed: Entity compatibility validation failed: {}", e)));
                    }
                    
                    return Ok(false); // Update existing entity
                }
            }
            Ok(None) => {
                // Entity doesn't exist in database
                if !*ai_is_new {
                    // AI says update but entity doesn't exist - this is a consistency error
                    warn!("AI marked entity {} as existing but it doesn't exist in database. Forcing create.", entity_id);
                    
                    // Check if there might be a duplicate entity with similar components
                    if let Some(duplicate_id) = self.find_potential_duplicate_entity(user_id, components, chronicle_id).await? {
                        warn!("Found potential duplicate entity {} for new entity {}. Consider using existing entity.", duplicate_id, entity_id);
                        // For now, we'll still create the new entity but log the potential issue
                        // In a more advanced system, we might merge or redirect to the existing entity
                    }
                    
                    return Ok(true); // Create new entity
                } else {
                    // AI says new and entity doesn't exist - this is correct
                    
                    // Still check for potential duplicates to avoid entity explosion
                    if let Some(duplicate_id) = self.find_potential_duplicate_entity(user_id, components, chronicle_id).await? {
                        if confidence < 0.9 {
                            warn!("Low confidence ({}) and potential duplicate entity {} found. Consider validation.", confidence, duplicate_id);
                        }
                    }
                    
                    return Ok(true); // Create new entity
                }
            }
            Err(_) => {
                // Database error - treat as entity doesn't exist and continue with AI decision
                warn!("Database error checking entity {} existence. Continuing with AI decision.", entity_id);
                
                if *ai_is_new {
                    return Ok(true); // Create new entity
                } else {
                    // AI says update but we can't verify existence - create new entity
                    warn!("AI marked entity {} as existing but couldn't verify. Creating new entity.", entity_id);
                    return Ok(true);
                }
            }
        }
    }

    /// Validates that new components are compatible with existing entity
    /// 
    /// This prevents corrupting existing entities with incompatible data
    async fn validate_entity_compatibility(
        &self,
        existing_entity: &EntityQueryResult,
        new_components: &Value,
    ) -> Result<(), String> {
        // Extract new entity name for validation
        let new_name = new_components.get("Name")
            .and_then(|n| n.get("name"))
            .and_then(|n| n.as_str());

        // Check existing entity name
        if let Some(existing_name_component) = existing_entity.components.iter().find(|c| c.component_type == "Name") {
            let existing_name = existing_name_component.component_data.get("name")
                .and_then(|n| n.as_str());

            // If both have names, they should be related
            if let (Some(existing), Some(new)) = (existing_name, new_name) {
                if existing != new {
                    // Names are different - check if they're aliases
                    let existing_aliases: Vec<String> = existing_name_component.component_data.get("aliases")
                        .and_then(|a| a.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default();

                    let new_aliases: Vec<String> = new_components.get("Name")
                        .and_then(|n| n.get("aliases"))
                        .and_then(|a| a.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default();

                    // Check if names are in each other's aliases
                    let is_compatible = existing_aliases.contains(&new.to_string()) || 
                                       new_aliases.contains(&existing.to_string()) ||
                                       existing_aliases.iter().any(|a| new_aliases.contains(a));

                    if !is_compatible {
                        return Err(format!("Name mismatch: existing '{}' vs new '{}' with no common aliases", existing, new));
                    }
                }
            }
        }

        // Validate archetype compatibility
        let new_archetype_parts: Vec<&str> = new_components.as_object()
            .map(|obj| obj.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        let existing_archetype_parts: Vec<String> = existing_entity.entity.component_types();

        // New components should generally be a subset or extension of existing ones
        // This prevents major structural changes to entities
        let has_major_structural_change = new_archetype_parts.iter()
            .any(|&new_part| !existing_archetype_parts.iter().any(|existing_part| existing_part == new_part));

        if has_major_structural_change {
            debug!("Allowing structural change to entity {} - new components: {:?}", 
                   existing_entity.entity.id, new_archetype_parts);
            // We'll allow it but log it for monitoring
        }

        Ok(())
    }

    /// Finds potential duplicate entities based on component similarity
    /// 
    /// This helps prevent entity explosion by detecting similar entities
    async fn find_potential_duplicate_entity(
        &self,
        user_id: Uuid,
        components: &Value,
        chronicle_id: Option<Uuid>,
    ) -> Result<Option<Uuid>, ToolError> {
        // Extract name for duplicate detection
        let name = components.get("Name")
            .and_then(|n| n.get("name"))
            .and_then(|n| n.as_str());

        if let Some(entity_name) = name {
            // Get entities from the same chronicle if available
            if let Some(chron_id) = chronicle_id {
                match self.app_state.ecs_entity_manager
                    .get_entities_by_chronicle(user_id, chron_id, Some(100))
                    .await
                {
                    Ok(entities) => {
                        for entity in entities {
                            // Check if any existing entity has the same name
                            if let Some(name_component) = entity.components.iter().find(|c| c.component_type == "Name") {
                                let existing_name = name_component.component_data.get("name")
                                    .and_then(|n| n.as_str());

                                if let Some(existing) = existing_name {
                                    // Exact name match
                                    if existing == entity_name {
                                        return Ok(Some(entity.entity.id));
                                    }

                                    // Check aliases
                                    let existing_aliases: Vec<String> = name_component.component_data.get("aliases")
                                        .and_then(|a| a.as_array())
                                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                                        .unwrap_or_default();

                                    if existing_aliases.contains(&entity_name.to_string()) {
                                        return Ok(Some(entity.entity.id));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to fetch entities for duplicate detection: {}", e);
                    }
                }
            }
        }

        Ok(None)
    }

    /// Resolve actors from narrative tools to entities - replaces entity_name_resolver
    /// 
    /// This method provides backward compatibility with the existing narrative tools
    /// while using the new Flash-Lite powered entity resolution system
    pub async fn resolve_actors_to_entities(
        &self,
        actors: &[Value],
        chronicle_id: Option<Uuid>,
        user_id: Uuid,
        processing_mode: ProcessingMode,
    ) -> Result<ActorResolutionResult, ToolError> {
        debug!("Resolving {} actors to entities in {:?} mode using multi-stage processing", actors.len(), processing_mode);

        // Extract entity names from actors
        let entity_names: Vec<String> = actors
            .iter()
            .filter_map(|actor| {
                actor.get("id")
                    .or_else(|| actor.get("entity_name"))
                    .and_then(|name| name.as_str())
                    .map(|s| s.to_string())
            })
            .collect();

        if entity_names.is_empty() {
            let empty_context = NarrativeContext {
                entities: vec![],
                spatial_context: SpatialContext { primary_location: None, secondary_locations: vec![], spatial_relationships: vec![] },
                temporal_context: TemporalContext { time_indicators: vec![], sequence_markers: vec![], duration_hints: vec![] },
                social_context: SocialContext { relationships: vec![], social_dynamics: vec![], emotional_tone: "neutral".to_string() },
                actions_and_events: vec![],
            };
            return Ok(ActorResolutionResult {
                resolved_actors: json!([]),
                narrative_context: empty_context,
            });
        }

        // Create narrative text from actors for better context
        let narrative_text = self.create_narrative_context_from_actors(actors);

        // Get existing entities for context
        let existing_entities = if let Some(chron_id) = chronicle_id {
            self.get_existing_entities_for_context(user_id, chron_id).await?
        } else {
            vec![]
        };

        // Use the new multi-stage processing pipeline (Phase 2.3)
        let extraction_result = self.extract_stage(&narrative_text).await?;
        let multi_stage_result = self.resolve_entities_multistage(
            &narrative_text,
            user_id,
            chronicle_id,
            &existing_entities,
        ).await?;

        debug!("Multi-stage processing completed: {} entities resolved, {} relationships found",
            multi_stage_result.resolved_entities.len(),
            multi_stage_result.relationships.len());

        // Build the actor array with resolved entity IDs
        let mut resolved_actors = Vec::new();
        for actor in actors.iter() {
            let mut resolved_actor = actor.clone();
            
            // Find the corresponding resolved entity
            if let Some(entity_name) = actor.get("id").or_else(|| actor.get("entity_name")).and_then(|n| n.as_str()) {
                if let Some(resolved_entity) = multi_stage_result.resolved_entities.iter().find(|e| {
                    e.name.eq_ignore_ascii_case(entity_name)
                }) {
                    if let Some(obj) = resolved_actor.as_object_mut() {
                        obj.insert(
                            "entity_id".to_string(),
                            json!(resolved_entity.entity_id.to_string())
                        );
                        // Add entity_name back for downstream consumers
                        obj.insert(
                            "entity_name".to_string(),
                            json!(entity_name)
                        );
                        // Add entity type and confidence from multi-stage processing
                        obj.insert(
                            "entity_type".to_string(),
                            json!(resolved_entity.entity_type)
                        );
                        obj.insert(
                            "confidence".to_string(),
                            json!(resolved_entity.confidence)
                        );
                        obj.insert(
                            "is_new".to_string(),
                            json!(resolved_entity.is_new)
                        );
                    }
                }
            }
            
            resolved_actors.push(resolved_actor);
        }

        Ok(ActorResolutionResult {
            resolved_actors: json!(resolved_actors),
            narrative_context: extraction_result.narrative_context,
        })
    }

    /// Create narrative context from actors for better entity resolution
    fn create_narrative_context_from_actors(&self, actors: &[Value]) -> String {
        let actor_descriptions: Vec<String> = actors
            .iter()
            .filter_map(|actor| {
                let name = actor.get("id").or_else(|| actor.get("entity_name")).and_then(|n| n.as_str())?;
                let role = actor.get("role").and_then(|r| r.as_str()).unwrap_or("UNKNOWN");
                let context = actor.get("context").and_then(|c| c.as_str()).unwrap_or("");
                
                Some(format!("{} (role: {}) {}", name, role, context))
            })
            .collect();

        format!("Narrative involves the following entities: {}", actor_descriptions.join(", "))
    }

    /// Get existing entities for context during resolution
    async fn get_existing_entities_for_context(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<Vec<ExistingEntity>, ToolError> {
        debug!("Retrieving existing entities for chronicle {} and user {}", chronicle_id, user_id);
        match self.app_state.ecs_entity_manager
            .get_entities_by_chronicle(user_id, chronicle_id, Some(50))
            .await
        {
            Ok(entities) => {
                debug!("Found {} ECS entities in chronicle", entities.len());
                let mut context_entities = Vec::new();
                for entity in entities {
                    if let Some(name_component) = entity.components.iter().find(|c| c.component_type == "Name") {
                        let name = name_component.component_data.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown").to_string();
                        let display_name = name_component.component_data.get("display_name").and_then(|n| n.as_str()).unwrap_or(&name).to_string();
                        let aliases: Vec<String> = name_component.component_data.get("aliases")
                            .and_then(|a| a.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                            .unwrap_or_default();

                        debug!("Found existing entity: {} (UUID: {}, type: {})", name, entity.entity.id, entity.entity.archetype_signature);
                        context_entities.push(ExistingEntity {
                            entity_id: entity.entity.id,
                            name,
                            display_name,
                            aliases,
                            entity_type: entity.entity.archetype_signature,
                            context: Some(format!("Existing entity from chronicle {}", chronicle_id))
                        });
                    }
                }
                debug!("Extracted {} existing entities for context matching", context_entities.len());
                Ok(context_entities)
            }
            Err(e) => {
                debug!("Failed to fetch existing entities for context: {}", e);
                Ok(vec![])
            }
        }
    }
}

/// Enhanced entity mention with rich context
#[derive(Debug, Clone)]
pub struct EnrichedEntityMention {
    pub original_mention: EntityMention,
    pub local_context: Vec<String>,
    pub semantic_hints: Vec<String>,
    pub potential_matches: Vec<String>,
}

/// Entity mention from narrative
#[derive(Debug, Clone)]
pub struct EntityMention {
    pub id: String,
    pub name: String,
    pub role: Option<String>,
    pub context: Option<String>,
}

/// Existing entity context for resolution
#[derive(Debug, Clone)]
pub struct ExistingEntityContext {
    pub entity_id: String,
    pub primary_name: String,
    pub aliases: Vec<String>,
    pub entity_type: String,
    pub last_context: String,
    pub component_summary: String,
}

/// Similarity match between mention and existing entity
#[derive(Debug, Clone)]
pub struct SimilarityMatch {
    pub mention_id: String,
    pub existing_entity_id: String,
    pub similarity_score: f32,
    pub match_type: MatchType,
}

/// Type of entity match
#[derive(Debug, Clone)]
pub enum MatchType {
    ExactName,
    AliasMatch,
    SemanticSimilarity,
    ContextualMatch,
}

/// AI resolution result
#[derive(Debug, Clone)]
pub struct AIResolution {
    pub mention_name: String,
    pub entity_id: String,
    pub is_new: bool,
    pub confidence: f64,
    pub reasoning: String,
    pub components: Value,
}

/// Validated resolution after reconciliation
#[derive(Debug, Clone)]
pub struct ValidatedResolution {
    pub mention_name: String,
    pub entity_id: String,
    pub is_new: bool,
    pub confidence: f64,
    pub reasoning: String,
    pub components: Value,
    pub validation_notes: Vec<String>,
}

/// Processing mode for entity resolution
#[derive(Debug, Clone, Copy)]
pub enum ProcessingMode {
    /// Incremental processing for regular roleplay
    Incremental,
    /// Batch processing for re-chronicle operations
    Batch,
}

impl std::fmt::Display for ProcessingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessingMode::Incremental => write!(f, "incremental"),
            ProcessingMode::Batch => write!(f, "batch"),
        }
    }
}

#[cfg(test)]
mod tests {
    include!("entity_resolution_tool_tests.rs");
}