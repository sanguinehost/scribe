//! AI-Driven Entity Resolution Tool V2
//!
//! This is a refactored version of the entity resolution tool that replaces
//! hardcoded logic with AI-driven intelligence using Flash/Flash-Lite.
//!
//! Key improvements:
//! - AI-powered component suggestions based on narrative context
//! - Semantic entity matching that understands context and roles
//! - Intelligent entity lifecycle decisions
//! - No hardcoded rules - all decisions are context-aware

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::AppState;

use super::tools::{ScribeTool, ToolError, ToolParams, ToolResult};

// Import AI-powered components
use super::tools::ai_entity_resolution::{
    AiComponentSuggester, AiSemanticMatcher, AiContextExtractor,
};

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

/// Data structures for multi-stage processing

/// Represents an existing entity in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExistingEntity {
    pub entity_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub entity_type: String,
    pub context: Option<String>,
}

/// Result of Stage 1: Extraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionStageResult {
    pub narrative_context: NarrativeContext,
    pub extracted_entity_names: Vec<String>,
    pub original_text: String,
}

/// A resolved entity (can be existing or new)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolutionStageResult {
    pub resolved_entities: Vec<ResolvedEntity>,
    pub new_entities: Vec<ResolvedEntity>,
}

/// A structured entity with component suggestions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityRelationship {
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub context: String,
}

/// Result of Stage 3: Structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructureStageResult {
    pub structured_entities: Vec<StructuredEntity>,
    pub relationships: Vec<EntityRelationship>,
}

/// Final resolved entity with full context
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Processing metadata for analysis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessingMetadata {
    pub total_entities_processed: usize,
    pub new_entities_created: usize,
    pub relationships_identified: usize,
    pub confidence_average: f32,
}

/// Final result of multi-stage resolution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiStageResolutionResult {
    pub resolved_entities: Vec<FinalResolvedEntity>,
    pub relationships: Vec<EntityRelationship>,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>,
    pub processing_metadata: ProcessingMetadata,
}

/// Processing mode for different resolution strategies
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProcessingMode {
    Fast,
    Standard,
    Comprehensive,
    Incremental,
}

/// Result of actor resolution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActorResolutionResult {
    pub resolved_actors: Value,
    pub narrative_context: NarrativeContext,
}

/// Enhanced entity resolution tool with AI-driven intelligence
pub struct EntityResolutionTool {
    app_state: Arc<AppState>,
    component_suggester: Arc<AiComponentSuggester>,
    semantic_matcher: Arc<AiSemanticMatcher>,
    context_extractor: Arc<AiContextExtractor>,
}

impl EntityResolutionTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        let component_suggester = Arc::new(AiComponentSuggester::new(app_state.clone()));
        let semantic_matcher = Arc::new(AiSemanticMatcher::new(app_state.clone()));
        let context_extractor = Arc::new(AiContextExtractor::new(app_state.clone()));
        
        Self {
            app_state,
            component_suggester,
            semantic_matcher,
            context_extractor,
        }
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

    /// Extract entity names from narrative text using AI
    pub async fn extract_entity_names(
        &self,
        narrative_text: &str,
    ) -> Result<Vec<String>, ToolError> {
        let timer = Self::start_timer("extract_entity_names");
        debug!("Extracting entity names from narrative: {}", narrative_text);
        
        // Build AI prompt for entity extraction
        let prompt = format!(
            r#"Extract all entity names (characters, locations, items, organizations) from this text:
"{}"

Return ONLY a JSON array of entity names. Example: ["Sol", "Borga", "Cantina"]"#,
            narrative_text
        );
        
        // Use Flash-Lite for entity extraction
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(500)
            .with_temperature(0.1);
        
        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Entity extraction AI call failed: {}", e)))?;
        
        let ai_response = response.first_content_text_as_str().unwrap_or_default().to_string();
        let entity_names = self.parse_entity_names_response(&ai_response)?;
        
        info!("Extracted {} entity names: {:?}", entity_names.len(), entity_names);
        Self::end_timer(timer, "extract_entity_names");
        Ok(entity_names)
    }

    /// Extract rich context information from narrative text using AI
    pub async fn extract_narrative_context(
        &self,
        narrative_text: &str,
    ) -> Result<NarrativeContext, ToolError> {
        debug!("Extracting rich context from narrative: {}", narrative_text);
        
        let prompt = self.build_context_extraction_prompt(narrative_text);
        
        // Use Flash for comprehensive context extraction
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.2);
        
        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Context extraction AI call failed: {}", e)))?;
        
        let ai_response = response.first_content_text_as_str().unwrap_or_default();
        let context = self.parse_narrative_context_response(ai_response)?;
        
        info!("Extracted narrative context with {} entities", context.entities.len());
        Ok(context)
    }

    /// Multi-stage entity resolution with AI-driven intelligence
    pub async fn resolve_entities_multistage(
        &self,
        narrative_text: &str,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        existing_entities: &[ExistingEntity],
    ) -> Result<MultiStageResolutionResult, ToolError> {
        let total_timer = Self::start_timer("resolve_entities_multistage_TOTAL");
        debug!("Starting AI-driven multi-stage entity resolution for user: {}", user_id);
        
        // Stage 1: Extract entities and context
        let stage1_timer = Self::start_timer("Stage1_extraction");
        let extraction_result = self.extract_stage(narrative_text).await?;
        Self::end_timer(stage1_timer, "Stage1_extraction");
        
        // Stage 2: Resolve entities with AI semantic matching
        let stage2_timer = Self::start_timer("Stage2_ai_resolution");
        let resolution_result = self.resolve_stage_with_ai(&extraction_result, existing_entities).await?;
        Self::end_timer(stage2_timer, "Stage2_ai_resolution");
        
        // Stage 3: Structure entities with AI-suggested components
        let stage3_timer = Self::start_timer("Stage3_ai_structure");
        let structure_result = self.structure_stage_with_ai(&resolution_result, &extraction_result).await?;
        Self::end_timer(stage3_timer, "Stage3_ai_structure");
        
        // Stage 4: Assemble final result
        let stage4_timer = Self::start_timer("Stage4_assembly");
        let final_result = self.assemble_stage(&structure_result, user_id, chronicle_id).await?;
        Self::end_timer(stage4_timer, "Stage4_assembly");
        
        Self::end_timer(total_timer, "resolve_entities_multistage_TOTAL");
        Ok(final_result)
    }
    
    /// Stage 1: Extract entities and context from narrative
    async fn extract_stage(&self, narrative_text: &str) -> Result<ExtractionStageResult, ToolError> {
        // Run both extractions in parallel
        let context_future = self.extract_narrative_context(narrative_text);
        let names_future = self.extract_entity_names(narrative_text);
        
        let (context_result, names_result) = tokio::join!(context_future, names_future);
        
        let context = context_result?;
        let entity_names = names_result.unwrap_or_else(|e| {
            warn!("Failed to extract entity names separately: {}", e);
            context.entities.iter().map(|e| e.name.clone()).collect()
        });
        
        Ok(ExtractionStageResult {
            narrative_context: context,
            extracted_entity_names: entity_names,
            original_text: narrative_text.to_string(),
        })
    }
    
    /// Stage 2: Resolve entities using AI semantic matching
    async fn resolve_stage_with_ai(
        &self,
        extraction: &ExtractionStageResult,
        existing_entities: &[ExistingEntity],
    ) -> Result<ResolutionStageResult, ToolError> {
        let mut resolved_entities = Vec::new();
        let mut new_entities = Vec::new();
        
        // Prepare existing entities for semantic matching
        let existing_candidates: Vec<(String, String)> = existing_entities.iter()
            .map(|e| (
                e.name.clone(),
                e.context.clone().unwrap_or_else(|| format!("Type: {}", e.entity_type))
            ))
            .collect();
        
        // Process entities from rich context
        for narrative_entity in &extraction.narrative_context.entities {
            let context = format!(
                "Type: {}, Description: {}, Properties: {:?}",
                narrative_entity.entity_type,
                narrative_entity.description,
                narrative_entity.properties
            );
            
            // Use AI semantic matching instead of simple string comparison
            match self.semantic_matcher.find_semantic_match(
                &narrative_entity.name,
                &context,
                &existing_candidates,
            ).await {
                Ok(Some((index, confidence))) if confidence > 0.7 => {
                    // Found a confident match
                    let existing = &existing_entities[index];
                    debug!("AI matched '{}' to existing entity {} with confidence {}", 
                        narrative_entity.name, existing.entity_id, confidence);
                    
                    resolved_entities.push(ResolvedEntity {
                        entity_id: existing.entity_id,
                        name: narrative_entity.name.clone(),
                        display_name: existing.display_name.clone(),
                        entity_type: narrative_entity.entity_type.clone(),
                        is_new: false,
                        confidence,
                        context: Some(narrative_entity.description.clone()),
                        properties: narrative_entity.properties.clone(),
                    });
                }
                _ => {
                    // No confident match found - create new entity
                    debug!("AI found no match for '{}' - creating new entity", narrative_entity.name);
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
        
        Ok(ResolutionStageResult {
            resolved_entities,
            new_entities,
        })
    }
    
    /// Stage 3: Structure entities with AI-suggested components
    async fn structure_stage_with_ai(
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
        
        // Create structured entities with AI-suggested components
        for entity in &all_entities {
            // Use AI to suggest components based on full context
            let components = match self.component_suggester.suggest_components(
                entity,
                &extraction.narrative_context
            ).await {
                Ok(suggested) => suggested,
                Err(e) => {
                    warn!("AI component suggestion failed for {}: {}", entity.name, e);
                    // Fallback to basic components
                    vec!["Name".to_string(), "Position".to_string()]
                }
            };
            
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
        
        // Extract relationships from context (this part remains similar)
        relationships = self.extract_relationships_from_context(
            &extraction.narrative_context,
            &all_entities
        );
        
        Ok(StructureStageResult {
            structured_entities,
            relationships,
        })
    }
    
    /// Stage 4: Assemble final result
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
    
    /// Extract relationships from narrative context
    fn extract_relationships_from_context(
        &self,
        context: &NarrativeContext,
        entities: &[&ResolvedEntity],
    ) -> Vec<EntityRelationship> {
        let mut relationships = Vec::new();
        
        // Helper to find entity by name
        let find_entity = |name: &str| -> Option<&ResolvedEntity> {
            entities.iter().find(|e| e.name.eq_ignore_ascii_case(name)).copied()
        };
        
        // Extract spatial relationships
        for spatial_rel in &context.spatial_context.spatial_relationships {
            if let (Some(entity1), Some(entity2)) = (
                find_entity(&spatial_rel.entity1),
                find_entity(&spatial_rel.entity2),
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
        
        // Extract social relationships
        for social_rel in &context.social_context.relationships {
            if let (Some(entity1), Some(entity2)) = (
                find_entity(&social_rel.entity1),
                find_entity(&social_rel.entity2),
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
        
        relationships
    }
    
    /// Build prompt for context extraction
    fn build_context_extraction_prompt(&self, narrative_text: &str) -> String {
        format!(
            r#"Extract comprehensive context from this narrative text. Identify all entities, their relationships, spatial context, and actions.

NARRATIVE TEXT:
"{}"

Return a JSON object with this structure:
{{
  "entities": [
    {{
      "name": "entity_name",
      "type": "CHARACTER|LOCATION|ITEM|ORGANIZATION|CONCEPT",
      "description": "brief description based on narrative",
      "properties": ["property1", "property2"]
    }}
  ],
  "spatial_context": {{
    "primary_location": "main location",
    "secondary_locations": ["other locations"],
    "spatial_relationships": [
      {{"entity1": "A", "relationship": "inside|near|above|below", "entity2": "B"}}
    ]
  }},
  "temporal_context": {{
    "time_indicators": ["now", "morning", "yesterday"],
    "sequence_markers": ["first", "then", "finally"],
    "duration_hints": ["briefly", "for hours"]
  }},
  "social_context": {{
    "relationships": [
      {{"entity1": "A", "relationship": "friend|enemy|subordinate", "entity2": "B"}}
    ],
    "social_dynamics": ["tension", "cooperation"],
    "emotional_tone": "neutral|positive|negative"
  }},
  "actions_and_events": [
    {{
      "action": "action_verb",
      "agent": "who performed it",
      "target": "what was affected",
      "context": "additional context"
    }}
  ]
}}

Be thorough and extract all relevant context."#,
            narrative_text
        )
    }
    
    /// Parse entity names from AI response
    fn parse_entity_names_response(&self, ai_response: &str) -> Result<Vec<String>, ToolError> {
        // Extract JSON from potential markdown code blocks
        let json_content = if let Some(start) = ai_response.find("[") {
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
    
    /// Resolve actors to entities (for backward compatibility)
    pub async fn resolve_actors_to_entities(
        &self,
        actors: &[Value],
        chronicle_id: Option<Uuid>,
        user_id: Uuid,
        _processing_mode: ProcessingMode,
    ) -> Result<ActorResolutionResult, ToolError> {
        debug!("Resolving {} actors to entities using AI-driven approach", actors.len());

        // Extract entity names from actors
        let entity_names: Vec<String> = actors
            .iter()
            .filter_map(|actor| actor.get("name").and_then(|n| n.as_str()))
            .map(|s| s.to_string())
            .collect();

        if entity_names.is_empty() {
            return Ok(ActorResolutionResult {
                resolved_actors: json!([]),
                narrative_context: NarrativeContext {
                    entities: vec![],
                    spatial_context: SpatialContext {
                        primary_location: None,
                        secondary_locations: vec![],
                        spatial_relationships: vec![],
                    },
                    temporal_context: TemporalContext {
                        time_indicators: vec![],
                        sequence_markers: vec![],
                        duration_hints: vec![],
                    },
                    social_context: SocialContext {
                        relationships: vec![],
                        social_dynamics: vec![],
                        emotional_tone: "neutral".to_string(),
                    },
                    actions_and_events: vec![],
                },
            });
        }

        // Create a narrative text from the actors for context extraction
        let narrative_text = format!("Actors involved: {}", entity_names.join(", "));
        
        // Extract context
        let narrative_context = self.extract_narrative_context(&narrative_text).await
            .unwrap_or_else(|_| NarrativeContext {
                entities: vec![],
                spatial_context: SpatialContext {
                    primary_location: None,
                    secondary_locations: vec![],
                    spatial_relationships: vec![],
                },
                temporal_context: TemporalContext {
                    time_indicators: vec![],
                    sequence_markers: vec![],
                    duration_hints: vec![],
                },
                social_context: SocialContext {
                    relationships: vec![],
                    social_dynamics: vec![],
                    emotional_tone: "neutral".to_string(),
                },
                actions_and_events: vec![],
            });

        // For now, return the actors as-is (this is a simplified implementation)
        let resolved_actors = json!(actors);

        Ok(ActorResolutionResult {
            resolved_actors,
            narrative_context,
        })
    }
}

#[async_trait]
impl ScribeTool for EntityResolutionTool {
    fn name(&self) -> &'static str {
        "resolve_entities"
    }

    fn description(&self) -> &'static str {
        "AI-driven entity resolution that uses Flash/Flash-Lite for intelligent entity matching, \
         component suggestion, and context-aware decision making. No hardcoded rules."
    }

    fn input_schema(&self) -> Value {
        // Same schema as original tool
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
                        "type": "object"
                    },
                    "description": "Array of existing entities to match against"
                }
            },
            "required": ["user_id", "narrative_text", "entity_names"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven entity resolution tool with params: {}", params);

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

        // Get existing entities from the database if chronicle_id is provided
        let mut existing_entities = Vec::new();
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

                            existing_entities.push(ExistingEntity {
                                entity_id: entity.entity.id,
                                name: name.to_string(),
                                display_name: display_name.to_string(),
                                aliases,
                                entity_type: "UNKNOWN".to_string(), // We'll determine this from context
                                context: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch existing entities: {}", e);
                }
            }
        }

        debug!("Found {} existing entities", existing_entities.len());

        // Execute AI-driven multi-stage resolution
        let result = self.resolve_entities_multistage(
            narrative_text,
            user_id,
            chronicle_id,
            &existing_entities,
        ).await?;

        info!("AI-driven entity resolution completed successfully for {} entities", 
              result.resolved_entities.len());

        // Return the result as JSON
        Ok(serde_json::to_value(result)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize result: {}", e)))?)
    }
}