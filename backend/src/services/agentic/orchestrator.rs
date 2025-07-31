//! Defines the `WorkflowOrchestrator` for managing the agentic workflow.
//!
//! This orchestrator enforces a sequential execution model where each stage
//! must complete successfully before the next stage begins. This prevents
//! race conditions and ensures data dependencies are respected.

use std::sync::Arc;
use tracing::{error, info, warn, debug, instrument};
use uuid::Uuid;
use chrono::Utc;
use crate::errors::AppError;
use crate::auth::session_dek::SessionDek;

use super::{
    lightning_agent::LightningAgent,
    strategic_agent::StrategicAgent,
    tactical_agent::TacticalAgent,
    perception_agent::PerceptionAgent,
    executor::ToolExecutor,
    tools::{ToolError, ToolParams},
};
use crate::llm::AiClient;
use crate::services::progressive_cache::ProgressiveCacheService;
use crate::services::AgentResultsService;
use crate::models::agent_results::{AgentType, OperationType};

/// Represents the current state of the sequential agentic workflow.
#[derive(Debug, Clone, PartialEq)]
pub enum OrchestratorState {
    /// Initial state
    Start,
    
    /// Stage 1: Strategic Analysis - Analyze conversation and set directives
    StrategicAnalysis,
    
    /// Stage 2: Tactical Planning - Break down strategic goals into concrete actions
    TacticalPlanning,
    
    /// Stage 3: Entity Creation - Extract and persist entities from narrative
    EntityCreation,
    
    /// Stage 4: Relationship Building - Establish spatial/hierarchical relationships
    RelationshipBuilding,
    
    /// Stage 5: Cache Update - Enrich cache for next interaction
    CacheUpdate,
    
    /// Terminal state: Success
    Done,
    
    /// Terminal state: Failure with reason
    Failed(String),
}

/// Results from each stage to pass forward
#[derive(Debug, Clone)]
pub struct StageResults {
    pub strategic_directive: Option<crate::services::context_assembly_engine::StrategicDirective>,
    pub enriched_context: Option<crate::services::context_assembly_engine::EnrichedContext>,
    pub entities_created: Vec<String>,
    pub relationships_established: usize,
    pub cache_updated: bool,
}

impl Default for StageResults {
    fn default() -> Self {
        Self {
            strategic_directive: None,
            enriched_context: None,
            entities_created: Vec::new(),
            relationships_established: 0,
            cache_updated: false,
        }
    }
}

/// The `WorkflowOrchestrator` manages the lifecycle of the sequential agentic process.
///
/// It coordinates the different stages in strict order, ensuring each completes
/// before the next begins. This prevents race conditions and ensures proper
/// data flow between agents.
pub struct WorkflowOrchestrator {
    strategic_agent: Arc<StrategicAgent>,
    tactical_agent: Arc<TacticalAgent>,
    perception_agent: Arc<PerceptionAgent>,
    cache_service: Arc<ProgressiveCacheService>,
    tool_executor: Arc<ToolExecutor>,
    agent_results_service: Arc<AgentResultsService>,
}

impl WorkflowOrchestrator {
    /// Creates a new `WorkflowOrchestrator`.
    pub fn new(
        strategic_agent: Arc<StrategicAgent>,
        tactical_agent: Arc<TacticalAgent>,
        perception_agent: Arc<PerceptionAgent>,
        cache_service: Arc<ProgressiveCacheService>,
        tool_executor: Arc<ToolExecutor>,
        agent_results_service: Arc<AgentResultsService>,
    ) -> Self {
        Self {
            strategic_agent,
            tactical_agent,
            perception_agent,
            cache_service,
            tool_executor,
            agent_results_service,
        }
    }

    /// Runs the entire sequential agentic workflow.
    ///
    /// Each stage must complete successfully before the next begins.
    /// Failed stages will terminate the workflow.
    #[instrument(skip(self, chat_history, session_dek), fields(user_id = %user_id, session_id = %session_id, chronicle_id = ?chronicle_id))]
    pub async fn run(
        &self,
        chat_history: &[crate::models::chats::ChatMessageForClient],
        user_id: Uuid,
        session_id: Uuid,
        session_dek: &SessionDek,
        current_message: &str,
        ai_response: &str,
        chronicle_id: Option<Uuid>,
    ) -> Result<StageResults, AppError> {
        info!("Starting sequential agentic workflow");
        let workflow_start = std::time::Instant::now();
        
        let mut state = OrchestratorState::Start;
        let mut results = StageResults::default();
        
        // Create extended history with AI response for background processing
        let mut extended_history = chat_history.to_vec();
        extended_history.push(crate::models::chats::ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            message_type: crate::models::chats::MessageRole::Assistant,
            content: ai_response.to_string(),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "gemini-2.5-flash".to_string(),
        });
        
        // Execute stages in strict sequence
        loop {
            let stage_start = std::time::Instant::now();
            
            state = match state {
                OrchestratorState::Start => {
                    info!("Beginning orchestration sequence");
                    OrchestratorState::StrategicAnalysis
                }
                
                OrchestratorState::StrategicAnalysis => {
                    self.execute_strategic_analysis(
                        &extended_history,
                        user_id,
                        session_id,
                        session_dek,
                        &mut results
                    ).await?
                }
                
                OrchestratorState::TacticalPlanning => {
                    self.execute_tactical_planning(
                        user_id,
                        session_id,
                        session_dek,
                        chronicle_id,
                        &mut results
                    ).await?
                }
                
                OrchestratorState::EntityCreation => {
                    self.execute_entity_creation(
                        &extended_history,
                        current_message,
                        user_id,
                        session_id,
                        session_dek,
                        &mut results
                    ).await?
                }
                
                OrchestratorState::RelationshipBuilding => {
                    self.execute_relationship_building(
                        user_id,
                        session_dek,
                        &mut results
                    ).await?
                }
                
                OrchestratorState::CacheUpdate => {
                    self.execute_cache_update(
                        session_id,
                        &mut results
                    ).await?
                }
                
                OrchestratorState::Done => {
                    let workflow_duration = workflow_start.elapsed().as_millis() as u64;
                    info!(
                        "Orchestration completed successfully in {}ms. \
                        Entities created: {}, Relationships: {}, Cache updated: {}",
                        workflow_duration,
                        results.entities_created.len(),
                        results.relationships_established,
                        results.cache_updated
                    );
                    break;
                }
                
                OrchestratorState::Failed(ref reason) => {
                    error!("Orchestration failed: {}", reason);
                    return Err(AppError::InternalServerErrorGeneric(
                        format!("Orchestration failed: {}", reason)
                    ));
                }
            };
            
            let stage_duration = stage_start.elapsed().as_millis() as u64;
            debug!("Stage {:?} completed in {}ms", state, stage_duration);
        }
        
        Ok(results)
    }
    
    /// Stage 1: Strategic Analysis
    #[instrument(skip(self, chat_history, session_dek, results))]
    async fn execute_strategic_analysis(
        &self,
        chat_history: &[crate::models::chats::ChatMessageForClient],
        user_id: Uuid,
        session_id: Uuid,
        session_dek: &SessionDek,
        results: &mut StageResults,
    ) -> Result<OrchestratorState, AppError> {
        info!("Stage 1: Executing strategic analysis");
        let start_time = std::time::Instant::now();
        
        match self.strategic_agent
            .analyze_conversation(chat_history, user_id, session_id, session_dek)
            .await
        {
            Ok(directive) => {
                info!("Strategic analysis successful: {:?}", directive.directive_type);
                
                // Store strategic analysis results in PostgreSQL for lightning agent retrieval
                let result_data = serde_json::json!({
                    "directive_type": directive.directive_type,
                    "narrative_arc": directive.narrative_arc,
                    "plot_significance": format!("{:?}", directive.plot_significance),
                    "emotional_tone": directive.emotional_tone,
                    "character_focus": directive.character_focus,
                    "world_impact_level": format!("{:?}", directive.world_impact_level)
                });
                
                let metadata = serde_json::json!({
                    "messages_analyzed": chat_history.len(),
                    "processing_time_ms": start_time.elapsed().as_millis(),
                    "stage": "strategic_analysis"
                });
                
                // Store the result (non-blocking, log errors but don't fail the pipeline)
                if let Err(e) = self.agent_results_service.store_agent_result(
                    user_id,
                    session_id,
                    None, // No specific message_id for strategic analysis
                    AgentType::Strategic,
                    OperationType::StrategicDirective,
                    result_data,
                    Some(metadata),
                    start_time.elapsed().as_millis() as i32,
                    None, // TODO: Add token counting
                    None, // TODO: Add confidence scoring for strategic directive
                    Some("strategic".to_string()),
                    Some(format!("strategic_{}", Utc::now().timestamp())),
                    session_dek,
                ).await {
                    warn!("Failed to store strategic analysis results: {}", e);
                }
                
                results.strategic_directive = Some(directive);
                Ok(OrchestratorState::TacticalPlanning)
            }
            Err(e) => {
                error!("Strategic analysis failed: {}", e);
                Ok(OrchestratorState::Failed(format!("Strategic analysis failed: {}", e)))
            }
        }
    }
    
    /// Stage 2: Tactical Planning
    #[instrument(skip(self, session_dek, results), fields(chronicle_id = ?chronicle_id))]
    async fn execute_tactical_planning(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        session_dek: &SessionDek,
        chronicle_id: Option<Uuid>,
        results: &mut StageResults,
    ) -> Result<OrchestratorState, AppError> {
        info!("Stage 2: Executing tactical planning");
        let start_time = std::time::Instant::now();
        
        let directive = results.strategic_directive.as_ref()
            .ok_or_else(|| AppError::InternalServerErrorGeneric(
                "No strategic directive available for tactical planning".to_string()
            ))?;
        
        match self.tactical_agent
            .process_directive(directive, user_id, session_dek, chronicle_id)
            .await
        {
            Ok(context) => {
                info!("Tactical planning successful, entities involved: {}", 
                    context.relevant_entities.len());
                
                // Store tactical planning results in PostgreSQL for lightning agent retrieval
                let result_data = serde_json::json!({
                    "relevant_entities_count": context.relevant_entities.len(),
                    "has_spatial_context": context.spatial_context.is_some(),
                    "has_temporal_context": context.temporal_context.is_some(),
                    "has_causal_context": context.causal_context.is_some(),
                    "validated_plan": {
                        "plan_id": context.validated_plan.plan_id,
                        "steps_count": context.validated_plan.steps.len(),
                        "preconditions_met": context.validated_plan.preconditions_met,
                        "causal_consistency_verified": context.validated_plan.causal_consistency_verified,
                        "entity_dependencies": context.validated_plan.entity_dependencies
                    },
                    "current_sub_goal": {
                        "goal_id": context.current_sub_goal.goal_id,
                        "description": context.current_sub_goal.description,
                        "priority_level": context.current_sub_goal.priority_level
                    },
                    "plan_validation_status": format!("{:?}", context.plan_validation_status)
                });
                
                let metadata = serde_json::json!({
                    "entities_count": context.relevant_entities.len(),
                    "plan_steps_count": context.validated_plan.steps.len(),
                    "processing_time_ms": start_time.elapsed().as_millis(),
                    "stage": "tactical_planning",
                    "source_directive": format!("{:?}", directive.directive_type),
                    "has_perception_analysis": context.perception_analysis.is_some()
                });
                
                // Store the result (non-blocking, log errors but don't fail the pipeline)
                if let Err(e) = self.agent_results_service.store_agent_result(
                    user_id,
                    session_id,
                    None, // No specific message_id for tactical planning
                    AgentType::Tactical,
                    OperationType::TacticalPlanning,
                    result_data,
                    Some(metadata),
                    start_time.elapsed().as_millis() as i32,
                    None, // TODO: Add token counting
                    None, // TODO: Add confidence scoring for tactical planning
                    Some("tactical".to_string()),
                    Some(format!("tactical_{}", Utc::now().timestamp())),
                    session_dek,
                ).await {
                    warn!("Failed to store tactical planning results: {}", e);
                }
                
                results.enriched_context = Some(context);
                Ok(OrchestratorState::EntityCreation)
            }
            Err(e) => {
                error!("Tactical planning failed: {}", e);
                Ok(OrchestratorState::Failed(format!("Tactical planning failed: {}", e)))
            }
        }
    }
    
    /// Stage 3: Entity Creation
    #[instrument(skip(self, chat_history, session_dek, results))]
    async fn execute_entity_creation(
        &self,
        chat_history: &[crate::models::chats::ChatMessageForClient],
        current_message: &str,
        user_id: Uuid,
        session_id: Uuid,
        session_dek: &SessionDek,
        results: &mut StageResults,
    ) -> Result<OrchestratorState, AppError> {
        info!("Stage 3: Executing entity creation");
        let start_time = std::time::Instant::now();
        
        // Run fresh perception analysis to extract entities
        let perception_result = self.perception_agent
            .analyze_pre_response(chat_history, current_message, user_id, session_dek)
            .await?;
        
        if perception_result.contextual_entities.is_empty() {
            info!("No entities to create, skipping to cache update");
            
            // Still store the perception result even if no entities were found
            let result_data = serde_json::json!({
                "contextual_entities": [],
                "hierarchy_analysis": perception_result.hierarchy_analysis,
                "salience_updates": perception_result.salience_updates,
                "confidence_score": perception_result.confidence_score,
                "entities_created": 0
            });
            
            let metadata = serde_json::json!({
                "messages_analyzed": chat_history.len(),
                "current_message_length": current_message.len(),
                "processing_time_ms": start_time.elapsed().as_millis(),
                "stage": "entity_creation"
            });
            
            if let Err(e) = self.agent_results_service.store_agent_result(
                user_id,
                session_id,
                None, // No specific message_id for perception analysis
                AgentType::Perception,
                OperationType::EntityExtraction,
                result_data,
                Some(metadata),
                start_time.elapsed().as_millis() as i32,
                None, // TODO: Add token counting
                None, // TODO: Add confidence scoring
                Some("entity".to_string()),
                Some(format!("perception_{}", Utc::now().timestamp())),
                session_dek,
            ).await {
                warn!("Failed to store perception analysis results: {}", e);
            }
            
            return Ok(OrchestratorState::CacheUpdate);
        }
        
        info!("Creating {} entities", perception_result.contextual_entities.len());
        
        // Ensure all entities exist in the system
        match self.perception_agent
            .ensure_entities_exist(&perception_result.contextual_entities, user_id, session_dek)
            .await
        {
            Ok(_) => {
                results.entities_created = perception_result.contextual_entities
                    .iter()
                    .map(|e| e.name.clone())
                    .collect();
                
                // Store perception analysis results in PostgreSQL for lightning agent retrieval
                let result_data = serde_json::json!({
                    "contextual_entities": perception_result.contextual_entities.iter().map(|e| serde_json::json!({
                        "name": e.name,
                        "entity_type": e.entity_type,
                        "relevance_score": e.relevance_score
                    })).collect::<Vec<_>>(),
                    "hierarchy_analysis": perception_result.hierarchy_analysis,
                    "salience_updates": perception_result.salience_updates,
                    "confidence_score": perception_result.confidence_score,
                    "entities_created": results.entities_created.len()
                });
                
                let metadata = serde_json::json!({
                    "messages_analyzed": chat_history.len(),
                    "current_message_length": current_message.len(),
                    "entities_extracted": perception_result.contextual_entities.len(),
                    "entities_created": results.entities_created.len(),
                    "processing_time_ms": start_time.elapsed().as_millis(),
                    "stage": "entity_creation"
                });
                
                // Store the result (non-blocking, log errors but don't fail the pipeline)
                if let Err(e) = self.agent_results_service.store_agent_result(
                    user_id,
                    session_id,
                    None, // No specific message_id for perception analysis
                    AgentType::Perception,
                    OperationType::EntityExtraction,
                    result_data,
                    Some(metadata),
                    start_time.elapsed().as_millis() as i32,
                    None, // TODO: Add token counting
                    None, // TODO: Add confidence scoring
                    Some("entity".to_string()),
                    Some(format!("perception_{}", Utc::now().timestamp())),
                    session_dek,
                ).await {
                    warn!("Failed to store perception analysis results: {}", e);
                }
                
                info!("Successfully created {} entities", results.entities_created.len());
                Ok(OrchestratorState::RelationshipBuilding)
            }
            Err(e) => {
                error!("Entity creation failed: {}", e);
                Ok(OrchestratorState::Failed(format!("Entity creation failed: {}", e)))
            }
        }
    }
    
    /// Stage 4: Relationship Building
    #[instrument(skip(self, session_dek, results))]
    async fn execute_relationship_building(
        &self,
        user_id: Uuid,
        session_dek: &SessionDek,
        results: &mut StageResults,
    ) -> Result<OrchestratorState, AppError> {
        info!("Stage 4: Executing relationship building");
        
        if results.entities_created.is_empty() {
            info!("No entities created, skipping relationship building");
            return Ok(OrchestratorState::CacheUpdate);
        }
        
        // Establish spatial relationships between entities
        match self.perception_agent
            .establish_all_spatial_relationships(user_id, session_dek)
            .await
        {
            Ok(_) => {
                // TODO: Get actual count of relationships established
                results.relationships_established = results.entities_created.len(); // Placeholder
                info!("Successfully established spatial relationships");
                Ok(OrchestratorState::CacheUpdate)
            }
            Err(e) => {
                // Non-fatal: Log but continue
                warn!("Relationship building failed (non-fatal): {}", e);
                Ok(OrchestratorState::CacheUpdate)
            }
        }
    }
    
    /// Stage 5: Cache Update
    #[instrument(skip(self, results))]
    async fn execute_cache_update(
        &self,
        session_id: Uuid,
        results: &mut StageResults,
    ) -> Result<OrchestratorState, AppError> {
        info!("Stage 5: Executing cache update");
        
        if let Some(context) = &results.enriched_context {
            // Convert enriched context to cache format
            let entities = context.relevant_entities
                .iter()
                .map(|e| crate::services::progressive_cache::EntitySummary {
                    entity_id: e.entity_id,
                    name: e.entity_name.clone(),
                    description: format!("Entity with importance {}", e.narrative_importance),
                    entity_type: e.entity_type.clone(),
                })
                .collect();
            
            // Create a location from spatial context or use a default
            let location = if let Some(_spatial) = &context.spatial_context {
                crate::services::progressive_cache::Location {
                    location_id: Uuid::new_v4(),
                    name: "Current Location".to_string(),
                    description: "Enriched from tactical planning".to_string(),
                    scale: "area".to_string(),
                }
            } else {
                crate::services::progressive_cache::Location {
                    location_id: Uuid::new_v4(),
                    name: "Unknown Location".to_string(),
                    description: "No spatial context available".to_string(),
                    scale: "unknown".to_string(),
                }
            };
            
            match self.cache_service
                .update_enhanced_context(session_id, entities, location)
                .await
            {
                Ok(_) => {
                    info!("Cache successfully updated");
                    results.cache_updated = true;
                }
                Err(e) => {
                    // Non-fatal: Log but continue
                    warn!("Cache update failed (non-fatal): {}", e);
                }
            }
        }
        
        Ok(OrchestratorState::Done)
    }
}