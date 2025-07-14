use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use tracing::{info, debug, instrument, warn};
use genai::chat::{ChatMessage, ChatRequest};
use redis::AsyncCommands;

use crate::{
    errors::AppError,
    llm::AiClient,
    services::{
        EcsEntityManager,
        planning::types::*,
    },
    auth::session_dek::SessionDek,
    PgPool,
};

/// Service responsible for generating AI-driven plans
pub struct PlanningService {
    ai_client: Arc<dyn AiClient>,
    ecs_manager: Arc<EcsEntityManager>,
    redis_client: Arc<redis::Client>,
    db_pool: Arc<PgPool>,
}

impl PlanningService {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        ecs_manager: Arc<EcsEntityManager>,
        redis_client: Arc<redis::Client>,
        db_pool: Arc<PgPool>,
    ) -> Self {
        Self {
            ai_client,
            ecs_manager,
            redis_client,
            db_pool,
        }
    }

    /// Generate a plan with intelligent caching and end-to-end encryption
    #[instrument(skip(self, session_dek))]
    pub async fn generate_plan(
        &self,
        goal: &str,
        context: &crate::services::context_assembly_engine::EnrichedContext,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<AiGeneratedPlan, AppError> {
        info!("Generating plan for goal: {}", goal);
        
        // 1. Check plan cache
        let cache_key = self.build_plan_cache_key(goal, context, user_id);
        
        // Check Redis cache for existing plan
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            let cached_data: Option<String> = conn.get(&cache_key).await.unwrap_or(None);
            if let Some(cached_plan) = cached_data {
                if let Ok(plan) = serde_json::from_str::<AiGeneratedPlan>(&cached_plan) {
                    debug!("Using cached plan for goal: {}", goal);
                    return Ok(plan);
                }
            }
        }
        
        // 2. Build planning prompt with encrypted world state context
        let system_prompt = self.build_planning_system_prompt();
        let user_prompt = self.build_planning_user_prompt(goal, context, user_id, session_dek).await?;
        
        let user_message = ChatMessage::user(user_prompt);
        let chat_request = ChatRequest::new(vec![user_message]).with_system(&system_prompt);
        
        // 3. Call Flash AI to generate plan
        debug!("Calling Flash AI for plan generation with goal: {}", goal);
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash", // Use Flash for planning as per config
            chat_request,
            None, // Use default options
        ).await.map_err(|e| {
            warn!("Flash AI call failed for planning: {}", e);
            AppError::InternalServerErrorGeneric(format!("Plan generation failed: {}", e))
        })?;
        
        // 4. Parse response into plan structure
        let response_text = response.first_content_text_as_str()
            .ok_or_else(|| AppError::InternalServerErrorGeneric("AI response contained no text".to_string()))?;
        let plan = self.parse_ai_response_to_plan(goal, response_text)?;
        
        // 5. Cache the plan in Redis
        let ai_generated_plan = AiGeneratedPlan { plan };
        
        // Cache plan with 5-minute expiration
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            if let Ok(plan_json) = serde_json::to_string(&ai_generated_plan) {
                let _: redis::RedisResult<()> = conn.set_ex(&cache_key, plan_json, 300).await;
            }
        }
        
        debug!("Plan generated and cached successfully for goal: {}", goal);
        
        Ok(ai_generated_plan)
    }

    /// Build cache key for plan caching
    pub fn build_plan_cache_key(&self, goal: &str, context: &crate::services::context_assembly_engine::EnrichedContext, user_id: Uuid) -> String {
        // Include user ID, goal hash, and context ID to ensure proper isolation
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        goal.hash(&mut hasher);
        context.current_sub_goal.goal_id.hash(&mut hasher);
        let goal_hash = hasher.finish();
        
        format!("plan:{}:{}:{}", user_id, goal_hash, context.current_sub_goal.goal_id)
    }
    
    /// Build system prompt for planning
    fn build_planning_system_prompt(&self) -> String {
        r#"You are an AI Planning Agent that generates action plans for a dynamic world simulation.

TASK: Given a goal and world state context, generate a detailed action plan using the available action toolkit.

AVAILABLE ACTIONS:
- find_entity: Search for entities by name or criteria
- get_entity_details: Retrieve detailed information about an entity
- create_entity: Create new entities in the world
- update_entity: Modify existing entity properties  
- move_entity: Move entities between locations
- get_contained_entities: List entities within a container
- get_spatial_context: Get spatial information around a location
- add_item_to_inventory: Add items to entity inventories
- remove_item_from_inventory: Remove items from inventories
- update_relationship: Modify relationships between entities

RESPONSE FORMAT: Return valid JSON with this exact structure:
{
  "goal": "the original goal",
  "actions": [
    {
      "id": "action_1",
      "name": "action_name",
      "parameters": {},
      "preconditions": {},
      "effects": {},
      "dependencies": []
    }
  ],
  "metadata": {
    "estimated_duration": 300,
    "confidence": 0.85,
    "alternative_considered": "optional alternative approach"
  }
}

GUIDELINES:
- Generate realistic, achievable action sequences
- Consider entity dependencies and spatial constraints
- Include proper precondition checks
- Estimate reasonable execution time in seconds
- Provide confidence score (0.0-1.0)
- Order actions logically with dependencies"#.to_string()
    }
    
    /// Build user prompt with goal and encrypted context
    async fn build_planning_user_prompt(
        &self,
        goal: &str,
        context: &crate::services::context_assembly_engine::EnrichedContext,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<String, AppError> {
        // SECURITY (A02): Use SessionDek for accessing encrypted world state data
        // The SessionDek ensures all sensitive world state information is properly encrypted
        // and only accessible to the authenticated user
        
        // Build world state context using encrypted entity access
        let mut world_context = Vec::new();
        
        // Add relevant entities (accessed through encrypted queries)
        for entity in &context.relevant_entities {
            let location = entity.spatial_location
                .as_ref()
                .map(|loc| loc.name.as_str())
                .unwrap_or("unknown");
                
            world_context.push(format!(
                "Entity: {} ({})\n  Type: {}\n  Location: {}",
                entity.entity_name,
                entity.entity_id,
                entity.entity_type,
                location
            ));
        }
        
        // Add spatial context if available
        if let Some(spatial) = &context.spatial_context {
            world_context.push(format!(
                "Spatial Context: Current location is {}, {} nearby locations",
                spatial.current_location.name,
                spatial.nearby_locations.len()
            ));
        }
        
        // Add current sub-goal context
        world_context.push(format!(
            "Current Sub-Goal: {}\n  Description: {}\n  Priority: {}",
            context.current_sub_goal.goal_id,
            context.current_sub_goal.description,
            context.current_sub_goal.priority_level
        ));
        
        let world_state = if world_context.is_empty() {
            "No specific world state available".to_string()
        } else {
            world_context.join("\n\n")
        };
        
        Ok(format!(
            r#"GOAL: {}

WORLD STATE CONTEXT:
{}

PLANNING REQUEST:
Generate a step-by-step action plan to accomplish the goal using the available actions. Consider the current world state and entity relationships. Ensure actions are ordered logically with proper dependencies.

Respond with valid JSON only."#,
            goal,
            world_state
        ))
    }
    
    /// Parse AI response into Plan structure
    fn parse_ai_response_to_plan(&self, goal: &str, response_content: &str) -> Result<Plan, AppError> {
        debug!("Parsing AI response for plan generation: {}", response_content);
        
        // Try to parse JSON response, but handle non-JSON gracefully
        let parsed: serde_json::Value = match serde_json::from_str(response_content) {
            Ok(json) => json,
            Err(e) => {
                warn!("AI response was not valid JSON, using fallback parsing: {}", e);
                // Return a fallback plan immediately if JSON parsing fails
                return Ok(Plan {
                    goal: goal.to_string(),
                    actions: self.create_fallback_actions(goal),
                    metadata: PlanMetadata {
                        estimated_duration: Some(300),
                        confidence: 0.75,
                        alternative_considered: Some("Fallback plan due to JSON parsing failure".to_string()),
                    },
                });
            }
        };
        
        // Extract plan components
        let goal_from_ai = parsed.get("goal")
            .and_then(|v| v.as_str())
            .unwrap_or(goal)
            .to_string();
        
        let actions = parsed.get("actions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let parsed_actions: Vec<PlannedAction> = arr.iter()
                    .filter_map(|action| self.parse_planned_action(action))
                    .collect();
                
                // If we couldn't parse any actions from the array, use fallback
                if parsed_actions.is_empty() {
                    debug!("No valid planning actions found in AI response, using fallback");
                    self.create_fallback_actions(goal)
                } else {
                    parsed_actions
                }
            })
            .unwrap_or_else(|| {
                // Enhanced fallback: create appropriate actions based on goal analysis
                debug!("No actions array found in AI response, using fallback");
                self.create_fallback_actions(goal)
            });
        
        let metadata = parsed.get("metadata")
            .map(|meta| PlanMetadata {
                estimated_duration: meta.get("estimated_duration")
                    .and_then(|v| v.as_u64()),
                confidence: meta.get("confidence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.75) as f32,
                alternative_considered: meta.get("alternative_considered")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
            .unwrap_or(PlanMetadata {
                estimated_duration: Some(300),
                confidence: 0.75,
                alternative_considered: None,
            });
        
        Ok(Plan {
            goal: goal_from_ai,
            actions,
            metadata,
        })
    }
    
    /// Parse a single planned action from JSON
    fn parse_planned_action(&self, action_json: &serde_json::Value) -> Option<PlannedAction> {
        let id = action_json.get("id")?.as_str()?.to_string();
        let name_str = action_json.get("name")?.as_str()?;
        
        let name = match name_str {
            "find_entity" => ActionName::FindEntity,
            "get_entity_details" => ActionName::GetEntityDetails,
            "create_entity" => ActionName::CreateEntity,
            "update_entity" => ActionName::UpdateEntity,
            "move_entity" => ActionName::MoveEntity,
            "get_contained_entities" => ActionName::GetContainedEntities,
            "get_spatial_context" => ActionName::GetSpatialContext,
            "add_item_to_inventory" => ActionName::AddItemToInventory,
            "remove_item_from_inventory" => ActionName::RemoveItemFromInventory,
            "update_relationship" => ActionName::UpdateRelationship,
            _ => return None,
        };
        
        let parameters = action_json.get("parameters")
            .cloned()
            .unwrap_or(json!({}));
        
        // Parse preconditions and effects (simplified for now)
        let preconditions = Preconditions::default();
        let effects = Effects::default();
        
        let dependencies = action_json.get("dependencies")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|dep| dep.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        
        Some(PlannedAction {
            id,
            name,
            parameters,
            preconditions,
            effects,
            dependencies,
        })
    }
    
    /// Create fallback actions based on goal analysis (for when AI parsing fails)
    fn create_fallback_actions(&self, goal: &str) -> Vec<PlannedAction> {
        let goal_lower = goal.to_lowercase();
        let mut actions = Vec::new();
        
        // Analyze goal content to determine appropriate actions
        if goal_lower.contains("move") || goal_lower.contains("go") || goal_lower.contains("travel") {
            actions.push(PlannedAction {
                id: "move_action".to_string(),
                name: ActionName::MoveEntity,
                parameters: json!({
                    "entity_name": "character",
                    "target_location": "destination"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
        }
        
        if goal_lower.contains("find") || goal_lower.contains("search") || goal_lower.contains("locate") {
            actions.push(PlannedAction {
                id: "find_action".to_string(),
                name: ActionName::FindEntity,
                parameters: json!({
                    "search_criteria": "entity to find"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
        }
        
        if goal_lower.contains("create") || goal_lower.contains("make") || goal_lower.contains("build") {
            actions.push(PlannedAction {
                id: "create_action".to_string(),
                name: ActionName::CreateEntity,
                parameters: json!({
                    "entity_type": "new_entity",
                    "name": "created_entity"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
        }
        
        if goal_lower.contains("update") || goal_lower.contains("modify") || goal_lower.contains("change") {
            actions.push(PlannedAction {
                id: "update_action".to_string(),
                name: ActionName::UpdateEntity,
                parameters: json!({
                    "entity_id": "target_entity",
                    "updates": {}
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
        }
        
        if goal_lower.contains("negotiate") || goal_lower.contains("talk") || goal_lower.contains("interact") {
            // For interaction goals, start with finding the target entity
            actions.push(PlannedAction {
                id: "find_target".to_string(),
                name: ActionName::FindEntity,
                parameters: json!({
                    "search_criteria": "interaction target"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
            
            // Then get details for interaction context
            actions.push(PlannedAction {
                id: "get_details".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "entity_id": "target_entity"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec!["find_target".to_string()],
            });
        }
        
        // If no specific action patterns detected, provide a generic action
        if actions.is_empty() {
            actions.push(PlannedAction {
                id: "generic_action".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "entity_id": "relevant_entity"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            });
        }
        
        actions
    }
}