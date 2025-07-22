use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::{
    errors::AppError,
    services::agentic::tools::ScribeTool,
};

/// Intelligent World State Planner
/// 
/// This module handles intelligent planning of world state updates based on narrative implications.
/// Instead of simply creating entities if they don't exist, it:
/// 1. Analyzes what operations are needed (create, update, move, upgrade)
/// 2. Checks existing state before deciding actions
/// 3. Plans operation sequences with proper dependencies
/// 4. Tracks decisions for queryability
pub struct IntelligentWorldStatePlanner {
    decision_log: Vec<PlanningDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningDecision {
    pub decision_type: String,
    pub entity: String,
    pub reasoning: String,
    pub action_taken: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligentWorldPlan {
    pub plan_id: Uuid,
    pub phases: Vec<PlanPhase>,
    pub decisions: Vec<PlanningDecision>,
    pub estimated_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanPhase {
    pub phase_name: String,
    pub description: String,
    pub actions: Vec<IntelligentAction>,
    pub dependencies: Vec<String>, // Previous phases that must complete
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligentAction {
    pub action_id: String,
    pub action_type: IntelligentActionType,
    pub target_entity: String,
    pub parameters: Value,
    pub preconditions: Vec<Precondition>,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntelligentActionType {
    CreateEntity,
    UpdateEntity,
    MoveEntity,
    UpgradeItem,
    AddToInventory,
    RemoveFromInventory,
    EstablishRelationship,
    UpdateRelationship,
    QueryState, // For checking current state
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precondition {
    pub condition_type: String,
    pub entity: String,
    pub requirement: String,
}

/// Narrative implications extracted from text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeImplications {
    pub entities_mentioned: Vec<EntityMention>,
    pub actions_implied: Vec<ImpliedAction>,
    pub spatial_changes: Vec<SpatialChange>,
    pub item_changes: Vec<ItemChange>,
    pub relationship_changes: Vec<RelationshipChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMention {
    pub name: String,
    pub entity_type: String,
    pub context: String,
    pub properties_mentioned: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpliedAction {
    pub action_type: String,
    pub actor: String,
    pub target: Option<String>,
    pub details: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialChange {
    pub entity: String,
    pub from_location: Option<String>,
    pub to_location: String,
    pub movement_type: String, // "move", "teleport", "enter", "exit"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemChange {
    pub entity: String,
    pub item: String,
    pub change_type: String, // "acquire", "lose", "upgrade", "use"
    pub properties: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipChange {
    pub source: String,
    pub target: String,
    pub relationship_type: String,
    pub change: String, // "establish", "strengthen", "weaken", "break"
    pub trust_delta: Option<f32>,
}

impl IntelligentWorldStatePlanner {
    pub fn new() -> Self {
        Self {
            decision_log: Vec::new(),
        }
    }

    /// Analyze narrative text for world state implications
    pub async fn analyze_narrative_implications(
        &mut self,
        narrative: &str,
        context: &HashMap<String, Value>,
    ) -> Result<NarrativeImplications, AppError> {
        // This would use AI to extract structured implications from the narrative
        // For now, a placeholder that shows the structure
        info!("Analyzing narrative for intelligent world state implications");
        
        // TODO: Implement AI-based narrative analysis
        // This should extract:
        // 1. All entities mentioned with their contexts
        // 2. Actions that imply state changes
        // 3. Spatial movements or location changes
        // 4. Item acquisitions, upgrades, or losses
        // 5. Relationship establishment or changes
        
        Ok(NarrativeImplications {
            entities_mentioned: vec![],
            actions_implied: vec![],
            spatial_changes: vec![],
            item_changes: vec![],
            relationship_changes: vec![],
        })
    }

    /// Generate an intelligent plan based on narrative implications
    pub async fn plan_world_updates(
        &mut self,
        implications: &NarrativeImplications,
        user_id: Uuid,
        get_tool: impl Fn(&str) -> Result<Arc<dyn ScribeTool>, AppError>,
    ) -> Result<IntelligentWorldPlan, AppError> {
        let mut phases = Vec::new();
        let plan_id = Uuid::new_v4();
        
        // Phase 1: Ensure all mentioned entities exist
        let entity_phase = self.plan_entity_creation_phase(
            &implications.entities_mentioned,
            user_id,
            &get_tool,
        ).await?;
        if !entity_phase.actions.is_empty() {
            phases.push(entity_phase);
        }
        
        // Phase 2: Handle spatial changes (movements)
        let spatial_phase = self.plan_spatial_changes_phase(
            &implications.spatial_changes,
            user_id,
            &get_tool,
        ).await?;
        if !spatial_phase.actions.is_empty() {
            phases.push(spatial_phase);
        }
        
        // Phase 3: Handle item changes
        let item_phase = self.plan_item_changes_phase(
            &implications.item_changes,
            user_id,
            &get_tool,
        ).await?;
        if !item_phase.actions.is_empty() {
            phases.push(item_phase);
        }
        
        // Phase 4: Handle relationship changes
        let relationship_phase = self.plan_relationship_changes_phase(
            &implications.relationship_changes,
            user_id,
            &get_tool,
        ).await?;
        if !relationship_phase.actions.is_empty() {
            phases.push(relationship_phase);
        }
        
        let estimated_duration_ms = phases.iter()
            .flat_map(|p| &p.actions)
            .count() as u64 * 100;
        
        Ok(IntelligentWorldPlan {
            plan_id,
            phases,
            decisions: self.decision_log.clone(),
            estimated_duration_ms,
        })
    }
    
    /// Plan entity creation/update phase
    async fn plan_entity_creation_phase(
        &mut self,
        entities: &[EntityMention],
        user_id: Uuid,
        get_tool: &impl Fn(&str) -> Result<Arc<dyn ScribeTool>, AppError>,
    ) -> Result<PlanPhase, AppError> {
        let mut actions = Vec::new();
        
        for entity in entities {
            // Check if entity exists
            let find_params = json!({
                "user_id": user_id.to_string(),
                "criteria": {
                    "type": "ByName",
                    "name": entity.name
                },
                "limit": 1
            });
            
            match get_tool("find_entity")?.execute(&find_params).await {
                Ok(result) => {
                    if let Some(entities_array) = result.get("entities").and_then(|e| e.as_array()) {
                        if let Some(existing) = entities_array.first() {
                            // Entity exists - check if we need to update it
                            let needs_update = self.check_if_entity_needs_update(
                                existing,
                                &entity.properties_mentioned,
                            );
                            
                            if needs_update {
                                self.log_decision(PlanningDecision {
                                    decision_type: "entity_update".to_string(),
                                    entity: entity.name.clone(),
                                    reasoning: format!(
                                        "Entity '{}' exists but has new properties mentioned in narrative",
                                        entity.name
                                    ),
                                    action_taken: "update_entity".to_string(),
                                    dependencies: vec![],
                                });
                                
                                actions.push(IntelligentAction {
                                    action_id: format!("update_entity_{}", entity.name),
                                    action_type: IntelligentActionType::UpdateEntity,
                                    target_entity: entity.name.clone(),
                                    parameters: json!({
                                        "updates": entity.properties_mentioned
                                    }),
                                    preconditions: vec![],
                                    expected_outcome: format!("Entity '{}' updated with new properties", entity.name),
                                });
                            } else {
                                self.log_decision(PlanningDecision {
                                    decision_type: "entity_exists".to_string(),
                                    entity: entity.name.clone(),
                                    reasoning: format!(
                                        "Entity '{}' already exists with required properties",
                                        entity.name
                                    ),
                                    action_taken: "none".to_string(),
                                    dependencies: vec![],
                                });
                            }
                        } else {
                            // Entity doesn't exist - create it
                            self.log_decision(PlanningDecision {
                                decision_type: "entity_creation".to_string(),
                                entity: entity.name.clone(),
                                reasoning: format!(
                                    "Entity '{}' mentioned in narrative but doesn't exist",
                                    entity.name
                                ),
                                action_taken: "create_entity".to_string(),
                                dependencies: vec![],
                            });
                            
                            actions.push(IntelligentAction {
                                action_id: format!("create_entity_{}", entity.name),
                                action_type: IntelligentActionType::CreateEntity,
                                target_entity: entity.name.clone(),
                                parameters: json!({
                                    "entity_type": entity.entity_type,
                                    "properties": entity.properties_mentioned
                                }),
                                preconditions: vec![],
                                expected_outcome: format!("Entity '{}' created", entity.name),
                            });
                        }
                    }
                },
                Err(_) => {
                    // Error checking - assume doesn't exist
                    self.log_decision(PlanningDecision {
                        decision_type: "entity_creation_error_fallback".to_string(),
                        entity: entity.name.clone(),
                        reasoning: "Error checking entity existence, assuming it doesn't exist".to_string(),
                        action_taken: "create_entity".to_string(),
                        dependencies: vec![],
                    });
                    
                    actions.push(IntelligentAction {
                        action_id: format!("create_entity_{}", entity.name),
                        action_type: IntelligentActionType::CreateEntity,
                        target_entity: entity.name.clone(),
                        parameters: json!({
                            "entity_type": entity.entity_type,
                            "properties": entity.properties_mentioned
                        }),
                        preconditions: vec![],
                        expected_outcome: format!("Entity '{}' created", entity.name),
                    });
                }
            }
        }
        
        Ok(PlanPhase {
            phase_name: "Entity Creation/Update".to_string(),
            description: "Ensure all mentioned entities exist with correct properties".to_string(),
            actions,
            dependencies: vec![],
        })
    }
    
    /// Plan spatial changes phase (movements)
    async fn plan_spatial_changes_phase(
        &mut self,
        spatial_changes: &[SpatialChange],
        user_id: Uuid,
        get_tool: &impl Fn(&str) -> Result<Arc<dyn ScribeTool>, AppError>,
    ) -> Result<PlanPhase, AppError> {
        let mut actions = Vec::new();
        let mut location_checks = HashSet::new();
        
        // First, identify all locations that need to exist
        for change in spatial_changes {
            location_checks.insert(&change.to_location);
            if let Some(from) = &change.from_location {
                location_checks.insert(from);
            }
        }
        
        // Check and create locations if needed
        for location in location_checks {
            let find_params = json!({
                "user_id": user_id.to_string(),
                "criteria": {
                    "type": "ByName",
                    "name": location
                },
                "limit": 1
            });
            
            match get_tool("find_entity")?.execute(&find_params).await {
                Ok(result) => {
                    if result.get("entities").and_then(|e| e.as_array()).map(|a| a.is_empty()).unwrap_or(true) {
                        // Location doesn't exist - create it first
                        self.log_decision(PlanningDecision {
                            decision_type: "location_creation".to_string(),
                            entity: location.to_string(),
                            reasoning: format!(
                                "Location '{}' needed for movement but doesn't exist",
                                location
                            ),
                            action_taken: "create_location".to_string(),
                            dependencies: vec![],
                        });
                        
                        actions.push(IntelligentAction {
                            action_id: format!("create_location_{}", location),
                            action_type: IntelligentActionType::CreateEntity,
                            target_entity: location.to_string(),
                            parameters: json!({
                                "entity_type": "location",
                                "properties": {
                                    "description": format!("Location mentioned in narrative: {}", location)
                                }
                            }),
                            preconditions: vec![],
                            expected_outcome: format!("Location '{}' created", location),
                        });
                    }
                },
                Err(_) => {
                    // Assume doesn't exist
                    actions.push(IntelligentAction {
                        action_id: format!("create_location_{}", location),
                        action_type: IntelligentActionType::CreateEntity,
                        target_entity: location.to_string(),
                        parameters: json!({
                            "entity_type": "location",
                            "properties": {}
                        }),
                        preconditions: vec![],
                        expected_outcome: format!("Location '{}' created", location),
                    });
                }
            }
        }
        
        // Now plan the movements
        for change in spatial_changes {
            self.log_decision(PlanningDecision {
                decision_type: "entity_movement".to_string(),
                entity: change.entity.clone(),
                reasoning: format!(
                    "Entity '{}' needs to move to '{}'",
                    change.entity, change.to_location
                ),
                action_taken: "move_entity".to_string(),
                dependencies: vec![format!("create_location_{}", change.to_location)],
            });
            
            actions.push(IntelligentAction {
                action_id: format!("move_{}_{}", change.entity, change.to_location),
                action_type: IntelligentActionType::MoveEntity,
                target_entity: change.entity.clone(),
                parameters: json!({
                    "to_location": change.to_location,
                    "movement_type": change.movement_type
                }),
                preconditions: vec![
                    Precondition {
                        condition_type: "entity_exists".to_string(),
                        entity: change.to_location.clone(),
                        requirement: "Location must exist before moving entity there".to_string(),
                    }
                ],
                expected_outcome: format!("{} moved to {}", change.entity, change.to_location),
            });
        }
        
        Ok(PlanPhase {
            phase_name: "Spatial Changes".to_string(),
            description: "Handle entity movements and location changes".to_string(),
            actions,
            dependencies: vec!["Entity Creation/Update".to_string()],
        })
    }
    
    /// Plan item changes phase
    async fn plan_item_changes_phase(
        &mut self,
        item_changes: &[ItemChange],
        user_id: Uuid,
        get_tool: &impl Fn(&str) -> Result<Arc<dyn ScribeTool>, AppError>,
    ) -> Result<PlanPhase, AppError> {
        let mut actions = Vec::new();
        
        for change in item_changes {
            match change.change_type.as_str() {
                "upgrade" => {
                    // Check if entity has the item
                    let inventory_params = json!({
                        "user_id": user_id.to_string(),
                        "entity_name": change.entity
                    });
                    
                    // TODO: Use actual inventory check tool
                    self.log_decision(PlanningDecision {
                        decision_type: "item_upgrade".to_string(),
                        entity: change.entity.clone(),
                        reasoning: format!(
                            "Item '{}' needs upgrade for entity '{}'",
                            change.item, change.entity
                        ),
                        action_taken: "upgrade_item".to_string(),
                        dependencies: vec![],
                    });
                    
                    actions.push(IntelligentAction {
                        action_id: format!("upgrade_{}_{}", change.entity, change.item),
                        action_type: IntelligentActionType::UpgradeItem,
                        target_entity: change.entity.clone(),
                        parameters: json!({
                            "item": change.item,
                            "upgrades": change.properties
                        }),
                        preconditions: vec![
                            Precondition {
                                condition_type: "has_item".to_string(),
                                entity: change.entity.clone(),
                                requirement: format!("Entity must have item '{}'", change.item),
                            }
                        ],
                        expected_outcome: format!("{}'s {} upgraded", change.entity, change.item),
                    });
                },
                "acquire" => {
                    self.log_decision(PlanningDecision {
                        decision_type: "item_acquisition".to_string(),
                        entity: change.entity.clone(),
                        reasoning: format!(
                            "Entity '{}' acquires item '{}'",
                            change.entity, change.item
                        ),
                        action_taken: "add_to_inventory".to_string(),
                        dependencies: vec![],
                    });
                    
                    actions.push(IntelligentAction {
                        action_id: format!("add_item_{}_{}", change.entity, change.item),
                        action_type: IntelligentActionType::AddToInventory,
                        target_entity: change.entity.clone(),
                        parameters: json!({
                            "item": change.item,
                            "properties": change.properties
                        }),
                        preconditions: vec![],
                        expected_outcome: format!("{} acquired {}", change.entity, change.item),
                    });
                },
                _ => {
                    // Handle other item change types
                }
            }
        }
        
        Ok(PlanPhase {
            phase_name: "Item Changes".to_string(),
            description: "Handle item acquisitions, upgrades, and losses".to_string(),
            actions,
            dependencies: vec!["Entity Creation/Update".to_string()],
        })
    }
    
    /// Plan relationship changes phase
    async fn plan_relationship_changes_phase(
        &mut self,
        relationship_changes: &[RelationshipChange],
        user_id: Uuid,
        get_tool: &impl Fn(&str) -> Result<Arc<dyn ScribeTool>, AppError>,
    ) -> Result<PlanPhase, AppError> {
        let mut actions = Vec::new();
        
        for change in relationship_changes {
            let action_type = match change.change.as_str() {
                "establish" => IntelligentActionType::EstablishRelationship,
                _ => IntelligentActionType::UpdateRelationship,
            };
            
            self.log_decision(PlanningDecision {
                decision_type: "relationship_change".to_string(),
                entity: change.source.clone(),
                reasoning: format!(
                    "Relationship between '{}' and '{}' needs to {}",
                    change.source, change.target, change.change
                ),
                action_taken: format!("{}_relationship", change.change),
                dependencies: vec![],
            });
            
            actions.push(IntelligentAction {
                action_id: format!("relationship_{}_{}_{}", change.source, change.target, change.change),
                action_type,
                target_entity: change.source.clone(),
                parameters: json!({
                    "target": change.target,
                    "relationship_type": change.relationship_type,
                    "trust_delta": change.trust_delta
                }),
                preconditions: vec![
                    Precondition {
                        condition_type: "entity_exists".to_string(),
                        entity: change.source.clone(),
                        requirement: "Source entity must exist".to_string(),
                    },
                    Precondition {
                        condition_type: "entity_exists".to_string(),
                        entity: change.target.clone(),
                        requirement: "Target entity must exist".to_string(),
                    }
                ],
                expected_outcome: format!(
                    "Relationship between {} and {} {}",
                    change.source, change.target, change.change
                ),
            });
        }
        
        Ok(PlanPhase {
            phase_name: "Relationship Changes".to_string(),
            description: "Handle relationship establishments and updates".to_string(),
            actions,
            dependencies: vec!["Entity Creation/Update".to_string()],
        })
    }
    
    /// Check if an entity needs updating based on mentioned properties
    fn check_if_entity_needs_update(
        &self,
        existing_entity: &Value,
        mentioned_properties: &HashMap<String, Value>,
    ) -> bool {
        // Compare mentioned properties with existing ones
        // Return true if there are new or different properties
        if mentioned_properties.is_empty() {
            return false;
        }
        
        // TODO: Implement proper property comparison
        // For now, assume update is needed if properties are mentioned
        true
    }
    
    /// Log a planning decision
    fn log_decision(&mut self, decision: PlanningDecision) {
        info!(
            "Planning Decision: {} for entity '{}' - {}",
            decision.decision_type, decision.entity, decision.reasoning
        );
        self.decision_log.push(decision);
    }
    
    /// Get all decisions made during planning
    pub fn get_decisions(&self) -> &[PlanningDecision] {
        &self.decision_log
    }
    
    /// Clear decision log
    pub fn clear_decisions(&mut self) {
        self.decision_log.clear();
    }
}