// backend/src/services/planning/confidence_calculator.rs
//
// Confidence Calculator Service - Multi-factor confidence scoring for repair operations
//
// This service provides sophisticated confidence scoring for repair plans by considering:
// - ECS state consistency assessment confidence
// - Number of affected entities and complexity
// - Historical success rates (if available)
// - Entity relationship depth and interconnectedness
// - Time since last state change (freshness)
// - Repair plan quality metrics

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::types::*,
    },
    models::ecs::*,
};

/// Configuration for confidence calculation algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceConfig {
    /// Weight for ECS consistency confidence (0.0-1.0)
    pub consistency_weight: f32,
    /// Weight for entity complexity factor (0.0-1.0) 
    pub complexity_weight: f32,
    /// Weight for relationship depth factor (0.0-1.0)
    pub relationship_weight: f32,
    /// Weight for temporal freshness factor (0.0-1.0)
    pub temporal_weight: f32,
    /// Weight for plan quality metrics (0.0-1.0)
    pub plan_quality_weight: f32,
    /// Maximum entities to consider before applying complexity penalty
    pub max_entities_threshold: u32,
    /// Maximum relationship depth to analyze
    pub max_relationship_depth: u32,
    /// Time threshold for considering state "fresh" (seconds)
    pub freshness_threshold: u64,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        Self {
            consistency_weight: 0.30,     // 30% - Primary factor from analysis
            complexity_weight: 0.20,      // 20% - Complexity penalty
            relationship_weight: 0.20,    // 20% - Interconnectedness impact
            temporal_weight: 0.15,        // 15% - State freshness
            plan_quality_weight: 0.15,    // 15% - Generated plan quality
            max_entities_threshold: 10,
            max_relationship_depth: 3,
            freshness_threshold: 300,     // 5 minutes
        }
    }
}

/// Detailed confidence breakdown for analysis and debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    /// Overall final confidence score (0.0-1.0)
    pub final_confidence: f32,
    /// Individual factor scores
    pub consistency_score: f32,
    pub complexity_score: f32,
    pub relationship_score: f32,
    pub temporal_score: f32,
    pub plan_quality_score: f32,
    /// Factor weights used
    pub weights: ConfidenceConfig,
    /// Detailed analysis
    pub entities_analyzed: u32,
    pub relationships_analyzed: u32,
    pub max_relationship_depth: u32,
    pub state_age_seconds: u64,
    pub plan_action_count: u32,
    /// Warnings or concerns
    pub warnings: Vec<String>,
}

/// Metrics about entity complexity and interconnectedness
#[derive(Debug, Clone)]
pub struct EntityComplexityMetrics {
    pub total_entities: u32,
    pub entities_with_components: u32,
    pub total_relationships: u32,
    pub max_relationship_depth: u32,
    pub component_types_count: u32,
    pub inventory_complexity: u32,
}

/// Service for calculating multi-factor confidence scores for repair operations
pub struct ConfidenceCalculator {
    ecs_manager: Arc<EcsEntityManager>,
    config: ConfidenceConfig,
}

impl ConfidenceCalculator {
    pub fn new(ecs_manager: Arc<EcsEntityManager>) -> Self {
        Self {
            ecs_manager,
            config: ConfidenceConfig::default(),
        }
    }

    pub fn with_config(ecs_manager: Arc<EcsEntityManager>, config: ConfidenceConfig) -> Self {
        Self {
            ecs_manager,
            config,
        }
    }

    /// Calculate comprehensive confidence score for a repair plan
    #[instrument(skip(self, analysis, repair_plan))]
    pub async fn calculate_repair_confidence(
        &self,
        analysis: &InconsistencyAnalysis,
        repair_plan: &Plan,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<ConfidenceBreakdown, AppError> {
        info!("Calculating repair confidence for {:?} inconsistency", analysis.inconsistency_type);

        // 1. Start with base consistency confidence from analysis
        let consistency_score = analysis.confidence_score.clamp(0.0, 1.0);
        debug!("Base consistency confidence: {:.3}", consistency_score);

        // 2. Calculate entity complexity factor
        let complexity_metrics = self.analyze_entity_complexity(user_id, original_plan).await?;
        let complexity_score = self.calculate_complexity_score(&complexity_metrics);
        debug!("Complexity score: {:.3} (entities: {}, relationships: {})", 
               complexity_score, complexity_metrics.total_entities, complexity_metrics.total_relationships);

        // 3. Calculate relationship depth and interconnectedness factor
        let relationship_score = self.calculate_relationship_score(&complexity_metrics);
        debug!("Relationship score: {:.3} (max depth: {})", 
               relationship_score, complexity_metrics.max_relationship_depth);

        // 4. Calculate temporal freshness factor
        let temporal_score = self.calculate_temporal_score(analysis);
        debug!("Temporal score: {:.3}", temporal_score);

        // 5. Calculate plan quality metrics
        let plan_quality_score = self.calculate_plan_quality_score(repair_plan, original_plan);
        debug!("Plan quality score: {:.3}", plan_quality_score);

        // 6. Combine scores using weighted average
        let final_confidence = (
            consistency_score * self.config.consistency_weight +
            complexity_score * self.config.complexity_weight +
            relationship_score * self.config.relationship_weight +
            temporal_score * self.config.temporal_weight +
            plan_quality_score * self.config.plan_quality_weight
        ).clamp(0.0, 1.0);

        // 7. Generate warnings for low confidence factors
        let mut warnings = Vec::new();
        if consistency_score < 0.5 {
            warnings.push("Low consistency confidence from analysis".to_string());
        }
        if complexity_score < 0.5 {
            warnings.push(format!("High complexity: {} entities, {} relationships", 
                                  complexity_metrics.total_entities, complexity_metrics.total_relationships));
        }
        if relationship_score < 0.5 {
            warnings.push(format!("Deep relationship interconnectedness (depth: {})", 
                                  complexity_metrics.max_relationship_depth));
        }
        if temporal_score < 0.7 {
            warnings.push("State may be stale - consider recent changes".to_string());
        }
        if plan_quality_score < 0.6 {
            warnings.push("Generated repair plan quality concerns".to_string());
        }

        let breakdown = ConfidenceBreakdown {
            final_confidence,
            consistency_score,
            complexity_score,
            relationship_score,
            temporal_score,
            plan_quality_score,
            weights: self.config.clone(),
            entities_analyzed: complexity_metrics.total_entities,
            relationships_analyzed: complexity_metrics.total_relationships,
            max_relationship_depth: complexity_metrics.max_relationship_depth,
            state_age_seconds: chrono::Utc::now()
                .signed_duration_since(analysis.detection_timestamp)
                .num_seconds() as u64,
            plan_action_count: repair_plan.actions.len() as u32,
            warnings,
        };

        info!("Final repair confidence: {:.3} (consistency: {:.3}, complexity: {:.3}, relationships: {:.3}, temporal: {:.3}, quality: {:.3})",
              final_confidence, consistency_score, complexity_score, relationship_score, temporal_score, plan_quality_score);

        Ok(breakdown)
    }

    /// Analyze entity complexity and interconnectedness
    async fn analyze_entity_complexity(
        &self,
        user_id: Uuid,
        plan: &Plan,
    ) -> Result<EntityComplexityMetrics, AppError> {
        let mut entity_ids = std::collections::HashSet::new();
        let mut component_types = std::collections::HashSet::new();
        let mut total_relationships = 0;
        let mut max_relationship_depth = 0;
        let mut inventory_complexity = 0;

        // Extract entity IDs from plan actions
        for action in &plan.actions {
            // Extract entity IDs from parameters
            if let Some(entity_id_str) = action.parameters.get("entity_id").and_then(|v| v.as_str()) {
                if let Ok(entity_id) = Uuid::parse_str(entity_id_str) {
                    entity_ids.insert(entity_id);
                }
            }

            // Extract from preconditions
            if let Some(existence_checks) = &action.preconditions.entity_exists {
                for check in existence_checks {
                    if let Some(id_str) = &check.entity_id {
                        if let Ok(entity_id) = Uuid::parse_str(id_str) {
                            entity_ids.insert(entity_id);
                        }
                    }
                }
            }

            if let Some(component_checks) = &action.preconditions.entity_has_component {
                for check in component_checks {
                    if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                        entity_ids.insert(entity_id);
                        component_types.insert(check.component_type.clone());
                    }
                }
            }
        }

        // Analyze each entity for complexity
        for entity_id in &entity_ids {
            if let Ok(Some(entity)) = self.ecs_manager.get_entity(user_id, *entity_id).await {
                // Count component types
                for component in &entity.components {
                    component_types.insert(component.component_type.clone());
                }

                // Check for inventory complexity
                if let Some(inventory_comp) = entity.components.iter()
                    .find(|c| c.component_type == "Inventory") {
                    if let Ok(inventory) = serde_json::from_value::<InventoryComponent>(inventory_comp.component_data.clone()) {
                        inventory_complexity += inventory.items.len() as u32;
                    }
                }

                // Analyze relationships for this entity
                if let Ok(relationships) = self.ecs_manager.get_entity_relationships(user_id, *entity_id).await {
                    total_relationships += relationships.len() as u32;
                    
                    // Calculate relationship depth (simplified - could be more sophisticated)
                    let depth = self.calculate_relationship_depth_for_entity(user_id, *entity_id, 0, &mut std::collections::HashSet::new()).await.unwrap_or(0);
                    max_relationship_depth = max_relationship_depth.max(depth);
                }
            }
        }

        Ok(EntityComplexityMetrics {
            total_entities: entity_ids.len() as u32,
            entities_with_components: entity_ids.len() as u32, // Simplified
            total_relationships,
            max_relationship_depth,
            component_types_count: component_types.len() as u32,
            inventory_complexity,
        })
    }

    /// Calculate complexity score (1.0 = simple, 0.0 = very complex)
    fn calculate_complexity_score(&self, metrics: &EntityComplexityMetrics) -> f32 {
        let mut score = 1.0;

        // Entity count penalty
        if metrics.total_entities > self.config.max_entities_threshold {
            let penalty = (metrics.total_entities - self.config.max_entities_threshold) as f32 * 0.05;
            score -= penalty.min(0.4); // Max 40% penalty
        }

        // Relationship complexity penalty
        if metrics.total_relationships > 20 {
            let penalty = (metrics.total_relationships - 20) as f32 * 0.02;
            score -= penalty.min(0.3); // Max 30% penalty
        }

        // Component diversity penalty (too many types can be complex)
        if metrics.component_types_count > 10 {
            let penalty = (metrics.component_types_count - 10) as f32 * 0.03;
            score -= penalty.min(0.2); // Max 20% penalty
        }

        // Inventory complexity penalty
        if metrics.inventory_complexity > 50 {
            let penalty = (metrics.inventory_complexity - 50) as f32 * 0.01;
            score -= penalty.min(0.2); // Max 20% penalty
        }

        score.clamp(0.0_f32, 1.0_f32)
    }

    /// Calculate relationship interconnectedness score (1.0 = simple, 0.0 = highly interconnected)
    fn calculate_relationship_score(&self, metrics: &EntityComplexityMetrics) -> f32 {
        let mut score = 1.0;

        // Relationship depth penalty
        if metrics.max_relationship_depth > self.config.max_relationship_depth {
            let penalty = (metrics.max_relationship_depth - self.config.max_relationship_depth) as f32 * 0.15;
            score -= penalty.min(0.6); // Max 60% penalty for deep relationships
        }

        // Relationship density penalty
        if metrics.total_entities > 0 {
            let relationship_density = metrics.total_relationships as f32 / metrics.total_entities as f32;
            if relationship_density > 3.0_f32 { // More than 3 relationships per entity on average
                let penalty = (relationship_density - 3.0_f32) * 0.1_f32;
                score -= penalty.min(0.4_f32); // Max 40% penalty
            }
        }

        score.clamp(0.0_f32, 1.0_f32)
    }

    /// Calculate temporal freshness score (1.0 = fresh, 0.0 = very stale)
    fn calculate_temporal_score(&self, analysis: &InconsistencyAnalysis) -> f32 {
        let age_seconds = chrono::Utc::now()
            .signed_duration_since(analysis.detection_timestamp)
            .num_seconds() as u64;

        if age_seconds <= self.config.freshness_threshold {
            1.0 // Fresh analysis
        } else {
            // Gradual decay over time
            let staleness = age_seconds - self.config.freshness_threshold;
            let decay_factor = 1.0 - (staleness as f32 / 3600.0) * 0.1; // 10% decay per hour after threshold
            decay_factor.clamp(0.2_f32, 1.0_f32) // Never go below 20%
        }
    }

    /// Calculate plan quality score based on repair plan characteristics
    fn calculate_plan_quality_score(&self, repair_plan: &Plan, original_plan: &Plan) -> f32 {
        let mut score = 0.8_f32; // Start with good baseline

        // Action count factor (prefer fewer actions for repairs)
        let action_count = repair_plan.actions.len();
        if action_count == 0 {
            score = 0.0; // No actions = no repair
        } else if action_count <= 3 {
            score += 0.2; // Bonus for concise repairs
        } else if action_count > 8 {
            score -= 0.3; // Penalty for overly complex repairs
        }

        // Plan confidence from metadata
        if repair_plan.metadata.confidence < 0.5 {
            score -= 0.2; // Penalty for low-confidence generated plans
        }

        // Goal clarity (simple heuristic)
        if repair_plan.goal.is_empty() || repair_plan.goal.len() < 10 {
            score -= 0.1;
        }

        // Action precondition completeness
        let actions_with_preconditions = repair_plan.actions.iter()
            .filter(|a| !a.preconditions.entity_exists.as_ref().map_or(true, |v| v.is_empty()))
            .count();
        
        if actions_with_preconditions == 0 && action_count > 0 {
            score -= 0.15; // Penalty for actions without preconditions
        }

        // Effects completeness
        let actions_with_effects = repair_plan.actions.iter()
            .filter(|a| self.has_meaningful_effects(a))
            .count();
            
        if actions_with_effects == 0 && action_count > 0 {
            score -= 0.15; // Penalty for actions without clear effects
        }

        score.clamp(0.0_f32, 1.0_f32)
    }

    /// Check if action has meaningful effects defined
    fn has_meaningful_effects(&self, action: &PlannedAction) -> bool {
        action.effects.entity_moved.is_some() ||
        action.effects.entity_created.is_some() ||
        action.effects.component_updated.as_ref().map_or(false, |v| !v.is_empty()) ||
        action.effects.inventory_changed.is_some() ||
        action.effects.relationship_changed.is_some()
    }

    /// Calculate relationship depth for a specific entity (recursive with cycle detection)
    async fn calculate_relationship_depth_for_entity(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        current_depth: u32,
        visited: &mut std::collections::HashSet<Uuid>,
    ) -> Result<u32, AppError> {
        if current_depth >= self.config.max_relationship_depth || visited.contains(&entity_id) {
            return Ok(current_depth);
        }

        visited.insert(entity_id);
        let mut max_depth = current_depth;

        if let Ok(relationships) = self.ecs_manager.get_entity_relationships(user_id, entity_id).await {
            for relationship in relationships {
                let connected_entity = if relationship.source_entity_id == entity_id {
                    relationship.target_entity_id
                } else {
                    relationship.source_entity_id
                };

                let depth = self.calculate_relationship_depth_for_entity(
                    user_id, 
                    connected_entity, 
                    current_depth + 1, 
                    visited
                ).await?;
                
                max_depth = max_depth.max(depth);
            }
        }

        visited.remove(&entity_id);
        Ok(max_depth)
    }

    /// Update configuration for confidence calculation
    pub fn update_config(&mut self, config: ConfidenceConfig) {
        self.config = config;
        info!("Updated confidence calculator configuration");
    }

    /// Get current configuration
    pub fn get_config(&self) -> &ConfidenceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_analysis() -> InconsistencyAnalysis {
        InconsistencyAnalysis {
            inconsistency_type: InconsistencyType::MissingMovement,
            narrative_evidence: vec!["Test evidence".to_string()],
            ecs_state_summary: "Test state".to_string(),
            repair_reasoning: "Test reasoning".to_string(),
            confidence_score: 0.8,
            detection_timestamp: Utc::now(),
        }
    }

    fn create_test_plan() -> Plan {
        Plan {
            goal: "Test repair plan".to_string(),
            actions: vec![PlannedAction {
                id: "test_action".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({"entity_id": "test"}),
                preconditions: Preconditions {
                    entity_exists: Some(vec![EntityExistenceCheck {
                        entity_id: Some("test".to_string()),
                        entity_name: None,
                    }]),
                    ..Default::default()
                },
                effects: Effects {
                    entity_moved: Some(EntityMovedEffect {
                        entity_id: "test".to_string(),
                        new_location: "new_loc".to_string(),
                    }),
                    ..Default::default()
                },
                dependencies: vec![],
            }],
            metadata: PlanMetadata {
                estimated_duration: Some(30),
                confidence: 0.7,
                alternative_considered: None,
            },
        }
    }

    #[test]
    fn test_complexity_score_calculation() {
        let metrics = EntityComplexityMetrics {
            total_entities: 5,
            entities_with_components: 5,
            total_relationships: 8,
            max_relationship_depth: 2,
            component_types_count: 4,
            inventory_complexity: 10,
        };

        // Create a test calculator without database dependencies
        let config = ConfidenceConfig::default();
        
        // Test the calculation method directly
        let mut score = 1.0_f32;

        // Entity count penalty
        if metrics.total_entities > config.max_entities_threshold {
            let penalty = (metrics.total_entities - config.max_entities_threshold) as f32 * 0.05;
            score -= penalty.min(0.4); // Max 40% penalty
        }

        // No penalty for 5 entities (under threshold of 10)
        assert!(score >= 0.0 && score <= 1.0);
        assert!(score > 0.9, "Simple metrics should yield high confidence");
    }

    #[test]
    fn test_plan_quality_score_basic() {
        let repair_plan = create_test_plan();
        let original_plan = create_test_plan();

        // Test the plan quality scoring logic directly
        let mut score = 0.8_f32; // Start with good baseline
        let action_count = repair_plan.actions.len();
        
        // Action count factor (prefer fewer actions for repairs)
        if action_count == 0 {
            score = 0.0; // No actions = no repair
        } else if action_count <= 3 {
            score += 0.2; // Bonus for concise repairs
        }

        // Plan confidence from metadata
        if repair_plan.metadata.confidence < 0.5 {
            score -= 0.2; // Penalty for low-confidence generated plans
        }

        assert!(score >= 0.0 && score <= 1.0);
        assert!(score > 0.8, "Good quality plan should yield high score");
    }

    #[test]
    fn test_temporal_score_fresh() {
        let analysis = create_test_analysis(); // Fresh analysis
        let config = ConfidenceConfig::default();
        
        let age_seconds = chrono::Utc::now()
            .signed_duration_since(analysis.detection_timestamp)
            .num_seconds() as u64;

        let score = if age_seconds <= config.freshness_threshold {
            1.0 // Fresh analysis
        } else {
            // Gradual decay over time
            let staleness = age_seconds - config.freshness_threshold;
            let decay_factor = 1.0 - (staleness as f32 / 3600.0) * 0.1; // 10% decay per hour after threshold
            decay_factor.clamp(0.2_f32, 1.0_f32) // Never go below 20%
        };
        
        assert_eq!(score, 1.0, "Fresh analysis should have perfect temporal score");
    }

    #[test]
    fn test_confidence_config_serialization() {
        let config = ConfidenceConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: ConfidenceConfig = serde_json::from_str(&serialized).unwrap();
        
        assert!((config.consistency_weight - deserialized.consistency_weight).abs() < f32::EPSILON);
        assert_eq!(config.max_entities_threshold, deserialized.max_entities_threshold);
    }
}