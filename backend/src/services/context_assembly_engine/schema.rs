//! EnrichedContext Schema Formalization
//! 
//! This module provides formal schema definitions, versioning, and validation
//! for the EnrichedContext API - the contract between the symbolic world model
//! and neural generation systems.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use super::{
    EnrichedContext, StrategicDirective, ValidatedPlan, SubGoal, 
    PlotSignificance, WorldImpactLevel, RiskAssessment, RiskLevel,
    PlanValidationStatus
};

/// Schema version for EnrichedContext
/// This allows for schema evolution without breaking changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaVersion {
    /// Initial version - Epic 4 implementation
    V1_0,
    // Future versions can be added here
}

impl SchemaVersion {
    pub fn current() -> Self {
        SchemaVersion::V1_0
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            SchemaVersion::V1_0 => "1.0",
        }
    }
}

/// Versioned EnrichedContext wrapper
/// This ensures all EnrichedContext payloads include version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedEnrichedContext {
    /// Schema version for this payload
    pub schema_version: SchemaVersion,
    
    /// Timestamp when this context was created
    pub created_at: DateTime<Utc>,
    
    /// The actual enriched context payload
    #[serde(flatten)]
    pub context: super::EnrichedContext,
}

impl VersionedEnrichedContext {
    pub fn new(context: super::EnrichedContext) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            created_at: Utc::now(),
            context,
        }
    }
}

/// Schema validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub field: String,
    pub message: String,
}

/// Validates an EnrichedContext against the schema
pub fn validate_enriched_context(context: &super::EnrichedContext) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    
    // Required field validations
    if context.current_sub_goal.description.is_empty() {
        errors.push(ValidationError {
            field: "current_sub_goal.description".to_string(),
            message: "Sub-goal description cannot be empty".to_string(),
        });
    }
    
    if context.current_sub_goal.actionable_directive.is_empty() {
        errors.push(ValidationError {
            field: "current_sub_goal.actionable_directive".to_string(),
            message: "Actionable directive cannot be empty".to_string(),
        });
    }
    
    // Validated plan consistency checks
    if context.validated_plan.steps.is_empty() {
        warnings.push(ValidationWarning {
            field: "validated_plan.steps".to_string(),
            message: "Validated plan has no steps".to_string(),
        });
    }
    
    // Entity validation
    for (i, entity) in context.relevant_entities.iter().enumerate() {
        if entity.entity_name.is_empty() {
            errors.push(ValidationError {
                field: format!("relevant_entities[{}].entity_name", i),
                message: "Entity name cannot be empty".to_string(),
            });
        }
        
        if entity.narrative_importance < 0.0 || entity.narrative_importance > 1.0 {
            errors.push(ValidationError {
                field: format!("relevant_entities[{}].narrative_importance", i),
                message: "Narrative importance must be between 0.0 and 1.0".to_string(),
            });
        }
    }
    
    // Performance metrics validation
    if context.execution_time_ms == 0 {
        warnings.push(ValidationWarning {
            field: "execution_time_ms".to_string(),
            message: "Execution time is 0, may indicate timing issue".to_string(),
        });
    }
    
    if context.confidence_score < 0.0 || context.confidence_score > 1.0 {
        errors.push(ValidationError {
            field: "confidence_score".to_string(),
            message: "Confidence score must be between 0.0 and 1.0".to_string(),
        });
    }
    
    // Plan validation status consistency
    match &context.plan_validation_status {
        super::PlanValidationStatus::Validated => {
            if !context.validated_plan.preconditions_met {
                warnings.push(ValidationWarning {
                    field: "validated_plan.preconditions_met".to_string(),
                    message: "Plan marked as validated but preconditions not met".to_string(),
                });
            }
        }
        super::PlanValidationStatus::Failed(_) => {
            if context.validated_plan.preconditions_met {
                warnings.push(ValidationWarning {
                    field: "validated_plan.preconditions_met".to_string(),
                    message: "Plan failed validation but preconditions marked as met".to_string(),
                });
            }
        }
        _ => {}
    }
    
    ValidationResult {
        is_valid: errors.is_empty(),
        errors,
        warnings,
    }
}

/// Token-optimized schema representation
/// This provides a more compact JSON representation for LLM consumption
#[derive(Debug, Serialize, Deserialize)]
pub struct CompactEnrichedContext {
    /// Strategic directive ID only (full directive available separately if needed)
    pub sd_id: Option<Uuid>,
    
    /// Current sub-goal in compact format
    pub goal: CompactSubGoal,
    
    /// Relevant entity IDs and names only
    pub entities: Vec<CompactEntity>,
    
    /// Plan summary
    pub plan: CompactPlan,
    
    /// Key metrics
    pub metrics: CompactMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactSubGoal {
    pub desc: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactEntity {
    pub id: Uuid,
    pub name: String,
    pub importance: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactPlan {
    pub steps: u32,
    pub valid: bool,
    pub risk: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactMetrics {
    pub conf: f32,
    pub time_ms: u64,
    pub tokens: u32,
}

impl From<&super::EnrichedContext> for CompactEnrichedContext {
    fn from(context: &super::EnrichedContext) -> Self {
        Self {
            sd_id: context.strategic_directive.as_ref().map(|d| d.directive_id),
            goal: CompactSubGoal {
                desc: context.current_sub_goal.description.clone(),
                action: context.current_sub_goal.actionable_directive.clone(),
            },
            entities: context.relevant_entities.iter().map(|e| CompactEntity {
                id: e.entity_id,
                name: e.entity_name.clone(),
                importance: e.narrative_importance,
            }).collect(),
            plan: CompactPlan {
                steps: context.validated_plan.steps.len() as u32,
                valid: matches!(context.plan_validation_status, super::PlanValidationStatus::Validated),
                risk: format!("{:?}", context.validated_plan.risk_assessment.overall_risk),
            },
            metrics: CompactMetrics {
                conf: context.confidence_score,
                time_ms: context.execution_time_ms,
                tokens: context.total_tokens_used,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_schema_versioning() {
        let context = create_test_enriched_context();
        let versioned = VersionedEnrichedContext::new(context);
        
        assert_eq!(versioned.schema_version, SchemaVersion::V1_0);
        assert_eq!(versioned.schema_version.as_str(), "1.0");
    }
    
    #[test]
    fn test_validation_catches_errors() {
        let mut context = create_test_enriched_context();
        
        // Make it invalid
        context.current_sub_goal.description = String::new();
        context.confidence_score = 1.5; // Out of range
        
        let result = validate_enriched_context(&context);
        
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors.iter().any(|e| e.field == "current_sub_goal.description"));
        assert!(result.errors.iter().any(|e| e.field == "confidence_score"));
    }
    
    #[test]
    fn test_compact_representation() {
        let context = create_test_enriched_context();
        let compact = CompactEnrichedContext::from(&context);
        
        // Test that compact representation is more concise
        let full_json = serde_json::to_string(&context).unwrap();
        let compact_json = serde_json::to_string(&compact).unwrap();
        
        assert!(compact_json.len() < full_json.len());
    }
    
    fn create_test_enriched_context() -> super::EnrichedContext {
        super::EnrichedContext {
            strategic_directive: Some(super::StrategicDirective {
                directive_id: Uuid::new_v4(),
                directive_type: "test".to_string(),
                narrative_arc: "test arc".to_string(),
                plot_significance: super::PlotSignificance::Moderate,
                emotional_tone: "neutral".to_string(),
                character_focus: vec!["Test Character".to_string()],
                world_impact_level: super::WorldImpactLevel::Local,
            }),
            validated_plan: super::ValidatedPlan {
                plan_id: Uuid::new_v4(),
                steps: vec![],
                preconditions_met: true,
                causal_consistency_verified: true,
                entity_dependencies: vec![],
                estimated_execution_time: Some(1000),
                risk_assessment: super::RiskAssessment {
                    overall_risk: super::RiskLevel::Low,
                    identified_risks: vec![],
                    mitigation_strategies: vec![],
                },
            },
            current_sub_goal: super::SubGoal {
                goal_id: Uuid::new_v4(),
                description: "Test goal".to_string(),
                actionable_directive: "Do test action".to_string(),
                required_entities: vec![],
                success_criteria: vec![],
                context_requirements: vec![],
                priority_level: 0.5,
            },
            relevant_entities: vec![],
            spatial_context: None,
            causal_context: None,
            temporal_context: None,
            plan_validation_status: super::PlanValidationStatus::Validated,
            symbolic_firewall_checks: vec![],
            assembled_context: None,
            total_tokens_used: 100,
            execution_time_ms: 50,
            validation_time_ms: 10,
            ai_model_calls: 1,
            confidence_score: 0.8,
        }
    }
}