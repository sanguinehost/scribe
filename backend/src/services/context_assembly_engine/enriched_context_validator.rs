use std::collections::HashSet;
use uuid::Uuid;
use tracing::{debug, instrument};
use chrono::Utc;

use crate::{
    errors::AppError,
    services::context_assembly_engine::{
        EnrichedContext, StrategicDirective, EntityContext,
        TemporalContext, PlanValidationStatus,
        ValidationSeverity,
    },
};

/// Comprehensive validation service for EnrichedContext payloads
/// 
/// Ensures that EnrichedContext structures produced by the TacticalAgent
/// are well-formed, consistent, and ready for consumption by the Operational Layer.
/// 
/// ## Security (OWASP Top 10):
/// - A03: Input validation for all context fields
/// - A04: Validates that required fields are present
/// - A09: Comprehensive logging for validation auditing
/// 
/// ## Validation Scope:
/// 1. Structural validation (required fields, data types)
/// 2. Business logic validation (entity consistency, plan coherence)
/// 3. Security validation (safe content, proper isolation)
/// 4. Performance validation (reasonable payload sizes)
#[derive(Debug)]
pub struct EnrichedContextValidator;

impl EnrichedContextValidator {
    /// Create a new validator instance
    pub fn new() -> Self {
        Self
    }

    /// Validate a complete EnrichedContext payload
    /// 
    /// Performs comprehensive validation ensuring the context is ready
    /// for consumption by the Operational Layer (RoleplayAI).
    #[instrument(skip(context))]
    pub async fn validate_enriched_context(
        &self,
        context: &EnrichedContext,
        user_id: Uuid,
    ) -> Result<ValidationReport, AppError> {
        let start_time = std::time::Instant::now();
        
        debug!("Starting comprehensive EnrichedContext validation for user: {}", user_id);
        
        let mut validation_report = ValidationReport::new();
        
        // 1. Structural validation (required fields and data types)
        self.validate_structure(context, &mut validation_report).await?;
        
        // 2. Business logic validation (entity consistency, plan coherence)
        self.validate_business_logic(context, &mut validation_report).await?;
        
        // 3. Security validation (safe content, proper isolation)
        self.validate_security(context, user_id, &mut validation_report).await?;
        
        // 4. Performance validation (reasonable payload sizes)
        self.validate_performance(context, &mut validation_report).await?;
        
        // 5. Consistency validation (cross-field consistency)
        self.validate_consistency(context, &mut validation_report).await?;
        
        validation_report.execution_time_ms = start_time.elapsed().as_millis() as u64;
        validation_report.finalize();
        
        debug!(
            "EnrichedContext validation completed in {}ms with {} issues",
            validation_report.execution_time_ms,
            validation_report.total_issues()
        );
        
        Ok(validation_report)
    }

    /// Validate structural integrity of the EnrichedContext
    async fn validate_structure(
        &self,
        context: &EnrichedContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        debug!("Validating EnrichedContext structure");
        
        // Validate ValidatedPlan
        if context.validated_plan.plan_id.is_nil() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: "validated_plan.plan_id".to_string(),
                message: "ValidatedPlan must have a valid plan_id".to_string(),
                severity: ValidationSeverity::Critical,
            });
        }
        
        if context.validated_plan.steps.is_empty() && context.validated_plan.preconditions_met {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::BusinessLogicViolation,
                field_path: "validated_plan.steps".to_string(),
                message: "ValidatedPlan has no steps but preconditions are marked as met".to_string(),
                severity: ValidationSeverity::Medium,
            });
        }
        
        // Validate SubGoal
        if context.current_sub_goal.goal_id.is_nil() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: "current_sub_goal.goal_id".to_string(),
                message: "SubGoal must have a valid goal_id".to_string(),
                severity: ValidationSeverity::Critical,
            });
        }
        
        if context.current_sub_goal.description.trim().is_empty() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: "current_sub_goal.description".to_string(),
                message: "SubGoal description cannot be empty".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        if context.current_sub_goal.actionable_directive.trim().is_empty() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: "current_sub_goal.actionable_directive".to_string(),
                message: "SubGoal actionable_directive cannot be empty".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        // Validate priority level bounds
        if context.current_sub_goal.priority_level < 0.0 || context.current_sub_goal.priority_level > 1.0 {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::InvalidValue,
                field_path: "current_sub_goal.priority_level".to_string(),
                message: format!(
                    "Priority level must be between 0.0 and 1.0, got: {}",
                    context.current_sub_goal.priority_level
                ),
                severity: ValidationSeverity::Medium,
            });
        }
        
        // Validate EntityContext structures
        for (index, entity) in context.relevant_entities.iter().enumerate() {
            self.validate_entity_context(entity, index, report).await?;
        }
        
        // Validate confidence score bounds
        if context.confidence_score < 0.0 || context.confidence_score > 1.0 {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::InvalidValue,
                field_path: "confidence_score".to_string(),
                message: format!(
                    "Confidence score must be between 0.0 and 1.0, got: {}",
                    context.confidence_score
                ),
                severity: ValidationSeverity::Medium,
            });
        }
        
        Ok(())
    }

    /// Validate individual EntityContext structure
    async fn validate_entity_context(
        &self,
        entity: &EntityContext,
        index: usize,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        let field_prefix = format!("relevant_entities[{}]", index);
        
        if entity.entity_id.is_nil() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: format!("{}.entity_id", field_prefix),
                message: "EntityContext must have a valid entity_id".to_string(),
                severity: ValidationSeverity::Critical,
            });
        }
        
        if entity.entity_name.trim().is_empty() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: format!("{}.entity_name", field_prefix),
                message: "EntityContext must have a non-empty entity_name".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        if entity.entity_type.trim().is_empty() {
            report.add_error(ValidationIssue {
                issue_type: ValidationIssueType::MissingRequiredField,
                field_path: format!("{}.entity_type", field_prefix),
                message: "EntityContext must have a non-empty entity_type".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        // Validate narrative importance bounds
        if entity.narrative_importance < 0.0 || entity.narrative_importance > 1.0 {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::InvalidValue,
                field_path: format!("{}.narrative_importance", field_prefix),
                message: format!(
                    "Narrative importance should be between 0.0 and 1.0, got: {}",
                    entity.narrative_importance
                ),
                severity: ValidationSeverity::Low,
            });
        }
        
        Ok(())
    }

    /// Validate business logic consistency
    async fn validate_business_logic(
        &self,
        context: &EnrichedContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        debug!("Validating EnrichedContext business logic");
        
        // Check if plan validation status aligns with confidence score
        match context.plan_validation_status {
            PlanValidationStatus::Validated => {
                if context.confidence_score < 0.7 {
                    report.add_warning(ValidationIssue {
                        issue_type: ValidationIssueType::InconsistentState,
                        field_path: "confidence_score".to_string(),
                        message: format!(
                            "Plan is validated but confidence score is low: {}",
                            context.confidence_score
                        ),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
            PlanValidationStatus::Failed(_) => {
                if context.confidence_score > 0.5 {
                    report.add_warning(ValidationIssue {
                        issue_type: ValidationIssueType::InconsistentState,
                        field_path: "confidence_score".to_string(),
                        message: format!(
                            "Plan validation failed but confidence score is high: {}",
                            context.confidence_score
                        ),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
            _ => {} // Other statuses can have varied confidence scores
        }
        
        // Validate entity references consistency
        if let Some(directive) = &context.strategic_directive {
            self.validate_entity_references_consistency(directive, context, report).await?;
        }
        
        // Validate temporal consistency
        if let Some(temporal) = &context.temporal_context {
            self.validate_temporal_consistency(temporal, report).await?;
        }
        
        Ok(())
    }

    /// Validate entity references are consistent across context components
    async fn validate_entity_references_consistency(
        &self,
        directive: &StrategicDirective,
        context: &EnrichedContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        let entity_names: HashSet<String> = context.relevant_entities
            .iter()
            .map(|e| e.entity_name.clone())
            .collect();
        
        // Check if character focus entities are represented in relevant_entities
        for character in &directive.character_focus {
            if !entity_names.contains(character) {
                report.add_warning(ValidationIssue {
                    issue_type: ValidationIssueType::MissingEntityReference,
                    field_path: "strategic_directive.character_focus".to_string(),
                    message: format!(
                        "Character '{}' mentioned in directive but not found in relevant_entities",
                        character
                    ),
                    severity: ValidationSeverity::Low,
                });
            }
        }
        
        // Check if sub-goal required entities are represented
        for required_entity in &context.current_sub_goal.required_entities {
            if !entity_names.contains(required_entity) {
                report.add_warning(ValidationIssue {
                    issue_type: ValidationIssueType::MissingEntityReference,
                    field_path: "current_sub_goal.required_entities".to_string(),
                    message: format!(
                        "Required entity '{}' not found in relevant_entities",
                        required_entity
                    ),
                    severity: ValidationSeverity::Medium,
                });
            }
        }
        
        Ok(())
    }

    /// Validate temporal context consistency
    async fn validate_temporal_consistency(
        &self,
        temporal: &TemporalContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        let now = Utc::now();
        
        // Validate current_time is not in the future
        if temporal.current_time > now {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::InvalidValue,
                field_path: "temporal_context.current_time".to_string(),
                message: "Current time is in the future".to_string(),
                severity: ValidationSeverity::Medium,
            });
        }
        
        // Validate recent events are actually recent (within last 24 hours)
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        for (index, event) in temporal.recent_events.iter().enumerate() {
            if event.timestamp < twenty_four_hours_ago {
                report.add_warning(ValidationIssue {
                    issue_type: ValidationIssueType::BusinessLogicViolation,
                    field_path: format!("temporal_context.recent_events[{}]", index),
                    message: format!(
                        "Event '{}' is older than 24 hours but marked as recent",
                        event.description
                    ),
                    severity: ValidationSeverity::Low,
                });
            }
        }
        
        // Validate scheduled events are in the future
        for (index, event) in temporal.future_scheduled_events.iter().enumerate() {
            if event.scheduled_time <= now {
                report.add_warning(ValidationIssue {
                    issue_type: ValidationIssueType::BusinessLogicViolation,
                    field_path: format!("temporal_context.future_scheduled_events[{}]", index),
                    message: format!(
                        "Scheduled event '{}' is in the past",
                        event.description
                    ),
                    severity: ValidationSeverity::Low,
                });
            }
        }
        
        Ok(())
    }

    /// Validate security aspects of the context
    async fn validate_security(
        &self,
        context: &EnrichedContext,
        user_id: Uuid,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        debug!("Validating EnrichedContext security for user: {}", user_id);
        
        // Validate user isolation - all entities should belong to the requesting user
        // This would require entity ownership validation in a real implementation
        // For now, we validate structure integrity
        
        // Check for potentially malicious content in text fields
        let text_fields = vec![
            &context.current_sub_goal.description,
            &context.current_sub_goal.actionable_directive,
        ];
        
        for field in text_fields {
            if self.contains_potentially_malicious_content(field) {
                report.add_error(ValidationIssue {
                    issue_type: ValidationIssueType::SecurityViolation,
                    field_path: "text_content".to_string(),
                    message: "Potentially malicious content detected".to_string(),
                    severity: ValidationSeverity::Critical,
                });
            }
        }
        
        // Validate symbolic firewall checks are present
        if context.symbolic_firewall_checks.is_empty() {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::MissingSecurityCheck,
                field_path: "symbolic_firewall_checks".to_string(),
                message: "No symbolic firewall checks present".to_string(),
                severity: ValidationSeverity::Medium,
            });
        }
        
        Ok(())
    }

    /// Check for potentially malicious content patterns
    fn contains_potentially_malicious_content(&self, text: &str) -> bool {
        let malicious_patterns = [
            "<script", "javascript:", "eval(", "document.cookie",
            "DROP TABLE", "DELETE FROM", "UPDATE SET", "INSERT INTO",
            "rm -rf", "sudo", "chmod", "passwd",
        ];
        
        let text_lower = text.to_lowercase();
        malicious_patterns.iter().any(|pattern| text_lower.contains(pattern))
    }

    /// Validate performance characteristics
    async fn validate_performance(
        &self,
        context: &EnrichedContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        debug!("Validating EnrichedContext performance characteristics");
        
        // Validate entity count is reasonable
        if context.relevant_entities.len() > 50 {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::PerformanceIssue,
                field_path: "relevant_entities".to_string(),
                message: format!(
                    "Large number of entities ({}) may impact performance",
                    context.relevant_entities.len()
                ),
                severity: ValidationSeverity::Low,
            });
        }
        
        // Validate token usage is reasonable
        if context.total_tokens_used > 100000 {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::PerformanceIssue,
                field_path: "total_tokens_used".to_string(),
                message: format!(
                    "High token usage ({}) may indicate inefficiency",
                    context.total_tokens_used
                ),
                severity: ValidationSeverity::Medium,
            });
        }
        
        // Validate execution time is reasonable
        if context.execution_time_ms > 30000 {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::PerformanceIssue,
                field_path: "execution_time_ms".to_string(),
                message: format!(
                    "Long execution time ({} ms) may impact user experience",
                    context.execution_time_ms
                ),
                severity: ValidationSeverity::Medium,
            });
        }
        
        Ok(())
    }

    /// Validate cross-field consistency
    async fn validate_consistency(
        &self,
        context: &EnrichedContext,
        report: &mut ValidationReport,
    ) -> Result<(), AppError> {
        debug!("Validating EnrichedContext consistency");
        
        // Validate AI model calls vs token usage consistency
        if context.ai_model_calls > 0 && context.total_tokens_used == 0 {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::InconsistentState,
                field_path: "token_usage".to_string(),
                message: "AI model calls reported but no tokens used".to_string(),
                severity: ValidationSeverity::Low,
            });
        }
        
        // Validate execution time vs validation time consistency
        if context.validation_time_ms > context.execution_time_ms {
            report.add_warning(ValidationIssue {
                issue_type: ValidationIssueType::InconsistentState,
                field_path: "timing_metrics".to_string(),
                message: "Validation time exceeds total execution time".to_string(),
                severity: ValidationSeverity::Low,
            });
        }
        
        Ok(())
    }
}

/// Comprehensive validation report for EnrichedContext
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub is_valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    pub execution_time_ms: u64,
    pub validation_timestamp: chrono::DateTime<Utc>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            execution_time_ms: 0,
            validation_timestamp: Utc::now(),
        }
    }

    pub fn add_error(&mut self, issue: ValidationIssue) {
        self.is_valid = false;
        self.errors.push(issue);
    }

    pub fn add_warning(&mut self, issue: ValidationIssue) {
        self.warnings.push(issue);
    }

    pub fn total_issues(&self) -> usize {
        self.errors.len() + self.warnings.len()
    }

    pub fn has_critical_issues(&self) -> bool {
        self.errors.iter().any(|e| matches!(e.severity, ValidationSeverity::Critical))
    }

    pub fn finalize(&mut self) {
        // Final validation state based on errors
        self.is_valid = self.errors.is_empty();
    }
}

/// Individual validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub issue_type: ValidationIssueType,
    pub field_path: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Types of validation issues
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationIssueType {
    MissingRequiredField,
    InvalidValue,
    BusinessLogicViolation,
    SecurityViolation,
    PerformanceIssue,
    InconsistentState,
    MissingEntityReference,
    MissingSecurityCheck,
}

impl Default for EnrichedContextValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::context_assembly_engine::*;
    use uuid::Uuid;

    fn create_minimal_valid_context() -> EnrichedContext {
        EnrichedContext {
            strategic_directive: None,
            validated_plan: ValidatedPlan {
                plan_id: Uuid::new_v4(),
                steps: vec![],
                preconditions_met: false,
                causal_consistency_verified: false,
                entity_dependencies: vec![],
                estimated_execution_time: None,
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::Low,
                    identified_risks: vec![],
                    mitigation_strategies: vec![],
                },
            },
            current_sub_goal: SubGoal {
                goal_id: Uuid::new_v4(),
                description: "Test goal".to_string(),
                actionable_directive: "Test directive".to_string(),
                required_entities: vec![],
                success_criteria: vec![],
                context_requirements: vec![],
                priority_level: 0.5,
            },
            relevant_entities: vec![],
            spatial_context: None,
            temporal_context: None,
            causal_context: None,
            plan_validation_status: PlanValidationStatus::Pending,
            symbolic_firewall_checks: vec![],
            assembled_context: None,
            total_tokens_used: 100,
            execution_time_ms: 1000,
            validation_time_ms: 100,
            ai_model_calls: 1,
            confidence_score: 0.8,
        }
    }

    #[tokio::test]
    async fn test_valid_context_passes_validation() {
        let validator = EnrichedContextValidator::new();
        let context = create_minimal_valid_context();
        let user_id = Uuid::new_v4();

        let result = validator.validate_enriched_context(&context, user_id).await;
        assert!(result.is_ok());
        
        let report = result.unwrap();
        assert!(report.is_valid);
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_priority_level_fails_validation() {
        let validator = EnrichedContextValidator::new();
        let mut context = create_minimal_valid_context();
        context.current_sub_goal.priority_level = 1.5; // Invalid: > 1.0
        let user_id = Uuid::new_v4();

        let result = validator.validate_enriched_context(&context, user_id).await;
        assert!(result.is_ok());
        
        let report = result.unwrap();
        assert!(!report.is_valid);
        assert!(!report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_empty_description_fails_validation() {
        let validator = EnrichedContextValidator::new();
        let mut context = create_minimal_valid_context();
        context.current_sub_goal.description = "".to_string();
        let user_id = Uuid::new_v4();

        let result = validator.validate_enriched_context(&context, user_id).await;
        assert!(result.is_ok());
        
        let report = result.unwrap();
        assert!(!report.is_valid);
        assert!(report.errors.iter().any(|e| e.field_path.contains("description")));
    }

    #[tokio::test]
    async fn test_malicious_content_fails_validation() {
        let validator = EnrichedContextValidator::new();
        let mut context = create_minimal_valid_context();
        context.current_sub_goal.description = "<script>alert('xss')</script>".to_string();
        let user_id = Uuid::new_v4();

        let result = validator.validate_enriched_context(&context, user_id).await;
        assert!(result.is_ok());
        
        let report = result.unwrap();
        assert!(!report.is_valid);
        assert!(report.errors.iter().any(|e| matches!(e.issue_type, ValidationIssueType::SecurityViolation)));
    }
}