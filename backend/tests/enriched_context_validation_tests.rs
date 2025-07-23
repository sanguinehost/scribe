use uuid::Uuid;
use chrono::Utc;

use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, StrategicDirective, ValidatedPlan, SubGoal, EntityContext,
    SpatialContext, TemporalContext, PlanValidationStatus, ValidationCheck,
    ValidationCheckType, ValidationStatus, ValidationSeverity, PlanStep,
    RiskAssessment, RiskLevel, PlotSignificance, WorldImpactLevel,
    ContextRequirement, SpatialLocation, EntityRelationship, RecentAction,
    EmotionalState, TemporalEvent, ScheduledEvent,
    EnrichedContextValidator, ValidationIssueType,
};

/// Test the comprehensive validation of EnrichedContext structures
#[tokio::test]
async fn test_enriched_context_validation_comprehensive() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    // Test 1: Valid context should pass validation
    let valid_context = create_comprehensive_valid_context();
    let result = validator.validate_enriched_context(&valid_context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(report.is_valid, "Valid context should pass validation");
    assert!(report.errors.is_empty(), "Valid context should have no errors");

    // Test 2: Context with missing required fields should fail
    let mut invalid_context = create_comprehensive_valid_context();
    invalid_context.current_sub_goal.description = "".to_string();
    
    let result = validator.validate_enriched_context(&invalid_context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(!report.is_valid, "Context with empty description should fail");
    assert!(!report.errors.is_empty(), "Should have validation errors");

    // Test 3: Context with invalid priority level should fail
    let mut invalid_context = create_comprehensive_valid_context();
    invalid_context.current_sub_goal.priority_level = 1.5; // Invalid: > 1.0
    
    let result = validator.validate_enriched_context(&invalid_context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(!report.is_valid, "Context with invalid priority should fail");
    assert!(
        report.errors.iter().any(|e| e.field_path.contains("priority_level")),
        "Should have priority level validation error"
    );

    // Test 4: Context with malicious content should fail
    let mut malicious_context = create_comprehensive_valid_context();
    malicious_context.current_sub_goal.description = "<script>alert('xss')</script>".to_string();
    
    let result = validator.validate_enriched_context(&malicious_context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(!report.is_valid, "Context with malicious content should fail");
    assert!(
        report.errors.iter().any(|e| matches!(e.issue_type, ValidationIssueType::SecurityViolation)),
        "Should detect security violation"
    );
}

/// Test validation of entity context structures
#[tokio::test]
async fn test_entity_context_validation() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    // Test valid entity context
    let mut context = create_comprehensive_valid_context();
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(report.is_valid);

    // Test invalid entity context (empty name)
    context.relevant_entities[0].entity_name = "".to_string();
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    assert!(!report.is_valid);
    assert!(
        report.errors.iter().any(|e| e.field_path.contains("entity_name")),
        "Should have entity_name validation error"
    );
}

/// Test business logic validation
#[tokio::test]
async fn test_business_logic_validation() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    // Test inconsistent validation status and confidence score
    let mut context = create_comprehensive_valid_context();
    context.plan_validation_status = PlanValidationStatus::Failed(vec!["Test failure".to_string()]);
    context.confidence_score = 0.9; // High confidence despite failure
    
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    // Should have warnings about inconsistent state
    assert!(
        report.warnings.iter().any(|w| matches!(w.issue_type, ValidationIssueType::InconsistentState)),
        "Should detect inconsistent validation status and confidence"
    );
}

/// Test temporal context validation
#[tokio::test]
async fn test_temporal_context_validation() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    let mut context = create_comprehensive_valid_context();
    
    // Add temporal context with future current_time (invalid)
    context.temporal_context = Some(TemporalContext {
        current_time: Utc::now() + chrono::Duration::hours(1), // Future time
        recent_events: vec![
            TemporalEvent {
                event_id: Uuid::new_v4(),
                description: "Old event".to_string(),
                timestamp: Utc::now() - chrono::Duration::hours(48), // Too old to be "recent"
                significance: 0.5,
            }
        ],
        future_scheduled_events: vec![
            ScheduledEvent {
                event_id: Uuid::new_v4(),
                description: "Past scheduled event".to_string(),
                scheduled_time: Utc::now() - chrono::Duration::hours(1), // In the past
                participants: vec!["TestCharacter".to_string()],
            }
        ],
        temporal_significance: 0.7,
    });
    
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    // Should have warnings about temporal inconsistencies
    assert!(
        report.warnings.iter().any(|w| w.field_path.contains("current_time")),
        "Should detect future current_time"
    );
    assert!(
        report.warnings.iter().any(|w| w.field_path.contains("recent_events")),
        "Should detect old 'recent' event"
    );
    assert!(
        report.warnings.iter().any(|w| w.field_path.contains("future_scheduled_events")),
        "Should detect past scheduled event"
    );
}

/// Test performance validation
#[tokio::test]
async fn test_performance_validation() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    let mut context = create_comprehensive_valid_context();
    
    // Add performance issues
    context.total_tokens_used = 150000; // Very high token usage
    context.execution_time_ms = 45000; // Very long execution time
    
    // Add many entities (performance concern)
    for i in 0..60 {
        context.relevant_entities.push(EntityContext {
            entity_id: Uuid::new_v4(),
            entity_name: format!("Entity{}", i),
            entity_type: "TestEntity".to_string(),
            current_state: std::collections::HashMap::new(),
            spatial_location: None,
            relationships: vec![],
            recent_actions: vec![],
            emotional_state: None,
            narrative_importance: 0.5,
            ai_insights: vec![],
        });
    }
    
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    // Should have performance warnings
    assert!(
        report.warnings.iter().any(|w| matches!(w.issue_type, ValidationIssueType::PerformanceIssue)),
        "Should detect performance issues"
    );
}

/// Test entity reference consistency validation
#[tokio::test]
async fn test_entity_reference_consistency() {
    let validator = EnrichedContextValidator::new();
    let user_id = Uuid::new_v4();

    let mut context = create_comprehensive_valid_context();
    
    // Add strategic directive with character focus not in relevant_entities
    context.strategic_directive = Some(StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "TestDirective".to_string(),
        narrative_arc: "Test narrative".to_string(),
        plot_significance: PlotSignificance::Moderate,
        emotional_tone: "neutral".to_string(),
        character_focus: vec!["MissingCharacter".to_string()], // Not in relevant_entities
        world_impact_level: WorldImpactLevel::Local,
    });
    
    let result = validator.validate_enriched_context(&context, user_id).await;
    assert!(result.is_ok());
    
    let report = result.unwrap();
    // Should have warnings about missing entity references
    assert!(
        report.warnings.iter().any(|w| matches!(w.issue_type, ValidationIssueType::MissingEntityReference)),
        "Should detect missing entity reference"
    );
}

/// Helper function to create a comprehensive valid EnrichedContext for testing
fn create_comprehensive_valid_context() -> EnrichedContext {
    EnrichedContext {
        strategic_directive: Some(StrategicDirective {
            directive_id: Uuid::new_v4(),
            directive_type: "TestDirective".to_string(),
            narrative_arc: "Test narrative arc".to_string(),
            plot_significance: PlotSignificance::Moderate,
            emotional_tone: "neutral".to_string(),
            character_focus: vec!["TestCharacter".to_string()],
            world_impact_level: WorldImpactLevel::Local,
        }),
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![
                PlanStep {
                    step_id: Uuid::new_v4(),
                    description: "Test step".to_string(),
                    preconditions: vec!["Test precondition".to_string()],
                    expected_outcomes: vec!["Test outcome".to_string()],
                    required_entities: vec!["TestCharacter".to_string()],
                    estimated_duration: Some(300),
                }
            ],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec!["TestCharacter".to_string()],
            estimated_execution_time: Some(300),
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Test sub-goal description".to_string(),
            actionable_directive: "Test actionable directive".to_string(),
            required_entities: vec!["TestCharacter".to_string()],
            success_criteria: vec!["Test success criteria".to_string()],
            context_requirements: vec![
                ContextRequirement {
                    requirement_type: "entity".to_string(),
                    description: "Requires TestCharacter".to_string(),
                    priority: 0.8,
                }
            ],
            priority_level: 0.8,
        },
        relevant_entities: vec![
            EntityContext {
                entity_id: Uuid::new_v4(),
                entity_name: "TestCharacter".to_string(),
                entity_type: "Character".to_string(),
                current_state: std::collections::HashMap::new(),
                spatial_location: Some(SpatialLocation {
                    location_id: Uuid::new_v4(),
                    name: "TestLocation".to_string(),
                    coordinates: Some((0.0, 0.0, 0.0)),
                    parent_location: None,
                    location_type: "Room".to_string(),
                }),
                relationships: vec![
                    EntityRelationship {
                        relationship_id: Uuid::new_v4(),
                        from_entity: "TestCharacter".to_string(),
                        to_entity: "OtherCharacter".to_string(),
                        relationship_type: "friendship".to_string(),
                        strength: 0.7,
                        context: "long-time friends".to_string(),
                    }
                ],
                recent_actions: vec![
                    RecentAction {
                        action_id: Uuid::new_v4(),
                        description: "Greeted someone".to_string(),
                        timestamp: Utc::now() - chrono::Duration::minutes(5),
                        action_type: "social".to_string(),
                        impact_level: 0.3,
                    }
                ],
                emotional_state: Some(EmotionalState {
                    primary_emotion: "neutral".to_string(),
                    intensity: 0.5,
                    contributing_factors: vec!["calm environment".to_string()],
                }),
                narrative_importance: 0.8,
                ai_insights: vec!["Character is well-positioned for the scene".to_string()],
            }
        ],
        spatial_context: Some(SpatialContext {
            current_location: SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "TestLocation".to_string(),
                coordinates: Some((0.0, 0.0, 0.0)),
                parent_location: None,
                location_type: "Room".to_string(),
            },
            nearby_locations: vec![],
            environmental_factors: vec![],
            spatial_relationships: vec![],
        }),
        temporal_context: Some(TemporalContext {
            current_time: Utc::now(),
            recent_events: vec![
                TemporalEvent {
                    event_id: Uuid::new_v4(),
                    description: "Recent conversation".to_string(),
                    timestamp: Utc::now() - chrono::Duration::minutes(10),
                    significance: 0.6,
                }
            ],
            future_scheduled_events: vec![
                ScheduledEvent {
                    event_id: Uuid::new_v4(),
                    description: "Upcoming meeting".to_string(),
                    scheduled_time: Utc::now() + chrono::Duration::hours(2),
                    participants: vec!["TestCharacter".to_string()],
                }
            ],
            temporal_significance: 0.7,
        }),
        causal_context: None,
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![
            ValidationCheck {
                check_type: ValidationCheckType::AccessControl,
                status: ValidationStatus::Passed,
                message: "User ownership validated".to_string(),
                severity: ValidationSeverity::Medium,
            },
            ValidationCheck {
                check_type: ValidationCheckType::InputValidation,
                status: ValidationStatus::Passed,
                message: "Input sanitized".to_string(),
                severity: ValidationSeverity::Low,
            },
        ],
        assembled_context: None,
        perception_analysis: None,
        total_tokens_used: 1500,
        execution_time_ms: 2500,
        validation_time_ms: 150,
        ai_model_calls: 2,
        confidence_score: 0.85,
    }
}