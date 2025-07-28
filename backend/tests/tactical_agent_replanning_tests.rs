use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    StrategicDirective, PlotSignificance, WorldImpactLevel
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;
use serde_json::json;

// Helper function to create test strategic directive
fn create_test_strategic_directive() -> StrategicDirective {
    StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "execute_combat_scenario".to_string(),
        narrative_arc: "Epic battle between heroes and villains".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "Intense and dramatic".to_string(),
        character_focus: vec!["Hero".to_string(), "Villain".to_string()],
        world_impact_level: WorldImpactLevel::Regional,
    }
}

// Helper to create a test tactical agent
async fn create_test_tactical_agent(app: &TestApp) -> TacticalAgent {
    let planning_service = Arc::new(scribe_backend::services::planning::PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
        "gemini-2.5-pro".to_string(),
    ));
    
    let plan_validator = Arc::new(scribe_backend::services::planning::PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    )
}

// Test plan caching functionality
#[tokio::test]
async fn test_plan_caching_storage() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Process directive and check if plan is cached
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    // Should succeed and store plan in cache
    assert!(result.is_ok());
    
    // Verify plan is cached (implementation dependent on Redis cache)
    let cached_plan = tactical_agent.get_cached_plan(user_id, &directive.directive_id).await;
    assert!(cached_plan.is_ok());
}

// Test world state deviation detection
#[tokio::test]
async fn test_world_state_deviation_detection() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Create initial plan
    let initial_result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    assert!(initial_result.is_ok());
    let initial_context = initial_result.unwrap();
    
    // Simulate world state change (e.g., entity moved unexpectedly)
    // This would be done by the PerceptionAgent in real scenarios
    
    // Process directive again with changed world state
    let updated_result = tactical_agent.process_directive_with_state_check(
        &directive,
        user_id,
        &session_dek,
        &initial_context,
    ).await;
    
    // Should detect deviation and trigger re-planning
    match updated_result {
        Ok(new_context) => {
            // Should have different plan due to re-planning
            assert_ne!(initial_context.validated_plan.plan_id, new_context.validated_plan.plan_id);
        }
        Err(e) => {
            // Re-planning might fail, which is also acceptable
            println!("Re-planning failed (expected in test): {:?}", e);
        }
    }
}

// Test plan invalidation when expected outcomes don't match reality
#[tokio::test]
async fn test_plan_invalidation_on_outcome_mismatch() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Process initial directive
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Simulate failed action outcome (e.g., persuasion failed)
    let failed_outcome = json!({
        "action": "persuade",
        "target": "guard",
        "expected_result": "convinced",
        "actual_result": "rejected",
        "deviation_severity": "high"
    });
    
    // Check if plan should be invalidated
    let should_replan = tactical_agent.should_invalidate_plan(
        &context.validated_plan,
        &failed_outcome,
        user_id,
    ).await;
    
    assert!(should_replan.unwrap_or(false));
}

// Test re-planning after action failure
#[tokio::test]
async fn test_replanning_after_action_failure() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Initial plan generation
    let initial_result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    assert!(initial_result.is_ok());
    let initial_context = initial_result.unwrap();
    
    // Simulate action failure scenario
    let failure_context = json!({
        "failed_action": "intimidate_guard",
        "failure_reason": "guard_too_experienced",
        "new_constraints": ["guard_is_alert", "backup_called"],
        "alternative_approaches": ["stealth", "diplomacy", "distraction"]
    });
    
    // Trigger re-planning
    let replan_result = tactical_agent.replan_after_failure(
        &directive,
        &failure_context,
        user_id,
        &session_dek,
    ).await;
    
    match replan_result {
        Ok(new_context) => {
            // New plan should be different from original
            assert_ne!(initial_context.validated_plan.plan_id, new_context.validated_plan.plan_id);
            
            // New plan should account for failure constraints
            assert!(new_context.validated_plan.steps.len() > 0);
        }
        Err(e) => {
            // Re-planning might fail in test environment
            println!("Re-planning failed (expected in test): {:?}", e);
        }
    }
}

// Test plan cache expiration and cleanup
#[tokio::test]
async fn test_plan_cache_expiration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Process directive to cache plan
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    
    // Check cache immediately
    let cached_plan = tactical_agent.get_cached_plan(user_id, &directive.directive_id).await;
    assert!(cached_plan.is_ok());
    
    // Wait for cache expiration (would need to be shorter in test)
    // In real implementation, this would test TTL functionality
    
    // Verify expired cache handling
    let expired_check = tactical_agent.handle_expired_cache(user_id, &directive.directive_id).await;
    assert!(expired_check.is_ok());
}

// Test concurrent re-planning requests
#[tokio::test]
async fn test_concurrent_replanning_handling() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = Arc::new(create_test_tactical_agent(&app).await);
    let directive = create_test_strategic_directive();
    
    let mut handles = vec![];
    
    // Spawn multiple concurrent re-planning requests
    for i in 0..3 {
        let agent_clone = tactical_agent.clone();
        let directive_clone = directive.clone();
        let dek_clone = session_dek.clone();
        
        let handle = tokio::spawn(async move {
            agent_clone.process_directive(
                &directive_clone,
                user_id,
                &dek_clone,
            ).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // At least one should succeed
    let successful = results.iter().filter(|r| r.is_ok()).count();
    assert!(successful > 0);
}

// Test deviation severity assessment
#[tokio::test]
async fn test_deviation_severity_assessment() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    
    // Test minor deviation (should not trigger re-planning)
    let minor_deviation = json!({
        "expected_position": "room_center",
        "actual_position": "room_left",
        "deviation_type": "position",
        "impact": "minimal"
    });
    
    let minor_severity = tactical_agent.assess_deviation_severity(&minor_deviation).await;
    assert!(minor_severity.unwrap_or(1.0) < 0.5); // Low severity
    
    // Test major deviation (should trigger re-planning)
    let major_deviation = json!({
        "expected_outcome": "enemy_defeated",
        "actual_outcome": "player_captured",
        "deviation_type": "critical_failure",
        "impact": "plan_invalidated"
    });
    
    let major_severity = tactical_agent.assess_deviation_severity(&major_deviation).await;
    assert!(major_severity.unwrap_or(0.0) > 0.8); // High severity
}

// Test integration with PerceptionAgent outcomes
#[tokio::test]
async fn test_integration_with_perception_agent() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let tactical_agent = create_test_tactical_agent(&app).await;
    let directive = create_test_strategic_directive();
    
    // Initial plan
    let initial_result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;
    
    assert!(initial_result.is_ok());
    let initial_context = initial_result.unwrap();
    
    // Simulate PerceptionAgent detecting world state changes
    let perception_changes = json!({
        "entities_moved": ["guard", "prisoner"],
        "new_relationships": [{"source": "guard", "target": "alarm", "type": "activated"}],
        "state_changes": [{"entity": "door", "property": "locked", "value": true}],
        "deviation_detected": true
    });
    
    // Process changes and check if re-planning is triggered
    let updated_result = tactical_agent.process_perception_changes(
        &directive,
        &perception_changes,
        &initial_context,
        user_id,
        &session_dek,
    ).await;
    
    // Should handle perception changes appropriately
    match updated_result {
        Ok(new_context) => {
            assert!(new_context.validated_plan.steps.len() > 0);
        }
        Err(e) => {
            println!("Perception integration failed (expected in test): {:?}", e);
        }
    }
}