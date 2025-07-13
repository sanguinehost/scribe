use scribe_backend::{
    services::{
        hierarchical_context_assembler::HierarchicalContextAssembler,
        intent_detection_service::IntentDetectionService,
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
        context_assembly_engine::{
            PlotSignificance, WorldImpactLevel, ValidationCheckType,
            ValidationStatus, PlanValidationStatus, RiskLevel,
        },
    },
    models::characters::CharacterMetadata,
    test_helpers::{MockAiClient, spawn_app_with_options, TestDataGuard, db::create_test_user},
    crypto::{generate_dek, encrypt_gcm},
};
use std::sync::Arc;
use uuid::Uuid;
use secrecy::SecretBox;
use genai::chat::{ChatMessage as GenAiChatMessage};
use chrono::Utc;

/// Helper to create a properly encrypted test character
async fn create_encrypted_test_character(user_dek: &Arc<SecretBox<Vec<u8>>>) -> CharacterMetadata {
    let (description_ct, description_nonce) = encrypt_gcm(
        b"A brave knight with a mysterious past",
        user_dek
    ).unwrap();
    
    let (personality_ct, personality_nonce) = encrypt_gcm(
        b"Noble, courageous, but haunted by secrets",
        user_dek
    ).unwrap();
    
    let (scenario_ct, scenario_nonce) = encrypt_gcm(
        b"The kingdom is under threat from an ancient evil",
        user_dek
    ).unwrap();
    
    let (example_ct, example_nonce) = encrypt_gcm(
        b"Knight: 'I shall protect the innocent, no matter the cost.'",
        user_dek
    ).unwrap();
    
    CharacterMetadata {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "Sir Galahad".to_string(),
        description: Some(description_ct),
        description_nonce: Some(description_nonce),
        personality: Some(personality_ct),
        personality_nonce: Some(personality_nonce),
        scenario: Some(scenario_ct),
        scenario_nonce: Some(scenario_nonce),
        mes_example: Some(example_ct),
        mes_example_nonce: Some(example_nonce),
        creator_comment: None,
        creator_comment_nonce: None,
        first_mes: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a functional HierarchicalContextAssembler with real services
async fn create_functional_assembler(test_app: &scribe_backend::test_helpers::TestApp) -> HierarchicalContextAssembler {
    // Use real AI client responses for functional testing
    let strategic_response = r#"{
        "directive_type": "Character Development",
        "narrative_arc": "Hero's Journey",
        "plot_significance": "Major",
        "emotional_tone": "Determined",
        "character_focus": ["Sir Galahad"],
        "world_impact_level": "Regional"
    }"#.to_string();
    
    let tactical_response = r#"{
        "steps": [{
            "description": "Establish character's current emotional state",
            "preconditions": ["Character context available"],
            "expected_outcomes": ["Emotional foundation set", "Player engagement increased"],
            "required_entities": ["Sir Galahad"],
            "estimated_duration": 1000
        }, {
            "description": "Introduce narrative conflict",
            "preconditions": ["Emotional state established"],
            "expected_outcomes": ["Tension created", "Stakes defined"],
            "required_entities": ["Sir Galahad", "Kingdom"],
            "estimated_duration": 2000
        }],
        "overall_risk": "Low",
        "mitigation_strategies": ["Maintain character consistency", "Balance exposition with action"]
    }"#.to_string();
    
    let intent_response = r#"{
        "intent_type": "NarrativeGeneration",
        "focus_entities": [{
            "name": "Sir Galahad",
            "entity_type": "CHARACTER",
            "priority": 1.0,
            "required": true
        }],
        "time_scope": {"type": "Current"},
        "spatial_scope": null,
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities", "CausalChains", "TemporalState"],
        "confidence": 0.9
    }"#.to_string();
    
    // Add entity resolution response
    let entity_response = r#"{
        "entities": [{
            "name": "Sir Galahad",
            "entity_type": "CHARACTER",
            "confidence": 0.9,
            "context": "Knight mentioned in the query"
        }],
        "relationships": [],
        "reasoning": "Extracted character entity from user query"
    }"#.to_string();
    
    // Create mock AI client with multiple responses
    let responses = vec![intent_response, strategic_response, tactical_response, entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone()));
    
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    // Create AppState for EntityResolutionTool
    let app_state = test_app.app_state.clone();
    let entity_tool = Arc::new(EntityResolutionTool::new(app_state));
    
    let encryption_service = Arc::new(EncryptionService);
    
    HierarchicalContextAssembler::new(
        mock_ai_client,
        intent_service,
        query_planner,
        entity_tool,
        encryption_service,
        db_pool,
    )
}

#[tokio::test]
async fn test_basic_enriched_context_assembly() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_id = Uuid::new_v4();
    let user_input = "Continue the story with Sir Galahad";
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        user_input,
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    if let Err(ref e) = result {
        eprintln!("Error occurred: {:?}", e);
    }
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify basic structure
    assert!(context.strategic_directive.is_some());
    assert_eq!(context.plan_validation_status, PlanValidationStatus::Validated);
    assert!(context.total_tokens_used > 0);
    assert!(context.execution_time_ms >= 0); // Can be 0 for very fast operations
    assert!(context.ai_model_calls >= 3); // Intent, strategic, tactical
    assert_eq!(context.confidence_score, 0.75); // Default for bridge implementation
    
    // Verify strategic directive
    let directive = context.strategic_directive.unwrap();
    assert_eq!(directive.directive_type, "Character Development");
    assert_eq!(directive.narrative_arc, "Hero's Journey");
    assert_eq!(directive.plot_significance, PlotSignificance::Major);
    assert_eq!(directive.emotional_tone, "Determined");
    assert_eq!(directive.world_impact_level, WorldImpactLevel::Regional);
    assert!(directive.character_focus.contains(&"Sir Galahad".to_string()));
    
    // Verify tactical plan
    assert_eq!(context.validated_plan.steps.len(), 2);
    assert_eq!(context.validated_plan.risk_assessment.overall_risk, RiskLevel::Low);
    assert!(context.validated_plan.preconditions_met);
    assert!(context.validated_plan.causal_consistency_verified);
    
    // Verify current sub-goal (should be first step)
    assert!(context.current_sub_goal.description.contains("emotional state"));
    assert_eq!(context.current_sub_goal.priority_level, 1.0); // Based on default or max priority
    
    // Verify validation checks
    assert!(context.symbolic_firewall_checks.len() > 0);
    assert!(context.symbolic_firewall_checks.iter()
        .any(|check| check.check_type == ValidationCheckType::NarrativeCoherence));
}

#[tokio::test]
async fn test_enriched_context_with_character_encryption() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    let assembler = create_functional_assembler(&test_app).await;
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        format!("test_hierarchical_{}", Uuid::new_v4()),
        "password123".to_string(),
    ).await.unwrap();
    guard.add_user(user.id);
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    let chat_history = vec![];
    
    // Test with DEK - should decrypt character data
    let result = assembler.assemble_enriched_context(
        "Tell me about Sir Galahad's personality",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify character entity is properly populated with decrypted data
    assert!(context.relevant_entities.len() > 0);
    let character_entity = &context.relevant_entities[0];
    assert_eq!(character_entity.entity_name, "Sir Galahad");
    assert_eq!(character_entity.entity_type, "Character");
    
    // Check that decrypted data was used
    assert!(character_entity.current_state.contains_key("description"));
    assert!(character_entity.current_state.contains_key("personality"));
    assert!(character_entity.current_state.contains_key("scenario"));
    assert!(character_entity.current_state.contains_key("example_dialogue"));
    
    // AI insights should reflect decrypted content
    assert!(character_entity.ai_insights.iter()
        .any(|insight| insight.contains("Character has detailed description")));
    assert!(character_entity.ai_insights.iter()
        .any(|insight| insight.contains("Character personality defined")));
}

#[tokio::test]
async fn test_enriched_context_without_dek() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    let chat_history = vec![];
    
    // Test without DEK - should work with limited context
    let result = assembler.assemble_enriched_context(
        "What is Sir Galahad doing?",
        &chat_history,
        Some(&character),
        character.user_id,
        None, // No DEK provided
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should still have character entity but with limited data
    assert!(context.relevant_entities.len() > 0);
    let character_entity = &context.relevant_entities[0];
    assert_eq!(character_entity.entity_name, "Sir Galahad");
    
    // Should only have basic unencrypted data
    assert!(character_entity.current_state.contains_key("character_name"));
    assert!(character_entity.current_state.contains_key("character_id"));
    
    // AI insights should indicate limited context
    assert!(character_entity.ai_insights.iter()
        .any(|insight| insight.contains("Limited character context")));
}

#[tokio::test]
async fn test_chat_history_context_integration() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_id = Uuid::new_v4();
    
    // Create chat history
    let chat_history = vec![
        GenAiChatMessage::user("I want to explore the ancient ruins"),
        GenAiChatMessage::assistant("You approach the crumbling stone archway..."),
        GenAiChatMessage::user("I draw my sword and enter carefully"),
        GenAiChatMessage::assistant("The darkness swallows you as you step inside..."),
    ];
    
    let result = assembler.assemble_enriched_context(
        "What do I see in the darkness?",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Temporal context should be populated
    assert!(context.temporal_context.is_some());
    let temporal = context.temporal_context.unwrap();
    
    // Should have temporal significance set
    assert!(temporal.temporal_significance >= 0.0);
}

#[tokio::test]
async fn test_spatial_context_creation() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Where is Sir Galahad right now?",
        &chat_history,
        Some(&character),
        character.user_id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have spatial context when character is present
    assert!(context.spatial_context.is_some());
    let spatial = context.spatial_context.unwrap();
    assert_eq!(spatial.current_location.name, "Current Scene");
    assert_eq!(spatial.current_location.location_type, "Scene");
}

#[tokio::test]
async fn test_validation_checks_creation() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Start a new adventure",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have validation checks
    assert!(context.symbolic_firewall_checks.len() >= 2);
    
    // Check for expected validation types
    let has_narrative_check = context.symbolic_firewall_checks.iter()
        .any(|check| check.check_type == ValidationCheckType::NarrativeCoherence);
    let has_data_check = context.symbolic_firewall_checks.iter()
        .any(|check| check.check_type == ValidationCheckType::DataIntegrity);
    
    assert!(has_narrative_check);
    assert!(has_data_check);
    
    // All checks should pass in normal operation
    for check in &context.symbolic_firewall_checks {
        assert_eq!(check.status, ValidationStatus::Passed);
    }
}

#[tokio::test]
async fn test_error_propagation_from_intent_detection() {
    // Test that errors from intent detection are properly propagated
    let test_app = spawn_app_with_options(false, false, false, false).await;
    
    // Create an AI client that will fail on intent detection
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(
        "INVALID_JSON_FOR_INTENT".to_string()
    ));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone()));
    
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    // Create AppState for EntityResolutionTool
    let app_state = test_app.app_state.clone();
    let entity_tool = Arc::new(EntityResolutionTool::new(app_state));
    
    let encryption_service = Arc::new(EncryptionService);
    
    let assembler = HierarchicalContextAssembler::new(
        mock_ai_client,
        intent_service,
        query_planner,
        entity_tool,
        encryption_service,
        db_pool,
    );
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Test query",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    // Should propagate the error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to parse"));
}

#[tokio::test]
async fn test_multiple_entity_context_assembly() {
    // Test with multiple entities (character + others from entity resolution)
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "How does Sir Galahad interact with the kingdom?",
        &chat_history,
        Some(&character),
        character.user_id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have at least the character entity
    assert!(context.relevant_entities.len() >= 1);
    
    // Find the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    
    // Should have high narrative importance
    assert!(character_entity.narrative_importance >= 0.9);
    
    // Validated plan should reference multiple entities
    assert!(context.validated_plan.steps.iter()
        .any(|step| step.required_entities.contains(&"Kingdom".to_string())));
}

#[tokio::test]
async fn test_performance_metrics() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let start = std::time::Instant::now();
    
    let result = assembler.assemble_enriched_context(
        "Quick test",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    let elapsed = start.elapsed();
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify performance metrics
    assert!(context.execution_time_ms >= 0); // Can be 0 for very fast operations
    assert!(context.execution_time_ms < 5000); // Should complete within 5 seconds
    
    // Execution time in context should roughly match actual elapsed time
    let elapsed_ms = elapsed.as_millis() as u64;
    assert!(context.execution_time_ms <= elapsed_ms + 100); // Allow 100ms margin
    
    // Token usage should be tracked
    assert!(context.total_tokens_used > 0);
    assert!(context.total_tokens_used < 10000); // Reasonable upper bound
    
    // AI calls should be tracked
    assert_eq!(context.ai_model_calls, 4); // Intent + Strategic + Tactical + Entity
    
    // Validation time should be minimal for bridge implementation
    assert!(context.validation_time_ms <= 50);
}