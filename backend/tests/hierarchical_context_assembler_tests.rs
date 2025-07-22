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
    models::{
        characters::CharacterMetadata,
        chats::MessageRole,
    },
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
    create_functional_assembler_with_options(test_app, true, true).await
}

/// Helper to create a functional HierarchicalContextAssembler with options for including responses
async fn create_functional_assembler_with_options(
    test_app: &scribe_backend::test_helpers::TestApp,
    include_emotional_state: bool,
    include_spatial_location: bool,
) -> HierarchicalContextAssembler {
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
    
    // Add spatial location response
    let spatial_response = r#"{
        "location_name": "Castle Hall",
        "location_type": "Room",
        "parent_location": "Castle",
        "description": "A grand hall within the castle"
    }"#.to_string();
    
    // Add relationship extraction response
    let relationship_response = r#"[{
        "from_entity": "Sir Galahad",
        "to_entity": "Princess Guinevere",
        "relationship_type": "acquaintance",
        "strength": 0.7,
        "context": "Talking to the princess"
    }, {
        "from_entity": "Sir Galahad",
        "to_entity": "Merlin",
        "relationship_type": "student",
        "strength": 0.8,
        "context": "Seeks guidance from mentor"
    }]"#.to_string();
    
    // Add recent actions response
    let recent_actions_response = r#"[{
        "description": "Spoke to Princess Guinevere",
        "action_type": "social",
        "impact_level": 0.7,
        "timestamp_relative": "recently"
    }, {
        "description": "Sought guidance from mentor",
        "action_type": "social",
        "impact_level": 0.8,
        "timestamp_relative": "just now"
    }]"#.to_string();
    
    let emotional_state_response = r#"{
        "primary_emotion": "grief",
        "intensity": 0.8,
        "contributing_factors": ["loss of friend", "doubt about mission", "seeking redemption"]
    }"#.to_string();
    
    let recent_events_response = r#"[{
        "description": "Defended the village from bandits",
        "significance": 0.8,
        "time_ago": "yesterday"
    }, {
        "description": "Received urgent message from the king",
        "significance": 0.9,
        "time_ago": "this morning"
    }]"#.to_string();
    
    let future_events_response = r#"[{
        "description": "Must arrive at castle to meet the king",
        "time_until": "tomorrow evening",
        "participants": ["Sir Galahad", "The King"],
        "urgency": 0.9
    }]"#.to_string();
    
    // Create mock AI client with multiple responses
    // Build response list based on what will actually be called
    let mut responses = vec![
        intent_response, 
        strategic_response, 
        tactical_response,
    ];
    
    // Character entity extraction responses (if character is present)
    if include_spatial_location {
        responses.push(spatial_response);
    }
    responses.push(relationship_response);
    responses.push(recent_actions_response);
    if include_emotional_state {
        responses.push(emotional_state_response);
    }
    
    // Entity resolution responses
    responses.push(entity_response.clone()); // narrative context
    responses.push(r#"{"entity_names": []}"#.to_string()); // entity names
    
    // Temporal event extraction
    responses.push(recent_events_response);
    responses.push(future_events_response);
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    
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
        "test-model".to_string(),
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
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    
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
        "test-model".to_string(),
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
async fn test_risk_identification() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "I want to attack the dragon in the dangerous cave",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    if result.is_err() {
        eprintln!("Error in assemble_enriched_context: {:?}", result.as_ref().unwrap_err());
    }
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have identified risks in the validated plan
    assert!(!context.validated_plan.risk_assessment.identified_risks.is_empty());
    
    // Should have at least one risk identified
    let identified_risks = &context.validated_plan.risk_assessment.identified_risks;
    assert!(identified_risks.len() > 0);
    
    // Should have risk description
    assert!(identified_risks[0].len() > 0);
    
    // For dangerous scenarios, overall risk should be Medium or higher
    assert!(matches!(context.validated_plan.risk_assessment.overall_risk, 
        RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical));
}

#[tokio::test]
async fn test_spatial_location_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler(&test_app).await;
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "I am standing in the grand castle hall",
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
    
    // Should have spatial location information
    assert!(character_entity.spatial_location.is_some());
    
    let spatial_location = character_entity.spatial_location.as_ref().unwrap();
    assert!(!spatial_location.name.is_empty());
    assert_eq!(spatial_location.location_type, "Scene");
    
    // Should have spatial context in the overall context
    assert!(context.spatial_context.is_some());
    let spatial_context = context.spatial_context.as_ref().unwrap();
    assert!(!spatial_context.current_location.name.is_empty());
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

#[tokio::test]
async fn test_entity_resolution_integration() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        format!("test_entity_resolution_{}", Uuid::new_v4()),
        "password123".to_string(),
    ).await.unwrap();
    guard.add_user(user.id);
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create assembler with entity resolution response
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
            "expected_outcomes": ["Emotional foundation set"],
            "required_entities": ["Sir Galahad"],
            "estimated_duration": 1000
        }],
        "overall_risk": "Low",
        "mitigation_strategies": ["Maintain character consistency"]
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
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#.to_string();
    
    // Entity resolution response with additional entities
    let entity_response = r#"{
        "resolved_entities": [
            {
                "entity_id": "11111111-1111-1111-1111-111111111111",
                "name": "Sir Galahad",
                "display_name": "Sir Galahad",
                "entity_type": "CHARACTER",
                "confidence": 0.9,
                "is_new": false,
                "context": "Knight mentioned in the query",
                "properties": ["Noble", "Knight"],
                "components": ["Position", "Health"]
            },
            {
                "entity_id": "22222222-2222-2222-2222-222222222222",
                "name": "Kingdom of Camelot",
                "display_name": "Kingdom of Camelot",
                "entity_type": "LOCATION",
                "confidence": 0.8,
                "is_new": true,
                "context": "Referenced kingdom in the story",
                "properties": ["Kingdom", "Castle"],
                "components": ["Spatial", "Political"]
            }
        ],
        "relationships": [
            {
                "from_entity": "11111111-1111-1111-1111-111111111111",
                "to_entity": "22222222-2222-2222-2222-222222222222",
                "relationship_type": "SERVES",
                "confidence": 0.9
            }
        ],
        "user_id": "5f53b14b-6a44-420e-a0bd-2242e349b60e",
        "chronicle_id": null,
        "processing_metadata": {
            "total_entities_processed": 2,
            "new_entities_created": 1,
            "relationships_identified": 1,
            "confidence_average": 0.85
        }
    }"#.to_string();
    
    let responses = vec![intent_response, strategic_response, tactical_response, entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    let db_pool = Arc::new(test_app.db_pool.clone());
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
        "test-model".to_string(),
    );
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Tell me about Sir Galahad's adventures in the kingdom",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have multiple entities from entity resolution
    assert!(context.relevant_entities.len() >= 2);
    
    // Should have the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    
    // Should have high narrative importance
    assert!(character_entity.narrative_importance >= 0.8);
    
    // Should have AI insights about entity resolution
    assert!(character_entity.ai_insights.iter()
        .any(|insight| insight.contains("confidence") || insight.contains("resolved")));
    
    // Entity resolution should have added additional entities
    let has_additional_entities = context.relevant_entities.iter()
        .any(|e| e.entity_name != "Sir Galahad");
    assert!(has_additional_entities, "Entity resolution should add additional entities");
}

#[tokio::test]
async fn test_entity_resolution_error_handling() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        format!("test_entity_error_{}", Uuid::new_v4()),
        "password123".to_string(),
    ).await.unwrap();
    guard.add_user(user.id);
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create assembler with failing entity resolution
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
            "expected_outcomes": ["Emotional foundation set"],
            "required_entities": ["Sir Galahad"],
            "estimated_duration": 1000
        }],
        "overall_risk": "Low",
        "mitigation_strategies": ["Maintain character consistency"]
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
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#.to_string();
    
    // Invalid entity response that should cause error
    let invalid_entity_response = "INVALID_JSON_FOR_ENTITY_RESOLUTION".to_string();
    
    let responses = vec![intent_response, strategic_response, tactical_response, invalid_entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    let db_pool = Arc::new(test_app.db_pool.clone());
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
        "test-model".to_string(),
    );
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Tell me about Sir Galahad's adventures in the kingdom",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    // Should still succeed even with entity resolution failure
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have at least the character entity (graceful fallback)
    assert!(context.relevant_entities.len() >= 1);
    
    // Should have the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present even with entity resolution failure");
    
    // Should have high narrative importance
    assert!(character_entity.narrative_importance >= 0.8);
}

#[tokio::test]
async fn test_entity_dependencies_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        format!("test_entity_deps_{}", Uuid::new_v4()),
        "password123".to_string(),
    ).await.unwrap();
    guard.add_user(user.id);
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create assembler with tactical response that includes entity dependencies
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
            "expected_outcomes": ["Emotional foundation set"],
            "required_entities": ["Sir Galahad", "Kingdom"],
            "estimated_duration": 1000
        }, {
            "description": "Introduce supporting characters",
            "preconditions": ["Emotional state established"],
            "expected_outcomes": ["Supporting cast introduced"],
            "required_entities": ["Sir Galahad", "Merlin", "Arthur"],
            "estimated_duration": 1500
        }],
        "overall_risk": "Low",
        "mitigation_strategies": ["Maintain character consistency"]
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
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#.to_string();
    
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
    
    let responses = vec![intent_response, strategic_response, tactical_response, entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    let db_pool = Arc::new(test_app.db_pool.clone());
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
        "test-model".to_string(),
    );
    
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Tell me about Sir Galahad's adventures with Arthur and Merlin",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have entity dependencies extracted from the plan steps
    assert!(context.validated_plan.entity_dependencies.len() > 0);
    
    // Each unique entity name should generate a UUID
    // Expected entities: Sir Galahad, Kingdom, Merlin, Arthur (4 unique entities)
    assert!(context.validated_plan.entity_dependencies.len() >= 4);
    
    // All entity dependencies should be unique
    let mut unique_deps = std::collections::HashSet::new();
    for dep in &context.validated_plan.entity_dependencies {
        assert!(unique_deps.insert(dep), "Duplicate entity dependency found: {}", dep);
    }
    
    // Should have 2 steps as defined in the tactical response
    assert_eq!(context.validated_plan.steps.len(), 2);
    
    // First step should have 2 required entities
    assert_eq!(context.validated_plan.steps[0].required_entities.len(), 2);
    assert!(context.validated_plan.steps[0].required_entities.contains(&"Sir Galahad".to_string()));
    assert!(context.validated_plan.steps[0].required_entities.contains(&"Kingdom".to_string()));
    
    // Second step should have 3 required entities
    assert_eq!(context.validated_plan.steps[1].required_entities.len(), 3);
    assert!(context.validated_plan.steps[1].required_entities.contains(&"Sir Galahad".to_string()));
    assert!(context.validated_plan.steps[1].required_entities.contains(&"Merlin".to_string()));
    assert!(context.validated_plan.steps[1].required_entities.contains(&"Arthur".to_string()));
}

#[tokio::test]
async fn test_relationship_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        "test_user@example.com".to_string(),
        "TestUser".to_string(),
    ).await.unwrap();
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create a functional assembler
    let assembler = create_functional_assembler(&test_app).await;
    
    // Create chat history that implies relationships
    let chat_history = vec![
        GenAiChatMessage::user("Sir Galahad is talking to Princess Guinevere"),
        GenAiChatMessage::assistant("The knight bows respectfully to the princess."),
        GenAiChatMessage::user("Merlin is Sir Galahad's mentor and guide"),
    ];
    
    let result = assembler.assemble_enriched_context(
        "Sir Galahad seeks guidance from his mentor about the princess",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should find the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    
    // Debug: Print relationship count and details
    println!("Character entity relationships count: {}", character_entity.relationships.len());
    for (i, rel) in character_entity.relationships.iter().enumerate() {
        println!("Relationship {}: {} -> {} ({}), strength: {}", i, rel.from_entity, rel.to_entity, rel.relationship_type, rel.strength);
    }
    
    // Should have extracted relationships
    assert!(character_entity.relationships.len() > 0);
    
    // Should have relationship with high confidence (>= 0.6)
    assert!(character_entity.relationships.iter()
        .any(|r| r.strength >= 0.6));
    
    // Should have meaningful relationship types
    assert!(character_entity.relationships.iter()
        .any(|r| !r.relationship_type.is_empty()));
    
    // Should have contextual information
    assert!(character_entity.relationships.iter()
        .any(|r| !r.context.is_empty()));
}

#[tokio::test]
async fn test_recent_actions_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        "test_user@example.com".to_string(),
        "TestUser".to_string(),
    ).await.unwrap();
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create a functional assembler
    let assembler = create_functional_assembler(&test_app).await;
    
    // Create chat history that implies recent actions
    let chat_history = vec![
        GenAiChatMessage::user("Sir Galahad fought the dragon yesterday"),
        GenAiChatMessage::assistant("The brave knight strikes with his sword, wounding the beast."),
        GenAiChatMessage::user("Then he spoke to the princess"),
        GenAiChatMessage::assistant("The princess listens to the knight's tale of valor."),
        GenAiChatMessage::user("Now he seeks guidance from his mentor"),
    ];
    
    let result = assembler.assemble_enriched_context(
        "Sir Galahad seeks guidance from his mentor about the dragon fight",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should find the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    
    // Debug: Print recent actions count and details
    println!("Character entity recent actions count: {}", character_entity.recent_actions.len());
    for (i, action) in character_entity.recent_actions.iter().enumerate() {
        println!("Action {}: {} ({}), impact: {}", i, action.description, action.action_type, action.impact_level);
    }
    
    // Should have extracted recent actions
    assert!(character_entity.recent_actions.len() > 0);
    
    // Should have actions with reasonable impact levels
    assert!(character_entity.recent_actions.iter()
        .any(|a| a.impact_level >= 0.5));
    
    // Should have meaningful action types
    assert!(character_entity.recent_actions.iter()
        .any(|a| !a.action_type.is_empty()));
    
    // Should have meaningful descriptions
    assert!(character_entity.recent_actions.iter()
        .any(|a| !a.description.is_empty()));
}

#[tokio::test]
async fn test_emotional_state_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        "test_user@example.com".to_string(),
        "TestUser".to_string(),
    ).await.unwrap();
    
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create a functional assembler
    let assembler = create_functional_assembler(&test_app).await;
    
    // Create chat history that implies emotional states
    let chat_history = vec![
        GenAiChatMessage::user("Sir Galahad is devastated by the loss of his closest friend"),
        GenAiChatMessage::assistant("The knight's shoulders sag with grief as he mourns the fallen companion."),
        GenAiChatMessage::user("He struggles with anger and doubt about his mission"),
        GenAiChatMessage::assistant("Sir Galahad's usual noble composure cracks, revealing deep uncertainty."),
        GenAiChatMessage::user("Now he seeks redemption and peace through meditation"),
    ];
    
    let result = assembler.assemble_enriched_context(
        "Sir Galahad meditates, seeking inner peace after his friend's death",
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should find the character entity
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    
    // Should have extracted emotional state
    assert!(character_entity.emotional_state.is_some());
    
    let emotional_state = character_entity.emotional_state.as_ref().unwrap();
    
    // Debug: Print emotional state details
    println!("Emotional state: {} (intensity: {})", emotional_state.primary_emotion, emotional_state.intensity);
    println!("Contributing factors: {:?}", emotional_state.contributing_factors);
    
    // Should have a valid primary emotion
    assert!(!emotional_state.primary_emotion.is_empty());
    
    // Should have reasonable intensity (0.0 to 1.0)
    assert!(emotional_state.intensity >= 0.0 && emotional_state.intensity <= 1.0);
    
    // Should have some contributing factors
    assert!(!emotional_state.contributing_factors.is_empty());
    
    // Should have meaningful contributing factors
    assert!(emotional_state.contributing_factors.iter()
        .any(|f| !f.is_empty()));
}

#[tokio::test]
async fn test_temporal_event_extraction() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user and DEK
    let user = create_test_user(
        &test_app.db_pool,
        "test_user@example.com".to_string(),
        "TestUser".to_string(),
    ).await.unwrap();
    
    let user_dek = Arc::new(generate_dek().unwrap());
    
    // Create a mock AI client that properly handles the temporal extraction flow
    // We'll set up the mocks to avoid the entity resolution complexity
    let mock_responses = vec![
        // 1. Intent detection
        r#"{
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
        }"#.to_string(),
        
        // 2. Strategic directive
        r#"{
            "directive_type": "Journey Preparation",
            "narrative_arc": "Hero's Journey",
            "plot_significance": "Major",
            "emotional_tone": "Urgent",
            "character_focus": ["Sir Galahad"],
            "world_impact_level": "Regional"
        }"#.to_string(),
        
        // 3. Tactical plan
        r#"{
            "steps": [{
                "description": "Plan journey route",
                "preconditions": ["Ready to travel"],
                "expected_outcomes": ["Route determined"],
                "required_entities": ["Sir Galahad"],
                "estimated_duration": 1000
            }],
            "overall_risk": "Low",
            "mitigation_strategies": ["Account for delays"]
        }"#.to_string(),
        
        // 4. Entity resolution will fail but that's ok
        r#"{"error": "mock failure"}"#.to_string(),
        
        // 5. Recent events extraction
        r#"[{
            "description": "Defended the village from bandits",
            "significance": 0.8,
            "time_ago": "yesterday"
        }, {
            "description": "Received urgent message from the king",
            "significance": 0.9,
            "time_ago": "this morning"
        }]"#.to_string(),
        
        // 6. Future events extraction  
        r#"[{
            "description": "Must arrive at castle to meet the king",
            "time_until": "tomorrow evening",
            "participants": ["Sir Galahad", "The King"],
            "urgency": 0.9
        }]"#.to_string(),
    ];
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(mock_responses));
    
    // Create services
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    let entity_tool = Arc::new(EntityResolutionTool::new(test_app.app_state.clone()));
    let encryption_service = Arc::new(EncryptionService);
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    let assembler = HierarchicalContextAssembler::new(
        mock_ai_client,
        intent_service,
        query_planner,
        entity_tool,
        encryption_service,
        db_pool,
        "test-model".to_string(),
    );
    
    // Create chat history with temporal indicators
    let chat_history = vec![
        GenAiChatMessage::user("Yesterday, Sir Galahad defended the village from bandits"),
        GenAiChatMessage::assistant("The knight fought valiantly."),
        GenAiChatMessage::user("This morning he received an urgent royal summons"),
        GenAiChatMessage::assistant("The king requires his presence."),
        GenAiChatMessage::user("He must arrive by tomorrow evening"),
    ];
    
    // Test without character to avoid encryption/entity extraction complexity
    let result = assembler.assemble_enriched_context(
        "Sir Galahad prepares for the journey to meet the king's deadline",
        &chat_history,
        None, // No character to simplify the test
        user.id,
        Some(&user_dek),
    ).await;
    
    if let Err(ref e) = result {
        eprintln!("Error assembling enriched context: {:?}", e);
    }
    assert!(result.is_ok(), "Should successfully assemble enriched context");
    let context = result.unwrap();
    
    // Should have temporal context
    assert!(context.temporal_context.is_some(), "Temporal context should be populated");
    
    let temporal_context = context.temporal_context.unwrap();
    
    // Debug: Print temporal event details
    println!("Recent events count: {}", temporal_context.recent_events.len());
    for (i, event) in temporal_context.recent_events.iter().enumerate() {
        println!("Event {}: {} (significance: {})", i, event.description, event.significance);
    }
    
    println!("Future scheduled events count: {}", temporal_context.future_scheduled_events.len());
    for (i, event) in temporal_context.future_scheduled_events.iter().enumerate() {
        println!("Scheduled Event {}: {} at {:?}", i, event.description, event.scheduled_time);
    }
    
    // Should have extracted recent events
    assert!(!temporal_context.recent_events.is_empty());
    
    // Should have events with reasonable significance
    assert!(temporal_context.recent_events.iter()
        .any(|e| e.significance > 0.0));
    
    // Should have meaningful descriptions
    assert!(temporal_context.recent_events.iter()
        .any(|e| !e.description.is_empty()));
    
    // Should have extracted future scheduled events
    assert!(!temporal_context.future_scheduled_events.is_empty());
    
    // Should have future events with participants
    assert!(temporal_context.future_scheduled_events.iter()
        .any(|e| !e.participants.is_empty()));
}