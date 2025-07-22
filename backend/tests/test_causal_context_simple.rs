use scribe_backend::{
    services::{
        hierarchical_context_assembler::HierarchicalContextAssembler,
        intent_detection_service::IntentDetectionService,
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
    },
    test_helpers::{MockAiClient, spawn_app_with_options, db::create_test_user},
    crypto::generate_dek,
};
use std::sync::Arc;
use genai::chat::ChatMessage as GenAiChatMessage;

/// Create a basic functional assembler for simple testing
async fn create_basic_assembler(test_app: &scribe_backend::test_helpers::TestApp) -> HierarchicalContextAssembler {
    let basic_responses = vec![
        r#"{"intent_type": "NarrativeGeneration", "focus_entities": [], "time_scope": {"type": "Current"}, "spatial_scope": null, "reasoning_depth": "Surface", "context_priorities": [], "confidence": 0.8}"#.to_string(),
        r#"{"directive_type": "Combat", "narrative_arc": "Action", "plot_significance": "Minor"}"#.to_string(),
        r#"{"steps": [{"description": "Execute attack", "required_entities": ["Dragon"], "estimated_duration": 1000}]}"#.to_string(),
        r#"{"primary_location": "Dragon's Lair", "confidence": 0.7}"#.to_string(),
        r#"[]"#.to_string(), // relationships
        r#"[]"#.to_string(), // recent actions
        r#"{"primary_emotion": "Determined", "intensity": 0.8}"#.to_string(),
        r#"["Dragon"]"#.to_string(), // entity names
        r#"{"entities": [{"name": "Dragon", "entity_type": "Creature"}]}"#.to_string(),
        r#"{"match_found": false}"#.to_string(), // entity matching
        r#"{"suggested_components": []}"#.to_string(), // ai components
        r#"[]"#.to_string(), // temporal events past
        r#"[]"#.to_string(), // temporal events future
        r#"{"causal_chains": [], "potential_consequences": [], "historical_precedents": [], "causal_confidence": 0.0}"#.to_string(),
    ];
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(basic_responses));
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string()));
    let entity_tool = Arc::new(EntityResolutionTool::new(test_app.app_state.clone()));
    let encryption_service = Arc::new(EncryptionService);
    let db_pool = Arc::new(test_app.db_pool.clone());
    
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
async fn test_causal_context_basic_functionality() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test@example.com".to_string(), "TestUser".to_string()).await.unwrap();
    let user_dek = Arc::new(generate_dek().unwrap());
    
    // Create a basic hierarchical context assembler
    let assembler = create_basic_assembler(&test_app).await;
    
    // Create simple chat history
    let chat_history = vec![
        GenAiChatMessage::user("I enter the dragon's lair"),
        GenAiChatMessage::assistant("The dragon awakens"),
        GenAiChatMessage::user("I attack with my sword"),
    ];
    
    // Test basic assembly
    let result = assembler.assemble_enriched_context(
        "I swing my sword at the dragon!",
        &chat_history,
        None,
        user.id,
        Some(&user_dek),
    ).await;
    
    // Just verify it doesn't crash - this is testing the implementation
    match result {
        Ok(_) => println!("✅ Basic causal context assembly works"),
        Err(e) => {
            println!("❌ Basic causal context assembly failed: {:?}", e);
            panic!("Basic causal context assembly should work: {}", e);
        }
    }
    
    let context = result.ok().unwrap();
    
    // The causal context might be None if no chat history is complex enough
    // But the function should still work
    println!("Causal context present: {}", context.causal_context.is_some());
    
    if let Some(causal_context) = context.causal_context {
        println!("Causal chains: {}", causal_context.causal_chains.len());
        println!("Potential consequences: {}", causal_context.potential_consequences.len());
        println!("Historical precedents: {}", causal_context.historical_precedents.len());
        println!("Causal confidence: {}", causal_context.causal_confidence);
    }
}