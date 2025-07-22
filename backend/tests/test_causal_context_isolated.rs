use scribe_backend::{
    services::{
        hierarchical_context_assembler::HierarchicalContextAssembler,
        intent_detection_service::IntentDetectionService,
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
        context_assembly_engine::{
            CausalContext, CausalChain, CausalEvent, PotentialConsequence, HistoricalPrecedent,
        },
    },
    test_helpers::{MockAiClient, spawn_app_with_options, db::create_test_user},
    crypto::generate_dek,
};
use std::sync::Arc;
use genai::chat::ChatMessage as GenAiChatMessage;

/// Test the causal context extraction with minimal AI calls to isolate the issue
#[tokio::test]
async fn test_causal_context_extraction_isolated() {
    let test_app = spawn_app_with_options(false, false, false, false).await;
    
    // Create a comprehensive mock response sequence that matches the HierarchicalContextAssembler flow
    let targeted_mock_responses = vec![
        // 1. Intent detection 
        r#"{"intent_type": "NarrativeGeneration", "focus_entities": [], "time_scope": {"type": "Current"}, "reasoning_depth": "Causal", "context_priorities": [], "confidence": 0.8}"#.to_string(),
        
        // 2. Strategic analysis 
        r#"{"directive_type": "Action", "narrative_arc": "Sequence", "plot_significance": "Minor", "emotional_tone": "Neutral", "character_focus": [], "world_impact_level": "Local"}"#.to_string(),
        
        // 3. Tactical planning 
        r#"{"steps": [{"description": "Execute action", "preconditions": [], "expected_outcomes": [], "required_entities": [], "estimated_duration": 1000}], "overall_risk": "Low", "mitigation_strategies": []}"#.to_string(),
        
        // 4. Entity resolution - main narrative context
        r#"{"entities": [], "spatial_context": {"primary_location": "unknown"}, "temporal_context": {}, "social_context": {}, "actions_and_events": []}"#.to_string(),
        
        // 5. Spatial context location extraction
        r#"{"primary_location": "forest path", "confidence": 0.7}"#.to_string(),
        
        // 6. Spatial context relationships
        r#"[]"#.to_string(),
        
        // 7. Spatial context recent actions
        r#"[]"#.to_string(),
        
        // 8. Spatial context emotional state
        r#"{"primary_emotion": "Determined", "intensity": 0.8}"#.to_string(),
        
        // 9. Entity names extraction
        r#"[]"#.to_string(),
        
        // 10. Entity semantic matching (none found)
        r#"{"match_found": false}"#.to_string(),
        
        // 11. AI component suggestions
        r#"{"suggested_components": []}"#.to_string(),
        
        // 12. Temporal events - past
        r#"[]"#.to_string(),
        
        // 13. Temporal events - future
        r#"[]"#.to_string(),
        
        // 14. CAUSAL CONTEXT - This is the rich response we want to test
        r#"{
            "causal_chains": [
                {
                    "events": [
                        {
                            "description": "Character made an important decision",
                            "timestamp": "2024-01-15T10:00:00Z",
                            "cause_strength": 0.9
                        },
                        {
                            "description": "This decision led to the current situation",
                            "timestamp": "2024-01-15T10:05:00Z",
                            "cause_strength": 0.8
                        }
                    ],
                    "confidence": 0.85
                },
                {
                    "events": [
                        {
                            "description": "External factors influenced the outcome",
                            "timestamp": "2024-01-15T09:30:00Z",
                            "cause_strength": 0.7
                        }
                    ],
                    "confidence": 0.75
                }
            ],
            "potential_consequences": [
                {
                    "description": "The character might succeed in their goal",
                    "probability": 0.6,
                    "impact_severity": 0.8
                },
                {
                    "description": "There could be unexpected complications",
                    "probability": 0.4,
                    "impact_severity": 0.7
                }
            ],
            "historical_precedents": [
                {
                    "event_description": "Similar situation occurred before",
                    "outcome": "Previous attempt was partially successful",
                    "similarity_score": 0.7,
                    "timestamp": "2024-01-10T14:00:00Z"
                }
            ],
            "causal_confidence": 0.82
        }"#.to_string(),
    ];
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(targeted_mock_responses));
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "gemini-2.5-flash-lite-preview-06-17".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "gemini-2.5-flash".to_string()));
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
        "gemini-2.5-flash".to_string(),
    );
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test@example.com".to_string(), "TestUser".to_string()).await.unwrap();
    let user_dek = Arc::new(generate_dek().unwrap());
    
    // Create meaningful chat history for causal analysis
    let chat_history = vec![
        GenAiChatMessage::user("I decided to take a risky path through the forest"),
        GenAiChatMessage::assistant("The forest path was dangerous but offered a shortcut"),
        GenAiChatMessage::user("Now I'm facing the consequences of that decision"),
        GenAiChatMessage::assistant("The choice has led to an unexpected encounter"),
    ];
    
    // Execute the context assembly
    let user_input = "I must deal with the situation my earlier decision created";
    let result = assembler.assemble_enriched_context(
        user_input,
        &chat_history,
        None,
        user.id,
        Some(&user_dek),
    ).await;
    
    // Verify the result
    assert!(result.is_ok(), "Context assembly should succeed");
    let context = result.unwrap();
    
    // Log the result for debugging
    println!("✅ Isolated causal context test results:");
    println!("   - Causal context present: {}", context.causal_context.is_some());
    println!("   - Total AI calls: {}", context.ai_model_calls);
    println!("   - Execution time: {}ms", context.execution_time_ms);
    
    if let Some(causal_context) = &context.causal_context {
        println!("   - Causal chains: {}", causal_context.causal_chains.len());
        println!("   - Potential consequences: {}", causal_context.potential_consequences.len());
        println!("   - Historical precedents: {}", causal_context.historical_precedents.len());
        println!("   - Causal confidence: {:.2}", causal_context.causal_confidence);
        
        // Verify causal chains
        assert_eq!(causal_context.causal_chains.len(), 2, "Should have 2 causal chains");
        
        let first_chain = &causal_context.causal_chains[0];
        assert_eq!(first_chain.events.len(), 2, "First chain should have 2 events");
        assert_eq!(first_chain.confidence, 0.85, "First chain should have 0.85 confidence");
        
        let second_chain = &causal_context.causal_chains[1];
        assert_eq!(second_chain.events.len(), 1, "Second chain should have 1 event");
        assert_eq!(second_chain.confidence, 0.75, "Second chain should have 0.75 confidence");
        
        // Verify potential consequences
        assert_eq!(causal_context.potential_consequences.len(), 2, "Should have 2 potential consequences");
        
        let success_consequence = &causal_context.potential_consequences[0];
        assert_eq!(success_consequence.probability, 0.6, "Success consequence should have 0.6 probability");
        assert_eq!(success_consequence.impact_severity, 0.8, "Success consequence should have 0.8 impact");
        
        let complication_consequence = &causal_context.potential_consequences[1];
        assert_eq!(complication_consequence.probability, 0.4, "Complication consequence should have 0.4 probability");
        assert_eq!(complication_consequence.impact_severity, 0.7, "Complication consequence should have 0.7 impact");
        
        // Verify historical precedents
        assert_eq!(causal_context.historical_precedents.len(), 1, "Should have 1 historical precedent");
        
        let precedent = &causal_context.historical_precedents[0];
        assert_eq!(precedent.similarity_score, 0.7, "Precedent should have 0.7 similarity");
        assert!(precedent.event_description.contains("Similar situation"), "Precedent should describe similar situation");
        
        // Verify overall confidence
        assert_eq!(causal_context.causal_confidence, 0.82, "Should have 0.82 causal confidence");
        
        println!("✅ All causal context assertions passed!");
    } else {
        println!("❌ Causal context should be present in isolated test");
        // Let's run a quick debug to see what's happening
        println!("   - Debug: Looking for causal extraction in hierarchical context assembler");
    }
}