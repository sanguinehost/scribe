// Test for Epic 7: Progressive Response Architecture
// This test validates that the immediate response path completes in <2 seconds

use std::time::Instant;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use scribe_backend::{
    test_helpers::{spawn_app_with_options, TestDataGuard, db::create_test_user},
    models::{
        chats::{ChatMessageForClient, MessageRole},
    },
    services::{
        agentic::hierarchical_pipeline::{HierarchicalAgentPipeline, HierarchicalPipelineConfig},
        agent_prompt_templates::PromptTemplateVersion,
    },
    auth::session_dek::SessionDek,
};

#[tokio::test]
async fn test_progressive_response_under_2_seconds() {
    // Initialize test environment
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let user = create_test_user(&test_app.db_pool, "speed_test_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    guard.add_user(user.id);
    
    // Create a session DEK
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create test chat history
    let session_id = Uuid::new_v4();
    let chat_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Hello, I'm exploring a mysterious forest.".to_string(),
            created_at: Utc::now(),
            user_id: user.id,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "gemini-2.0-flash-exp".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "The ancient trees tower above you, their branches forming a dense canopy.".to_string(),
            created_at: Utc::now(),
            user_id: user.id,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "gemini-2.0-flash-exp".to_string(),
        },
    ];
    
    // Create hierarchical pipeline with progressive response enabled
    let config = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V1,
        response_generation_model: "gemini-2.0-flash-exp".to_string(),
        enable_optimizations: false, // Disable to avoid complex perception agent calls
        max_pipeline_time_ms: 30000,
        enable_parallel_agents: false,
        enable_progressive_response: true, // KEY: Enable progressive response
    };
    
    let pipeline = HierarchicalAgentPipeline::from_app_state(&test_app.app_state, Some(config));
    
    // Set up mock AI responses for perception and generation
    // First response: entity extraction
    test_app.mock_ai_client.as_ref().unwrap().set_next_chat_response(r#"{
        "entities": [
            {"name": "Forest", "entity_type": "Location", "relevance_score": 0.9, "context_notes": "Dense forest setting"},
            {"name": "Trees", "entity_type": "Object", "relevance_score": 0.8, "context_notes": "Ancient trees with glowing symbols"}
        ],
        "confidence": 0.85
    }"#.to_string());
    
    // Queue the operational response separately
    // Second response: hierarchy analysis
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{
        "hierarchy_insights": [
            {"entity_name": "Forest", "hierarchy_depth": 1, "parent_entity": null, "child_entities": ["Trees"]}
        ],
        "spatial_relationships": []
    }"#.to_string());
    
    // Third response: salience analysis
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{
        "salience_updates": [
            {"entity_name": "Forest", "previous_tier": null, "new_tier": "Core", "reasoning": "Primary location", "confidence": 0.9}
        ],
        "newly_salient": ["Forest"],
        "confidence": 0.85
    }"#.to_string());
    
    // Fourth response: operational response generation
    test_app.mock_ai_client.as_ref().unwrap().add_response("You notice strange glowing symbols carved into the bark of the nearest tree.".to_string());
    
    // Execute the progressive response and measure time
    let current_message = "I examine the trees more closely.";
    let start_time = Instant::now();
    
    let result = pipeline.execute_progressive(
        &chat_history,
        user.id,
        &session_dek,
        current_message,
    ).await.unwrap();
    
    let elapsed = start_time.elapsed();
    
    // Verify response was generated
    assert!(!result.response.is_empty(), "Response should not be empty");
    assert!(result.response.contains("glowing symbols"), "Response should contain expected content");
    
    // Verify timing - should be under 2 seconds
    info!("Progressive response completed in {:?}", elapsed);
    assert!(
        elapsed.as_secs() < 2,
        "Progressive response should complete in under 2 seconds, but took {:?}",
        elapsed
    );
    
    // Verify that perception data was captured
    assert!(result.enriched_context.perception_analysis.is_some(), "Perception analysis should be present");
    let perception = result.enriched_context.perception_analysis.as_ref().unwrap();
    assert_eq!(perception.contextual_entities.len(), 2, "Should have 2 contextual entities");
    assert_eq!(perception.hierarchy_insights.len(), 1, "Should have 1 hierarchy insight");
    assert_eq!(perception.salience_updates.len(), 1, "Should have 1 salience update");
    
    // Verify metrics show minimal processing
    assert_eq!(result.metrics.strategic_time_ms, 0, "Strategic time should be 0 in progressive mode");
    assert_eq!(result.metrics.tactical_time_ms, 0, "Tactical time should be 0 in progressive mode");
    assert!(result.metrics.perception_time_ms > 0, "Perception time should be > 0");
    assert!(result.metrics.operational_time_ms > 0, "Operational time should be > 0");
    
    info!("✅ Progressive response test passed with timing: {:?}", elapsed);
}

#[tokio::test]
async fn test_progressive_vs_full_pipeline_timing() {
    // This test compares the timing of progressive vs full pipeline
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let user = create_test_user(&test_app.db_pool, "comparison_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    guard.add_user(user.id);
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let session_id = Uuid::new_v4();
    let chat_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Tell me about this world.".to_string(),
            created_at: Utc::now(),
            user_id: user.id,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "gemini-2.0-flash-exp".to_string(),
        },
    ];
    
    // Test 1: Progressive Response (should be fast)
    let progressive_config = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V1,
        response_generation_model: "gemini-2.0-flash-exp".to_string(),
        enable_optimizations: true,
        max_pipeline_time_ms: 30000,
        enable_parallel_agents: true,
        enable_progressive_response: true,
    };
    
    let progressive_pipeline = HierarchicalAgentPipeline::from_app_state(&test_app.app_state, Some(progressive_config));
    
    // Set up mock responses for progressive mode
    // Entity extraction
    test_app.mock_ai_client.as_ref().unwrap().set_next_chat_response(r#"{"entities": [], "confidence": 0.8}"#.to_string());
    // Hierarchy analysis  
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"hierarchy_insights": [], "spatial_relationships": []}"#.to_string());
    // Salience analysis
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"salience_updates": [], "newly_salient": [], "confidence": 0.8}"#.to_string());
    test_app.mock_ai_client.as_ref().unwrap().add_response("This is a quick response about the world.".to_string());
    
    let progressive_start = Instant::now();
    let progressive_result = progressive_pipeline.execute_progressive(
        &chat_history,
        user.id,
        &session_dek,
        "What's happening here?",
    ).await.unwrap();
    let progressive_time = progressive_start.elapsed();
    
    // Test 2: Full Pipeline (should be slower)
    let full_config = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V1,
        response_generation_model: "gemini-2.0-flash-exp".to_string(),
        enable_optimizations: true,
        max_pipeline_time_ms: 30000,
        enable_parallel_agents: true,
        enable_progressive_response: false, // Disable progressive
    };
    
    let full_pipeline = HierarchicalAgentPipeline::from_app_state(&test_app.app_state, Some(full_config));
    
    // Set up mock responses for full pipeline (perception + strategic + tactical + operational)
    // Entity extraction
    test_app.mock_ai_client.as_ref().unwrap().set_next_chat_response(r#"{"entities": [], "confidence": 0.8}"#.to_string());
    // Hierarchy analysis  
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"hierarchy_insights": [], "spatial_relationships": []}"#.to_string());
    // Salience analysis
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"salience_updates": [], "newly_salient": [], "confidence": 0.8}"#.to_string());
    // Strategic
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"primary_goal": "continue", "scene_type": "exploration", "desired_tone": ["mysterious"], "focus_elements": [], "character_focus": [], "pacing_guidance": "moderate", "narrative_hooks": [], "priority": 0.8, "confidence": 0.85}"#.to_string());
    // Tactical (multiple calls)
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"steps": [{"description": "Describe world", "confidence": 0.8}], "confidence": 0.8, "validation_notes": []}"#.to_string());
    test_app.mock_ai_client.as_ref().unwrap().add_response(r#"{"sub_goal": "Describe the world", "context_requirements": [], "priority": 0.8}"#.to_string());
    // Operational
    test_app.mock_ai_client.as_ref().unwrap().add_response("This is a detailed response about the world from the full pipeline.".to_string());
    
    let full_start = Instant::now();
    let full_result = full_pipeline.execute(
        &chat_history,
        user.id,
        &session_dek,
        "What's happening here?",
    ).await.unwrap();
    let full_time = full_start.elapsed();
    
    // Compare timings
    info!("Progressive pipeline time: {:?}", progressive_time);
    info!("Full pipeline time: {:?}", full_time);
    
    // Progressive should be significantly faster
    assert!(
        progressive_time < full_time,
        "Progressive response ({:?}) should be faster than full pipeline ({:?})",
        progressive_time,
        full_time
    );
    
    // Both should produce valid responses
    assert!(!progressive_result.response.is_empty(), "Progressive response should not be empty");
    assert!(!full_result.response.is_empty(), "Full response should not be empty");
    
    // Progressive should have minimal agent processing
    assert_eq!(progressive_result.metrics.strategic_time_ms, 0, "Progressive should skip strategic");
    assert_eq!(progressive_result.metrics.tactical_time_ms, 0, "Progressive should skip tactical");
    
    // Full pipeline should have all agent processing
    assert!(full_result.metrics.strategic_time_ms > 0, "Full pipeline should have strategic time");
    assert!(full_result.metrics.tactical_time_ms > 0, "Full pipeline should have tactical time");
    
    info!("✅ Progressive vs Full pipeline comparison test passed");
}