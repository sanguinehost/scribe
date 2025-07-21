// Simplified test for Epic 7: Progressive Response Architecture
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
async fn test_progressive_response_timing() {
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
            content: "Hello, I'm exploring a forest.".to_string(),
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
        enable_optimizations: false, // Disable to simplify test
        max_pipeline_time_ms: 30000,
        enable_parallel_agents: false,
        enable_progressive_response: true, // KEY: Enable progressive response
    };
    
    let pipeline = HierarchicalAgentPipeline::from_app_state(&test_app.app_state, Some(config));
    
    // Set up mock AI responses for perception pre-response analysis
    // This is a simplified version that just returns the expected JSON in one call
    test_app.mock_ai_client.as_ref().unwrap().set_next_chat_response(r#"{
        "contextual_entities": [
            {"name": "Forest", "entity_type": "Location", "relevance_score": 0.9}
        ],
        "hierarchy_analysis": {
            "hierarchy_insights": [
                {"entity_name": "Forest", "hierarchy_depth": 1, "parent_entity": null, "child_entities": []}
            ],
            "spatial_relationships": []
        },
        "salience_updates": [
            {"entity_name": "Forest", "previous_tier": null, "new_tier": "Core", "reasoning": "Primary location", "confidence": 0.9}
        ],
        "execution_time_ms": 150,
        "confidence_score": 0.85,
        "analysis_timestamp": "2025-07-20T10:00:00Z"
    }"#.to_string());
    
    // Second response: operational response generation
    test_app.mock_ai_client.as_ref().unwrap().add_response("The dense canopy overhead filters the sunlight into dancing patterns on the forest floor.".to_string());
    
    // Execute the progressive response and measure time
    let current_message = "What do I see around me?";
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
    
    // Verify timing - should be under 2 seconds
    info!("Progressive response completed in {:?}", elapsed);
    assert!(
        elapsed.as_secs() < 2,
        "Progressive response should complete in under 2 seconds, but took {:?}",
        elapsed
    );
    
    // Verify metrics show minimal processing (no strategic/tactical)
    assert_eq!(result.metrics.strategic_time_ms, 0, "Strategic time should be 0 in progressive mode");
    assert_eq!(result.metrics.tactical_time_ms, 0, "Tactical time should be 0 in progressive mode");
    assert!(result.metrics.perception_time_ms > 0, "Perception time should be > 0");
    assert!(result.metrics.operational_time_ms > 0, "Operational time should be > 0");
    
    info!("✅ Progressive response test passed with timing: {:?}", elapsed);
}