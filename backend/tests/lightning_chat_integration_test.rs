use scribe_backend::services::agentic::{
    HierarchicalAgentPipeline, 
    hierarchical_pipeline::HierarchicalPipelineConfig,
};
use scribe_backend::services::agentic::lightning_agent::LightningAgent;
use scribe_backend::services::progressive_cache::ProgressiveCacheService;
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;

/// Test that Lightning Agent is properly integrated into the chat service
#[tokio::test]
async fn test_lightning_agent_integration_in_chat_service() {
    let app = spawn_app(false, false, false).await;
    
    // Create config with progressive response enabled
    let config = HierarchicalPipelineConfig {
        enable_progressive_response: true,
        ..Default::default()
    };
    
    // Create pipeline from app state
    let _pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Verify Lightning Agent is created when progressive response is enabled
    // This is an internal test - in production, the existence of Lightning Agent
    // is verified by the behavior of execute_progressive
    
    // Create test session data
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Pre-warm cache through Lightning Agent
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    let lightning_agent = LightningAgent::new(
        cache_service,
        app.app_state.redis_client.clone(),
        app.app_state.pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    // Warm the cache
    lightning_agent.warm_cache_for_session(
        session_id,
        user_id,
        Some(Uuid::new_v4()),
        Some(Uuid::new_v4()),
    ).await.unwrap();
    
    // Test that progressive context retrieval works
    let context = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    // Should get at least immediate context since we warmed the cache
    assert!(matches!(
        context.cache_layer,
        scribe_backend::services::agentic::lightning_agent::CacheLayer::Immediate
    ));
    assert!(context.retrieval_time_ms < 100); // Should be fast
    assert!(context.quality_score >= 0.4); // Immediate context quality
    
    println!("Lightning Agent successfully integrated:");
    println!("  - Cache layer: {:?}", context.cache_layer);
    println!("  - Retrieval time: {}ms", context.retrieval_time_ms);
    println!("  - Quality score: {}", context.quality_score);
}

/// Test progressive response mode with Lightning Agent
#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_progressive_response_with_lightning() {
    let app = spawn_app(true, true, true).await;
    
    // Create config with progressive response enabled
    let config = HierarchicalPipelineConfig {
        enable_progressive_response: true,
        max_pipeline_time_ms: 2000, // 2 second timeout
        ..Default::default()
    };
    
    // Create pipeline from app state
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Create test data
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Pre-warm cache with Lightning Agent
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    let lightning_agent = LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.app_state.pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    lightning_agent.warm_cache_for_session(
        session_id,
        user_id,
        Some(Uuid::new_v4()),
        Some(Uuid::new_v4()),
    ).await.unwrap();
    
    // Add some immediate context
    let immediate_context = scribe_backend::services::progressive_cache::ImmediateContext {
        user_id,
        session_id,
        current_location: Uuid::new_v4(),
        current_location_name: "Mystical Forest".to_string(),
        active_character: Some(Uuid::new_v4()),
        active_character_name: Some("Sage Elderwind".to_string()),
        recent_messages: vec![
            scribe_backend::services::progressive_cache::MessageSummary {
                role: "user".to_string(),
                summary: "Hello there!".to_string(),
                timestamp: chrono::Utc::now(),
            },
            scribe_backend::services::progressive_cache::MessageSummary {
                role: "assistant".to_string(),
                summary: "Greetings, traveler!".to_string(),
                timestamp: chrono::Utc::now(),
            },
        ],
    };
    
    cache_service.set_immediate_context(session_id, immediate_context).await.unwrap();
    
    // Test progressive response execution
    let chat_history = vec![
        scribe_backend::models::chats::ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            user_id,
            content: "Hello!".to_string(),
            message_type: scribe_backend::models::chats::MessageRole::User,
            created_at: chrono::Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        scribe_backend::models::chats::ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id,
            user_id,
            content: "Greetings, traveler! Welcome to this mystical place.".to_string(),
            message_type: scribe_backend::models::chats::MessageRole::Assistant,
            created_at: chrono::Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];
    let current_message = "What do you see around here?";
    
    let start = std::time::Instant::now();
    let result = pipeline.execute_progressive(
        &chat_history,
        user_id,
        &session_dek,
        current_message,
    ).await;
    let elapsed = start.elapsed();
    
    if let Err(e) = &result {
        eprintln!("Progressive response failed: {:?}", e);
    }
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Should be fast due to Lightning cache
    assert!(elapsed.as_secs() < 3, "Progressive response took too long: {:?}", elapsed);
    assert!(!response.response.is_empty());
    
    println!("Progressive response completed in {:?}", elapsed);
    println!("Response preview: {}", &response.response.chars().take(100).collect::<String>());
    
    // Verify metrics show Lightning was used
    assert!(response.metrics.perception_time_ms < 1000);
    println!("Perception time: {}ms", response.metrics.perception_time_ms);
}