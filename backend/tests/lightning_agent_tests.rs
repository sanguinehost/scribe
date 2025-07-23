use scribe_backend::services::agentic::lightning_agent::{
    LightningAgent, CacheLayer
};
use scribe_backend::services::progressive_cache::{
    ProgressiveCacheService, Context, ImmediateContext, EnhancedContext, FullContext,
    MessageSummary, EntitySummary, Location, RelationshipSummary, NarrativeThread,
    SalienceScore, Memory, NarrativeState
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
use chrono::Utc;

/// Helper to create test Lightning Agent
async fn create_test_lightning_agent(app: &TestApp) -> LightningAgent {
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    LightningAgent::new(
        cache_service,
        app.app_state.redis_client.clone(),
        app.app_state.pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    )
}

/// Helper to create test immediate context
fn create_test_immediate_context(session_id: Uuid, user_id: Uuid) -> ImmediateContext {
    ImmediateContext {
        user_id,
        session_id,
        current_location: Uuid::new_v4(),
        current_location_name: "The Cantina".to_string(),
        active_character: Some(Uuid::new_v4()),
        active_character_name: Some("Bartender Bob".to_string()),
        recent_messages: vec![
            MessageSummary {
                role: "user".to_string(),
                summary: "Where am I?".to_string(),
                timestamp: Utc::now(),
            },
            MessageSummary {
                role: "assistant".to_string(),
                summary: "You are in the cantina.".to_string(),
                timestamp: Utc::now(),
            },
        ],
    }
}

/// Helper to create test enhanced context
fn create_test_enhanced_context(immediate: ImmediateContext) -> EnhancedContext {
    EnhancedContext {
        immediate,
        visible_entities: vec![
            EntitySummary {
                entity_id: Uuid::new_v4(),
                name: "Borga".to_string(),
                description: "A gruff alien merchant".to_string(),
                entity_type: "character".to_string(),
            },
        ],
        location_details: Location {
            location_id: Uuid::new_v4(),
            name: "Mos Eisley Cantina".to_string(),
            description: "A wretched hive of scum and villainy".to_string(),
            scale: "building".to_string(),
        },
        character_relationships: vec![
            RelationshipSummary {
                target_id: Uuid::new_v4(),
                target_name: "Borga".to_string(),
                relationship_type: "acquaintance".to_string(),
                strength: 0.3,
            },
        ],
        active_narrative_threads: vec![
            NarrativeThread {
                thread_id: Uuid::new_v4(),
                description: "Finding the stolen datapad".to_string(),
                priority: 0.8,
            },
        ],
    }
}

/// Helper to create test full context
fn create_test_full_context(enhanced: EnhancedContext) -> FullContext {
    let mut salience_scores = HashMap::new();
    salience_scores.insert(
        Uuid::new_v4(),
        SalienceScore {
            entity_id: Uuid::new_v4(),
            score: 0.9,
            reason: "Main quest NPC".to_string(),
        },
    );
    
    FullContext {
        enhanced,
        entity_salience_scores: salience_scores,
        memory_associations: vec![
            Memory {
                memory_id: Uuid::new_v4(),
                memory_type: "quest".to_string(),
                content: "Borga mentioned seeing suspicious activity near the docks".to_string(),
                relevance: 0.8,
            },
        ],
        complete_entity_details: vec![],
        narrative_state: NarrativeState {
            current_phase: "investigation".to_string(),
            active_goals: vec!["Find the datapad".to_string()],
            tension_level: 0.6,
        },
    }
}

#[tokio::test]
async fn test_lightning_agent_creation() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    // Agent should be created successfully
    let _ = agent; // Just ensure it compiles and creates
}

#[tokio::test]
async fn test_retrieve_minimal_context() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // With no cache, should return minimal context
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    assert!(matches!(context.context, Context::Minimal));
    assert_eq!(context.cache_layer, CacheLayer::Minimal);
    assert!(context.quality_score < 0.2);
    assert!(context.retrieval_time_ms < 500); // Should be fast
}

#[tokio::test]
async fn test_retrieve_immediate_context() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate immediate context
    let immediate = create_test_immediate_context(session_id, user_id);
    cache_service.set_immediate_context(session_id, immediate.clone()).await.unwrap();
    
    // Retrieve should return immediate context
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    assert!(matches!(context.context, Context::Immediate(_)));
    assert_eq!(context.cache_layer, CacheLayer::Immediate);
    assert!(context.quality_score > 0.3 && context.quality_score < 0.5);
    assert!(context.retrieval_time_ms < 100); // Should be very fast
}

#[tokio::test]
async fn test_retrieve_enhanced_context() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate enhanced context
    let immediate = create_test_immediate_context(session_id, user_id);
    let enhanced = create_test_enhanced_context(immediate);
    cache_service.set_enhanced_context(session_id, enhanced.clone()).await.unwrap();
    
    // Retrieve should return enhanced context
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    assert!(matches!(context.context, Context::Enhanced(_)));
    assert_eq!(context.cache_layer, CacheLayer::Enhanced);
    assert!(context.quality_score > 0.6 && context.quality_score < 0.8);
    assert!(context.retrieval_time_ms < 200); // Should be fast
}

#[tokio::test]
async fn test_retrieve_full_context() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate full context
    let immediate = create_test_immediate_context(session_id, user_id);
    let enhanced = create_test_enhanced_context(immediate);
    let full = create_test_full_context(enhanced);
    cache_service.set_full_context(session_id, full.clone()).await.unwrap();
    
    // Retrieve should return full context
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    assert!(matches!(context.context, Context::Full(_)));
    assert_eq!(context.cache_layer, CacheLayer::Full);
    assert_eq!(context.quality_score, 1.0);
    assert!(context.retrieval_time_ms < 300); // Should still be fast
}

#[tokio::test]
async fn test_progressive_fallback() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate only immediate and enhanced (no full)
    let immediate = create_test_immediate_context(session_id, user_id);
    let enhanced = create_test_enhanced_context(immediate);
    cache_service.set_enhanced_context(session_id, enhanced.clone()).await.unwrap();
    
    // Should fall back to enhanced
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    assert!(matches!(context.context, Context::Enhanced(_)));
    assert_eq!(context.cache_layer, CacheLayer::Enhanced);
}

#[tokio::test]
async fn test_retrieval_timeout_handling() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Even with potential network issues, should return minimal within timeout
    let start = std::time::Instant::now();
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await;
    let elapsed = start.elapsed();
    
    assert!(result.is_ok());
    assert!(elapsed.as_millis() < 600); // Should timeout at 500ms + overhead
}

#[tokio::test]
async fn test_prompt_building_minimal() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    
    let prompt = agent.build_minimal_prompt(session_id, user_id);
    
    assert!(prompt.contains("Continue the conversation"));
    assert!(prompt.contains(&session_id.to_string()));
    assert!(prompt.contains(&user_id.to_string()));
}

#[tokio::test]
async fn test_prompt_building_immediate() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let immediate = create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4());
    let prompt = agent.build_immediate_prompt(&immediate);
    
    assert!(prompt.contains("Current location"));
    assert!(prompt.contains("Active character"));
    assert!(prompt.contains("Recent conversation"));
    assert!(prompt.contains("Where am I?"));
    assert!(prompt.contains("You are in the cantina"));
}

#[tokio::test]
async fn test_prompt_building_enhanced() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let immediate = create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4());
    let enhanced = create_test_enhanced_context(immediate);
    let prompt = agent.build_enhanced_prompt(&enhanced);
    
    assert!(prompt.contains("Location details"));
    assert!(prompt.contains("Mos Eisley Cantina"));
    assert!(prompt.contains("Visible entities"));
    assert!(prompt.contains("Borga"));
    assert!(prompt.contains("Relationships"));
    assert!(prompt.contains("Active narrative threads"));
}

#[tokio::test]
async fn test_prompt_building_full() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let immediate = create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4());
    let enhanced = create_test_enhanced_context(immediate);
    let full = create_test_full_context(enhanced);
    let prompt = agent.build_rich_prompt(&full);
    
    assert!(prompt.contains("Important entities (by salience)"));
    assert!(prompt.contains("Relevant memories"));
    assert!(prompt.contains("suspicious activity near the docks"));
    assert!(prompt.contains("Narrative state"));
    assert!(prompt.contains("investigation"));
}

#[tokio::test]
async fn test_context_to_prompt_conversion() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    // Test all context types
    let contexts = vec![
        Context::Minimal,
        Context::Immediate(create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4())),
        Context::Enhanced(create_test_enhanced_context(
            create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4())
        )),
        Context::Full(create_test_full_context(
            create_test_enhanced_context(
                create_test_immediate_context(Uuid::new_v4(), Uuid::new_v4())
            )
        )),
    ];
    
    for context in contexts {
        let prompt = agent.context_to_prompt(&context);
        assert!(!prompt.is_empty());
    }
}

#[tokio::test]
async fn test_cache_health_check() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let result = agent.check_cache_health().await;
    
    assert!(result.is_ok());
    let health = result.unwrap();
    
    assert!(health.redis_healthy);
    assert!(health.cache_service_healthy);
    assert!(health.response_time_ms < 100); // Should be fast
}

#[tokio::test]
async fn test_cache_warming() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let location_id = Some(Uuid::new_v4());
    let character_id = Some(Uuid::new_v4());
    
    // Warm the cache
    let result = agent.warm_cache_for_session(
        session_id,
        user_id,
        location_id,
        character_id,
    ).await;
    
    assert!(result.is_ok());
    
    // Verify cache was warmed
    let cached = cache_service.get_immediate_context(session_id).await.unwrap();
    assert!(cached.is_some());
    
    let immediate = cached.unwrap();
    assert_eq!(immediate.user_id, user_id);
    assert_eq!(immediate.session_id, session_id);
    assert_eq!(immediate.current_location, location_id.unwrap());
    assert_eq!(immediate.active_character, character_id);
}

#[tokio::test]
async fn test_performance_metrics() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Run multiple retrievals to test performance
    let mut total_time = 0u64;
    let iterations = 10;
    
    for _ in 0..iterations {
        let result = agent.retrieve_progressive_context(
            session_id,
            user_id,
            &session_dek,
        ).await.unwrap();
        
        total_time += result.retrieval_time_ms;
    }
    
    let avg_time = total_time / iterations as u64;
    assert!(avg_time < 100); // Average should be well under 100ms
}

#[tokio::test]
async fn test_cache_invalidation_handling() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate cache
    let immediate = create_test_immediate_context(session_id, user_id);
    cache_service.set_immediate_context(session_id, immediate).await.unwrap();
    
    // Invalidate cache
    cache_service.invalidate_session_cache(session_id).await.unwrap();
    
    // Should return minimal context after invalidation
    let result = agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result.context, Context::Minimal));
    assert_eq!(result.cache_layer, CacheLayer::Minimal);
}

#[tokio::test]
async fn test_concurrent_retrievals() {
    let app = spawn_app(false, false, false).await;
    let agent = Arc::new(create_test_lightning_agent(&app).await);
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mut handles = vec![];
    
    // Spawn multiple concurrent retrievals
    for i in 0..5 {
        let agent_clone = agent.clone();
        let dek_clone = session_dek.clone();
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        
        let handle = tokio::spawn(async move {
            agent_clone.retrieve_progressive_context(
                session_id,
                user_id,
                &dek_clone,
            ).await
        });
        
        handles.push(handle);
    }
    
    // All should complete successfully
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    for result in results {
        assert!(result.is_ok());
        let retrieval_result = result.unwrap();
        assert!(retrieval_result.is_ok());
        let context = retrieval_result.unwrap();
        assert!(context.retrieval_time_ms < 500);
    }
}