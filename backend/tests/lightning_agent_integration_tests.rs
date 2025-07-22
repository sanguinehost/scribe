use scribe_backend::services::agentic::lightning_agent::{LightningAgent, CacheLayer};
use scribe_backend::services::progressive_cache::{
    ProgressiveCacheService, Context, ImmediateContext, EnhancedContext, FullContext,
    EntitySummary, Location, FullContextUpdate, SalienceScore, 
    Memory, NarrativeState
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::models::characters::CharacterMetadata;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
use genai::chat::{ChatMessage as GenAiChatMessage, MessageContent, ChatRole};

/// Test Lightning Agent integration with progressive cache population
#[tokio::test]
async fn test_lightning_agent_progressive_enrichment() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // First retrieval - should be minimal
    let result1 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result1.context, Context::Minimal));
    assert_eq!(result1.cache_layer, CacheLayer::Minimal);
    assert!(result1.quality_score < 0.2);
    
    // Simulate perception agent populating enhanced context
    let entities = vec![
        EntitySummary {
            entity_id: Uuid::new_v4(),
            name: "Sol".to_string(),
            description: "A bounty hunter".to_string(),
            entity_type: "character".to_string(),
        },
    ];
    
    let location = Location {
        location_id: Uuid::new_v4(),
        name: "Cantina".to_string(),
        description: "A busy spaceport bar".to_string(),
        scale: "building".to_string(),
    };
    
    cache_service.update_enhanced_context(session_id, entities, location).await.unwrap();
    
    // Second retrieval - should get enhanced context
    let result2 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result2.context, Context::Enhanced(_)));
    assert_eq!(result2.cache_layer, CacheLayer::Enhanced);
    assert!(result2.quality_score > 0.6);
    
    // Simulate background agents completing full analysis
    let mut salience_scores = HashMap::new();
    salience_scores.insert(
        Uuid::new_v4(),
        SalienceScore {
            entity_id: Uuid::new_v4(),
            score: 0.9,
            reason: "Primary character".to_string(),
        },
    );
    
    let update = FullContextUpdate {
        salience_scores,
        memory_associations: vec![
            Memory {
                memory_id: Uuid::new_v4(),
                memory_type: "recent_event".to_string(),
                content: "Sol entered the cantina looking for information".to_string(),
                relevance: 0.8,
            },
        ],
        narrative_state: NarrativeState {
            current_phase: "investigation".to_string(),
            active_goals: vec!["Find information about the target".to_string()],
            tension_level: 0.4,
        },
    };
    
    cache_service.update_full_context(session_id, update).await.unwrap();
    
    // Third retrieval - should get full context
    let result3 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result3.context, Context::Full(_)));
    assert_eq!(result3.cache_layer, CacheLayer::Full);
    assert_eq!(result3.quality_score, 1.0);
}

/// Test Lightning Agent with chat service prompt building
#[tokio::test]
async fn test_lightning_agent_prompt_generation() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let session_dek_arc = Arc::new(SessionDek::new(vec![0u8; 32]).0);
    
    // Warm cache with immediate context
    lightning_agent.warm_cache_for_session(
        session_id,
        user_id,
        Some(Uuid::new_v4()),
        Some(Uuid::new_v4()),
    ).await.unwrap();
    
    // Retrieve context
    let result = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result.context, Context::Immediate(_)));
    
    // Generate prompt from context
    let prompt = lightning_agent.context_to_prompt(&result.context);
    assert!(prompt.contains("Current location"));
    assert!(prompt.contains("Active character"));
    
    // Test integration with prompt builder (would require actual prompt builder integration)
    let character_metadata = CharacterMetadata {
        id: Uuid::new_v4(),
        user_id,
        name: "Test Character".to_string(),
        description: Some("A test character".as_bytes().to_vec()),
        description_nonce: None,
        personality: None,
        personality_nonce: None,
        scenario: None,
        scenario_nonce: None,
        mes_example: None,
        mes_example_nonce: None,
        creator_comment: None,
        creator_comment_nonce: None,
        first_mes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    
    let current_user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::from_text("What do you see around you?"),
        options: None,
    };
    
    // Build enriched prompt with lightning context
    let prompt_result = scribe_backend::prompt_builder::build_enriched_context_prompt(
        scribe_backend::prompt_builder::EnrichedPromptBuildParams {
            config: app.app_state.config.clone(),
            token_counter: app.app_state.token_counter.clone(),
            model_name: "gemini-2.5-flash-lite-preview-06-17".to_string(),
            user_id,
            user_dek: Some(&*session_dek_arc),
            enriched_context: None, // Would use lightning context in real integration
            current_user_message: current_user_message.clone(),
            user_persona_name: None,
            legacy_params: Some(scribe_backend::prompt_builder::PromptBuildParams {
                config: app.app_state.config.clone(),
                token_counter: app.app_state.token_counter.clone(),
                recent_history: vec![],
                rag_items: vec![],
                system_prompt_base: Some("You are a helpful AI assistant.".to_string()),
                raw_character_system_prompt: None,
                character_metadata: Some(&character_metadata),
                current_user_message,
                model_name: "gemini-2.5-flash-lite-preview-06-17".to_string(),
                user_dek: Some(&*session_dek_arc),
                user_persona_name: None,
                world_state_context: Some(prompt), // Use lightning context as world state
                user_id: Some(user_id),
                chronicle_id: None,
                agentic_context: None,
            }),
        }
    ).await;
    
    assert!(prompt_result.is_ok());
}

/// Test cache invalidation and refresh cycle
#[tokio::test]
async fn test_cache_invalidation_and_refresh() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Populate all cache layers
    let immediate = ImmediateContext {
        user_id,
        session_id,
        current_location: Uuid::new_v4(),
        current_location_name: "Test Location".to_string(),
        active_character: Some(Uuid::new_v4()),
        active_character_name: Some("Test Character".to_string()),
        recent_messages: vec![],
    };
    cache_service.set_immediate_context(session_id, immediate.clone()).await.unwrap();
    
    // Verify cache is populated
    let result1 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result1.context, Context::Immediate(_)));
    
    // Invalidate cache (simulating location change or significant event)
    cache_service.invalidate_session_cache(session_id).await.unwrap();
    
    // Next retrieval should be minimal
    let result2 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result2.context, Context::Minimal));
    assert_eq!(result2.cache_layer, CacheLayer::Minimal);
}

/// Test performance under concurrent load
#[tokio::test]
async fn test_concurrent_lightning_retrievals() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = Arc::new(LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    ));
    
    // Pre-populate cache for some sessions
    let mut session_ids = vec![];
    for i in 0..10 {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        session_ids.push((session_id, user_id));
        
        if i % 3 == 0 {
            // Populate with full context
            let immediate = ImmediateContext {
                user_id,
                session_id,
                current_location: Uuid::new_v4(),
                current_location_name: "Test Location".to_string(),
                active_character: Some(Uuid::new_v4()),
                active_character_name: Some("Test Character".to_string()),
                recent_messages: vec![],
            };
            
            let enhanced = EnhancedContext {
                immediate,
                visible_entities: vec![],
                location_details: Location {
                    location_id: Uuid::new_v4(),
                    name: format!("Location {}", i),
                    description: "Test location".to_string(),
                    scale: "room".to_string(),
                },
                character_relationships: vec![],
                active_narrative_threads: vec![],
            };
            
            let full = FullContext {
                enhanced,
                entity_salience_scores: HashMap::new(),
                memory_associations: vec![],
                complete_entity_details: vec![],
                narrative_state: NarrativeState {
                    current_phase: "test".to_string(),
                    active_goals: vec![],
                    tension_level: 0.5,
                },
            };
            
            cache_service.set_full_context(session_id, full).await.unwrap();
        }
    }
    
    // Spawn concurrent retrievals
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mut handles = vec![];
    
    for i in 0..50 {
        let agent_clone = lightning_agent.clone();
        let dek_clone = session_dek.clone();
        let idx = i % session_ids.len();
        let (session_id, user_id) = session_ids[idx];
        
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let result = agent_clone.retrieve_progressive_context(
                session_id,
                user_id,
                &dek_clone,
            ).await;
            let elapsed = start.elapsed();
            (result, elapsed)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // Verify all completed successfully and quickly
    let mut total_time = 0u128;
    let mut cache_hits = 0;
    
    for result in results {
        assert!(result.is_ok());
        let (retrieval_result, elapsed) = result.unwrap();
        assert!(retrieval_result.is_ok());
        
        let context = retrieval_result.unwrap();
        total_time += elapsed.as_millis();
        
        if context.cache_layer != CacheLayer::None {
            cache_hits += 1;
        }
        
        // Each retrieval should be fast
        assert!(elapsed.as_millis() < 100);
    }
    
    let avg_time = total_time / 50;
    assert!(avg_time < 50); // Average should be very fast
    assert!(cache_hits > 10); // Should have some cache hits
}

/// Test session warming for new conversations
#[tokio::test]
async fn test_session_warming_integration() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let location_id = Uuid::new_v4();
    let character_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Warm cache for new session
    lightning_agent.warm_cache_for_session(
        session_id,
        user_id,
        Some(location_id),
        Some(character_id),
    ).await.unwrap();
    
    // First retrieval should have immediate context available
    let result = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    assert!(matches!(result.context, Context::Immediate(_)));
    assert_eq!(result.cache_layer, CacheLayer::Immediate);
    assert!(result.retrieval_time_ms < 50); // Should be very fast
    
    if let Context::Immediate(ctx) = result.context {
        assert_eq!(ctx.current_location, location_id);
        assert_eq!(ctx.active_character, Some(character_id));
    }
}

/// Test health monitoring integration
#[tokio::test]
async fn test_health_monitoring_integration() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = LightningAgent::new(
        cache_service,
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    );
    
    // Check health multiple times
    for _ in 0..5 {
        let health = lightning_agent.check_cache_health().await.unwrap();
        
        assert!(health.redis_healthy);
        assert!(health.cache_service_healthy);
        assert!(health.response_time_ms < 50);
        
        // Small delay between checks
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// Test integration with background pipeline simulation
#[tokio::test]
async fn test_background_pipeline_integration() {
    let app = spawn_app(false, false, false).await;
    
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    let lightning_agent = Arc::new(LightningAgent::new(
        cache_service.clone(),
        app.app_state.redis_client.clone(),
        app.db_pool.clone(),
        app.app_state.ecs_entity_manager.clone(),
    ));
    
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Simulate chat flow with progressive enrichment
    
    // Message 1: Cold start
    let result1 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    assert!(matches!(result1.context, Context::Minimal));
    
    // Simulate background processing after first message
    tokio::spawn({
        let cache_service = cache_service.clone();
        let session_id = session_id.clone();
        
        async move {
            // Simulate perception agent work
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            
            let entities = vec![
                EntitySummary {
                    entity_id: Uuid::new_v4(),
                    name: "Background NPC".to_string(),
                    description: "Added by background processing".to_string(),
                    entity_type: "character".to_string(),
                },
            ];
            
            let location = Location {
                location_id: Uuid::new_v4(),
                name: "Discovered Location".to_string(),
                description: "Found during analysis".to_string(),
                scale: "room".to_string(),
            };
            
            let _ = cache_service.update_enhanced_context(session_id, entities, location).await;
            
            // Simulate strategic/tactical agent work
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            
            let update = FullContextUpdate {
                salience_scores: HashMap::new(),
                memory_associations: vec![],
                narrative_state: NarrativeState {
                    current_phase: "background_complete".to_string(),
                    active_goals: vec![],
                    tension_level: 0.3,
                },
            };
            
            let _ = cache_service.update_full_context(session_id, update).await;
        }
    });
    
    // Message 2: After some background processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let result2 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    // Should have enhanced context by now
    assert!(matches!(result2.context, Context::Enhanced(_)));
    
    // Message 3: After full background processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let result3 = lightning_agent.retrieve_progressive_context(
        session_id,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    // Should have full context
    assert!(matches!(result3.context, Context::Full(_)));
    assert_eq!(result3.quality_score, 1.0);
}