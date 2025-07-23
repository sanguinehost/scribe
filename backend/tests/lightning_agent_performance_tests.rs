use scribe_backend::services::agentic::lightning_agent::{LightningAgent, CacheLayer};
use scribe_backend::services::progressive_cache::{
    ProgressiveCacheService, Context, ImmediateContext, EnhancedContext, FullContext,
    MessageSummary, EntitySummary, Location, RelationshipSummary, NarrativeThread,
    SalienceScore, Memory, NarrativeState, FullContextUpdate
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
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

/// Helper to populate full context for testing
async fn populate_full_context(
    cache_service: &ProgressiveCacheService,
    session_id: Uuid,
    user_id: Uuid,
) {
    // Create immediate context
    let immediate = ImmediateContext {
        user_id,
        session_id,
        current_location: Uuid::new_v4(),
        current_location_name: "Test Location".to_string(),
        active_character: Some(Uuid::new_v4()),
        active_character_name: Some("Test Character".to_string()),
        recent_messages: (0..5).map(|i| MessageSummary {
            role: if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
            summary: format!("Message {}", i),
            timestamp: Utc::now(),
        }).collect(),
    };
    
    // Create enhanced context
    let enhanced = EnhancedContext {
        immediate,
        visible_entities: (0..10).map(|i| EntitySummary {
            entity_id: Uuid::new_v4(),
            name: format!("Entity {}", i),
            description: format!("Description for entity {}", i),
            entity_type: "character".to_string(),
        }).collect(),
        location_details: Location {
            location_id: Uuid::new_v4(),
            name: "Test Location".to_string(),
            description: "A detailed test location with many features".to_string(),
            scale: "building".to_string(),
        },
        character_relationships: (0..5).map(|i| RelationshipSummary {
            target_id: Uuid::new_v4(),
            target_name: format!("Character {}", i),
            relationship_type: "acquaintance".to_string(),
            strength: 0.5 + (i as f32 * 0.1),
        }).collect(),
        active_narrative_threads: (0..3).map(|i| NarrativeThread {
            thread_id: Uuid::new_v4(),
            description: format!("Thread {}", i),
            priority: 0.5 + (i as f32 * 0.2),
        }).collect(),
    };
    
    // Create full context
    let mut salience_scores = HashMap::new();
    for i in 0..20 {
        let entity_id = Uuid::new_v4();
        salience_scores.insert(
            entity_id,
            SalienceScore {
                entity_id,
                score: 0.1 + (i as f32 * 0.04),
                reason: format!("Reason {}", i),
            },
        );
    }
    
    let full = FullContext {
        enhanced,
        entity_salience_scores: salience_scores,
        memory_associations: (0..10).map(|i| Memory {
            memory_id: Uuid::new_v4(),
            memory_type: "event".to_string(),
            content: format!("Memory content {}", i),
            relevance: 0.5 + (i as f32 * 0.05),
        }).collect(),
        complete_entity_details: vec![],
        narrative_state: NarrativeState {
            current_phase: "active".to_string(),
            active_goals: vec!["Goal 1".to_string(), "Goal 2".to_string()],
            tension_level: 0.7,
        },
    };
    
    cache_service.set_full_context(session_id, full).await.unwrap();
}

/// Test minimal context retrieval performance
#[tokio::test]
async fn test_minimal_context_retrieval_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mut total_time = Duration::ZERO;
    let iterations = 100;
    
    for _ in 0..iterations {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        
        let start = Instant::now();
        let result = agent.retrieve_progressive_context(
            session_id,
            user_id,
            &session_dek,
        ).await.unwrap();
        let elapsed = start.elapsed();
        
        total_time += elapsed;
        
        assert!(matches!(result.context, Context::Minimal));
        assert!(elapsed < Duration::from_millis(10)); // Should be very fast
    }
    
    let avg_time = total_time / iterations;
    println!("Average minimal context retrieval time: {:?}", avg_time);
    assert!(avg_time < Duration::from_millis(5));
}

/// Test immediate context retrieval performance
#[tokio::test]
async fn test_immediate_context_retrieval_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    );
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mut total_time = Duration::ZERO;
    let iterations = 100;
    
    // Pre-populate cache
    for _ in 0..iterations {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        
        let immediate = ImmediateContext {
            user_id,
            session_id,
            current_location: Uuid::new_v4(),
            current_location_name: "Test Location".to_string(),
            active_character: Some(Uuid::new_v4()),
            active_character_name: Some("Test Character".to_string()),
            recent_messages: vec![],
        };
        
        cache_service.set_immediate_context(session_id, immediate).await.unwrap();
        
        // Test retrieval
        let start = Instant::now();
        let result = agent.retrieve_progressive_context(
            session_id,
            user_id,
            &session_dek,
        ).await.unwrap();
        let elapsed = start.elapsed();
        
        total_time += elapsed;
        
        assert!(matches!(result.context, Context::Immediate(_)));
        assert!(elapsed < Duration::from_millis(50));
    }
    
    let avg_time = total_time / iterations;
    println!("Average immediate context retrieval time: {:?}", avg_time);
    assert!(avg_time < Duration::from_millis(20));
}

/// Test full context retrieval performance
#[tokio::test]
async fn test_full_context_retrieval_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    );
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mut total_time = Duration::ZERO;
    let iterations = 50; // Fewer iterations due to more complex data
    
    // Pre-populate cache with full contexts
    let mut sessions = vec![];
    for _ in 0..iterations {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        sessions.push((session_id, user_id));
        
        populate_full_context(&cache_service, session_id, user_id).await;
    }
    
    // Test retrieval
    for (session_id, user_id) in sessions {
        let start = Instant::now();
        let result = agent.retrieve_progressive_context(
            session_id,
            user_id,
            &session_dek,
        ).await.unwrap();
        let elapsed = start.elapsed();
        
        total_time += elapsed;
        
        assert!(matches!(result.context, Context::Full(_)));
        assert!(elapsed < Duration::from_millis(100));
    }
    
    let avg_time = total_time / iterations;
    println!("Average full context retrieval time: {:?}", avg_time);
    assert!(avg_time < Duration::from_millis(50));
}

/// Test concurrent retrieval performance
#[tokio::test]
async fn test_concurrent_retrieval_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = Arc::new(create_test_lightning_agent(&app).await);
    let cache_service = Arc::new(ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    ));
    
    // Pre-populate various context levels
    let mut sessions = vec![];
    for i in 0..30 {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        sessions.push((session_id, user_id));
        
        match i % 3 {
            0 => {
                // Immediate context
                let immediate = ImmediateContext {
                    user_id,
                    session_id,
                    current_location: Uuid::new_v4(),
                    current_location_name: "Test Location".to_string(),
                    active_character: Some(Uuid::new_v4()),
                    active_character_name: Some("Test Character".to_string()),
                    recent_messages: vec![],
                };
                cache_service.set_immediate_context(session_id, immediate).await.unwrap();
            }
            1 => {
                // Enhanced context
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
                        name: "Test".to_string(),
                        description: "Test".to_string(),
                        scale: "room".to_string(),
                    },
                    character_relationships: vec![],
                    active_narrative_threads: vec![],
                };
                cache_service.set_enhanced_context(session_id, enhanced).await.unwrap();
            }
            _ => {
                // Full context
                populate_full_context(&cache_service, session_id, user_id).await;
            }
        }
    }
    
    // Test concurrent retrievals
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let concurrent_requests = 100;
    let start = Instant::now();
    
    let mut handles = vec![];
    for i in 0..concurrent_requests {
        let agent_clone = agent.clone();
        let dek_clone = session_dek.clone();
        let (session_id, user_id) = sessions[i % sessions.len()];
        
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let result = agent_clone.retrieve_progressive_context(
                session_id,
                user_id,
                &dek_clone,
            ).await;
            (result, start.elapsed())
        });
        
        handles.push(handle);
    }
    
    let results: Vec<_> = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();
    
    // Analyze results
    let mut individual_times = vec![];
    let mut cache_hits = HashMap::new();
    
    for result in results {
        assert!(result.is_ok());
        let (retrieval_result, elapsed) = result.unwrap();
        assert!(retrieval_result.is_ok());
        
        let context = retrieval_result.unwrap();
        individual_times.push(elapsed);
        
        let layer_name = format!("{:?}", context.cache_layer);
        *cache_hits.entry(layer_name).or_insert(0) += 1;
    }
    
    // Calculate statistics
    individual_times.sort();
    let median_time = individual_times[individual_times.len() / 2];
    let p95_time = individual_times[(individual_times.len() * 95) / 100];
    let p99_time = individual_times[(individual_times.len() * 99) / 100];
    
    println!("Concurrent retrieval statistics:");
    println!("  Total time for {} requests: {:?}", concurrent_requests, total_elapsed);
    println!("  Median time: {:?}", median_time);
    println!("  95th percentile: {:?}", p95_time);
    println!("  99th percentile: {:?}", p99_time);
    println!("  Cache hits: {:?}", cache_hits);
    
    // Performance assertions
    assert!(median_time < Duration::from_millis(50));
    assert!(p95_time < Duration::from_millis(100));
    assert!(p99_time < Duration::from_millis(200));
}

/// Test prompt building performance
#[tokio::test]
async fn test_prompt_building_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    );
    
    // Create contexts of different complexity
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    
    populate_full_context(&cache_service, session_id, user_id).await;
    let full_context = cache_service.get_full_context(session_id).await.unwrap().unwrap();
    
    // Test prompt building performance
    let iterations = 1000;
    
    // Minimal prompt
    let start = Instant::now();
    for _ in 0..iterations {
        let _prompt = agent.build_minimal_prompt(session_id, user_id);
    }
    let minimal_time = start.elapsed();
    
    // Immediate prompt
    let start = Instant::now();
    for _ in 0..iterations {
        let _prompt = agent.build_immediate_prompt(&full_context.enhanced.immediate);
    }
    let immediate_time = start.elapsed();
    
    // Enhanced prompt
    let start = Instant::now();
    for _ in 0..iterations {
        let _prompt = agent.build_enhanced_prompt(&full_context.enhanced);
    }
    let enhanced_time = start.elapsed();
    
    // Full prompt
    let start = Instant::now();
    for _ in 0..iterations {
        let _prompt = agent.build_rich_prompt(&full_context);
    }
    let full_time = start.elapsed();
    
    println!("Prompt building performance ({} iterations):", iterations);
    println!("  Minimal: {:?} (avg: {:?})", minimal_time, minimal_time / iterations);
    println!("  Immediate: {:?} (avg: {:?})", immediate_time, immediate_time / iterations);
    println!("  Enhanced: {:?} (avg: {:?})", enhanced_time, enhanced_time / iterations);
    println!("  Full: {:?} (avg: {:?})", full_time, full_time / iterations);
    
    // Even full prompt building should be very fast
    assert!(full_time / iterations < Duration::from_micros(500));
}

/// Test cache warming performance
#[tokio::test]
async fn test_cache_warming_performance() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    
    let mut total_time = Duration::ZERO;
    let iterations = 100;
    
    for _ in 0..iterations {
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let location_id = Some(Uuid::new_v4());
        let character_id = Some(Uuid::new_v4());
        
        let start = Instant::now();
        agent.warm_cache_for_session(
            session_id,
            user_id,
            location_id,
            character_id,
        ).await.unwrap();
        let elapsed = start.elapsed();
        
        total_time += elapsed;
        assert!(elapsed < Duration::from_millis(50));
    }
    
    let avg_time = total_time / iterations;
    println!("Average cache warming time: {:?}", avg_time);
    assert!(avg_time < Duration::from_millis(20));
}

/// Test timeout enforcement under load
#[tokio::test]
async fn test_timeout_enforcement_under_load() {
    let app = spawn_app(false, false, false).await;
    let agent = Arc::new(create_test_lightning_agent(&app).await);
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let concurrent_requests = 200;
    
    let mut handles = vec![];
    for _ in 0..concurrent_requests {
        let agent_clone = agent.clone();
        let dek_clone = session_dek.clone();
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let _result = agent_clone.retrieve_progressive_context(
                session_id,
                user_id,
                &dek_clone,
            ).await;
            start.elapsed()
        });
        
        handles.push(handle);
    }
    
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // All requests should complete within timeout even under load
    for result in results {
        assert!(result.is_ok());
        let elapsed = result.unwrap();
        assert!(elapsed < Duration::from_millis(600)); // 500ms timeout + overhead
    }
}

/// Test cache hit ratio optimization
#[tokio::test]
async fn test_cache_hit_ratio_optimization() {
    let app = spawn_app(false, false, false).await;
    let agent = create_test_lightning_agent(&app).await;
    let cache_service = ProgressiveCacheService::new(
        app.app_state.redis_client.clone()
    );
    
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create a realistic session pattern
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    // Warm the cache
    agent.warm_cache_for_session(
        session_id,
        user_id,
        Some(Uuid::new_v4()),
        Some(Uuid::new_v4()),
    ).await.unwrap();
    
    // Simulate progressive enrichment
    let mut cache_layers = vec![];
    
    // Message 1: Immediate context
    let result1 = agent.retrieve_progressive_context(session_id, user_id, &session_dek).await.unwrap();
    cache_layers.push(result1.cache_layer);
    
    // Background enrichment to enhanced
    let entities = vec![EntitySummary {
        entity_id: Uuid::new_v4(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        entity_type: "character".to_string(),
    }];
    let location = Location {
        location_id: Uuid::new_v4(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        scale: "room".to_string(),
    };
    cache_service.update_enhanced_context(session_id, entities, location).await.unwrap();
    
    // Message 2: Enhanced context
    let result2 = agent.retrieve_progressive_context(session_id, user_id, &session_dek).await.unwrap();
    cache_layers.push(result2.cache_layer);
    
    // Background enrichment to full
    let update = FullContextUpdate {
        salience_scores: HashMap::new(),
        memory_associations: vec![],
        narrative_state: NarrativeState {
            current_phase: "active".to_string(),
            active_goals: vec![],
            tension_level: 0.5,
        },
    };
    cache_service.update_full_context(session_id, update).await.unwrap();
    
    // Messages 3-10: Should all hit full context
    for _ in 3..=10 {
        let result = agent.retrieve_progressive_context(session_id, user_id, &session_dek).await.unwrap();
        cache_layers.push(result.cache_layer);
    }
    
    // Analyze cache hit progression
    let full_hits = cache_layers.iter().filter(|l| matches!(l, CacheLayer::Full)).count();
    let enhanced_hits = cache_layers.iter().filter(|l| matches!(l, CacheLayer::Enhanced)).count();
    let immediate_hits = cache_layers.iter().filter(|l| matches!(l, CacheLayer::Immediate)).count();
    
    println!("Cache hit progression: {:?}", cache_layers);
    println!("Full hits: {}, Enhanced hits: {}, Immediate hits: {}", full_hits, enhanced_hits, immediate_hits);
    
    // Should show progressive improvement
    assert!(immediate_hits >= 1);
    assert!(enhanced_hits >= 1);
    assert!(full_hits >= 6); // Most should be full context
}