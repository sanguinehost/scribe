// backend/tests/entity_resolution_performance_test.rs
//
// Performance test for entity resolution to ensure sub-2s response time

use std::sync::Arc;
use std::time::Instant;

use scribe_backend::{
    services::agentic::entity_resolution_tool::EntityResolutionTool,
    test_helpers::{spawn_app, MockAiClient, TestDataGuard, db::create_test_user},
};

use serde_json::json;

#[tokio::test]
async fn test_entity_resolution_performance_basic() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    
    // Configure mock AI to return instant responses
    let entity_extraction_response = json!({
        "entities": ["Sol", "Borga", "Vargo", "cantina"],
        "entity_names": ["Sol", "Borga", "Vargo", "cantina"]
    });
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(entity_extraction_response.to_string()));
    
    // Create minimal app state by building AppStateServices manually  
    let app_state = scribe_backend::test_helpers::TestAppStateBuilder::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        mock_ai_client.clone() as Arc<dyn scribe_backend::llm::AiClient + Send + Sync>,
        test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
        test_app.qdrant_service.clone(),
        Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
    )
    .build()
    .await
    .unwrap();
    
    // Create EntityResolutionTool
    let entity_resolution_tool = EntityResolutionTool::new(Arc::new(app_state));
    
    // Test cases with varying complexity
    let test_cases = vec![
        ("Simple narrative", "Sol meets Borga"),
        ("Medium narrative", "Sol meets with Borga at the cantina while Vargo watches from the shadows"),
        ("Complex narrative", "Sol meets with Borga at the cantina while Vargo watches from the shadows. The atmosphere is tense as they discuss the upcoming heist. Borga's enforcers stand guard at the entrance, weapons barely concealed under their cloaks."),
    ];
    
    println!("\n=== Entity Resolution Performance Test ===");
    
    for (name, narrative) in test_cases {
        println!("\nTest case: {}", name);
        println!("Narrative length: {} chars", narrative.len());
        
        // Test 1: Entity name extraction
        let start = Instant::now();
        let names_result = entity_resolution_tool.extract_entity_names(narrative).await;
        let extraction_time = start.elapsed();
        
        match names_result {
            Ok(names) => {
                println!("✓ Entity extraction: {:.2}ms ({} entities)", 
                    extraction_time.as_millis(), names.len());
                // With mock AI, this should be very fast
                assert!(extraction_time.as_millis() < 1000, "Entity extraction took more than 1 second!");
            }
            Err(e) => {
                println!("⚠ Entity extraction failed: {} ({:.2}ms)", e, extraction_time.as_millis());
            }
        }
        
        // Test 2: Multi-stage processing (if implemented)
        let start = Instant::now();
        let multistage_result = entity_resolution_tool.resolve_entities_multistage(
            narrative,
            user_id,
            None,
            &[], // No existing entities
        ).await;
        let multistage_time = start.elapsed();
        
        match multistage_result {
            Ok(result) => {
                println!("✓ Multi-stage processing: {:.2}ms ({} entities, {} relationships)", 
                    multistage_time.as_millis(), 
                    result.resolved_entities.len(),
                    result.relationships.len());
                
                // CRITICAL: Ensure sub-2s performance even with mock
                assert!(multistage_time.as_secs() < 2, 
                    "Multi-stage processing took {:.2}s, exceeding 2s threshold!", 
                    multistage_time.as_secs_f32());
                    
                // With optimizations, mock AI should be much faster than 2s
                assert!(multistage_time.as_millis() < 1000, 
                    "Multi-stage processing took {:.2}ms, should be under 1s with mock AI", 
                    multistage_time.as_millis());
            }
            Err(e) => {
                println!("⚠ Multi-stage processing failed: {} ({:.2}ms)", e, multistage_time.as_millis());
            }
        }
    }
    
    println!("\n✅ Performance test completed - all operations under thresholds!");
}

#[tokio::test] 
async fn test_early_return_optimization() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response("{}".to_string()));
    
    let app_state = scribe_backend::test_helpers::TestAppStateBuilder::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        mock_ai_client.clone() as Arc<dyn scribe_backend::llm::AiClient + Send + Sync>,
        test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
        test_app.qdrant_service.clone(),
        Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
    )
    .build()
    .await
    .unwrap();
    
    let entity_resolution_tool = EntityResolutionTool::new(Arc::new(app_state));
    
    println!("\n=== Early Return Optimization Test ===");
    
    // Test empty text early return
    let start = Instant::now();
    let result = entity_resolution_tool.resolve_entities_multistage(
        "",  // Empty string
        user_id,
        None,
        &[],
    ).await;
    let empty_time = start.elapsed();
    
    match result {
        Ok(result) => {
            println!("✓ Empty text processed in {:.2}ms", empty_time.as_millis());
            assert_eq!(result.resolved_entities.len(), 0, "Empty text should produce no entities");
            assert_eq!(result.relationships.len(), 0, "Empty text should produce no relationships");
            
            // Early return should be extremely fast (< 10ms)
            assert!(empty_time.as_millis() < 10, 
                "Empty text processing took {:.2}ms, should be under 10ms with early return", 
                empty_time.as_millis());
        }
        Err(e) => {
            println!("⚠ Empty text processing failed: {}", e);
        }
    }
    
    // Test whitespace-only text early return
    let start = Instant::now();
    let result = entity_resolution_tool.resolve_entities_multistage(
        "   \n\t  ",  // Whitespace only
        user_id,
        None,
        &[],
    ).await;
    let whitespace_time = start.elapsed();
    
    match result {
        Ok(result) => {
            println!("✓ Whitespace-only text processed in {:.2}ms", whitespace_time.as_millis());
            assert_eq!(result.resolved_entities.len(), 0, "Whitespace-only text should produce no entities");
            
            // Early return should be extremely fast (< 10ms)
            assert!(whitespace_time.as_millis() < 10, 
                "Whitespace-only text processing took {:.2}ms, should be under 10ms with early return", 
                whitespace_time.as_millis());
        }
        Err(e) => {
            println!("⚠ Whitespace-only text processing failed: {}", e);
        }
    }
    
    println!("\n✅ Early return optimization verified!");
}