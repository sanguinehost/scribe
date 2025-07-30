use scribe_backend::test_helpers::*;
use scribe_backend::services::agentic::perception_agent::PerceptionAgent;
use scribe_backend::models::entities::SpatialScale;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::Arc;

#[tokio::test]
async fn test_batch_entity_creation() -> Result<(), AppError> {
    let test_app = spawn_app_permissive_rate_limiting().await;
    let guard = TestDataGuard::new(&test_app.pool).await;
    let session_dek = Arc::new([0u8; 32]);
    
    // Create test user and session
    let user_id = guard.user_id;
    let session_id = Uuid::new_v4();
    
    // Initialize perception agent
    let perception_agent = PerceptionAgent::new(
        test_app.app_state.ai_client.clone(),
        test_app.app_state.ai_client.clone(),
        test_app.app_state.ecs_manager.clone(),
        test_app.app_state.vector_db_service.clone(),
        test_app.app_state.chronicle_service.clone(),
        test_app.app_state.unified_tool_registry.clone(),
        test_app.app_state.planning_service.clone(),
        test_app.app_state.world_model_service.clone(),
    );
    
    // Create test entities
    let entities = vec![
        scribe_backend::services::agentic::perception_agent::EntityToResolve {
            name: "Test Entity 1".to_string(),
            entity_type: "location".to_string(),
            context: "A test location".to_string(),
            spatial_scale: Some(SpatialScale::District),
        },
        scribe_backend::services::agentic::perception_agent::EntityToResolve {
            name: "Test Entity 2".to_string(),
            entity_type: "character".to_string(),
            context: "A test character".to_string(),
            spatial_scale: None,
        },
        scribe_backend::services::agentic::perception_agent::EntityToResolve {
            name: "Test Entity 3".to_string(),
            entity_type: "item".to_string(),
            context: "A test item".to_string(),
            spatial_scale: None,
        },
    ];
    
    println!("Creating {} entities in batch...", entities.len());
    
    // Process entities with atomic coordination
    let result = perception_agent.process_entities_with_atomic_coordination(
        entities,
        user_id,
        session_id,
        &session_dek,
    ).await;
    
    match result {
        Ok(()) => {
            println!("✅ Batch entity creation succeeded!");
            
            // Verify entities were created
            let entity1 = test_app.app_state.ecs_manager.find_entity(
                "Test Entity 1",
                user_id,
                &session_dek,
            ).await?;
            assert!(entity1.is_some(), "Entity 1 should exist");
            
            let entity2 = test_app.app_state.ecs_manager.find_entity(
                "Test Entity 2",
                user_id,
                &session_dek,
            ).await?;
            assert!(entity2.is_some(), "Entity 2 should exist");
            
            let entity3 = test_app.app_state.ecs_manager.find_entity(
                "Test Entity 3",
                user_id,
                &session_dek,
            ).await?;
            assert!(entity3.is_some(), "Entity 3 should exist");
            
            println!("✅ All entities verified!");
        }
        Err(e) => {
            if e.to_string().contains("Rate Limit") {
                println!("⚠️ Test skipped due to API rate limiting: {}", e);
                // Don't fail the test due to rate limiting
                return Ok(());
            } else {
                panic!("❌ Batch entity creation failed: {}", e);
            }
        }
    }
    
    guard.cleanup().await;
    Ok(())
}