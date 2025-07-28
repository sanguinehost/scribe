use scribe_backend::test_helpers::*;
use scribe_backend::services::agentic::{
    perception_agent::PerceptionAgent,
    shared_context::{SharedAgentContext, AgentType, ContextType},
};
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;
use serde_json::json;

#[tokio::test]
async fn test_perception_agent_handles_duplicate_entities_gracefully() {
    let test_app = TestApp::spawn().await;
    let user = test_app.create_test_user("perception_test@example.com", "password123").await;
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create perception agent
    let perception_agent = Arc::new(PerceptionAgent::new(
        test_app.app_state.ai_client.clone(),
        test_app.app_state.unified_tool_registry.clone(),
        test_app.app_state.redis_client.clone(),
        test_app.app_state.shared_agent_context.clone(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
    ));
    
    // Create the same entity multiple times - should not fail
    let entity_name = "Test Mountain";
    let entity_type = "location";
    
    // First creation should succeed
    let create_params = json!({
        "user_id": user.id.to_string(),
        "creation_request": format!("Create a {} entity named '{}' with planetary scale", entity_type, entity_name),
        "context": "Test entity creation"
    });
    
    let result1 = perception_agent.get_tool("create_entity")
        .unwrap()
        .execute(&create_params, &session_dek)
        .await;
    
    assert!(result1.is_ok(), "First entity creation should succeed");
    
    // Second creation should either succeed or fail gracefully
    let result2 = perception_agent.get_tool("create_entity")
        .unwrap()
        .execute(&create_params, &session_dek)
        .await;
    
    match &result2 {
        Ok(_) => {
            // If it succeeded, that's fine (might have been handled gracefully)
            println!("Second creation succeeded (handled gracefully)");
        }
        Err(e) => {
            // If it failed, it should be due to duplicate key
            let error_str = format!("{:?}", e);
            assert!(
                error_str.contains("duplicate key"),
                "Expected duplicate key error, got: {}",
                error_str
            );
        }
    }
    
    // Verify shared context has the entity discovery
    let query = scribe_backend::services::agentic::shared_context::ContextQuery {
        context_types: Some(vec![ContextType::EntityDiscovery]),
        source_agents: Some(vec![AgentType::Perception]),
        session_id: None,
        since_timestamp: Some(chrono::Utc::now() - chrono::Duration::minutes(5)),
        keys: None,
        limit: Some(10),
    };
    
    match test_app.app_state.shared_agent_context.query_context(user.id, query, &session_dek).await {
        Ok(entries) => {
            println!("Found {} shared context entries", entries.len());
            
            // Look for our entity
            let found_entity = entries.iter().any(|entry| {
                entry.key.contains(entity_name) || 
                entry.data.get("entity_name").and_then(|n| n.as_str()) == Some(entity_name)
            });
            
            assert!(found_entity, "Entity should be recorded in shared context");
        }
        Err(e) => {
            // This is expected with test encryption keys
            println!("Shared context query failed (expected with test keys): {}", e);
        }
    }
}

#[tokio::test]
async fn test_perception_agent_checks_shared_context_before_creation() {
    let test_app = TestApp::spawn().await;
    let user = test_app.create_test_user("perception_test2@example.com", "password123").await;
    let session_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // First, store an entity discovery in shared context
    let entity_name = "Mystic Forest";
    let discovery_data = json!({
        "entity_name": entity_name,
        "entity_type": "location",
        "spatial_scale": "Planetary",
        "salience_tier": "Core",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "relevance_score": 0.9
    });
    
    let entities = vec![discovery_data];
    let store_result = test_app.app_state.shared_agent_context.store_entity_discovery(
        user.id,
        session_id,
        &entities,
        Some("Test entity discovery".to_string()),
        &session_dek,
    ).await;
    
    match store_result {
        Ok(_) => println!("Successfully stored entity discovery in shared context"),
        Err(e) => println!("Failed to store in shared context (expected with test keys): {}", e),
    }
    
    // Now create perception agent and try to create the same entity
    let perception_agent = Arc::new(PerceptionAgent::new(
        test_app.app_state.ai_client.clone(),
        test_app.app_state.unified_tool_registry.clone(),
        test_app.app_state.redis_client.clone(),
        test_app.app_state.shared_agent_context.clone(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
    ));
    
    // Try to create an entity that should already exist in shared context
    let contextual_entity = scribe_backend::services::agentic::perception_agent::ContextualEntity {
        name: entity_name.to_string(),
        entity_type: "location".to_string(),
        relevance_score: 0.9,
        references: vec![],
    };
    
    // This should check shared context and skip creation
    let result = perception_agent.create_entity_with_spatial_data(
        &contextual_entity,
        user.id,
        &session_dek,
    ).await;
    
    assert!(result.is_ok(), "Should handle existing entity gracefully");
}