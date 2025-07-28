//! Functional tests for CreateEntityTool
//! 
//! Tests the atomic entity creation tool to ensure it properly:
//! - Creates entities from natural language descriptions using AI
//! - Generates appropriate component structures
//! - Handles various entity types (characters, locations, items, etc.)
//! - Creates entities unconditionally (no duplicate checking)
//! - Returns consistent structured output
//! - Handles edge cases and error conditions

use scribe_backend::services::agentic::tools::entity_crud_tools::CreateEntityTool;
use scribe_backend::services::agentic::tools::ScribeTool;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::services::EcsEntityManager;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, db::create_test_user};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_create_character_entity() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_char".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a wise old sage named Eldrich who knows ancient magic",
        "context": "The party needs to find someone who can help them understand an ancient artifact"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
    
    match &result {
        Ok(res) => println!("Tool result: {}", serde_json::to_string_pretty(res).unwrap()),
        Err(err) => println!("Tool error: {:?}", err),
    }
    
    let result = result.expect("Tool execution failed");
    
    // Verify result structure
    assert_eq!(result["status"], "success");
    assert_eq!(result["created"], true);
    assert!(result["entity_id"].is_string());
    assert!(result["creation_plan"].is_object());
    assert!(result["summary"].is_string());
    assert_eq!(result["user_request"], "Create a wise old sage named Eldrich who knows ancient magic");
    
    // Verify entity was actually created in ECS
    let entity_id_str = result["entity_id"].as_str().unwrap();
    let entity_id = Uuid::parse_str(entity_id_str).unwrap();
    
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_details = entity_manager.get_entity(user.id, entity_id).await
        .expect("Failed to query entity")
        .expect("Entity should exist after creation");
    
    assert_eq!(entity_details.entity.id, entity_id);
    
    // Verify components were created
    assert!(!entity_details.components.is_empty(), "Entity should have components");
    
    // Look for Name component
    let name_component = entity_details.components.iter()
        .find(|comp| comp.component_type == "Name");
    assert!(name_component.is_some(), "Entity should have a Name component");
    
    if let Some(name_comp) = name_component {
        let name_data = &name_comp.component_data;
        assert!(name_data.get("name").is_some(), "Name component should have a name field");
        let name = name_data.get("name").unwrap().as_str().unwrap();
        assert!(name.contains("Eldrich") || name.to_lowercase().contains("sage"), 
               "Entity name should relate to the creation request: {}", name);
    }
}

#[tokio::test]
async fn test_create_location_entity() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_loc".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a haunted library with mysterious books and floating candles",
        "context": "The adventurers have discovered a secret passage leading to this magical place"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result structure
    assert_eq!(result["status"], "success");
    assert_eq!(result["created"], true);
    assert!(result["entity_id"].is_string());
    
    // Verify entity was created in ECS
    let entity_id_str = result["entity_id"].as_str().unwrap();
    let entity_id = Uuid::parse_str(entity_id_str).unwrap();
    
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_details = entity_manager.get_entity(user.id, entity_id).await
        .expect("Failed to query entity")
        .expect("Entity should exist after creation");
    
    assert_eq!(entity_details.entity.id, entity_id);
    assert!(!entity_details.components.is_empty(), "Location entity should have components");
}

#[tokio::test]
async fn test_create_item_entity() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_item".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a magical sword that glows blue when orcs are near",
        "context": "This is a legendary weapon that will help the heroes in their quest"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result structure
    assert_eq!(result["status"], "success");
    assert_eq!(result["created"], true);
    assert!(result["entity_id"].is_string());
    
    // Verify entity was created
    let entity_id_str = result["entity_id"].as_str().unwrap();
    let entity_id = Uuid::parse_str(entity_id_str).unwrap();
    
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_details = entity_manager.get_entity(user.id, entity_id).await
        .expect("Failed to query entity")
        .expect("Entity should exist after creation");
    
    assert_eq!(entity_details.entity.id, entity_id);
}

#[tokio::test]
async fn test_create_entity_unconditional_no_duplicate_check() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_dupes".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let creation_request = "Create a guard named Bob who stands at the gate";
    
    // Create first entity
    let params1 = json!({
        "user_id": user.id.to_string(),
        "creation_request": creation_request,
        "context": "First guard for the main gate"
    });
    
    let result1 = tool.execute(&params1, &SessionDek::new(vec![0u8; 32])).await
        .expect("First tool execution failed");
    
    assert_eq!(result1["status"], "success");
    assert_eq!(result1["created"], true);
    let entity_id1 = result1["entity_id"].as_str().unwrap();
    
    // Create second entity with similar request - should create another entity, not return existing
    let params2 = json!({
        "user_id": user.id.to_string(),
        "creation_request": creation_request,
        "context": "Second guard for backup"
    });
    
    let result2 = tool.execute(&params2, &SessionDek::new(vec![0u8; 32])).await
        .expect("Second tool execution failed");
    
    assert_eq!(result2["status"], "success");
    assert_eq!(result2["created"], true);
    let entity_id2 = result2["entity_id"].as_str().unwrap();
    
    // Verify that two different entities were created (atomic behavior - no duplicate checking)
    assert_ne!(entity_id1, entity_id2, "CreateEntityTool should create new entities unconditionally, not return existing ones");
    
    // Verify both entities exist in ECS
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity1 = entity_manager.get_entity(user.id, Uuid::parse_str(entity_id1).unwrap()).await
        .expect("Query should succeed")
        .expect("First entity should exist");
    let entity2 = entity_manager.get_entity(user.id, Uuid::parse_str(entity_id2).unwrap()).await
        .expect("Query should succeed")
        .expect("Second entity should exist");
    
    assert_ne!(entity1.entity.id, entity2.entity.id);
}

#[tokio::test]
async fn test_create_entity_user_isolation() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two test users
    let user1 = create_test_user(&test_app.db_pool, "test_user1_isolation".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user1.id);
    let user2 = create_test_user(&test_app.db_pool, "test_user2_isolation".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user2.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    
    // User1 creates an entity
    let params1 = json!({
        "user_id": user1.id.to_string(),
        "creation_request": "Create a merchant named Trader Joe",
        "context": "User1's merchant for their story"
    });
    
    let result1 = tool.execute(&params1, &SessionDek::new(vec![0u8; 32])).await
        .expect("User1 tool execution failed");
    
    let entity_id1 = result1["entity_id"].as_str().unwrap();
    
    // User2 creates an entity
    let params2 = json!({
        "user_id": user2.id.to_string(),
        "creation_request": "Create a blacksmith named Iron Will",
        "context": "User2's blacksmith for their story"
    });
    
    let result2 = tool.execute(&params2, &SessionDek::new(vec![0u8; 32])).await
        .expect("User2 tool execution failed");
    
    let entity_id2 = result2["entity_id"].as_str().unwrap();
    
    // Verify entities were created for respective users
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    // User1 should be able to access their entity
    let _entity1 = entity_manager.get_entity(user1.id, Uuid::parse_str(entity_id1).unwrap()).await
        .expect("Query should succeed")
        .expect("User1 should access their entity");
    
    // User2 should be able to access their entity
    let _entity2 = entity_manager.get_entity(user2.id, Uuid::parse_str(entity_id2).unwrap()).await
        .expect("Query should succeed")
        .expect("User2 should access their entity");
    
    // User1 should NOT be able to access User2's entity
    let user1_access_user2_entity = entity_manager.get_entity(user1.id, Uuid::parse_str(entity_id2).unwrap()).await
        .expect("Query should succeed but return None");
    assert!(user1_access_user2_entity.is_none(), "User1 should not access User2's entity");
    
    // User2 should NOT be able to access User1's entity
    let user2_access_user1_entity = entity_manager.get_entity(user2.id, Uuid::parse_str(entity_id1).unwrap()).await
        .expect("Query should succeed but return None");
    assert!(user2_access_user1_entity.is_none(), "User2 should not access User1's entity");
}

#[tokio::test]
async fn test_create_entity_invalid_user_id() {
    let test_app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": "invalid-uuid",
        "creation_request": "Create something",
        "context": "Test context"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
    
    // Should fail with invalid user_id
    assert!(result.is_err(), "Should fail with invalid user_id");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid user_id format"), "Error should mention user_id format: {}", error_msg);
}

#[tokio::test]
async fn test_create_entity_missing_parameters() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_missing".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    
    // Missing user_id
    let params1 = json!({
        "creation_request": "Create something",
        "context": "Test context"
    });
    
    let result1 = tool.execute(&params1, &SessionDek::new(vec![0u8; 32])).await;
    assert!(result1.is_err(), "Should fail without user_id");
    
    // Missing creation_request
    let params2 = json!({
        "user_id": user.id.to_string(),
        "context": "Test context"
    });
    
    let result2 = tool.execute(&params2, &SessionDek::new(vec![0u8; 32])).await;
    assert!(result2.is_err(), "Should fail without creation_request");
    
    // Missing context (should work with default)
    let params3 = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a simple entity"
    });
    
    let result3 = tool.execute(&params3, &SessionDek::new(vec![0u8; 32])).await;
    assert!(result3.is_ok(), "Should work without context (uses default)");
}

#[tokio::test]
async fn test_create_entity_empty_creation_request() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_empty".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "",
        "context": "Test with empty request"
    });
    
    // Even with empty request, the tool should try to use AI to interpret it
    // The AI might return an error or create a default entity - either is acceptable
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
    
    // We allow this to pass or fail gracefully - the important thing is no crash
    match result {
        Ok(response) => {
            // If it succeeds, verify basic structure
            assert!(response["status"].is_string());
        },
        Err(error) => {
            // If it fails, error should be descriptive
            let error_msg = error.to_string();
            assert!(!error_msg.is_empty(), "Error message should not be empty");
        }
    }
}

#[tokio::test]
async fn test_create_entity_complex_description() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_complex".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a floating crystal tower that serves as both a lighthouse and a magical academy, with spiral staircases made of hardened moonbeams and classrooms that exist in pocket dimensions",
        "context": "This is a major landmark in a high-fantasy world where magic and architecture blend seamlessly"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle complex descriptions");
    
    // Verify the tool can handle complex descriptions
    assert_eq!(result["status"], "success");
    assert_eq!(result["created"], true);
    
    // Verify the creation plan contains some reference to the complexity
    let creation_plan = &result["creation_plan"];
    assert!(creation_plan.is_object(), "Creation plan should be detailed for complex entities");
}

#[tokio::test]
async fn test_create_entity_with_special_characters() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_special".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "creation_request": "Create a café called 'L'Étoile d'Or' with naïve paintings and a résumé-reading patron named François",
        "context": "Testing Unicode and special character handling"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle special characters");
    
    assert_eq!(result["status"], "success");
    assert_eq!(result["created"], true);
    
    // Verify the entity was created and can be retrieved
    let entity_id_str = result["entity_id"].as_str().unwrap();
    let entity_id = Uuid::parse_str(entity_id_str).unwrap();
    
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_details = entity_manager.get_entity(user.id, entity_id).await
        .expect("Query should succeed")
        .expect("Entity with special characters should be retrievable");
    
    assert_eq!(entity_details.entity.id, entity_id);
}

#[tokio::test]
async fn test_create_entity_response_format_consistency() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_format".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CreateEntityTool::new(test_app.app_state.clone());
    
    // Test multiple different creation requests
    let test_cases = vec![
        ("Create a dragon", "Fantasy scenario"),
        ("Create a spaceship", "Sci-fi scenario"),
        ("Create a coffee shop", "Modern scenario"),
        ("Create a magical crystal", "Mystical item"),
    ];
    
    for (request, context) in test_cases {
        let params = json!({
            "user_id": user.id.to_string(),
            "creation_request": request,
            "context": context
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect(&format!("Tool execution failed for: {}", request));
        
        // Verify consistent response format
        assert_eq!(result["status"], "success", "Status should be success for: {}", request);
        assert_eq!(result["created"], true, "Created should be true for: {}", request);
        assert!(result["entity_id"].is_string(), "entity_id should be string for: {}", request);
        assert!(result["creation_plan"].is_object(), "creation_plan should be object for: {}", request);
        assert!(result["summary"].is_string(), "summary should be string for: {}", request);
        assert_eq!(result["user_request"], request, "user_request should match input for: {}", request);
        
        // Verify entity_id is a valid UUID
        let entity_id_str = result["entity_id"].as_str().unwrap();
        assert!(Uuid::parse_str(entity_id_str).is_ok(), "entity_id should be valid UUID for: {}", request);
    }
}