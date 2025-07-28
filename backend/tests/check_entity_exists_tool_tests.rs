//! Functional tests for CheckEntityExistsTool
//! 
//! Tests the atomic entity existence checking tool to ensure it properly:
//! - Checks entities by UUID
//! - Checks entities by name
//! - Applies entity type filters correctly
//! - Returns proper boolean results
//! - Handles non-existent entities gracefully

use scribe_backend::services::agentic::tools::entity_crud_tools::CheckEntityExistsTool;
use scribe_backend::services::agentic::tools::ScribeTool;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::services::{EcsEntityManager, ChronicleService};
use scribe_backend::models::chronicle::CreateChronicleRequest;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, db::create_test_user};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_check_entity_exists_by_uuid_found() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_uuid".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create test chronicle
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create a test entity
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": "Test Entity",
            "entity_type": "character"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test the tool
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": created_entity.entity.id.to_string()
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result
    assert_eq!(result["exists"], true);
    assert_eq!(result["entity_id"], created_entity.entity.id.to_string());
    assert_eq!(result["entity_type"], "character");
    assert_eq!(result["name"], "Test Entity");
}

#[tokio::test]
async fn test_check_entity_exists_by_uuid_not_found() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_not_found".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Test with non-existent UUID
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let non_existent_id = Uuid::new_v4();
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": non_existent_id.to_string()
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result
    assert_eq!(result["exists"], false);
    assert_eq!(result["entity_id"], serde_json::Value::Null);
    assert_eq!(result["entity_type"], serde_json::Value::Null);
    assert_eq!(result["name"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_check_entity_exists_by_name_found() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_name".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create test chronicle
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create a test entity with unique name
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let unique_name = format!("Unique Entity {}", Uuid::new_v4());
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": &unique_name,
            "entity_type": "location"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test the tool with name lookup
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": &unique_name
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result
    assert_eq!(result["exists"], true);
    assert_eq!(result["entity_id"], created_entity.entity.id.to_string());
    assert_eq!(result["entity_type"], "location");
    assert_eq!(result["name"], unique_name);
}

#[tokio::test]
async fn test_check_entity_exists_by_name_not_found() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_name_missing".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Test with non-existent name
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": "Non-existent Entity Name"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result
    assert_eq!(result["exists"], false);
    assert_eq!(result["entity_id"], serde_json::Value::Null);
    assert_eq!(result["entity_type"], serde_json::Value::Null);
    assert_eq!(result["name"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_check_entity_exists_with_type_filter_match() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_type_match".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create test chronicle
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create a test entity
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let unique_name = format!("Typed Entity {}", Uuid::new_v4());
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": &unique_name,
            "entity_type": "item"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test with matching type filter
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": &unique_name,
        "entity_type": "item"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result - should find the entity
    assert_eq!(result["exists"], true);
    assert_eq!(result["entity_id"], created_entity.entity.id.to_string());
    assert_eq!(result["entity_type"], "item");
    assert_eq!(result["name"], unique_name);
}

#[tokio::test]
async fn test_check_entity_exists_with_type_filter_mismatch() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_type_mismatch".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create test chronicle
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create a test entity
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let unique_name = format!("Mismatched Type Entity {}", Uuid::new_v4());
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": &unique_name,
            "entity_type": "character"
        })),
    ];
    
    let _created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test with non-matching type filter
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": &unique_name,
        "entity_type": "location"  // Wrong type
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result - should NOT find the entity due to type mismatch
    assert_eq!(result["exists"], false);
    assert_eq!(result["entity_id"], serde_json::Value::Null);
    assert_eq!(result["entity_type"], serde_json::Value::Null);
    assert_eq!(result["name"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_check_entity_exists_invalid_user_id() {
    let test_app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": "invalid-uuid",
        "identifier": "Some Entity"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
    
    // Should fail with invalid params error
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.to_string().contains("user_id must be a valid UUID"));
    }
}

#[tokio::test]
async fn test_check_entity_exists_missing_identifier() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_missing".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string()
        // Missing identifier
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
    
    // Should fail with invalid params error
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.to_string().contains("identifier must be a string"));
    }
}

#[tokio::test]
async fn test_check_entity_exists_any_type_filter() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_any_type".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create test chronicle
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create a test entity
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let unique_name = format!("Any Type Entity {}", Uuid::new_v4());
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": &unique_name,
            "entity_type": "organization"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test with "any" type filter (should ignore type)
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": &unique_name,
        "entity_type": "any"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    // Verify result - should find the entity regardless of type
    assert_eq!(result["exists"], true);
    assert_eq!(result["entity_id"], created_entity.entity.id.to_string());
    assert_eq!(result["entity_type"], "organization");
    assert_eq!(result["name"], unique_name);
}

#[tokio::test]
async fn test_check_entity_exists_user_isolation() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test users
    let user1 = create_test_user(&test_app.db_pool, "test_user1_isolation".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user1.id);
    let user2 = create_test_user(&test_app.db_pool, "test_user2_isolation".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user2.id);
    
    // Create chronicle for user1
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle_request = CreateChronicleRequest {
        name: "User1 Chronicle".to_string(),
        description: None,
    };
    let chronicle = chronicle_service.create_chronicle(user1.id, chronicle_request).await
        .expect("Failed to create chronicle");
    let world_id = chronicle.id;
    
    // Create entity for user1
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let unique_name = format!("User Isolated Entity {}", Uuid::new_v4());
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": &unique_name,
            "entity_type": "character"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user1.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test as user1 - should find the entity
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params1 = json!({
        "user_id": user1.id.to_string(),
        "identifier": created_entity.entity.id.to_string()
    });
    
    let result1 = tool.execute(&params1, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    assert_eq!(result1["exists"], true);
    
    // Test as user2 - should NOT find the entity
    let params2 = json!({
        "user_id": user2.id.to_string(),
        "identifier": created_entity.entity.id.to_string()
    });
    
    let result2 = tool.execute(&params2, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution failed");
    
    assert_eq!(result2["exists"], false);
}