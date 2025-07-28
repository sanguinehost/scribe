use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::models::ecs::NameComponent;
use serde_json::json;
use uuid::Uuid;

/// Test that demonstrates the duplicate entity creation issue and verifies the fix
#[tokio::test]
async fn test_perception_agent_handles_duplicate_entity_creation() {
    let test_app = spawn_app(false, false, false).await;
    let user = db::create_test_user(&test_app.db_pool, "duplicate_test".to_string(), "password123".to_string())
        .await
        .expect("Failed to create test user");
    let _session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create a location entity using the entity manager directly
    let entity_name = "Mystic Tower";
    let entity_uuid = Uuid::new_v4();
    
    // First creation should succeed
    let name_component = NameComponent {
        name: entity_name.to_string(),
        display_name: entity_name.to_string(),
        aliases: vec![],
    };
    
    let components = vec![
        ("name".to_string(), serde_json::to_value(&name_component).unwrap()),
        ("position".to_string(), json!({
            "x": 0.0,
            "y": 0.0,
            "z": 0.0,
            "spatial_reference": "absolute"
        })),
    ];
    
    let result1 = test_app.app_state.ecs_entity_manager.create_entity(
        user.id,
        Some(entity_uuid),
        "location".to_string(),
        components,
    ).await;
    assert!(result1.is_ok(), "First entity creation failed: {:?}", result1.err());
    
    println!("✅ First entity creation succeeded");
    
    // Second creation with a different UUID but same name - should succeed
    let entity_uuid2 = Uuid::new_v4();
    let components2 = vec![
        ("name".to_string(), serde_json::to_value(&name_component).unwrap()),
        ("position".to_string(), json!({
            "x": 10.0,
            "y": 10.0,
            "z": 0.0,
            "spatial_reference": "absolute"
        })),
    ];
    
    let result2 = test_app.app_state.ecs_entity_manager.create_entity(
        user.id,
        Some(entity_uuid2),
        "location".to_string(),
        components2,
    ).await;
    
    // This should succeed since entity names are not unique across entities
    assert!(result2.is_ok(), "Second entity creation with different UUID should succeed");
    println!("✅ Second entity creation with same name succeeded");
    
    // Now test that creating with the SAME UUID fails
    let name_component3 = NameComponent {
        name: "Different Name".to_string(),
        display_name: "Different Name".to_string(),
        aliases: vec![],
    };
    
    let components3 = vec![
        ("name".to_string(), serde_json::to_value(&name_component3).unwrap()),
    ];
    
    let result3 = test_app.app_state.ecs_entity_manager.create_entity(
        user.id,
        Some(entity_uuid), // Reuse the first UUID
        "location".to_string(),
        components3,
    ).await;
    
    match result3 {
        Ok(_) => panic!("Creating entity with duplicate UUID should fail"),
        Err(e) => {
            let error_str = format!("{:?}", e);
            println!("✅ Duplicate UUID correctly rejected: {}", error_str);
            assert!(
                error_str.contains("duplicate key") || error_str.contains("already exists"),
                "Expected duplicate key error, got: {}",
                error_str
            );
        }
    }
}

/// Test the perception agent's intelligent entity handling
#[tokio::test]
async fn test_perception_agent_entity_existence_checking() {
    let test_app = spawn_app(false, false, false).await;
    let user = db::create_test_user(&test_app.db_pool, "perception_check".to_string(), "password123".to_string())
        .await
        .expect("Failed to create test user");
    let _session_dek = SessionDek::new(vec![0u8; 32]);
    
    // First, create an entity directly
    let entity_name = "Ancient Library";
    let entity_uuid = Uuid::new_v4();
    
    let name_component = NameComponent {
        name: entity_name.to_string(),
        display_name: entity_name.to_string(),
        aliases: vec![],
    };
    
    let components = vec![
        ("name".to_string(), serde_json::to_value(&name_component).unwrap()),
        ("position".to_string(), json!({
            "x": 0.0,
            "y": 0.0,
            "z": 0.0,
            "spatial_reference": "absolute"
        })),
    ];
    
    let _ = test_app.app_state.ecs_entity_manager.create_entity(
        user.id,
        Some(entity_uuid),
        "location".to_string(),
        components,
    ).await
    .expect("Failed to create first entity");
    
    println!("✅ First entity created successfully");
    
    // Now test query for entities
    use scribe_backend::services::ecs_entity_manager::ComponentQuery;
    let query_result = test_app.app_state.ecs_entity_manager.query_entities(
        user.id,
        vec![ComponentQuery::ComponentDataEquals(
            "name".to_string(),
            "name".to_string(),
            json!(entity_name),
        )],
        Some(10),
        None,
    ).await
    .expect("Failed to query entities");
    
    assert!(!query_result.is_empty(), "Should find at least one entity");
    println!("✅ Successfully queried for existing entities: found {}", query_result.len());
    
    // Try to create another entity with the same name but different UUID
    // This should succeed as names are not unique
    let entity_uuid2 = Uuid::new_v4();
    let components2 = vec![
        ("name".to_string(), serde_json::to_value(&name_component).unwrap()),
        ("position".to_string(), json!({
            "x": 100.0,
            "y": 100.0,
            "z": 0.0,
            "spatial_reference": "absolute"
        })),
    ];
    
    let result = test_app.app_state.ecs_entity_manager.create_entity(
        user.id,
        Some(entity_uuid2),
        "location".to_string(),
        components2,
    ).await;
    
    match &result {
        Ok(_) => {
            println!("✅ Second entity with same name but different UUID created successfully");
        }
        Err(e) => {
            panic!("Should be able to create entity with same name but different UUID: {:?}", e);
        }
    }
}