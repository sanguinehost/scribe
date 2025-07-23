//! Functional Tests for World Interaction Tools - Inventory functionality
//!
//! This test suite validates inventory management operations (add/remove items)
//! as outlined in Task 2.4 of the Living World Implementation Roadmap.

use scribe_backend::{
    models::ecs::InventoryComponent,
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{
            ScribeTool, ToolError,
            world_interaction_tools::{AddItemToInventoryTool, RemoveItemFromInventoryTool, CreateEntityTool}
        },
    },
    test_helpers::spawn_app,
    PgPool,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Create EcsEntityManager with Redis for testing
async fn create_entity_manager(db_pool: PgPool) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig {
        default_cache_ttl: 60,
        hot_cache_ttl: 300,
        bulk_operation_batch_size: 50,
        enable_component_caching: true,
    };
    
    Arc::new(EcsEntityManager::new(
        db_pool.into(),
        redis_client,
        Some(config),
    ))
}


#[cfg(test)]
mod inventory_functional_tests {
    use super::*;

    /// Helper function to create test entities for inventory operations
    async fn create_test_entities(
        entity_manager: Arc<EcsEntityManager>,
        user_id: Uuid,
    ) -> (Uuid, Uuid, Uuid) {
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Create character with inventory
        let character_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Sol Kantara",
            "archetype_signature": "Name|Inventory",
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Sol Kantara", "display_name": "Sol", "aliases": ["Bounty Hunter"]},
                "Inventory": {"items": [], "capacity": 10}
            }
        });
        let character_result = create_tool.execute(&character_params).await.expect("Character creation failed");
        let character_id = Uuid::parse_str(character_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create blaster item
        let blaster_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "DL-44 Heavy Blaster Pistol",
            "archetype_signature": "Name",
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "DL-44 Heavy Blaster Pistol", "display_name": "Blaster", "aliases": ["Pistol", "Weapon"]}
            }
        });
        let blaster_result = create_tool.execute(&blaster_params).await.expect("Blaster creation failed");
        let blaster_id = Uuid::parse_str(blaster_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create credits item
        let credits_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Imperial Credits",
            "archetype_signature": "Name",
            "salience_tier": "Flavor",
            "components": {
                "Name": {"name": "Imperial Credits", "display_name": "Credits", "aliases": ["Money", "Currency"]}
            }
        });
        let credits_result = create_tool.execute(&credits_params).await.expect("Credits creation failed");
        let credits_id = Uuid::parse_str(credits_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        (character_id, blaster_id, credits_id)
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_add_item_to_inventory_basic_functionality() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, blaster_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = AddItemToInventoryTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1,
            "slot": null
        });

        let result = tool.execute(&params).await.expect("Add item should succeed");

        // Verify result structure
        assert!(result.get("success").unwrap().as_bool().unwrap());
        assert_eq!(result.get("item_added").unwrap().get("entity_id").unwrap().as_str().unwrap(), blaster_id.to_string());
        assert_eq!(result.get("item_added").unwrap().get("quantity").unwrap().as_u64().unwrap(), 1);

        // Verify inventory was updated in database
        let character_details = entity_manager.get_entity(user_id, character_id).await.unwrap().unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");

        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");

        assert_eq!(inventory.items.len(), 1);
        assert_eq!(inventory.items[0].entity_id, blaster_id);
        assert_eq!(inventory.items[0].quantity, 1);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_add_item_with_specific_slot() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, blaster_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = AddItemToInventoryTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1,
            "slot": 5
        });

        let result = tool.execute(&params).await.expect("Add item to specific slot should succeed");

        // Verify slot assignment
        assert_eq!(result.get("item_added").unwrap().get("slot").unwrap().as_u64().unwrap(), 5);

        // Verify in database
        let character_details = entity_manager.get_entity(user_id, character_id).await.unwrap().unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");

        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");

        assert_eq!(inventory.items[0].slot, Some(5));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_add_item_with_quantity() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, _, credits_id) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = AddItemToInventoryTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 1000,
            "slot": null
        });

        let result = tool.execute(&params).await.expect("Add stackable item should succeed");

        // Verify quantity
        assert_eq!(result.get("item_added").unwrap().get("quantity").unwrap().as_u64().unwrap(), 1000);

        // Verify in database
        let character_details = entity_manager.get_entity(user_id, character_id).await.unwrap().unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");

        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");

        assert_eq!(inventory.items[0].quantity, 1000);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_remove_item_from_inventory_basic_functionality() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, blaster_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        // First add item
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        let add_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        add_tool.execute(&add_params).await.expect("Add item should succeed");

        // Now remove item
        let remove_tool = RemoveItemFromInventoryTool::new(entity_manager.clone());
        let remove_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1
        });

        let result = remove_tool.execute(&remove_params).await.expect("Remove item should succeed");

        // Verify result structure
        assert!(result.get("success").unwrap().as_bool().unwrap());
        assert_eq!(result.get("item_removed").unwrap().get("entity_id").unwrap().as_str().unwrap(), blaster_id.to_string());
        assert_eq!(result.get("item_removed").unwrap().get("quantity").unwrap().as_u64().unwrap(), 1);

        // Verify inventory is now empty
        let character_details = entity_manager.get_entity(user_id, character_id).await.unwrap().unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");

        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");

        assert_eq!(inventory.items.len(), 0);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_remove_partial_quantity() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, _, credits_id) = create_test_entities(entity_manager.clone(), user_id).await;

        // Add 1000 credits
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        let add_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 1000,
            "slot": null
        });
        add_tool.execute(&add_params).await.expect("Add credits should succeed");

        // Remove 300 credits
        let remove_tool = RemoveItemFromInventoryTool::new(entity_manager.clone());
        let remove_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 300
        });

        let result = remove_tool.execute(&remove_params).await.expect("Remove partial quantity should succeed");

        // Verify result
        assert_eq!(result.get("item_removed").unwrap().get("quantity").unwrap().as_u64().unwrap(), 300);

        // Verify 700 credits remain
        let character_details = entity_manager.get_entity(user_id, character_id).await.unwrap().unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");

        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");

        assert_eq!(inventory.items.len(), 1);
        assert_eq!(inventory.items[0].quantity, 700);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_add_item_capacity_exceeded() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");

        // Create character with very small inventory capacity
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let character_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Limited Sol",
            "archetype_signature": "Name|Inventory",
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Limited Sol", "display_name": "Sol", "aliases": []},
                "Inventory": {"items": [], "capacity": 1}
            }
        });
        let character_result = create_tool.execute(&character_params).await.expect("Character creation failed");
        let character_id = Uuid::parse_str(character_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        let (_, blaster_id, credits_id) = create_test_entities(entity_manager.clone(), user_id).await;

        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());

        // Add first item (should succeed)
        let params1 = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        add_tool.execute(&params1).await.expect("First item should fit");

        // Try to add second item (should fail due to capacity)
        let params2 = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 1,
            "slot": null
        });

        let result = add_tool.execute(&params2).await;
        assert!(result.is_err());
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("capacity") || msg.contains("full"));
        } else {
            panic!("Expected capacity error");
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_remove_item_not_found() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, blaster_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let remove_tool = RemoveItemFromInventoryTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": blaster_id.to_string(),
            "quantity": 1
        });

        let result = remove_tool.execute(&params).await;
        assert!(result.is_err());
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("not found") || msg.contains("does not have"));
        } else {
            panic!("Expected item not found error");
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_remove_insufficient_quantity() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, _, credits_id) = create_test_entities(entity_manager.clone(), user_id).await;

        // Add 100 credits
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        let add_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 100,
            "slot": null
        });
        add_tool.execute(&add_params).await.expect("Add credits should succeed");

        // Try to remove 500 credits (should fail)
        let remove_tool = RemoveItemFromInventoryTool::new(entity_manager.clone());
        let remove_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": credits_id.to_string(),
            "quantity": 500
        });

        let result = remove_tool.execute(&remove_params).await;
        assert!(result.is_err());
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("insufficient") || msg.contains("not enough"));
        } else {
            panic!("Expected insufficient quantity error");
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_inventory_operations_with_nonexistent_entities() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (character_id, _, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let fake_item_id = Uuid::new_v4();
        let fake_character_id = Uuid::new_v4();

        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());

        // Test with nonexistent character
        let params1 = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": fake_character_id.to_string(),
            "item_entity_id": fake_item_id.to_string(),
            "quantity": 1,
            "slot": null
        });

        let result1 = add_tool.execute(&params1).await;
        assert!(result1.is_err());

        // Test with nonexistent item
        let params2 = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": fake_item_id.to_string(),
            "quantity": 1,
            "slot": null
        });

        let result2 = add_tool.execute(&params2).await;
        assert!(result2.is_err());
    }
}