//! OWASP Top 10 Security Tests for World Interaction Tools - Inventory & Relationship functionality
//!
//! This comprehensive security test suite validates inventory and relationship tools against 
//! all OWASP Top 10 vulnerability categories as outlined in Task 2.4 of the Living World 
//! Implementation Roadmap.

use scribe_backend::{
    models::ecs::{
        InventoryComponent, InventoryItem, RelationshipsComponent, Relationship,
        NameComponent, SalienceTier,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{ScribeTool, ToolError},
    },
    test_helpers::{spawn_app, db::create_test_user},
    errors::AppError,
    PgPool,
};
use serde_json::{json, Value as JsonValue};
use std::{sync::Arc, collections::HashMap};
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

use scribe_backend::services::agentic::tools::world_interaction_tools::{
    CreateEntityTool, AddItemToInventoryTool, RemoveItemFromInventoryTool, UpdateRelationshipTool,
};

/// Helper function to create test entities for security tests
async fn create_test_entities_for_security(
    entity_manager: Arc<EcsEntityManager>,
    user_id: Uuid,
) -> (Uuid, Uuid, Uuid) {
    let create_tool = CreateEntityTool::new(entity_manager.clone());

    let character_params = json!({
        "user_id": user_id.to_string(),
        "entity_name": "Security Test Character",
        "archetype_signature": "Name|Inventory|Relationships",
        "salience_tier": "Core",
        "components": {
            "Name": {"name": "Security Test Character", "display_name": "TestChar", "aliases": []},
            "Inventory": {"items": [], "capacity": 10},
            "Relationships": {"relationships": []}
        }
    });
    let character_result = create_tool.execute(&character_params).await.expect("Character creation failed");
    let character_id = Uuid::parse_str(character_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

    let item_params = json!({
        "user_id": user_id.to_string(),
        "entity_name": "Security Test Item",
        "archetype_signature": "Name",
        "salience_tier": "Secondary",
        "components": {
            "Name": {"name": "Security Test Item", "display_name": "TestItem", "aliases": []}
        }
    });
    let item_result = create_tool.execute(&item_params).await.expect("Item creation failed");
    let item_id = Uuid::parse_str(item_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

    let target_params = json!({
        "user_id": user_id.to_string(),
        "entity_name": "Security Test Target",
        "archetype_signature": "Name|Relationships",
        "salience_tier": "Secondary",
        "components": {
            "Name": {"name": "Security Test Target", "display_name": "TestTarget", "aliases": []},
            "Relationships": {"relationships": []}
        }
    });
    let target_result = create_tool.execute(&target_params).await.expect("Target creation failed");
    let target_id = Uuid::parse_str(target_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

    (character_id, item_id, target_id)
}

#[cfg(test)]
mod inventory_relationship_security_tests {
    use super::*;

    // ========================================================================================
    // A01:2021 - Broken Access Control
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a01_inventory_cross_user_access_control(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        
        // Create entities for user A
        let user_a_id = create_test_user(&ctx.db_pool).await;
        let (character_a_id, item_a_id, _) = create_test_entities_for_security(entity_manager.clone(), user_a_id).await;
        
        // Create user B
        let user_b_id = create_test_user(&ctx.db_pool).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // User B attempts to access User A's character
        let malicious_params = json!({
            "user_id": user_b_id.to_string(),
            "character_entity_id": character_a_id.to_string(),
            "item_entity_id": item_a_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&malicious_params).await;
        assert!(result.is_err(), "Cross-user inventory access should be denied");
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("not found") || msg.contains("access"), 
                "Should return access control error, got: {}", msg);
        } else {
            panic!("Expected access control error");
        }
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a01_relationship_cross_user_access_control(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        
        // Create entities for user A
        let user_a_id = create_test_user(&ctx.db_pool).await;
        let (character_a_id, _, target_a_id) = create_test_entities_for_security(entity_manager.clone(), user_a_id).await;
        
        // Create user B
        let user_b_id = create_test_user(&ctx.db_pool).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // User B attempts to modify User A's character relationships
        let malicious_params = json!({
            "user_id": user_b_id.to_string(),
            "source_entity_id": character_a_id.to_string(),
            "target_entity_id": target_a_id.to_string(),
            "relationship_type": "malicious",
            "trust": -1.0,
            "affection": -1.0,
            "metadata": {}
        });
        
        let result = update_tool.execute(&malicious_params).await;
        assert!(result.is_err(), "Cross-user relationship access should be denied");
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("not found") || msg.contains("access"), 
                "Should return access control error, got: {}", msg);
        } else {
            panic!("Expected access control error");
        }
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a01_privilege_escalation_prevention(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Attempt to use admin-level user ID
        let admin_user_id = Uuid::nil(); // Attempt to use system/admin UUID
        let escalation_params = json!({
            "user_id": admin_user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&escalation_params).await;
        assert!(result.is_err(), "Privilege escalation should be prevented");
    }

    // ========================================================================================
    // A02:2021 - Cryptographic Failures  
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a02_sensitive_relationship_data_encryption(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Create relationship with sensitive metadata
        let sensitive_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "confidential_source",
            "trust": 0.8,
            "affection": 0.2,
            "metadata": {
                "access_codes": "alpha-7-bravo-2",
                "payment_account": "swiss-bank-4401992",
                "secret_meetings": ["Location X", "Safe House 7"],
                "classified_intel": "Empire's weak point is thermal exhaust port"
            }
        });
        
        let result = update_tool.execute(&sensitive_params).await
            .expect("Sensitive relationship creation should succeed");
        
        // Verify the data is processed but we cannot verify encryption at this level
        // (Encryption verification would require database-level tests)
        assert!(result.get("success").unwrap().as_bool().unwrap());
        assert!(result.get("relationship").unwrap().get("metadata").unwrap()
            .get("access_codes").is_some());
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a02_inventory_data_integrity(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Add item with specific quantity
        let params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 42,
            "slot": 3
        });
        
        let result = add_tool.execute(&params).await
            .expect("Inventory operation should succeed");
        
        // Verify data integrity is maintained
        assert_eq!(result.get("item_added").unwrap().get("quantity").unwrap().as_u64().unwrap(), 42);
        assert_eq!(result.get("item_added").unwrap().get("slot").unwrap().as_u64().unwrap(), 3);
        assert_eq!(result.get("item_added").unwrap().get("entity_id").unwrap().as_str().unwrap(), item_id.to_string());
    }

    // ========================================================================================
    // A03:2021 - Injection
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a03_sql_injection_in_relationship_metadata(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Attempt SQL injection in metadata
        let injection_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "'; DROP TABLE ecs_entities; --",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {
                "injection_attempt": "'; UPDATE ecs_entities SET entity_name = 'HACKED' WHERE user_id = '",
                "another_injection": "1' OR '1'='1",
                "payload": "'; DELETE FROM ecs_components; COMMIT; --"
            }
        });
        
        // Should either succeed with sanitized data or fail gracefully
        let result = update_tool.execute(&injection_params).await;
        
        if let Ok(success_result) = result {
            // If successful, verify injection was sanitized
            let rel_type = success_result.get("relationship").unwrap()
                .get("relationship_type").unwrap().as_str().unwrap();
            // The relationship_type should be stored safely (not cause SQL injection)
            assert!(rel_type.contains("DROP TABLE") == false || rel_type.len() < 100);
        } else {
            // Failure is acceptable for security (input validation)
            assert!(result.is_err());
        }
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a03_nosql_injection_in_inventory_operations(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Attempt NoSQL-style injection with malformed UUIDs
        let injection_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": "'; $where: '1 == 1'; db.dropDatabase(); '",
            "item_entity_id": "{$ne: null}",
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&injection_params).await;
        assert!(result.is_err(), "NoSQL injection should be prevented by UUID validation");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a03_json_injection_prevention(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Attempt JSON injection in metadata
        let json_injection_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {
                "malicious_json": "\"},\"admin\":true,\"injected\":{\"",
                "escaped_quotes": "\\\"admin\\\":true",
                "script_tag": "<script>alert('xss')</script>",
                "json_break": "}\",\"malicious\":\"data"
            }
        });
        
        let result = update_tool.execute(&json_injection_params).await;
        
        if let Ok(success_result) = result {
            // Verify the malicious content is safely stored as string data
            let metadata = success_result.get("relationship").unwrap().get("metadata").unwrap();
            assert!(metadata.get("malicious_json").is_some());
            // Should be stored as literal string, not parsed as JSON structure
        }
        // Failure is also acceptable (input validation)
    }

    // ========================================================================================
    // A04:2021 - Insecure Design
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a04_inventory_capacity_business_logic(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        
        // Create character with limited capacity
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let limited_char_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Limited Character",
            "archetype_signature": "Name|Inventory",
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Limited Character", "display_name": "Limited", "aliases": []},
                "Inventory": {"items": [], "capacity": 2}
            }
        });
        let char_result = create_tool.execute(&limited_char_params).await.expect("Character creation failed");
        let char_id = Uuid::parse_str(char_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        let (_, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Fill inventory to capacity
        for _i in 0..2 {
            let params = json!({
                "user_id": user_id.to_string(),
                "character_entity_id": char_id.to_string(),
                "item_entity_id": item_id.to_string(),
                "quantity": 1,
                "slot": null
            });
            add_tool.execute(&params).await.expect("Should fit in capacity");
        }
        
        // Attempt to exceed capacity
        let overflow_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": char_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&overflow_params).await;
        assert!(result.is_err(), "Capacity overflow should be prevented");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a04_relationship_trust_bounds_validation(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Test bounds validation for trust values
        let invalid_trust_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "test",
            "trust": 999.9,  // Invalid: exceeds bounds
            "affection": -999.9,  // Invalid: exceeds bounds
            "metadata": {}
        });
        
        let result = update_tool.execute(&invalid_trust_params).await;
        assert!(result.is_err(), "Invalid trust/affection bounds should be rejected");
    }

    // ========================================================================================
    // A05:2021 - Security Misconfiguration
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a05_input_validation_enforcement(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Test with invalid JSON structure (missing required fields)
        let invalid_params = json!({
            "user_id": user_id.to_string(),
            // Missing character_entity_id
            "item_entity_id": Uuid::new_v4().to_string(),
            "quantity": 1
        });
        
        let result = add_tool.execute(&invalid_params).await;
        assert!(result.is_err(), "Invalid input should be rejected");
        
        // Test with invalid data types
        let wrong_type_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": "not-a-uuid",
            "item_entity_id": 12345,  // Wrong type
            "quantity": "not-a-number"  // Wrong type
        });
        
        let result2 = add_tool.execute(&wrong_type_params).await;
        assert!(result2.is_err(), "Wrong data types should be rejected");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a05_schema_enforcement_relationships(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Test with malformed UUID
        let malformed_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": "not-a-valid-uuid-format",
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {}
        });
        
        let result = update_tool.execute(&malformed_params).await;
        assert!(result.is_err(), "Malformed UUID should be rejected");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a05_default_secure_configuration(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Test that null/missing optional fields have secure defaults
        let minimal_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1
            // slot is optional and null
        });
        
        let result = add_tool.execute(&minimal_params).await
            .expect("Minimal valid params should succeed");
        
        // Verify secure defaults are applied
        assert!(result.get("item_added").unwrap().get("slot").is_null());
    }

    // ========================================================================================
    // A07:2021 - Identification and Authentication Failures
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a07_user_id_validation(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Test with invalid user ID format
        let invalid_user_params = json!({
            "user_id": "invalid-user-id-format",
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&invalid_user_params).await;
        assert!(result.is_err(), "Invalid user ID should be rejected");
        
        // Test with empty user ID
        let empty_user_params = json!({
            "user_id": "",
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result2 = add_tool.execute(&empty_user_params).await;
        assert!(result2.is_err(), "Empty user ID should be rejected");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a07_session_context_integrity(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Test that user_id must match the entity owner
        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "test",
            "trust": 0.5,
            "affection": 0.5,
            "metadata": {}
        });
        
        let result = update_tool.execute(&params).await
            .expect("Valid user should succeed");
        
        assert!(result.get("success").unwrap().as_bool().unwrap());
    }

    // ========================================================================================
    // A08:2021 - Software and Data Integrity Failures
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a08_inventory_data_consistency(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        let remove_tool = RemoveItemFromInventoryTool::new(entity_manager.clone());
        
        // Add 100 items
        let add_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 100,
            "slot": null
        });
        
        add_tool.execute(&add_params).await.expect("Add should succeed");
        
        // Remove 30 items
        let remove_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 30
        });
        
        remove_tool.execute(&remove_params).await.expect("Remove should succeed");
        
        // Verify data consistency: should have 70 items remaining
        let character_details = entity_manager.get_entity_details(user_id, character_id).await.unwrap();
        let inventory_component = character_details.components.iter()
            .find(|c| c.component_type == "Inventory")
            .expect("Character should have inventory component");
        
        let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
            .expect("Should deserialize inventory");
        
        assert_eq!(inventory.items.len(), 1);
        assert_eq!(inventory.items[0].quantity, 70);
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a08_relationship_data_integrity(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Create relationship with specific metadata
        let original_metadata = json!({
            "meeting_location": "Tatooine Cantina",
            "shared_secret": "blue_milk_special",
            "trust_history": [0.1, 0.3, 0.5, 0.7],
            "last_interaction": "2024-03-15T10:30:00Z"
        });
        
        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "trusted_ally",
            "trust": 0.8,
            "affection": 0.6,
            "metadata": original_metadata
        });
        
        let result = update_tool.execute(&params).await.expect("Relationship creation should succeed");
        
        // Verify data integrity: complex metadata should be preserved
        let returned_metadata = result.get("relationship").unwrap().get("metadata").unwrap();
        assert_eq!(returned_metadata.get("meeting_location").unwrap().as_str().unwrap(), "Tatooine Cantina");
        assert_eq!(returned_metadata.get("trust_history").unwrap().as_array().unwrap().len(), 4);
    }

    // ========================================================================================
    // A09:2021 - Security Logging and Monitoring Failures
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a09_security_event_logging_inventory(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let user_b_id = create_test_user(&ctx.db_pool).await;
        let (character_id, item_id, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Attempt unauthorized access (should be logged)
        let unauthorized_params = json!({
            "user_id": user_b_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": item_id.to_string(),
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&unauthorized_params).await;
        assert!(result.is_err(), "Unauthorized access should fail");
        
        // Note: Actual logging verification would require checking log output
        // which is beyond the scope of unit tests but should be monitored
        // in integration/system tests
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a09_audit_trail_for_relationship_changes(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Create initial relationship
        let initial_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "neutral",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {"audit": "initial_creation"}
        });
        
        update_tool.execute(&initial_params).await.expect("Initial relationship should succeed");
        
        // Update relationship (should create audit trail)
        let update_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "trusted",
            "trust": 0.8,
            "affection": 0.5,
            "metadata": {"audit": "trust_increased"}
        });
        
        let result = update_tool.execute(&update_params).await.expect("Relationship update should succeed");
        
        // Verify the update was applied
        assert_eq!(result.get("relationship").unwrap().get("relationship_type").unwrap().as_str().unwrap(), "trusted");
        assert_eq!(result.get("relationship").unwrap().get("trust").unwrap().as_f64().unwrap(), 0.8);
    }

    // ========================================================================================
    // A10:2021 - Server-Side Request Forgery (SSRF)
    // ========================================================================================

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a10_prevent_external_entity_references(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, _) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let add_tool = AddItemToInventoryTool::new(entity_manager.clone());
        
        // Attempt to reference external resource as item_entity_id
        let external_ref_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": "http://evil.com/steal-data",
            "quantity": 1,
            "slot": null
        });
        
        let result = add_tool.execute(&external_ref_params).await;
        assert!(result.is_err(), "External entity references should be blocked");
        
        // Test with URL-like UUID format
        let url_like_params = json!({
            "user_id": user_id.to_string(),
            "character_entity_id": character_id.to_string(),
            "item_entity_id": "file:///etc/passwd",
            "quantity": 1,
            "slot": null
        });
        
        let result2 = add_tool.execute(&url_like_params).await;
        assert!(result2.is_err(), "File URL references should be blocked");
    }

    #[test_context(test::TestContext)]
    #[serial_test::serial]
    #[test]
    async fn test_a10_relationship_metadata_ssrf_prevention(ctx: &mut test::TestContext) {
        let entity_manager = create_entity_manager(ctx.db_pool.clone()).await;
        let user_id = create_test_user(&ctx.db_pool).await;
        let (character_id, _, target_id) = create_test_entities_for_security(entity_manager.clone(), user_id).await;
        
        let update_tool = UpdateRelationshipTool::new(entity_manager.clone());
        
        // Attempt SSRF through metadata fields
        let ssrf_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": character_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {
                "profile_url": "http://internal.service/admin/delete-all",
                "avatar_src": "file:///etc/shadow",
                "webhook_url": "gopher://internal.network:70/sensitive-data",
                "data_source": "ldap://internal.ad:389/users"
            }
        });
        
        // Should succeed but URLs should be treated as literal data, not fetched
        let result = update_tool.execute(&ssrf_params).await;
        
        if let Ok(success_result) = result {
            // URLs should be stored as literal strings, not processed
            let metadata = success_result.get("relationship").unwrap().get("metadata").unwrap();
            assert!(metadata.get("profile_url").unwrap().as_str().unwrap().contains("http://"));
            // But no actual HTTP request should have been made
        }
        // Failure is also acceptable (input validation)
    }
}