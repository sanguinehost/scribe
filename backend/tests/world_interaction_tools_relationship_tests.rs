//! Functional Tests for World Interaction Tools - Relationship functionality
//!
//! This test suite validates relationship management operations (update/create relationships)
//! as outlined in Task 2.4 of the Living World Implementation Roadmap.

use scribe_backend::{
    models::ecs::RelationshipsComponent,
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{
            ScribeTool, ToolError,
            world_interaction_tools::{UpdateRelationshipTool, CreateEntityTool}
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
mod relationship_functional_tests {
    use super::*;

    /// Helper function to create test entities for relationship operations
    async fn create_test_entities(
        entity_manager: Arc<EcsEntityManager>,
        user_id: Uuid,
    ) -> (Uuid, Uuid, Uuid) {
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Create Sol Kantara (bounty hunter)
        let sol_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Sol Kantara",
            "archetype_signature": "Name|Relationships",
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Sol Kantara", "display_name": "Sol", "aliases": ["Bounty Hunter"]},
                "Relationships": {"relationships": []}
            }
        });
        let sol_result = create_tool.execute(&sol_params).await.expect("Sol creation failed");
        let sol_id = Uuid::parse_str(sol_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create Borga the Hutt (crime lord)
        let borga_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Borga the Hutt",
            "archetype_signature": "Name|Relationships",
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Borga the Hutt", "display_name": "Borga", "aliases": ["Crime Lord", "Hutt"]},
                "Relationships": {"relationships": []}
            }
        });
        let borga_result = create_tool.execute(&borga_params).await.expect("Borga creation failed");
        let borga_id = Uuid::parse_str(borga_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create Jenna Zan Arbor (ally)
        let jenna_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Dr. Jenna Zan Arbor",
            "archetype_signature": "Name|Relationships",
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Dr. Jenna Zan Arbor", "display_name": "Dr. Arbor", "aliases": ["Scientist", "Doctor"]},
                "Relationships": {"relationships": []}
            }
        });
        let jenna_result = create_tool.execute(&jenna_params).await.expect("Jenna creation failed");
        let jenna_id = Uuid::parse_str(jenna_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        (sol_id, borga_id, jenna_id)
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_create_new_relationship_basic_functionality() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, borga_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "fears",
            "trust": -0.8,
            "affection": -0.9,
            "metadata": {
                "reason": "Borga is a dangerous crime lord",
                "established": "2024-03-15",
                "intensity": "high"
            }
        });

        let result = tool.execute(&params).await.expect("Create relationship should succeed");

        // Verify result structure
        assert!(result.get("success").unwrap().as_bool().unwrap());
        assert_eq!(result.get("relationship").unwrap().get("target_entity_id").unwrap().as_str().unwrap(), borga_id.to_string());
        assert_eq!(result.get("relationship").unwrap().get("relationship_type").unwrap().as_str().unwrap(), "fears");
        assert_eq!(result.get("relationship").unwrap().get("trust").unwrap().as_f64().unwrap(), -0.8);
        assert_eq!(result.get("relationship").unwrap().get("affection").unwrap().as_f64().unwrap(), -0.9);

        // Verify relationship was added to database
        let sol_details = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
        let relationships_component = sol_details.components.iter()
            .find(|c| c.component_type == "Relationships")
            .expect("Sol should have relationships component");

        let relationships: RelationshipsComponent = serde_json::from_value(relationships_component.component_data.clone())
            .expect("Should deserialize relationships");

        assert_eq!(relationships.relationships.len(), 1);
        assert_eq!(relationships.relationships[0].target_entity_id, borga_id);
        assert_eq!(relationships.relationships[0].relationship_type, "fears");
        assert_eq!(relationships.relationships[0].trust, -0.8);
        assert_eq!(relationships.relationships[0].affection, -0.9);
        assert_eq!(relationships.relationships[0].metadata.get("reason").unwrap().as_str().unwrap(), "Borga is a dangerous crime lord");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_update_existing_relationship() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, borga_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Create initial relationship
        let initial_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "neutral",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {
                "status": "unknown"
            }
        });

        tool.execute(&initial_params).await.expect("Initial relationship should succeed");

        // Update the relationship
        let update_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "fears",
            "trust": -0.8,
            "affection": -0.9,
            "metadata": {
                "status": "hostile",
                "reason": "Borga threatened Sol's contacts",
                "last_interaction": "2024-03-15"
            }
        });

        let result = tool.execute(&update_params).await.expect("Update relationship should succeed");

        // Verify result shows updated values
        assert_eq!(result.get("relationship").unwrap().get("relationship_type").unwrap().as_str().unwrap(), "fears");
        assert_eq!(result.get("relationship").unwrap().get("trust").unwrap().as_f64().unwrap(), -0.8);

        // Verify only one relationship exists (updated, not duplicated)
        let sol_details = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
        let relationships_component = sol_details.components.iter()
            .find(|c| c.component_type == "Relationships")
            .expect("Sol should have relationships component");

        let relationships: RelationshipsComponent = serde_json::from_value(relationships_component.component_data.clone())
            .expect("Should deserialize relationships");

        assert_eq!(relationships.relationships.len(), 1);
        assert_eq!(relationships.relationships[0].relationship_type, "fears");
        assert_eq!(relationships.relationships[0].trust, -0.8);
        assert_eq!(relationships.relationships[0].metadata.get("status").unwrap().as_str().unwrap(), "hostile");
        assert_eq!(relationships.relationships[0].metadata.get("reason").unwrap().as_str().unwrap(), "Borga threatened Sol's contacts");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_multiple_relationships_same_entity() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, borga_id, jenna_id) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Create relationship with Borga
        let borga_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "fears",
            "trust": -0.8,
            "affection": -0.9,
            "metadata": {}
        });

        tool.execute(&borga_params).await.expect("Borga relationship should succeed");

        // Create relationship with Jenna
        let jenna_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": jenna_id.to_string(),
            "relationship_type": "trusts",
            "trust": 0.7,
            "affection": 0.5,
            "metadata": {
                "alliance": "scientific cooperation"
            }
        });

        tool.execute(&jenna_params).await.expect("Jenna relationship should succeed");

        // Verify both relationships exist
        let sol_details = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
        let relationships_component = sol_details.components.iter()
            .find(|c| c.component_type == "Relationships")
            .expect("Sol should have relationships component");

        let relationships: RelationshipsComponent = serde_json::from_value(relationships_component.component_data.clone())
            .expect("Should deserialize relationships");

        assert_eq!(relationships.relationships.len(), 2);

        // Find relationships by target
        let borga_rel = relationships.relationships.iter()
            .find(|r| r.target_entity_id == borga_id)
            .expect("Should have relationship with Borga");
        let jenna_rel = relationships.relationships.iter()
            .find(|r| r.target_entity_id == jenna_id)
            .expect("Should have relationship with Jenna");

        assert_eq!(borga_rel.relationship_type, "fears");
        assert_eq!(borga_rel.trust, -0.8);
        assert_eq!(jenna_rel.relationship_type, "trusts");
        assert_eq!(jenna_rel.trust, 0.7);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_with_complex_metadata() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, jenna_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": jenna_id.to_string(),
            "relationship_type": "scientific_collaboration",
            "trust": 0.8,
            "affection": 0.3,
            "metadata": {
                "collaboration_type": "genetic research",
                "shared_projects": ["Project Genesis", "Bacta Enhancement"],
                "security_clearance": "level_7",
                "last_contact": "2024-03-15T14:30:00Z",
                "communication_method": "encrypted_holonet",
                "mutual_contacts": 3,
                "financial_dealings": {
                    "total_value": 150000,
                    "currency": "imperial_credits",
                    "payment_status": "completed"
                }
            }
        });

        let result = tool.execute(&params).await.expect("Complex relationship should succeed");

        // Verify complex metadata is preserved
        let metadata = result.get("relationship").unwrap().get("metadata").unwrap();
        assert_eq!(metadata.get("collaboration_type").unwrap().as_str().unwrap(), "genetic research");
        assert_eq!(metadata.get("shared_projects").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(metadata.get("financial_dealings").unwrap().get("total_value").unwrap().as_u64().unwrap(), 150000);

        // Verify in database
        let sol_details = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
        let relationships_component = sol_details.components.iter()
            .find(|c| c.component_type == "Relationships")
            .expect("Sol should have relationships component");

        let relationships: RelationshipsComponent = serde_json::from_value(relationships_component.component_data.clone())
            .expect("Should deserialize relationships");

        let rel = &relationships.relationships[0];
        assert_eq!(rel.metadata.get("collaboration_type").unwrap().as_str().unwrap(), "genetic research");
        assert_eq!(rel.metadata.get("shared_projects").unwrap().as_array().unwrap().len(), 2);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_trust_affection_bounds() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, borga_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Test minimum bounds
        let min_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "despises",
            "trust": -1.0,
            "affection": -1.0,
            "metadata": {}
        });

        let result = tool.execute(&min_params).await.expect("Minimum values should succeed");
        assert_eq!(result.get("relationship").unwrap().get("trust").unwrap().as_f64().unwrap(), -1.0);
        assert_eq!(result.get("relationship").unwrap().get("affection").unwrap().as_f64().unwrap(), -1.0);

        // Test maximum bounds
        let max_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "adores",
            "trust": 1.0,
            "affection": 1.0,
            "metadata": {}
        });

        let result = tool.execute(&max_params).await.expect("Maximum values should succeed");
        assert_eq!(result.get("relationship").unwrap().get("trust").unwrap().as_f64().unwrap(), 1.0);
        assert_eq!(result.get("relationship").unwrap().get("affection").unwrap().as_f64().unwrap(), 1.0);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_with_invalid_trust_values() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, borga_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Test trust value too high
        let high_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "test",
            "trust": 2.0,
            "affection": 0.0,
            "metadata": {}
        });

        let result = tool.execute(&high_params).await;
        assert!(result.is_err(), "Trust value > 1.0 should be rejected");

        // Test trust value too low
        let low_params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": borga_id.to_string(),
            "relationship_type": "test",
            "trust": -2.0,
            "affection": 0.0,
            "metadata": {}
        });

        let result = tool.execute(&low_params).await;
        assert!(result.is_err(), "Trust value < -1.0 should be rejected");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_with_nonexistent_entities() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, _, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let fake_entity_id = Uuid::new_v4();
        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Test with nonexistent source entity
        let params1 = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": fake_entity_id.to_string(),
            "target_entity_id": sol_id.to_string(),
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {}
        });

        let result1 = tool.execute(&params1).await;
        assert!(result1.is_err());

        // Test with nonexistent target entity
        let params2 = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": fake_entity_id.to_string(),
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {}
        });

        let result2 = tool.execute(&params2).await;
        assert!(result2.is_err());
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_self_reference_prevention() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");
        let (sol_id, _, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        // Test relationship with self
        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": sol_id.to_string(),
            "target_entity_id": sol_id.to_string(),
            "relationship_type": "self_reflection",
            "trust": 0.5,
            "affection": 0.5,
            "metadata": {}
        });

        let result = tool.execute(&params).await;
        assert!(result.is_err(), "Self-relationships should be prevented");
        
        if let Err(ToolError::ExecutionFailed(msg)) = result {
            assert!(msg.contains("self") || msg.contains("same"));
        } else {
            panic!("Expected self-relationship error");
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_relationship_missing_component_handling() {
        let app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("Valid test UUID");

        // Create entity without Relationships component
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let entity_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Basic Entity",
            "archetype_signature": "Name",
            "salience_tier": "Flavor",
            "components": {
                "Name": {"name": "Basic Entity", "display_name": "Basic", "aliases": []}
            }
        });
        let entity_result = create_tool.execute(&entity_params).await.expect("Entity creation failed");
        let entity_id = Uuid::parse_str(entity_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        let (_, target_id, _) = create_test_entities(entity_manager.clone(), user_id).await;

        let tool = UpdateRelationshipTool::new(entity_manager.clone());

        let params = json!({
            "user_id": user_id.to_string(),
            "source_entity_id": entity_id.to_string(),
            "target_entity_id": target_id.to_string(),
            "relationship_type": "test",
            "trust": 0.0,
            "affection": 0.0,
            "metadata": {}
        });

        let result = tool.execute(&params).await;
        assert!(result.is_err(), "Should fail when source entity lacks Relationships component");
    }
}