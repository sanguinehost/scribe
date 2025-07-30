// Hierarchy Tools Functional Tests
//
// Comprehensive functional test suite for hierarchy promotion tools
// This test suite validates the core functionality of the hierarchy management system
// including successful promotion scenarios, edge cases, and integration with the ECS
//
// TODO: This test file was written for PromoteEntityHierarchyTool which no longer exists.
// It has been updated to use SuggestHierarchyPromotionTool, but this is an AI-powered
// suggestion tool, not a direct promotion tool. The tests need to be completely rewritten
// to match the new tool's behavior (suggesting promotions vs actually promoting).
// Temporarily disabled until migration is complete.

/*

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, TemporalComponent,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{ScribeTool, ToolError},
        agentic::tools::hierarchy_tools::GetEntityHierarchyTool,
        agentic::tools::ai_powered_tools::SuggestHierarchyPromotionTool,
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    errors::AppError,
    PgPool,
};
use serde_json::{json, Value as JsonValue};
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
mod hierarchy_tools_functional_tests {
    use super::*;

    /// Helper function to create a test entity with proper components
    async fn create_test_entity(
        entity_manager: &Arc<EcsEntityManager>,
        user_id: Uuid,
        name: &str,
        scale: SpatialScale,
        hierarchical_level: u32,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, AppError> {
        let entity_id = Uuid::new_v4();
        
        let level_name = scale.level_name(hierarchical_level)
            .ok_or_else(|| AppError::InternalServerErrorGeneric(format!("Invalid level {} for scale {:?}", hierarchical_level, scale)))?;

        let spatial_archetype = SpatialArchetypeComponent::new(
            scale,
            hierarchical_level,
            level_name.to_string(),
        ).map_err(|e| AppError::InternalServerErrorGeneric(e))?;

        let name_component = NameComponent {
            name: name.to_string(),
            display_name: name.to_string(),
            aliases: Vec::new(),
        };

        let temporal_component = TemporalComponent::default();

        let mut components = vec![
            ("SpatialArchetype".to_string(), serde_json::to_value(spatial_archetype)?),
            ("Name".to_string(), serde_json::to_value(name_component)?),
            ("Temporal".to_string(), serde_json::to_value(temporal_component)?),
        ];

        if let Some(parent) = parent_id {
            let parent_link = ParentLinkComponent {
                parent_entity_id: parent,
                depth_from_root: 1,
                spatial_relationship: "contained_within".to_string(),
            };
            components.push(("ParentLink".to_string(), serde_json::to_value(parent_link)?));
        }

        entity_manager.create_entity(
            user_id,
            Some(entity_id),
            "Test Entity".to_string(),
            components,
        ).await?;

        Ok(entity_id)
    }

    /// Helper to verify entity exists and has expected properties
    async fn verify_entity_properties(
        entity_manager: &Arc<EcsEntityManager>,
        user_id: Uuid,
        entity_id: Uuid,
        expected_name: &str,
    ) -> Result<(), AppError> {
        let entity = entity_manager.get_entity(user_id, entity_id).await?;
        
        let entity = entity.ok_or_else(|| AppError::InternalServerErrorGeneric("Entity not found".to_string()))?;
        
        // Find the name component
        let name_component = entity.components.iter()
            .find(|c| c.component_type == "Name")
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Name component not found".to_string()))?;

        let name_data: NameComponent = serde_json::from_value(name_component.component_data.clone())?;
        assert_eq!(name_data.name, expected_name, "Entity name should match expected value");

        Ok(())
    }

    // =============================================================================
    // BASIC FUNCTIONALITY TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_promote_hierarchy_basic_success() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Create a planet entity
        let planet_id = create_test_entity(
            &entity_manager,
            user_id,
            "Tatooine",
            SpatialScale::Planetary,
            0, // Root level
            None,
        ).await.expect("Failed to create planet entity");

        let promote_tool = SuggestHierarchyPromotionTool::new(entity_manager.clone());

        // Promote the planet to have a solar system parent
        let params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
            "new_parent_name": "Tatooine System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "orbits"
        });

        let result = promote_tool.execute(&params).await;
        assert!(result.is_ok(), "Basic hierarchy promotion should succeed");

        let output: JsonValue = result.unwrap();
        
        // Verify the output structure
        assert!(output.get("new_parent_id").is_some(), "Should return new parent ID");
        assert!(output.get("new_parent_name").is_some(), "Should return new parent name");
        assert!(output.get("promoted_entity_id").is_some(), "Should return promoted entity ID");
        assert!(output.get("hierarchy_path").is_some(), "Should return hierarchy path");

        let new_parent_id_str = output.get("new_parent_id").unwrap().as_str().unwrap();
        let new_parent_id = Uuid::parse_str(new_parent_id_str).expect("Should be valid UUID");

        // Verify the new parent entity was created
        verify_entity_properties(&entity_manager, user_id, new_parent_id, "Tatooine System").await
            .expect("New parent entity should exist");

        // Verify the original entity now has the new parent
        let planet_entity = entity_manager.get_entity(user_id, planet_id).await
            .expect("Should be able to get planet entity")
            .expect("Planet entity should exist");

        let parent_link = planet_entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .expect("Planet should have ParentLink component");

        let parent_link_data: ParentLinkComponent = serde_json::from_value(parent_link.component_data.clone())
            .expect("Should be able to deserialize ParentLink");

        assert_eq!(parent_link_data.parent_entity_id, new_parent_id, "Planet should point to new parent");
        assert_eq!(parent_link_data.spatial_relationship, "orbits", "Relationship type should match");
    }

    #[tokio::test]
    async fn test_promote_hierarchy_with_relative_position() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Create a reference entity and a target entity
        let reference_id = create_test_entity(
            &entity_manager,
            user_id,
            "Galactic Core",
            SpatialScale::Cosmic,
            0,
            None,
        ).await.expect("Failed to create reference entity");

        let planet_id = create_test_entity(
            &entity_manager,
            user_id,
            "Alderaan",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create planet entity");

        let promote_tool = SuggestHierarchyPromotionTool::new(entity_manager.clone());

        // Promote the planet with relative positioning
        let params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
            "new_parent_name": "Alderaan System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "relative",
                "coordinates": {"x": 100.0, "y": 50.0, "z": 25.0},
                "relative_to_entity": reference_id.to_string()
            },
            "relationship_type": "orbits"
        });

        let result = promote_tool.execute(&params).await;
        assert!(result.is_ok(), "Relative position hierarchy promotion should succeed");

        let output: JsonValue = result.unwrap();
        let new_parent_id_str = output.get("new_parent_id").unwrap().as_str().unwrap();
        let new_parent_id = Uuid::parse_str(new_parent_id_str).expect("Should be valid UUID");

        // Verify the new parent entity was created with relative positioning
        verify_entity_properties(&entity_manager, user_id, new_parent_id, "Alderaan System").await
            .expect("New parent entity should exist");
    }

    #[tokio::test]
    async fn test_get_hierarchy_basic_functionality() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Create a simple hierarchy: Galaxy -> System -> Planet
        let galaxy_id = create_test_entity(
            &entity_manager,
            user_id,
            "Milky Way",
            SpatialScale::Cosmic,
            0,
            None,
        ).await.expect("Failed to create galaxy");

        let system_id = create_test_entity(
            &entity_manager,
            user_id,
            "Sol System",
            SpatialScale::Cosmic,
            1,
            Some(galaxy_id),
        ).await.expect("Failed to create system");

        let planet_id = create_test_entity(
            &entity_manager,
            user_id,
            "Earth",
            SpatialScale::Planetary,
            0,
            Some(system_id),
        ).await.expect("Failed to create planet");

        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());

        // Get hierarchy for the planet
        let params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
        });

        let result = get_tool.execute(&params).await;
        assert!(result.is_ok(), "Get hierarchy should succeed");

        let output: JsonValue = result.unwrap();
        
        // Verify output structure
        assert!(output.get("entity_id").is_some(), "Should return entity ID");
        assert!(output.get("hierarchy_path").is_some(), "Should return hierarchy path");
        assert!(output.get("total_depth").is_some(), "Should return total depth");
        assert!(output.get("root_entity").is_some(), "Should return root entity");

        let hierarchy_path = output.get("hierarchy_path").unwrap().as_array().unwrap();
        assert_eq!(hierarchy_path.len(), 3, "Should have 3 levels in hierarchy");

        // Verify hierarchy order (root to leaf)
        let level_names: Vec<String> = hierarchy_path.iter()
            .map(|level| level.get("name").unwrap().as_str().unwrap().to_string())
            .collect();

        assert_eq!(level_names, vec!["Milky Way", "Sol System", "Earth"], "Hierarchy should be in correct order");

        let total_depth = output.get("total_depth").unwrap().as_u64().unwrap();
        assert_eq!(total_depth, 3, "Total depth should be 3");
    }

    // =============================================================================
    // COMPLEX SCENARIO TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_star_wars_interplanetary_travel_scenario() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Start with Tatooine as a standalone planet
        let tatooine_id = create_test_entity(
            &entity_manager,
            user_id,
            "Tatooine",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create Tatooine");

        let promote_tool = SuggestHierarchyPromotionTool::new(entity_manager.clone());

        // Player travels to another planet - need to create Tatooine System
        let tatooine_system_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": tatooine_id.to_string(),
            "new_parent_name": "Tatooine System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": -50000.0, "y": 25000.0, "z": -10000.0}
            },
            "relationship_type": "orbits"
        });

        let tatooine_system_result = promote_tool.execute(&tatooine_system_params).await;
        assert!(tatooine_system_result.is_ok(), "Tatooine system creation should succeed");

        let tatooine_system_output: JsonValue = tatooine_system_result.unwrap();
        let tatooine_system_id_str = tatooine_system_output.get("new_parent_id").unwrap().as_str().unwrap();
        let tatooine_system_id = Uuid::parse_str(tatooine_system_id_str).expect("Should be valid UUID");

        // Now create Coruscant as another standalone planet
        let coruscant_id = create_test_entity(
            &entity_manager,
            user_id,
            "Coruscant",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create Coruscant");

        // Player travels between systems - need to create Coruscant System and a Galaxy
        let coruscant_system_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": coruscant_id.to_string(),
            "new_parent_name": "Coruscant System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "orbits"
        });

        let coruscant_system_result = promote_tool.execute(&coruscant_system_params).await;
        assert!(coruscant_system_result.is_ok(), "Coruscant system creation should succeed");

        let coruscant_system_output: JsonValue = coruscant_system_result.unwrap();
        let coruscant_system_id_str = coruscant_system_output.get("new_parent_id").unwrap().as_str().unwrap();
        let coruscant_system_id = Uuid::parse_str(coruscant_system_id_str).expect("Should be valid UUID");

        // Now create a galaxy to contain both systems
        let galaxy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": tatooine_system_id.to_string(),
            "new_parent_name": "Galaxy Far Far Away",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let galaxy_result = promote_tool.execute(&galaxy_params).await;
        assert!(galaxy_result.is_ok(), "Galaxy creation should succeed");

        let galaxy_output: JsonValue = galaxy_result.unwrap();
        let galaxy_id_str = galaxy_output.get("new_parent_id").unwrap().as_str().unwrap();
        let _galaxy_id = Uuid::parse_str(galaxy_id_str).expect("Should be valid UUID");

        // Add Coruscant System to the same galaxy
        let coruscant_to_galaxy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": coruscant_system_id.to_string(),
            "new_parent_name": "Galaxy Far Far Away Duplicate Check",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        // This might create a duplicate galaxy or handle it gracefully
        let _coruscant_to_galaxy_result = promote_tool.execute(&coruscant_to_galaxy_params).await;
        // We don't assert success here since this is testing edge case behavior

        // Verify the final hierarchy structure
        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());

        // Check Tatooine hierarchy
        let tatooine_hierarchy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": tatooine_id.to_string(),
        });

        let tatooine_hierarchy_result = get_tool.execute(&tatooine_hierarchy_params).await;
        assert!(tatooine_hierarchy_result.is_ok(), "Should be able to get Tatooine hierarchy");

        let tatooine_hierarchy: JsonValue = tatooine_hierarchy_result.unwrap();
        let tatooine_path = tatooine_hierarchy.get("hierarchy_path").unwrap().as_array().unwrap();
        
        // Should have at least Galaxy -> System -> Planet
        assert!(tatooine_path.len() >= 3, "Tatooine should have multi-level hierarchy");

        // Check Coruscant hierarchy
        let coruscant_hierarchy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": coruscant_id.to_string(),
        });

        let coruscant_hierarchy_result = get_tool.execute(&coruscant_hierarchy_params).await;
        assert!(coruscant_hierarchy_result.is_ok(), "Should be able to get Coruscant hierarchy");

        let coruscant_hierarchy: JsonValue = coruscant_hierarchy_result.unwrap();
        let coruscant_path = coruscant_hierarchy.get("hierarchy_path").unwrap().as_array().unwrap();
        
        // Should have at least System -> Planet (might have Galaxy if promotion succeeded)
        assert!(coruscant_path.len() >= 2, "Coruscant should have multi-level hierarchy");
    }

    #[tokio::test]
    async fn test_office_worker_to_cosmic_god_transition() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Start with an intimate-scale scenario - office worker
        let office_building_id = create_test_entity(
            &entity_manager,
            user_id,
            "Corporate Tower",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create office building");

        let office_id = create_test_entity(
            &entity_manager,
            user_id,
            "Conference Room",
            SpatialScale::Intimate,
            1,
            Some(office_building_id),
        ).await.expect("Failed to create office");

        let promote_tool = SuggestHierarchyPromotionTool::new(entity_manager.clone());

        // Character suddenly gains cosmic powers - need to scale up the context
        // First, promote office building to be in a city
        let city_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": office_building_id.to_string(),
            "new_parent_name": "New York City",
            "new_parent_scale": "Planetary",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 40.7128, "y": -74.0060, "z": 0.0}
            },
            "relationship_type": "located_in"
        });

        let city_result = promote_tool.execute(&city_params).await;
        assert!(city_result.is_ok(), "City creation should succeed");

        let city_output: JsonValue = city_result.unwrap();
        let city_id_str = city_output.get("new_parent_id").unwrap().as_str().unwrap();
        let city_id = Uuid::parse_str(city_id_str).expect("Should be valid UUID");

        // Then promote city to be on a planet
        let planet_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": city_id.to_string(),
            "new_parent_name": "Earth",
            "new_parent_scale": "Planetary",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "on_surface_of"
        });

        let planet_result = promote_tool.execute(&planet_params).await;
        assert!(planet_result.is_ok(), "Planet creation should succeed");

        let planet_output: JsonValue = planet_result.unwrap();
        let planet_id_str = planet_output.get("new_parent_id").unwrap().as_str().unwrap();
        let planet_id = Uuid::parse_str(planet_id_str).expect("Should be valid UUID");

        // Finally, promote planet to cosmic scale
        let cosmic_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
            "new_parent_name": "Sol System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "orbits"
        });

        let cosmic_result = promote_tool.execute(&cosmic_params).await;
        assert!(cosmic_result.is_ok(), "Cosmic scale promotion should succeed");

        // Verify the final hierarchy - should span from cosmic to intimate
        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());
        let office_hierarchy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": office_id.to_string(),
        });

        let office_hierarchy_result = get_tool.execute(&office_hierarchy_params).await;
        assert!(office_hierarchy_result.is_ok(), "Should be able to get office hierarchy");

        let office_hierarchy: JsonValue = office_hierarchy_result.unwrap();
        let office_path = office_hierarchy.get("hierarchy_path").unwrap().as_array().unwrap();
        
        // Should have multiple levels spanning different scales
        assert!(office_path.len() >= 5, "Should have deep hierarchy spanning multiple scales");

        // Verify we can find entities at cosmic scale now
        let building_hierarchy_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": office_building_id.to_string(),
        });

        let building_hierarchy_result = get_tool.execute(&building_hierarchy_params).await;
        assert!(building_hierarchy_result.is_ok(), "Should be able to get building hierarchy");

        let building_hierarchy: JsonValue = building_hierarchy_result.unwrap();
        let building_path = building_hierarchy.get("hierarchy_path").unwrap().as_array().unwrap();
        
        assert!(building_path.len() >= 4, "Building should be part of cosmic hierarchy");
    }

    // =============================================================================
    // EDGE CASE TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_promote_already_promoted_entity() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let planet_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create planet");

        let promote_tool = SuggestHierarchyPromotionTool::new(entity_manager.clone());

        // First promotion
        let first_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
            "new_parent_name": "First System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "orbits"
        });

        let first_result = promote_tool.execute(&first_params).await;
        assert!(first_result.is_ok(), "First promotion should succeed");

        let first_output: JsonValue = first_result.unwrap();
        let first_parent_id_str = first_output.get("new_parent_id").unwrap().as_str().unwrap();
        let first_parent_id = Uuid::parse_str(first_parent_id_str).expect("Should be valid UUID");

        // Second promotion - promote the same entity again
        let second_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": planet_id.to_string(),
            "new_parent_name": "Second System",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 100.0, "y": 100.0, "z": 100.0}
            },
            "relationship_type": "orbits"
        });

        let second_result = promote_tool.execute(&second_params).await;
        assert!(second_result.is_ok(), "Second promotion should succeed");

        let second_output: JsonValue = second_result.unwrap();
        let second_parent_id_str = second_output.get("new_parent_id").unwrap().as_str().unwrap();
        let second_parent_id = Uuid::parse_str(second_parent_id_str).expect("Should be valid UUID");

        // Verify that both parents exist and are different
        assert_ne!(first_parent_id, second_parent_id, "Should create different parent entities");

        verify_entity_properties(&entity_manager, user_id, first_parent_id, "First System").await
            .expect("First parent should exist");
        verify_entity_properties(&entity_manager, user_id, second_parent_id, "Second System").await
            .expect("Second parent should exist");

        // Verify the planet now points to the second parent
        let planet_entity = entity_manager.get_entity(user_id, planet_id).await
            .expect("Should be able to get planet")
            .expect("Planet entity should exist");

        let parent_link = planet_entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .expect("Planet should have ParentLink component");

        let parent_link_data: ParentLinkComponent = serde_json::from_value(parent_link.component_data.clone())
            .expect("Should deserialize ParentLink");

        assert_eq!(parent_link_data.parent_entity_id, second_parent_id, "Planet should point to second parent");
    }

    #[tokio::test]
    async fn test_get_hierarchy_for_root_entity() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        // Create a root entity (no parent)
        let root_id = create_test_entity(
            &entity_manager,
            user_id,
            "Universe",
            SpatialScale::Cosmic,
            0,
            None,
        ).await.expect("Failed to create root entity");

        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user_id.to_string(),
            "entity_id": root_id.to_string(),
        });

        let result = get_tool.execute(&params).await;
        assert!(result.is_ok(), "Should be able to get hierarchy for root entity");

        let output: JsonValue = result.unwrap();
        let hierarchy_path = output.get("hierarchy_path").unwrap().as_array().unwrap();
        
        assert_eq!(hierarchy_path.len(), 1, "Root entity should have hierarchy of length 1");
        
        let root_entry = &hierarchy_path[0];
        assert_eq!(
            root_entry.get("name").unwrap().as_str().unwrap(),
            "Universe",
            "Root entry should be the entity itself"
        );

        let total_depth = output.get("total_depth").unwrap().as_u64().unwrap();
        assert_eq!(total_depth, 1, "Total depth should be 1 for root entity");
    }

    #[tokio::test]
    async fn test_get_hierarchy_for_nonexistent_entity() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        let nonexistent_id = Uuid::new_v4();

        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user_id.to_string(),
            "entity_id": nonexistent_id.to_string(),
        });

        let result = get_tool.execute(&params).await;
        assert!(result.is_err(), "Should fail for nonexistent entity");

        match result.unwrap_err() {
            ToolError::ExecutionFailed(msg) => {
                assert!(msg.contains("Entity not found"), "Should indicate entity not found");
            }
            ToolError::AppError(_) => {
                // Also acceptable - database/app-level error for nonexistent entity
            }
            other => panic!("Expected ExecutionFailed or AppError for nonexistent entity, got: {:?}", other),
        }
    }
}*/
