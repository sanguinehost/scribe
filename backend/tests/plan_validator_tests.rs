use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService,
            types::*,
        },
        EcsEntityManager,
    },
    models::ecs::{
        SalienceTier,
    },
    test_helpers::{spawn_app, TestDataGuard},
    PgPool,
};
use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;

/// Helper to create test entity manager
async fn create_test_entity_manager(db_pool: PgPool) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    Arc::new(EcsEntityManager::new(
        db_pool.into(),
        redis_client,
        None,
    ))
}

/// Helper to create test entities with a test user
async fn create_test_entities(
    entity_manager: &Arc<EcsEntityManager>,
    db_pool: &PgPool,
) -> Result<(Uuid, Uuid, Uuid, Uuid, Uuid), Box<dyn std::error::Error>> {
    // Create test user first
    let test_user = scribe_backend::test_helpers::db::create_test_user(
        db_pool,
        "plan_validator_test_user".to_string(),
        "password123".to_string(),
    ).await?;
    let user_id = test_user.id;
    // Create Sol (player character)
    let sol_id = Uuid::new_v4();
    let sol_components = vec![
        ("Name".to_string(), json!({
            "name": "Sol",
            "display_name": "Sol",
            "aliases": []
        })),
        ("Inventory".to_string(), json!({
            "items": [],
            "capacity": 10
        })),
        ("Relationships".to_string(), json!({
            "relationships": []
        })),
        ("Salience".to_string(), json!({
            "tier": "Core"
        }))
    ];
    
    entity_manager.create_entity(
        user_id,
        Some(sol_id),
        "Name|Inventory|Relationships|Salience".to_string(),
        sol_components,
    ).await.unwrap();
    
    // Create Cantina (location)
    let cantina_id = Uuid::new_v4();
    let cantina_components = vec![
        ("Name".to_string(), json!({
            "name": "Cantina",
            "display_name": "Cantina",
            "aliases": ["Mos Eisley Cantina"]
        })),
        ("Salience".to_string(), json!({
            "tier": "Secondary"
        }))
    ];
    
    entity_manager.create_entity(
        user_id,
        Some(cantina_id),
        "Name|Salience".to_string(),
        cantina_components,
    ).await.unwrap();
    
    // Create Borga (NPC)
    let borga_id = Uuid::new_v4();
    let borga_components = vec![
        ("Name".to_string(), json!({
            "name": "Borga",
            "display_name": "Borga the Trader",
            "aliases": []
        })),
        ("Inventory".to_string(), json!({
            "items": [],
            "capacity": 20
        })),
        ("Salience".to_string(), json!({
            "tier": "Secondary"
        })),
        ("ParentLink".to_string(), json!({
            "parent_entity_id": cantina_id,
            "depth_from_root": 1,
            "spatial_relationship": "contained_within"
        }))
    ];
    
    entity_manager.create_entity(
        user_id,
        Some(borga_id),
        "Name|Inventory|Salience|ParentLink".to_string(),
        borga_components,
    ).await.unwrap();
    
    // Create datapad (item)
    let datapad_id = Uuid::new_v4();
    let datapad_components = vec![
        ("Name".to_string(), json!({
            "name": "Datapad",
            "display_name": "Encrypted Datapad",
            "aliases": []
        })),
        ("Salience".to_string(), json!({
            "tier": "Flavor"
        }))
    ];
    
    entity_manager.create_entity(
        user_id,
        Some(datapad_id),
        "Name|Salience".to_string(),
        datapad_components,
    ).await.unwrap();
    
    // Add datapad to Borga's inventory
    entity_manager.add_item_to_inventory(
        user_id,
        borga_id,
        datapad_id,
        1,
        None, // Let the system choose the slot
    ).await.unwrap();
    
    Ok((sol_id, cantina_id, borga_id, datapad_id, user_id))
}

#[tokio::test]
async fn test_valid_plan_simple_movement() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, cantina_id, _, _, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    // Debug: Print entity IDs
    println!("Created Sol entity with ID: {}", sol_id);
    println!("Created Cantina entity with ID: {}", cantina_id);
    println!("Using user ID: {}", user_id);
    
    // Verify entities exist before validation
    match entity_manager.get_entity(sol_id, user_id).await {
        Ok(Some(entity)) => println!("Found Sol entity: {:?}", entity.entity.id),
        Ok(None) => println!("Sol entity not found!"),
        Err(e) => println!("Error getting Sol entity: {}", e),
    }
    
    match entity_manager.get_entity(cantina_id, user_id).await {
        Ok(Some(entity)) => println!("Found Cantina entity: {:?}", entity.entity.id),
        Ok(None) => println!("Cantina entity not found!"),
        Err(e) => println!("Error getting Cantina entity: {}", e),
    }
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager.clone(), redis_client);
    
    // Create a simple movement plan
    let plan = Plan {
        goal: "Sol goes to the cantina".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({
                    "entity_to_move": sol_id.to_string(),
                    "new_parent": cantina_id.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(sol_id.to_string()),
                            entity_name: None,
                        },
                        EntityExistenceCheck {
                            entity_id: Some(cantina_id.to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    entity_moved: Some(EntityMovedEffect {
                        entity_id: sol_id.to_string(),
                        new_location: cantina_id.to_string(),
                    }),
                    ..Default::default()
                },
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(validated) => {
            assert_eq!(validated.original_plan.goal, "Sol goes to the cantina");
            assert_eq!(validated.original_plan.actions.len(), 1);
        }
        PlanValidationResult::Invalid(invalid) => {
            panic!("Expected valid plan, got failures: {:?}", invalid.failures);
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_entity_not_found() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let test_user = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        "plan_validator_test_user2".to_string(),
        "password123".to_string(),
    ).await.unwrap();
    let user_id = test_user.id;
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    let fake_id = Uuid::new_v4();
    
    // Create a plan with non-existent entity
    let plan = Plan {
        goal: "NonExistent goes somewhere".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({
                    "entity_to_move": fake_id.to_string(),
                    "new_parent": fake_id.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(fake_id.to_string()),
                            entity_name: Some("NonExistent".to_string()),
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.5,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to non-existent entity");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert_eq!(invalid.failures.len(), 1);
            assert_eq!(invalid.failures[0].failure_type, ValidationFailureType::EntityNotFound);
            assert!(invalid.failures[0].message.contains("Entity not found"));
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_location_precondition_not_met() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, cantina_id, borga_id, datapad_id, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan that requires Sol to be at the cantina (but Sol is not there)
    let plan = Plan {
        goal: "Sol takes datapad from Borga".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::RemoveItemFromInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": borga_id.to_string(),
                    "item_entity_id": datapad_id.to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: sol_id.to_string(),
                            location_id: cantina_id.to_string(),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(30),
            confidence: 0.7,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to location precondition");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert_eq!(invalid.failures.len(), 1);
            assert_eq!(invalid.failures[0].failure_type, ValidationFailureType::PreconditionNotMet);
            assert!(invalid.failures[0].message.contains("not at location") || 
                    invalid.failures[0].message.contains("has no location"));
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_missing_component() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let test_user = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        "plan_validator_test_user3".to_string(),
        "password123".to_string(),
    ).await.unwrap();
    let user_id = test_user.id;
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    
    // Create entity without inventory component
    let no_inventory_id = Uuid::new_v4();
    let no_inventory_components = vec![
        ("Name".to_string(), json!({
            "name": "NoInventory",
            "display_name": "NoInventory",
            "aliases": []
        })),
        ("Salience".to_string(), json!({
            "tier": "Secondary"
        }))
    ];
    
    entity_manager.create_entity(
        user_id,
        Some(no_inventory_id),
        "Name|Salience".to_string(),
        no_inventory_components,
    ).await.unwrap();
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan that requires inventory component
    let plan = Plan {
        goal: "Add item to entity without inventory".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": no_inventory_id.to_string(),
                    "item_entity_id": Uuid::new_v4().to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    entity_has_component: Some(vec![
                        EntityComponentCheck {
                            entity_id: no_inventory_id.to_string(),
                            component_type: "Inventory".to_string(),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(10),
            confidence: 0.8,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to missing component");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert_eq!(invalid.failures.len(), 1);
            assert_eq!(invalid.failures[0].failure_type, ValidationFailureType::PreconditionNotMet);
            assert!(invalid.failures[0].message.contains("missing component"));
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_insufficient_inventory_space() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _, _, datapad_id, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    // Fill Sol's inventory
    for i in 0..10 {
        let item_id = Uuid::new_v4();
        let item_components = vec![
            ("Name".to_string(), json!({
                "name": format!("Item{}", i),
                "display_name": format!("Item{}", i),
                "aliases": []
            })),
            ("Salience".to_string(), json!({
                "tier": "Flavor"
            }))
        ];
        
        entity_manager.create_entity(
            user_id,
            Some(item_id),
            "Name|Salience".to_string(),
            item_components,
        ).await.unwrap();
        
        entity_manager.add_item_to_inventory(user_id, sol_id, item_id, 1, None).await.unwrap();
    }
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan that requires inventory space
    let plan = Plan {
        goal: "Sol picks up datapad".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": sol_id.to_string(),
                    "item_entity_id": datapad_id.to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    inventory_has_space: Some(InventorySpaceCheck {
                        entity_id: sol_id.to_string(),
                        required_slots: 1,
                    }),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(5),
            confidence: 0.95,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to insufficient inventory space");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert_eq!(invalid.failures.len(), 1);
            assert_eq!(invalid.failures[0].failure_type, ValidationFailureType::PreconditionNotMet);
            assert!(invalid.failures[0].message.to_lowercase().contains("insufficient inventory space"));
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_relationship_trust_too_low() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _, borga_id, datapad_id, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    // Create low trust relationship
    entity_manager.update_relationship(
        user_id,
        sol_id,
        borga_id,
        "knows".to_string(),
        0.1, // Low trust
        0.0, // No affection
        std::collections::HashMap::from([
            ("description".to_string(), json!("Just met"))
        ]),
    ).await.unwrap();
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan that requires higher trust
    let plan = Plan {
        goal: "Sol asks Borga for the datapad".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::RemoveItemFromInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": borga_id.to_string(),
                    "item_entity_id": datapad_id.to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    relationship_exists: Some(vec![
                        RelationshipCheck {
                            source_entity: sol_id.to_string(),
                            target_entity: borga_id.to_string(),
                            min_trust: Some(0.5), // Requires higher trust
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(30),
            confidence: 0.6,
            alternative_considered: Some("Sol could try to improve relationship first".to_string()),
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to insufficient trust");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert_eq!(invalid.failures.len(), 1);
            assert_eq!(invalid.failures[0].failure_type, ValidationFailureType::PreconditionNotMet);
            assert!(invalid.failures[0].message.to_lowercase().contains("insufficient trust"));
        }
    }
}

#[tokio::test]
async fn test_valid_plan_complex_multi_step() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, cantina_id, borga_id, datapad_id, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    // Create sufficient trust relationship
    entity_manager.update_relationship(
        user_id,
        sol_id,
        borga_id,
        "knows".to_string(),
        0.6, // Good trust
        0.3, // Some affection
        std::collections::HashMap::from([
            ("description".to_string(), json!("Trading partners"))
        ]),
    ).await.unwrap();
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager.clone(), redis_client);
    
    // Create a complex multi-step plan
    let plan = Plan {
        goal: "Sol gets the datapad from Borga".to_string(),
        actions: vec![
            // Step 1: Move Sol to cantina
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({
                    "entity_to_move": sol_id.to_string(),
                    "new_parent": cantina_id.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(sol_id.to_string()),
                            entity_name: None,
                        },
                        EntityExistenceCheck {
                            entity_id: Some(cantina_id.to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    entity_moved: Some(EntityMovedEffect {
                        entity_id: sol_id.to_string(),
                        new_location: cantina_id.to_string(),
                    }),
                    ..Default::default()
                },
                dependencies: vec![],
            },
            // Step 2: Remove datapad from Borga
            PlannedAction {
                id: "step2".to_string(),
                name: ActionName::RemoveItemFromInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": borga_id.to_string(),
                    "item_entity_id": datapad_id.to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: sol_id.to_string(),
                            location_id: cantina_id.to_string(),
                        }
                    ]),
                    relationship_exists: Some(vec![
                        RelationshipCheck {
                            source_entity: sol_id.to_string(),
                            target_entity: borga_id.to_string(),
                            min_trust: Some(0.5),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    inventory_changed: Some(InventoryChangeEffect {
                        entity_id: borga_id.to_string(),
                        item_id: datapad_id.to_string(),
                        quantity_change: -1,
                    }),
                    ..Default::default()
                },
                dependencies: vec!["step1".to_string()],
            },
            // Step 3: Add datapad to Sol
            PlannedAction {
                id: "step3".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": sol_id.to_string(),
                    "item_entity_id": datapad_id.to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    inventory_has_space: Some(InventorySpaceCheck {
                        entity_id: sol_id.to_string(),
                        required_slots: 1,
                    }),
                    ..Default::default()
                },
                effects: Effects {
                    inventory_changed: Some(InventoryChangeEffect {
                        entity_id: sol_id.to_string(),
                        item_id: datapad_id.to_string(),
                        quantity_change: 1,
                    }),
                    ..Default::default()
                },
                dependencies: vec!["step2".to_string()],
            },
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(300),
            confidence: 0.85,
            alternative_considered: Some("Sol could try to steal the datapad".to_string()),
        },
    };
    
    // First move Sol to cantina to satisfy location precondition
    // Update Sol's parent link component
    use scribe_backend::services::ecs_entity_manager::{ComponentUpdate, ComponentOperation};
    entity_manager.update_components(
        user_id,
        sol_id,
        vec![
            ComponentUpdate {
                entity_id: sol_id,
                component_type: "ParentLink".to_string(),
                component_data: json!({
                    "parent_entity_id": cantina_id,
                    "depth_from_root": 1,
                    "spatial_relationship": "contained_within"
                }),
                operation: ComponentOperation::Update,
            }
        ]
    ).await.unwrap();
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(validated) => {
            assert_eq!(validated.original_plan.goal, "Sol gets the datapad from Borga");
            assert_eq!(validated.original_plan.actions.len(), 3);
            // All preconditions should be met
        }
        PlanValidationResult::Invalid(invalid) => {
            panic!("Expected valid plan, got failures: {:?}", invalid.failures);
        }
    }
}

#[tokio::test]
async fn test_invalid_plan_circular_dependencies() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let test_user = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        "plan_validator_test_user4".to_string(),
        "password123".to_string(),
    ).await.unwrap();
    let user_id = test_user.id;
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan with circular dependencies
    let plan = Plan {
        goal: "Impossible circular plan".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::FindEntity,
                parameters: serde_json::json!({}),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec!["step2".to_string()], // Depends on step2
            },
            PlannedAction {
                id: "step2".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: serde_json::json!({}),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec!["step1".to_string()], // Depends on step1 - circular!
            },
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.1,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to circular dependencies");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert!(!invalid.failures.is_empty());
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::InvalidDependency
            ));
        }
    }
}

#[tokio::test]
async fn test_plan_validation_caching() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, cantina_id, _, _, user_id) = create_test_entities(&entity_manager, &test_app.db_pool).await.unwrap();
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client.clone());
    
    // Create a simple plan
    let plan = Plan {
        goal: "Sol goes to the cantina".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({
                    "entity_to_move": sol_id.to_string(),
                    "new_parent": cantina_id.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(sol_id.to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    // First validation
    let result1 = validator.validate_plan(&plan, user_id).await.unwrap();
    let cache_key = match &result1 {
        PlanValidationResult::Valid(v) => v.cache_key.clone(),
        _ => panic!("Expected valid plan"),
    };
    
    // Check if result was cached
    use redis::AsyncCommands;
    let mut conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let cached: Option<String> = conn.get(&cache_key).await.unwrap();
    assert!(cached.is_some(), "Validation result should be cached");
    
    // Second validation should use cache
    let result2 = validator.validate_plan(&plan, user_id).await.unwrap();
    match (result1, result2) {
        (PlanValidationResult::Valid(v1), PlanValidationResult::Valid(v2)) => {
            assert_eq!(v1.cache_key, v2.cache_key);
        }
        _ => panic!("Both validations should be valid"),
    }
}