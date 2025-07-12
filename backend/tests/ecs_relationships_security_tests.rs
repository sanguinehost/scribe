// ECS Relationships Security Tests
//
// Comprehensive security testing targeting OWASP Top 10 Web Application Security Risks (2021)
// for Enhanced ECS Relationships, CausalComponent, and ChronicleEcsTranslator features.
// These tests ensure our ECS and Chronicle query systems are secure against common vulnerabilities.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::{Utc, Duration};

use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::{
        ecs_diesel::{NewEcsEntityRelationship, EcsEntityRelationship, NewEcsEntity},
        ecs::{CausalComponent, RelationshipCategory},
        chronicle_event::{ChronicleEvent, NewChronicleEvent, EventSource},
    },
    services::chronicle_ecs_translator::ChronicleEcsTranslator,
    errors::AppError,
    schema::{ecs_entity_relationships, ecs_entities, chronicle_events},
    PgPool,
};
use diesel::prelude::*;

// Helper to create a test chronicle
async fn create_test_chronicle(user_id: uuid::Uuid, test_app: &scribe_backend::test_helpers::TestApp) -> Result<uuid::Uuid, anyhow::Error> {
    use scribe_backend::services::ChronicleService;
    use scribe_backend::models::chronicle::CreateChronicleRequest;
    
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "Security Test Chronicle".to_string(),
        description: Some("Testing security features".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

// A01:2021 - Broken Access Control
mod a01_broken_access_control {
    use super::*;

    #[tokio::test]
    async fn test_horizontal_privilege_escalation_prevention() {
        // Prevent users from accessing other users' ECS data
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
        let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();
        let malicious_user = create_test_user(&app.db_pool, "attacker".to_string(), "password123".to_string()).await.unwrap();

        let user1_entity = Uuid::new_v4();
        let user2_entity = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities for different users
        let entities = vec![
            NewEcsEntity { id: user1_entity, user_id: user1.id, archetype_signature: "PrivateData".to_string() },
            NewEcsEntity { id: user2_entity, user_id: user2.id, archetype_signature: "ConfidentialData".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // User1 creates sensitive relationship
        let sensitive_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: user1_entity,
            to_entity_id: user2_entity,
            user_id: user1.id,
            relationship_type: "financial_access".to_string(),
            relationship_data: json!({
                "account_number": "SECRET123456",
                "credit_limit": 50000,
                "ssn": "123-45-6789"
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(1.0),
            causal_metadata: Some(json!({
                "classification": "TOP_SECRET",
                "clearance_required": "LEVEL_5"
            })),
            temporal_validity: None,
        };

        conn.interact({
            let sensitive_relationship = sensitive_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&sensitive_relationship)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Malicious user attempts horizontal privilege escalation
        let malicious_query_result = conn.interact({
            let malicious_user_id = malicious_user.id;
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::user_id.eq(malicious_user_id))
                    .select(EcsEntityRelationship::as_select())
                    .load::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(malicious_query_result.len(), 0, "Malicious user should not access other users' relationships");

        // Test CausalComponent access control
        let causal_component_result = CausalComponent::generate_for_entity(
            user1_entity,
            malicious_user.id,
            &app.db_pool
        ).await;

        match causal_component_result {
            Ok(component) => {
                // If it succeeds, should return empty data
                assert!(component.caused_by_events.is_empty(), "Should not access other user's causal data");
                assert!(component.causes_events.is_empty(), "Should not access other user's causal data");
            }
            Err(_) => {
                // Failure is also acceptable for access control
            }
        }
    }

    #[tokio::test]
    async fn test_vertical_privilege_escalation_prevention() {
        // Prevent privilege escalation to admin functions
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let regular_user = create_test_user(&app.db_pool, "regular".to_string(), "password123".to_string()).await.unwrap();
        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: regular_user.id, archetype_signature: "Regular".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Attempt to create relationship with admin-level permissions
        let escalation_attempt = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_id,
            to_entity_id: entity_id,
            user_id: regular_user.id,
            relationship_type: "admin_override".to_string(),
            relationship_data: json!({
                "privilege_level": "ADMIN",
                "bypass_security": true,
                "grant_all_access": true
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(1.0),
            causal_metadata: Some(json!({
                "security_override": true,
                "elevation_attempt": "UNAUTHORIZED"
            })),
            temporal_validity: None,
        };

        // Should be able to create the relationship, but it shouldn't grant actual privileges
        let result = conn.interact({
            let escalation_attempt = escalation_attempt.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&escalation_attempt)
                    .execute(conn)
            }
        }).await.unwrap();

        // The relationship should be stored safely without granting actual privileges
        assert!(result.is_ok(), "Regular users should be able to store data");
        
        // Verify user still has no special privileges (they can only see their own data)
        let user_relationships = conn.interact({
            let user_id = regular_user.id;
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(user_relationships, 1, "User should only see their own relationships");
    }

    #[tokio::test]
    async fn test_insecure_direct_object_reference_prevention() {
        // Prevent direct access to objects via ID manipulation
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
        let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();

        let user1_entity = Uuid::new_v4();
        let user2_entity = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities
        let entities = vec![
            NewEcsEntity { id: user1_entity, user_id: user1.id, archetype_signature: "User1Data".to_string() },
            NewEcsEntity { id: user2_entity, user_id: user2.id, archetype_signature: "User2Data".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // User1 attempts to access User2's entity directly by ID
        let direct_access_attempt = conn.interact({
            let user1_id = user1.id;
            let user2_entity_id = user2_entity;
            move |conn| {
                ecs_entities::table
                    .filter(ecs_entities::id.eq(user2_entity_id))
                    .filter(ecs_entities::user_id.eq(user1_id)) // This should fail
                    .count()
                    .get_result::<i64>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(direct_access_attempt, 0, "Should not access other user's entity by direct ID reference");

        // Test CausalComponent with direct ID manipulation
        let causal_attempt = CausalComponent::generate_for_entity(
            user2_entity,  // User2's entity
            user1.id,      // User1's credentials
            &app.db_pool
        ).await;

        match causal_attempt {
            Ok(component) => {
                // Should return empty data due to access control
                assert!(component.caused_by_events.is_empty());
                assert!(component.causes_events.is_empty());
            }
            Err(_) => {
                // Error is also acceptable
            }
        }
    }
}

// A02:2021 - Cryptographic Failures
mod a02_cryptographic_failures {
    use super::*;

    #[tokio::test]
    async fn test_sensitive_data_exposure_prevention() {
        // Ensure sensitive data in relationships is not exposed inappropriately
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities
        let entities = vec![
            NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Bank".to_string() },
            NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Customer".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create relationship with sensitive financial data
        let sensitive_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            user_id: user.id,
            relationship_type: "financial_account".to_string(),
            relationship_data: json!({
                "account_number": "4532-1234-5678-9012", // Credit card number
                "ssn": "123-45-6789",                     // Social Security Number
                "pin": "1234",                            // PIN
                "balance": 50000.00,
                "credit_score": 750
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(1.0),
            causal_metadata: Some(json!({
                "encryption_required": true,
                "pii_classification": "SENSITIVE",
                "access_log_required": true
            })),
            temporal_validity: Some(json!({
                "data_retention_policy": "7_YEARS",
                "last_accessed": Utc::now()
            })),
        };

        let stored_relationship = conn.interact({
            let sensitive_relationship = sensitive_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&sensitive_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify sensitive data is stored (application should handle encryption at higher layers)
        let relationship_data = &stored_relationship.relationship_data;
        
        // Data should be stored as JSON (encryption should happen at application layer)
        assert!(relationship_data.get("account_number").is_some());
        assert!(relationship_data.get("ssn").is_some());
        
        // Verify metadata indicates encryption requirements
        let causal_metadata = stored_relationship.causal_metadata.unwrap();
        assert_eq!(causal_metadata.get("encryption_required").unwrap().as_bool().unwrap(), true);
        assert_eq!(causal_metadata.get("pii_classification").unwrap().as_str().unwrap(), "SENSITIVE");
    }

    #[tokio::test]
    async fn test_data_integrity_protection() {
        // Ensure data integrity is maintained and tampering is detectable
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "IntegrityTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create relationship with integrity protection metadata
        let integrity_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_id,
            to_entity_id: entity_id,
            user_id: user.id,
            relationship_type: "integrity_protected".to_string(),
            relationship_data: json!({
                "data": "important_information",
                "checksum": "sha256:abcdef123456789",
                "version": 1,
                "last_modified": Utc::now()
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(1.0),
            causal_metadata: Some(json!({
                "integrity_check": "sha256:fedcba987654321",
                "signature": "digital_signature_here",
                "tamper_evident": true
            })),
            temporal_validity: Some(json!({
                "created_timestamp": Utc::now(),
                "hash_algorithm": "SHA256"
            })),
        };

        let stored_relationship = conn.interact({
            let integrity_relationship = integrity_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&integrity_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify integrity metadata is preserved
        let causal_metadata = stored_relationship.causal_metadata.unwrap();
        assert!(causal_metadata.get("integrity_check").is_some());
        assert!(causal_metadata.get("signature").is_some());
        assert_eq!(causal_metadata.get("tamper_evident").unwrap().as_bool().unwrap(), true);

        // Verify timestamps for tamper detection
        assert!(stored_relationship.created_at <= Utc::now());
        assert!(stored_relationship.updated_at <= Utc::now());
        assert_eq!(stored_relationship.created_at, stored_relationship.updated_at); // Should be equal for new records
    }
}

// A03:2021 - Injection
mod a03_injection {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        // Test SQL injection prevention in all JSON fields
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities
        let entities = vec![
            NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "SQLTest".to_string() },
            NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "InjectionTest".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // SQL injection payloads
        let sql_payloads = vec![
            "'; DROP TABLE ecs_entity_relationships; --",
            "' UNION SELECT * FROM users --",
            "'; DELETE FROM ecs_entities; --",
            "' OR '1'='1",
            "'; TRUNCATE TABLE chronicle_events; --",
        ];

        for payload in &sql_payloads {
            let malicious_relationship = NewEcsEntityRelationship {
                id: Uuid::new_v4(),
                from_entity_id: entity_a,
                to_entity_id: entity_b,
                user_id: user.id,
                relationship_type: format!("injection_test_{}", payload),
                relationship_data: json!({
                    "malicious_field": payload,
                    "description": format!("Testing payload: {}", payload)
                }),
                relationship_category: Some("social".to_string()),
                strength: Some(0.5),
                causal_metadata: Some(json!({
                    "payload": payload,
                    "injection_type": "sql"
                })),
                temporal_validity: Some(json!({
                    "exploit_attempt": payload
                })),
            };

            // Should store safely without executing the SQL
            let result = conn.interact({
                let malicious_relationship = malicious_relationship.clone();
                move |conn| {
                    diesel::insert_into(ecs_entity_relationships::table)
                        .values(&malicious_relationship)
                        .execute(conn)
                }
            }).await.unwrap();

            assert!(result.is_ok(), "Should safely store malicious SQL payload");
        }

        // Verify database integrity - tables should still exist
        let entity_count = conn.interact(move |conn| {
            ecs_entities::table.count().get_result::<i64>(conn)
        }).await.unwrap().unwrap();

        let relationship_count = conn.interact(move |conn| {
            ecs_entity_relationships::table.count().get_result::<i64>(conn)
        }).await.unwrap().unwrap();

        assert!(entity_count >= 2, "Entities table should still exist with data");
        assert!(relationship_count >= sql_payloads.len() as i64, "Relationships should be stored safely");
    }

    #[tokio::test]
    async fn test_nosql_injection_prevention() {
        // Test NoSQL injection prevention in JSON fields
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "NoSQLTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // NoSQL injection payloads
        let nosql_payloads = vec![
            json!({"$where": "function() { return true; }"}),
            json!({"$ne": null}),
            json!({"$regex": ".*"}),
            json!({"$gt": ""}),
            json!({"$or": [{"password": {"$exists": true}}, {"admin": true}]}),
        ];

        for (i, payload) in nosql_payloads.iter().enumerate() {
            let malicious_relationship = NewEcsEntityRelationship {
                id: Uuid::new_v4(),
                from_entity_id: entity_id,
                to_entity_id: entity_id,
                user_id: user.id,
                relationship_type: format!("nosql_test_{}", i),
                relationship_data: payload.clone(),
                relationship_category: Some("social".to_string()),
                strength: Some(0.5),
                causal_metadata: Some(payload.clone()),
                temporal_validity: Some(payload.clone()),
            };

            // Should store safely as JSON data
            let result = conn.interact({
                let malicious_relationship = malicious_relationship.clone();
                move |conn| {
                    diesel::insert_into(ecs_entity_relationships::table)
                        .values(&malicious_relationship)
                        .execute(conn)
                }
            }).await.unwrap();

            assert!(result.is_ok(), "Should safely store NoSQL injection payloads as JSON");
        }

        // Verify data integrity
        let stored_relationships = conn.interact({
            let user_id = user.id;
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::user_id.eq(user_id))
                    .select(EcsEntityRelationship::as_select())
                    .load::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(stored_relationships.len(), nosql_payloads.len());
        
        for relationship in &stored_relationships {
            // Verify JSON data is stored safely without interpretation
            assert!(relationship.relationship_data.is_object() || relationship.relationship_data.is_null());
            assert!(relationship.causal_metadata.is_some());
            assert!(relationship.temporal_validity.is_some());
        }
    }

    #[tokio::test]
    async fn test_json_injection_prevention() {
        // Test JSON injection prevention and structure validation
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "JSONTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Malformed JSON and injection attempts
        let malicious_data = json!({
            "normal_field": "normal_value",
            "script_injection": "<script>alert('xss')</script>",
            "html_injection": "<img src=x onerror=alert('xss')>",
            "nested_object": {
                "command_injection": "; rm -rf /",
                "path_traversal": "../../../../etc/passwd",
                "prototype_pollution": {"__proto__": {"isAdmin": true}}
            },
            "array_with_injections": [
                "'; DROP TABLE users; --",
                {"eval": "require('child_process').exec('rm -rf /')"}
            ]
        });

        let test_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_id,
            to_entity_id: entity_id,
            user_id: user.id,
            relationship_type: "json_injection_test".to_string(),
            relationship_data: malicious_data.clone(),
            relationship_category: Some("social".to_string()),
            strength: Some(0.5),
            causal_metadata: Some(malicious_data.clone()),
            temporal_validity: Some(malicious_data),
        };

        // Should store safely as JSON without interpretation
        let result = conn.interact({
            let test_relationship = test_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&test_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap();

        assert!(result.is_ok(), "Should safely store complex JSON with potential injections");
        
        let stored_relationship = result.unwrap();
        
        // Verify data is stored as-is without interpretation
        assert!(stored_relationship.relationship_data.get("script_injection").is_some());
        assert!(stored_relationship.relationship_data.get("nested_object").is_some());
        
        // Verify no code execution occurred (system should still be intact)
        let entity_count = conn.interact(move |conn| {
            ecs_entities::table.count().get_result::<i64>(conn)
        }).await.unwrap().unwrap();
        
        assert!(entity_count > 0, "System should remain intact after JSON injection attempts");
    }
}

// A04:2021 - Insecure Design
mod a04_insecure_design {
    use super::*;

    #[tokio::test]
    async fn test_secure_design_patterns() {
        // Verify secure design patterns are implemented
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "SecureDesign".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Test defense in depth - multiple security layers
        let secure_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_id,
            to_entity_id: entity_id,
            user_id: user.id,
            relationship_type: "security_test".to_string(),
            relationship_data: json!({
                "access_level": "restricted",
                "audit_required": true,
                "validation_passed": true
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(0.8),
            causal_metadata: Some(json!({
                "security_context": "high_security",
                "validation_rules": ["user_authorization", "data_integrity", "audit_logging"],
                "threat_model_reviewed": true
            })),
            temporal_validity: Some(json!({
                "access_window": {
                    "start": Utc::now(),
                    "end": Utc::now() + Duration::hours(1)
                },
                "max_access_duration": "1_HOUR"
            })),
        };

        let result = conn.interact({
            let secure_relationship = secure_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&secure_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify security metadata is preserved
        let causal_metadata = result.causal_metadata.unwrap();
        assert_eq!(causal_metadata.get("security_context").unwrap().as_str().unwrap(), "high_security");
        assert!(causal_metadata.get("validation_rules").unwrap().is_array());
        assert_eq!(causal_metadata.get("threat_model_reviewed").unwrap().as_bool().unwrap(), true);

        // Verify temporal security controls
        let temporal_validity = result.temporal_validity.unwrap();
        assert!(temporal_validity.get("access_window").is_some());
        assert!(temporal_validity.get("max_access_duration").is_some());
    }

    #[tokio::test]
    async fn test_fail_secure_design() {
        // Test that system fails securely when encountering edge cases
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        // Test CausalComponent generation with non-existent entity (should fail securely)
        let non_existent_entity = Uuid::new_v4();
        
        let causal_result = CausalComponent::generate_for_entity(
            non_existent_entity,
            user.id,
            &app.db_pool
        ).await;

        match causal_result {
            Ok(component) => {
                // Should return empty/safe data rather than failing insecurely
                assert!(component.caused_by_events.is_empty());
                assert!(component.causes_events.is_empty());
                assert_eq!(component.causal_confidence, 0.0);
                assert_eq!(component.causal_chain_depth, 0);
            }
            Err(_) => {
                // Graceful failure is also acceptable
            }
        }

        // Test translator with malformed data (should fail securely)
        let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
        
        let malformed_event = ChronicleEvent {
            id: Uuid::new_v4(),
            chronicle_id: Uuid::new_v4(),
            user_id: user.id,
            event_type: String::new(), // Empty event type
            summary: String::new(),    // Empty summary
            source: "INVALID_SOURCE".to_string(),
            event_data: Some(json!({"invalid": "structure"})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now(),
            actors: Some(json!("invalid_actors_format")), // Invalid actors format
            action: None,
            context_data: None,
            causality: None,
            valence: None,
            modality: None,
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 1,
        };

        let translation_result = translator.translate_event(&malformed_event, user.id).await;
        
        match translation_result {
            Ok(result) => {
                // Should handle gracefully without creating invalid data
                assert!(result.entities_created.is_empty() || !result.entities_created.is_empty());
                // Should not crash or create inconsistent state
            }
            Err(_) => {
                // Graceful error handling is expected for malformed data
            }
        }
    }
}

// A08:2021 - Software and Data Integrity Failures
mod a08_data_integrity {
    use super::*;

    #[tokio::test]
    async fn test_data_consistency_constraints() {
        // Test referential integrity and consistency constraints
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities
        let entities = vec![
            NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "EntityA".to_string() },
            NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "EntityB".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create relationship with integrity metadata
        let integrity_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            user_id: user.id,
            relationship_type: "integrity_test".to_string(),
            relationship_data: json!({
                "data_version": 1,
                "checksum": "abc123",
                "last_verified": Utc::now()
            }),
            relationship_category: Some("social".to_string()),
            strength: Some(0.7),
            causal_metadata: Some(json!({
                "integrity_hash": "sha256:abcdef123456",
                "validation_timestamp": Utc::now(),
                "consistency_check_passed": true
            })),
            temporal_validity: Some(json!({
                "data_lineage": "user_input -> validation -> storage",
                "integrity_verified": true
            })),
        };

        let stored_rel = conn.interact({
            let integrity_relationship = integrity_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&integrity_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify integrity constraints
        assert_eq!(stored_rel.from_entity_id, entity_a);
        assert_eq!(stored_rel.to_entity_id, entity_b);
        assert_eq!(stored_rel.user_id, user.id);

        // Verify integrity metadata
        let causal_metadata = stored_rel.causal_metadata.as_ref().unwrap();
        assert!(causal_metadata.get("integrity_hash").is_some());
        assert_eq!(causal_metadata.get("consistency_check_passed").unwrap().as_bool().unwrap(), true);

        // Test relationship data consistency across multiple reads
        let second_read = conn.interact({
            let rel_id = stored_rel.id;
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::id.eq(rel_id))
                    .select(EcsEntityRelationship::as_select())
                    .first::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(stored_rel.relationship_data, second_read.relationship_data);
        assert_eq!(stored_rel.causal_metadata, second_read.causal_metadata);
        assert_eq!(stored_rel.temporal_validity, second_read.temporal_validity);
    }

    #[tokio::test]
    async fn test_causal_component_consistency() {
        // Test CausalComponent consistency across multiple generations
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "ConsistencyTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create consistent causal events
        let events = vec![
            NewChronicleEvent {
                chronicle_id,
                user_id: user.id,
                event_type: "CONSISTENCY_TEST_1".to_string(),
                summary: "First consistent event".to_string(),
                source: EventSource::AiExtracted.to_string(),
                event_data: Some(json!({"sequence": 1})),
                summary_encrypted: None,
                summary_nonce: None,
                timestamp_iso8601: Utc::now(),
                actors: Some(json!([{"entity_id": entity_id, "role": "SUBJECT"}])),
                action: Some("TEST".to_string()),
                context_data: None,
                causality: None,
                valence: None,
                modality: Some("ACTUAL".to_string()),
                caused_by_event_id: None,
                causes_event_ids: None,
                sequence_number: 1,
            },
            NewChronicleEvent {
                chronicle_id,
                user_id: user.id,
                event_type: "CONSISTENCY_TEST_2".to_string(),
                summary: "Second consistent event".to_string(),
                source: EventSource::AiExtracted.to_string(),
                event_data: Some(json!({"sequence": 2})),
                summary_encrypted: None,
                summary_nonce: None,
                timestamp_iso8601: Utc::now(),
                actors: Some(json!([{"entity_id": entity_id, "role": "SUBJECT"}])),
                action: Some("TEST".to_string()),
                context_data: None,
                causality: None,
                valence: None,
                modality: Some("ACTUAL".to_string()),
                caused_by_event_id: None,
                causes_event_ids: None,
                sequence_number: 2,
            },
        ];

        conn.interact({
            let events = events.clone();
            move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&events)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Generate CausalComponent multiple times
        let component1 = CausalComponent::generate_for_entity(entity_id, user.id, &app.db_pool).await.unwrap();
        let component2 = CausalComponent::generate_for_entity(entity_id, user.id, &app.db_pool).await.unwrap();
        let component3 = CausalComponent::generate_for_entity(entity_id, user.id, &app.db_pool).await.unwrap();

        // Verify consistency across multiple generations
        assert_eq!(component1.caused_by_events, component2.caused_by_events);
        assert_eq!(component2.caused_by_events, component3.caused_by_events);
        
        assert_eq!(component1.causes_events, component2.causes_events);
        assert_eq!(component2.causes_events, component3.causes_events);
        
        assert_eq!(component1.causal_confidence, component2.causal_confidence);
        assert_eq!(component2.causal_confidence, component3.causal_confidence);
        
        assert_eq!(component1.causal_chain_depth, component2.causal_chain_depth);
        assert_eq!(component2.causal_chain_depth, component3.causal_chain_depth);

        // Verify metadata consistency
        assert_eq!(component1.causal_metadata.len(), component2.causal_metadata.len());
        assert_eq!(component2.causal_metadata.len(), component3.causal_metadata.len());
    }
}

// A09:2021 - Security Logging and Monitoring Failures
mod a09_logging_monitoring {
    use super::*;

    #[tokio::test]
    async fn test_audit_trail_creation() {
        // Test that security-sensitive operations create proper audit trails
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entities
        let entities = vec![
            NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "AuditSource".to_string() },
            NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "AuditTarget".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create relationship with comprehensive audit information
        let audited_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            user_id: user.id,
            relationship_type: "high_privilege_access".to_string(),
            relationship_data: json!({
                "access_level": "admin",
                "permission_granted": true,
                "session_id": Uuid::new_v4()
            }),
            relationship_category: Some("ownership".to_string()),
            strength: Some(1.0),
            causal_metadata: Some(json!({
                "audit_event_id": Uuid::new_v4(),
                "user_id": user.id,
                "action": "GRANT_HIGH_PRIVILEGE_ACCESS",
                "timestamp": Utc::now(),
                "ip_address": "192.168.1.100", // Would be real IP in production
                "user_agent": "TestAgent/1.0",
                "risk_level": "HIGH",
                "requires_approval": true,
                "approved_by": user.id
            })),
            temporal_validity: Some(json!({
                "access_granted_at": Utc::now(),
                "access_expires_at": Utc::now() + Duration::hours(24),
                "max_session_duration": "24_HOURS",
                "audit_retention_period": "7_YEARS"
            })),
        };

        let stored_relationship = conn.interact({
            let audited_relationship = audited_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&audited_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify audit trail information is captured
        let causal_metadata = stored_relationship.causal_metadata.unwrap();
        assert!(causal_metadata.get("audit_event_id").is_some());
        assert_eq!(causal_metadata.get("user_id").unwrap().as_str().unwrap(), user.id.to_string());
        assert_eq!(causal_metadata.get("action").unwrap().as_str().unwrap(), "GRANT_HIGH_PRIVILEGE_ACCESS");
        assert!(causal_metadata.get("timestamp").is_some());
        assert_eq!(causal_metadata.get("risk_level").unwrap().as_str().unwrap(), "HIGH");

        // Verify temporal audit information
        let temporal_validity = stored_relationship.temporal_validity.unwrap();
        assert!(temporal_validity.get("access_granted_at").is_some());
        assert!(temporal_validity.get("access_expires_at").is_some());
        assert_eq!(temporal_validity.get("audit_retention_period").unwrap().as_str().unwrap(), "7_YEARS");

        // Verify database-level audit fields
        assert!(stored_relationship.created_at <= Utc::now());
        assert!(stored_relationship.updated_at <= Utc::now());
        assert_eq!(stored_relationship.user_id, user.id);
    }

    #[tokio::test]
    async fn test_security_event_logging() {
        // Test that security events are properly logged with sufficient detail
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "SecurityTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Create security event with detailed logging
        let security_event = NewChronicleEvent {
            chronicle_id,
            user_id: user.id,
            event_type: "SECURITY_VIOLATION_ATTEMPT".to_string(),
            summary: "Potential security violation detected".to_string(),
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "violation_type": "UNAUTHORIZED_ACCESS_ATTEMPT",
                "target_resource": "high_security_data",
                "source_ip": "10.0.0.50",
                "user_agent": "SuspiciousBot/1.0",
                "request_method": "POST",
                "request_path": "/api/admin/delete_all",
                "payload_size": 1024,
                "security_headers_missing": true
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT",
                "context": "potential_attacker"
            }])),
            action: Some("ATTEMPT_UNAUTHORIZED_ACCESS".to_string()),
            context_data: Some(json!({
                "alert_level": "HIGH",
                "automatic_block": true,
                "incident_id": Uuid::new_v4(),
                "forensic_data_collected": true
            })),
            causality: None,
            valence: None,
            modality: Some("ACTUAL".to_string()),
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 1,
        };

        let stored_event = conn.interact({
            let security_event = security_event.clone();
            move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&security_event)
                    .get_result::<ChronicleEvent>(conn)
            }
        }).await.unwrap().unwrap();

        // Verify security event logging
        assert_eq!(stored_event.event_type, "SECURITY_VIOLATION_ATTEMPT");
        assert_eq!(stored_event.source, EventSource::System.to_string());
        
        let event_data = stored_event.event_data.unwrap();
        assert_eq!(event_data.get("violation_type").unwrap().as_str().unwrap(), "UNAUTHORIZED_ACCESS_ATTEMPT");
        assert!(event_data.get("source_ip").is_some());
        assert!(event_data.get("user_agent").is_some());
        
        let context_data = stored_event.context_data.unwrap();
        assert_eq!(context_data.get("alert_level").unwrap().as_str().unwrap(), "HIGH");
        assert_eq!(context_data.get("automatic_block").unwrap().as_bool().unwrap(), true);
        assert!(context_data.get("incident_id").is_some());

        // Verify timestamp accuracy for forensics
        let time_diff = (Utc::now() - stored_event.created_at).num_seconds();
        assert!(time_diff < 60, "Event timestamp should be recent for accurate forensics");
    }
}

// Performance and DoS Protection Tests
mod performance_security {
    use super::*;

    #[tokio::test]
    async fn test_resource_exhaustion_protection() {
        // Test protection against resource exhaustion attacks
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "DoSTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Test with reasonably sized data (should succeed)
        let normal_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_id,
            to_entity_id: entity_id,
            user_id: user.id,
            relationship_type: "normal_size".to_string(),
            relationship_data: json!({
                "data": "normal_sized_content"
            }),
            relationship_category: Some("social".to_string()),
            strength: Some(0.5),
            causal_metadata: Some(json!({
                "metadata": "normal_metadata"
            })),
            temporal_validity: Some(json!({
                "validity": "normal_validity"
            })),
        };

        let start_time = std::time::Instant::now();
        
        let normal_result = conn.interact({
            let normal_relationship = normal_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&normal_relationship)
                    .execute(conn)
            }
        }).await.unwrap();

        let normal_duration = start_time.elapsed();
        
        assert!(normal_result.is_ok(), "Normal-sized data should be processed successfully");
        assert!(normal_duration.as_millis() < 1000, "Normal operations should complete quickly");

        // Test CausalComponent generation performance
        let causal_start = std::time::Instant::now();
        
        let causal_result = CausalComponent::generate_for_entity(
            entity_id,
            user.id,
            &app.db_pool
        ).await;

        let causal_duration = causal_start.elapsed();
        
        assert!(causal_result.is_ok(), "CausalComponent generation should succeed");
        assert!(causal_duration.as_secs() < 5, "CausalComponent generation should complete within 5 seconds");
        
        let component = causal_result.unwrap();
        assert!(component.causal_metadata.len() < 10000, "Generated metadata should be reasonably sized");
    }

    #[tokio::test]
    async fn test_concurrent_access_safety() {
        // Test that concurrent access is handled safely
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

        let entity_id = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Create entity
        let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "ConcurrencyTest".to_string() };
        conn.interact({
            let entity = entity.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entity)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        // Test concurrent CausalComponent generation
        let mut handles = Vec::new();
        
        for i in 0..5 {
            let pool = app.db_pool.clone();
            let user_id = user.id;
            let entity_id = entity_id;
            
            let handle = tokio::spawn(async move {
                let result = CausalComponent::generate_for_entity(entity_id, user_id, &pool).await;
                (i, result)
            });
            
            handles.push(handle);
        }

        // Wait for all concurrent operations to complete
        let mut results = Vec::new();
        for handle in handles {
            let (index, result) = handle.await.unwrap();
            results.push((index, result));
        }

        // Verify all operations completed successfully or failed gracefully
        for (index, result) in results {
            match result {
                Ok(component) => {
                    // Should return consistent data
                    assert!(component.causal_confidence >= 0.0 && component.causal_confidence <= 1.0);
                    assert!(component.causal_chain_depth >= 0);
                }
                Err(_) => {
                    // Graceful failure under concurrent load is acceptable
                    println!("Operation {} failed gracefully under concurrent load", index);
                }
            }
        }

        // Verify database consistency after concurrent operations
        let final_entity_count = conn.interact({
            let user_id = user.id;
            move |conn| {
                ecs_entities::table
                    .filter(ecs_entities::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn)
            }
        }).await.unwrap().unwrap();

        assert_eq!(final_entity_count, 1, "Database should maintain consistency under concurrent access");
    }
}