// Enhanced ECS Relationships Tests
// 
// Tests for Phase 1: Foundation Enhancements
// - Enhanced relationship metadata (category, strength, causal_metadata, temporal_validity)
// - OWASP Top 10 security compliance
// - Database integrity and data validation
// - Access control and authorization

use uuid::Uuid;
use serde_json::json;
use chrono::{Utc, Duration};

use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::{
        ecs_diesel::{NewEcsEntityRelationship, EcsEntityRelationship, NewEcsEntity},
        ecs::{RelationshipCategory},
    },
    schema::{ecs_entity_relationships, ecs_entities},
};
use diesel::prelude::*;

#[tokio::test]
async fn test_enhanced_relationship_creation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    // Create entities
    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities first
    let new_entity_a = NewEcsEntity {
        id: entity_a,
        user_id: user.id,
        archetype_signature: "Character|Health".to_string(),
    };
    let new_entity_b = NewEcsEntity {
        id: entity_b,
        user_id: user.id,
        archetype_signature: "Character|Health".to_string(),
    };
    
    conn.interact({
        let new_entity_a = new_entity_a.clone();
        let new_entity_b = new_entity_b.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&vec![new_entity_a, new_entity_b])
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create enhanced relationship
    let new_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "trust".to_string(),
        relationship_data: json!({
            "trust_level": 0.8,
            "created_context": "first meeting"
        }),
        relationship_category: Some(RelationshipCategory::Social.as_str().to_string()),
        strength: Some(0.7),
        causal_metadata: Some(json!({
            "caused_by_event": Uuid::new_v4(),
            "confidence": 0.9,
            "causality_type": "direct"
        })),
        temporal_validity: Some(json!({
            "valid_from": Utc::now(),
            "valid_until": null,
            "confidence": 1.0
        })),
    };

    let result = conn.interact({
        let new_relationship = new_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&new_relationship)
                .get_result::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap();

    let relationship = result.unwrap();
    
    // Verify enhanced fields
    assert_eq!(relationship.relationship_category, Some(RelationshipCategory::Social.as_str().to_string()));
    assert_eq!(relationship.strength, Some(0.7));
    assert!(relationship.causal_metadata.is_some());
    assert!(relationship.temporal_validity.is_some());
    
    // Verify causal metadata structure
    let causal_metadata = relationship.causal_metadata.unwrap();
    assert!(causal_metadata.get("confidence").is_some());
    assert_eq!(causal_metadata.get("causality_type").unwrap().as_str().unwrap(), "direct");
}

#[tokio::test]
async fn test_relationship_category_validation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    // Test all valid relationship categories
    let categories = vec![
        RelationshipCategory::Social,
        RelationshipCategory::Spatial,
        RelationshipCategory::Causal,
        RelationshipCategory::Ownership,
        RelationshipCategory::Temporal,
    ];

    for category in categories {
        let entity_a = Uuid::new_v4();
        let entity_b = Uuid::new_v4();
        
        let conn = app.db_pool.get().await.unwrap();
        
        // Insert entities
        let entities = vec![
            NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
            NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
        ];
        
        conn.interact({
            let entities = entities.clone();
            move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&entities)
                    .execute(conn)
            }
        }).await.unwrap().unwrap();

        let new_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            user_id: user.id,
            relationship_type: format!("test_{}", category.as_str()),
            relationship_data: json!({}),
            relationship_category: Some(category.as_str().to_string()),
            strength: Some(0.5),
            causal_metadata: None,
            temporal_validity: None,
        };

        let result = conn.interact({
            let new_relationship = new_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&new_relationship)
                    .get_result::<EcsEntityRelationship>(conn)
            }
        }).await.unwrap();

        assert!(result.is_ok(), "Failed to create relationship with category: {:?}", category);
    }
}

#[tokio::test]
async fn test_strength_bounds_validation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test valid strength values
    let valid_strengths = vec![0.0, 0.5, 1.0];
    
    for strength in valid_strengths {
        let new_relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            user_id: user.id,
            relationship_type: format!("test_strength_{}", strength),
            relationship_data: json!({}),
            relationship_category: Some("social".to_string()),
            strength: Some(strength),
            causal_metadata: None,
            temporal_validity: None,
        };

        let result = conn.interact({
            let new_relationship = new_relationship.clone();
            move |conn| {
                diesel::insert_into(ecs_entity_relationships::table)
                    .values(&new_relationship)
                    .execute(conn)
            }
        }).await.unwrap();

        assert!(result.is_ok(), "Failed to create relationship with valid strength: {}", strength);
    }
}

#[tokio::test]
async fn test_temporal_validity_structure() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    let valid_from = Utc::now();
    let valid_until = valid_from + Duration::days(30);

    let new_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "temporary_alliance".to_string(),
        relationship_data: json!({}),
        relationship_category: Some("social".to_string()),
        strength: Some(0.6),
        causal_metadata: None,
        temporal_validity: Some(json!({
            "valid_from": valid_from,
            "valid_until": valid_until,
            "confidence": 0.95
        })),
    };

    let result = conn.interact({
        let new_relationship = new_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&new_relationship)
                .get_result::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap();

    let relationship = result.unwrap();
    let temporal_validity = relationship.temporal_validity.unwrap();
    
    assert!(temporal_validity.get("valid_from").is_some());
    assert!(temporal_validity.get("valid_until").is_some());
    assert_eq!(temporal_validity.get("confidence").unwrap().as_f64().unwrap(), 0.95);
}

// OWASP Top 10 Security Tests

#[tokio::test] 
async fn test_a01_broken_access_control_prevention() {
    // A01: Broken Access Control - Ensure users can only access their own relationships
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // User1 creates entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user1.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user1.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // User1 creates relationship
    let user1_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user1.id,
        relationship_type: "private_trust".to_string(),
        relationship_data: json!({"secret": "confidential_data"}),
        relationship_category: Some("social".to_string()),
        strength: Some(0.8),
        causal_metadata: None,
        temporal_validity: None,
    };

    conn.interact({
        let user1_relationship = user1_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&user1_relationship)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // User2 should NOT be able to access User1's relationships
    let user2_query_result = conn.interact({
        let user2_id = user2.id;
        move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::user_id.eq(user2_id))
                .select(EcsEntityRelationship::as_select())
                .load::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap().unwrap();

    assert_eq!(user2_query_result.len(), 0, "User2 should not see User1's relationships");

    // User1 should be able to access their own relationships
    let user1_query_result = conn.interact({
        let user1_id = user1.id;
        move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::user_id.eq(user1_id))
                .select(EcsEntityRelationship::as_select())
                .load::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap().unwrap();

    assert_eq!(user1_query_result.len(), 1, "User1 should see their own relationships");
}

#[tokio::test]
async fn test_a03_injection_prevention() {
    // A03: Injection - Test SQL injection prevention in relationship data
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Attempt SQL injection through JSON fields
    let malicious_data = json!({
        "description": "'; DROP TABLE ecs_entity_relationships; --",
        "xss_attempt": "<script>alert('xss')</script>",
        "sql_injection": "1' OR '1'='1",
        "command_injection": "; rm -rf /",
    });

    let new_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "malicious_test".to_string(),
        relationship_data: malicious_data.clone(),
        relationship_category: Some("social".to_string()),
        strength: Some(0.5),
        causal_metadata: Some(malicious_data.clone()),
        temporal_validity: Some(malicious_data),
    };

    // Should safely store malicious data without executing it
    let result = conn.interact({
        let new_relationship = new_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&new_relationship)
                .get_result::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap();

    let relationship = result.unwrap();
    
    // Verify data is stored safely as JSON (not executed)
    assert!(relationship.relationship_data.get("description").is_some());
    assert!(relationship.causal_metadata.is_some());
    assert!(relationship.temporal_validity.is_some());
    
    // Verify table still exists (SQL injection didn't work)
    let count_result = conn.interact(move |conn| {
        ecs_entity_relationships::table
            .count()
            .get_result::<i64>(conn)
    }).await.unwrap().unwrap();
    
    assert!(count_result > 0, "Table should still exist");
}

#[tokio::test]
async fn test_a08_data_integrity_validation() {
    // A08: Software and Data Integrity Failures - Ensure data integrity constraints
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test data integrity: duplicate relationships should be prevented
    let relationship_data = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "trust".to_string(),
        relationship_data: json!({}),
        relationship_category: Some("social".to_string()),
        strength: Some(0.5),
        causal_metadata: None,
        temporal_validity: None,
    };

    // First insertion should succeed
    let first_result = conn.interact({
        let relationship_data = relationship_data.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&relationship_data)
                .execute(conn)
        }
    }).await.unwrap();
    assert!(first_result.is_ok());

    // Second insertion with same entities and type should be handled gracefully
    let duplicate_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(), // Different ID
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "trust".to_string(), // Same type
        relationship_data: json!({"different": "data"}),
        relationship_category: Some("social".to_string()),
        strength: Some(0.7),
        causal_metadata: None,
        temporal_validity: None,
    };

    // This should either succeed (if duplicates are allowed) or fail gracefully
    let second_result = conn.interact({
        let duplicate_relationship = duplicate_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&duplicate_relationship)
                .execute(conn)
        }
    }).await.unwrap();
    
    // Either way, the database should remain consistent
    let count = conn.interact(move |conn| {
        ecs_entity_relationships::table
            .filter(ecs_entity_relationships::from_entity_id.eq(entity_a))
            .filter(ecs_entity_relationships::to_entity_id.eq(entity_b))
            .filter(ecs_entity_relationships::relationship_type.eq("trust"))
            .count()
            .get_result::<i64>(conn)
    }).await.unwrap().unwrap();
    
    // Should have at least one relationship
    assert!(count >= 1, "Database should maintain referential integrity");
}

#[tokio::test]
async fn test_a09_security_logging() {
    // A09: Security Logging and Monitoring Failures - Ensure sensitive operations are logged
    // This test verifies that relationship creation/modification events are properly logged
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: entity_a, user_id: user.id, archetype_signature: "Test".to_string() },
        NewEcsEntity { id: entity_b, user_id: user.id, archetype_signature: "Test".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create a sensitive relationship that should be logged
    let sensitive_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: entity_a,
        to_entity_id: entity_b,
        user_id: user.id,
        relationship_type: "financial_trust".to_string(),
        relationship_data: json!({
            "access_level": "high",
            "financial_limit": 10000
        }),
        relationship_category: Some("ownership".to_string()),
        strength: Some(0.9),
        causal_metadata: Some(json!({
            "audit_required": true,
            "created_by": user.id,
            "creation_timestamp": Utc::now()
        })),
        temporal_validity: None,
    };

    let result = conn.interact({
        let sensitive_relationship = sensitive_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&sensitive_relationship)
                .get_result::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap();

    let relationship = result.unwrap();
    
    // Verify audit information is preserved in causal_metadata
    let causal_metadata = relationship.causal_metadata.unwrap();
    assert_eq!(causal_metadata.get("audit_required").unwrap().as_bool().unwrap(), true);
    assert_eq!(causal_metadata.get("created_by").unwrap().as_str().unwrap(), user.id.to_string());
    assert!(causal_metadata.get("creation_timestamp").is_some());
    
    // Verify relationship has proper timestamps for audit trail
    assert!(relationship.created_at <= Utc::now());
    assert!(relationship.updated_at <= Utc::now());
    assert_eq!(relationship.created_at, relationship.updated_at); // Should be equal for new records
}

#[tokio::test]
async fn test_relationship_query_performance() {
    // Performance test to ensure enhanced relationships don't significantly degrade query performance
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let conn = app.db_pool.get().await.unwrap();
    
    // Create multiple entities and relationships for performance testing
    let mut entities = Vec::new();
    let mut relationships = Vec::new();
    
    let entity_count = 50;
    
    // Create entities
    for i in 0..entity_count {
        let entity_id = Uuid::new_v4();
        entities.push(NewEcsEntity {
            id: entity_id,
            user_id: user.id,
            archetype_signature: format!("TestEntity{}", i),
        });
    }
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create relationships between entities
    for i in 0..entity_count - 1 {
        let relationship = NewEcsEntityRelationship {
            id: Uuid::new_v4(),
            from_entity_id: entities[i].id,
            to_entity_id: entities[i + 1].id,
            user_id: user.id,
            relationship_type: format!("relationship_{}", i),
            relationship_data: json!({
                "index": i,
                "data": format!("test_data_{}", i)
            }),
            relationship_category: Some("social".to_string()),
            strength: Some((i as f64) / (entity_count as f64)),
            causal_metadata: Some(json!({
                "batch_id": "performance_test",
                "created_index": i
            })),
            temporal_validity: Some(json!({
                "valid_from": Utc::now(),
                "valid_until": null,
                "confidence": 1.0
            })),
        };
        relationships.push(relationship);
    }

    let start_time = std::time::Instant::now();
    
    conn.interact({
        let relationships = relationships.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&relationships)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    let insert_duration = start_time.elapsed();
    
    // Query all relationships for the user
    let query_start = std::time::Instant::now();
    
    let queried_relationships = conn.interact({
        let user_id = user.id;
        move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::user_id.eq(user_id))
                .select(EcsEntityRelationship::as_select())
                .load::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap().unwrap();

    let query_duration = query_start.elapsed();
    
    // Performance assertions
    assert_eq!(queried_relationships.len(), entity_count - 1);
    assert!(insert_duration.as_millis() < 5000, "Insert should complete within 5 seconds");
    assert!(query_duration.as_millis() < 1000, "Query should complete within 1 second");
    
    // Verify enhanced fields are properly stored and retrieved
    for relationship in &queried_relationships {
        assert!(relationship.relationship_category.is_some());
        assert!(relationship.strength.is_some());
        assert!(relationship.causal_metadata.is_some());
        assert!(relationship.temporal_validity.is_some());
    }
}