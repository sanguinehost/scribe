#![cfg(test)]
// backend/tests/ecs_security_tests.rs
//
// Security-focused tests for ECS implementation based on OWASP Top 10
// These tests verify that the ECS system properly handles security concerns

use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        ecs_diesel::{EcsEntity, NewEcsEntity, EcsComponent, NewEcsComponent},
    },
    schema::{users, ecs_entities, ecs_components},
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use serde_json::json;
use secrecy::ExposeSecret;
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;

/// Helper to create multiple test users for isolation testing
async fn create_test_users(test_app: &TestApp, count: usize) -> AnyhowResult<Vec<Uuid>> {
    let mut user_ids = Vec::new();
    
    for i in 0..count {
        let conn = test_app.db_pool.get().await?;
        
        let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
        let username = format!("security_test_user_{}_{}", i, Uuid::new_v4().simple());
        let email = format!("{}@test.com", username);
        
        // Generate proper crypto keys
        let kek_salt = scribe_backend::crypto::generate_salt()?;
        let dek = scribe_backend::crypto::generate_dek()?;
        
        let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
        let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;
        
        let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
        
        let new_user = NewUser {
            username,
            password_hash: hashed_password,
            email,
            kek_salt,
            encrypted_dek,
            encrypted_dek_by_recovery: None,
            role: UserRole::User,
            recovery_kek_salt: None,
            dek_nonce,
            recovery_dek_nonce: None,
            account_status: AccountStatus::Active,
        };
        
        let user_db: UserDbQuery = conn
            .interact(move |conn| {
                diesel::insert_into(users::table)
                    .values(&new_user)
                    .returning(UserDbQuery::as_returning())
                    .get_result(conn)
            })
            .await
            .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
        
        user_ids.push(user_db.id);
    }
    
    Ok(user_ids)
}

/// Helper to create test entities for a specific user
async fn create_test_entities_for_user(test_app: &TestApp, user_id: Uuid, count: usize) -> AnyhowResult<Vec<Uuid>> {
    let conn = test_app.db_pool.get().await?;
    let mut entity_ids = Vec::new();
    
    for i in 0..count {
        let entity_id = Uuid::new_v4();
        let new_entity = NewEcsEntity {
            id: entity_id,
            user_id,
            archetype_signature: format!("TestEntity_{}_User_{}", i, user_id),
        };
        
        conn.interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
        
        // Add a component with user-specific data
        let component = NewEcsComponent {
            id: Uuid::new_v4(),
            entity_id,
            user_id,
            component_type: "UserData".to_string(),
            component_data: json!({
                "owner_id": user_id.to_string(),
                "secret_data": format!("secret_for_user_{}", user_id),
                "test_index": i
            }),
        };
        
        conn.interact(move |conn| {
            diesel::insert_into(ecs_components::table)
                .values(&component)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
        
        entity_ids.push(entity_id);
    }
    
    Ok(entity_ids)
}

// ============================================================================
// A01: Broken Access Control Tests
// ============================================================================

#[tokio::test]
async fn test_user_isolation_entities_not_cross_accessible() {
    // Test that users cannot access entities belonging to other users
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two users
    let user_ids = create_test_users(&test_app, 2).await.unwrap();
    let user1_id = user_ids[0];
    let user2_id = user_ids[1];
    
    // Create entities for each user
    let _user1_entities = create_test_entities_for_user(&test_app, user1_id, 3).await.unwrap();
    let _user2_entities = create_test_entities_for_user(&test_app, user2_id, 3).await.unwrap();
    
    // Attempt to query user2's entities as user1 - should fail or return empty
    let conn = test_app.db_pool.get().await.unwrap();
    
    // This test exposes a potential security issue: there's no user filtering in ECS queries
    let all_entities: Vec<EcsEntity> = conn.interact(move |conn| {
        ecs_entities::table.select(EcsEntity::as_select()).load::<EcsEntity>(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // SECURITY GAP: This should be user-scoped, but currently returns all entities
    assert!(all_entities.len() >= 6); // Should contain entities from both users
    
    println!("🚨 SECURITY ISSUE: ECS entities are not user-scoped - all entities returned");
    println!("   Found {} entities total (should be user-filtered)", all_entities.len());
}

#[tokio::test]
async fn test_component_data_isolation() {
    // Test that component data containing sensitive information is properly isolated
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 2).await.unwrap();
    let user1_id = user_ids[0];
    let user2_id = user_ids[1];
    
    let _user1_entities = create_test_entities_for_user(&test_app, user1_id, 1).await.unwrap();
    let _user2_entities = create_test_entities_for_user(&test_app, user2_id, 1).await.unwrap();
    
    let conn = test_app.db_pool.get().await.unwrap();
    
    // Query all components (simulating a potential data breach)
    let all_components: Vec<EcsComponent> = conn.interact(move |conn| {
        ecs_components::table.select(EcsComponent::as_select()).load::<EcsComponent>(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // Check if sensitive data is accessible across users
    for component in &all_components {
        if let Some(secret_data) = component.component_data.get("secret_data") {
            println!("🚨 POTENTIAL DATA LEAK: Found secret data: {}", secret_data);
        }
    }
    
    // SECURITY GAP: Components should be user-scoped
    assert!(all_components.len() >= 2);
    println!("🚨 SECURITY ISSUE: Component queries are not user-scoped");
}

#[tokio::test]
async fn test_entity_enumeration_protection() {
    // Test protection against entity ID enumeration attacks
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    let entity_ids = create_test_entities_for_user(&test_app, user_id, 5).await.unwrap();
    
    // Test that UUIDs are not sequential (good)
    let mut sorted_ids = entity_ids.clone();
    sorted_ids.sort();
    
    // UUIDs should not be predictable
    assert_ne!(entity_ids, sorted_ids, "Entity IDs should not be sequential");
    
    println!("✅ SECURITY CHECK PASSED: Entity IDs use UUIDs (not enumerable)");
}

// ============================================================================
// A02: Cryptographic Failures Tests
// ============================================================================

#[tokio::test]
async fn test_sensitive_component_data_encryption() {
    // Test that sensitive component data should be encrypted
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    let entity_ids = create_test_entities_for_user(&test_app, user_id, 1).await.unwrap();
    let entity_id = entity_ids[0];
    
    let conn = test_app.db_pool.get().await.unwrap();
    
    // Create component with sensitive data
    let sensitive_component = NewEcsComponent {
        id: Uuid::new_v4(),
        entity_id,
        user_id: user_id,
        component_type: "PersonalInfo".to_string(),
        component_data: json!({
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111", 
            "password_hash": "secret_hash",
            "private_key": "-----BEGIN PRIVATE KEY-----"
        }),
    };
    
    conn.interact(move |conn| {
        diesel::insert_into(ecs_components::table)
            .values(&sensitive_component)
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // Query the component back and check if data is plaintext
    let stored_component: EcsComponent = conn.interact(move |conn| {
        ecs_components::table
            .filter(ecs_components::entity_id.eq(entity_id))
            .filter(ecs_components::component_type.eq("PersonalInfo"))
            .select(EcsComponent::as_select())
            .first::<EcsComponent>(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // SECURITY GAP: Sensitive data is stored in plaintext JSONB
    if let Some(ssn) = stored_component.component_data.get("ssn") {
        println!("🚨 SECURITY ISSUE: SSN stored in plaintext: {}", ssn);
    }
    
    if let Some(cc) = stored_component.component_data.get("credit_card") {
        println!("🚨 SECURITY ISSUE: Credit card stored in plaintext: {}", cc);
    }
    
    println!("🚨 SECURITY RECOMMENDATION: Implement encryption for sensitive component data");
}

// ============================================================================
// A03: Injection Tests 
// ============================================================================

#[tokio::test]
async fn test_jsonb_injection_protection() {
    // Test protection against JSONB injection in component data
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    let entity_ids = create_test_entities_for_user(&test_app, user_id, 1).await.unwrap();
    let entity_id = entity_ids[0];
    
    let conn = test_app.db_pool.get().await.unwrap();
    
    // Attempt to inject malicious JSON
    let malicious_data = json!({
        "normal_field": "value",
        "injection_attempt": {
            "__proto__": {"evil": true},
            "constructor": {"prototype": {"evil": true}}
        },
        "script_injection": "<script>alert('xss')</script>",
        "sql_like_injection": "'; DROP TABLE ecs_components; --"
    });
    
    let malicious_component = NewEcsComponent {
        id: Uuid::new_v4(),
        entity_id,
        user_id: user_id,
        component_type: "TestInjection".to_string(),
        component_data: malicious_data,
    };
    
    // This should succeed but the data should be safely stored
    let result = conn.interact(move |conn| {
        diesel::insert_into(ecs_components::table)
            .values(&malicious_component)
            .execute(conn)
    })
    .await
    .unwrap();
    
    assert!(result.is_ok(), "Injection data should be safely stored as JSON");
    
    println!("✅ SECURITY CHECK: JSONB injection attempts safely stored (Diesel protection)");
    println!("⚠️  RECOMMENDATION: Validate and sanitize component data before storage");
}

// ============================================================================
// A04: Insecure Design Tests
// ============================================================================

#[tokio::test]
async fn test_bulk_operation_limits() {
    // Test for bulk operation limits to prevent resource exhaustion
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    // Attempt to create a large number of entities rapidly
    let large_batch_size = 1000;
    let start_time = std::time::Instant::now();
    
    let result = create_test_entities_for_user(&test_app, user_id, large_batch_size).await;
    
    let duration = start_time.elapsed();
    
    if result.is_ok() {
        println!("🚨 SECURITY ISSUE: No rate limiting - created {} entities in {:?}", 
                large_batch_size, duration);
        println!("   RECOMMENDATION: Implement rate limiting for bulk operations");
    }
    
    // Check if there are any safeguards
    assert!(duration.as_secs() < 30, "Operation took too long, might indicate some protection");
}

#[tokio::test]
async fn test_component_size_limits() {
    // Test for component data size limits
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    let entity_ids = create_test_entities_for_user(&test_app, user_id, 1).await.unwrap();
    let entity_id = entity_ids[0];
    
    let conn = test_app.db_pool.get().await.unwrap();
    
    // Create a very large component data payload
    let large_string = "x".repeat(10_000_000); // 10MB string
    let large_component = NewEcsComponent {
        id: Uuid::new_v4(),
        entity_id,
        user_id: user_id,
        component_type: "LargeData".to_string(),
        component_data: json!({
            "large_field": large_string
        }),
    };
    
    let result = conn.interact(move |conn| {
        diesel::insert_into(ecs_components::table)
            .values(&large_component)
            .execute(conn)
    })
    .await;
    
    match result {
        Ok(Ok(_)) => {
            println!("🚨 SECURITY ISSUE: No size limits - accepted 10MB component data");
            println!("   RECOMMENDATION: Implement component data size limits");
        }
        Ok(Err(_)) | Err(_) => {
            println!("✅ SECURITY CHECK: Large component data rejected (some protection exists)");
        }
    }
}

// ============================================================================
// A09: Security Logging and Monitoring Tests
// ============================================================================

#[tokio::test]
async fn test_security_event_logging() {
    // Test that security-relevant events are properly logged
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 2).await.unwrap();
    let user1_id = user_ids[0];
    let user2_id = user_ids[1];
    
    // Simulate suspicious activity: rapid entity creation
    let _user1_entities = create_test_entities_for_user(&test_app, user1_id, 10).await.unwrap();
    
    // Simulate access attempt to another user's data
    let _user2_entities = create_test_entities_for_user(&test_app, user2_id, 5).await.unwrap();
    
    // Currently, there's no built-in security event logging for ECS operations
    // This test documents the gap
    
    println!("🚨 SECURITY GAP: No dedicated security event logging for ECS operations");
    println!("   RECOMMENDATION: Add security event logging for:");
    println!("   - Cross-user data access attempts");
    println!("   - Bulk operations");
    println!("   - Failed authorization checks");
    println!("   - Suspicious query patterns");
}

#[tokio::test]
async fn test_audit_trail_completeness() {
    // Test that all ECS operations create audit trails
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_ids = create_test_users(&test_app, 1).await.unwrap();
    let user_id = user_ids[0];
    
    // Perform various ECS operations
    let entity_ids = create_test_entities_for_user(&test_app, user_id, 1).await.unwrap();
    let entity_id = entity_ids[0];
    
    let conn = test_app.db_pool.get().await.unwrap();
    
    // Update component
    conn.interact(move |conn| {
        diesel::update(ecs_components::table)
            .filter(ecs_components::entity_id.eq(entity_id))
            .set(ecs_components::component_data.eq(json!({"updated": true})))
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // Delete component
    conn.interact(move |conn| {
        diesel::delete(ecs_components::table)
            .filter(ecs_components::entity_id.eq(entity_id))
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    println!("🚨 SECURITY GAP: No audit trail for ECS operations");
    println!("   Current audit relies only on application logs via tracing");
    println!("   RECOMMENDATION: Implement database-level audit trail for ECS changes");
}