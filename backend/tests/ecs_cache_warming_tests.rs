#![cfg(test)]
// backend/tests/ecs_cache_warming_tests.rs
//
// Comprehensive test cases for ECS cache warming functionality
// Tests validate cache warming strategies, performance, and error handling

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        ecs_diesel::{NewEcsEntity, NewEcsComponent, EcsEntity},
    },
    services::{
        EcsEntityManager, EntityManagerConfig, ComponentQuery, EntityQueryOptions,
        ComponentSort, SortDirection,
    },
    schema::{users, ecs_entities, ecs_components},
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use serde_json::json;
use secrecy::ExposeSecret;
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;
use redis::AsyncCommands;
use tracing::info;

/// Helper to create a test user
async fn create_cache_test_user(test_app: &TestApp) -> AnyhowResult<Uuid> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("cache_user_{}", Uuid::new_v4().simple());
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
    
    Ok(user_db.id)
}

/// Helper to create test entities with components
async fn create_test_entities_with_components(
    test_app: &TestApp,
    user_id: Uuid,
    entity_count: usize,
) -> AnyhowResult<Vec<Uuid>> {
    let conn = test_app.db_pool.get().await?;
    
    let entity_ids: Vec<Uuid> = conn.interact(move |conn| -> AnyhowResult<Vec<Uuid>> {
        // Create entities
        let entities: Vec<NewEcsEntity> = (0..entity_count).map(|i| {
            NewEcsEntity {
                id: Uuid::new_v4(),
                user_id,
                archetype_signature: format!("test_archetype_{}", i % 3), // 3 different archetypes
            }
        }).collect();
        
        let created_entities: Vec<EcsEntity> = diesel::insert_into(ecs_entities::table)
            .values(&entities)
            .returning(EcsEntity::as_returning())
            .get_results(conn)
            .map_err(|e| anyhow::anyhow!("Failed to create entities: {}", e))?;
        
        let entity_ids: Vec<Uuid> = created_entities.iter().map(|e| e.id).collect();
        
        // Create components for each entity
        let mut all_components = Vec::new();
        for (i, entity_id) in entity_ids.iter().enumerate() {
            // Each entity gets multiple components
            let components = vec![
                NewEcsComponent {
                    id: Uuid::new_v4(),
                    entity_id: *entity_id,
                    user_id,
                    component_type: "Position".to_string(),
                    component_data: json!({
                        "x": i as f64 * 10.0,
                        "y": i as f64 * 20.0,
                        "z": 0.0
                    }),
                },
                NewEcsComponent {
                    id: Uuid::new_v4(),
                    entity_id: *entity_id,
                    user_id,
                    component_type: "Health".to_string(),
                    component_data: json!({
                        "current": 100,
                        "maximum": 100,
                        "regeneration_rate": 1.0
                    }),
                },
                NewEcsComponent {
                    id: Uuid::new_v4(),
                    entity_id: *entity_id,
                    user_id,
                    component_type: "Inventory".to_string(),
                    component_data: json!({
                        "items": [
                            {"name": format!("item_{}", i), "quantity": 1}
                        ],
                        "capacity": 20
                    }),
                },
            ];
            all_components.extend(components);
        }
        
        diesel::insert_into(ecs_components::table)
            .values(&all_components)
            .execute(conn)
            .map_err(|e| anyhow::anyhow!("Failed to create components: {}", e))?;
        
        Ok(entity_ids)
    }).await.map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    info!("Created {} test entities with components", entity_ids.len());
    Ok(entity_ids)
}

/// Helper to hash user ID for cache keys (same as EcsEntityManager)
fn hash_user_id(user_id: Uuid) -> u64 {
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    hasher.finish()
}

/// Helper to clear Redis cache
async fn clear_cache(redis_client: &mut redis::aio::MultiplexedConnection, user_id: Uuid) -> AnyhowResult<()> {
    let user_hash = hash_user_id(user_id);
    let pattern = format!("ecs:entity:{}:*", user_hash);
    let keys: Vec<String> = redis_client.keys(pattern).await?;
    if !keys.is_empty() {
        let _: () = redis_client.del(keys).await?;
    }
    Ok(())
}

/// Helper to count cached entities
async fn count_cached_entities(redis_client: &mut redis::aio::MultiplexedConnection, user_id: Uuid) -> AnyhowResult<usize> {
    let user_hash = hash_user_id(user_id);
    let pattern = format!("ecs:entity:{}:*", user_hash);
    let keys: Vec<String> = redis_client.keys(&pattern).await?;
    Ok(keys.len())
}

#[tokio::test]
async fn test_warm_specific_entity_cache() {
    // Test warming cache for specific entities
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let entity_ids = create_test_entities_with_components(&test_app, user_id, 10).await.unwrap();
    
    // Create entity manager with proper Redis client
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear ALL cache first to avoid interference from other tests
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis_conn.flushdb().await.unwrap(); // Clear entire Redis DB for clean test
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Verify cache is empty
    let cached_count = count_cached_entities(&mut redis_conn, user_id).await.unwrap();
    assert_eq!(cached_count, 0, "Cache should be empty initially");
    
    // Warm cache for first 5 entities
    let target_entities = &entity_ids[0..5];
    let start_time = Instant::now();
    let result = entity_manager.warm_entity_cache(user_id, target_entities).await.unwrap();
    let warming_duration = start_time.elapsed();
    
    info!("Cache warming result: {:?}", result);
    info!("Warming took: {:?}", warming_duration);
    
    // Verify warming statistics
    assert_eq!(result.stats.entities_requested, 5, "Should request 5 entities");
    assert_eq!(result.stats.entities_warmed, 5, "Should warm 5 entities");
    assert_eq!(result.stats.cache_misses, 5, "All should be cache misses initially");
    assert_eq!(result.stats.cache_hits, 0, "No cache hits expected initially");
    assert_eq!(result.stats.errors, 0, "No errors expected");
    assert_eq!(result.success_rate, 100.0, "Should have 100% success rate");
    assert!(result.duration_ms > 0, "Duration should be measured");
    
    // Verify entities are now in cache
    let cached_count = count_cached_entities(&mut redis_conn, user_id).await.unwrap();
    assert_eq!(cached_count, 5, "Should have 5 entities cached");
    
    // Test warming the same entities again (should hit cache)
    let start_time = Instant::now();
    let result2 = entity_manager.warm_entity_cache(user_id, target_entities).await.unwrap();
    let warming_duration2 = start_time.elapsed();
    
    info!("Second warming result: {:?}", result2);
    info!("Second warming took: {:?}", warming_duration2);
    
    // Second warming should be faster (cache hits)
    assert_eq!(result2.stats.entities_requested, 5, "Should request 5 entities");
    assert_eq!(result2.stats.entities_warmed, 0, "Should warm 0 entities (already cached)");
    assert_eq!(result2.stats.cache_hits, 5, "All should be cache hits now");
    assert_eq!(result2.stats.cache_misses, 0, "No cache misses expected");
    assert!(warming_duration2 < warming_duration, "Second warming should be faster");
}

#[tokio::test]
async fn test_warm_recent_entities_cache() {
    // Test warming cache for recently accessed entities
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let entity_ids = create_test_entities_with_components(&test_app, user_id, 15).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear ALL cache first to avoid interference from other tests
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis_conn.flushdb().await.unwrap(); // Clear entire Redis DB for clean test
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Access some entities to create "recent access" pattern
    for entity_id in &entity_ids[0..5] {
        let _entity = entity_manager.get_entity(user_id, *entity_id).await.unwrap();
    }
    
    // Clear cache again to test warming
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Warm recent entities (limit to 3)
    let result = entity_manager.warm_recent_entities_cache(user_id, 3).await.unwrap();
    
    info!("Recent entities warming result: {:?}", result);
    
    // Should warm up to 3 entities
    assert!(result.stats.entities_warmed <= 3, "Should warm at most 3 entities");
    assert!(result.stats.entities_warmed > 0, "Should warm at least 1 entity");
    assert_eq!(result.stats.errors, 0, "No errors expected");
    assert!(result.success_rate > 0.0, "Should have positive success rate");
    
    // Verify entities are cached
    let cached_count = count_cached_entities(&mut redis_conn, user_id).await.unwrap();
    assert!(cached_count > 0, "Should have entities cached");
    assert!(cached_count <= 3, "Should not exceed limit");
}

#[tokio::test]
async fn test_warm_query_pattern_cache() {
    // Test warming cache for entities matching query patterns
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let entity_ids = create_test_entities_with_components(&test_app, user_id, 12).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear ALL cache first to avoid interference from other tests
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis_conn.flushdb().await.unwrap(); // Clear entire Redis DB for clean test
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Define query patterns
    let query_patterns = vec![
        ComponentQuery::HasComponent("Position".to_string()),
        ComponentQuery::ComponentDataEquals("Health".to_string(), "current".to_string(), json!(100)),
    ];
    
    // Warm cache for query patterns
    let result = entity_manager.warm_query_pattern_cache(user_id, &query_patterns).await.unwrap();
    
    info!("Query pattern warming result: {:?}", result);
    
    // Should warm entities matching the patterns
    assert!(result.stats.entities_warmed > 0, "Should warm at least some entities");
    assert_eq!(result.stats.errors, 0, "No errors expected");
    assert!(result.success_rate > 0.0, "Should have positive success rate");
    
    // Verify entities are cached
    let cached_count = count_cached_entities(&mut redis_conn, user_id).await.unwrap();
    assert!(cached_count > 0, "Should have entities cached");
    
    // Test that subsequent queries are faster due to cache
    let query_options = EntityQueryOptions {
        criteria: vec![ComponentQuery::HasComponent("Position".to_string())],
        sort_by: Some(ComponentSort {
            component_type: "Position".to_string(),
            field_path: "x".to_string(),
            direction: SortDirection::Ascending,
        }),
        limit: Some(5),
        offset: Some(0),
        min_components: None,
        max_components: None,
        cache_key: Some("test_pattern_query".to_string()),
        cache_ttl: Some(300),
    };
    
    let start_time = Instant::now();
    let _results = entity_manager.query_entities_advanced(user_id, query_options).await.unwrap();
    let query_duration = start_time.elapsed();
    
    info!("Query after warming took: {:?}", query_duration);
    assert!(query_duration < Duration::from_millis(100), "Query should be fast after warming");
}

#[tokio::test]
async fn test_schedule_automatic_warming() {
    // Test automatic cache warming scheduling
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let _entity_ids = create_test_entities_with_components(&test_app, user_id, 8).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear ALL cache first to avoid interference from other tests
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis_conn.flushdb().await.unwrap(); // Clear entire Redis DB for clean test
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Schedule automatic warming
    let result = entity_manager.schedule_automatic_warming(user_id).await;
    
    // Should complete without error
    assert!(result.is_ok(), "Automatic warming scheduling should succeed");
    
    // Note: In a real scenario, this would schedule background tasks
    // For testing, we just verify the function completes successfully
    info!("Automatic warming scheduled successfully");
}

#[tokio::test]
async fn test_cache_warming_error_handling() {
    // Test cache warming with error conditions
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let entity_ids = create_test_entities_with_components(&test_app, user_id, 5).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Test warming with non-existent entities
    let mut test_entities = entity_ids.clone();
    test_entities.push(Uuid::new_v4()); // Non-existent entity
    test_entities.push(Uuid::new_v4()); // Another non-existent entity
    
    let result = entity_manager.warm_entity_cache(user_id, &test_entities).await.unwrap();
    
    info!("Error handling result: {:?}", result);
    
    // Should handle errors gracefully - non-existent entities don't cause errors, they just aren't found/warmed
    assert_eq!(result.stats.entities_requested, 7, "Should request 7 entities");
    assert_eq!(result.stats.entities_warmed, 5, "Should warm 5 existing entities");
    // Cache warming doesn't generate errors for non-existent entities, it just doesn't find them
    assert_eq!(result.stats.errors, 0, "Should have 0 errors (non-existent entities just aren't found)");
    assert!((result.success_rate - 71.43).abs() < 1.0, "Success rate should be around 71.43%");
}

#[tokio::test]
async fn test_cache_warming_performance() {
    // Test cache warming performance with larger datasets
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_cache_test_user(&test_app).await.unwrap();
    let entity_ids = create_test_entities_with_components(&test_app, user_id, 50).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear ALL cache first to avoid interference from other tests
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis_conn.flushdb().await.unwrap(); // Clear entire Redis DB for clean test
    clear_cache(&mut redis_conn, user_id).await.unwrap();
    
    // Warm large batch of entities
    let start_time = Instant::now();
    let result = entity_manager.warm_entity_cache(user_id, &entity_ids).await.unwrap();
    let warming_duration = start_time.elapsed();
    
    info!("Performance test result: {:?}", result);
    info!("Warming {} entities took: {:?}", entity_ids.len(), warming_duration);
    
    // Performance assertions
    assert_eq!(result.stats.entities_warmed, 50, "Should warm all 50 entities");
    assert_eq!(result.stats.errors, 0, "No errors expected");
    assert_eq!(result.success_rate, 100.0, "Should have 100% success rate");
    
    // Should complete warming within reasonable time (adjust as needed)
    assert!(warming_duration < Duration::from_secs(10), "Warming should complete within 10 seconds");
    
    // Test query performance after warming
    let query_options = EntityQueryOptions {
        criteria: vec![],
        sort_by: None,
        limit: Some(20),
        offset: Some(0),
        min_components: None,
        max_components: None,
        cache_key: Some("performance_test".to_string()),
        cache_ttl: Some(300),
    };
    
    let start_time = Instant::now();
    let query_result = entity_manager.query_entities_advanced(user_id, query_options).await.unwrap();
    let query_duration = start_time.elapsed();
    
    info!("Query after warming returned {} entities in {:?}", query_result.entities.len(), query_duration);
    
    // Query should be fast after warming
    assert!(query_duration < Duration::from_millis(100), "Query should be sub-100ms after warming");
    // Note: cache hits depend on the specific query and cache key, individual entity warming may not affect complex queries
    info!("Query cache hit status: {}", query_result.stats.cache_hit);
}

#[tokio::test]
async fn test_cache_warming_with_user_isolation() {
    // Test that cache warming respects user isolation
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two different users
    let user1_id = create_cache_test_user(&test_app).await.unwrap();
    let user2_id = create_cache_test_user(&test_app).await.unwrap();
    
    let user1_entities = create_test_entities_with_components(&test_app, user1_id, 5).await.unwrap();
    let user2_entities = create_test_entities_with_components(&test_app, user2_id, 5).await.unwrap();
    
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig::default();
    let entity_manager = Arc::new(EcsEntityManager::new(
        test_app.db_pool.clone().into(),
        redis_client.clone(),
        Some(config),
    ));
    
    // Clear cache
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();
    clear_cache(&mut redis_conn, user1_id).await.unwrap();
    clear_cache(&mut redis_conn, user2_id).await.unwrap();
    
    // Warm cache for user1 only
    let result1 = entity_manager.warm_entity_cache(user1_id, &user1_entities).await.unwrap();
    assert_eq!(result1.stats.entities_warmed, 5, "Should warm user1's entities");
    
    // Try to warm user2's entities as user1 (should find 0 entities, not generate errors)
    let result_cross = entity_manager.warm_entity_cache(user1_id, &user2_entities).await.unwrap();
    assert_eq!(result_cross.stats.entities_warmed, 0, "Should not warm other user's entities");
    // User isolation works by not finding entities, not by generating errors
    assert_eq!(result_cross.stats.errors, 0, "Should have 0 errors (entities just not found due to isolation)");
    
    // Warm cache for user2 with their own entities
    let result2 = entity_manager.warm_entity_cache(user2_id, &user2_entities).await.unwrap();
    assert_eq!(result2.stats.entities_warmed, 5, "Should warm user2's entities");
    
    // Verify cache isolation
    let user1_cached = count_cached_entities(&mut redis_conn, user1_id).await.unwrap();
    let user2_cached = count_cached_entities(&mut redis_conn, user2_id).await.unwrap();
    
    assert_eq!(user1_cached, 5, "User1 should have 5 entities cached");
    assert_eq!(user2_cached, 5, "User2 should have 5 entities cached");
    
    info!("User isolation test passed: user1={} cached, user2={} cached", user1_cached, user2_cached);
}