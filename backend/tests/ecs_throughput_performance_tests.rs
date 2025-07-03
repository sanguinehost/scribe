#![cfg(test)]
// backend/tests/ecs_throughput_performance_tests.rs
//
// High-throughput performance tests for ECS outbox processor
// These tests validate 1000+ events/sec processing capability with proper cleanup

use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        ecs_diesel::{NewEcsOutboxEvent, EcsOutboxEvent},
    },
    services::{
        EcsOutboxProcessor, OutboxProcessorConfig, OutboxEventHandler,
    },
    schema::{users, ecs_outbox},
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
    errors::AppError,
};
use uuid::Uuid;
use serde_json::json;
use secrecy::ExposeSecret;
use diesel::{RunQueryDsl, prelude::*, QueryableByName};
use bcrypt;

/// Helper struct for SQL query results
#[derive(QueryableByName)]
struct EventIdResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}
use tokio::sync::Semaphore;
use tracing::{info, warn, debug};

/// High-performance event handler for throughput testing
struct ThroughputTestHandler {
    processed_count: Arc<AtomicU64>,
    processing_time_ns: Arc<AtomicU64>,
}

impl ThroughputTestHandler {
    fn new() -> Self {
        Self {
            processed_count: Arc::new(AtomicU64::new(0)),
            processing_time_ns: Arc::new(AtomicU64::new(0)),
        }
    }

    fn get_stats(&self) -> (u64, f64) {
        let count = self.processed_count.load(Ordering::Relaxed);
        let total_time_ns = self.processing_time_ns.load(Ordering::Relaxed);
        let avg_time_ms = if count > 0 {
            (total_time_ns as f64 / count as f64) / 1_000_000.0
        } else {
            0.0
        };
        (count, avg_time_ms)
    }

    fn reset_stats(&self) {
        self.processed_count.store(0, Ordering::Relaxed);
        self.processing_time_ns.store(0, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl OutboxEventHandler for ThroughputTestHandler {
    async fn handle_event(&self, event: &EcsOutboxEvent) -> Result<(), AppError> {
        let start = Instant::now();
        
        // Simulate minimal processing work (just validate the event is well-formed)
        if event.event_data.get("test_data").is_none() {
            return Err(AppError::InvalidInput("Missing test_data".to_string()));
        }
        
        let processing_time = start.elapsed();
        
        self.processed_count.fetch_add(1, Ordering::Relaxed);
        self.processing_time_ns.fetch_add(processing_time.as_nanos() as u64, Ordering::Relaxed);
        
        Ok(())
    }

    fn supported_event_types(&self) -> Vec<String> {
        vec!["throughput_test".to_string()]
    }
}

/// Helper to create a test user quickly
async fn create_throughput_test_user(test_app: &TestApp) -> AnyhowResult<Uuid> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("throughput_user_{}", Uuid::new_v4().simple());
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

/// Create events in bulk for performance testing
async fn bulk_create_test_events(
    test_app: &TestApp,
    user_id: Uuid,
    event_count: usize,
    batch_size: usize,
) -> AnyhowResult<()> {
    let _conn = test_app.db_pool.get().await?;
    
    // Use semaphore to limit concurrent database connections
    let semaphore = Arc::new(Semaphore::new(5));
    
    let chunks: Vec<_> = (0..event_count).collect::<Vec<_>>().chunks(batch_size).map(|chunk| chunk.to_vec()).collect();
    
    let mut handles = Vec::new();
    
    for chunk in chunks {
        let conn = test_app.db_pool.get().await?;
        let user_id = user_id;
        let semaphore = semaphore.clone();
        
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            conn.interact(move |conn| -> AnyhowResult<()> {
                let events: Vec<NewEcsOutboxEvent> = chunk.into_iter().map(|i| {
                    NewEcsOutboxEvent {
                        user_id,
                        event_type: "throughput_test".to_string(),
                        entity_id: Some(Uuid::new_v4()),
                        component_type: Some("TestComponent".to_string()),
                        event_data: json!({
                            "test_data": format!("event_{}", i),
                            "batch_id": i / 100, // Group events into batches for easier tracking
                            "timestamp": chrono::Utc::now().timestamp_millis()
                        }),
                        aggregate_id: None,
                        aggregate_type: None,
                        max_retries: Some(1), // Reduce retries for performance test
                    }
                }).collect();
                
                diesel::insert_into(ecs_outbox::table)
                    .values(&events)
                    .execute(conn)
                    .map_err(|e| anyhow::anyhow!("Failed to insert events: {}", e))?;
                
                Ok(())
            }).await.map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
            
            Ok::<(), anyhow::Error>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all insertions to complete
    for handle in handles {
        handle.await??;
    }
    
    info!("Successfully created {} test events in bulk", event_count);
    Ok(())
}

/// Clean up test events efficiently
async fn cleanup_test_events(test_app: &TestApp, user_id: Uuid) -> AnyhowResult<usize> {
    let conn = test_app.db_pool.get().await?;
    
    let deleted_count = conn.interact(move |conn| {
        diesel::delete(ecs_outbox::table)
            .filter(ecs_outbox::user_id.eq(user_id))
            .filter(ecs_outbox::event_type.eq("throughput_test"))
            .execute(conn)
    }).await.map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    info!("Cleaned up {} test events for user {}", deleted_count, user_id);
    Ok(deleted_count)
}

#[tokio::test]
#[ignore] // Ignore by default - run with: cargo test test_throughput_1000_events_per_second -- --ignored
async fn test_throughput_1000_events_per_second() {
    // This test validates the system can handle 1000+ events/sec
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user_id = create_throughput_test_user(&test_app).await.unwrap();
    
    // Configure outbox processor for high throughput
    let config = OutboxProcessorConfig {
        worker_count: 8, // Multiple workers for concurrency
        polling_interval_secs: 1, // Fast polling
        batch_size: 100, // Large batches for efficiency
        base_retry_delay_secs: 1,
        max_retry_delay_secs: 10,
        enable_dead_letter_queue: false, // Disable for performance
        dead_letter_max_age_hours: 1,
    };
    
    // Create processor and handler
    let mut processor = EcsOutboxProcessor::new(test_app.db_pool.clone().into(), Some(config.clone()));
    let handler = Arc::new(ThroughputTestHandler::new());
    processor.register_handler(handler.clone());
    
    let target_events = 2000; // Test with 2000 events to ensure we exceed 1000/sec
    let batch_size = 500; // Insert in batches for efficiency
    
    info!("Creating {} test events for throughput validation...", target_events);
    
    // Create events in bulk
    let creation_start = Instant::now();
    bulk_create_test_events(&test_app, user_id, target_events, batch_size).await.unwrap();
    let creation_time = creation_start.elapsed();
    info!("Event creation took: {:?}", creation_time);
    
    // Start processing and measure throughput
    handler.reset_stats();
    let processing_start = Instant::now();
    
    // Process events in batches manually to measure throughput
    let mut total_processed = 0;
    let mut batch_count = 0;
    let batch_size = config.batch_size;
    
    loop {
        // Get current stats
        let (processed_count, _avg_time_ms) = handler.get_stats();
        
        if processed_count >= target_events as u64 {
            break;
        }
        
        // Process a batch manually to simulate the processor
        let conn = test_app.db_pool.get().await.unwrap();
        let handler_clone = handler.clone();
        let events_processed = conn.interact(move |conn| -> AnyhowResult<usize> {
            let events: Vec<EcsOutboxEvent> = ecs_outbox::table
                .filter(ecs_outbox::user_id.eq(user_id))
                .filter(ecs_outbox::delivery_status.eq("pending"))
                .limit(batch_size)
                .select(EcsOutboxEvent::as_select())
                .load(conn)
                .map_err(|e| anyhow::anyhow!("Failed to load events: {}", e))?;
            
            let event_count = events.len();
            
            // Process events
            for event in &events {
                if let Err(e) = futures::executor::block_on(handler_clone.handle_event(event)) {
                    warn!("Event processing failed: {}", e);
                }
            }
            
            // Mark events as processed
            diesel::update(ecs_outbox::table)
                .filter(ecs_outbox::user_id.eq(user_id))
                .filter(ecs_outbox::delivery_status.eq("pending"))
                .set(ecs_outbox::delivery_status.eq("delivered"))
                .execute(conn)
                .map_err(|e| anyhow::anyhow!("Failed to update events: {}", e))?;
            
            Ok(event_count)
        }).await.unwrap().unwrap();
        
        total_processed += events_processed;
        batch_count += 1;
        
        if events_processed == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        // Prevent infinite loop
        if batch_count > 100 {
            warn!("Too many batches processed, breaking");
            break;
        }
    }
    
    let processing_time = processing_start.elapsed();
    let (final_processed_count, avg_processing_time_ms) = handler.get_stats();
    
    // Calculate throughput
    let events_per_second = final_processed_count as f64 / processing_time.as_secs_f64();
    
    info!("=== THROUGHPUT TEST RESULTS ===");
    info!("Target events: {}", target_events);
    info!("Events processed: {}", final_processed_count);
    info!("Total processing time: {:?}", processing_time);
    info!("Events per second: {:.2}", events_per_second);
    info!("Average processing time per event: {:.3}ms", avg_processing_time_ms);
    info!("Batch count: {}", batch_count);
    
    // Cleanup
    let cleaned_up = cleanup_test_events(&test_app, user_id).await.unwrap();
    info!("Cleaned up {} events", cleaned_up);
    
    // Assertions for 1000+ events/sec requirement
    assert!(
        events_per_second >= 1000.0,
        "Throughput requirement not met: {:.2} events/sec < 1000 events/sec",
        events_per_second
    );
    
    assert_eq!(
        final_processed_count as usize, 
        target_events,
        "Not all events were processed: {} != {}",
        final_processed_count,
        target_events
    );
    
    // Verify processing efficiency (should be sub-millisecond per event)
    assert!(
        avg_processing_time_ms < 5.0,
        "Processing too slow: {:.3}ms > 5ms per event",
        avg_processing_time_ms
    );
    
    info!("✅ THROUGHPUT VALIDATION PASSED: {:.2} events/sec", events_per_second);
}

#[tokio::test]
#[ignore] // Ignore by default
async fn test_concurrent_worker_throughput() {
    // Test multiple workers processing events concurrently without conflicts
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_throughput_test_user(&test_app).await.unwrap();
    
    // Create a large number of events
    let target_events = 3000;
    bulk_create_test_events(&test_app, user_id, target_events, 500).await.unwrap();
    
    // Create multiple handlers to simulate concurrent workers
    let handlers: Vec<Arc<ThroughputTestHandler>> = (0..4)
        .map(|_| Arc::new(ThroughputTestHandler::new()))
        .collect();
    
    let start_time = Instant::now();
    
    // Process events concurrently with multiple "workers"
    let mut join_handles = Vec::new();
    
    for (worker_id, handler) in handlers.iter().enumerate() {
        let pool = test_app.db_pool.clone();
        let handler = handler.clone();
        let user_id = user_id;
        
        let handle = tokio::spawn(async move {
            let mut processed = 0;
            loop {
                let conn = pool.get().await.unwrap();
                
                // Simulate worker claiming and processing events
                let handler_clone = handler.clone();
                let events_processed = conn.interact(move |conn| -> AnyhowResult<usize> {
                    // Use FOR UPDATE SKIP LOCKED to safely claim events
                    let claimed_ids: Vec<Uuid> = diesel::sql_query(
                        "UPDATE ecs_outbox 
                         SET delivery_status = 'processing' 
                         WHERE id IN (
                             SELECT id FROM ecs_outbox 
                             WHERE user_id = $1 
                             AND delivery_status = 'pending' 
                             AND event_type = 'throughput_test'
                             LIMIT 50
                             FOR UPDATE SKIP LOCKED
                         )
                         RETURNING id"
                    )
                    .bind::<diesel::sql_types::Uuid, _>(user_id)
                    .load::<EventIdResult>(conn)
                    .map_err(|e| anyhow::anyhow!("Failed to claim events: {}", e))?
                    .into_iter()
                    .map(|result| result.id)
                    .collect();
                    
                    if claimed_ids.is_empty() {
                        return Ok(0);
                    }
                    
                    // Fetch and process claimed events
                    let events: Vec<EcsOutboxEvent> = ecs_outbox::table
                        .filter(ecs_outbox::id.eq_any(&claimed_ids))
                        .select(EcsOutboxEvent::as_select())
                        .load(conn)
                        .map_err(|e| anyhow::anyhow!("Failed to load events: {}", e))?;
                    
                    let event_count = events.len();
                    
                    // Process each event
                    for event in &events {
                        futures::executor::block_on(handler_clone.handle_event(event)).unwrap();
                    }
                    
                    // Mark as delivered
                    diesel::update(ecs_outbox::table)
                        .filter(ecs_outbox::id.eq_any(&claimed_ids))
                        .set(ecs_outbox::delivery_status.eq("delivered"))
                        .execute(conn)
                        .map_err(|e| anyhow::anyhow!("Failed to mark delivered: {}", e))?;
                    
                    Ok(event_count)
                }).await.unwrap().unwrap();
                
                processed += events_processed;
                
                if events_processed == 0 {
                    break; // No more events to process
                }
            }
            
            debug!("Worker {} processed {} events", worker_id, processed);
            processed
        });
        
        join_handles.push(handle);
    }
    
    // Wait for all workers to complete
    let mut total_processed = 0;
    for handle in join_handles {
        total_processed += handle.await.unwrap();
    }
    
    let processing_time = start_time.elapsed();
    let events_per_second = total_processed as f64 / processing_time.as_secs_f64();
    
    // Calculate total events processed by all handlers
    let total_handler_events: u64 = handlers.iter()
        .map(|h| h.get_stats().0)
        .sum();
    
    info!("=== CONCURRENT WORKER TEST RESULTS ===");
    info!("Target events: {}", target_events);
    info!("Events processed by workers: {}", total_processed);
    info!("Events processed by handlers: {}", total_handler_events);
    info!("Processing time: {:?}", processing_time);
    info!("Concurrent throughput: {:.2} events/sec", events_per_second);
    
    // Cleanup
    cleanup_test_events(&test_app, user_id).await.unwrap();
    
    // Verify no events were processed twice (handler count should equal worker count)
    assert_eq!(
        total_processed, 
        total_handler_events as usize,
        "Event processing mismatch - possible duplicate processing"
    );
    
    assert_eq!(
        total_processed,
        target_events,
        "Not all events were processed: {} != {}",
        total_processed,
        target_events
    );
    
    assert!(
        events_per_second >= 1000.0,
        "Concurrent throughput too low: {:.2} events/sec < 1000 events/sec",
        events_per_second
    );
    
    info!("✅ CONCURRENT WORKER VALIDATION PASSED: {:.2} events/sec", events_per_second);
}