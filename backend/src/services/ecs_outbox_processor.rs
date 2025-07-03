// backend/src/services/ecs_outbox_processor.rs
//
// ECS Outbox Processor
//
// This service implements the transactional outbox pattern for reliable event delivery.
// It processes events from the ecs_outbox table with concurrent workers and retry logic.

use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use serde_json::{Value as JsonValue, json};
use tracing::{info, warn, debug, error, instrument};
use tokio::time::{sleep, Instant};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

use crate::{
    PgPool,
    errors::AppError,
    models::ecs_diesel::{EcsOutboxEvent, NewEcsOutboxEvent, UpdateEcsOutboxEvent},
    schema::ecs_outbox,
};

use diesel::prelude::*;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods, QueryableByName};

/// Helper struct for SQL query results
#[derive(QueryableByName)]
struct EventIdResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}

/// Configuration for the outbox processor
#[derive(Debug, Clone)]
pub struct OutboxProcessorConfig {
    /// Number of concurrent worker threads
    pub worker_count: usize,
    /// Polling interval for new events (seconds)
    pub polling_interval_secs: u64,
    /// Batch size for processing events
    pub batch_size: i64,
    /// Base retry delay in seconds
    pub base_retry_delay_secs: u64,
    /// Maximum retry delay in seconds
    pub max_retry_delay_secs: u64,
    /// Whether to enable dead letter queue
    pub enable_dead_letter_queue: bool,
    /// Maximum age for events in dead letter queue (hours)
    pub dead_letter_max_age_hours: u64,
}

impl Default for OutboxProcessorConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            polling_interval_secs: 5,
            batch_size: 50,
            base_retry_delay_secs: 30,
            max_retry_delay_secs: 3600, // 1 hour
            enable_dead_letter_queue: true,
            dead_letter_max_age_hours: 72, // 3 days
        }
    }
}

/// Result of processing an outbox event
#[derive(Debug, Clone)]
pub struct EventProcessingResult {
    pub event_id: Uuid,
    pub success: bool,
    pub error_message: Option<String>,
    pub should_retry: bool,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Statistics about outbox processing
#[derive(Debug, Clone)]
pub struct OutboxProcessingStats {
    pub events_processed: u64,
    pub events_succeeded: u64,
    pub events_failed: u64,
    pub events_retried: u64,
    pub events_dead_lettered: u64,
    pub average_processing_time_ms: f64,
    pub backlog_size: u64,
}

/// Event handler trait for processing different event types
#[async_trait::async_trait]
pub trait OutboxEventHandler: Send + Sync {
    /// Process a single outbox event
    async fn handle_event(&self, event: &EcsOutboxEvent) -> Result<(), AppError>;
    
    /// Get supported event types
    fn supported_event_types(&self) -> Vec<String>;
}

/// ECS Outbox Processor with concurrent workers and retry logic
pub struct EcsOutboxProcessor {
    db_pool: Arc<PgPool>,
    config: OutboxProcessorConfig,
    event_handlers: std::collections::HashMap<String, Arc<dyn OutboxEventHandler>>,
    stats: Arc<tokio::sync::RwLock<OutboxProcessingStats>>,
    shutdown_signal: Arc<tokio::sync::Notify>,
}

impl EcsOutboxProcessor {
    /// Create a new outbox processor
    pub fn new(
        db_pool: Arc<PgPool>,
        config: Option<OutboxProcessorConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        info!("Initializing ECS Outbox Processor with config: {:?}", config);
        
        Self {
            db_pool,
            config,
            event_handlers: std::collections::HashMap::new(),
            stats: Arc::new(tokio::sync::RwLock::new(OutboxProcessingStats {
                events_processed: 0,
                events_succeeded: 0,
                events_failed: 0,
                events_retried: 0,
                events_dead_lettered: 0,
                average_processing_time_ms: 0.0,
                backlog_size: 0,
            })),
            shutdown_signal: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Register an event handler for specific event types
    pub fn register_handler(&mut self, handler: Arc<dyn OutboxEventHandler>) {
        for event_type in handler.supported_event_types() {
            info!("Registering handler for event type: {}", event_type);
            self.event_handlers.insert(event_type, handler.clone());
        }
    }

    /// Add an event to the outbox
    #[instrument(skip(self, event_data), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn add_event(
        &self,
        user_id: Uuid,
        event_type: String,
        entity_id: Option<Uuid>,
        component_type: Option<String>,
        event_data: JsonValue,
        aggregate_id: Option<Uuid>,
        aggregate_type: Option<String>,
    ) -> Result<Uuid, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let event_id = conn.interact({
            let user_id = user_id;
            let event_type = event_type.clone();
            let entity_id = entity_id;
            let component_type = component_type.clone();
            let event_data = event_data.clone();
            let aggregate_id = aggregate_id;
            let aggregate_type = aggregate_type.clone();
            
            move |conn| -> Result<Uuid, AppError> {
                let new_event = NewEcsOutboxEvent {
                    user_id,
                    event_type,
                    entity_id,
                    component_type,
                    event_data,
                    aggregate_id,
                    aggregate_type,
                    max_retries: Some(3),
                };

                let event: EcsOutboxEvent = diesel::insert_into(ecs_outbox::table)
                    .values(&new_event)
                    .returning(EcsOutboxEvent::as_returning())
                    .get_result(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                Ok(event.id)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)?;

        debug!("Added event {} to outbox for user {}", event_id, user_id);
        Ok(event_id)
    }

    /// Start the outbox processor with concurrent workers
    pub async fn start(&self) -> Result<(), AppError> {
        info!("Starting ECS Outbox Processor with {} workers", self.config.worker_count);

        let mut handles = Vec::new();

        // Start worker tasks
        for worker_id in 0..self.config.worker_count {
            let handle = self.start_worker(worker_id).await;
            handles.push(handle);
        }

        // Start cleanup task if dead letter queue is enabled
        if self.config.enable_dead_letter_queue {
            let cleanup_handle = self.start_cleanup_task().await;
            handles.push(cleanup_handle);
        }

        // Wait for shutdown signal
        self.shutdown_signal.notified().await;
        
        info!("Shutting down ECS Outbox Processor");
        
        // Cancel all worker tasks
        for handle in handles {
            handle.abort();
        }

        Ok(())
    }

    /// Signal shutdown to all workers
    pub fn shutdown(&self) {
        self.shutdown_signal.notify_waiters();
    }

    /// Get current processing statistics
    pub async fn get_stats(&self) -> OutboxProcessingStats {
        self.stats.read().await.clone()
    }

    // Private methods

    async fn start_worker(&self, worker_id: usize) -> tokio::task::JoinHandle<()> {
        let db_pool = self.db_pool.clone();
        let config = self.config.clone();
        let event_handlers = self.event_handlers.clone();
        let stats = self.stats.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        tokio::spawn(async move {
            info!("Starting outbox worker {}", worker_id);

            loop {
                tokio::select! {
                    _ = shutdown_signal.notified() => {
                        info!("Worker {} received shutdown signal", worker_id);
                        break;
                    }
                    _ = Self::worker_loop(
                        worker_id,
                        &db_pool,
                        &config,
                        &event_handlers,
                        &stats,
                    ) => {
                        // Worker loop completed, restart after a short delay
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            info!("Worker {} stopped", worker_id);
        })
    }

    async fn worker_loop(
        worker_id: usize,
        db_pool: &PgPool,
        config: &OutboxProcessorConfig,
        event_handlers: &std::collections::HashMap<String, Arc<dyn OutboxEventHandler>>,
        stats: &Arc<tokio::sync::RwLock<OutboxProcessingStats>>,
    ) {
        loop {
            match Self::process_batch(db_pool, config, event_handlers, worker_id).await {
                Ok(processed_count) => {
                    if processed_count == 0 {
                        // No events to process, wait before next poll
                        sleep(Duration::from_secs(config.polling_interval_secs)).await;
                    }
                    
                    // Update backlog size
                    if let Ok(backlog_size) = Self::get_backlog_size(db_pool).await {
                        let mut stats_guard = stats.write().await;
                        stats_guard.backlog_size = backlog_size;
                    }
                }
                Err(e) => {
                    error!("Worker {} error during batch processing: {}", worker_id, e);
                    sleep(Duration::from_secs(config.polling_interval_secs)).await;
                }
            }
        }
    }

    async fn process_batch(
        db_pool: &PgPool,
        config: &OutboxProcessorConfig,
        event_handlers: &std::collections::HashMap<String, Arc<dyn OutboxEventHandler>>,
        worker_id: usize,
    ) -> Result<usize, AppError> {
        let events = Self::fetch_and_claim_events(db_pool, config.batch_size, worker_id).await?;
        
        if events.is_empty() {
            return Ok(0);
        }

        let event_count = events.len();
        debug!("Processing batch of {} events", event_count);

        for event in events {
            let start_time = Instant::now();
            let result = Self::process_single_event(&event, event_handlers).await;
            let processing_time = start_time.elapsed();

            Self::update_event_status(db_pool, &event, result).await?;

            debug!("Processed event {} in {:?}", event.id, processing_time);
        }

        Ok(event_count)
    }

    async fn fetch_and_claim_events(
        db_pool: &PgPool,
        batch_size: i64,
        worker_id: usize,
    ) -> Result<Vec<EcsOutboxEvent>, AppError> {
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| -> Result<Vec<EcsOutboxEvent>, AppError> {
            // Use a transaction to atomically claim events
            conn.build_transaction()
                .run(|conn| -> Result<Vec<EcsOutboxEvent>, diesel::result::Error> {
                    // First, claim events by setting them to "processing" status with FOR UPDATE SKIP LOCKED
                    let claimed_ids: Vec<uuid::Uuid> = diesel::sql_query(
                        "UPDATE ecs_outbox 
                         SET delivery_status = 'processing', 
                             retry_count = retry_count,
                             next_retry_at = NULL
                         WHERE id IN (
                             SELECT id FROM ecs_outbox 
                             WHERE (delivery_status = 'pending' 
                                    OR (delivery_status = 'failed' 
                                        AND (next_retry_at <= NOW() OR next_retry_at IS NULL)))
                             ORDER BY user_id ASC, sequence_number ASC 
                             LIMIT $1
                             FOR UPDATE SKIP LOCKED
                         )
                         RETURNING id"
                    )
                    .bind::<diesel::sql_types::BigInt, _>(batch_size)
                    .load::<EventIdResult>(conn)?
                    .into_iter()
                    .map(|result| result.id)
                    .collect();

                    if claimed_ids.is_empty() {
                        return Ok(vec![]);
                    }

                    debug!("Worker {} claimed {} events", worker_id, claimed_ids.len());

                    // Now fetch the full event data for the claimed events
                    let events: Vec<EcsOutboxEvent> = ecs_outbox::table
                        .filter(ecs_outbox::id.eq_any(&claimed_ids))
                        .order((ecs_outbox::user_id.asc(), ecs_outbox::sequence_number.asc()))
                        .select(EcsOutboxEvent::as_select())
                        .load(conn)?;

                    Ok(events)
                })
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    async fn process_single_event(
        event: &EcsOutboxEvent,
        event_handlers: &std::collections::HashMap<String, Arc<dyn OutboxEventHandler>>,
    ) -> EventProcessingResult {
        if let Some(handler) = event_handlers.get(&event.event_type) {
            match handler.handle_event(event).await {
                Ok(()) => EventProcessingResult {
                    event_id: event.id,
                    success: true,
                    error_message: None,
                    should_retry: false,
                    next_retry_at: None,
                },
                Err(e) => {
                    let should_retry = event.retry_count < event.max_retries;
                    let next_retry_at = if should_retry {
                        Some(Self::calculate_next_retry(event.retry_count, 30, 3600))
                    } else {
                        None
                    };

                    EventProcessingResult {
                        event_id: event.id,
                        success: false,
                        error_message: Some(e.to_string()),
                        should_retry,
                        next_retry_at,
                    }
                }
            }
        } else {
            warn!("No handler registered for event type: {}", event.event_type);
            EventProcessingResult {
                event_id: event.id,
                success: false,
                error_message: Some(format!("No handler for event type: {}", event.event_type)),
                should_retry: false,
                next_retry_at: None,
            }
        }
    }

    async fn update_event_status(
        db_pool: &PgPool,
        event: &EcsOutboxEvent,
        result: EventProcessingResult,
    ) -> Result<(), AppError> {
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let event_id = event.id;
        let retry_count = event.retry_count;

        conn.interact({
            let result = result.clone();
            
            move |conn| -> Result<(), AppError> {
                let update = if result.success {
                    UpdateEcsOutboxEvent {
                        processed_at: Some(Some(Utc::now())),
                        delivery_status: Some("delivered".to_string()),
                        retry_count: None,
                        next_retry_at: None,
                        error_message: None,
                    }
                } else if result.should_retry {
                    UpdateEcsOutboxEvent {
                        processed_at: None,
                        delivery_status: Some("failed".to_string()),
                        retry_count: Some(retry_count + 1),
                        next_retry_at: Some(result.next_retry_at),
                        error_message: Some(result.error_message),
                    }
                } else {
                    UpdateEcsOutboxEvent {
                        processed_at: Some(Some(Utc::now())),
                        delivery_status: Some("dead_letter".to_string()),
                        retry_count: None,
                        next_retry_at: None,
                        error_message: Some(result.error_message),
                    }
                };

                diesel::update(ecs_outbox::table.filter(ecs_outbox::id.eq(event_id)))
                    .set(&update)
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                Ok(())
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    async fn get_backlog_size(db_pool: &PgPool) -> Result<u64, AppError> {
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| -> Result<u64, AppError> {
            let count: i64 = ecs_outbox::table
                .filter(ecs_outbox::delivery_status.eq("pending"))
                .count()
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            Ok(count as u64)
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    async fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let db_pool = self.db_pool.clone();
        let config = self.config.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        tokio::spawn(async move {
            info!("Starting dead letter cleanup task");

            loop {
                tokio::select! {
                    _ = shutdown_signal.notified() => {
                        info!("Cleanup task received shutdown signal");
                        break;
                    }
                    _ = sleep(Duration::from_secs(3600)) => { // Run every hour
                        if let Err(e) = Self::cleanup_old_events(&db_pool, &config).await {
                            error!("Error during cleanup: {}", e);
                        }
                    }
                }
            }

            info!("Cleanup task stopped");
        })
    }

    async fn cleanup_old_events(
        db_pool: &PgPool,
        config: &OutboxProcessorConfig,
    ) -> Result<(), AppError> {
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let cutoff_time = Utc::now() - chrono::Duration::hours(config.dead_letter_max_age_hours as i64);

        conn.interact(move |conn| -> Result<(), AppError> {
            let deleted_count = diesel::delete(
                ecs_outbox::table
                    .filter(ecs_outbox::delivery_status.eq("dead_letter"))
                    .filter(ecs_outbox::created_at.lt(cutoff_time))
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if deleted_count > 0 {
                info!("Cleaned up {} old dead letter events", deleted_count);
            }

            Ok(())
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    fn calculate_next_retry(retry_count: i32, base_delay_secs: u64, max_delay_secs: u64) -> DateTime<Utc> {
        let exponential_delay = base_delay_secs * 2_u64.pow(retry_count as u32);
        let delay_secs = exponential_delay.min(max_delay_secs);
        Utc::now() + chrono::Duration::seconds(delay_secs as i64)
    }

    fn hash_user_id(user_id: Uuid) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        hasher.finish()
    }
}

/// Default event handler that logs all events
pub struct LoggingEventHandler;

#[async_trait::async_trait]
impl OutboxEventHandler for LoggingEventHandler {
    async fn handle_event(&self, event: &EcsOutboxEvent) -> Result<(), AppError> {
        info!("Processing event {}: {} for entity {:?}", 
              event.id, event.event_type, event.entity_id);
        
        // Simulate processing time
        sleep(Duration::from_millis(10)).await;
        
        Ok(())
    }

    fn supported_event_types(&self) -> Vec<String> {
        vec!["*".to_string()] // Handle all event types
    }
}