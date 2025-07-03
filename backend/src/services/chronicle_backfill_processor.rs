// backend/src/services/chronicle_backfill_processor.rs
//
// Chronicle Backfill Processing Service
//
// This service handles the idempotent processing of historical chronicle events
// into ECS state, supporting chronological order, checkpointing, and deduplication.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::json;
use tracing::{info, warn, debug, error, instrument};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        chronicle::PlayerChronicle,
        chronicle_event::{ChronicleEvent, EventFilter, EventOrderBy},
    },
    services::{
        ChronicleService,
        ChronicleEcsTranslator,
        chronicle_ecs_translator::TranslationResult,
    },
    schema::ecs_backfill_checkpoints,
};

use diesel::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Hash user ID for privacy-preserving logging (GDPR/privacy compliant)
fn hash_user_id(user_id: Uuid) -> u64 {
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    hasher.finish()
}

/// Checkpoint tracking for backfill progress
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Insertable)]
#[diesel(table_name = ecs_backfill_checkpoints)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct BackfillCheckpoint {
    pub id: Uuid,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>, // None for global checkpoints
    pub last_processed_event_id: Uuid,
    pub last_processed_timestamp: DateTime<Utc>,
    pub events_processed_count: i64,
    pub status: String, // "IN_PROGRESS", "COMPLETED", "FAILED"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Configuration for backfill processing behavior
#[derive(Debug, Clone)]
pub struct BackfillConfig {
    /// Maximum number of events to process in a single batch
    pub batch_size: usize,
    /// Maximum number of chronicles to process in parallel
    pub max_parallel_chronicles: usize,
    /// Whether to skip events that are already processed (idempotency)
    pub skip_processed_events: bool,
    /// Whether to validate ECS state consistency after processing
    pub validate_consistency: bool,
    /// Whether to create detailed progress checkpoints
    pub enable_checkpointing: bool,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_parallel_chronicles: 1, // Start with sequential processing
            skip_processed_events: true,
            validate_consistency: true,
            enable_checkpointing: true,
        }
    }
}

/// Result of backfill processing
#[derive(Debug, Clone)]
pub struct BackfillResult {
    /// Total number of chronicles processed
    pub chronicles_processed: usize,
    /// Total number of events processed
    pub events_processed: usize,
    /// Total number of events skipped (already processed)
    pub events_skipped: usize,
    /// Number of translation errors encountered
    pub translation_errors: usize,
    /// Processing start time
    pub started_at: DateTime<Utc>,
    /// Processing completion time
    pub completed_at: DateTime<Utc>,
    /// Any warnings or messages generated during processing
    pub messages: Vec<String>,
    /// Detailed processing statistics per chronicle
    pub chronicle_stats: HashMap<Uuid, ChronicleBackfillStats>,
}

/// Statistics for individual chronicle processing
#[derive(Debug, Clone)]
pub struct ChronicleBackfillStats {
    pub chronicle_id: Uuid,
    pub events_processed: usize,
    pub events_skipped: usize,
    pub translation_errors: usize,
    pub entities_created: usize,
    pub components_updated: usize,
    pub relationships_updated: usize,
    pub processing_duration_ms: i64,
}

/// Service for processing historical chronicle events into ECS state
pub struct ChronicleBackfillProcessor {
    db_pool: Arc<PgPool>,
    chronicle_service: ChronicleService,
    translator: ChronicleEcsTranslator,
    config: BackfillConfig,
}

impl ChronicleBackfillProcessor {
    /// Create a new backfill processor with default configuration
    pub fn new(db_pool: Arc<PgPool>) -> Self {
        let chronicle_service = ChronicleService::new((*db_pool).clone());
        let translator = ChronicleEcsTranslator::new(db_pool.clone());
        
        Self {
            db_pool,
            chronicle_service,
            translator,
            config: BackfillConfig::default(),
        }
    }

    /// Create a new backfill processor with custom configuration
    pub fn with_config(db_pool: Arc<PgPool>, config: BackfillConfig) -> Self {
        let chronicle_service = ChronicleService::new((*db_pool).clone());
        let translator = ChronicleEcsTranslator::new(db_pool.clone());
        
        Self {
            db_pool,
            chronicle_service,
            translator,
            config,
        }
    }

    /// Process all chronicles for a user into ECS state
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", hash_user_id(user_id))))]
    pub async fn backfill_user_chronicles(
        &self,
        user_id: Uuid,
    ) -> Result<BackfillResult, AppError> {
        let started_at = Utc::now();
        info!("Starting chronicle backfill for user_hash {:x}", hash_user_id(user_id));

        // Get all chronicles for the user
        let chronicles = self.chronicle_service.get_user_chronicles(user_id).await?;
        
        let mut result = BackfillResult {
            chronicles_processed: 0,
            events_processed: 0,
            events_skipped: 0,
            translation_errors: 0,
            started_at,
            completed_at: Utc::now(), // Will be updated at the end
            messages: Vec::new(),
            chronicle_stats: HashMap::new(),
        };

        // Process each chronicle in chronological order (by creation date)
        let mut sorted_chronicles = chronicles.clone();
        sorted_chronicles.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        for chronicle in sorted_chronicles {
            debug!("Processing chronicle: {} ({})", chronicle.name, chronicle.id);
            
            match self.backfill_chronicle(user_id, &chronicle).await {
                Ok(stats) => {
                    result.chronicles_processed += 1;
                    result.events_processed += stats.events_processed;
                    result.events_skipped += stats.events_skipped;
                    result.translation_errors += stats.translation_errors;
                    
                    info!("Completed processing chronicle {} - {} events processed, {} skipped", 
                          chronicle.id, stats.events_processed, stats.events_skipped);
                    
                    result.chronicle_stats.insert(chronicle.id, stats);
                }
                Err(e) => {
                    error!("Failed to process chronicle {}: {}", chronicle.id, e);
                    result.translation_errors += 1;
                    result.messages.push(format!("Chronicle {} failed: {}", chronicle.id, e));
                }
            }
        }

        result.completed_at = Utc::now();
        
        info!("Chronicle backfill completed for user_hash {:x} - {} chronicles, {} events processed, {} skipped, {} errors",
              hash_user_id(user_id), result.chronicles_processed, result.events_processed, 
              result.events_skipped, result.translation_errors);

        Ok(result)
    }

    /// Process a single chronicle into ECS state
    async fn backfill_chronicle(
        &self,
        user_id: Uuid,
        chronicle: &PlayerChronicle,
    ) -> Result<ChronicleBackfillStats, AppError> {
        let processing_start = Utc::now();
        
        // Check for existing checkpoint
        let checkpoint = if self.config.enable_checkpointing {
            self.get_checkpoint(user_id, Some(chronicle.id)).await?
        } else {
            None
        };

        let mut stats = ChronicleBackfillStats {
            chronicle_id: chronicle.id,
            events_processed: 0,
            events_skipped: 0,
            translation_errors: 0,
            entities_created: 0,
            components_updated: 0,
            relationships_updated: 0,
            processing_duration_ms: 0,
        };

        // Track processed events for deduplication
        let mut processed_event_ids = HashSet::new();
        if let Some(ref checkpoint) = checkpoint {
            // In a real implementation, we'd load previously processed event IDs
            // For now, we'll rely on the timestamp filter
            debug!("Resuming from checkpoint: {} events processed", checkpoint.events_processed_count);
        }

        // Process events in batches until no more events
        let mut last_processed_timestamp = checkpoint.as_ref().map(|cp| cp.last_processed_timestamp);
        let mut last_event_for_checkpoint: Option<ChronicleEvent> = None;
        
        loop {
            // Get events in chronological order
            let filter = EventFilter {
                event_type: None,
                source: None,
                action: None,
                modality: None,
                involves_entity: None,
                after_timestamp: last_processed_timestamp,
                before_timestamp: None,
                limit: Some(self.config.batch_size as i64),
                offset: None,
                order_by: Some(EventOrderBy::CreatedAtAsc), // Chronological order
            };

            let events = self.chronicle_service.get_chronicle_events(user_id, chronicle.id, filter).await?;
            
            // Exit loop if no more events
            if events.is_empty() {
                break;
            }

            // Process events in this batch
            for event in &events {
                // Skip if already processed (idempotency)
                if self.config.skip_processed_events && processed_event_ids.contains(&event.id) {
                    stats.events_skipped += 1;
                    debug!("Skipping already processed event: {}", event.id);
                    continue;
                }

                // Translate event to ECS changes  
                match self.translator.translate_event(&event, event.user_id).await {
                    Ok(translation_result) => {
                        stats.events_processed += 1;
                        stats.entities_created += translation_result.entities_created.len();
                        stats.components_updated += translation_result.component_updates.len();
                        stats.relationships_updated += translation_result.relationship_updates.len();
                        
                        processed_event_ids.insert(event.id);
                        
                        debug!("Translated event {} - {} entities, {} components, {} relationships",
                               event.id, translation_result.entities_created.len(),
                               translation_result.component_updates.len(),
                               translation_result.relationship_updates.len());
                    }
                    Err(e) => {
                        warn!("Failed to translate event {}: {}", event.id, e);
                        stats.translation_errors += 1;
                    }
                }

                // Update checkpoint periodically
                if self.config.enable_checkpointing && stats.events_processed % 10 == 0 {
                    self.update_checkpoint(user_id, Some(chronicle.id), &event, stats.events_processed as i64).await?;
                }
            }

            // Update last processed timestamp for next batch
            if let Some(last_event) = events.last() {
                last_processed_timestamp = Some(last_event.created_at);
                last_event_for_checkpoint = Some(last_event.clone());
            }
            
            // If batch was smaller than batch_size, we've reached the end
            if events.len() < self.config.batch_size {
                break;
            }
        }

        // Final checkpoint update
        if self.config.enable_checkpointing && stats.events_processed > 0 {
            if let Some(last_event) = last_event_for_checkpoint {
                self.update_checkpoint(user_id, Some(chronicle.id), &last_event, stats.events_processed as i64).await?;
            }
        }

        let processing_end = Utc::now();
        stats.processing_duration_ms = (processing_end - processing_start).num_milliseconds();

        Ok(stats)
    }

    /// Get checkpoint for a user/chronicle combination
    pub async fn get_checkpoint(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
    ) -> Result<Option<BackfillCheckpoint>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let checkpoint_opt = conn.interact({
            let user_id = user_id;
            let chronicle_id = chronicle_id;
            move |conn| {
                let mut query = ecs_backfill_checkpoints::table
                    .filter(ecs_backfill_checkpoints::user_id.eq(user_id))
                    .into_boxed();

                match chronicle_id {
                    Some(cid) => query = query.filter(ecs_backfill_checkpoints::chronicle_id.eq(cid)),
                    None => query = query.filter(ecs_backfill_checkpoints::chronicle_id.is_null()),
                }

                query
                    .order(ecs_backfill_checkpoints::updated_at.desc())
                    .first::<BackfillCheckpoint>(conn)
                    .optional()
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(checkpoint_opt)
    }

    /// Update or create checkpoint
    async fn update_checkpoint(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        last_event: &ChronicleEvent,
        events_processed: i64,
    ) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // First check if checkpoint exists
        let existing = self.get_checkpoint(user_id, chronicle_id).await?;

        if let Some(mut existing_checkpoint) = existing {
            // Update existing checkpoint
            existing_checkpoint.last_processed_event_id = last_event.id;
            existing_checkpoint.last_processed_timestamp = last_event.created_at;
            existing_checkpoint.events_processed_count = events_processed;
            existing_checkpoint.updated_at = Utc::now();

            conn.interact({
                let checkpoint = existing_checkpoint;
                move |conn| {
                    diesel::update(ecs_backfill_checkpoints::table.find(checkpoint.id))
                        .set((
                            ecs_backfill_checkpoints::last_processed_event_id.eq(checkpoint.last_processed_event_id),
                            ecs_backfill_checkpoints::last_processed_timestamp.eq(checkpoint.last_processed_timestamp),
                            ecs_backfill_checkpoints::events_processed_count.eq(checkpoint.events_processed_count),
                            ecs_backfill_checkpoints::updated_at.eq(checkpoint.updated_at),
                        ))
                        .execute(conn)
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        } else {
            // Create new checkpoint
            let checkpoint = BackfillCheckpoint {
                id: Uuid::new_v4(),
                user_id,
                chronicle_id,
                last_processed_event_id: last_event.id,
                last_processed_timestamp: last_event.created_at,
                events_processed_count: events_processed,
                status: "IN_PROGRESS".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            conn.interact({
                let checkpoint = checkpoint;
                move |conn| {
                    diesel::insert_into(ecs_backfill_checkpoints::table)
                        .values(&checkpoint)
                        .execute(conn)
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }

        Ok(())
    }

    /// Validate ECS state consistency after backfill
    pub async fn validate_consistency(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let mut issues = Vec::new();

        // TODO: Implement consistency checks
        // - Verify all entities have valid archetype signatures
        // - Check that relationships reference existing entities
        // - Validate component data integrity
        // - Ensure valence changes are properly applied

        debug!("Consistency validation for user_hash {:x} - {} issues found", hash_user_id(user_id), issues.len());
        Ok(issues)
    }

    /// Reset checkpoints for a user (forces full reprocessing)
    pub async fn reset_checkpoints(&self, user_id: Uuid) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact({
            let user_id = user_id;
            move |conn| {
                diesel::delete(ecs_backfill_checkpoints::table
                    .filter(ecs_backfill_checkpoints::user_id.eq(user_id)))
                    .execute(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        info!("Reset backfill checkpoints for user_hash {:x}", hash_user_id(user_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_processor() -> ChronicleBackfillProcessor {
        // Create a minimal mock processor for unit tests that don't need real DB access
        let config = BackfillConfig::default();
        let manager = deadpool_diesel::postgres::Manager::new("postgresql://test", deadpool_diesel::Runtime::Tokio1);
        let pool = deadpool_diesel::postgres::Pool::builder(manager).build().unwrap();
        ChronicleBackfillProcessor::with_config(Arc::new(pool), config)
    }

    #[test]
    fn test_backfill_config_defaults() {
        let config = BackfillConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_parallel_chronicles, 1);
        assert!(config.skip_processed_events);
        assert!(config.validate_consistency);
        assert!(config.enable_checkpointing);
    }

    #[test]
    fn test_backfill_result_initialization() {
        let started_at = Utc::now();
        let result = BackfillResult {
            chronicles_processed: 0,
            events_processed: 0,
            events_skipped: 0,
            translation_errors: 0,
            started_at,
            completed_at: started_at,
            messages: Vec::new(),
            chronicle_stats: HashMap::new(),
        };

        assert_eq!(result.chronicles_processed, 0);
        assert_eq!(result.events_processed, 0);
        assert!(result.messages.is_empty());
        assert!(result.chronicle_stats.is_empty());
    }
}