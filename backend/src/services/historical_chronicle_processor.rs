//! Historical Chronicle Processor Service
//!
//! This service implements Phase 5.1.1 of the ECS Architecture Plan:
//! - Orchestrates distributed processing of all historical chronicles
//! - Manages job queue for scalable backfill operations
//! - Provides progress tracking and error recovery
//! - Implements expert-recommended distributed architecture
//!
//! Key Features:
//! - Job Enqueuer: Discovers chronicles and creates processing jobs
//! - Distributed Workers: Scalable stateless workers for individual chronicle processing
//! - Dead Letter Queue: Handles failed jobs and error recovery
//! - Progress Monitoring: Comprehensive tracking and reporting
//! - Resource Management: Protects live system performance

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, instrument};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::{
    PgPool,
    config::NarrativeFeatureFlags,
    errors::AppError,
    models::{
        chronicle::PlayerChronicle,
        chronicle_event::{ChronicleEvent, EventFilter},
        chronicle_processing_job::{
            ChronicleProcessingJob, NewChronicleProcessingJob, UpdateChronicleProcessingJob,
            ChronicleJobStatus, ChronicleJobStats,
        },
    },
    services::{
        chronicle_service::ChronicleService,
        chronicle_ecs_translator::{ChronicleEcsTranslator, TranslationResult},
        ecs_entity_manager::EcsEntityManager,
    },
    schema::chronicle_processing_jobs,
};

use diesel::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use bigdecimal::ToPrimitive;

/// Simple count result for raw SQL queries
#[derive(diesel::QueryableByName)]
struct CountResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

/// Simple total result for raw SQL queries
#[derive(diesel::QueryableByName)]
struct TotalResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    total: i64,
}

/// Average time result for raw SQL queries
#[derive(diesel::QueryableByName)]
struct AvgTimeResult {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Double>)]
    avg_time: Option<f64>,
}

/// Hash user ID for privacy-preserving logging (GDPR/privacy compliant)
fn hash_user_id(user_id: Uuid) -> u64 {
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    hasher.finish()
}

/// Configuration for historical chronicle processing
#[derive(Debug, Clone)]
pub struct HistoricalProcessorConfig {
    /// Maximum number of concurrent workers
    pub max_concurrent_workers: usize,
    /// Batch size for job discovery
    pub discovery_batch_size: usize,
    /// Job processing timeout (seconds)
    pub job_timeout_secs: u64,
    /// Retry delay multiplier for exponential backoff
    pub retry_delay_multiplier: f64,
    /// Maximum retry delay (seconds)
    pub max_retry_delay_secs: u64,
    /// Enable separate connection pool for workers
    pub use_separate_connection_pool: bool,
    /// Worker CPU priority (lower = less priority)
    pub worker_cpu_priority: i32,
    /// Progress reporting interval (seconds)
    pub progress_report_interval_secs: u64,
    /// Enable checksum generation for validation
    pub enable_checksum_generation: bool,
}

impl Default for HistoricalProcessorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workers: 4, // Conservative default
            discovery_batch_size: 100,
            job_timeout_secs: 300, // 5 minutes per chronicle
            retry_delay_multiplier: 2.0,
            max_retry_delay_secs: 3600, // 1 hour max delay
            use_separate_connection_pool: true,
            worker_cpu_priority: -10, // Lower priority than live system
            progress_report_interval_secs: 30,
            enable_checksum_generation: true,
        }
    }
}

/// Result of job enqueuing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueResult {
    pub total_chronicles_discovered: usize,
    pub jobs_created: usize,
    pub jobs_already_existed: usize,
    pub jobs_failed_to_create: usize,
    pub discovery_duration_ms: u64,
    pub users_processed: usize,
}

/// Result of backfill processing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillResult {
    pub backfill_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub dead_letter_jobs: usize,
    pub total_processing_time_ms: u64,
    pub success_rate: f64,
    pub events_processed: i64,
    pub entities_created: i64,
    pub components_created: i64,
    pub relationships_created: i64,
}

/// Progress report for ongoing backfill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillProgress {
    pub backfill_id: Uuid,
    pub current_time: DateTime<Utc>,
    pub jobs_stats: ChronicleJobStats,
    pub estimated_completion_time: Option<DateTime<Utc>>,
    pub processing_rate_jobs_per_minute: f64,
    pub average_job_duration_ms: f64,
    pub active_workers: usize,
}

/// Historical Chronicle Processor Service
///
/// This service orchestrates the distributed processing of all historical chronicles
/// to populate ECS state. It implements a job queue-based architecture for
/// scalability, reliability, and resource management.
pub struct HistoricalChronicleProcessor {
    /// Configuration
    config: HistoricalProcessorConfig,
    /// Feature flags for toggle control
    feature_flags: Arc<NarrativeFeatureFlags>,
    /// Database connection pool
    db_pool: Arc<PgPool>,
    /// Chronicle service for data access
    chronicle_service: Arc<ChronicleService>,
    /// Chronicle-ECS translator
    translator: Arc<ChronicleEcsTranslator>,
    /// ECS entity manager
    entity_manager: Arc<EcsEntityManager>,
    /// Worker management
    active_workers: Arc<RwLock<HashMap<Uuid, WorkerInfo>>>,
    /// Processing state
    is_running: Arc<AtomicBool>,
    jobs_processed: Arc<AtomicU64>,
    jobs_failed: Arc<AtomicU64>,
}

/// Information about an active worker
#[derive(Debug, Clone)]
struct WorkerInfo {
    worker_id: Uuid,
    started_at: Instant,
    current_job: Option<Uuid>,
    jobs_completed: u64,
    jobs_failed: u64,
}

impl HistoricalChronicleProcessor {
    /// Create a new historical chronicle processor
    pub fn new(
        config: HistoricalProcessorConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        db_pool: Arc<PgPool>,
        chronicle_service: Arc<ChronicleService>,
        translator: Arc<ChronicleEcsTranslator>,
        entity_manager: Arc<EcsEntityManager>,
    ) -> Self {
        Self {
            config,
            feature_flags,
            db_pool,
            chronicle_service,
            translator,
            entity_manager,
            active_workers: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            jobs_processed: Arc::new(AtomicU64::new(0)),
            jobs_failed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Discover and enqueue all chronicles for processing
    ///
    /// This is the Job Enqueuer component that discovers chronicles needing
    /// processing and creates jobs for them.
    #[instrument(skip(self))]
    pub async fn enqueue_all_chronicles(&self) -> Result<EnqueueResult, AppError> {
        let start_time = Instant::now();
        
        info!("Starting chronicle discovery and job enqueuing");
        
        if !self.feature_flags.enable_ecs_system {
            return Err(AppError::ConfigError("ECS system disabled - cannot enqueue chronicles".to_string()));
        }
        
        let mut total_chronicles = 0;
        let mut jobs_created = 0;
        let mut jobs_already_existed = 0;
        let mut jobs_failed = 0;
        let mut users_processed = 0;
        
        // Get all users to process their chronicles
        let users = self.get_all_users_with_chronicles().await?;
        
        for user_id in users {
            users_processed += 1;
            
            debug!(
                user_hash = %format!("{:x}", hash_user_id(user_id)),
                "Processing chronicles for user"
            );
            
            // Get all chronicles for this user
            let chronicles = self.chronicle_service.get_user_chronicles(user_id).await?;
            total_chronicles += chronicles.len();
            
            // Create jobs for each chronicle
            for chronicle in chronicles {
                match self.create_chronicle_job(user_id, chronicle.id).await {
                    Ok(created) => {
                        if created {
                            jobs_created += 1;
                        } else {
                            jobs_already_existed += 1;
                        }
                    }
                    Err(e) => {
                        warn!(
                            user_hash = %format!("{:x}", hash_user_id(user_id)),
                            chronicle_id = %chronicle.id,
                            error = %e,
                            "Failed to create job for chronicle"
                        );
                        jobs_failed += 1;
                    }
                }
            }
        }
        
        let discovery_duration = start_time.elapsed().as_millis() as u64;
        
        let result = EnqueueResult {
            total_chronicles_discovered: total_chronicles,
            jobs_created,
            jobs_already_existed,
            jobs_failed_to_create: jobs_failed,
            discovery_duration_ms: discovery_duration,
            users_processed,
        };
        
        info!(
            total_chronicles = total_chronicles,
            jobs_created = jobs_created,
            jobs_already_existed = jobs_already_existed,
            jobs_failed = jobs_failed,
            users_processed = users_processed,
            duration_ms = discovery_duration,
            "Chronicle discovery and job enqueuing completed"
        );
        
        Ok(result)
    }

    /// Start distributed backfill processing
    ///
    /// This spawns worker tasks to process jobs from the queue.
    #[instrument(skip(self))]
    pub async fn start_backfill_processing(&self) -> Result<Uuid, AppError> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(AppError::ConfigError("Backfill processing already running".to_string()));
        }
        
        self.is_running.store(true, Ordering::Relaxed);
        let backfill_id = Uuid::new_v4();
        
        info!(
            backfill_id = %backfill_id,
            max_workers = self.config.max_concurrent_workers,
            "Starting distributed backfill processing"
        );
        
        // Spawn worker tasks
        for worker_index in 0..self.config.max_concurrent_workers {
            let worker = self.clone_for_worker().await;
            let backfill_id = backfill_id;
            
            tokio::spawn(async move {
                worker.run_worker(backfill_id, worker_index).await;
            });
        }
        
        // Spawn progress monitoring task
        let monitor = self.clone_for_monitoring().await;
        tokio::spawn(async move {
            monitor.run_progress_monitor(backfill_id).await;
        });
        
        Ok(backfill_id)
    }

    /// Stop backfill processing
    pub async fn stop_backfill_processing(&self) -> Result<(), AppError> {
        info!("Stopping backfill processing");
        self.is_running.store(false, Ordering::Relaxed);
        
        // Wait for workers to finish their current jobs
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // Clear active workers
        self.active_workers.write().await.clear();
        
        info!("Backfill processing stopped");
        Ok(())
    }

    /// Get current job statistics
    pub async fn get_job_stats(&self) -> Result<ChronicleJobStats, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let stats = conn.interact(move |conn| -> Result<ChronicleJobStats, AppError> {
            use crate::schema::chronicle_processing_jobs::dsl::*;

            // Get status counts using individual queries to avoid QueryId issues
            let total_jobs: i64 = chronicle_processing_jobs
                .count()
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
            // Use raw SQL queries to avoid QueryId trait issues with enum
            let pending_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'pending'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let in_progress_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'in_progress'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let completed_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'completed'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let failed_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'failed'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let dead_letter_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'dead_letter'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);

            // Get aggregated statistics for completed jobs using raw SQL to avoid enum QueryId issues
            let avg_time_result: Option<f64> = diesel::sql_query(
                "SELECT AVG(processing_duration_ms) as avg_time FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<AvgTimeResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .and_then(|result| result.avg_time);
                
            let total_events: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(events_processed), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_entities: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(entities_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_components: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(components_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_relationships: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(relationships_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);

            Ok(ChronicleJobStats {
                total_jobs,
                pending_jobs,
                in_progress_jobs,
                completed_jobs,
                failed_jobs,
                dead_letter_jobs,
                average_processing_time_ms: avg_time_result,
                total_events_processed: total_events,
                total_entities_created: total_entities,
                total_components_created: total_components,
                total_relationships_created: total_relationships,
            })
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;

        Ok(stats)
    }

    // Private helper methods

    /// Get all users that have chronicles
    async fn get_all_users_with_chronicles(&self) -> Result<Vec<Uuid>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let user_ids = conn.interact(move |conn| {
            use crate::schema::player_chronicles::dsl::*;
            player_chronicles
                .select(user_id)
                .distinct()
                .load::<Uuid>(conn)
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(user_ids)
    }

    /// Create a processing job for a chronicle (idempotent)
    async fn create_chronicle_job(&self, user_id_param: Uuid, chronicle_id_param: Uuid) -> Result<bool, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let created = conn.interact(move |conn| -> Result<bool, AppError> {
            use crate::schema::chronicle_processing_jobs::dsl::*;

            // Check if job already exists  
            let existing = chronicle_processing_jobs
                .filter(user_id.eq(user_id_param))
                .filter(chronicle_id.eq(chronicle_id_param))
                .select(ChronicleProcessingJob::as_select())
                .first::<ChronicleProcessingJob>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if existing.is_some() {
                return Ok(false); // Job already exists
            }

            // Create new job
            let new_job = NewChronicleProcessingJob {
                user_id: user_id_param,
                chronicle_id: chronicle_id_param,
                status: ChronicleJobStatus::Pending,
                priority: ChronicleJobStatus::NORMAL_PRIORITY,
                processing_metadata: Some(serde_json::json!({
                    "created_by": "historical_chronicle_processor",
                    "phase": "5.1.1"
                })),
            };

            diesel::insert_into(chronicle_processing_jobs)
                .values(&new_job)
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            Ok(true)
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;

        Ok(created)
    }

    /// Clone processor for worker tasks
    async fn clone_for_worker(&self) -> HistoricalChronicleProcessorWorker {
        HistoricalChronicleProcessorWorker {
            config: self.config.clone(),
            feature_flags: Arc::clone(&self.feature_flags),
            db_pool: Arc::clone(&self.db_pool),
            chronicle_service: Arc::clone(&self.chronicle_service),
            translator: Arc::clone(&self.translator),
            entity_manager: Arc::clone(&self.entity_manager),
            is_running: Arc::clone(&self.is_running),
            jobs_processed: Arc::clone(&self.jobs_processed),
            jobs_failed: Arc::clone(&self.jobs_failed),
        }
    }

    /// Clone processor for monitoring tasks
    async fn clone_for_monitoring(&self) -> HistoricalChronicleProcessorMonitor {
        HistoricalChronicleProcessorMonitor {
            config: self.config.clone(),
            db_pool: Arc::clone(&self.db_pool),
            is_running: Arc::clone(&self.is_running),
        }
    }

    /// Execute full historical chronicle backfill with comprehensive monitoring
    ///
    /// This is the main entry point for Phase 5.3 - orchestrates the complete
    /// backfill process from start to finish with real-time monitoring.
    #[instrument(skip(self))]
    pub async fn execute_full_backfill(&self) -> Result<BackfillResult, AppError> {
        let backfill_id = Uuid::new_v4();
        let started_at = Utc::now();
        
        info!(
            backfill_id = %backfill_id,
            "Starting full historical chronicle backfill with monitoring"
        );
        
        // Phase 1: Discovery and Job Enqueuing
        info!(backfill_id = %backfill_id, "Phase 1: Discovering and enqueuing chronicles");
        let enqueue_result = self.enqueue_all_chronicles().await?;
        
        info!(
            backfill_id = %backfill_id,
            total_chronicles = enqueue_result.total_chronicles_discovered,
            jobs_created = enqueue_result.jobs_created,
            jobs_already_existed = enqueue_result.jobs_already_existed,
            users_processed = enqueue_result.users_processed,
            "Discovery phase completed"
        );
        
        // Phase 2: Start Distributed Processing
        info!(backfill_id = %backfill_id, "Phase 2: Starting distributed processing workers");
        let processing_backfill_id = self.start_backfill_processing().await?;
        
        // Phase 3: Monitor Progress Until Completion
        info!(backfill_id = %backfill_id, "Phase 3: Monitoring processing progress");
        let mut _final_progress = None;
        let mut completion_checks = 0;
        let max_completion_checks = 720; // Max 6 hours of monitoring (30s intervals)
        
        loop {
            tokio::time::sleep(Duration::from_secs(self.config.progress_report_interval_secs)).await;
            
            // Create monitor instance for progress reporting
            let monitor = HistoricalChronicleProcessorMonitor {
                config: self.config.clone(),
                db_pool: self.db_pool.clone(),
                is_running: Arc::new(AtomicBool::new(true)),
            };
            let progress = monitor.report_progress(processing_backfill_id).await?;
            
            info!(
                backfill_id = %backfill_id,
                processing_backfill_id = %processing_backfill_id,
                total_jobs = progress.jobs_stats.total_jobs,
                completed = progress.jobs_stats.completed_jobs,
                failed = progress.jobs_stats.failed_jobs,
                pending = progress.jobs_stats.pending_jobs,
                in_progress = progress.jobs_stats.in_progress_jobs,
                dead_letter = progress.jobs_stats.dead_letter_jobs,
                processing_rate = %format!("{:.2}", progress.processing_rate_jobs_per_minute),
                avg_duration = %format!("{:.2}ms", progress.average_job_duration_ms),
                active_workers = progress.active_workers,
                estimated_completion = ?progress.estimated_completion_time,
                "Backfill progress update"
            );
            
            // Check for completion
            let all_jobs_done = progress.jobs_stats.pending_jobs == 0 && 
                               progress.jobs_stats.in_progress_jobs == 0;
            
            if all_jobs_done {
                _final_progress = Some(progress);
                info!(
                    backfill_id = %backfill_id,
                    "All jobs completed - backfill finished"
                );
                break;
            }
            
            // Safety check to prevent infinite monitoring
            completion_checks += 1;
            if completion_checks >= max_completion_checks {
                warn!(
                    backfill_id = %backfill_id,
                    "Backfill monitoring timeout reached - stopping monitoring"
                );
                break;
            }
        }
        
        // Phase 4: Stop Processing and Generate Final Report
        info!(backfill_id = %backfill_id, "Phase 4: Stopping workers and generating final report");
        self.stop_backfill_processing().await?;
        
        let completed_at = Utc::now();
        let total_processing_time = (completed_at - started_at).num_milliseconds() as u64;
        
        // Get final statistics
        // Create monitor instance for final stats reporting
        let monitor = HistoricalChronicleProcessorMonitor {
            config: self.config.clone(),
            db_pool: self.db_pool.clone(),
            is_running: Arc::new(AtomicBool::new(true)),
        };
        let final_stats = monitor.report_progress(processing_backfill_id).await?.jobs_stats;
        
        let success_rate = if final_stats.total_jobs > 0 {
            final_stats.completed_jobs as f64 / final_stats.total_jobs as f64 * 100.0
        } else {
            0.0
        };
        
        let result = BackfillResult {
            backfill_id,
            started_at,
            completed_at: Some(completed_at),
            total_jobs: final_stats.total_jobs as usize,
            completed_jobs: final_stats.completed_jobs as usize,
            failed_jobs: final_stats.failed_jobs as usize,
            dead_letter_jobs: final_stats.dead_letter_jobs as usize,
            total_processing_time_ms: total_processing_time,
            success_rate,
            events_processed: final_stats.total_events_processed,
            entities_created: final_stats.total_entities_created,
            components_created: final_stats.total_components_created,
            relationships_created: final_stats.total_relationships_created,
        };
        
        info!(
            backfill_id = %backfill_id,
            total_jobs = result.total_jobs,
            completed_jobs = result.completed_jobs,
            failed_jobs = result.failed_jobs,
            dead_letter_jobs = result.dead_letter_jobs,
            success_rate = %format!("{:.2}%", result.success_rate),
            total_processing_time = %format!("{:.2}s", total_processing_time as f64 / 1000.0),
            events_processed = result.events_processed,
            entities_created = result.entities_created,
            components_created = result.components_created,
            relationships_created = result.relationships_created,
            "Full historical chronicle backfill completed"
        );
        
        Ok(result)
    }

    /// Execute full backfill with state validation
    ///
    /// Enhanced version that includes checksum validation of the final state
    /// against the chronicle data to ensure consistency.
    #[instrument(skip(self, validator))]
    pub async fn execute_full_backfill_with_validation(
        &self,
        validator: Option<Arc<crate::services::ChecksumStateValidator>>,
    ) -> Result<(BackfillResult, Vec<String>), AppError> {
        let backfill_result = self.execute_full_backfill().await?;
        let mut validation_messages = Vec::new();
        
        // If validator is provided, run validation on a sample of chronicles
        if let Some(validator) = validator {
            info!(
                backfill_id = %backfill_result.backfill_id,
                "Starting post-backfill checksum validation"
            );
            
            // Get a sample of completed jobs for validation
            let sample_jobs = self.get_sample_completed_jobs(50).await?;
            
            for job in sample_jobs {
                let chronicle_id = job.chronicle_id;
                match validator.validate_state_consistency(
                    job.user_id,
                    chronicle_id,
                ).await {
                    Ok(validation_result) => {
                        if !validation_result.component_results.is_empty() {
                            validation_messages.push(format!(
                                "Chronicle {} validation: {} components validated, success: {}",
                                chronicle_id,
                                validation_result.component_results.len(),
                                validation_result.is_valid
                            ));
                        }
                    }
                    Err(e) => {
                        validation_messages.push(format!(
                            "Chronicle {} validation failed: {}",
                            chronicle_id, e
                        ));
                    }
                }
            }
            
            info!(
                backfill_id = %backfill_result.backfill_id,
                validations_performed = validation_messages.len(),
                "Post-backfill validation completed"
            );
        }
        
        Ok((backfill_result, validation_messages))
    }

    /// Get a sample of completed jobs for validation
    async fn get_sample_completed_jobs(&self, limit: i64) -> Result<Vec<ChronicleProcessingJob>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact(move |conn| {
            use crate::schema::chronicle_processing_jobs::dsl::*;
            
            // Use raw SQL to avoid enum QueryId issues, with string interpolation for limit
            let query_sql = format!(
                "SELECT * FROM chronicle_processing_jobs WHERE status = 'completed' ORDER BY completed_at DESC LIMIT {}",
                limit
            );
            
            let jobs: Vec<ChronicleProcessingJob> = diesel::sql_query(query_sql)
                .load(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            
            Ok(jobs)
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
    }

}

/// Worker component for processing individual jobs
struct HistoricalChronicleProcessorWorker {
    config: HistoricalProcessorConfig,
    feature_flags: Arc<NarrativeFeatureFlags>,
    db_pool: Arc<PgPool>,
    chronicle_service: Arc<ChronicleService>,
    translator: Arc<ChronicleEcsTranslator>,
    entity_manager: Arc<EcsEntityManager>,
    is_running: Arc<AtomicBool>,
    jobs_processed: Arc<AtomicU64>,
    jobs_failed: Arc<AtomicU64>,
}

impl HistoricalChronicleProcessorWorker {
    /// Run worker to process jobs from the queue
    #[instrument(skip(self))]
    async fn run_worker(&self, backfill_id: Uuid, worker_index: usize) {
        let worker_id = Uuid::new_v4();
        
        info!(
            backfill_id = %backfill_id,
            worker_index = worker_index,
            worker_id = %worker_id,
            "Starting chronicle processing worker"
        );
        
        while self.is_running.load(Ordering::Relaxed) {
            match self.process_next_job(worker_id).await {
                Ok(Some(job_id)) => {
                    debug!(
                        worker_id = %worker_id,
                        job_id = %job_id,
                        "Successfully processed job"
                    );
                    self.jobs_processed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {
                    // No jobs available, wait before checking again
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => {
                    error!(
                        worker_id = %worker_id,
                        error = %e,
                        "Worker encountered error processing job"
                    );
                    self.jobs_failed.fetch_add(1, Ordering::Relaxed);
                    
                    // Back off on error to avoid tight error loops
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
        
        info!(
            worker_id = %worker_id,
            "Chronicle processing worker stopped"
        );
    }
    
    /// Process the next available job from the queue
    async fn process_next_job(&self, worker_id: Uuid) -> Result<Option<Uuid>, AppError> {
        // Get next job using SELECT...FOR UPDATE SKIP LOCKED pattern
        let job = self.claim_next_job(worker_id).await?;
        
        let job = match job {
            Some(job) => job,
            None => return Ok(None), // No jobs available
        };
        
        info!(
            worker_id = %worker_id,
            job_id = %job.id,
            user_hash = %format!("{:x}", hash_user_id(job.user_id)),
            chronicle_id = %job.chronicle_id,
            attempt = job.attempt_count + 1,
            "Processing chronicle job"
        );
        
        let job_start = Instant::now();
        let processing_result = self.process_chronicle_job(&job).await;
        let processing_duration = job_start.elapsed().as_millis() as i64;
        
        match processing_result {
            Ok(metrics) => {
                // Update job as completed with metrics
                let update = UpdateChronicleProcessingJob {
                    status: Some(ChronicleJobStatus::Completed),
                    completed_at: Some(Some(Utc::now())),
                    processing_duration_ms: Some(Some(processing_duration)),
                    events_processed: Some(Some(metrics.events_processed)),
                    entities_created: Some(Some(metrics.entities_created)),
                    components_created: Some(Some(metrics.components_created)),
                    relationships_created: Some(Some(metrics.relationships_created)),
                    chronicle_events_hash: Some(metrics.chronicle_events_hash),
                    ecs_state_checksum: Some(metrics.ecs_state_checksum),
                    worker_id: Some(Some(worker_id)),
                    last_error: Some(None),
                    error_details: Some(None),
                    ..Default::default()
                };
                
                self.update_job_status(job.id, update).await?;
                
                info!(
                    job_id = %job.id,
                    duration_ms = processing_duration,
                    events = metrics.events_processed,
                    entities = metrics.entities_created,
                    components = metrics.components_created,
                    relationships = metrics.relationships_created,
                    "Chronicle job completed successfully"
                );
                
                Ok(Some(job.id))
            }
            Err(e) => {
                error!(
                    job_id = %job.id,
                    error = %e,
                    attempt = job.attempt_count + 1,
                    max_attempts = job.max_attempts,
                    "Chronicle job failed"
                );
                
                let new_attempt_count = job.attempt_count + 1;
                let should_retry = new_attempt_count < job.max_attempts;
                
                let (new_status, next_retry_at) = if should_retry {
                    let delay_secs = (self.config.retry_delay_multiplier.powi(new_attempt_count))
                        .min(self.config.max_retry_delay_secs as f64) as u64;
                    
                    (
                        ChronicleJobStatus::Failed,
                        Some(Some(Utc::now() + chrono::Duration::seconds(delay_secs as i64)))
                    )
                } else {
                    // Max attempts reached, send to dead letter queue
                    (ChronicleJobStatus::DeadLetter, Some(None))
                };
                
                let update = UpdateChronicleProcessingJob {
                    status: Some(new_status),
                    attempt_count: Some(new_attempt_count),
                    next_retry_at,
                    last_error: Some(Some(e.to_string())),
                    error_details: Some(Some(serde_json::json!({
                        "error": e.to_string(),
                        "worker_id": worker_id,
                        "processing_duration_ms": processing_duration,
                        "timestamp": Utc::now().to_rfc3339()
                    }))),
                    processing_duration_ms: Some(Some(processing_duration)),
                    worker_id: Some(Some(worker_id)),
                    ..Default::default()
                };
                
                self.update_job_status(job.id, update).await?;
                
                Err(e)
            }
        }
    }
    
    /// Claim the next job from the queue using distributed locking
    async fn claim_next_job(&self, worker_id: Uuid) -> Result<Option<ChronicleProcessingJob>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        let job = conn.interact(move |conn| -> Result<Option<ChronicleProcessingJob>, AppError> {
            let worker_id_value = worker_id; // Capture by value for closure
            
            // Use raw SQL for SELECT...FOR UPDATE SKIP LOCKED to avoid enum QueryId issues
            let claimed_job_sql = r#"
                SELECT * FROM chronicle_processing_jobs 
                WHERE status = 'pending'
                ORDER BY priority DESC, created_at ASC 
                LIMIT 1 
                FOR UPDATE SKIP LOCKED
            "#;
            
            let claimed_job: Option<ChronicleProcessingJob> = diesel::sql_query(claimed_job_sql)
                .load::<ChronicleProcessingJob>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .into_iter()
                .next();
                
            // If no pending jobs, try failed jobs ready for retry
            let claimed_job = if claimed_job.is_none() {
                let retry_job_sql = r#"
                    SELECT * FROM chronicle_processing_jobs 
                    WHERE status = 'failed' AND next_retry_at IS NOT NULL AND next_retry_at <= NOW()
                    ORDER BY priority DESC, created_at ASC 
                    LIMIT 1 
                    FOR UPDATE SKIP LOCKED
                "#;
                
                diesel::sql_query(retry_job_sql)
                    .load::<ChronicleProcessingJob>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                    .into_iter()
                    .next()
            } else {
                claimed_job
            };
            
            if let Some(job) = claimed_job {
                // Update job to in_progress status using raw SQL to avoid enum issues
                let update_sql = r#"
                    UPDATE chronicle_processing_jobs 
                    SET status = 'in_progress', started_at = NOW(), worker_id = $1
                    WHERE id = $2
                "#;
                
                diesel::sql_query(update_sql)
                    .bind::<diesel::sql_types::Uuid, _>(worker_id_value)
                    .bind::<diesel::sql_types::Uuid, _>(job.id)
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
                Ok(Some(job))
            } else {
                Ok(None)
            }
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;
        
        Ok(job)
    }
    
    /// Process a single chronicle job
    async fn process_chronicle_job(&self, job: &ChronicleProcessingJob) -> Result<JobProcessingMetrics, AppError> {
        // Get chronicle and its events
        let _chronicle = self.chronicle_service.get_chronicle(job.user_id, job.chronicle_id).await?;
        let events = self.chronicle_service.get_chronicle_events(
            job.user_id, 
            job.chronicle_id, 
            Default::default()
        ).await?;
        
        debug!(
            job_id = %job.id,
            chronicle_id = %job.chronicle_id,
            events_count = events.len(),
            "Processing chronicle events"
        );
        
        // Generate chronicle events hash for validation
        let chronicle_events_hash = if self.config.enable_checksum_generation {
            Some(self.generate_chronicle_events_hash(&events))
        } else {
            None
        };
        
        let mut metrics = JobProcessingMetrics {
            events_processed: events.len() as i32,
            entities_created: 0,
            components_created: 0,
            relationships_created: 0,
            chronicle_events_hash,
            ecs_state_checksum: None,
        };
        
        // Process each event through the translator
        for event in &events {
            let translation_result = self.translator.translate_event(event, job.user_id).await?;
            
            // For now, the translator returns entity IDs that were already processed
            // This is more for updating existing ECS state rather than creating from scratch
            // We track the metrics from what was returned
            metrics.entities_created += translation_result.entities_created.len() as i32;
            metrics.components_created += translation_result.component_updates.len() as i32;
            metrics.relationships_created += translation_result.relationship_updates.len() as i32;
            
            // Log any translation messages
            for message in &translation_result.messages {
                debug!(
                    job_id = %job.id,
                    event_id = %event.id,
                    message = %message,
                    "Translation message"
                );
            }
        }
        
        // Generate ECS state checksum for validation
        if self.config.enable_checksum_generation {
            metrics.ecs_state_checksum = Some(
                self.generate_ecs_state_checksum(job.user_id, job.chronicle_id).await?
            );
        }
        
        Ok(metrics)
    }
    
    /// Update job status in database
    async fn update_job_status(&self, job_id: Uuid, update: UpdateChronicleProcessingJob) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact(move |conn| -> Result<(), AppError> {
            use crate::schema::chronicle_processing_jobs::dsl::*;
            
            diesel::update(chronicle_processing_jobs.filter(id.eq(job_id)))
                .set(&update)
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            
            Ok(())
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;
        
        Ok(())
    }
    
    /// Generate hash of chronicle events for validation
    fn generate_chronicle_events_hash(&self, events: &[ChronicleEvent]) -> String {
        let mut hasher = DefaultHasher::new();
        
        // Sort events by created_at to ensure consistent ordering
        let mut sorted_events = events.to_vec();
        sorted_events.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        
        for event in sorted_events {
            event.id.hash(&mut hasher);
            event.event_type.hash(&mut hasher);
            event.summary.hash(&mut hasher);
            event.created_at.timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        }
        
        format!("{:x}", hasher.finish())
    }
    
    /// Generate checksum of current ECS state for validation
    async fn generate_ecs_state_checksum(&self, user_id: Uuid, chronicle_id: Uuid) -> Result<String, AppError> {
        // For now, generate a simple checksum based on entity and component counts
        // In a production system, this would be more sophisticated
        let entity_count = self.entity_manager.get_user_entity_count(user_id).await?;
        let component_count = self.entity_manager.get_user_component_count(user_id).await?;
        let relationship_count = self.entity_manager.get_user_relationship_count(user_id).await?;
        
        let mut hasher = DefaultHasher::new();
        chronicle_id.hash(&mut hasher);
        entity_count.hash(&mut hasher);
        component_count.hash(&mut hasher);
        relationship_count.hash(&mut hasher);
        Utc::now().timestamp().hash(&mut hasher);
        
        Ok(format!("{:x}", hasher.finish()))
    }
}

/// Metrics collected during job processing
#[derive(Debug, Clone)]
struct JobProcessingMetrics {
    events_processed: i32,
    entities_created: i32,
    components_created: i32,
    relationships_created: i32,
    chronicle_events_hash: Option<String>,
    ecs_state_checksum: Option<String>,
}

impl Default for UpdateChronicleProcessingJob {
    fn default() -> Self {
        Self {
            status: None,
            attempt_count: None,
            started_at: None,
            completed_at: None,
            next_retry_at: None,
            worker_id: None,
            processing_metadata: None,
            last_error: None,
            error_details: None,
            chronicle_events_hash: None,
            ecs_state_checksum: None,
            events_processed: None,
            entities_created: None,
            components_created: None,
            relationships_created: None,
            processing_duration_ms: None,
        }
    }
}

/// Monitor component for tracking progress
struct HistoricalChronicleProcessorMonitor {
    config: HistoricalProcessorConfig,
    db_pool: Arc<PgPool>,
    is_running: Arc<AtomicBool>,
}

impl HistoricalChronicleProcessorMonitor {
    /// Run progress monitoring task
    #[instrument(skip(self))]
    async fn run_progress_monitor(&self, backfill_id: Uuid) {
        info!(
            backfill_id = %backfill_id,
            "Starting chronicle processing progress monitor"
        );
        
        while self.is_running.load(Ordering::Relaxed) {
            match self.report_progress(backfill_id).await {
                Ok(progress) => {
                    info!(
                        backfill_id = %backfill_id,
                        total_jobs = progress.jobs_stats.total_jobs,
                        completed = progress.jobs_stats.completed_jobs,
                        in_progress = progress.jobs_stats.in_progress_jobs,
                        failed = progress.jobs_stats.failed_jobs,
                        dead_letter = progress.jobs_stats.dead_letter_jobs,
                        processing_rate = %format!("{:.2}", progress.processing_rate_jobs_per_minute),
                        active_workers = progress.active_workers,
                        "Chronicle processing progress report"
                    );
                }
                Err(e) => {
                    error!(
                        backfill_id = %backfill_id,
                        error = %e,
                        "Failed to generate progress report"
                    );
                }
            }
            
            tokio::time::sleep(Duration::from_secs(self.config.progress_report_interval_secs)).await;
        }
        
        info!(
            backfill_id = %backfill_id,
            "Chronicle processing progress monitor stopped"
        );
    }
    
    /// Generate progress report
    async fn report_progress(&self, backfill_id: Uuid) -> Result<BackfillProgress, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        let (job_stats, active_workers, avg_duration) = conn.interact(move |conn| -> Result<(ChronicleJobStats, usize, f64), AppError> {
            use crate::schema::chronicle_processing_jobs::dsl::*;
            
            // Get status counts using individual queries to avoid QueryId issues
            let total_jobs: i64 = chronicle_processing_jobs
                .count()
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
            // Use raw SQL queries to avoid QueryId trait issues with enum
            let pending_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'pending'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let in_progress_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'in_progress'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let completed_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'completed'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let failed_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'failed'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);
                
            let dead_letter_jobs: i64 = diesel::sql_query("SELECT COUNT(*) as count FROM chronicle_processing_jobs WHERE status = 'dead_letter'")
                .load::<CountResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.count)
                .unwrap_or(0);

            // Get aggregated statistics for completed jobs using raw SQL to avoid enum QueryId issues
            let avg_time_result: Option<f64> = diesel::sql_query(
                "SELECT AVG(processing_duration_ms) as avg_time FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<AvgTimeResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .and_then(|result| result.avg_time);
                
            let total_events: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(events_processed), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_entities: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(entities_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_components: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(components_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);
                
            let total_relationships: i64 = diesel::sql_query(
                "SELECT COALESCE(SUM(relationships_created), 0) as total FROM chronicle_processing_jobs WHERE status = 'completed'"
            )
                .load::<TotalResult>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                .first()
                .map(|result| result.total)
                .unwrap_or(0);

            let job_stats = ChronicleJobStats {
                total_jobs,
                pending_jobs,
                in_progress_jobs,
                completed_jobs,
                failed_jobs,
                dead_letter_jobs,
                average_processing_time_ms: avg_time_result,
                total_events_processed: total_events,
                total_entities_created: total_entities,
                total_components_created: total_components,
                total_relationships_created: total_relationships,
            };
            
            Ok((job_stats, in_progress_jobs as usize, avg_time_result.unwrap_or(0.0)))
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;
        
        // Calculate processing rate (jobs per minute)
        let processing_rate = if job_stats.completed_jobs > 0 && avg_duration > 0.0 {
            60000.0 / avg_duration // Convert ms to minutes
        } else {
            0.0
        };
        
        // Estimate completion time
        let estimated_completion = if job_stats.pending_jobs > 0 && processing_rate > 0.0 {
            let remaining_minutes = job_stats.pending_jobs as f64 / processing_rate;
            Some(Utc::now() + chrono::Duration::minutes(remaining_minutes as i64))
        } else {
            None
        };
        
        Ok(BackfillProgress {
            backfill_id,
            current_time: Utc::now(),
            jobs_stats: job_stats,
            estimated_completion_time: estimated_completion,
            processing_rate_jobs_per_minute: processing_rate,
            average_job_duration_ms: avg_duration,
            active_workers,
        })
    }
}
