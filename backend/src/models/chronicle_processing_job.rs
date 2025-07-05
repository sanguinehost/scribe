use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::schema::chronicle_processing_jobs;

/// Chronicle job status enum for distributed processing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, diesel_derive_enum::DbEnum)]
#[ExistingTypePath = "crate::schema::sql_types::ChronicleJobStatus"]
pub enum ChronicleJobStatus {
    #[db_rename = "pending"]
    Pending,
    #[db_rename = "in_progress"]
    InProgress,
    #[db_rename = "completed"]
    Completed,
    #[db_rename = "failed"]
    Failed,
    #[db_rename = "dead_letter"]
    DeadLetter,
}

/// Chronicle processing job for Phase 5 distributed backfill
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize, diesel::QueryableByName)]
#[diesel(table_name = chronicle_processing_jobs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChronicleProcessingJob {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub chronicle_id: Uuid,
    
    // Job management
    #[diesel(sql_type = crate::schema::sql_types::ChronicleJobStatus)]
    pub status: ChronicleJobStatus,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub priority: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub attempt_count: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub max_attempts: i32,
    
    // Timing
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub started_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub next_retry_at: Option<DateTime<Utc>>,
    
    // Processing details
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub worker_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    pub processing_metadata: Option<Value>,
    
    // Error handling
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    pub error_details: Option<Value>,
    
    // Checksum for validation (Phase 5.1.2)
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub chronicle_events_hash: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub ecs_state_checksum: Option<String>,
    
    // Performance tracking
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    pub events_processed: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    pub entities_created: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    pub components_created: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    pub relationships_created: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    pub processing_duration_ms: Option<i64>,
}

/// New chronicle processing job for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = chronicle_processing_jobs)]
pub struct NewChronicleProcessingJob {
    pub user_id: Uuid,
    pub chronicle_id: Uuid,
    pub status: ChronicleJobStatus,
    pub priority: i32,
    pub processing_metadata: Option<Value>,
}

/// Update chronicle processing job
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = chronicle_processing_jobs)]
pub struct UpdateChronicleProcessingJob {
    pub status: Option<ChronicleJobStatus>,
    pub attempt_count: Option<i32>,
    pub started_at: Option<Option<DateTime<Utc>>>,
    pub completed_at: Option<Option<DateTime<Utc>>>,
    pub next_retry_at: Option<Option<DateTime<Utc>>>,
    pub worker_id: Option<Option<Uuid>>,
    pub processing_metadata: Option<Value>,
    pub last_error: Option<Option<String>>,
    pub error_details: Option<Option<Value>>,
    pub chronicle_events_hash: Option<Option<String>>,
    pub ecs_state_checksum: Option<Option<String>>,
    pub events_processed: Option<Option<i32>>,
    pub entities_created: Option<Option<i32>>,
    pub components_created: Option<Option<i32>>,
    pub relationships_created: Option<Option<i32>>,
    pub processing_duration_ms: Option<Option<i64>>,
}

impl Default for NewChronicleProcessingJob {
    fn default() -> Self {
        Self {
            user_id: Uuid::nil(),
            chronicle_id: Uuid::nil(),
            status: ChronicleJobStatus::Pending,
            priority: 0,
            processing_metadata: Some(serde_json::json!({})),
        }
    }
}

impl ChronicleProcessingJob {
    /// Check if job can be retried
    pub fn can_retry(&self) -> bool {
        matches!(self.status, ChronicleJobStatus::Failed) 
            && self.attempt_count < self.max_attempts
    }
    
    /// Check if job is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status, 
            ChronicleJobStatus::Completed | ChronicleJobStatus::DeadLetter
        )
    }
    
    /// Check if job is currently being processed
    pub fn is_in_progress(&self) -> bool {
        matches!(self.status, ChronicleJobStatus::InProgress)
    }
    
    /// Get processing duration in milliseconds if completed
    pub fn get_processing_duration(&self) -> Option<i64> {
        match (&self.started_at, &self.completed_at) {
            (Some(start), Some(end)) => {
                Some((end.timestamp_millis() - start.timestamp_millis()).max(0))
            }
            _ => self.processing_duration_ms,
        }
    }
}

/// Job priority levels for easier use
impl ChronicleJobStatus {
    pub const NORMAL_PRIORITY: i32 = 0;
    pub const HIGH_PRIORITY: i32 = 100;
    pub const CRITICAL_PRIORITY: i32 = 1000;
}

/// Statistics for chronicle processing jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleJobStats {
    pub total_jobs: i64,
    pub pending_jobs: i64,
    pub in_progress_jobs: i64,
    pub completed_jobs: i64,
    pub failed_jobs: i64,
    pub dead_letter_jobs: i64,
    pub average_processing_time_ms: Option<f64>,
    pub total_events_processed: i64,
    pub total_entities_created: i64,
    pub total_components_created: i64,
    pub total_relationships_created: i64,
}