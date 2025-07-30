// backend/src/services/task_queue/types.rs
//
// Task Queue Types for Epic 8: Orchestrator-Driven Intelligent Agent System

use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use diesel::prelude::*;
use crate::schema::world_enrichment_tasks;

/// Task status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum TaskStatus {
    Pending = 0,
    InProgress = 1,
    Completed = 2,
    Failed = 3,
}

impl From<i32> for TaskStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => TaskStatus::Pending,
            1 => TaskStatus::InProgress,
            2 => TaskStatus::Completed,
            3 => TaskStatus::Failed,
            _ => TaskStatus::Pending, // Default fallback
        }
    }
}

/// Task priority enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum TaskPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
}

impl From<i32> for TaskPriority {
    fn from(value: i32) -> Self {
        match value {
            0 => TaskPriority::Critical,
            1 => TaskPriority::High,
            2 => TaskPriority::Normal,
            3 => TaskPriority::Low,
            _ => TaskPriority::Normal, // Default fallback
        }
    }
}

/// Database model for enrichment tasks
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = world_enrichment_tasks)]
pub struct EnrichmentTask {
    pub id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub status: i32,
    pub priority: i32,
    pub encrypted_payload: Vec<u8>,
    pub payload_nonce: Vec<u8>,
    pub encrypted_error: Option<Vec<u8>>,
    pub error_nonce: Option<Vec<u8>>,
    pub retry_count: i32,
    pub worker_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insertable model for creating new tasks
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = world_enrichment_tasks)]
pub struct NewEnrichmentTask {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub status: i32,
    pub priority: i32,
    pub encrypted_payload: Vec<u8>,
    pub payload_nonce: Vec<u8>,
    pub retry_count: i32,
}

/// Decrypted task payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentTaskPayload {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub user_message: String,
    pub ai_response: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
    pub chronicle_id: Option<Uuid>,
}

/// Request structure for creating new tasks
#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub payload: EnrichmentTaskPayload,
    pub priority: TaskPriority,
}

/// Dequeued task with decrypted payload
#[derive(Debug, Clone)]
pub struct DequeuedTask {
    pub task: EnrichmentTask,
    pub payload: EnrichmentTaskPayload,
}

/// Task update parameters
#[derive(Debug, Clone)]
pub struct TaskUpdate {
    pub status: TaskStatus,
    pub error_message: Option<String>,
    pub worker_id: Option<Uuid>,
}

impl EnrichmentTask {
    /// Convert database integer to TaskStatus enum
    pub fn status(&self) -> TaskStatus {
        TaskStatus::from(self.status)
    }
    
    /// Convert database integer to TaskPriority enum  
    pub fn priority(&self) -> TaskPriority {
        TaskPriority::from(self.priority)
    }
}