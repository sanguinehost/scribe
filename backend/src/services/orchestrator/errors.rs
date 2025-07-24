// backend/src/services/orchestrator/errors.rs
//
// Orchestrator Error Types

use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum OrchestratorError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Phase timeout: {phase} took longer than {timeout_ms}ms")]
    PhaseTimeout { phase: String, timeout_ms: u64 },
    
    #[error("Task processing failed: {0}")]
    TaskProcessingError(String),
    
    #[error("Reasoning loop error: {0}")]
    ReasoningError(String),
    
    #[error("Tool execution failed: {tool} - {error}")]
    ToolExecutionError { tool: String, error: String },
    
    #[error("State persistence error: {0}")]
    StatePersistenceError(String),
    
    #[error("Worker conflict: task {task_id} already being processed by {worker_id}")]
    WorkerConflict { task_id: Uuid, worker_id: Uuid },
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

impl From<OrchestratorError> for crate::errors::AppError {
    fn from(error: OrchestratorError) -> Self {
        match error {
            OrchestratorError::ConfigurationError(msg) => 
                crate::errors::AppError::InternalServerErrorGeneric(msg),
            OrchestratorError::PhaseTimeout { phase, timeout_ms } => 
                crate::errors::AppError::InternalServerErrorGeneric(
                    format!("Phase {} timed out after {}ms", phase, timeout_ms)
                ),
            OrchestratorError::TaskProcessingError(msg) => 
                crate::errors::AppError::InternalServerErrorGeneric(msg),
            OrchestratorError::ReasoningError(msg) => 
                crate::errors::AppError::InternalServerErrorGeneric(msg),
            OrchestratorError::ToolExecutionError { tool, error } => 
                crate::errors::AppError::InternalServerErrorGeneric(
                    format!("Tool {} failed: {}", tool, error)
                ),
            OrchestratorError::StatePersistenceError(msg) => 
                crate::errors::AppError::InternalServerErrorGeneric(msg),
            OrchestratorError::WorkerConflict { task_id, .. } => 
                crate::errors::AppError::Conflict(
                    format!("Task {} already being processed", task_id)
                ),
            OrchestratorError::DatabaseError(msg) => 
                crate::errors::AppError::DatabaseQueryError(msg),
            OrchestratorError::EncryptionError(msg) => 
                crate::errors::AppError::EncryptionError(msg),
        }
    }
}