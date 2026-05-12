// backend/src/services/edm/workflow.rs
use crate::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowEvent {
    Start,
    ExternalSignal(String, Vec<u8>),
    TaskCompleted(String, Vec<u8>),
    TaskFailed(String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowAction {
    ExecuteActivity {
        activity_type: String,
        input: Vec<u8>,
    },
    CompleteWorkflow(Vec<u8>),
    FailWorkflow(String),
    Yield,
}

pub trait DurableWorkflow: Send + Sync {
    /// Unique identifier for this workflow type.
    fn workflow_type(&self) -> &'static str;

    /// Process a single step in the workflow.
    fn step(&mut self, event: WorkflowEvent) -> Result<Vec<WorkflowAction>>;

    /// Serialize the current state for checkpointing.
    fn snapshot(&self) -> Result<Vec<u8>>;

    /// Restore state from a checkpoint.
    fn restore(&mut self, data: &[u8]) -> Result<()>;
}
