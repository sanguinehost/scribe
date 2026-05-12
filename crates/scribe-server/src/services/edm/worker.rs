// backend/src/services/edm/worker.rs
use crate::errors::{AppError, Result};
use crate::models::{NarrativeTask, TaskStatus};
use crate::services::edm::otel_propagation::OtelPropagation;
use crate::services::edm::task_store::TaskStore;
use crate::services::edm::workflow::{DurableWorkflow, WorkflowAction, WorkflowEvent};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub type WorkflowFactory = Box<dyn Fn() -> Box<dyn DurableWorkflow> + Send + Sync>;

pub struct NarrativeWorker {
    worker_id: String,
    store: Arc<dyn TaskStore>,
    registry: HashMap<String, WorkflowFactory>,
}

impl NarrativeWorker {
    pub fn new(worker_id: String, store: Arc<dyn TaskStore>) -> Self {
        Self {
            worker_id,
            store,
            registry: HashMap::new(),
        }
    }

    pub fn register_workflow<F>(&mut self, workflow_type: String, factory: F)
    where
        F: Fn() -> Box<dyn DurableWorkflow> + Send + Sync + 'static,
    {
        self.registry.insert(workflow_type, Box::new(factory));
    }

    pub async fn run(&self) {
        info!(worker_id = %self.worker_id, "Starting NarrativeWorker loop");
        loop {
            match self.store.claim_next_task(&self.worker_id).await {
                Ok(Some(task)) => {
                    if let Err(e) = self.process_task(task).await {
                        error!(error = %e, "Failed to process task");
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!(error = %e, "Error claiming task");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    #[instrument(skip(self, task), fields(task_id = %task.id, workflow_type = %task.workflow_type))]
    pub async fn process_task(&self, mut task: NarrativeTask) -> Result<()> {
        // 1. Restore Trace Context
        if let Some(ref ctx_data) = task.trace_context {
            if let Some(parent_ctx) = OtelPropagation::deserialize_context(ctx_data) {
                let _ = Span::current().set_parent(parent_ctx);
            }
        }

        info!("Processing durable task");

        // 2. Instantiate Workflow
        let factory = self.registry.get(&task.workflow_type).ok_or_else(|| {
            AppError::InternalServerErrorGeneric(format!(
                "Unknown workflow type: {}",
                task.workflow_type
            ))
        })?;

        let mut workflow = factory();

        // 3. Restore State
        workflow.restore(&task.current_state)?;

        // 4. Execute Step (Start if first time, or resume)
        // For now, we just send a Start event if it's new, otherwise we might send signals.
        // This is a simplified version of the state machine.
        let event = WorkflowEvent::Start;
        let actions = workflow.step(event)?;

        // 5. Handle Actions
        for action in actions {
            match action {
                WorkflowAction::ExecuteActivity {
                    activity_type,
                    input: _,
                } => {
                    // TODO: Implement activity execution via dispatcher
                    info!(activity_type = %activity_type, "Executing activity (stub)");
                }
                WorkflowAction::CompleteWorkflow(result) => {
                    info!("Workflow completed");
                    task.status = TaskStatus::Completed.to_string();
                    task.current_state = result;
                    self.store.update_task(task.clone()).await?;
                    return Ok(());
                }
                WorkflowAction::FailWorkflow(reason) => {
                    error!(reason = %reason, "Workflow failed");
                    task.status = TaskStatus::Failed.to_string();
                    self.store.update_task(task.clone()).await?;
                    return Ok(());
                }
                WorkflowAction::Yield => {
                    info!("Workflow yielded, checkpointing");
                    break;
                }
            }
        }

        // 6. Checkpoint
        task.current_state = workflow.snapshot()?;
        task.last_step_at = crate::db::DbTimestamp::from(Utc::now());
        task.expires_at = crate::db::DbTimestamp::from(Utc::now() + chrono::Duration::minutes(5)); // Reset heartbeat
        self.store.update_task(task).await?;

        Ok(())
    }
}
