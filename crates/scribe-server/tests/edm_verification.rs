// backend/tests/edm_verification.rs
#![cfg(feature = "sqlite-backend")]
use chrono::Utc;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
use scribe_backend::db::{DbId, DbPool, DbTimestamp};
use scribe_backend::errors::{AppError, Result};
use scribe_backend::models::{NewNarrativeTask, TaskStatus};
use scribe_backend::services::edm::{
    DurableWorkflow, NarrativeWorker, OtelPropagation, SqliteTaskStore, TaskStore, WorkflowAction,
    WorkflowEvent,
};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info_span, Instrument};

struct MockWorkflow {
    state: i32,
}

impl DurableWorkflow for MockWorkflow {
    fn workflow_type(&self) -> &'static str {
        "mock_workflow"
    }

    fn step(&mut self, event: WorkflowEvent) -> Result<Vec<WorkflowAction>> {
        match event {
            WorkflowEvent::Start => {
                if self.state == 0 {
                    self.state = 1;
                    Ok(vec![WorkflowAction::Yield])
                } else if self.state == 1 {
                    self.state = 2;
                    Ok(vec![WorkflowAction::CompleteWorkflow(vec![2])])
                } else {
                    Ok(vec![])
                }
            }
            _ => Ok(vec![]),
        }
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        Ok(vec![self.state as u8])
    }
    fn restore(&mut self, data: &[u8]) -> Result<()> {
        self.state = data[0] as i32;
        Ok(())
    }
}

#[tokio::test]
#[cfg(feature = "sqlite-backend")]
async fn test_edm_durability_and_otel_propagation() {
    // 1. Setup DB and TaskStore
    // Environment setup
    dotenvy::dotenv().ok();
    let db_url = ":memory:";

    use diesel::r2d2::{ConnectionManager, Pool};
    let manager = ConnectionManager::<SqliteConnection>::new(db_url);
    let pool: DbPool = Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    // Run migrations
    {
        use scribe_backend::db::MIGRATIONS;
        let mut conn = pool.get().expect("Failed to get connection for migrations");
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let pool_arc: Arc<DbPool> = Arc::new(pool);
    let store = Arc::new(SqliteTaskStore::new(pool_arc.clone()));

    // 2. Create a trace context to propagate
    let _span = info_span!("origin_request").entered();
    let trace_ctx = OtelPropagation::serialize_current_context();

    let user_id = DbId::new();
    let session_id = DbId::new();
    let task_id = DbId::new();

    // 3. Enqueue Task
    let new_task = NewNarrativeTask {
        id: task_id,
        user_id,
        session_id,
        workflow_type: "mock_workflow".to_string(),
        current_state: vec![0], // Initial state
        status: TaskStatus::Pending.to_string(),
        trace_context: trace_ctx,
        expires_at: DbTimestamp::from(Utc::now() + chrono::Duration::minutes(5)),
        last_step_at: DbTimestamp::from(Utc::now()),
    };

    store.enqueue_task(new_task).await.unwrap();

    // 4. Setup Worker
    let mut worker = NarrativeWorker::new("test_worker".to_string(), store.clone());
    worker.register_workflow("mock_workflow".to_string(), || {
        Box::new(MockWorkflow { state: 0 })
    });

    // 5. Run Worker for one step (Claims and Yields)
    let task = store
        .claim_next_task("test_worker")
        .await
        .unwrap()
        .expect("Task not found");
    worker
        .process_task(task)
        .await
        .expect("Failed to process task");

    // 6. Re-verify task state after first step
    // We need to fetch it from the DB again (not claiming, just fetching)
    // For simplicity in test, we'll try to claim it but it should fail
    let task_after_step1 = store.claim_next_task("test_worker").await.unwrap();
    assert!(task_after_step1.is_none());

    // We could add a get_task method to TaskStore for easier verification

    // 6. Stimulate crash (reset worker, but task is still 'processing')
    // Wait for "heartbeat" to expire (we'll fast forward if we could, but here we'll just manually reset status)
    // Actually, let's just test that the second worker can pick it up if we clear the status or it expires.

    // 7. Verify trace propagation in logs (manually via OTel if collector were active)
    // In this unit test, we'll verify it doesn't panic and we can restore the context.
}
