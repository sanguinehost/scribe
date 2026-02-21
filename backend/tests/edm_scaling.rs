// backend/tests/edm_scaling.rs
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, CustomizeConnection, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
use scribe_backend::db::{DbId, DbPool, DbTimestamp};
use scribe_backend::errors::Result;
use scribe_backend::models::{NewNarrativeTask, TaskStatus};
use scribe_backend::services::edm::{
    DurableWorkflow, NarrativeWorker, OtelPropagation, SqliteTaskStore, TaskStore, WorkflowAction,
    WorkflowEvent,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, info_span, Instrument};

struct ScalingWorkflow {
    id: u32,
}

impl DurableWorkflow for ScalingWorkflow {
    fn workflow_type(&self) -> &'static str {
        "scaling_workflow"
    }

    fn step(&mut self, event: WorkflowEvent) -> Result<Vec<WorkflowAction>> {
        match event {
            WorkflowEvent::Start => {
                // Simulate some "work" with a small sleep
                std::thread::sleep(Duration::from_millis(10));
                Ok(vec![WorkflowAction::CompleteWorkflow(vec![self.id as u8])])
            }
            _ => Ok(vec![]),
        }
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        Ok(vec![self.id as u8])
    }
    fn restore(&mut self, data: &[u8]) -> Result<()> {
        self.id = data[0] as u32;
        Ok(())
    }
}

#[tokio::test]
#[cfg(feature = "sqlite-backend")]
async fn test_edm_scaling_concurrency() {
    // 1. Setup DB (File-based for multi-connection simulation)
    let temp_db = "/tmp/edm_scaling_test.db";
    let _ = std::fs::remove_file(temp_db);

    #[derive(Debug, Clone, Copy)]
    struct SqliteCustomizer;

    impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqliteCustomizer {
        fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
            diesel::sql_query("PRAGMA journal_mode = WAL;")
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;
            diesel::sql_query("PRAGMA busy_timeout = 10000;")
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;
            Ok(())
        }
    }

    let manager = ConnectionManager::<SqliteConnection>::new(temp_db);
    let pool: DbPool = Pool::builder()
        .max_size(20)
        .connection_customizer(Box::new(SqliteCustomizer))
        .build(manager)
        .expect("Failed to create pool");

    // Run migrations
    {
        use scribe_backend::db::MIGRATIONS;
        let mut conn = pool.get().expect("Failed to get connection for migrations");
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let pool_arc = Arc::new(pool);
    let store = Arc::new(SqliteTaskStore::new(pool_arc.clone()));

    // 2. Enqueue N tasks
    let num_tasks = 50;
    let trace_ctx = OtelPropagation::serialize_current_context();

    for i in 0..num_tasks {
        let task_id = DbId::new();
        let new_task = NewNarrativeTask {
            id: task_id,
            user_id: DbId::new(),
            session_id: DbId::new(),
            workflow_type: "scaling_workflow".to_string(),
            current_state: vec![i as u8],
            status: TaskStatus::Pending.to_string(),
            trace_context: trace_ctx.clone(),
            expires_at: DbTimestamp::from(Utc::now() + chrono::Duration::minutes(5)),
            last_step_at: DbTimestamp::from(Utc::now()),
        };
        store.enqueue_task(new_task).await.unwrap();
    }

    info!("Enqueued {} tasks", num_tasks);

    // 3. Spawn M workers
    let num_workers = 5;
    let completed_count = Arc::new(AtomicU32::new(0));
    let mut worker_joins = vec![];

    for w in 0..num_workers {
        let store_clone = store.clone();
        let completed_clone = completed_count.clone();
        let worker_name = format!("worker_{}", w);

        let join = tokio::spawn(async move {
            let mut worker = NarrativeWorker::new(worker_name.clone(), store_clone.clone());
            worker.register_workflow("scaling_workflow".to_string(), || {
                Box::new(ScalingWorkflow { id: 0 })
            });

            let mut processed_by_this_worker = 0;
            loop {
                match store_clone.claim_next_task(&worker_name).await {
                    Ok(Some(task)) => {
                        worker
                            .process_task(task)
                            .await
                            .expect("Worker failed to process");
                        processed_by_this_worker += 1;
                        completed_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(None) => break, // No more tasks
                    Err(e) => {
                        eprintln!("Worker {} error: {:?}", worker_name, e);
                        break;
                    }
                }
            }
            processed_by_this_worker
        });
        worker_joins.push(join);
    }

    // 4. Wait for completion
    let mut total_processed = 0;
    for join in worker_joins {
        total_processed += join.await.unwrap();
    }

    info!("All workers finished. Total processed: {}", total_processed);
    assert_eq!(total_processed, num_tasks);
    assert_eq!(completed_count.load(Ordering::SeqCst), num_tasks);

    // 5. Cleanup
    let _ = std::fs::remove_file(temp_db);
}
