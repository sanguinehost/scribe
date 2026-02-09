// backend/src/services/edm/task_store.rs
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
use crate::db::{with_conn, with_conn_immediate};
use crate::db::{DbPool, DbTimestamp};
use crate::errors::{AppError, Result};
use crate::models::{NarrativeTask, NewNarrativeTask};
use async_trait::async_trait;
use diesel::prelude::*;
use std::sync::Arc;
use tracing::{debug, instrument};

#[async_trait]
pub trait TaskStore: Send + Sync {
    /// Claims the next pending or expired task.
    async fn claim_next_task(&self, claiming_worker_id: &str) -> Result<Option<NarrativeTask>>;

    /// Updates an existing task (e.g., heartbeat, state change).
    async fn update_task(&self, task: NarrativeTask) -> Result<()>;

    /// Enqueues a new task.
    async fn enqueue_task(&self, new_task: NewNarrativeTask) -> Result<()>;
}

#[cfg(feature = "postgres-backend")]
pub struct PostgresTaskStore {
    pool: Arc<DbPool>,
}

#[cfg(feature = "postgres-backend")]
impl PostgresTaskStore {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "postgres-backend")]
#[async_trait]
impl TaskStore for PostgresTaskStore {
    #[instrument(skip(self), fields(worker_id = %claiming_worker_id))]
    async fn claim_next_task(&self, claiming_worker_id: &str) -> Result<Option<NarrativeTask>> {
        use crate::schema::narrative_tasks::dsl::*;
        use chrono::Utc;

        let worker_id_str = claiming_worker_id.to_string();

        self.pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                // Postgres: Use FOR UPDATE SKIP LOCKED
                // We look for tasks that are:
                // 1. Pending
                // 2. Processing but expired (crashed worker)
                let now = Utc::now();

                let task = narrative_tasks
                    .filter(
                        status
                            .eq("pending")
                            .or(status.eq("processing").and(expires_at.lt(now))),
                    )
                    .order(created_at.asc())
                    .for_update()
                    .skip_locked()
                    .first::<NarrativeTask>(conn)
                    .optional()?;

                if let Some(mut t) = task {
                    debug!(task_id = %t.id, "Claiming task via Postgres SKIP LOCKED");
                    t.status = "processing".to_string();
                    t.worker_id = Some(worker_id_str);
                    t.updated_at = DbTimestamp::from(now);

                    diesel::update(narrative_tasks.find(t.id))
                        .set((
                            status.eq(&t.status),
                            worker_id.eq(&t.worker_id),
                            updated_at.eq(&t.updated_at),
                        ))
                        .execute(conn)?;

                    Ok(Some(t))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    async fn update_task(&self, task: NarrativeTask) -> Result<()> {
        use crate::schema::narrative_tasks::dsl::*;
        self.pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                diesel::update(narrative_tasks.find(task.id))
                    .set(&task)
                    .execute(conn)?;
                Ok(())
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    async fn enqueue_task(&self, new_task: NewNarrativeTask) -> Result<()> {
        use crate::schema::narrative_tasks::dsl::*;
        self.pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?
            .interact(move |conn| {
                diesel::insert_into(narrative_tasks)
                    .values(&new_task)
                    .execute(conn)?;
                Ok(())
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub struct SqliteTaskStore {
    pool: Arc<DbPool>,
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
impl SqliteTaskStore {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
#[async_trait]
impl TaskStore for SqliteTaskStore {
    #[instrument(skip(self), fields(worker_id = %claiming_worker_id))]
    async fn claim_next_task(&self, claiming_worker_id: &str) -> Result<Option<NarrativeTask>> {
        use crate::schema::narrative_tasks::dsl::*;
        use chrono::Utc;

        let worker_id_str = claiming_worker_id.to_string();
        let now = Utc::now();
        let now_db = DbTimestamp::from(now);
        let expiry = DbTimestamp::from(now + chrono::Duration::minutes(5));

        with_conn_immediate(self.pool.as_ref(), move |conn| {
            // SQLite: Use atomic-ish selection within immediate transaction
            let task = narrative_tasks
                .filter(
                    status
                        .eq("pending")
                        .or(status.eq("processing").and(expires_at.lt(&now_db))),
                )
                .order(created_at.asc())
                .first::<NarrativeTask>(conn)
                .optional()?;

            if let Some(mut t) = task {
                debug!(task_id = %t.id, "Claiming task via SQLite immediate transaction");
                t.status = "processing".to_string();
                t.worker_id = Some(worker_id_str);
                t.updated_at = now_db;
                t.expires_at = expiry;

                diesel::update(narrative_tasks.find(&t.id))
                    .set((
                        status.eq(&t.status),
                        worker_id.eq(&t.worker_id),
                        updated_at.eq(&t.updated_at),
                        expires_at.eq(&t.expires_at),
                    ))
                    .execute(conn)?;

                Ok(Some(t))
            } else {
                Ok(None)
            }
        })
        .await
    }

    async fn update_task(&self, task: NarrativeTask) -> Result<()> {
        use crate::schema::narrative_tasks::dsl::*;
        with_conn(self.pool.as_ref(), move |conn| {
            diesel::update(narrative_tasks.find(&task.id))
                .set(&task)
                .execute(conn)?;
            Ok(())
        })
        .await
    }

    async fn enqueue_task(&self, new_task: NewNarrativeTask) -> Result<()> {
        use crate::schema::narrative_tasks::dsl::*;
        with_conn(self.pool.as_ref(), move |conn| {
            diesel::insert_into(narrative_tasks)
                .values(&new_task)
                .execute(conn)?;
            Ok(())
        })
        .await
    }
}
