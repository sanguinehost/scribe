// backend/src/models/narrative_task.rs
use crate::db::{DbId, DbTimestamp};
use crate::schema::narrative_tasks;
use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Queryable,
    Selectable,
    Identifiable,
    Insertable,
    AsChangeset,
    PartialEq,
)]
#[diesel(table_name = narrative_tasks)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NarrativeTask {
    pub id: DbId,
    pub user_id: DbId,
    pub session_id: DbId,
    pub workflow_type: String,
    pub current_state: Vec<u8>,
    pub status: String,
    pub worker_id: Option<String>,
    pub trace_context: Option<String>,
    pub expires_at: DbTimestamp,
    pub last_step_at: DbTimestamp,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = narrative_tasks)]
pub struct NewNarrativeTask {
    pub id: DbId,
    pub user_id: DbId,
    pub session_id: DbId,
    pub workflow_type: String,
    pub current_state: Vec<u8>,
    pub status: String,
    pub trace_context: Option<String>,
    pub expires_at: DbTimestamp,
    pub last_step_at: DbTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Processing => "processing",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
        };
        write!(f, "{s}")
    }
}
