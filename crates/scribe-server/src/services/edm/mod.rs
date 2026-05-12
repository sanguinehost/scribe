// backend/src/services/edm/mod.rs
pub mod otel_propagation;
pub mod task_store;
pub mod worker;
pub mod workflow;

pub use otel_propagation::*;
#[cfg(feature = "postgres-backend")]
pub use task_store::PostgresTaskStore;
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub use task_store::SqliteTaskStore;
pub use task_store::TaskStore;
pub use worker::NarrativeWorker;
pub use workflow::*;
