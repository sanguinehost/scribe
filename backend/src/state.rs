use diesel::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use std::sync::Arc;

// --- DB Connection Pool Type ---
pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

// --- Shared application state ---
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
}
