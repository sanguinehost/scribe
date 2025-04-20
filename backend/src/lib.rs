pub mod auth; // Added auth module
pub mod errors; // Corrected from 'error'
pub mod llm; // Added llm module
pub mod logging;
pub mod models;
pub mod routes;
pub mod schema;
pub mod services;
pub mod state;

use deadpool_diesel::postgres::{Manager as DeadpoolManager, Pool as DeadpoolPool};

// Define PgPool type alias here for library-wide use
pub type PgPool = DeadpoolPool;

// You might add common error types or other shared utilities here later.
