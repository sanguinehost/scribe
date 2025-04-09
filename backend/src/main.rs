use axum::{
    routing::{get},
    Json,
    Router,
};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use serde::Serialize;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

// Use modules from the library crate
use scribe_backend::routes::characters::{get_character, list_characters, upload_character};
use scribe_backend::state::{AppState};
// We might not need direct access to models/schema/services in main.rs itself,
// but if we do, they would be imported like:
// use scribe_backend::models; 
// use scribe_backend::schema;
// use scribe_backend::services;

// No longer need these pub mod declarations here
// pub mod models;
// pub mod routes;
// pub mod services;
// pub mod schema;

// --- DB Connection Pool Type ---
// type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

// --- Shared application state ---
// #[derive(Clone)] // Axum requires state to be Clone
// struct AppState {
//     pool: DbPool,
// }

#[tokio::main]
async fn main() {
    // Load .env file
    dotenvy::dotenv().ok();

    // Set up database connection pool
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .expect("Failed to create DB pool.");

    let app_state = AppState { pool: Arc::new(pool) };

    // Build our application with routes and state
    let app = Router::new()
        .route("/api/health", get(health_check)) // health_check is local to main.rs
        // Character routes
        .route("/api/characters", get(list_characters).post(upload_character))
        .route("/api/characters/:id", get(get_character))
        .with_state(app_state); // Pass state to the router

    // Run our application
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct HealthStatus {
    status: String,
}

// health_check remains defined locally in main.rs
async fn health_check() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok".to_string() })
} 