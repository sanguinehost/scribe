//! Cleanup orphaned embeddings from the vector database.
//!
//! This tool scans all embeddings in the vector database and cross-references them
//! with the main database. If an entity (lorebook entry, chat message, or chronicle event)
//! no longer exists in the main database, its corresponding embeddings are deleted.
//!
//! Usage:
//!   cargo run --bin cleanup_embeddings
//!
//! Optional flags:
//!   --dry-run: Only show what would be deleted without actually deleting.

use anyhow::{Context, Result};
use clap::Parser;
use diesel::prelude::*;
use scribe_backend::{config::Config, vector_db::qdrant_client::QdrantClientServiceTrait};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Only show what would be deleted without actually deleting
    #[arg(long)]
    dry_run: bool,

    /// Batch size for processing embeddings
    #[arg(long, default_value = "100")]
    batch_size: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring) for rustls FIRST.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize logging
    scribe_backend::logging::init_subscriber();

    // Parse command line arguments
    let args = Args::parse();

    if args.dry_run {
        info!("DRY RUN MODE: No deletions will be performed.");
    }

    // Load configuration
    let config = Arc::new(Config::load().context("Failed to load configuration")?);

    // Setup database connection pool
    let database_url = config
        .database_url
        .as_ref()
        .context("DATABASE_URL is required")?;

    #[cfg(feature = "postgres-backend")]
    let pool = {
        use deadpool_diesel::postgres::{Manager, Runtime};
        scribe_backend::db::DbPool::builder(Manager::new(database_url.clone(), Runtime::Tokio1))
            .max_size(5)
            .build()
            .context("Failed to create database pool")?
    };

    #[cfg(feature = "sqlite-backend")]
    let pool = {
        use diesel::r2d2::{ConnectionManager, Pool};
        use diesel::SqliteConnection;
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        Pool::builder()
            .max_size(5)
            .build(manager)
            .context("Failed to create database pool")?
    };

    // Initialize vector database service
    #[cfg(feature = "remote-vector")]
    let qdrant_service = {
        info!("Initializing Qdrant client service (remote-vector mode)...");
        let service = Arc::new(QdrantClientService::new(config.clone()).await?);
        service as Arc<dyn QdrantClientServiceTrait + Send + Sync>
    };

    #[cfg(feature = "embedded-vector")]
    let qdrant_service = {
        info!("Initializing LanceDB vector service (embedded-vector mode)...");
        use scribe_backend::vector_db::lancedb_client::LanceDbClient;
        let service = Arc::new(LanceDbClient::new(config.clone()).await?);
        service.ensure_collection_exists().await?;
        service as Arc<dyn QdrantClientServiceTrait + Send + Sync>
    };

    // Fallback when neither remote-vector nor embedded-vector is enabled
    #[cfg(not(any(feature = "remote-vector", feature = "embedded-vector")))]
    let qdrant_service = {
        info!("Initializing no-op vector service (no vector features enabled)...");
        use scribe_backend::vector_db::qdrant_client::NoOpQdrantService;
        let service = Arc::new(NoOpQdrantService::new(config.clone()).await?);
        service as Arc<dyn QdrantClientServiceTrait + Send + Sync>
    };

    info!("Starting embedding cleanup process...");

    // 1. Retrieve all points from the vector database
    // Note: We might need to do this in batches if the database is very large.
    // For now, we'll retrieve them in batches using the limit.

    let mut total_deleted = 0;
    let mut total_checked = 0;

    let mut offset = 0;
    loop {
        info!(
            "Retrieving batch of embeddings (limit: {}, offset: {})",
            args.batch_size, offset
        );

        // We use retrieve_points with no filter to get all points
        let points = qdrant_service
            .retrieve_points(None, args.batch_size, Some(offset))
            .await?;

        if points.is_empty() {
            break;
        }

        let batch_len = points.len();
        total_checked += batch_len;

        let mut points_to_delete = Vec::new();

        for point in points {
            let point_id = match &point.id {
                Some(id) => id.clone(),
                None => continue,
            };

            let payload = &point.payload;
            let source_type = payload
                .get("source_type")
                .and_then(|v| v.as_str())
                .map_or("unknown", |v| v);

            let exists = match source_type {
                "lorebook_entry" => {
                    if let Some(entry_id_str) = payload
                        .get("original_lorebook_entry_id")
                        .and_then(|v| v.as_str())
                    {
                        if let Ok(entry_id) = scribe_backend::db::DbId::parse_str(entry_id_str) {
                            check_lorebook_entry_exists(&pool, entry_id).await?
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                "chat_message" => {
                    if let Some(msg_id_str) = payload.get("message_id").and_then(|v| v.as_str()) {
                        if let Ok(msg_id) = scribe_backend::db::DbId::parse_str(msg_id_str) {
                            check_chat_message_exists(&pool, msg_id).await?
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                "chronicle_event" => {
                    if let Some(event_id_str) = payload.get("event_id").and_then(|v| v.as_str()) {
                        if let Ok(event_id) = scribe_backend::db::DbId::parse_str(event_id_str) {
                            check_chronicle_event_exists(&pool, event_id).await?
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                _ => {
                    warn!("Unknown source_type: {}. Skipping.", source_type);
                    true // Assume it exists to be safe
                }
            };

            if !exists {
                info!(
                    "Orphaned embedding found: ID={:?}, source_type={}, payload={:?}",
                    point_id, source_type, payload
                );
                points_to_delete.push(point_id);
            }
        }

        let num_deleted_in_batch = points_to_delete.len();
        if !points_to_delete.is_empty() {
            if !args.dry_run {
                info!("Deleting {} orphaned embeddings...", num_deleted_in_batch);
                qdrant_service.delete_points(points_to_delete).await?;
            } else {
                info!(
                    "DRY RUN: Would delete {} orphaned embeddings.",
                    num_deleted_in_batch
                );
            }
            total_deleted += num_deleted_in_batch;
        }

        // If we got fewer points than the batch size, we've reached the end
        if (batch_len as u64) < args.batch_size {
            break;
        }

        // If we are in dry_run mode, we must increment offset because we didn't delete anything
        if args.dry_run {
            offset += args.batch_size;
        } else {
            // If we are NOT in dry_run mode, we deleted the points, so we don't need to increment offset
            // (the next batch will start from the same physical offset but with new data)
            // However, if we didn't delete ALL points in the batch, we might need to be careful.
            // Actually, the current logic retrieves ALL points in a batch, then deletes some.
            // If we don't increment offset, we'll retrieve the points we DIDN'T delete again.
            // So we SHOULD increment offset by the number of points we DIDN'T delete.
            offset += (batch_len - num_deleted_in_batch) as u64;
        }
    }

    info!(
        "Cleanup complete. Checked {} embeddings, deleted {} orphaned embeddings.",
        total_checked, total_deleted
    );

    // 2. Optimize the collection
    if !args.dry_run {
        info!("Optimizing vector database...");
        qdrant_service.optimize_collection().await?;
        info!("Optimization complete.");
    }

    Ok(())
}

async fn check_lorebook_entry_exists(
    pool: &scribe_backend::db::DbPool,
    entry_id: scribe_backend::db::DbId,
) -> Result<bool> {
    scribe_backend::db::with_conn(pool, move |conn| {
        use scribe_backend::schema::lorebook_entries;
        lorebook_entries::table
            .filter(lorebook_entries::id.eq(entry_id))
            .select(diesel::dsl::count_star())
            .get_result::<i64>(conn)
            .map(|count| count > 0)
            .map_err(scribe_backend::errors::AppError::from)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
}

async fn check_chat_message_exists(
    pool: &scribe_backend::db::DbPool,
    msg_id: scribe_backend::db::DbId,
) -> Result<bool> {
    scribe_backend::db::with_conn(pool, move |conn| {
        use scribe_backend::schema::chat_messages;
        chat_messages::table
            .filter(chat_messages::id.eq(msg_id))
            .select(diesel::dsl::count_star())
            .get_result::<i64>(conn)
            .map(|count| count > 0)
            .map_err(scribe_backend::errors::AppError::from)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
}

async fn check_chronicle_event_exists(
    pool: &scribe_backend::db::DbPool,
    event_id: scribe_backend::db::DbId,
) -> Result<bool> {
    scribe_backend::db::with_conn(pool, move |conn| {
        use scribe_backend::schema::chronicle_events;
        chronicle_events::table
            .filter(chronicle_events::id.eq(event_id))
            .select(diesel::dsl::count_star())
            .get_result::<i64>(conn)
            .map(|count| count > 0)
            .map_err(scribe_backend::errors::AppError::from)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
}
