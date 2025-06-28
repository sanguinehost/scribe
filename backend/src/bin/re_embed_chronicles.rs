//! Re-embed all existing chronicle events to ensure they have proper embeddings
//! for semantic search after we improved the chronicle event retrieval system.
//!
//! Usage:
//!   cargo run --bin re_embed_chronicles -- --username <username> --password <password>
//!   
//! This tool requires user credentials to decrypt encrypted chronicle events.

use anyhow::{Result, Context};
use scribe_backend::{
    auth::session_dek::SessionDek,
    config::Config,
    models::{chronicle_event::ChronicleEvent, users::{User, UserDbQuery}},
    schema::{chronicle_events, users},
    state::AppState,
    logging::init_subscriber,
    llm::{gemini_client::build_gemini_client, gemini_embedding_client::build_gemini_embedding_client},
    vector_db::QdrantClientService,
};
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper, ExpressionMethods};
use std::sync::Arc;
use tracing::{info, error, warn};
use tokio::time::{sleep, Duration, Instant};
use tokio::sync::Semaphore;
use futures::future::join_all;
use clap::Parser;
use secrecy::{SecretString, ExposeSecret};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Username for authentication
    #[arg(short, long)]
    username: String,

    /// Password for authentication
    #[arg(short, long)]
    password: String,

    /// Process all users' chronicle events (admin only)
    #[arg(long)]
    all_users: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring) for rustls FIRST.
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // Load environment variables from .env file
    dotenvy::dotenv().ok(); // Don't fail if .env doesn't exist
    
    // Initialize logging  
    init_subscriber();
    
    // Parse command line arguments
    let args = Args::parse();
    
    info!("Starting chronicle event re-embedding process...");
    info!("Authenticating user: {}", args.username);
    
    // Load configuration
    let config = Arc::new(Config::load().context("Failed to load configuration")?);
    
    // Setup database connection pool 
    let database_url = config.database_url.as_ref()
        .context("DATABASE_URL is required")?;
    let pool = scribe_backend::PgPool::builder(
        deadpool_diesel::postgres::Manager::new(
            database_url.clone(),
            deadpool_diesel::postgres::Runtime::Tokio1
        )
    )
    .max_size(20)
    .build()
    .context("Failed to create database pool")?;
    
    // Initialize required services for embedding
    let api_key = config.gemini_api_key.as_ref()
        .context("GEMINI_API_KEY is required")?;
    let ai_client = Arc::new(build_gemini_client(api_key, &config.gemini_api_base_url)?);
    let embedding_client = Arc::new(build_gemini_embedding_client(config.clone())?);
    let qdrant_service = Arc::new(QdrantClientService::new(config.clone()).await?);
    
    // Initialize services - build with required external services
    let app_state = AppState::builder(pool.clone(), config)
        .with_ai_client(ai_client)
        .with_embedding_client(embedding_client)
        .with_qdrant_service(qdrant_service)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build app state: {}", e))?;
    
    let state = Arc::new(app_state);
    
    // Authenticate user and get session DEK
    let (user, session_dek) = authenticate_user(&state, &args.username, &args.password).await
        .context("Failed to authenticate user")?;
    
    info!("Successfully authenticated user: {} ({})", user.username, user.id);
    
    // Get chronicle events for the user (or all if admin)
    let events: Vec<ChronicleEvent> = if args.all_users {
        warn!("Processing ALL users' chronicle events - this may take a long time!");
        // Get all events (admin mode)
        state
            .pool
            .get()
            .await
            .context("Failed to get database connection")?
            .interact(|conn| {
                chronicle_events::table
                    .select(ChronicleEvent::as_select())
                    .load(conn)
                    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
            })
            .await
            .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))??
    } else {
        // Get events only for this user
        let user_id = user.id;
        state
            .pool
            .get()
            .await
            .context("Failed to get database connection")?
            .interact(move |conn| {
                chronicle_events::table
                    .filter(chronicle_events::user_id.eq(user_id))
                    .select(ChronicleEvent::as_select())
                    .load(conn)
                    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
            })
            .await
            .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))??
    };
        
    info!("Found {} chronicle events to re-embed", events.len());
    
    let total_events = events.len();
    let start_time = Instant::now();
    
    // Use a semaphore to limit concurrent processing (avoid overwhelming API)
    let max_concurrent = 5; // Process up to 5 events concurrently
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    
    info!("Processing {} chronicle events with max {} concurrent tasks", total_events, max_concurrent);
    
    // Process events in chunks to provide progress updates
    let chunk_size = 20;
    let mut processed = 0;
    let mut failed = 0;
    
    for (chunk_idx, chunk) in events.chunks(chunk_size).enumerate() {
        let chunk_start = chunk_idx * chunk_size;
        info!("Processing chunk {}/{} (events {}-{})", 
               chunk_idx + 1, 
               (total_events + chunk_size - 1) / chunk_size,
               chunk_start + 1,
               std::cmp::min(chunk_start + chunk_size, total_events));
        
        // Create tasks for this chunk
        let tasks: Vec<_> = chunk
            .iter()
            .enumerate()
            .map(|(idx_in_chunk, event)| {
                let state = state.clone();
                let semaphore = semaphore.clone();
                let event = event.clone();
                let session_dek = session_dek.clone();
                let global_idx = chunk_start + idx_in_chunk;
                
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    // Add staggered delay to avoid all hitting API at once
                    sleep(Duration::from_millis((idx_in_chunk * 1000) as u64)).await;
                    
                    info!(
                        progress = format!("{}/{}", global_idx + 1, total_events),
                        event_id = %event.id,
                        chronicle_id = %event.chronicle_id,
                        event_type = %event.event_type,
                        "Processing chronicle event for re-embedding"
                    );
                    
                    // Delete existing embeddings for this event
                    if let Err(e) = state
                        .embedding_pipeline_service
                        .delete_chronicle_event_chunks(state.clone(), event.id, event.user_id)
                        .await
                    {
                        error!("Failed to delete existing embeddings for event {}: {}", event.id, e);
                        // Continue anyway - we'll try to re-embed
                    }
                    
                    // Re-embed the event with the user's session DEK for decryption
                    match state
                        .embedding_pipeline_service
                        .process_and_embed_chronicle_event(state.clone(), event.clone(), Some(&session_dek))
                        .await
                    {
                        Ok(()) => {
                            info!(
                                progress = format!("{}/{}", global_idx + 1, total_events),
                                event_id = %event.id,
                                "Successfully re-embedded chronicle event"
                            );
                            Ok(())
                        }
                        Err(e) => {
                            error!(
                                progress = format!("{}/{}", global_idx + 1, total_events),
                                event_id = %event.id,
                                error = %e,
                                "Failed to re-embed chronicle event"
                            );
                            Err(e)
                        }
                    }
                })
            })
            .collect();
        
        // Wait for all tasks in this chunk to complete
        let results = join_all(tasks).await;
        
        // Count successes and failures for this chunk
        for result in results {
            match result {
                Ok(Ok(())) => processed += 1,
                Ok(Err(_)) => failed += 1,
                Err(e) => {
                    error!("Task join error: {}", e);
                    failed += 1;
                }
            }
        }
        
        let elapsed = start_time.elapsed();
        let events_done = chunk_start + chunk.len();
        let avg_time_per_event = elapsed.as_secs_f64() / events_done as f64;
        let estimated_remaining_time = avg_time_per_event * (total_events - events_done) as f64;
        
        info!(
            chunk_progress = format!("Chunk {}/{}", chunk_idx + 1, (total_events + chunk_size - 1) / chunk_size),
            overall_progress = format!("{}/{}", events_done, total_events),
            success_count = processed,
            failed_count = failed,
            elapsed_time = format!("{:.1}s", elapsed.as_secs_f64()),
            avg_time_per_event = format!("{:.1}s", avg_time_per_event),
            estimated_remaining = format!("{:.1}s", estimated_remaining_time),
            "Chunk processing complete"
        );
    }
    
    let total_duration = start_time.elapsed();
    info!(
        "Chronicle event re-embedding complete: {} processed, {} failed in {:.1}s", 
        processed, failed, total_duration.as_secs_f64()
    );
    
    if failed > 0 {
        error!("Some chronicle events failed to re-embed. Check logs above for details.");
        std::process::exit(1);
    }
    
    info!("All chronicle events successfully re-embedded!");
    Ok(())
}

/// Authenticate a user and return their User object and SessionDek for decryption
async fn authenticate_user(
    state: &Arc<AppState>, 
    username: &str, 
    password: &str
) -> Result<(User, SessionDek)> {
    use diesel::OptionalExtension;
    use scribe_backend::crypto;
    
    // Find user by username
    let user_db_query: UserDbQuery = state
        .pool
        .get()
        .await
        .context("Failed to get database connection")?
        .interact({
            let username = username.to_string();
            move |conn| {
                users::table
                    .filter(users::username.eq(&username))
                    .select(UserDbQuery::as_select())
                    .first(conn)
                    .optional()
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;
    
    let user = User::from(user_db_query);
    
    // Verify password using bcrypt directly
    if !bcrypt::verify(password, &user.password_hash)
        .map_err(|e| anyhow::anyhow!("Password verification failed: {}", e))? {
        return Err(anyhow::anyhow!("Invalid password for user '{}'", username));
    }
    
    // Derive session DEK from password (same way the login process does it)
    let password_secret = SecretString::new(password.to_string().into_boxed_str());
    let kek = crypto::derive_kek(&password_secret, &user.kek_salt)
        .map_err(|e| anyhow::anyhow!("Failed to derive KEK: {}", e))?;
    
    // Decrypt the user's DEK using the derived KEK
    let session_dek_bytes = crypto::decrypt_gcm(
        &user.encrypted_dek,
        &user.dek_nonce,
        &kek
    )
    .map_err(|e| anyhow::anyhow!("Failed to decrypt DEK: {}", e))?;
    
    let session_dek = SessionDek::new(session_dek_bytes.expose_secret().clone());
    
    Ok((user, session_dek))
}