//! Re-embed all existing lorebook entries to ensure they use atomic chunking
//! instead of fragmented chunks, fixing the issue where entries appear as multiple
//! separate fragments in the prompt.
//!
//! Usage:
//!   cargo run --bin re_embed_lorebook_entries -- --username <username> --password <password>
//!   
//! This tool requires user credentials to decrypt encrypted lorebook entries.

use anyhow::{Result, Context};
use scribe_backend::{
    auth::session_dek::SessionDek,
    config::Config,
    models::{lorebooks::LorebookEntry, users::{User, UserDbQuery}},
    schema::{lorebook_entries, users},
    state::AppState,
    logging::init_subscriber,
    llm::{gemini_client::build_gemini_client, gemini_embedding_client::build_gemini_embedding_client},
    vector_db::QdrantClientService,
    services::embeddings::metadata::LorebookEntryParams,
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

    /// Process all users' lorebook entries (admin only)
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
    
    info!("Starting lorebook entry re-embedding process...");
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
    
    // Get lorebook entries for the user (or all if admin)
    let entries: Vec<LorebookEntry> = if args.all_users {
        warn!("Processing ALL users' lorebook entries - this may take a long time!");
        // Get all entries (admin mode)
        state
            .pool
            .get()
            .await
            .context("Failed to get database connection")?
            .interact(|conn| {
                lorebook_entries::table
                    .select(LorebookEntry::as_select())
                    .load(conn)
                    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
            })
            .await
            .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))??
    } else {
        // Get entries only for this user
        let user_id = user.id;
        state
            .pool
            .get()
            .await
            .context("Failed to get database connection")?
            .interact(move |conn| {
                lorebook_entries::table
                    .filter(lorebook_entries::user_id.eq(user_id))
                    .select(LorebookEntry::as_select())
                    .load(conn)
                    .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
            })
            .await
            .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))??
    };
        
    info!("Found {} lorebook entries to re-embed", entries.len());
    
    let total_entries = entries.len();
    let start_time = Instant::now();
    
    // Use a semaphore to limit concurrent processing (avoid overwhelming API)
    let max_concurrent = 5; // Process up to 5 entries concurrently
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    
    info!("Processing {} lorebook entries with max {} concurrent tasks", total_entries, max_concurrent);
    
    // Process entries in chunks to provide progress updates
    let chunk_size = 20;
    let mut processed = 0;
    let mut failed = 0;
    
    for (chunk_idx, chunk) in entries.chunks(chunk_size).enumerate() {
        let chunk_start = chunk_idx * chunk_size;
        info!("Processing chunk {}/{} (entries {}-{})", 
               chunk_idx + 1, 
               (total_entries + chunk_size - 1) / chunk_size,
               chunk_start + 1,
               std::cmp::min(chunk_start + chunk_size, total_entries));
        
        // Create tasks for this chunk
        let tasks: Vec<_> = chunk
            .iter()
            .enumerate()
            .map(|(idx_in_chunk, entry)| {
                let state = state.clone();
                let semaphore = semaphore.clone();
                let entry = entry.clone();
                let session_dek = session_dek.clone();
                let global_idx = chunk_start + idx_in_chunk;
                
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    // Add staggered delay to avoid all hitting API at once
                    sleep(Duration::from_millis((idx_in_chunk * 1000) as u64)).await;
                    
                    info!(
                        progress = format!("{}/{}", global_idx + 1, total_entries),
                        entry_id = %entry.id,
                        lorebook_id = %entry.lorebook_id,
                        title = entry.name.as_deref().unwrap_or("<encrypted>"),
                        "Processing lorebook entry for re-embedding"
                    );
                    
                    // Delete existing embeddings for this entry
                    if let Err(e) = state
                        .embedding_pipeline_service
                        .delete_lorebook_entry_chunks(state.clone(), entry.id, entry.user_id)
                        .await
                    {
                        error!("Failed to delete existing embeddings for entry {}: {}", entry.id, e);
                        // Continue anyway - we'll try to re-embed
                    }
                    
                    // Decrypt the content using the session DEK  
                    let decrypted_content = match (&entry.content_ciphertext, &entry.content_nonce) {
                        (content, nonce) if !content.is_empty() && !nonce.is_empty() => {
                            match scribe_backend::crypto::decrypt_gcm(content, nonce, &session_dek.0) {
                                Ok(plaintext_bytes) => {
                                    String::from_utf8(plaintext_bytes.expose_secret().clone())
                                        .unwrap_or_else(|_| {
                                            warn!("Failed to convert decrypted content to UTF-8 for entry {}", entry.id);
                                            String::new()
                                        })
                                }
                                Err(e) => {
                                    error!("Failed to decrypt content for entry {}: {}", entry.id, e);
                                    return Err(anyhow::anyhow!("Decryption failed: {}", e));
                                }
                            }
                        }
                        _ => {
                            warn!("Entry {} has no encrypted content to re-embed", entry.id);
                            return Ok(());
                        }
                    };
                    
                    // Decrypt title if available
                    let decrypted_title = match (&entry.entry_title_ciphertext, &entry.entry_title_nonce) {
                        (title, nonce) if !title.is_empty() && !nonce.is_empty() => {
                            match scribe_backend::crypto::decrypt_gcm(title, nonce, &session_dek.0) {
                                Ok(plaintext_bytes) => {
                                    Some(String::from_utf8(plaintext_bytes.expose_secret().clone())
                                        .unwrap_or_else(|_| {
                                            warn!("Failed to convert decrypted title to UTF-8 for entry {}", entry.id);
                                            "Untitled".to_string()
                                        }))
                                }
                                Err(e) => {
                                    warn!("Failed to decrypt title for entry {}: {}", entry.id, e);
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    
                    // Decrypt keywords if available
                    let decrypted_keywords = match (&entry.keys_text_ciphertext, &entry.keys_text_nonce) {
                        (keywords, nonce) if !keywords.is_empty() && !nonce.is_empty() => {
                            match scribe_backend::crypto::decrypt_gcm(keywords, nonce, &session_dek.0) {
                                Ok(plaintext_bytes) => {
                                    let keywords_str = String::from_utf8(plaintext_bytes.expose_secret().clone())
                                        .unwrap_or_else(|_| {
                                            warn!("Failed to convert decrypted keywords to UTF-8 for entry {}", entry.id);
                                            String::new()
                                        });
                                    
                                    if keywords_str.trim().is_empty() {
                                        None
                                    } else {
                                        // Split keywords by comma and clean them up
                                        Some(keywords_str
                                            .split(',')
                                            .map(|k| k.trim().to_string())
                                            .filter(|k| !k.is_empty())
                                            .collect())
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to decrypt keywords for entry {}: {}", entry.id, e);
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    
                    // Create LorebookEntryParams for re-embedding with atomic chunking
                    let params = LorebookEntryParams {
                        original_lorebook_entry_id: entry.id,
                        lorebook_id: entry.lorebook_id,
                        user_id: entry.user_id,
                        decrypted_content,
                        decrypted_title,
                        decrypted_keywords,
                        is_enabled: entry.is_enabled,
                        is_constant: entry.is_constant,
                    };
                    
                    // Re-embed the entry using atomic chunking
                    match state
                        .embedding_pipeline_service
                        .process_and_embed_lorebook_entry(state.clone(), params)
                        .await
                    {
                        Ok(()) => {
                            info!(
                                progress = format!("{}/{}", global_idx + 1, total_entries),
                                entry_id = %entry.id,
                                "Successfully re-embedded lorebook entry with atomic chunking"
                            );
                            Ok(())
                        }
                        Err(e) => {
                            error!(
                                progress = format!("{}/{}", global_idx + 1, total_entries),
                                entry_id = %entry.id,
                                error = %e,
                                "Failed to re-embed lorebook entry"
                            );
                            Err(e.into())
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
        let entries_done = chunk_start + chunk.len();
        let avg_time_per_entry = elapsed.as_secs_f64() / entries_done as f64;
        let estimated_remaining_time = avg_time_per_entry * (total_entries - entries_done) as f64;
        
        info!(
            chunk_progress = format!("Chunk {}/{}", chunk_idx + 1, (total_entries + chunk_size - 1) / chunk_size),
            overall_progress = format!("{}/{}", entries_done, total_entries),
            success_count = processed,
            failed_count = failed,
            elapsed_time = format!("{:.1}s", elapsed.as_secs_f64()),
            avg_time_per_entry = format!("{:.1}s", avg_time_per_entry),
            estimated_remaining = format!("{:.1}s", estimated_remaining_time),
            "Chunk processing complete"
        );
    }
    
    let total_duration = start_time.elapsed();
    info!(
        "Lorebook entry re-embedding complete: {} processed, {} failed in {:.1}s", 
        processed, failed, total_duration.as_secs_f64()
    );
    
    if failed > 0 {
        error!("Some lorebook entries failed to re-embed. Check logs above for details.");
        std::process::exit(1);
    }
    
    info!("All lorebook entries successfully re-embedded with atomic chunking!");
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