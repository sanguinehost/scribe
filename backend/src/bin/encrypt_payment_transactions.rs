//! Encrypt existing plaintext payment transaction customer data
//!
//! This migration script addresses a critical security issue where 4 payment
//! transactions were stored with plaintext customer PII instead of being
//! properly encrypted with AES-256-GCM.
//!
//! **Security Context:**
//! - Discovered 2025-10-03: 4 transactions with all-zero nonces (placeholder values)
//! - Customer email addresses stored in plaintext in customer_data_encrypted column
//! - PCI DSS compliance violation requiring immediate remediation
//!
//! **What This Script Does:**
//! 1. Identifies transactions with placeholder nonces (all zeros)
//! 2. Reads the plaintext JSON customer data
//! 3. Generates fresh random 12-byte nonces
//! 4. Properly encrypts data with AES-256-GCM using PAYMENT_DATA_ENCRYPTION_KEY
//! 5. Updates database with encrypted data and valid nonces
//!
//! **Usage:**
//!   # Dry run (preview changes without modifying database):
//!   cargo run --bin encrypt_payment_transactions --features payment -- --dry-run
//!
//!   # Execute migration:
//!   cargo run --bin encrypt_payment_transactions --features payment
//!
//! **Prerequisites:**
//! - PAYMENT_DATA_ENCRYPTION_KEY must be set (base64-encoded 256-bit key)
//! - DATABASE_URL must be set
//! - Database backup recommended before running

use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use scribe_backend::{
    config::Config, logging::init_subscriber, models::payment::PaymentTransaction,
    schema::payment_transactions, services::encryption_service::EncryptionService,
};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Dry run mode - preview changes without modifying database
    #[arg(long)]
    dry_run: bool,

    /// Custom database URL (overrides config)
    #[arg(long)]
    database_url: Option<String>,
}

/// Placeholder nonce value (all zeros) that indicates plaintext data
const PLACEHOLDER_NONCE: [u8; 12] = [0u8; 12];

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring) for rustls FIRST
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load environment variables from .env file
    dotenvy::dotenv().ok(); // Don't fail if .env doesn't exist

    // Initialize logging
    init_subscriber();

    // Parse command line arguments
    let args = Args::parse();

    if args.dry_run {
        warn!("🔍 DRY RUN MODE - No database changes will be made");
    } else {
        warn!("⚠️  LIVE MODE - Database will be modified");
    }

    info!("Starting payment transaction encryption migration...");

    // Load configuration
    let config = Config::load().context("Failed to load configuration")?;

    // Get payment encryption key
    let payment_key = config
        .payment
        .data_encryption_key
        .as_ref()
        .context("PAYMENT_DATA_ENCRYPTION_KEY not configured - cannot encrypt data")?;

    // Decode base64 key to bytes
    let payment_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(payment_key)
        .context("Failed to decode PAYMENT_DATA_ENCRYPTION_KEY - must be valid base64")?;

    if payment_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "PAYMENT_DATA_ENCRYPTION_KEY must be 256 bits (32 bytes), got {} bytes",
            payment_key_bytes.len()
        ));
    }

    info!("✓ Payment encryption key loaded successfully (256 bits)");

    // Setup database connection pool
    let database_url = args
        .database_url
        .or_else(|| config.database_url.clone())
        .context("DATABASE_URL is required")?;

    let pool = scribe_backend::PgPool::builder(deadpool_diesel::postgres::Manager::new(
        database_url.clone(),
        deadpool_diesel::postgres::Runtime::Tokio1,
    ))
    .max_size(5)
    .build()
    .context("Failed to create database pool")?;

    info!("✓ Database connection pool created");

    // Query for transactions with placeholder nonces
    info!("Querying for transactions with placeholder nonces...");

    let conn = pool
        .get()
        .await
        .context("Failed to get database connection")?;

    let placeholder_transactions: Vec<PaymentTransaction> = conn
        .interact(|conn| {
            use diesel::prelude::*;
            payment_transactions::table
                .filter(payment_transactions::customer_data_nonce.eq(PLACEHOLDER_NONCE.to_vec()))
                .load::<PaymentTransaction>(conn)
                .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))??;

    let total_to_migrate = placeholder_transactions.len();

    if total_to_migrate == 0 {
        info!("✓ No transactions with placeholder nonces found - migration not needed");
        return Ok(());
    }

    warn!(
        "Found {} transactions with placeholder nonces (plaintext customer data)",
        total_to_migrate
    );

    // Display transaction details
    info!("Transactions requiring encryption:");
    for (idx, txn) in placeholder_transactions.iter().enumerate() {
        let created_str = txn
            .created_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        info!(
            "  {}. ID: {} | Paddle ID: {} | User: {} | Created: {}",
            idx + 1,
            txn.id,
            txn.paddle_transaction_id,
            txn.user_id,
            created_str
        );

        // Display plaintext preview (WARNING: contains PII)
        if let Some(ref plaintext_bytes) = txn.customer_data_encrypted {
            match String::from_utf8(plaintext_bytes.clone()) {
                Ok(plaintext) => {
                    // Redact email for logging (show first 3 chars + @domain)
                    let redacted = if plaintext.len() > 50 {
                        format!("{}...", &plaintext[..50])
                    } else {
                        plaintext.clone()
                    };
                    warn!("     Plaintext data preview: {}", redacted);
                }
                Err(_) => {
                    warn!("     Data appears to already be encrypted (not valid UTF-8)");
                }
            }
        }
    }

    if args.dry_run {
        info!("DRY RUN: Would encrypt {} transactions", total_to_migrate);
        info!("To execute migration, run without --dry-run flag");
        return Ok(());
    }

    // Initialize encryption service
    let encryption_service = EncryptionService::new();

    // Process each transaction
    let mut migrated = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for (idx, txn) in placeholder_transactions.into_iter().enumerate() {
        info!(
            "Processing transaction {}/{}: {}",
            idx + 1,
            total_to_migrate,
            txn.id
        );

        match migrate_transaction(
            &pool,
            &encryption_service,
            &payment_key_bytes,
            txn.id,
            txn.customer_data_encrypted.clone(),
            txn.paddle_data_encrypted.clone(),
        )
        .await
        {
            Ok(MigrationResult::Success {
                old_nonce,
                new_nonce,
            }) => {
                migrated += 1;
                info!(
                    "✓ Migrated transaction {}: nonce {} → {}",
                    txn.id,
                    hex::encode(old_nonce),
                    hex::encode(new_nonce)
                );
            }
            Ok(MigrationResult::Skipped(reason)) => {
                skipped += 1;
                warn!("⊘ Skipped transaction {}: {}", txn.id, reason);
            }
            Err(e) => {
                failed += 1;
                error!("✗ Failed to migrate transaction {}: {}", txn.id, e);
            }
        }
    }

    // Final summary
    info!("═════════════════════════════════════════════");
    info!("Migration Summary:");
    info!("  Total transactions processed: {}", total_to_migrate);
    info!("  Successfully migrated: {}", migrated);
    info!("  Skipped: {}", skipped);
    info!("  Failed: {}", failed);
    info!("═════════════════════════════════════════════");

    if failed > 0 {
        error!(
            "Migration completed with {} failures - review logs above",
            failed
        );
        std::process::exit(1);
    }

    if migrated == 0 {
        warn!("No transactions were migrated - all were skipped");
        std::process::exit(0);
    }

    info!("✓ All transactions successfully encrypted!");

    // Verify no placeholder nonces remain
    let conn = pool
        .get()
        .await
        .context("Failed to get database connection for verification")?;

    let remaining_placeholder_count: i64 = conn
        .interact(|conn| {
            use diesel::dsl::count_star;
            use diesel::prelude::*;
            payment_transactions::table
                .filter(payment_transactions::customer_data_nonce.eq(PLACEHOLDER_NONCE.to_vec()))
                .select(count_star())
                .first::<i64>(conn)
                .map_err(|e| anyhow::anyhow!("Verification query failed: {}", e))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed during verification: {}", e))??;

    if remaining_placeholder_count > 0 {
        error!(
            "⚠️  Verification failed: {} transactions still have placeholder nonces",
            remaining_placeholder_count
        );
        std::process::exit(1);
    }

    info!("✓ Verification passed: No placeholder nonces remaining");
    Ok(())
}

enum MigrationResult {
    Success {
        old_nonce: Vec<u8>,
        new_nonce: Vec<u8>,
    },
    #[allow(dead_code)]
    Skipped(String),
}

/// Migrate a single transaction
async fn migrate_transaction(
    pool: &scribe_backend::PgPool,
    encryption_service: &EncryptionService,
    payment_key_bytes: &[u8],
    transaction_id: Uuid,
    customer_data_encrypted: Option<Vec<u8>>,
    paddle_data_encrypted: Option<Vec<u8>>,
) -> Result<MigrationResult> {
    // Verify customer data exists
    let customer_data_bytes =
        customer_data_encrypted.ok_or_else(|| anyhow::anyhow!("No customer data to encrypt"))?;

    // Try to parse as UTF-8 JSON (plaintext)
    let customer_data_str = String::from_utf8(customer_data_bytes.clone())
        .context("Customer data is not valid UTF-8 - might already be encrypted or corrupted")?;

    // Verify it's valid JSON
    let _customer_data_json: serde_json::Value = serde_json::from_str(&customer_data_str)
        .context("Customer data is not valid JSON - cannot encrypt")?;

    // Encrypt customer data with fresh nonce
    let (new_customer_encrypted, new_customer_nonce) = encryption_service
        .encrypt(&customer_data_str, payment_key_bytes)
        .context("Failed to encrypt customer data")?;

    info!(
        "Encrypted customer data: {} bytes plaintext → {} bytes encrypted",
        customer_data_str.len(),
        new_customer_encrypted.len()
    );

    // Encrypt paddle data if present (also plaintext)
    let (new_paddle_encrypted, new_paddle_nonce) =
        if let Some(paddle_data_bytes) = paddle_data_encrypted {
            let paddle_data_str =
                String::from_utf8(paddle_data_bytes).context("Paddle data is not valid UTF-8")?;

            // Verify it's valid JSON
            let _paddle_data_json: serde_json::Value =
                serde_json::from_str(&paddle_data_str).context("Paddle data is not valid JSON")?;

            let (encrypted, nonce) = encryption_service
                .encrypt(&paddle_data_str, payment_key_bytes)
                .context("Failed to encrypt paddle data")?;

            (Some(encrypted), Some(nonce))
        } else {
            (None, None)
        };

    // Update database with encrypted data and new nonces
    let conn = pool
        .get()
        .await
        .context("Failed to get database connection")?;

    let old_nonce = PLACEHOLDER_NONCE.to_vec();

    let result = conn
        .interact(move |conn| {
            use diesel::prelude::*;

            diesel::update(payment_transactions::table.find(transaction_id))
                .set((
                    payment_transactions::customer_data_encrypted.eq(Some(new_customer_encrypted)),
                    payment_transactions::customer_data_nonce.eq(Some(new_customer_nonce.clone())),
                    payment_transactions::paddle_data_encrypted.eq(new_paddle_encrypted),
                    payment_transactions::paddle_data_nonce.eq(new_paddle_nonce),
                ))
                .execute(conn)
                .map_err(|e| anyhow::anyhow!("Failed to update transaction: {}", e))
                .map(|_| MigrationResult::Success {
                    old_nonce: old_nonce.clone(),
                    new_nonce: new_customer_nonce,
                })
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed during update: {}", e))??;

    Ok(result)
}
