#![cfg(feature = "payment")]

use diesel::prelude::*;
/// Credit Transaction Encryption Test Suite
///
/// Comprehensive test coverage for credit transaction encryption:
/// - Description and metadata encryption at rest
/// - Decryption roundtrip verification
/// - Edge cases: key mismatch, special characters, corrupted data
/// - Nonce uniqueness enforcement
/// - PII protection verification
use scribe_backend::models::credit::CreditTransaction;
use scribe_backend::services::payment::CreditService;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

/// Helper function to create test user
async fn create_test_user(
    pool: &deadpool_diesel::postgres::Pool,
    user_id: Uuid,
    username: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let username = username.to_string();
    let email = email.to_string();
    conn.interact(move |conn| {
        diesel::sql_query(
            "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
             dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
             total_token_cost_cents, token_usage_updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
             ON CONFLICT (id) DO NOTHING"
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(username)
        .bind::<diesel::sql_types::Text, _>(email)
        .bind::<diesel::sql_types::Text, _>("test_hash")
        .bind::<diesel::sql_types::Text, _>("test_salt")
        .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 32])
        .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 12])
        .bind::<diesel::sql_types::Text, _>("User")
        .bind::<diesel::sql_types::Text, _>("active")
        .bind::<diesel::sql_types::Int8, _>(0i64)
        .bind::<diesel::sql_types::Int8, _>(0i64)
        .bind::<diesel::sql_types::Int8, _>(0i64)
        .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
        .execute(conn)
    })
    .await??;
    Ok(())
}

// ============================================================================
// Core Encryption Tests
// ============================================================================

#[tokio::test]
async fn test_credit_description_encrypted_at_rest() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "encrypt_test", "encrypt@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Add credits with sensitive description
    let sensitive_description = "SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111";

    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact(move |conn| {
        let service = CreditService::new(config.clone());
        service.initialize_user_credits(conn, user_id)?;
        service.add_credits(
            conn,
            user_id,
            100,
            "test",
            sensitive_description,
            None,
            None,
        )
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Query database directly to verify encryption
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id;
    let transaction: CreditTransaction = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl;
            dsl::credit_transactions
                .filter(dsl::user_id.eq(test_user_id))
                .order(dsl::created_at.desc())
                .first::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transaction");

    // Verify description is encrypted (not plaintext)
    assert!(
        !transaction.description_encrypted.is_empty(),
        "Description should be encrypted"
    );

    // Verify encrypted data is NOT the plaintext string
    let encrypted_str = String::from_utf8_lossy(&transaction.description_encrypted);
    assert!(
        !encrypted_str.contains("SSN"),
        "Encrypted data should not contain plaintext SSN"
    );
    assert!(
        !encrypted_str.contains("Credit Card"),
        "Encrypted data should not contain plaintext 'Credit Card'"
    );
    assert!(
        !encrypted_str.contains("4111"),
        "Encrypted data should not contain plaintext card number"
    );

    // Verify nonce is valid (12 bytes, not all zeros)
    assert_eq!(
        transaction.description_nonce.len(),
        12,
        "Nonce should be 12 bytes (AES-GCM standard)"
    );
    assert!(
        !transaction.description_nonce.iter().all(|&b| b == 0),
        "Nonce should not be all zeros"
    );

    println!("✅ Credit description properly encrypted at rest");
}

#[tokio::test]
async fn test_credit_metadata_encrypted_at_rest() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "metadata_test", "metadata@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Add credits with PII in metadata
    let metadata = json!({
        "email": "john.doe@example.com",
        "address": "123 Main St, Apt 4B",
        "payment_method": "Visa ending in 1234",
        "ip_address": "192.168.1.100"
    });

    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact(move |conn| {
        let service = CreditService::new(config.clone());
        service.initialize_user_credits(conn, user_id)?;
        service.add_credits(
            conn,
            user_id,
            200,
            "purchase",
            "Credit package purchase",
            None,
            Some(metadata),
        )
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Query database to verify metadata encryption
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id;
    let transaction: CreditTransaction = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl;
            dsl::credit_transactions
                .filter(dsl::user_id.eq(test_user_id))
                .order(dsl::created_at.desc())
                .first::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transaction");

    // Verify metadata is encrypted
    assert!(
        transaction.metadata_encrypted.is_some(),
        "Metadata should be present"
    );
    assert!(
        transaction.metadata_nonce.is_some(),
        "Metadata nonce should be present"
    );

    let encrypted_metadata = transaction.metadata_encrypted.unwrap();
    let metadata_nonce = transaction.metadata_nonce.unwrap();

    assert!(
        !encrypted_metadata.is_empty(),
        "Metadata should be encrypted"
    );
    assert_eq!(
        metadata_nonce.len(),
        12,
        "Metadata nonce should be 12 bytes"
    );
    assert!(
        !metadata_nonce.iter().all(|&b| b == 0),
        "Metadata nonce should not be all zeros"
    );

    // Verify encrypted data is binary, not JSON
    let encrypted_str = String::from_utf8_lossy(&encrypted_metadata);
    assert!(
        !encrypted_str.contains("john.doe"),
        "Encrypted metadata should not contain plaintext email"
    );
    assert!(
        !encrypted_str.contains("123 Main St"),
        "Encrypted metadata should not contain plaintext address"
    );
    assert!(
        !encrypted_str.contains("192.168"),
        "Encrypted metadata should not contain plaintext IP"
    );

    println!("✅ Credit metadata properly encrypted at rest");
}

#[tokio::test]
async fn test_credit_transaction_decryption_roundtrip() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "decrypt_test", "decrypt@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Known description and metadata
    let original_description = "Monthly subscription credit grant";
    let original_metadata = json!({
        "plan": "premium",
        "credits": 500,
        "period": "2025-10"
    });

    // Add credits with known values
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        let metadata = original_metadata.clone();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(
                conn,
                user_id,
                500,
                "monthly_grant",
                original_description,
                None,
                Some(metadata),
            )
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Retrieve and decrypt
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id; // Rename to avoid DSL collision
    let (decrypted_description, decrypted_metadata) = conn
        .interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());

                // Get transaction
                use scribe_backend::schema::credit_transactions::dsl;
                let transaction = dsl::credit_transactions
                    .filter(dsl::user_id.eq(test_user_id))
                    .order(dsl::created_at.desc())
                    .first::<CreditTransaction>(conn)?;

                // Decrypt (using fallback DEK derivation for testing)
                service.decrypt_transaction_data(conn, test_user_id, &transaction, None)
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to decrypt");

    // Verify decrypted values match originals
    assert_eq!(
        decrypted_description, original_description,
        "Decrypted description should match original"
    );

    assert!(decrypted_metadata.is_some(), "Metadata should be decrypted");
    let metadata = decrypted_metadata.unwrap();
    assert_eq!(metadata["plan"], "premium", "Plan should match");
    assert_eq!(metadata["credits"], 500, "Credits should match");
    assert_eq!(metadata["period"], "2025-10", "Period should match");

    println!("✅ Credit transaction decryption roundtrip successful");
}

// ============================================================================
// Edge Cases & Failure Modes
// ============================================================================

#[tokio::test]
async fn test_credit_encryption_key_mismatch() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    // Create two users
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();

    create_test_user(&app.db_pool, user1_id, "user1", "user1@test.com")
        .await
        .expect("Failed to create user1");
    create_test_user(&app.db_pool, user2_id, "user2", "user2@test.com")
        .await
        .expect("Failed to create user2");

    let config = app.config.clone();

    // Add credits for user1
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user1_id)?;
            service.add_credits(
                conn,
                user1_id,
                100,
                "test",
                "User 1 secret data",
                None,
                Some(json!({"secret": "user1_value"})),
            )
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits for user1");

    // Get user1's transaction
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let transaction = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl::*;
            credit_transactions
                .filter(user_id.eq(user1_id))
                .order(created_at.desc())
                .first::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transaction");

    // Attempt to decrypt with user2's DEK (should fail gracefully)
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let result = conn
        .interact({
            let config = config.clone();
            let transaction = transaction.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                // Try to decrypt user1's transaction using user2's key derivation
                service.decrypt_transaction_data(conn, user2_id, &transaction, None)
            }
        })
        .await
        .expect("Failed to interact");

    // Should return an error (graceful failure, not panic)
    assert!(result.is_err(), "Decryption with wrong key should fail");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("decrypt") || error_msg.contains("Decryption"),
        "Error should indicate decryption failure: {}",
        error_msg
    );

    println!("✅ Key mismatch handled gracefully with error");
}

#[tokio::test]
async fn test_credit_encryption_with_special_characters() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "special_test", "special@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Description with unicode, quotes, special chars
    let description = "Crédito para José García-López d'Artagnan \"Premium\" — 50% bonus! 🎉";

    // Metadata with newlines, quotes, emoji, unicode
    let metadata = json!({
        "note": "Test\n\"quoted\"\n🎉",
        "customer": "François São Paulo",
        "address": "Calle España #123\nApartamento 4º"
    });

    // Add credits
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        let metadata = metadata.clone();
        let description = description.to_string();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(
                conn,
                user_id,
                150,
                "bonus",
                &description,
                None,
                Some(metadata),
            )
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Decrypt and verify special characters preserved
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id; // Rename to avoid DSL collision
    let (decrypted_desc, decrypted_meta) = conn
        .interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());

                use scribe_backend::schema::credit_transactions::dsl;
                let transaction = dsl::credit_transactions
                    .filter(dsl::user_id.eq(test_user_id))
                    .order(dsl::created_at.desc())
                    .first::<CreditTransaction>(conn)?;

                service.decrypt_transaction_data(conn, test_user_id, &transaction, None)
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to decrypt");

    // Verify all special characters preserved
    assert_eq!(
        decrypted_desc, description,
        "Description with special chars should be preserved"
    );

    let meta = decrypted_meta.unwrap();
    assert!(
        meta["note"].as_str().unwrap().contains("\"quoted\""),
        "Quotes should be preserved"
    );
    assert!(
        meta["note"].as_str().unwrap().contains("\n"),
        "Newlines should be preserved"
    );
    assert!(
        meta["note"].as_str().unwrap().contains("🎉"),
        "Emoji should be preserved"
    );
    assert!(
        meta["customer"].as_str().unwrap().contains("François"),
        "Accented chars should be preserved"
    );
    assert!(
        meta["address"].as_str().unwrap().contains("España"),
        "Unicode chars should be preserved"
    );

    println!("✅ Special characters and unicode preserved through encryption");
}

#[tokio::test]
async fn test_credit_encryption_nonce_uniqueness() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "nonce_test", "nonce@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Initialize credits
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user_id)
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to initialize credits");

    // Create 50 transactions with IDENTICAL data
    for i in 0..50 {
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.add_credits(
                    conn,
                    user_id,
                    10,
                    "test",
                    "Identical description for nonce test",
                    None,
                    Some(json!({"iteration": i})),
                )
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add credits");
    }

    // Query all transactions and collect nonces
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let transactions: Vec<CreditTransaction> = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl::*;
            credit_transactions
                .filter(user_id.eq(user_id))
                .load::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transactions");

    assert_eq!(transactions.len(), 50, "Should have 50 transactions");

    // Collect description nonces
    let desc_nonces: HashSet<Vec<u8>> = transactions
        .iter()
        .map(|t| t.description_nonce.clone())
        .collect();

    // Collect metadata nonces
    let meta_nonces: HashSet<Vec<u8>> = transactions
        .iter()
        .filter_map(|t| t.metadata_nonce.clone())
        .collect();

    // Verify all nonces are unique
    assert_eq!(
        desc_nonces.len(),
        50,
        "All 50 description nonces should be unique"
    );
    assert_eq!(
        meta_nonces.len(),
        50,
        "All 50 metadata nonces should be unique"
    );

    // Verify no placeholder nonces (all zeros)
    let all_zeros_nonce = vec![0u8; 12];
    assert!(
        !desc_nonces.contains(&all_zeros_nonce),
        "Should not have placeholder description nonces"
    );
    assert!(
        !meta_nonces.contains(&all_zeros_nonce),
        "Should not have placeholder metadata nonces"
    );

    // Verify all nonces are 12 bytes
    for nonce in &desc_nonces {
        assert_eq!(nonce.len(), 12, "Description nonce should be 12 bytes");
    }
    for nonce in &meta_nonces {
        assert_eq!(nonce.len(), 12, "Metadata nonce should be 12 bytes");
    }

    println!(
        "✅ Nonce uniqueness verified: 50 description nonces unique, 50 metadata nonces unique"
    );
}

#[tokio::test]
async fn test_credit_decryption_with_corrupted_data() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "corrupt_test", "corrupt@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Add valid transaction
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(
                conn,
                user_id,
                100,
                "test",
                "Original data before corruption",
                None,
                Some(json!({"status": "valid"})),
            )
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Get transaction
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let transaction_id = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl::*;
            let txn: CreditTransaction = credit_transactions
                .filter(user_id.eq(user_id))
                .order(created_at.desc())
                .first(conn)?;
            Ok::<Uuid, diesel::result::Error>(txn.id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transaction");

    // Corrupt the encrypted data (flip bits at positions 5 and 10)
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact(move |conn| {
        use scribe_backend::schema::credit_transactions::dsl::*;

        // Get current encrypted data
        let mut transaction: CreditTransaction =
            credit_transactions.find(transaction_id).first(conn)?;

        // Corrupt description
        if transaction.description_encrypted.len() > 10 {
            transaction.description_encrypted[5] ^= 0xFF;
            transaction.description_encrypted[10] ^= 0xFF;
        }

        // Update with corrupted data
        diesel::update(credit_transactions.find(transaction_id))
            .set(description_encrypted.eq(&transaction.description_encrypted))
            .execute(conn)?;

        Ok::<(), diesel::result::Error>(())
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to corrupt data");

    // Attempt to decrypt corrupted data
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id; // Rename to avoid DSL collision
    let result = conn
        .interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());

                use scribe_backend::schema::credit_transactions::dsl;
                let transaction = dsl::credit_transactions
                    .find(transaction_id)
                    .first::<CreditTransaction>(conn)?;

                service.decrypt_transaction_data(conn, test_user_id, &transaction, None)
            }
        })
        .await
        .expect("Failed to interact");

    // Should detect corruption and return error (not silent corruption)
    assert!(result.is_err(), "Corrupted data should be detected");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("decrypt") || error_msg.contains("Decryption"),
        "Error should indicate decryption failure: {}",
        error_msg
    );

    println!("✅ Data corruption detected and handled gracefully");
}

#[tokio::test]
async fn test_credit_encryption_without_metadata() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "no_meta_test", "no_meta@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Add credits with NO metadata
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    conn.interact({
        let config = config.clone();
        move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(
                conn,
                user_id,
                50,
                "test",
                "Description only, no metadata",
                None,
                None, // No metadata
            )
        }
    })
    .await
    .expect("Failed to interact")
    .expect("Failed to add credits");

    // Verify metadata fields are NULL
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let transaction: CreditTransaction = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl::*;
            credit_transactions
                .filter(user_id.eq(user_id))
                .order(created_at.desc())
                .first::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transaction");

    assert!(
        transaction.metadata_encrypted.is_none(),
        "Metadata encrypted should be NULL"
    );
    assert!(
        transaction.metadata_nonce.is_none(),
        "Metadata nonce should be NULL"
    );
    assert!(
        !transaction.description_encrypted.is_empty(),
        "Description should still be encrypted"
    );
    assert!(
        !transaction.description_nonce.is_empty(),
        "Description nonce should be present"
    );

    // Decrypt and verify None metadata
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let (decrypted_desc, decrypted_meta) = conn
        .interact({
            let config = config.clone();
            let transaction = transaction.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.decrypt_transaction_data(conn, user_id, &transaction, None)
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to decrypt");

    assert_eq!(decrypted_desc, "Description only, no metadata");
    assert!(
        decrypted_meta.is_none(),
        "Decrypted metadata should be None"
    );

    println!("✅ Encryption handles None metadata correctly");
}

// ============================================================================
// PII Protection Verification
// ============================================================================

#[tokio::test]
async fn test_no_plaintext_pii_in_credit_transactions() {
    let app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone(), None);

    let user_id = Uuid::new_v4();
    create_test_user(&app.db_pool, user_id, "pii_test", "pii@test.com")
        .await
        .expect("Failed to create user");

    let config = app.config.clone();

    // Insert transactions with known PII patterns
    let test_cases = vec![
        ("SSN: 123-45-6789", json!({"ssn": "123-45-6789"})),
        (
            "Email: john.doe@example.com",
            json!({"email": "john.doe@example.com"}),
        ),
        (
            "Card: 4111-1111-1111-1111",
            json!({"card": "4111-1111-1111-1111"}),
        ),
        ("Phone: (555) 123-4567", json!({"phone": "(555) 123-4567"})),
    ];

    for (desc, meta) in test_cases {
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact({
            let config = config.clone();
            let description = desc.to_string();
            let metadata = meta.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.add_credits(
                    conn,
                    user_id,
                    25,
                    "test",
                    &description,
                    None,
                    Some(metadata),
                )
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add credits");
    }

    // Query all transactions
    let conn = app.db_pool.get().await.expect("Failed to get connection");
    let test_user_id = user_id;
    let transactions: Vec<CreditTransaction> = conn
        .interact(move |conn| {
            use scribe_backend::schema::credit_transactions::dsl;
            dsl::credit_transactions
                .filter(dsl::user_id.eq(test_user_id))
                .load::<CreditTransaction>(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to get transactions");

    // PII patterns to check for
    let pii_patterns = vec![
        ("SSN", "123-45-6789"),
        ("Email", "john.doe"),
        ("Email domain", "@example.com"),
        ("Card number", "4111"),
        ("Phone", "555"),
        ("Phone format", "(555)"),
    ];

    // Verify no plaintext PII in encrypted fields
    for transaction in transactions {
        let desc_str = String::from_utf8_lossy(&transaction.description_encrypted);
        let meta_str = transaction
            .metadata_encrypted
            .as_ref()
            .map(|m| String::from_utf8_lossy(m))
            .unwrap_or_default();

        for (name, pattern) in &pii_patterns {
            assert!(
                !desc_str.contains(pattern),
                "Encrypted description should not contain plaintext {}: {}",
                name,
                pattern
            );
            assert!(
                !meta_str.contains(pattern),
                "Encrypted metadata should not contain plaintext {}: {}",
                name,
                pattern
            );
        }
    }

    println!("✅ No plaintext PII found in encrypted credit transaction data");
}
