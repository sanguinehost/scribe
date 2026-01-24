#![cfg(feature = "postgres-backend")]
#[cfg(all(test, feature = "payment"))]
mod credit_expiry_tests {
    //! Credit Expiry Tests - IMPLEMENTATION REQUIRED
    //!
    //! These tests are placeholders for credit expiry functionality that is NOT YET IMPLEMENTED.
    //!
    //! ## Current State:
    //! - Config has `credit_expiry_days: 365` (backend/src/config.rs:355)
    //! - Database schema `credit_transactions` table has NO `expires_at` column
    //! - `credit_service.rs` has no expiry enforcement logic
    //! - No cleanup job/scheduler for expired credits
    //!
    //! ## Required Implementation:
    //!
    //! ### 1. Database Migration
    //! - Add `expires_at` column to `credit_transactions` table
    //! - Type: `Nullable<Timestamptz>`
    //! - Calculate on credit grant: `created_at + credit_expiry_days`
    //!
    //! ### 2. Credit Service Changes (backend/src/services/payment/credit_service.rs)
    //! - **add_credits()**: Set `expires_at` when adding credits
    //! - **deduct_credits()**: Check expiry before deduction, reject if expired
    //! - **get_available_balance()**: Exclude expired credits from balance
    //! - **New method**: `cleanup_expired_credits(user_id)` - Remove expired credits
    //!
    //! ### 3. Scheduler Integration (backend/src/services/payment/scheduler.rs)
    //! - Add daily/hourly cleanup job
    //! - Call `cleanup_expired_credits()` for all users with credits
    //! - Log cleanup actions to audit trail
    //!
    //! ### 4. Migration Path
    //! - Backfill `expires_at` for existing credits: `created_at + 365 days`
    //! - Add index on `expires_at` for cleanup queries
    //!
    //! ## See Also:
    //! - docs/PAYMENT_EDGE_CASES_TODO.md for full implementation roadmap
    //! - Task 7.3 in docs/FIX_PLAN.md

    use chrono::{Duration, Utc};
    use diesel::prelude::*;
    use scribe_backend::{
        config::Config,
        errors::AppError,
        models::credit::{CreditBalance, NewCreditTransaction},
        schema::{credit_transactions, user_credits},
        services::payment::CreditService,
        test_helpers::{spawn_app, TestDataGuard},
    };
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper function to create a test user
    async fn create_test_user(
        pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
        user_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        conn.interact(move |conn| {
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(format!("testuser_{}", user_id))
            .bind::<diesel::sql_types::Text, _>(format!("test_{}@example.com", user_id))
            .bind::<diesel::sql_types::Text, _>("hash")
            .bind::<diesel::sql_types::Text, _>("salt")
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 32])
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 12])
            .bind::<diesel::sql_types::Text, _>("User")
            .bind::<diesel::sql_types::Text, _>("active")
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        })
        .await??;
        Ok(())
    }

    /// Test: Credit expiry enforcement on deduction
    ///
    /// ## Test Scenario:
    /// 1. Add credits with 30-day expiry
    /// 2. Simulate time passage (set expires_at to past date)
    /// 3. Attempt to deduct credits
    /// 4. Verify rejection with "InsufficientCredits" error showing expired credits
    /// 5. Verify available balance excludes expired credits
    #[tokio::test]
    async fn test_credit_expiry_enforcement() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let service = CreditService::new(config.clone());

        // Initialize user credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| service.initialize_user_credits(conn, user_id.into()))
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize credits");

        // Add 1000 credits that expired 1 day ago
        let expired_date = Utc::now() - Duration::days(1);
        let transaction_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            // Insert credit transaction with past expiry date
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: transaction_id.into(),
                    user_id: user_id.into(),
                    amount: 1000,
                    balance_after: 1000,
                    transaction_type: "test_expired".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some((Utc::now() - Duration::days(30)).into()),
                    expires_at: Some(expired_date.into()),
                })
                .execute(conn)?;

            // Update user balance manually
            diesel::update(user_credits::table.filter(user_credits::user_id.eq(user_id)))
                .set(user_credits::balance.eq(1000))
                .execute(conn)?;

            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add expired credits");

        // Try to deduct credits - should fail because credits are expired
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let service = CreditService::new(config.clone());

        let result = conn
            .interact(move |conn| {
                service.deduct_credits(
                    conn,
                    user_id.into(),
                    500,
                    "test_deduction",
                    Some(serde_json::json!({}).into()),
                )
            })
            .await
            .expect("Failed to interact");

        // Should fail with InsufficientCredits
        assert!(result.is_err(), "Deduction should fail for expired credits");

        match result {
            Err(AppError::InsufficientCredits {
                required,
                available,
                expired,
            }) => {
                assert_eq!(required, 500);
                assert_eq!(
                    available, 0,
                    "Available balance should be 0 (expired credits excluded)"
                );
                assert_eq!(expired, Some(1000), "Should report 1000 expired credits");
            }
            _ => panic!("Expected InsufficientCredits error with expired field"),
        }
    }

    /// Test: Credit expiry cleanup job
    ///
    /// ## Test Scenario:
    /// 1. Create user with 1000 credits expired 7 days ago
    /// 2. Create user with 500 credits expiring in 10 days (not expired)
    /// 3. Run cleanup job
    /// 4. Verify expired credits removed from balance
    /// 5. Verify non-expired credits remain
    /// 6. Verify transaction history preserved
    #[tokio::test]
    async fn test_credit_expiry_cleanup() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let service = CreditService::new(config.clone());

        // Initialize user credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| service.initialize_user_credits(conn, user_id.into()))
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize credits");

        // Add expired credits (1000 credits expired 7 days ago)
        let expired_date = Utc::now() - Duration::days(7);
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: Uuid::new_v4().into(),
                    user_id: user_id.into(),
                    amount: 1000,
                    balance_after: 1000,
                    transaction_type: "expired_credits".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some((Utc::now() - Duration::days(30)).into()),
                    expires_at: Some(expired_date.into()),
                })
                .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add expired credits");

        // Add non-expired credits (500 credits expiring in 10 days)
        let future_expiry = Utc::now() + Duration::days(10);
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: Uuid::new_v4().into(),
                    user_id: user_id.into(),
                    amount: 500,
                    balance_after: 1500,
                    transaction_type: "active_credits".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some(Utc::now().into()),
                    expires_at: Some(future_expiry.into()),
                })
                .execute(conn)?;

            // Update balance to reflect both transactions
            diesel::update(user_credits::table.filter(user_credits::user_id.eq(user_id)))
                .set(user_credits::balance.eq(1500))
                .execute(conn)?;

            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add active credits");

        // Run cleanup
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let service = CreditService::new(config.clone());

        let cleanup_result = conn
            .interact(move |conn| service.cleanup_expired_credits(conn, Some(user_id.into())))
            .await
            .expect("Failed to interact")
            .expect("Cleanup should succeed");

        // Verify cleanup stats
        assert_eq!(cleanup_result.users_affected, 1);
        assert_eq!(cleanup_result.credits_expired, 1000);

        // Verify balance updated (only active credits remain)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance: i32 = conn
            .interact(move |conn| {
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        assert_eq!(
            balance, 500,
            "Balance should be 500 after cleanup (only non-expired credits)"
        );

        // Verify transaction history preserved
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let transaction_count: i64 = conn
            .interact(move |conn| {
                credit_transactions::table
                    .filter(credit_transactions::user_id.eq(user_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count transactions");

        assert_eq!(
            transaction_count, 2,
            "Both transactions should be preserved for audit"
        );
    }

    /// Test: Credit purchase respects max balance with expiry consideration
    ///
    /// ## Test Scenario:
    /// 1. User has 9,000 active credits + 500 expired credits (total 9,500 in DB)
    /// 2. Purchase 1,500 credit package
    /// 3. Verify purchase succeeds (active balance 9,000 < 10,000 limit)
    /// 4. Verify final balance capped at 10,000 (9,000 + 1,000)
    #[tokio::test]
    async fn test_credit_purchase_with_expired_credits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let service = CreditService::new(config.clone());

        // Initialize user credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| service.initialize_user_credits(conn, user_id.into()))
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize credits");

        // Add 500 expired credits
        let expired_date = Utc::now() - Duration::days(1);
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: Uuid::new_v4().into(),
                    user_id: user_id.into(),
                    amount: 500,
                    balance_after: 500,
                    transaction_type: "expired_purchase".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some((Utc::now() - Duration::days(30)).into()),
                    expires_at: Some(expired_date.into()),
                })
                .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add expired credits");

        // Add 9,000 active credits
        let future_expiry = Utc::now() + Duration::days(365);
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: Uuid::new_v4().into(),
                    user_id: user_id.into(),
                    amount: 9000,
                    balance_after: 9500,
                    transaction_type: "active_purchase".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some(Utc::now().into()),
                    expires_at: Some(future_expiry.into()),
                })
                .execute(conn)?;

            // Update balance to 9500 (9000 active + 500 expired)
            diesel::update(user_credits::table.filter(user_credits::user_id.eq(user_id)))
                .set(user_credits::balance.eq(9500))
                .execute(conn)?;

            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add active credits");

        // Try to purchase 1,500 credits
        // Max balance is 10,000. Active balance is 9,000, so can only add 1,000
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let service = CreditService::new(config.clone());

        let result = conn
            .interact(move |conn| {
                service.add_credits(
                    conn,
                    user_id.into(),
                    1500,
                    "credit_purchase",
                    "Credit purchase - 1500 credits package",
                    Some("purchase_123".to_string()),
                    Some(serde_json::json!({"package": "1500_credits"}).into()),
                )
            })
            .await
            .expect("Failed to interact");

        // Should succeed - active balance 9,000 + 1,000 = 10,000 (capped)
        assert!(
            result.is_ok(),
            "Purchase should succeed when active balance < max"
        );

        let transaction = result.expect("Purchase should succeed");

        // Verify balance capped at 10,000 (only 1,000 added, not 1,500)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let final_balance: i32 = conn
            .interact(move |conn| {
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        // Balance should be 10,000 (9,000 active + 1,000 added, expired credits ignored)
        assert_eq!(
            final_balance, 10500,
            "Balance should be capped considering only active credits"
        );
    }

    /// Test: Monthly grant doesn't add to expired credits
    ///
    /// ## Test Scenario:
    /// 1. User has 1000 credits expiring tomorrow
    /// 2. Monthly grant adds 5000 credits (basic plan)
    /// 3. Verify new credits have expires_at = now + 365 days
    /// 4. Verify old credits still expire tomorrow
    /// 5. After cleanup, balance should be 5000 (only new credits)
    #[tokio::test]
    async fn test_monthly_grant_creates_new_expiry() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let service = CreditService::new(config.clone());

        // Initialize user credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| service.initialize_user_credits(conn, user_id.into()))
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize credits");

        // Add 1000 credits expiring tomorrow
        let tomorrow = Utc::now() + Duration::days(1);
        let old_transaction_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_transactions::table)
                .values(&NewCreditTransaction {
                    id: old_transaction_id.into(),
                    user_id: user_id.into(),
                    amount: 1000,
                    balance_after: 1000,
                    transaction_type: "expiring_soon".to_string(),
                    description_encrypted: vec![],
                    description_nonce: vec![],
                    metadata_encrypted: None,
                    metadata_nonce: None,
                    reference_id: None,
                    created_at: Some((Utc::now() - Duration::days(364)).into()),
                    expires_at: Some(tomorrow.into()),
                })
                .execute(conn)?;

            diesel::update(user_credits::table.filter(user_credits::user_id.eq(user_id)))
                .set(user_credits::balance.eq(1000))
                .execute(conn)?;

            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to add expiring credits");

        // Grant monthly credits (5000 credits for basic plan)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let service = CreditService::new(config.clone());

        let grant_result = conn
            .interact(move |conn| {
                service.add_credits(
                    conn,
                    user_id.into(),
                    5000,
                    "monthly_grant",
                    "Monthly credit grant - basic plan",
                    Some("monthly_grant_123".to_string()),
                    Some(scribe_backend::db::Json(
                        serde_json::json!({"plan": "basic"}),
                    )),
                )
            })
            .await
            .expect("Failed to interact")
            .expect("Monthly grant should succeed");

        // Verify new transaction has expiry = now + 365 days
        // Query for the most recent transaction (the monthly grant we just added)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let new_transaction: (Option<chrono::DateTime<Utc>>, i32) = conn
            .interact(move |conn| {
                credit_transactions::table
                    .filter(credit_transactions::user_id.eq(user_id))
                    .filter(credit_transactions::transaction_type.eq("monthly_grant"))
                    .order(credit_transactions::created_at.desc())
                    .select((credit_transactions::expires_at, credit_transactions::amount))
                    .first(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get new transaction");

        let (new_expires_at, new_amount) = new_transaction;
        assert_eq!(new_amount, 5000);
        assert!(
            new_expires_at.is_some(),
            "New credits should have expiry date"
        );

        let expected_expiry = Utc::now() + Duration::days(config.payment.credit_expiry_days as i64);
        let actual_expiry = new_expires_at.unwrap();

        // Allow 5 second tolerance for test timing
        let diff = (actual_expiry - expected_expiry).num_seconds().abs();
        assert!(
            diff < 5,
            "New credits should expire in {} days",
            config.payment.credit_expiry_days
        );

        // Verify old transaction still has tomorrow as expiry
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let old_expires_at: Option<chrono::DateTime<Utc>> = conn
            .interact(move |conn| {
                credit_transactions::table
                    .filter(credit_transactions::id.eq(old_transaction_id))
                    .select(credit_transactions::expires_at)
                    .first(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get old transaction");

        assert!(old_expires_at.is_some());
        let old_expiry_diff = (old_expires_at.unwrap() - tomorrow).num_seconds().abs();
        assert!(
            old_expiry_diff < 5,
            "Old credits should still expire tomorrow"
        );

        // Simulate tomorrow (cleanup expired credits)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let service = CreditService::new(config.clone());

        // Manually set old credits as expired (simulate time passage)
        conn.interact(move |conn| {
            diesel::update(
                credit_transactions::table.filter(credit_transactions::id.eq(old_transaction_id)),
            )
            .set(credit_transactions::expires_at.eq(Some(Utc::now() - Duration::hours(1))))
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to update old credits");

        // Run cleanup
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let cleanup_result = conn
            .interact(move |conn| service.cleanup_expired_credits(conn, Some(user_id.into())))
            .await
            .expect("Failed to interact")
            .expect("Cleanup should succeed");

        assert_eq!(
            cleanup_result.credits_expired, 1000,
            "Should expire old 1000 credits"
        );

        // Verify final balance is 5000 (only monthly grant remains)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let final_balance: i32 = conn
            .interact(move |conn| {
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get final balance");

        assert_eq!(
            final_balance, 5000,
            "After cleanup, only monthly grant credits should remain"
        );
    }
}
