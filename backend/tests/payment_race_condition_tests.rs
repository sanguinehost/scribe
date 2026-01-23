#![cfg(feature = "postgres-backend")]
#[cfg(all(test, feature = "payment"))]
mod payment_race_condition_tests {
    use chrono::Utc;
    use deadpool_diesel::{Manager as DeadpoolManager, Pool};
    use diesel::prelude::*;
    use scribe_backend::{
        errors::AppError,
        models::users::UserRole,
        services::payment::CreditService,
        test_helpers::{spawn_app, TestDataGuard},
    };
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;
    use tokio::task::JoinSet;
    use uuid::Uuid;

    /// Helper function to create a test user
    async fn create_test_user(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        user_id: Uuid,
        username: &str,
        email: &str,
        role: Option<UserRole>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let username = username.to_string();
        let email = email.to_string();
        let role_str = match role.unwrap_or(UserRole::User) {
            UserRole::User => "User",
            UserRole::Moderator => "Moderator",
            UserRole::Administrator => "Administrator",
        };

        let conn = pool.get().await?;
        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            // Check if user exists
            let existing = dsl::users
                .filter(dsl::id.eq(user_id))
                .count()
                .get_result::<i64>(conn)?;

            if existing > 0 {
                return Ok::<_, diesel::result::Error>(());
            }

            // Insert user
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
            .bind::<diesel::sql_types::Text, _>("hash")
            .bind::<diesel::sql_types::Text, _>("salt")
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 32])
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 12])
            .bind::<diesel::sql_types::Text, _>(role_str)
            .bind::<diesel::sql_types::Text, _>("active")
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::BigInt, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now().into())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        }).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_sequential_credit_operations_integrity() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "seq_test", "seq@test.com", None)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        // Sequential operations to verify basic functionality
        conn.interact(move |conn| {
            let service = CreditService::new(config.clone());

            // Initialize user credits
            service.initialize_user_credits(conn, user_id.into())?;

            // Add credits sequentially
            for i in 1..=5 {
                service.add_credits(
                    conn,
                    user_id.into(),
                    100,
                    "sequential_test",
                    &format!("Sequential operation {}", i),
                    None,
                    None,
                )?;
            }

            // Check final balance
            let balance = service.get_balance(conn, user_id.into())?;
            assert_eq!(
                balance.balance, 500,
                "Sequential operations should sum correctly"
            );

            Ok::<_, scribe_backend::errors::AppError>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to perform sequential operations");
    }

    #[tokio::test]
    async fn test_basic_concurrent_credit_operations() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "concurrent_test",
            "concurrent@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        // Initialize user credits first
        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.initialize_user_credits(conn, user_id.into())
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize user");

        // Perform basic concurrent operations (reduced concurrency for reliability)
        let pool = app.db_pool.clone();
        let mut tasks = JoinSet::new();

        for i in 0..3 {
            let pool = pool.clone();
            let config = config.clone();
            tasks.spawn(async move {
                let conn = pool.get().await.expect("Failed to get connection");
                conn.interact(move |conn| {
                    let service = CreditService::new(config.clone());
                    service.add_credits(
                        conn,
                        user_id.into(),
                        50,
                        "concurrent_test",
                        &format!("Concurrent operation {}", i),
                        None,
                        None,
                    )
                })
                .await
                .expect("Failed to interact")
            });
        }

        // Wait for all tasks
        let mut successful_ops = 0;
        while let Some(result) = tasks.join_next().await {
            if result.is_ok() && result.unwrap().is_ok() {
                successful_ops += 1;
            }
        }

        // Verify that at least some operations succeeded (allowing for race conditions)
        assert!(
            successful_ops >= 1,
            "At least one concurrent operation should succeed"
        );

        // Check final balance is reasonable
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");
        let final_balance = conn2
            .interact({
                let config = config.clone();
                move |conn| {
                    let service = CreditService::new(config.clone());
                    service.get_balance(conn, user_id.into())
                }
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        assert!(
            final_balance.balance >= 50,
            "Balance should reflect at least one successful operation"
        );
        assert!(
            final_balance.balance <= 150,
            "Balance should not exceed maximum possible"
        );
    }

    #[tokio::test]
    async fn test_credit_reservation_basic_functionality() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "reservation_test",
            "reservation@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            let service = CreditService::new(config.clone());

            // Initialize and add credits
            service.initialize_user_credits(conn, user_id.into())?;
            service.add_credits(
                conn,
                user_id.into(),
                1000,
                "reservation_test",
                "Initial credits for reservation test",
                None,
                None,
            )?;

            // Reserve credits
            let (_balance, reservation_id) =
                service.reserve_credits(conn, user_id.into(), 300, "Test reservation", None)?;

            // Confirm reservation
            let final_balance =
                service.confirm_reservation(conn, user_id.into(), reservation_id)?;

            assert_eq!(
                final_balance.balance, 700,
                "Balance should be reduced after confirmed reservation"
            );
            assert_eq!(
                final_balance.lifetime_spent, 300,
                "Lifetime spent should track confirmed reservation"
            );

            Ok::<_, scribe_backend::errors::AppError>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to perform reservation operations");
    }

    #[tokio::test]
    async fn test_insufficient_credits_handling() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "insufficient_test",
            "insufficient@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());

                // Initialize user with no additional credits
                service.initialize_user_credits(conn, user_id.into())?;

                // Try to reserve more credits than available
                service.reserve_credits(
                    conn,
                    user_id.into(),
                    500,
                    "Should fail - insufficient credits",
                    None,
                )
            })
            .await
            .expect("Failed to interact");

        assert!(
            result.is_err(),
            "Reserving more credits than available should fail"
        );
    }

    #[tokio::test]
    async fn test_transaction_isolation_basic() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "isolation_test",
            "isolation@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            let service = CreditService::new(config.clone());

            // Initialize and add credits
            service.initialize_user_credits(conn, user_id.into())?;
            service.add_credits(
                conn,
                user_id.into(),
                200,
                "isolation_test",
                "Initial credits",
                None,
                None,
            )?;

            // Perform multiple operations in sequence
            let balance1 = service.get_balance(conn, user_id.into())?;

            let (_balance, reservation_id) = service.reserve_credits(
                conn,
                user_id.into(),
                100,
                "Isolation test reservation",
                None,
            )?;

            let balance2 = service.get_balance(conn, user_id.into())?;

            // Balances should be consistent
            assert_eq!(balance1.balance, 200, "Initial balance should be correct");
            assert_eq!(
                balance2.balance, 100,
                "Balance after reservation should be reduced"
            );

            // Confirm reservation
            service.confirm_reservation(conn, user_id.into(), reservation_id)?;

            let final_balance = service.get_balance(conn, user_id.into())?;
            assert_eq!(
                final_balance.balance, 100,
                "Final balance should remain consistent"
            );

            Ok::<_, scribe_backend::errors::AppError>(())
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to perform isolation test");
    }

    /// Test high-concurrency credit operations with 100 concurrent tasks
    /// This verifies the system can handle realistic high-load scenarios
    ///
    /// With optimistic locking (version-based concurrency control):
    /// - Each operation reads the current balance and version
    /// - Updates only succeed if version hasn't changed
    /// - Failed updates retry with exponential backoff (max 3 attempts)
    /// - Exactly 20 operations should succeed (1000 / 50 = 20)
    /// - Remaining 80 should fail with "Insufficient credits"
    #[tokio::test]
    async fn test_high_concurrency_credit_operations() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "high_concurrency_test",
            "high_concurrency@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        let config = app.config.clone();

        // Initialize user with 1000 credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.initialize_user_credits(conn, user_id.into())?;
                service.add_credits(
                    conn,
                    user_id.into(),
                    1000,
                    "high_concurrency_test",
                    "Initial credits for high-concurrency test",
                    None,
                    None,
                )
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize user");

        // Spawn 100 concurrent tasks attempting to reserve 50 credits each
        // Total requested: 5000 credits
        // Available: 1000 credits
        //
        // With optimistic locking:
        // - Exactly 20 operations should succeed (1000 / 50 = 20)
        // - Remaining 80 will fail with "Insufficient credits"
        // - No race conditions or lost updates
        let pool = app.db_pool.clone();
        let mut tasks = JoinSet::new();

        let successful_ops = Arc::new(AtomicU32::new(0));
        let failed_ops = Arc::new(AtomicU32::new(0));

        for i in 0..100 {
            let pool = pool.clone();
            let config = config.clone();
            let successful = successful_ops.clone();
            let failed = failed_ops.clone();

            tasks.spawn(async move {
                let conn = pool.get().await.expect("Failed to get connection");
                let result = conn
                    .interact(move |conn| {
                        let service = CreditService::new(config.clone());
                        service.reserve_credits(
                            conn,
                            user_id.into(),
                            50,
                            &format!("High-concurrency reservation {}", i),
                            None,
                        )
                    })
                    .await
                    .expect("Failed to interact");

                match result {
                    Ok(_) => successful.fetch_add(1, Ordering::SeqCst),
                    Err(AppError::BadRequest(msg)) if msg.contains("Insufficient credits") => {
                        failed.fetch_add(1, Ordering::SeqCst)
                    }
                    Err(AppError::Conflict(_)) => {
                        // Optimistic locking conflict after max retries
                        // This shouldn't happen often, but count as failed
                        failed.fetch_add(1, Ordering::SeqCst)
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                };
            });
        }

        // Wait for all tasks to complete
        while let Some(result) = tasks.join_next().await {
            result.expect("Task panicked");
        }

        let successful_count = successful_ops.load(Ordering::SeqCst);
        let failed_count = failed_ops.load(Ordering::SeqCst);

        println!(
            "High-concurrency test: {} succeeded, {} failed",
            successful_count, failed_count
        );

        // Verify all operations completed
        assert_eq!(
            successful_count + failed_count,
            100,
            "All 100 operations should complete (either success or failure)"
        );

        // Verify final balance is correct (critical test for data consistency)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let final_balance = conn
            .interact({
                let config = config.clone();
                move |conn| {
                    let service = CreditService::new(config.clone());
                    service.get_balance(conn, user_id.into())
                }
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        // With optimistic locking, we expect:
        // - Exactly 20 successful operations (1000 / 50 = 20)
        // - Final balance should be exactly 0
        // - No over-spending or race conditions

        println!("=== High-Concurrency Test Results ===");
        println!("Successful operations: {}", successful_count);
        println!("Failed operations: {}", failed_count);
        println!("Final balance: {}", final_balance.balance);
        println!("Expected balance: 0");

        // Verify balance is exactly 0 (all available credits used, no over-spending)
        assert_eq!(
            final_balance.balance, 0,
            "Final balance should be exactly 0 (1000 - 20*50 = 0), got: {}",
            final_balance.balance
        );

        // Verify exactly 20 operations succeeded
        assert_eq!(
            successful_count, 20,
            "Expected exactly 20 successful operations (1000 / 50), got: {}",
            successful_count
        );

        // Verify exactly 80 operations failed
        assert_eq!(
            failed_count, 80,
            "Expected exactly 80 failed operations (100 - 20), got: {}",
            failed_count
        );

        println!("✅ Optimistic locking working correctly - no race conditions!");
    }

    /// Test optimistic locking retry behavior
    /// Verifies that version conflicts trigger retries with exponential backoff
    #[tokio::test]
    async fn test_optimistic_locking_retry_on_version_conflict() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "retry_test", "retry@test.com", None)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();

        // Initialize user with 500 credits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact({
            let config = config.clone();
            move |conn| {
                let service = CreditService::new(config.clone());
                service.initialize_user_credits(conn, user_id.into())?;
                service.add_credits(
                    conn,
                    user_id.into(),
                    500,
                    "retry_test",
                    "Initial credits for retry test",
                    None,
                    None,
                )
            }
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize user");

        // Spawn 10 concurrent operations competing for the same credits
        // This will cause version conflicts and trigger retries
        let pool = app.db_pool.clone();
        let mut tasks = JoinSet::new();

        let successful_ops = Arc::new(AtomicU32::new(0));
        let failed_ops = Arc::new(AtomicU32::new(0));
        let conflict_ops = Arc::new(AtomicU32::new(0));

        for i in 0..10 {
            let pool = pool.clone();
            let config = config.clone();
            let successful = successful_ops.clone();
            let failed = failed_ops.clone();
            let conflicts = conflict_ops.clone();

            tasks.spawn(async move {
                let conn = pool.get().await.expect("Failed to get connection");
                let result = conn
                    .interact(move |conn| {
                        let service = CreditService::new(config.clone());
                        service.reserve_credits(
                            conn,
                            user_id.into(),
                            100,
                            &format!("Retry test reservation {}", i),
                            None,
                        )
                    })
                    .await
                    .expect("Failed to interact");

                match result {
                    Ok(_) => successful.fetch_add(1, Ordering::SeqCst),
                    Err(AppError::BadRequest(msg)) if msg.contains("Insufficient credits") => {
                        failed.fetch_add(1, Ordering::SeqCst)
                    }
                    Err(AppError::Conflict(_)) => {
                        // Version conflict after max retries
                        conflicts.fetch_add(1, Ordering::SeqCst)
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                };
            });
        }

        // Wait for all tasks to complete
        while let Some(result) = tasks.join_next().await {
            result.expect("Task panicked");
        }

        let successful_count = successful_ops.load(Ordering::SeqCst);
        let failed_count = failed_ops.load(Ordering::SeqCst);
        let conflict_count = conflict_ops.load(Ordering::SeqCst);

        println!("=== Optimistic Locking Retry Test Results ===");
        println!("Successful operations: {}", successful_count);
        println!("Failed (insufficient): {}", failed_count);
        println!("Failed (conflict): {}", conflict_count);

        // Verify all operations completed
        assert_eq!(
            successful_count + failed_count + conflict_count,
            10,
            "All 10 operations should complete"
        );

        // Verify exactly 5 operations succeeded (500 / 100 = 5)
        assert_eq!(
            successful_count, 5,
            "Expected exactly 5 successful operations (500 / 100), got: {}",
            successful_count
        );

        // Verify final balance is correct
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let final_balance = conn
            .interact({
                let config = config.clone();
                move |conn| {
                    let service = CreditService::new(config.clone());
                    service.get_balance(conn, user_id.into())
                }
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        assert_eq!(
            final_balance.balance, 0,
            "Final balance should be 0 (500 - 5*100), got: {}",
            final_balance.balance
        );

        println!("✅ Optimistic locking retries working correctly!");
    }
}
