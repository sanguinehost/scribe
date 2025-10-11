//! Unit and integration tests for the CreditService
//!
//! Tests credit balance management, transaction recording,
//! monthly grants, and purchase processing.

#[cfg(all(test, feature = "payment"))]
mod credit_service_tests {
    use chrono::{Duration, Utc};
    use deadpool_diesel::{Manager as DeadpoolManager, Pool};
    use diesel::prelude::*;
    use scribe_backend::{
        config::Config,
        errors::AppError,
        models::credit::{CreditBalance, CreditPackage, CreditTransaction, NewCreditPackage},
        models::users::{AccountStatus, NewUser, UserRole},
        schema::users,
        services::payment::CreditService,
        test_helpers::{TestDataGuard, spawn_app},
    };
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper function to create a test user
    async fn create_test_user(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        user_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            // First check if user exists
            let existing = dsl::users
                .filter(dsl::id.eq(user_id))
                .count()
                .get_result::<i64>(conn)?;

            if existing > 0 {
                return Ok::<_, diesel::result::Error>(());
            }

            // Insert directly with ID, using proper casts for enums
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
        }).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_credit_service_initialization() {
        let config = Config::load().expect("Failed to load config");
        let service = CreditService::new(Arc::new(config));

        // Service should initialize without errors
        assert!(!service.is_enabled()); // Should be disabled by default in tests
    }

    #[tokio::test]
    async fn test_credit_balance_lifecycle() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create a test user first
        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        let config = app.config.clone();

        // Initialize credits for new user
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());
                service.initialize_user_credits(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize credits");

        assert_eq!(balance.balance, 0);
        assert_eq!(balance.lifetime_earned, 0);
        assert_eq!(balance.lifetime_spent, 0);
        assert!(balance.last_monthly_grant.is_none());

        // Get balance should return the same for existing user
        let config2 = app.config.clone();
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");
        let retrieved_balance = conn2
            .interact(move |conn| {
                let service = CreditService::new(config2);
                service.get_balance(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get balance");

        assert_eq!(retrieved_balance.user_id, balance.user_id);
        assert_eq!(retrieved_balance.balance, 0);
    }

    #[tokio::test]
    async fn test_add_credits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits for this test
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Add credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.add_credits(
                    conn,
                    user_id,
                    100,
                    "purchase",
                    "Test credit purchase",
                    Some("paddle_123".to_string()),
                    Some(json!({"test": "data"})),
                )
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to add credits");

        assert_eq!(balance.balance, 100);
        assert_eq!(balance.lifetime_earned, 100);
        assert_eq!(balance.lifetime_spent, 0);

        // Add more credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.add_credits(conn, user_id, 50, "bonus", "Bonus credits", None, None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to add bonus credits");

        assert_eq!(balance.balance, 150);
        assert_eq!(balance.lifetime_earned, 150);
    }

    #[tokio::test]
    async fn test_deduct_credits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Setup user with credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(conn, user_id, 100, "test", "Setup", None, None)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to setup");

        // Deduct credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.deduct_credits(
                    conn,
                    user_id,
                    30,
                    "Usage for Gemini Pro",
                    Some(json!({"model": "gemini-2.5-pro", "messages": 1})),
                )
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to deduct credits");

        assert_eq!(balance.balance, 70);
        assert_eq!(balance.lifetime_spent, 30);
        assert_eq!(balance.lifetime_earned, 100);

        // Try to deduct more than available
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.deduct_credits(conn, user_id, 100, "Too much", None)
            })
            .await
            .expect("Failed to interact");

        assert!(result.is_err());
        if let Err(AppError::InsufficientCredits {
            required,
            available,
            expired: _,
        }) = result
        {
            assert_eq!(required, 100);
            assert_eq!(available, 70);
        } else {
            panic!("Expected InsufficientCredits error, got: {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_monthly_grant() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Grant monthly credits for basic tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.grant_monthly_credits(conn, user_id, "basic")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to grant monthly credits");

        // Basic tier should get 250 credits per month (from config)
        assert_eq!(balance.balance, 250);
        assert_eq!(balance.lifetime_earned, 250);
        assert!(balance.last_monthly_grant.is_some());

        // Try to grant again in same month - should not double grant
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance2 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.grant_monthly_credits(conn, user_id, "basic")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed second grant attempt");

        assert_eq!(balance2.balance, 250); // Should still be 250, not 500
        assert_eq!(balance2.lifetime_earned, 250);
    }

    #[tokio::test]
    async fn test_monthly_grant_premium_tier() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Grant monthly credits for premium tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.grant_monthly_credits(conn, user_id, "premium")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to grant monthly credits");

        // Premium tier should get 800 credits per month (from config)
        assert_eq!(balance.balance, 800);
        assert_eq!(balance.lifetime_earned, 800);
        assert!(balance.last_monthly_grant.is_some());

        // Try to grant again in same month - should not double grant
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance2 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.grant_monthly_credits(conn, user_id, "premium")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed second grant attempt");

        assert_eq!(balance2.balance, 800); // Should still be 800, not 1600
        assert_eq!(balance2.lifetime_earned, 800);
    }

    #[tokio::test]
    async fn test_monthly_grant_free_tier_gets_zero() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Grant monthly credits for free tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.grant_monthly_credits(conn, user_id, "free")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to grant monthly credits");

        // Free tier should get 0 monthly credits (no subscription)
        assert_eq!(balance.balance, 0);
        assert_eq!(balance.lifetime_earned, 0);
        // last_monthly_grant should NOT be updated for free tier since no credits granted
        assert!(balance.last_monthly_grant.is_none());
    }

    #[tokio::test]
    async fn test_transaction_history() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Create some transactions
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(conn, user_id, 100, "purchase", "Purchase 1", None, None)?;
            service.add_credits(conn, user_id, 50, "bonus", "Bonus", None, None)?;
            service.deduct_credits(conn, user_id, 30, "Usage 1", None)?;
            service.deduct_credits(conn, user_id, 20, "Usage 2", None)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to create transactions");

        // Get transaction history
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let transactions = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.get_transaction_history(conn, user_id, Some(10), None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get transaction history");

        assert_eq!(transactions.len(), 4);

        // Verify transactions are in reverse chronological order
        let amounts: Vec<i32> = transactions.iter().map(|t| t.amount).collect();
        assert_eq!(amounts, vec![-20, -30, 50, 100]); // Most recent first

        // Test pagination
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let page1 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.get_transaction_history(conn, user_id, Some(2), None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get page 1");
        assert_eq!(page1.len(), 2);

        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let page2 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.get_transaction_history(conn, user_id, Some(2), Some(2))
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get page 2");
        assert_eq!(page2.len(), 2);
        assert_ne!(page1[0].id, page2[0].id);
    }

    #[tokio::test]
    async fn test_max_balance_limit() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits with a low max balance for testing
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.max_credit_balance = 1000;
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Try to add credits that would exceed max
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.add_credits(
                    conn,
                    user_id,
                    1001,
                    "purchase",
                    "Too many credits",
                    None,
                    None,
                )
            })
            .await
            .expect("Failed to interact");

        assert!(result.is_err());
        if let Err(AppError::BadRequest(msg)) = result {
            assert!(msg.contains("exceed maximum limit"));
        } else {
            panic!("Expected max balance error");
        }

        // Adding exactly max should work
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.add_credits(conn, user_id, 1000, "purchase", "Max credits", None, None)
            })
            .await
            .expect("Failed to interact")
            .expect("Should allow exactly max credits");

        assert_eq!(balance.balance, 1000);
    }

    #[tokio::test]
    async fn test_credit_purchase_processing() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Initialize user
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone);
            service.initialize_user_credits(conn, user_id)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to initialize");

        // Insert a test credit package into the database
        use scribe_backend::schema::credit_packages;

        let test_package = NewCreditPackage {
            package_id: "test_package".to_string(),
            name: "Test Package".to_string(),
            credits: 500,
            price_cents: 1000,
            bonus_percentage: Some(20), // 20% bonus
            paddle_price_id: Some("pri_test".to_string()),
            active: Some(true),
            display_order: Some(1),
        };

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(credit_packages::table)
                .values(&test_package)
                .execute(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to insert test package");

        // Process credit purchase
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.process_credit_purchase(conn, user_id, "test_package", "paddle_txn_123")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to process credit purchase");

        // Should have base credits + bonus (500 + 100 = 600)
        assert_eq!(balance.balance, 600);
        assert_eq!(balance.lifetime_earned, 600);

        // Verify transaction was recorded
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let transactions = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.get_transaction_history(conn, user_id, None, None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get transactions");

        assert_eq!(transactions.len(), 1);
        assert_eq!(
            transactions[0].reference_id,
            Some("paddle_txn_123".to_string())
        );
    }

    #[tokio::test]
    async fn test_has_sufficient_credits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable credits and set config path
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.subscription_config_path = "config/subscription_tiers.json".to_string();
        let config = Arc::new(config);

        // Initialize with 100 credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let service = CreditService::new(config_clone.clone());
            service.initialize_user_credits(conn, user_id)?;
            service.add_credits(conn, user_id, 100, "test", "Setup", None, None)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to setup");

        // Check sufficient credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let has_50 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.has_sufficient_credits(conn, user_id, 50)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to check");
        assert!(has_50);

        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let has_100 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.has_sufficient_credits(conn, user_id, 100)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to check");
        assert!(has_100);

        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let has_101 = conn
            .interact(move |conn| {
                let service = CreditService::new(config_clone);
                service.has_sufficient_credits(conn, user_id, 101)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to check");
        assert!(!has_101);
    }

    #[tokio::test]
    async fn test_credits_disabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Override config to explicitly disable credits for this test
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = false;
        let config_arc = Arc::new(config);
        let service = CreditService::new(config_arc.clone());
        assert!(!service.is_enabled());

        // Operations should fail when disabled
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config_arc);
                service.add_credits(conn, user_id, 100, "test", "Should fail", None, None)
            })
            .await
            .expect("Failed to interact");

        assert!(result.is_err());
        if let Err(AppError::BadRequest(msg)) = result {
            assert!(msg.contains("not enabled"));
        } else {
            panic!("Expected credits disabled error");
        }
    }
}
