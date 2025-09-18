//! Integration tests for credit system with other services
//!
//! Tests interactions between credit system, subscriptions,
//! chat generation, and Paddle webhooks.

#[cfg(all(test, feature = "payment"))]
mod credit_integration_tests {
    use scribe_backend::{
        models::{
            credit::{CreditBalance, CreditPackage, NewCreditPackage},
            payment::{NewSubscription, Subscription},
        },
        services::payment::{CreditService, SoftLimitService, SubscriptionService},
        services::EncryptionService,
        test_helpers::{spawn_app, TestDataGuard},
        schema::{credit_packages, subscriptions, user_credits},
        config::Config,
    };
    use uuid::Uuid;
    use chrono::{Utc, Duration};
    use diesel::prelude::*;
    use serde_json::json;
    use std::sync::Arc;
    use deadpool_diesel::Pool;
    use deadpool_diesel::Manager as DeadpoolManager;

    /// Helper function to create a test user
    async fn create_test_user(pool: &Pool<DeadpoolManager<diesel::PgConnection>>, user_id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        conn.interact(move |conn| {
            // Check if user already exists
            use scribe_backend::schema::users;
            let existing: Result<i64, _> = users::table
                .filter(users::id.eq(user_id))
                .count()
                .get_result(conn);

            if let Ok(count) = existing {
                if count > 0 {
                    return Ok(()) as Result<(), diesel::result::Error>;
                }
            }

            // Insert new user with SQL query to handle enum types
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(format!("test_user_{}", user_id))
            .bind::<diesel::sql_types::Text, _>(format!("test_{}@example.com", user_id))
            .bind::<diesel::sql_types::Text, _>("test_hash")
            .bind::<diesel::sql_types::Text, _>("test_salt")
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 32])
            .bind::<diesel::sql_types::Bytea, _>(vec![0u8; 12])
            .bind::<diesel::sql_types::Text, _>("User") // user_role enum
            .bind::<diesel::sql_types::Text, _>("active") // account_status enum
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        }).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_subscription_credit_grant() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id).await.expect("Failed to create user");

        // Enable credits
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        let config = Arc::new(config);

        // Create subscription for user
        let encryption_service = EncryptionService::new();
        let config_for_sub = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let sub = conn.interact(move |conn| {
            let subscription_service = SubscriptionService::new(config_for_sub.as_ref().clone(), encryption_service);

            // Create subscription
            let new_sub = NewSubscription {
                id: Uuid::new_v4(),
                user_id,
                plan_type: "basic".to_string(),
                paddle_subscription_id: Some("test_sub_123".to_string()),
                paddle_customer_id: Some("test_customer_123".to_string()),
                status: "active".to_string(),
                current_period_start: Utc::now(),
                current_period_end: Utc::now() + Duration::days(30),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(false),
                last_credit_grant: None,
                soft_limit_override: None,
            };

            use scribe_backend::schema::subscriptions::dsl;
            diesel::insert_into(dsl::subscriptions)
                .values(&new_sub)
                .get_result::<Subscription>(conn)
        }).await.expect("Failed to interact").expect("Failed to create subscription");

        // Initialize and grant credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.initialize_user_credits(conn, user_id)?;
            credit_service.grant_monthly_credits(conn, user_id, "basic")
        }).await.expect("Failed to interact").expect("Failed to grant credits");

        // Check balance
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.get_balance(conn, user_id)
        }).await.expect("Failed to interact").expect("Failed to get balance");

        // Basic tier should get credits
        assert!(balance.balance > 0);
        assert!(balance.last_monthly_grant.is_some());

        // Update subscription to track grant
        let sub_id = sub.id;
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use scribe_backend::schema::subscriptions::dsl;
            diesel::update(dsl::subscriptions.find(sub_id))
                .set((
                    dsl::credits_allocated_this_period.eq(true),
                    dsl::last_credit_grant.eq(Some(Utc::now())),
                ))
                .execute(conn)
        }).await.expect("Failed to interact").expect("Failed to update subscription");
    }

    #[tokio::test]
    async fn test_credit_usage_with_soft_limits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id).await.expect("Failed to create user");

        // Enable both credits and soft limits
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Setup user with credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone.clone());
            credit_service.initialize_user_credits(conn, user_id)?;
            credit_service.add_credits(conn, user_id, 1000, "test", "Setup", None, None)
        }).await.expect("Failed to interact").expect("Failed to setup credits");

        // Simulate chat usage
        for i in 0..30 {
            let config_clone = config.clone();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let usage = conn.interact(move |conn| {
                let soft_limit_service = SoftLimitService::new(config_clone);
                soft_limit_service.record_usage(conn, user_id, "gemini-2.5-flash", 1000)
            }).await.expect("Failed to interact").expect("Failed to record usage");

            // After some messages, should trigger soft limit
            if i >= 10 {
                assert!(usage.soft_limit_triggered_at.is_some());

                // Should be throttled
                let config_clone = config.clone();
                let conn = app.db_pool.get().await.expect("Failed to get connection");
                let throttle = conn.interact(move |conn| {
                    let soft_limit_service = SoftLimitService::new(config_clone);
                    soft_limit_service.should_throttle(conn, user_id)
                }).await.expect("Failed to interact").expect("Failed to check throttle");
                assert!(throttle.is_some());
            }

            // Deduct credits for premium model usage
            if i % 5 == 0 {
                // Every 5th message uses Pro model
                let config_clone = config.clone();
                let conn = app.db_pool.get().await.expect("Failed to get connection");
                conn.interact(move |conn| {
                    let credit_service = CreditService::new(config_clone);
                    credit_service.deduct_credits(
                        conn,
                        user_id,
                        50,
                        "Gemini Pro usage",
                        Some(json!({"model": "gemini-2.5-pro", "message": i})),
                    )
                }).await.expect("Failed to interact").expect("Failed to deduct credits");
            }
        }

        // Check final states
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.get_balance(conn, user_id)
        }).await.expect("Failed to interact").expect("Failed to get balance");
        assert_eq!(balance.balance, 700); // 1000 - (6 * 50)

        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let remaining = conn.interact(move |conn| {
            let soft_limit_service = SoftLimitService::new(config_clone);
            soft_limit_service.get_remaining_messages(conn, user_id)
        }).await.expect("Failed to interact").expect("Failed to get remaining");
        assert_eq!(remaining, Some(0)); // Over limit
    }

    #[tokio::test]
    async fn test_credit_package_purchase() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id).await.expect("Failed to create user");

        // Enable credits
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        let config = Arc::new(config);

        // Create credit package
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let package = conn.interact(move |conn| {
            let new_package = NewCreditPackage {
                package_id: "starter_pack".to_string(),
                name: "Starter Pack".to_string(),
                credits: 500,
                price_cents: 499, // $4.99
                bonus_percentage: None,
                paddle_price_id: Some("price_test_123".to_string()),
                active: Some(true),
                display_order: None,
            };

            use scribe_backend::schema::credit_packages::dsl;
            diesel::insert_into(dsl::credit_packages)
                .values(&new_package)
                .get_result::<CreditPackage>(conn)
        }).await.expect("Failed to interact").expect("Failed to create package");

        // Initialize user credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.initialize_user_credits(conn, user_id)
        }).await.expect("Failed to interact").expect("Failed to initialize");

        // Process purchase
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.process_credit_purchase(
                conn,
                user_id,
                &package.package_id,
                "trans_test_123",
            )
        }).await.expect("Failed to interact").expect("Failed to process purchase");

        assert_eq!(balance.balance, 500);
        // Note: lifetime_purchased field doesn't exist in CreditBalance
        assert_eq!(balance.lifetime_earned, 500); // Purchased credits count as earned
        assert_eq!(balance.lifetime_spent, 0); // No credits spent yet
    }

    #[tokio::test]
    async fn test_monthly_grant_with_existing_balance() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id).await.expect("Failed to create user");

        // Enable credits
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        let config = Arc::new(config);

        // Initialize and add some purchased credits
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone.clone());
            credit_service.initialize_user_credits(conn, user_id)?;
            // Create a package and process purchase
            let package_id = "initial_pack";
            diesel::sql_query(
                "INSERT INTO credit_packages (id, package_id, name, credits, price_cents, active)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (package_id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(Uuid::new_v4())
            .bind::<diesel::sql_types::Text, _>(package_id)
            .bind::<diesel::sql_types::Text, _>("Initial Pack")
            .bind::<diesel::sql_types::Int4, _>(1000)
            .bind::<diesel::sql_types::Int4, _>(999)
            .bind::<diesel::sql_types::Bool, _>(true)
            .execute(conn)?;

            credit_service.process_credit_purchase(
                conn,
                user_id,
                package_id,
                "trans_initial",
            )
        }).await.expect("Failed to interact").expect("Failed to add initial credits");

        // Grant monthly credits for premium tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.grant_monthly_credits(conn, user_id, "premium")
        }).await.expect("Failed to interact").expect("Failed to grant monthly credits");

        // Should have both purchased and granted credits
        assert!(balance.balance > 1000);
        // Note: lifetime_purchased field doesn't exist in CreditBalance
        assert!(balance.lifetime_earned > 1000); // Includes monthly grant
        assert!(balance.last_monthly_grant.is_some());

        // Try to grant again in same month - should not double grant
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance2 = conn.interact(move |conn| {
            let credit_service = CreditService::new(config_clone);
            credit_service.grant_monthly_credits(conn, user_id, "premium")
        }).await.expect("Failed to interact").expect("Failed second grant attempt");

        // Balance should not have increased
        assert_eq!(balance2.balance, balance.balance);
        assert_eq!(balance2.lifetime_earned, balance.lifetime_earned);
    }
}