#![cfg(feature = "postgres-backend")]
//! Tests for the SoftLimitService
//!
//! Tests daily usage tracking, soft limit enforcement,
//! progressive throttling, and usage statistics.

#[cfg(all(test, feature = "payment"))]
mod soft_limit_tests {
    use chrono::{Duration, Utc};
    use deadpool_diesel::Manager as DeadpoolManager;
    use deadpool_diesel::Pool;
    use diesel::prelude::*;
    use scribe_backend::db::DbId;
    use scribe_backend::models::users::UserRole;
    use scribe_backend::{
        config::Config,
        models::payment::NewSubscription,
        schema::{daily_usage_tracking, subscriptions},
        services::payment::SoftLimitService,
        test_helpers::{spawn_app, TestDataGuard},
    };
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper function to create a test user
    async fn create_test_user(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        user_id: DbId,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            .bind::<diesel::sql_types::Uuid, _>(user_id.into_uuid())
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

            Ok(())
        }).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_soft_limit_service_initialization() {
        let config = Config::load().expect("Failed to load config");
        let service = SoftLimitService::new(Arc::new(config));

        // Service should initialize without errors
        assert!(!service.is_enabled()); // Disabled by default in tests
    }

    #[tokio::test]
    async fn test_daily_usage_creation() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");
        let config = app.config.clone();

        // Get or create daily usage
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config);
                service.get_or_create_daily_usage(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to create daily usage");

        assert_eq!(usage.user_id, user_id.into_uuid());
        assert_eq!(usage.message_count, 0);
        assert_eq!(usage.token_count, 0);
        assert!(usage.soft_limit_triggered_at.is_none());

        // Getting again should return same record
        let config2 = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage2 = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config2);
                service.get_or_create_daily_usage(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get usage");

        assert_eq!(usage.user_id, usage2.user_id);
        assert_eq!(usage.date, usage2.date);
    }

    #[tokio::test]
    async fn test_record_usage() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable soft limits
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Record usage multiple times
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage1 = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.record_usage(conn, user_id, "gemini-2.5-flash", 100)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to record usage");

        assert_eq!(usage1.message_count, 1);
        assert_eq!(usage1.token_count, 100);

        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage2 = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.record_usage(conn, user_id, "gemini-2.5-pro", 200)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to record usage");

        assert_eq!(usage2.message_count, 2);
        assert_eq!(usage2.token_count, 300);

        // Check model breakdown
        let breakdown = usage2.model_breakdown.unwrap();
        assert_eq!(breakdown["gemini-2.5-flash"], 1);
        assert_eq!(breakdown["gemini-2.5-pro"], 1);
    }

    #[tokio::test]
    async fn test_soft_limit_trigger() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable soft limits with low threshold for testing
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        config.payment.free_tier_token_limit = 1000; // Set low limit for testing
        let config = Arc::new(config);

        // Record usage up to limit (free tier is 20 messages)
        for i in 0..25 {
            let config_clone = config.clone();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let usage = conn
                .interact(move |conn| {
                    let service = SoftLimitService::new(config_clone);
                    service.record_usage(conn, user_id, "gemini-2.5-flash", 100)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to record usage");

            if i < 19 {
                assert!(
                    usage.soft_limit_triggered_at.is_none(),
                    "Should not trigger before 20 messages, but triggered at message {}",
                    i + 1
                );
            } else {
                // Should trigger at 20th message (index 19)
                assert!(
                    usage.soft_limit_triggered_at.is_some(),
                    "Should trigger at message 20 or after, current message: {}",
                    i + 1
                );
            }
        }
    }

    #[tokio::test]
    async fn test_throttling_delays() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Create a basic subscription (which has throttling thresholds)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            let new_sub = NewSubscription {
                id: Uuid::new_v4(),
                user_id: user_id.into_uuid(),
                plan_type: "basic".to_string(),
                paddle_subscription_id: Some("test_throttle".to_string()),
                paddle_customer_id: Some("test_customer".to_string()),
                status: "active".to_string(),
                current_period_start: Utc::now(),
                current_period_end: Utc::now() + Duration::days(30),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(false),
                last_credit_grant: None,
                soft_limit_override: None,
                paddle_sync_attempted: false,
                first_payment_date: None,
                has_ever_paid: Some(false),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: None,
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            use scribe_backend::schema::subscriptions::dsl;
            diesel::insert_into(dsl::subscriptions)
                .values(&new_sub)
                .execute(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to create subscription");

        // Enable soft limits
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Trigger soft limit (basic tier is 100 messages, triggers throttling after 100)
        for _ in 0..101 {
            let config_clone = config.clone();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.record_usage(conn, user_id, "test", 100)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to record");
        }

        // Check throttling - basic tier has 2 second delay after 100 messages
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let throttle = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.should_throttle(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to check throttle");

        assert!(
            throttle.is_some(),
            "Should have throttle delay for basic tier after 100 messages"
        );
        let delay = throttle.unwrap();
        let delay_secs = delay.as_secs();
        assert!(
            delay_secs >= 2 && delay_secs <= 5,
            "Delay should be 2-5 seconds, got {} seconds",
            delay_secs
        );
    }

    #[tokio::test]
    async fn test_tier_based_limits() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable soft limits
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Create premium subscription
        let sub = NewSubscription {
            id: Uuid::new_v4(),
            user_id: user_id.into_uuid(),
            paddle_customer_id: Some("cus_test".to_string()),
            paddle_subscription_id: Some("sub_test".to_string()),
            plan_type: "premium".to_string(),
            status: "active".to_string(),
            current_period_start: Utc::now(),
            current_period_end: Utc::now() + Duration::days(30),
            cancel_at_period_end: Some(false),
            trial_end: None,
            credits_allocated_this_period: Some(false),
            soft_limit_override: None,
            paddle_sync_attempted: false,
            first_payment_date: None,
            has_ever_paid: Some(false),
            cancellation_date: None,
            trial_start_date: None,
            last_payment_date: None,
            last_credit_grant: None,
            grace_period_end: None,
            scheduled_plan_change: None,
            scheduled_change_date: None,
        };

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(subscriptions::table)
                .values(&sub)
                .execute(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to insert subscription");

        // Check remaining messages for premium tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let remaining = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.get_remaining_messages(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get remaining");

        // Premium tier should have 200 messages
        assert_eq!(remaining, Some(200));
    }

    #[tokio::test]
    async fn test_usage_stats() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable soft limits
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Create usage for multiple days
        for days_ago in 0..5 {
            let date = (Utc::now() - Duration::days(days_ago)).date_naive();

            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let config_clone = config.clone();
            conn.interact(move |conn| {
                use scribe_backend::models::credit::NewDailyUsage;

                let usage = NewDailyUsage {
                    user_id: user_id.into_uuid(),
                    date,
                    message_count: 10 + days_ago as i32,
                    token_count: 1000 + (days_ago as i64 * 100),
                    soft_limit_triggered_at: None,
                    model_breakdown: Some(json!({
                        "test_model": days_ago + 1
                    })),
                };

                diesel::insert_into(daily_usage_tracking::table)
                    .values(&usage)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to insert usage");
        }

        // Get usage stats for last 7 days
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let stats = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.get_usage_stats(conn, user_id, Some(7))
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get stats");

        assert_eq!(stats.len(), 5);
        // Stats should be in reverse chronological order (newest first)
        // Day 0 (today) has 10 messages, Day 4 (4 days ago) has 14 messages
        assert!(stats[0].message_count < stats[4].message_count);
    }

    #[tokio::test]
    async fn test_daily_reset() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");
        let config = app.config.clone();

        // Create usage for yesterday
        let yesterday = (Utc::now() - Duration::days(1)).date_naive();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use scribe_backend::models::credit::NewDailyUsage;

            let usage = NewDailyUsage {
                user_id: user_id.into_uuid(),
                date: yesterday,
                message_count: 50,
                token_count: 5000,
                soft_limit_triggered_at: Some(25), // Triggered at message 25
                model_breakdown: None,
            };

            diesel::insert_into(daily_usage_tracking::table)
                .values(&usage)
                .execute(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to insert");

        // Get today's usage - should be fresh
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let today_usage = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.get_or_create_daily_usage(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get today's usage");

        assert_eq!(today_usage.message_count, 0);
        assert_eq!(today_usage.token_count, 0);
        assert!(today_usage.soft_limit_triggered_at.is_none());
    }

    #[tokio::test]
    async fn test_subscription_override() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Enable soft limits
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        // Create subscription with soft limit override
        let sub = NewSubscription {
            id: Uuid::new_v4(),
            user_id: user_id.into_uuid(),
            paddle_customer_id: Some("cus_test".to_string()),
            paddle_subscription_id: Some("sub_test".to_string()),
            plan_type: "basic".to_string(),
            status: "active".to_string(),
            current_period_start: Utc::now(),
            current_period_end: Utc::now() + Duration::days(30),
            cancel_at_period_end: Some(false),
            trial_end: None,
            credits_allocated_this_period: Some(false),
            soft_limit_override: Some(500), // Custom limit
            paddle_sync_attempted: false,
            first_payment_date: None,
            has_ever_paid: Some(false),
            cancellation_date: None,
            trial_start_date: None,
            last_payment_date: None,
            last_credit_grant: None,
            grace_period_end: None,
            scheduled_plan_change: None,
            scheduled_change_date: None,
        };

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            diesel::insert_into(subscriptions::table)
                .values(&sub)
                .execute(conn)
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to insert subscription");

        // Check remaining messages - should use override
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let remaining = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.get_remaining_messages(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get remaining");

        assert_eq!(remaining, Some(500)); // Using override value
    }

    #[tokio::test]
    async fn test_soft_limits_disabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = DbId::new();
        create_test_user(&app.db_pool, user_id)
            .await
            .expect("Failed to create user");

        // Soft limits disabled by default
        let config = app.config.clone();
        let service = SoftLimitService::new(config.clone());
        assert!(!service.is_enabled());

        // Record usage should work but not enforce limits
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config);
                service.record_usage(conn, user_id, "test", 1000)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to record");

        assert_eq!(usage.message_count, 1);
        assert!(usage.soft_limit_triggered_at.is_none()); // No limit trigger when disabled
    }
}
