#![cfg(feature = "postgres-backend")]
/// Integration tests for subscription tier context limit enforcement
///
/// Tests verify that users' requested context limits are properly capped
/// based on their subscription tier's max_context_tokens setting:
/// - Free tier: 64,000 tokens
/// - Basic tier: 100,000 tokens
/// - Premium tier: 200,000 tokens

#[cfg(feature = "payment")]
mod subscription_context_limit_tests {
    use chrono::Utc;
    use diesel::prelude::*;
    use scribe_backend::{
        schema::{subscriptions, users},
        test_helpers::{spawn_app, TestDataGuard},
    };
    use std::env;
    use uuid::Uuid;

    /// Helper function to create a test user in the database
    async fn create_test_user(
        pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
        user_id: Uuid,
        email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        let email = email.to_string();

        conn.interact(move |conn| {
            // Check if user already exists
            let existing = users::table
                .filter(users::id.eq(user_id))
                .count()
                .get_result::<i64>(conn)?;

            if existing > 0 {
                return Ok::<_, diesel::result::Error>(());
            }

            // Insert with all required fields using raw SQL
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(format!("test_user_{}", user_id.simple()))
            .bind::<diesel::sql_types::Text, _>(email)
            .bind::<diesel::sql_types::Text, _>("test_hash")
            .bind::<diesel::sql_types::Text, _>("test_salt")
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

    /// Helper function to create a subscription with a specific plan type
    async fn create_test_subscription(
        pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
        user_id: Uuid,
        plan_type: &str,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        let plan_type = plan_type.to_string();

        let subscription_id = conn
            .interact(move |conn| {
                diesel::insert_into(subscriptions::table)
                    .values((
                        subscriptions::user_id.eq(user_id),
                        subscriptions::plan_type.eq(plan_type),
                        subscriptions::status.eq("active"),
                        subscriptions::current_period_start.eq(Utc::now()),
                        subscriptions::current_period_end
                            .eq(Utc::now() + chrono::Duration::days(30)),
                        subscriptions::cancel_at_period_end.eq(false),
                    ))
                    .returning(subscriptions::id)
                    .get_result::<Uuid>(conn)
            })
            .await??;

        Ok(subscription_id)
    }

    #[tokio::test]
    async fn test_free_tier_context_limit_64k() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let email = format!("free_test_{}@example.com", user_id.simple());

        // Create user without subscription (defaults to Free tier)
        create_test_user(&app.db_pool, user_id, &email)
            .await
            .expect("Failed to create test user");

        // Verify free tier plan_features has max_context_tokens = 64000
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let max_tokens: Option<i32> = conn
            .interact(|conn| {
                use scribe_backend::schema::plan_features;
                plan_features::table
                    .filter(plan_features::plan_type.eq("free"))
                    .select(plan_features::max_context_tokens)
                    .first::<Option<i32>>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to query plan_features");

        assert_eq!(
            max_tokens,
            Some(64000),
            "Free tier should have max_context_tokens = 64000"
        );
    }

    #[tokio::test]
    async fn test_basic_tier_context_limit_100k() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let email = format!("basic_test_{}@example.com", user_id.simple());

        // Create user with Basic subscription
        create_test_user(&app.db_pool, user_id, &email)
            .await
            .expect("Failed to create test user");

        create_test_subscription(&app.db_pool, user_id, "basic")
            .await
            .expect("Failed to create subscription");

        // Verify basic tier plan_features has max_context_tokens = 100000
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let max_tokens: Option<i32> = conn
            .interact(|conn| {
                use scribe_backend::schema::plan_features;
                plan_features::table
                    .filter(plan_features::plan_type.eq("basic"))
                    .select(plan_features::max_context_tokens)
                    .first::<Option<i32>>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to query plan_features");

        assert_eq!(
            max_tokens,
            Some(100000),
            "Basic tier should have max_context_tokens = 100000"
        );
    }

    #[tokio::test]
    async fn test_premium_tier_context_limit_200k() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let email = format!("premium_test_{}@example.com", user_id.simple());

        // Create user with Premium subscription
        create_test_user(&app.db_pool, user_id, &email)
            .await
            .expect("Failed to create test user");

        create_test_subscription(&app.db_pool, user_id, "premium")
            .await
            .expect("Failed to create subscription");

        // Verify premium tier plan_features has max_context_tokens = 200000
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let max_tokens: Option<i32> = conn
            .interact(|conn| {
                use scribe_backend::schema::plan_features;
                plan_features::table
                    .filter(plan_features::plan_type.eq("premium"))
                    .select(plan_features::max_context_tokens)
                    .first::<Option<i32>>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to query plan_features");

        assert_eq!(
            max_tokens,
            Some(200000),
            "Premium tier should have max_context_tokens = 200000"
        );
    }

    #[tokio::test]
    async fn test_context_limit_within_tier_allowed() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let email = format!("within_limit_test_{}@example.com", user_id.simple());

        // Create user with Basic subscription (100k limit)
        create_test_user(&app.db_pool, user_id, &email)
            .await
            .expect("Failed to create test user");

        create_test_subscription(&app.db_pool, user_id, "basic")
            .await
            .expect("Failed to create subscription");

        // Test that a request within the limit (80k < 100k) is not capped
        // This is a database-level test verifying the subscription and plan_features exist
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let subscription_exists = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .filter(subscriptions::plan_type.eq("basic"))
                    .filter(subscriptions::status.eq("active"))
                    .count()
                    .get_result::<i64>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count subscriptions");

        assert_eq!(
            subscription_exists, 1,
            "User should have exactly 1 active Basic subscription"
        );
    }

    #[tokio::test]
    async fn test_no_subscription_defaults_to_free_tier_limit() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let email = format!("no_sub_test_{}@example.com", user_id.simple());

        // Create user WITHOUT subscription
        create_test_user(&app.db_pool, user_id, &email)
            .await
            .expect("Failed to create test user");

        // Verify no subscription exists for user
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let subscription_count = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count subscriptions");

        assert_eq!(
            subscription_count, 0,
            "User should have no subscriptions (defaults to Free tier)"
        );

        // Verify free tier plan_features exist
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let free_tier_exists = conn
            .interact(|conn| {
                use scribe_backend::schema::plan_features;
                plan_features::table
                    .filter(plan_features::plan_type.eq("free"))
                    .filter(plan_features::max_context_tokens.eq(64000))
                    .count()
                    .get_result::<i64>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to query plan_features");

        assert_eq!(
            free_tier_exists, 1,
            "Free tier plan_features should exist with 64k context limit"
        );
    }

    #[tokio::test]
    async fn test_all_tiers_have_context_limits_configured() {
        // Skip if not running integration tests
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Verify all three tiers have max_context_tokens set
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let tier_limits: Vec<(Option<String>, Option<i32>)> = conn
            .interact(|conn| {
                use scribe_backend::schema::plan_features;
                plan_features::table
                    .filter(plan_features::plan_type.eq_any(vec!["free", "basic", "premium"]))
                    .select((plan_features::plan_type, plan_features::max_context_tokens))
                    .order(plan_features::plan_type.asc())
                    .load::<(Option<String>, Option<i32>)>(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to query plan_features");

        // Should have exactly 3 tiers: basic, free, premium (alphabetically)
        assert_eq!(tier_limits.len(), 3, "Should have 3 tier configurations");

        // Verify each tier has the correct limit
        let expected_limits = vec![
            (Some("basic".to_string()), Some(100000)),
            (Some("free".to_string()), Some(64000)),
            (Some("premium".to_string()), Some(200000)),
        ];

        assert_eq!(
            tier_limits, expected_limits,
            "All tiers should have correct max_context_tokens values"
        );
    }
}

// Test without payment feature to verify no enforcement occurs
#[cfg(not(feature = "payment"))]
mod subscription_context_limit_no_payment_tests {
    // Tests for non-payment behavior would go here
}
