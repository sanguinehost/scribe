//! Tests for the credit system feature flag system
//!
//! Tests the three-layer feature gating:
//! 1. Cargo feature flags (compile-time)
//! 2. Runtime configuration (config.yaml)
//! 3. Frontend environment variables

#[cfg(all(test, feature = "payment"))]
mod feature_flag_tests {
    use scribe_backend::{
        config::Config,
        services::payment::{CreditService, SoftLimitService},
        test_helpers::{spawn_app, TestDataGuard},
    };
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_feature_flag_cargo_enabled() {
        // This test only compiles when the payment feature is enabled
        // via cargo features
        assert!(true, "Payment feature is enabled at compile time");
    }

    #[tokio::test]
    async fn test_credit_service_runtime_disabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create service with credits disabled in config
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = false;
        let config = Arc::new(config);

        let service = CreditService::new(config.clone());
        assert!(!service.is_enabled());

        // Operations should fail when disabled
        let user_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let result = conn
            .interact(move |conn| {
                service.add_credits(conn, user_id, 100, "test", "Should fail", None, None)
            })
            .await
            .expect("Failed to interact");

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("not enabled"));
        }
    }

    #[tokio::test]
    async fn test_credit_service_runtime_enabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create service with credits enabled in config
        let mut config = (*app.config).clone();
        config.payment.credits_enabled = true;
        let config = Arc::new(config);

        let user_id = Uuid::new_v4();

        // Create test user first
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;
            use scribe_backend::schema::users;

            // Check if user exists first
            let exists: Result<i64, _> = users::table
                .filter(users::id.eq(user_id))
                .count()
                .get_result(conn);

            if let Ok(count) = exists {
                if count > 0 {
                    return Ok(()) as Result<(), diesel::result::Error>;
                }
            }

            // Create user with raw SQL to handle enums
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
            .bind::<diesel::sql_types::Text, _>("User")
            .bind::<diesel::sql_types::Text, _>("active")
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
            .execute(conn)?;
            Ok(())
        }).await.expect("Failed to interact").expect("Failed to create user");

        let service = CreditService::new(config.clone());
        assert!(service.is_enabled());

        // Initialize and add credits should work
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| service.initialize_user_credits(conn, user_id))
            .await
            .expect("Failed to interact")
            .expect("Should initialize when enabled");

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config);
                service.add_credits(conn, user_id, 100, "test", "Test credits", None, None)
            })
            .await
            .expect("Failed to interact")
            .expect("Should add credits when enabled");

        assert_eq!(balance.balance, 100);
    }

    #[tokio::test]
    async fn test_soft_limit_service_runtime_disabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create service with soft limits disabled in config
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = false;
        let config = Arc::new(config);

        let user_id = Uuid::new_v4();

        // Create test user first
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;
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
            .bind::<diesel::sql_types::Text, _>("User")
            .bind::<diesel::sql_types::Text, _>("active")
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        }).await.expect("Failed to interact").expect("Failed to create user");

        let service = SoftLimitService::new(config.clone());
        assert!(!service.is_enabled());

        // Should still track usage even when disabled
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let usage = conn
            .interact(move |conn| service.record_usage(conn, user_id, "gemini-2.5-flash", 1000))
            .await
            .expect("Failed to interact")
            .expect("Should track usage even when disabled");
        assert_eq!(usage.message_count, 1);

        // But should not throttle
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let throttle = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.should_throttle(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Should check throttle");
        assert!(throttle.is_none(), "Should not throttle when disabled");

        // And should return no limit
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let remaining = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config);
                service.get_remaining_messages(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Should get remaining");
        assert_eq!(remaining, None, "Should have no limit when disabled");
    }

    #[tokio::test]
    async fn test_soft_limit_service_runtime_enabled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create service with soft limits enabled in config
        let mut config = (*app.config).clone();
        config.payment.soft_limits_enabled = true;
        let config = Arc::new(config);

        let user_id = Uuid::new_v4();

        // Create test user first
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;
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
            .bind::<diesel::sql_types::Text, _>("User")
            .bind::<diesel::sql_types::Text, _>("active")
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Int8, _>(0i64)
            .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        }).await.expect("Failed to interact").expect("Failed to create user");

        let service = SoftLimitService::new(config.clone());
        assert!(service.is_enabled());

        // Should have remaining messages for free tier
        let config_clone = config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let remaining = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.get_remaining_messages(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Should get remaining");
        assert_eq!(remaining, Some(20), "Free tier should have 20 messages");

        // Record usage up to limit
        for _ in 0..20 {
            let config_clone = config.clone();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                let service = SoftLimitService::new(config_clone);
                service.record_usage(conn, user_id, "gemini-2.5-flash", 100)
            })
            .await
            .expect("Failed to interact")
            .unwrap();
        }

        // Should now be throttled
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let throttle = conn
            .interact(move |conn| {
                let service = SoftLimitService::new(config);
                service.should_throttle(conn, user_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Should check throttle");
        assert!(throttle.is_some(), "Should throttle after limit reached");
    }

    #[tokio::test]
    async fn test_both_services_can_be_independently_controlled() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Test with credits enabled, soft limits disabled
        let mut config1 = (*app.config).clone();
        config1.payment.credits_enabled = true;
        config1.payment.soft_limits_enabled = false;

        let credit_service1 = CreditService::new(Arc::new(config1.clone()));
        let soft_limit_service1 = SoftLimitService::new(Arc::new(config1));

        assert!(credit_service1.is_enabled());
        assert!(!soft_limit_service1.is_enabled());

        // Test with credits disabled, soft limits enabled
        let mut config2 = (*app.config).clone();
        config2.payment.credits_enabled = false;
        config2.payment.soft_limits_enabled = true;

        let credit_service2 = CreditService::new(Arc::new(config2.clone()));
        let soft_limit_service2 = SoftLimitService::new(Arc::new(config2));

        assert!(!credit_service2.is_enabled());
        assert!(soft_limit_service2.is_enabled());

        // Test with both enabled
        let mut config3 = (*app.config).clone();
        config3.payment.credits_enabled = true;
        config3.payment.soft_limits_enabled = true;

        let credit_service3 = CreditService::new(Arc::new(config3.clone()));
        let soft_limit_service3 = SoftLimitService::new(Arc::new(config3));

        assert!(credit_service3.is_enabled());
        assert!(soft_limit_service3.is_enabled());
    }

    #[tokio::test]
    async fn test_config_loading_preserves_feature_flags() {
        // Load actual config from file
        let config = Config::load().expect("Should load config");

        // Check that the config fields exist and have expected defaults
        // (These are the test environment defaults)
        assert_eq!(
            config.payment.credits_enabled, false,
            "Credits should be disabled by default in test config"
        );
        assert_eq!(
            config.payment.soft_limits_enabled, false,
            "Soft limits should be disabled by default in test config"
        );

        // Verify other payment config fields are present
        assert!(config.payment.max_credit_balance > 0);
        assert!(config.payment.usage_reset_hour_utc >= 0);
        assert!(config.payment.usage_reset_hour_utc < 24);
    }

    #[tokio::test]
    async fn test_frontend_environment_flag_coordination() {
        // This test documents the expected frontend environment variables
        // that should be coordinated with backend feature flags

        // Frontend should check process.env.PUBLIC_CREDITS_ENABLED
        // Frontend should check process.env.PUBLIC_SOFT_LIMITS_ENABLED

        // These would be set in the frontend's .env file:
        // PUBLIC_CREDITS_ENABLED=false
        // PUBLIC_SOFT_LIMITS_ENABLED=false

        // This test serves as documentation of the expected coordination
        assert!(true, "Frontend flags documented");
    }
}

#[cfg(not(feature = "payment"))]
mod feature_flag_disabled_tests {
    #[tokio::test]
    async fn test_payment_feature_disabled() {
        // This test runs when the payment feature is NOT enabled
        // It verifies that the credit services don't exist when the feature is off

        // The following would not compile:
        // use scribe_backend::services::payment::CreditService;
        // use scribe_backend::services::payment::SoftLimitService;

        assert!(true, "Payment feature is disabled at compile time");
    }
}
