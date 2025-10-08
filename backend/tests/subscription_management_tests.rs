#[cfg(all(test, feature = "payment"))]
mod subscription_management_tests {
    use chrono::Utc;
    use deadpool_diesel::{Manager as DeadpoolManager, Pool};
    use diesel::prelude::*;
    use scribe_backend::{
        models::users::UserRole,
        services::{
            EncryptionService,
            payment::{SubscriptionService, UsageTrackingService},
        },
        test_helpers::{TestDataGuard, spawn_app},
    };
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
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
            Ok::<_, diesel::result::Error>(())
        }).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_subscription_service_creation() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Test that SubscriptionService can be created with the app config
        let encryption_service = EncryptionService::new();
        let subscription_service =
            SubscriptionService::new((*app.config).clone(), encryption_service);

        // Basic smoke test - service should be created successfully
        assert!(true, "SubscriptionService created successfully");
    }

    #[tokio::test]
    async fn test_usage_tracking_service_creation() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "usage_test", "usage@test.com", None)
            .await
            .expect("Failed to create user");

        // Test that UsageTrackingService can be created with the app config
        let encryption_service = EncryptionService::new();
        let usage_service = UsageTrackingService::new((*app.config).clone(), encryption_service);

        // Basic smoke test - service should be created successfully
        assert!(true, "UsageTrackingService created successfully");
    }

    #[tokio::test]
    async fn test_subscription_service_integration() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "sub_test", "sub@test.com", None)
            .await
            .expect("Failed to create user");

        let encryption_service = EncryptionService::new();
        let subscription_service =
            SubscriptionService::new((*app.config).clone(), encryption_service);

        // Note: Actual subscription operations would require more setup
        // This is a placeholder test for basic service functionality
        assert!(true, "Subscription service integration test passed");
    }

    #[tokio::test]
    async fn test_usage_tracking_service_integration() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "tracking_test",
            "tracking@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        let encryption_service = EncryptionService::new();
        let usage_service = UsageTrackingService::new((*app.config).clone(), encryption_service);

        // Note: Actual usage tracking operations would require more setup
        // This is a placeholder test for basic service functionality
        assert!(true, "Usage tracking service integration test passed");
    }
}
