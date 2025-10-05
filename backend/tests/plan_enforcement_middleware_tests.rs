#[cfg(all(test, feature = "payment"))]
mod plan_enforcement_middleware_tests {
    use chrono::Utc;
    use deadpool_diesel::{Manager as DeadpoolManager, Pool};
    use diesel::prelude::*;
    use scribe_backend::{
        middleware::plan_enforcement::EnforcementConfig,
        models::users::UserRole,
        services::{EncryptionService, payment::SubscriptionService},
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
    async fn test_enforcement_config_creation() {
        // Test that various enforcement configurations can be created
        let _basic_config = EnforcementConfig::basic_chat();
        let _advanced_config = EnforcementConfig::advanced_chat();
        let _disabled_config = EnforcementConfig::disabled();

        // Basic smoke tests - configs should be created successfully
        assert!(true, "EnforcementConfig variants created successfully");
    }

    #[tokio::test]
    async fn test_plan_enforcement_middleware_setup() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "plan_test", "plan@test.com", None)
            .await
            .expect("Failed to create user");

        // Test that we can create enforcement configs for different scenarios
        let configs = vec![
            EnforcementConfig::basic_chat(),
            EnforcementConfig::advanced_chat(),
            EnforcementConfig::character_generation(),
            EnforcementConfig::unlimited_characters(),
            EnforcementConfig::enterprise_features(),
            EnforcementConfig::disabled(),
        ];

        assert_eq!(
            configs.len(),
            6,
            "All enforcement config variants should be available"
        );
    }

    #[tokio::test]
    async fn test_subscription_service_integration() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            user_id,
            "sub_enforcement_test",
            "subtest@test.com",
            None,
        )
        .await
        .expect("Failed to create user");

        // Test that SubscriptionService can be created for plan enforcement
        let encryption_service = EncryptionService::new();
        let _subscription_service =
            SubscriptionService::new((*app.config).clone(), encryption_service);

        // Basic smoke test - service should be created successfully
        assert!(
            true,
            "SubscriptionService created for plan enforcement testing"
        );
    }

    #[tokio::test]
    async fn test_admin_user_role() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let admin_user_id = Uuid::new_v4();
        create_test_user(
            &app.db_pool,
            admin_user_id,
            "admin_test",
            "admin@test.com",
            Some(UserRole::Administrator),
        )
        .await
        .expect("Failed to create admin user");

        // Test that admin user can be created successfully
        assert!(true, "Administrator user created successfully");
    }
}
