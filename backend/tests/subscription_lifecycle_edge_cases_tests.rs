#[cfg(all(test, feature = "payment"))]
mod subscription_lifecycle_edge_cases_tests {
    use chrono::{Duration, Utc};
    use deadpool_diesel::Manager as DeadpoolManager;
    use deadpool_diesel::Pool;
    use diesel::prelude::*;
    use scribe_backend::models::payment::{NewSubscription, Subscription};
    use scribe_backend::schema::{subscriptions, users};
    use scribe_backend::test_helpers::{TestDataGuard, spawn_app};
    use uuid::Uuid;

    /// Helper function to create a test user with a specific UUID
    async fn create_test_user(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        user_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        conn.interact(move |conn| {
            // Check if user already exists
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

    mod subscription_reactivation_tests {
        use super::*;

        #[tokio::test]
        async fn test_subscription_reactivation_after_cancellation() {
            let app = spawn_app(true, false, false).await;
            let _guard = TestDataGuard::new(app.db_pool.clone(), None);

            let user_id = Uuid::new_v4();
            create_test_user(&app.db_pool, user_id)
                .await
                .expect("Failed to create user");

            // Create an active subscription that's set to cancel at period end
            let subscription_id = Uuid::new_v4();
            let expected_period_end = Utc::now() + Duration::days(25); // Save this before moving
            let subscription = NewSubscription {
                id: subscription_id,
                user_id,
                paddle_customer_id: Some("cus_test_reactivate".to_string()),
                paddle_subscription_id: Some("sub_test_reactivate".to_string()),
                plan_type: "basic".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now() - Duration::days(5),
                current_period_end: expected_period_end,
                cancel_at_period_end: Some(true), // Set to cancel at period end
                trial_end: None,
                credits_allocated_this_period: Some(true),
                last_credit_grant: Some(Utc::now() - Duration::days(5)),
                soft_limit_override: None,
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now() - Duration::days(30)),
                has_ever_paid: Some(true),
                cancellation_date: Some(Utc::now() - Duration::hours(2)), // Cancelled 2 hours ago
                trial_start_date: None,
                last_payment_date: Some(Utc::now() - Duration::days(5)),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            // Insert the subscription
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::insert_into(subscriptions::table)
                    .values(&subscription)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to insert subscription");

            println!("✓ Created cancelled subscription (cancel_at_period_end = true)");

            // Verify initial state
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let initial_sub: Subscription = conn
                .interact(move |conn| {
                    subscriptions::table
                        .filter(subscriptions::id.eq(subscription_id))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to get subscription");

            assert_eq!(initial_sub.status, "active");
            assert_eq!(initial_sub.cancel_at_period_end, Some(true));
            println!("✓ Verified initial state: active with cancel_at_period_end = true");

            // Simulate reactivation by setting cancel_at_period_end back to false
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancel_at_period_end.eq(false))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancellation_date.eq(Option::<chrono::DateTime<Utc>>::None))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::updated_at.eq(Utc::now()))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to update subscription");

            println!("✓ Reactivated subscription (cancel_at_period_end = false)");

            // Verify reactivation
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let reactivated_sub: Subscription = conn
                .interact(move |conn| {
                    subscriptions::table
                        .filter(subscriptions::id.eq(subscription_id))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to get subscription");

            assert_eq!(
                reactivated_sub.status, "active",
                "Status should remain active after reactivation"
            );
            assert_eq!(
                reactivated_sub.cancel_at_period_end,
                Some(false),
                "cancel_at_period_end should be false after reactivation"
            );
            assert_eq!(
                reactivated_sub.cancellation_date, None,
                "cancellation_date should be cleared after reactivation"
            );
            assert_eq!(
                reactivated_sub.current_period_end, expected_period_end,
                "current_period_end should remain unchanged"
            );

            println!("✓ Verified reactivation: subscription will continue beyond current period");
        }

        #[tokio::test]
        async fn test_cancel_at_period_end_toggle_behavior() {
            let app = spawn_app(true, false, false).await;
            let _guard = TestDataGuard::new(app.db_pool.clone(), None);

            let user_id = Uuid::new_v4();
            create_test_user(&app.db_pool, user_id)
                .await
                .expect("Failed to create user");

            // Create an active subscription
            let subscription_id = Uuid::new_v4();
            let subscription = NewSubscription {
                id: subscription_id,
                user_id,
                paddle_customer_id: Some("cus_test_toggle".to_string()),
                paddle_subscription_id: Some("sub_test_toggle".to_string()),
                plan_type: "premium".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now() - Duration::days(10),
                current_period_end: Utc::now() + Duration::days(20),
                cancel_at_period_end: Some(false), // Not cancelled
                trial_end: None,
                credits_allocated_this_period: Some(true),
                last_credit_grant: Some(Utc::now() - Duration::days(10)),
                soft_limit_override: None,
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now() - Duration::days(60)),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now() - Duration::days(10)),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            // Insert the subscription
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::insert_into(subscriptions::table)
                    .values(&subscription)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to insert subscription");

            println!("✓ Created active subscription (cancel_at_period_end = false)");

            // Step 1: Cancel subscription (set cancel_at_period_end = true)
            let cancellation_time = Utc::now();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancel_at_period_end.eq(true))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancellation_date.eq(Some(cancellation_time)))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::updated_at.eq(cancellation_time))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to cancel subscription");

            println!("✓ Cancelled subscription (cancel_at_period_end = true)");

            // Verify cancelled state
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let cancelled_sub: Subscription = conn
                .interact(move |conn| {
                    subscriptions::table
                        .filter(subscriptions::id.eq(subscription_id))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to get subscription");

            assert_eq!(cancelled_sub.status, "active");
            assert_eq!(cancelled_sub.cancel_at_period_end, Some(true));
            assert!(cancelled_sub.cancellation_date.is_some());
            println!("✓ Verified cancelled state: active but will cancel at period end");

            // Step 2: Undo cancellation (set cancel_at_period_end back to false)
            let reactivation_time = Utc::now();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancel_at_period_end.eq(false))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancellation_date.eq(Option::<chrono::DateTime<Utc>>::None))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::updated_at.eq(reactivation_time))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to reactivate subscription");

            println!("✓ Undid cancellation (cancel_at_period_end = false)");

            // Verify reactivated state
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let reactivated_sub: Subscription = conn
                .interact(move |conn| {
                    subscriptions::table
                        .filter(subscriptions::id.eq(subscription_id))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to get subscription");

            assert_eq!(reactivated_sub.status, "active");
            assert_eq!(reactivated_sub.cancel_at_period_end, Some(false));
            assert!(reactivated_sub.cancellation_date.is_none());
            println!("✓ Verified reactivated state: subscription will auto-renew");

            // Step 3: Cancel again to test multiple toggles
            let second_cancellation_time = Utc::now();
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancel_at_period_end.eq(true))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::cancellation_date.eq(Some(second_cancellation_time)))
                    .execute(conn)?;
                diesel::update(subscriptions::table.filter(subscriptions::id.eq(subscription_id)))
                    .set(subscriptions::updated_at.eq(second_cancellation_time))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to cancel subscription again");

            println!("✓ Cancelled subscription again (testing multiple toggles)");

            // Final verification
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let final_sub: Subscription = conn
                .interact(move |conn| {
                    subscriptions::table
                        .filter(subscriptions::id.eq(subscription_id))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                })
                .await
                .expect("Failed to interact")
                .expect("Failed to get subscription");

            assert_eq!(final_sub.status, "active");
            assert_eq!(final_sub.cancel_at_period_end, Some(true));
            assert!(final_sub.cancellation_date.is_some());
            println!("✓ Verified final state: multiple toggle operations work correctly");
        }
    }
}
