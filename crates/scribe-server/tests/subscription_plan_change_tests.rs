#![cfg(feature = "postgres-backend")]
//! Integration tests for subscription plan upgrades and downgrades
//!
//! Tests cover:
//! - Immediate upgrades with credit bonuses
//! - Scheduled downgrades at period end
//! - Credit preservation on downgrade
//! - Unknown price_id handling
//! - Upgrade canceling pending downgrades
//! - Multiple consecutive plan changes
//! - Scheduler applying due changes
//! - Audit trail for plan changes

#[cfg(all(test, feature = "payment"))]
mod plan_change_tests {
    use chrono::Utc;
    use scribe_backend::{
        config::Config,
        errors::AppError,
        models::payment::{NewSubscription, Subscription},
        schema::{payment_audit_logs, subscriptions, user_credits},
        services::payment::{
            audit_service::{AuditEventType, PaymentAuditService},
            PaymentScheduler,
        },
        test_helpers::{spawn_app, TestDataGuard},
    };
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore]
    async fn test_immediate_upgrade_basic_to_premium() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create test user with basic subscription
        let user_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;

            // Create user credit balance
            diesel::sql_query(
                "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                 VALUES ($1, 250, 250, 1, NOW(), NOW())",
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(conn)?;

            // Create basic subscription
            let new_subscription = NewSubscription {
                id: subscription_id.into(),
                user_id: user_id.into(),
                paddle_customer_id: Some("cus_test_123".to_string()),
                paddle_subscription_id: Some("sub_test_123".to_string()),
                plan_type: "basic".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now().into(),
                current_period_end: (Utc::now() + chrono::Duration::days(30)).into(),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(true),
                soft_limit_override: None,
                last_credit_grant: Some(Utc::now().into()),
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now().into()),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now().into()),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            diesel::insert_into(subscriptions::table)
                .values(&new_subscription)
                .execute(conn)?;

            Ok::<_, AppError>(())
        })
        .await??;

        // Simulate subscription.updated webhook with premium price_id
        let webhook_payload = json!({
            "event_id": "evt_upgrade_test",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_test_123",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k5ej7wzvpcj6j65vcbpam6t4" // Premium monthly
                    },
                    "quantity": 1
                }],
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        // Send webhook
        use reqwest::Client;
        let client = Client::new();
        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .json(&webhook_payload)
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        // Verify subscription upgraded to premium
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub: Subscription = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await??;

        assert_eq!(updated_sub.plan_type, "premium");
        assert!(updated_sub.scheduled_plan_change.is_none());

        // Verify credit bonus added (premium=800, basic=250, diff=550)
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");
        let credit_balance: i32 = conn2
            .interact(move |conn| {
                use diesel::prelude::*;
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first::<i32>(conn)
            })
            .await??;

        assert_eq!(credit_balance, 800); // 250 + 550 upgrade bonus

        // Verify audit log
        let conn3 = app.db_pool.get().await.expect("Failed to get connection");
        let audit_count: i64 = conn3
            .interact(move |conn| {
                use diesel::prelude::*;
                payment_audit_logs::table
                    .filter(payment_audit_logs::event_type.eq("plan_upgraded"))
                    .count()
                    .get_result(conn)
            })
            .await??;

        assert_eq!(audit_count, 1);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_scheduled_downgrade_premium_to_basic() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create test user with premium subscription
        let user_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();
        let period_end = Utc::now() + chrono::Duration::days(15);

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;

            // Create user credit balance
            diesel::sql_query(
                "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                 VALUES ($1, 800, 800, 1, NOW(), NOW())",
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(conn)?;

            // Create premium subscription
            let new_subscription = NewSubscription {
                id: subscription_id.into(),
                user_id: user_id.into(),
                paddle_customer_id: Some("cus_test_456".to_string()),
                paddle_subscription_id: Some("sub_test_456".to_string()),
                plan_type: "premium".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now().into(),
                current_period_end: period_end.into(),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(true),
                soft_limit_override: None,
                last_credit_grant: Some(Utc::now().into()),
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now().into()),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now().into()),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            diesel::insert_into(subscriptions::table)
                .values(&new_subscription)
                .execute(conn)?;

            Ok::<_, AppError>(())
        })
        .await??;

        // Simulate subscription.updated webhook with basic price_id
        let webhook_payload = json!({
            "event_id": "evt_downgrade_test",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_test_456",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02" // Basic monthly
                    },
                    "quantity": 1
                }],
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": period_end.to_rfc3339()
                }
            }
        });

        // Send webhook
        use reqwest::Client;
        let client = Client::new();
        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .json(&webhook_payload)
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        // Verify downgrade is scheduled, not applied immediately
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub: Subscription = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await??;

        assert_eq!(updated_sub.plan_type, "premium"); // Still premium
        assert_eq!(updated_sub.scheduled_plan_change, Some("basic".to_string()));
        assert!(updated_sub.scheduled_change_date.is_some());

        // Verify audit log for scheduled change
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");
        let audit_count: i64 = conn2
            .interact(move |conn| {
                use diesel::prelude::*;
                payment_audit_logs::table
                    .filter(payment_audit_logs::event_type.eq("plan_change_scheduled"))
                    .count()
                    .get_result(conn)
            })
            .await??;

        assert_eq!(audit_count, 1);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_downgrade_preserves_credits() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create test user with premium subscription and 1500 credits
        let user_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;

            // Create user with 1500 credits (more than premium includes)
            diesel::sql_query(
                "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                 VALUES ($1, 1500, 1500, 1, NOW(), NOW())",
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(conn)?;

            // Create premium subscription
            let new_subscription = NewSubscription {
                id: subscription_id.into(),
                user_id: user_id.into(),
                paddle_customer_id: Some("cus_test_789".to_string()),
                paddle_subscription_id: Some("sub_test_789".to_string()),
                plan_type: "premium".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now().into(),
                current_period_end: (Utc::now() + chrono::Duration::days(30)).into(),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(true),
                soft_limit_override: None,
                last_credit_grant: Some(Utc::now().into()),
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now().into()),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now().into()),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            diesel::insert_into(subscriptions::table)
                .values(&new_subscription)
                .execute(conn)?;

            Ok::<_, AppError>(())
        })
        .await??;

        // Simulate downgrade webhook
        let webhook_payload = json!({
            "event_id": "evt_preserve_credits",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_test_789",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02" // Basic monthly
                    },
                    "quantity": 1
                }],
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        // Send webhook
        use reqwest::Client;
        let client = Client::new();
        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .json(&webhook_payload)
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        // Verify credits unchanged (downgrade scheduled, not applied)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let credit_balance: i32 = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first::<i32>(conn)
            })
            .await??;

        assert_eq!(credit_balance, 1500); // Credits preserved

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_unknown_price_id_continues_webhook() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create test user with subscription
        let user_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;

            diesel::sql_query(
                "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                 VALUES ($1, 250, 250, 1, NOW(), NOW())",
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(conn)?;

            let new_subscription = NewSubscription {
                id: subscription_id.into(),
                user_id: user_id.into(),
                paddle_customer_id: Some("cus_unknown".to_string()),
                paddle_subscription_id: Some("sub_unknown".to_string()),
                plan_type: "basic".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now().into(),
                current_period_end: (Utc::now() + chrono::Duration::days(30)).into(),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(true),
                soft_limit_override: None,
                last_credit_grant: Some(Utc::now().into()),
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now().into()),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now().into()),
                grace_period_end: None,
                scheduled_plan_change: None,
                scheduled_change_date: None,
            };

            diesel::insert_into(subscriptions::table)
                .values(&new_subscription)
                .execute(conn)?;

            Ok::<_, AppError>(())
        })
        .await??;

        // Send webhook with unknown price_id
        let webhook_payload = json!({
            "event_id": "evt_unknown_price",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_unknown",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_UNKNOWN_999" // Unknown price_id
                    },
                    "quantity": 1
                }],
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        // Webhook should succeed despite unknown price_id
        use reqwest::Client;
        let client = Client::new();
        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .json(&webhook_payload)
            .send()
            .await?;

        assert_eq!(response.status(), 200); // Webhook succeeds

        // Verify subscription status updated but plan unchanged
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub: Subscription = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await??;

        assert_eq!(updated_sub.plan_type, "basic"); // Plan unchanged
        assert_eq!(updated_sub.status, "active"); // Status updated

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_upgrade_cancels_pending_downgrade() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        conn.interact(move |conn| {
            use diesel::prelude::*;

            diesel::sql_query(
                "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                 VALUES ($1, 800, 800, 1, NOW(), NOW())",
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .execute(conn)?;

            // Create premium subscription with scheduled downgrade to basic
            let new_subscription = NewSubscription {
                id: subscription_id.into(),
                user_id: user_id.into(),
                paddle_customer_id: Some("cus_cancel_downgrade".to_string()),
                paddle_subscription_id: Some("sub_cancel_downgrade".to_string()),
                plan_type: "premium".to_string(),
                status: "active".to_string(),
                current_period_start: Utc::now().into(),
                current_period_end: (Utc::now() + chrono::Duration::days(15)).into(),
                cancel_at_period_end: Some(false),
                trial_end: None,
                credits_allocated_this_period: Some(true),
                soft_limit_override: None,
                last_credit_grant: Some(Utc::now().into()),
                paddle_sync_attempted: false,
                first_payment_date: Some(Utc::now().into()),
                has_ever_paid: Some(true),
                cancellation_date: None,
                trial_start_date: None,
                last_payment_date: Some(Utc::now().into()),
                grace_period_end: None,
                scheduled_plan_change: Some("basic".to_string()), // Downgrade pending
                scheduled_change_date: Some((Utc::now() + chrono::Duration::days(15)).into()),
            };

            diesel::insert_into(subscriptions::table)
                .values(&new_subscription)
                .execute(conn)?;

            Ok::<_, AppError>(())
        })
        .await??;

        // User changes mind and upgrades - send premium webhook again
        let webhook_payload = json!({
            "event_id": "evt_cancel_downgrade",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_cancel_downgrade",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k5ej7wzvpcj6j65vcbpam6t4" // Premium (staying)
                    },
                    "quantity": 1
                }],
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        use reqwest::Client;
        let client = Client::new();
        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .json(&webhook_payload)
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        // Verify scheduled downgrade was cleared
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub: Subscription = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await??;

        assert_eq!(updated_sub.plan_type, "premium");
        assert!(updated_sub.scheduled_plan_change.is_none()); // Downgrade cancelled
        assert!(updated_sub.scheduled_change_date.is_none());

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_scheduler_handles_multiple_due_changes() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create 3 subscriptions with scheduled downgrades due now
        for i in 0..3 {
            let user_id = Uuid::new_v4();
            let subscription_id = Uuid::new_v4();

            let conn = app.db_pool.get().await.expect("Failed to get connection");
            conn.interact(move |conn| {
                use diesel::prelude::*;

                diesel::sql_query(
                    "INSERT INTO user_credits (user_id, balance, lifetime_earned, version, created_at, updated_at)
                     VALUES ($1, 800, 800, 1, NOW(), NOW())",
                )
                .bind::<diesel::sql_types::Uuid, _>(user_id)
                .execute(conn)?;

                let new_subscription = NewSubscription {
                    id: subscription_id.into(),
                    user_id: user_id.into(),
                    paddle_customer_id: Some(format!("cus_scheduler_{}", i)),
                    paddle_subscription_id: Some(format!("sub_scheduler_{}", i)),
                    plan_type: "premium".to_string(),
                    status: "active".to_string(),
                    current_period_start: Utc::now().into(),
                    current_period_end: (Utc::now() + chrono::Duration::days(30)).into(),
                    cancel_at_period_end: Some(false),
                    trial_end: None,
                    credits_allocated_this_period: Some(true),
                    soft_limit_override: None,
                    last_credit_grant: Some(Utc::now().into()),
                    paddle_sync_attempted: false,
                    first_payment_date: Some(Utc::now().into()),
                    has_ever_paid: Some(true),
                    cancellation_date: None,
                    trial_start_date: None,
                    last_payment_date: Some(Utc::now().into()),
                    grace_period_end: None,
                    scheduled_plan_change: Some("basic".to_string()),
                    scheduled_change_date: Some((Utc::now() - chrono::Duration::hours(1)).into()), // Due 1 hour ago
                };

                diesel::insert_into(subscriptions::table)
                    .values(&new_subscription)
                    .execute(conn)?;

                Ok::<_, AppError>(())
            })
            .await??;
        }

        // Run scheduler task
        let config = Arc::new(Config::load().unwrap());
        let scheduler = Arc::new(PaymentScheduler::new(config, app.db_pool.clone()));
        scheduler.apply_scheduled_plan_changes().await?;

        // Verify all 3 subscriptions downgraded
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let basic_count: i64 = conn
            .interact(|conn| {
                use diesel::prelude::*;
                subscriptions::table
                    .filter(subscriptions::plan_type.eq("basic"))
                    .filter(subscriptions::scheduled_plan_change.is_null())
                    .count()
                    .get_result(conn)
            })
            .await??;

        assert_eq!(basic_count, 3);

        // Verify audit logs
        let audit_count: i64 = conn
            .interact(|conn| {
                use diesel::prelude::*;
                payment_audit_logs::table
                    .filter(payment_audit_logs::event_type.eq("plan_downgraded"))
                    .count()
                    .get_result(conn)
            })
            .await??;

        assert_eq!(audit_count, 3);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_plan_change_audit_trail() -> Result<(), AppError> {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();

        // Perform upgrade
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let audit_service = PaymentAuditService::new();

        conn.interact(move |conn| {
            audit_service.log_plan_change(
                conn,
                user_id.into(),
                AuditEventType::PlanUpgraded,
                "basic",
                "premium",
                Some("sub_audit_test"),
            )
        })
        .await??;

        // Verify audit log structure
        let audit_logs: Vec<(String, String, String)> = conn
            .interact(move |conn| {
                use diesel::prelude::*;
                payment_audit_logs::table
                    .select((
                        payment_audit_logs::event_type,
                        payment_audit_logs::event_category,
                        payment_audit_logs::user_id_hash,
                    ))
                    .filter(payment_audit_logs::event_type.eq("plan_upgraded"))
                    .load::<(String, String, String)>(conn)
            })
            .await??;

        assert_eq!(audit_logs.len(), 1);
        let (event_type, category, user_hash) = &audit_logs[0];
        assert_eq!(event_type, "plan_upgraded");
        assert_eq!(category, "subscription");
        assert!(!user_hash.is_empty()); // User ID is hashed

        Ok(())
    }
}
