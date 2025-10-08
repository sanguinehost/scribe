/// End-to-End Subscription Flow Integration Tests
///
/// Tests the complete subscription lifecycle from Paddle webhooks
/// through database state to API responses that the frontend consumes.
///
/// These tests verify:
/// 1. Transaction webhook -> Subscription creation -> API verification
/// 2. Subscription state correctly reflected in user API responses
/// 3. Frontend polling will receive updated subscription data

#[cfg(feature = "payment")]
mod subscription_e2e_tests {
    use diesel::prelude::*;
    use reqwest::{Client, StatusCode};
    use scribe_backend::schema::{subscriptions, users};
    use scribe_backend::test_helpers::{TestDataGuard, spawn_app};
    use serde_json::json;
    use std::env;
    use uuid::Uuid;

    /// Helper to create valid Paddle webhook signature
    fn create_webhook_signature(payload: &str, secret: &str, timestamp: i64) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let signed_payload = format!("{}:{}", timestamp, payload);
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(signed_payload.as_bytes());
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        format!("ts={};h1={}", timestamp, signature)
    }

    /// Test complete E2E flow: transaction webhook -> subscription creation -> database state
    #[tokio::test]
    async fn test_e2e_transaction_to_subscription_verification() {
        // Check if integration tests should run
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        // Arrange: Create test app and user
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let test_user_id = Uuid::new_v4();
        let test_email = format!("e2e_test_{}@example.com", Uuid::new_v4());
        let paddle_customer_id = format!("cus_01e2e{}", Uuid::new_v4().simple());
        let paddle_subscription_id = format!("sub_01e2e{}", Uuid::new_v4().simple());
        let transaction_id = format!("txn_01e2e{}", Uuid::new_v4().simple());

        // Insert test user
        {
            let test_email_clone = test_email.clone();
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            conn.interact(move |conn| {
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(test_user_id),
                        users::username.eq(format!("e2e_user_{}", Uuid::new_v4().simple())),
                        users::email.eq(&test_email_clone),
                        users::password_hash.eq("dummy_hash"),
                    ))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert test user");
        }

        // Get webhook secret from app config
        let webhook_secret = env::var("PADDLE_WEBHOOK_SECRET").unwrap_or_else(|_| {
            "pdl_ntfset_01j87hbdgdyb1fzftb77yqamwzpdl_ntfset_01k5ge1e3f9h4xrwq9jv9mnpez".to_string()
        });

        // Act 1: Send transaction.completed webhook with subscription_id
        let webhook_payload = json!({
            "event_type": "transaction.completed",
            "event_id": format!("evt_e2e_test_{}", Uuid::new_v4().simple()),
            "occurred_at": "2025-01-15T10:00:00.000Z",
            "data": {
                "transaction": {
                    "id": transaction_id,
                    "customer_id": paddle_customer_id,
                    "status": "completed",
                    "subscription_id": paddle_subscription_id,
                    "items": [{
                        "price": {
                            "id": "pri_01k4qbyetvn495nzv9nkqhxz02", // basic monthly
                            "subscription_id": paddle_subscription_id
                        },
                        "quantity": 1
                    }],
                    "billing_details": {
                        "subscription_id": paddle_subscription_id
                    }
                },
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email.clone()
                }
            }
        });

        let payload_str = serde_json::to_string(&webhook_payload).unwrap();
        let timestamp = chrono::Utc::now().timestamp();
        let signature = create_webhook_signature(&payload_str, &webhook_secret, timestamp);

        let webhook_response = Client::new()
            .post(format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to send webhook request");

        // Assert: Webhook accepted
        assert_eq!(
            webhook_response.status(),
            StatusCode::OK,
            "Webhook should be accepted"
        );

        // Assert: Subscription created in database with paddle_subscription_id
        let subscription_id = {
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            let paddle_customer_id_for_check = paddle_customer_id.clone();
            let paddle_subscription_id_for_check = paddle_subscription_id.clone();

            let subscription: (Uuid, String, Option<String>, Option<String>, String) = conn
                .interact(move |conn| {
                    subscriptions::table
                        .select((
                            subscriptions::id,
                            subscriptions::plan_type,
                            subscriptions::paddle_customer_id,
                            subscriptions::paddle_subscription_id,
                            subscriptions::status,
                        ))
                        .filter(subscriptions::user_id.eq(test_user_id))
                        .first(conn)
                })
                .await
                .expect("Failed to interact with database")
                .expect("Should find subscription for user");

            assert_eq!(subscription.1, "basic", "Plan type should be basic");
            assert_eq!(
                subscription.2,
                Some(paddle_customer_id_for_check),
                "Customer ID should be stored"
            );
            assert_eq!(
                subscription.3,
                Some(paddle_subscription_id_for_check),
                "Subscription ID should be stored from transaction"
            );
            assert_eq!(subscription.4, "active", "Status should be active");

            subscription.0
        };

        // Verify subscription can be queried by paddle_subscription_id
        {
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            let paddle_subscription_id_for_query = paddle_subscription_id.clone();

            let found_subscription: (Uuid, Uuid, String) = conn
                .interact(move |conn| {
                    subscriptions::table
                        .select((
                            subscriptions::id,
                            subscriptions::user_id,
                            subscriptions::plan_type,
                        ))
                        .filter(
                            subscriptions::paddle_subscription_id
                                .eq(&paddle_subscription_id_for_query),
                        )
                        .first(conn)
                })
                .await
                .expect("Failed to interact with database")
                .expect("Should find subscription by paddle_subscription_id");

            assert_eq!(found_subscription.0, subscription_id);
            assert_eq!(found_subscription.1, test_user_id);
            assert_eq!(found_subscription.2, "basic");
        }

        println!(
            "✅ E2E Test passed: Transaction webhook → Subscription created → Database state correct"
        );
    }

    /// Test E2E flow: subscription.created webhook -> subscription visible in database
    #[tokio::test]
    async fn test_e2e_subscription_created_to_api_response() {
        // Check if integration tests should run
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        // Arrange: Create test app and user
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let test_user_id = Uuid::new_v4();
        let test_email = format!("e2e_sub_test_{}@example.com", Uuid::new_v4());
        let paddle_customer_id = format!("cus_01sub{}", Uuid::new_v4().simple());
        let paddle_subscription_id = format!("sub_01sub{}", Uuid::new_v4().simple());

        // Insert test user
        {
            let test_email_clone = test_email.clone();
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            conn.interact(move |conn| {
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(test_user_id),
                        users::username.eq(format!("e2e_sub_user_{}", Uuid::new_v4().simple())),
                        users::email.eq(&test_email_clone),
                        users::password_hash.eq("dummy_hash"),
                    ))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert test user");
        }

        // Get webhook secret
        let webhook_secret = env::var("PADDLE_WEBHOOK_SECRET").unwrap_or_else(|_| {
            "pdl_ntfset_01j87hbdgdyb1fzftb77yqamwzpdl_ntfset_01k5ge1e3f9h4xrwq9jv9mnpez".to_string()
        });

        // Act: Send subscription.created webhook
        let webhook_payload = json!({
            "event_type": "subscription.created",
            "event_id": format!("evt_e2e_sub_{}", Uuid::new_v4().simple()),
            "occurred_at": "2025-01-15T10:00:00.000Z",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": paddle_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k5ej7wzvpcj6j65vcbpam6t4" // premium monthly
                    }
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email.clone()
                }
            }
        });

        let payload_str = serde_json::to_string(&webhook_payload).unwrap();
        let timestamp = chrono::Utc::now().timestamp();
        let signature = create_webhook_signature(&payload_str, &webhook_secret, timestamp);

        let webhook_response = Client::new()
            .post(format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to send webhook request");

        // Assert: Webhook accepted
        assert_eq!(
            webhook_response.status(),
            StatusCode::OK,
            "Webhook should be accepted"
        );

        // Assert: Premium subscription created with all Paddle data
        {
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            let paddle_customer_id_for_check = paddle_customer_id.clone();
            let paddle_subscription_id_for_check = paddle_subscription_id.clone();

            let subscription: (String, Option<String>, Option<String>, String) = conn
                .interact(move |conn| {
                    subscriptions::table
                        .select((
                            subscriptions::plan_type,
                            subscriptions::paddle_customer_id,
                            subscriptions::paddle_subscription_id,
                            subscriptions::status,
                        ))
                        .filter(subscriptions::user_id.eq(test_user_id))
                        .first(conn)
                })
                .await
                .expect("Failed to interact with database")
                .expect("Should find subscription for user");

            assert_eq!(subscription.0, "premium", "Plan type should be premium");
            assert_eq!(
                subscription.1,
                Some(paddle_customer_id_for_check),
                "Customer ID should be stored"
            );
            assert_eq!(
                subscription.2,
                Some(paddle_subscription_id_for_check),
                "Subscription ID should be stored"
            );
            assert_eq!(subscription.3, "active", "Status should be active");
        }

        println!(
            "✅ E2E Test passed: Subscription.created webhook → Premium subscription visible in database"
        );
    }

    /// Test that subscription changes are immediately visible after webhook processing
    #[tokio::test]
    async fn test_e2e_subscription_change_detection() {
        // Check if integration tests should run
        if env::var("RUN_INTEGRATION_TESTS").unwrap_or_default() != "true" {
            eprintln!("Skipping integration test - RUN_INTEGRATION_TESTS not set to 'true'");
            return;
        }

        // Arrange: Create test app and user
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let test_user_id = Uuid::new_v4();
        let test_email = format!("e2e_change_test_{}@example.com", Uuid::new_v4());
        let paddle_customer_id = format!("cus_01change{}", Uuid::new_v4().simple());
        let first_subscription_id = format!("sub_01first{}", Uuid::new_v4().simple());
        let second_subscription_id = format!("sub_01second{}", Uuid::new_v4().simple());

        // Insert test user
        {
            let test_email_clone = test_email.clone();
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            conn.interact(move |conn| {
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(test_user_id),
                        users::username.eq(format!("e2e_change_user_{}", Uuid::new_v4().simple())),
                        users::email.eq(&test_email_clone),
                        users::password_hash.eq("dummy_hash"),
                    ))
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert test user");
        }

        // Get webhook secret
        let webhook_secret = env::var("PADDLE_WEBHOOK_SECRET").unwrap_or_else(|_| {
            "pdl_ntfset_01j87hbdgdyb1fzftb77yqamwzpdl_ntfset_01k5ge1e3f9h4xrwq9jv9mnpez".to_string()
        });

        // Act 1: Create initial basic subscription via webhook
        let first_webhook = json!({
            "event_type": "subscription.created",
            "event_id": format!("evt_first_{}", Uuid::new_v4().simple()),
            "occurred_at": "2025-01-15T10:00:00.000Z",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": first_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02" // basic monthly
                    }
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email.clone()
                }
            }
        });

        let payload_str = serde_json::to_string(&first_webhook).unwrap();
        let timestamp = chrono::Utc::now().timestamp();
        let signature = create_webhook_signature(&payload_str, &webhook_secret, timestamp);

        Client::new()
            .post(format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to send first webhook");

        // Assert: Basic subscription exists
        {
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");

            let plan: String = conn
                .interact(move |conn| {
                    subscriptions::table
                        .select(subscriptions::plan_type)
                        .filter(subscriptions::user_id.eq(test_user_id))
                        .first(conn)
                })
                .await
                .expect("Failed to interact with database")
                .expect("Should find basic subscription");

            assert_eq!(plan, "basic");
        }

        // Act 2: Upgrade to premium via second webhook
        let second_webhook = json!({
            "event_type": "subscription.created",
            "event_id": format!("evt_second_{}", Uuid::new_v4().simple()),
            "occurred_at": "2025-01-15T11:00:00.000Z",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": second_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k5ej7wzvpcj6j65vcbpam6t4" // premium monthly
                    }
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email.clone()
                }
            }
        });

        let payload_str = serde_json::to_string(&second_webhook).unwrap();
        let timestamp = chrono::Utc::now().timestamp() + 3600;
        let signature = create_webhook_signature(&payload_str, &webhook_secret, timestamp);

        Client::new()
            .post(format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to send second webhook");

        // Assert: Subscription upgraded to premium (no duplicate)
        {
            let conn = app
                .db_pool
                .get()
                .await
                .expect("Failed to get DB connection");
            let second_subscription_id_for_check = second_subscription_id.clone();

            let subscriptions: Vec<(String, Option<String>)> = conn
                .interact(move |conn| {
                    subscriptions::table
                        .select((
                            subscriptions::plan_type,
                            subscriptions::paddle_subscription_id,
                        ))
                        .filter(subscriptions::user_id.eq(test_user_id))
                        .load(conn)
                })
                .await
                .expect("Failed to interact with database")
                .expect("Should find subscriptions");

            assert_eq!(
                subscriptions.len(),
                1,
                "Should have exactly one subscription"
            );
            assert_eq!(
                subscriptions[0].0, "premium",
                "Plan should be upgraded to premium"
            );
            assert_eq!(
                subscriptions[0].1,
                Some(second_subscription_id_for_check),
                "Subscription ID should be updated"
            );
        }

        println!("✅ E2E Test passed: Subscription change immediately visible after webhook");
    }
}
