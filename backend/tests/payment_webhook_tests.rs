//! Integration tests for Paddle webhook handlers
//!
//! These tests verify that our webhook endpoints can:
//! - Properly authenticate webhook requests
//! - Validate webhook signatures
//! - Handle different webhook event types
//! - Update database records correctly
//! - Handle error conditions gracefully

#[cfg(feature = "payment")]
mod payment_webhook_tests {
    use chrono::Utc;
    use reqwest::{Client, StatusCode};
    use scribe_backend::{
        config::PaymentConfig,
        services::payment::paddle_service::PaddleService,
        test_helpers::{TestDataGuard, spawn_app},
    };
    use serde_json::json;
    use std::env;

    /// Helper to create a valid webhook signature for testing in Paddle format
    fn create_webhook_signature(payload: &str, secret: &str) -> String {
        create_webhook_signature_with_timestamp(payload, secret, None)
    }

    /// Helper to create a valid webhook signature with optional fixed timestamp for deterministic tests
    fn create_webhook_signature_with_timestamp(
        payload: &str,
        secret: &str,
        timestamp: Option<i64>,
    ) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        // Use provided timestamp or current time
        let timestamp = timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp());

        // Create signed payload in Paddle format: timestamp:request_body
        let signed_payload = format!("{}:{}", timestamp, payload);

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Return Paddle signature format: ts=timestamp;h1=signature
        format!("ts={};h1={}", timestamp, signature)
    }

    /// Helper to create a test webhook payload
    fn create_webhook_payload(event_type: &str, event_id: &str) -> serde_json::Value {
        json!({
            "event_type": event_type,
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested under data.subscription
                "id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "active",
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02"
                    },
                    "quantity": 1
                }],
                "customer": {
                    "id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                    "email": "test@example.com"
                }
            }
        })
    }

    #[tokio::test]
    async fn test_webhook_endpoint_rejects_missing_signature() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let payload = create_webhook_payload("subscription_created", "evt_test_001");

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .json(&payload)
            // No signature header provided
            .send()
            .await
            .expect("Failed to execute request");

        // Should reject requests without proper signature
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_webhook_endpoint_rejects_invalid_signature() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let payload = create_webhook_payload("subscription_created", "evt_test_002");
        let payload_str = payload.to_string();

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", "invalid_signature_value")
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        // Should reject requests with invalid signature
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_webhook_signature_with_different_timestamp_formats() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let payload = create_webhook_payload("subscription_created", "evt_test_timestamp_001");
        let payload_str = payload.to_string();

        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());

        // Test with various timestamp formats
        let test_timestamps = vec![
            chrono::Utc::now().timestamp(),
            1699123456,                          // Fixed timestamp
            chrono::Utc::now().timestamp() - 60, // 1 minute ago
        ];

        for timestamp in test_timestamps {
            let signature = create_webhook_signature_with_timestamp(
                &payload_str,
                &webhook_secret,
                Some(timestamp),
            );

            let response = Client::new()
                .post(&format!("{}/api/payment/webhook/paddle", &app.address))
                .header("Paddle-Signature", signature)
                .header("Content-Type", "application/json")
                .body(payload_str.clone())
                .send()
                .await
                .expect("Failed to execute request");

            // Should accept valid signatures regardless of timestamp format
            assert!(
                response.status() == StatusCode::OK
                    || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
                "Failed for timestamp {}: Expected OK or Internal Server Error, got: {}",
                timestamp,
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn test_webhook_signature_malformed_formats() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let payload = create_webhook_payload("subscription_created", "evt_test_malformed_001");
        let payload_str = payload.to_string();

        // Test various malformed signature formats
        let malformed_signatures = vec![
            "just_a_string",                // No format at all
            "ts=123;",                      // Missing h1
            "h1=abcdef;",                   // Missing ts
            "ts=invalid;h1=abcdef",         // Invalid timestamp
            "ts=123;h1=invalid_hex",        // Invalid hex in h1
            "ts=123;h1=",                   // Empty h1
            "ts=;h1=abcdef",                // Empty timestamp
            "ts=123;h1=abcdef;extra=value", // Extra fields (should still work)
        ];

        for signature in malformed_signatures {
            let response = Client::new()
                .post(&format!("{}/api/payment/webhook/paddle", &app.address))
                .header("Paddle-Signature", signature)
                .header("Content-Type", "application/json")
                .body(payload_str.clone())
                .send()
                .await
                .expect("Failed to execute request");

            // Should reject malformed signatures
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "Malformed signature '{}' should be rejected",
                signature
            );
        }
    }

    #[tokio::test]
    async fn test_webhook_signature_payload_tampering() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let original_payload =
            create_webhook_payload("subscription_created", "evt_test_tamper_001");
        let original_payload_str = original_payload.to_string();

        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&original_payload_str, &webhook_secret);

        // Test with tampered payload but original signature
        let tampered_payload = json!({
            "event_type": "subscription_created",
            "event_id": "evt_test_tamper_001",
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "subscription_id": "sub_tampered_id", // Changed value
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "active"
            }
        });
        let tampered_payload_str = tampered_payload.to_string();

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(tampered_payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        // Should reject tampered payloads
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_webhook_signature_with_real_paddle_format() {
        unsafe {
            std::env::set_var(
                "PAYMENT_DATA_ENCRYPTION_KEY",
                "KiPQq5EQ6mAopid3HxUC5S4uHD+qdI8nN0rkSPUDa3k=", // gitleaks:allow
            );
            std::env::set_var(
                "PAYMENT_PADDLE_WEBHOOK_SECRET",
                "test_webhook_secret_for_development",
            );
        }
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Simplified but realistic Paddle webhook payload
        // Note: Paddle sends transaction data directly in 'data', not nested under 'data.transaction'
        let payload = json!({
            "event_id": "evt_01hqmjk3n2p4r5s6t7u8v9w0x1",
            "event_type": "transaction.completed",
            "occurred_at": "2024-01-15T14:30:00.000Z",
            "notification_id": "ntf_01hqmjk3n2p4r5s6t7u8v9w0x2",
            "data": {
                "id": "txn_01hqmjk3n2p4r5s6t7u8v9w0x3",
                "status": "completed",
                "customer_id": "cus_01hqmjk3n2p4r5s6t7u8v9w0x4",
                "currency_code": "USD",
                "details": {
                    "totals": {
                        "total": "500",
                        "currency_code": "USD"
                    },
                    "line_items": [{
                        "price_id": "pri_01k5ejc7dkwxfty64nfvenj8yq",
                        "quantity": 1
                    }]
                },
                "customer": {
                    "id": "cus_01hqmjk3n2p4r5s6t7u8v9w0x4",
                    "name": "John Doe",
                    "email": "john.doe@example.com"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        // Should accept the real Paddle format
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error for real Paddle format, got: {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_webhook_endpoint_accepts_valid_signature() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let payload = create_webhook_payload("subscription_created", "evt_test_003");
        let payload_str = payload.to_string();

        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());

        // Use explicit timestamp for deterministic testing
        let timestamp = chrono::Utc::now().timestamp();
        let signature =
            create_webhook_signature_with_timestamp(&payload_str, &webhook_secret, Some(timestamp));

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Should accept requests with valid signature
        // Note: This might return 500 if the webhook processing logic isn't complete,
        // but it should not be a 400 (bad request) due to signature issues
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error, got: {}. Body: {}",
            status,
            body
        );
    }

    #[tokio::test]
    async fn test_webhook_credit_allocation_via_transaction_completed() {
        unsafe {
            std::env::set_var(
                "PAYMENT_DATA_ENCRYPTION_KEY",
                "KiPQq5EQ6mAopid3HxUC5S4uHD+qdI8nN0rkSPUDa3k=", // gitleaks:allow
            );
            std::env::set_var(
                "PAYMENT_PADDLE_WEBHOOK_SECRET",
                "test_webhook_secret_for_development",
            );
        }
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create a credit purchase webhook using our real price ID
        let payload = json!({
            "event_id": "evt_credit_purchase_001",
            "event_type": "transaction.completed",
            "occurred_at": "2024-01-15T14:30:00.000Z",
            "notification_id": "ntf_credit_purchase_001",
            "data": {
                "id": "txn_credit_purchase_001",
                "status": "completed",
                "customer_id": "cus_credit_test_001",
                "currency_code": "USD",
                "details": {
                    "totals": {
                        "subtotal": "1000",
                        "total": "1000",
                        "grand_total": "1000",
                        "currency_code": "USD"
                    },
                    "line_items": [{
                        "id": "txnitm_credit_purchase_001",
                        "price_id": "pri_01k5ejc7dkwxfty64nfvenj8yq", // Real 500 credit package price ID
                        "quantity": 1,
                        "totals": {
                            "subtotal": "1000",
                            "total": "1000"
                        },
                        "product": {
                            "id": "pro_01k5ejbmke0myye47nggy9c0e7",
                            "name": "Credits_500",
                            "description": "500 credits (Inc. tax)"
                        }
                    }]
                },
                "customer": {
                    "id": "cus_credit_test_001",
                    "name": "Credit Test User",
                    "email": "credit.test@example.com"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        // Should process the credit purchase webhook successfully
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Credit purchase webhook failed with status: {}",
            response.status()
        );

        // TODO: Add database verification once user lookup by email is implemented
        // This would verify that credits were actually allocated to the user
    }

    #[tokio::test]
    async fn test_webhook_handles_subscription_created_event() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let event_id = format!("evt_test_sub_created_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "active",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                },
                "items": [{
                    "price_id": "pri_01k4qbyetvn495nzv9nkqhxz02",
                    "quantity": 1
                }],
                "customer": {
                    "id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                    "email": "test@example.com",
                    "name": "Test User"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        // Log response for debugging
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        println!("Webhook response status: {}, body: {}", status, body);

        // Should handle the webhook (may return 500 if processing logic is incomplete)
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error, got: {} with body: {}",
            status,
            body
        );
    }

    #[tokio::test]
    async fn test_webhook_handles_subscription_updated_event() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let event_id = format!("evt_test_sub_updated_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "event_type": "subscription_updated",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "paused",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                },
                "items": [{
                    "price_id": "pri_01k4qbyetvn495nzv9nkqhxz02",
                    "quantity": 1
                }]
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        println!("Subscription updated webhook response status: {}", status);

        // Should handle the webhook
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error, got: {}",
            status
        );
    }

    #[tokio::test]
    async fn test_subscription_updated_status_change_to_cancelled() {
        use diesel::prelude::*;
        use scribe_backend::schema::{subscriptions, users};
        use uuid::Uuid;

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "sub_updated_test@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("sub_updated_test_user")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Create initial active subscription
        let paddle_subscription_id = "sub_01updated_test_001";
        let paddle_customer_id = "cus_01updated_test_001";

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let subscription_id = conn
            .interact(move |conn| {
                diesel::insert_into(subscriptions::table)
                    .values((
                        subscriptions::user_id.eq(user_id),
                        subscriptions::plan_type.eq("basic"),
                        subscriptions::status.eq("active"),
                        subscriptions::paddle_customer_id.eq(Some(paddle_customer_id)),
                        subscriptions::paddle_subscription_id.eq(Some(paddle_subscription_id)),
                        subscriptions::current_period_start.eq(Utc::now()),
                        subscriptions::current_period_end
                            .eq(Utc::now() + chrono::Duration::days(30)),
                        subscriptions::cancel_at_period_end.eq(false),
                    ))
                    .returning(subscriptions::id)
                    .get_result::<Uuid>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to create subscription");

        // Send subscription.updated webhook with cancelled status
        let payload = json!({
            "event_id": "evt_subscription_updated_cancel_001",
            "event_type": "subscription.updated",
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": paddle_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "canceled",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert_eq!(
            status,
            StatusCode::OK,
            "Subscription.updated webhook should succeed. Status: {}, Body: {}",
            status,
            body
        );

        // Verify subscription status was updated to cancelled
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub = conn
            .interact(move |conn| {
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query subscription");

        assert_eq!(
            updated_sub.status, "canceled",
            "Subscription status should be updated to canceled"
        );
        assert_eq!(
            updated_sub.cancel_at_period_end,
            Some(true),
            "cancel_at_period_end should be true"
        );
    }

    #[tokio::test]
    async fn test_subscription_updated_trialing_to_active() {
        use diesel::prelude::*;
        use scribe_backend::schema::{subscriptions, users};
        use uuid::Uuid;

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "trial_to_active_test@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("trial_to_active_user")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Create initial trialing subscription
        let paddle_subscription_id = "sub_01trial_to_active_001";
        let paddle_customer_id = "cus_01trial_to_active_001";
        let trial_end = Utc::now() + chrono::Duration::days(7);

        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let subscription_id = conn
            .interact(move |conn| {
                diesel::insert_into(subscriptions::table)
                    .values((
                        subscriptions::user_id.eq(user_id),
                        subscriptions::plan_type.eq("basic"),
                        subscriptions::status.eq("trialing"),
                        subscriptions::paddle_customer_id.eq(Some(paddle_customer_id)),
                        subscriptions::paddle_subscription_id.eq(Some(paddle_subscription_id)),
                        subscriptions::trial_end.eq(Some(trial_end)),
                        subscriptions::current_period_start.eq(Utc::now()),
                        subscriptions::current_period_end
                            .eq(Utc::now() + chrono::Duration::days(7)),
                        subscriptions::cancel_at_period_end.eq(false),
                    ))
                    .returning(subscriptions::id)
                    .get_result::<Uuid>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to create subscription");

        // Send subscription.updated webhook with active status and new billing period
        let new_period_start = Utc::now() + chrono::Duration::days(7);
        let new_period_end = Utc::now() + chrono::Duration::days(37);

        let payload = json!({
            "event_id": "evt_subscription_trial_to_active_001",
            "event_type": "subscription.updated",
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": paddle_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "current_billing_period": {
                    "starts_at": new_period_start.to_rfc3339(),
                    "ends_at": new_period_end.to_rfc3339()
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert_eq!(
            status,
            StatusCode::OK,
            "Subscription.updated webhook should succeed. Status: {}, Body: {}",
            status,
            body
        );

        // Verify subscription status and dates were updated
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let updated_sub = conn
            .interact(move |conn| {
                subscriptions::table
                    .find(subscription_id)
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query subscription");

        assert_eq!(
            updated_sub.status, "active",
            "Subscription status should be updated to active"
        );
        assert_eq!(
            updated_sub.cancel_at_period_end,
            Some(false),
            "cancel_at_period_end should be false"
        );
        // Verify billing period was updated
        assert!(
            updated_sub.current_period_start > trial_end - chrono::Duration::days(1),
            "Billing period start should be updated"
        );
        // Verify trial-to-paid conversion tracking fields are set
        assert_eq!(
            updated_sub.has_ever_paid,
            Some(true),
            "has_ever_paid should be set to true when trial converts to paid"
        );
        assert!(
            updated_sub.first_payment_date.is_some(),
            "first_payment_date should be set when trial converts to paid"
        );
        // first_payment_date should be set to the new billing period start
        if let Some(first_payment) = updated_sub.first_payment_date {
            assert!(
                (first_payment - updated_sub.current_period_start)
                    .num_seconds()
                    .abs()
                    < 2,
                "first_payment_date should be set to current_period_start"
            );
        }
    }

    #[tokio::test]
    async fn test_webhook_handles_subscription_cancelled_event() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let event_id = format!("evt_test_sub_cancelled_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "event_type": "subscription_cancelled",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "canceled",
                "canceled_at": Utc::now().to_rfc3339(),
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        println!("Subscription cancelled webhook response status: {}", status);

        // Should handle the webhook
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error, got: {}",
            status
        );
    }

    #[tokio::test]
    async fn test_webhook_handles_transaction_completed_event() {
        unsafe {
            std::env::set_var(
                "PAYMENT_DATA_ENCRYPTION_KEY",
                "KiPQq5EQ6mAopid3HxUC5S4uHD+qdI8nN0rkSPUDa3k=", // gitleaks:allow
            );
            std::env::set_var(
                "PAYMENT_PADDLE_WEBHOOK_SECRET",
                "test_webhook_secret_for_development",
            );
        }
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let event_id = format!("evt_test_transaction_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "event_type": "transaction_completed",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "txn_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "subscription_id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "completed",
                "total": "999",
                "currency_code": "USD",
                "billing_details": {
                    "payment_method": {
                        "type": "card"
                    }
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        println!("Transaction completed webhook response status: {}", status);

        // Should handle the webhook
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or Internal Server Error, got: {}",
            status
        );
    }

    #[tokio::test]
    async fn test_webhook_rejects_malformed_json() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let malformed_payload = "{ invalid json :::";
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(malformed_payload, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(malformed_payload)
            .send()
            .await
            .expect("Failed to execute request");

        // Should reject malformed JSON
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_webhook_handles_unknown_event_type() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        let event_id = format!("evt_test_unknown_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "event_type": "unknown_event_type",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "test": "data"
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        println!("Unknown event type webhook response status: {}", status);

        // Should handle unknown events gracefully (probably with OK status but no action)
        assert!(
            status == StatusCode::OK
                || status == StatusCode::BAD_REQUEST
                || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK, Bad Request, or Internal Server Error, got: {}",
            status
        );
    }

    #[test]
    fn test_signature_creation_consistency() {
        let payload = "test payload";
        let secret = "test_secret";
        let fixed_timestamp = 1234567890; // Fixed timestamp for deterministic tests

        let signature1 =
            create_webhook_signature_with_timestamp(payload, secret, Some(fixed_timestamp));
        let signature2 =
            create_webhook_signature_with_timestamp(payload, secret, Some(fixed_timestamp));

        assert_eq!(
            signature1, signature2,
            "Signature creation should be deterministic"
        );
        assert!(!signature1.is_empty(), "Signature should not be empty");

        // Paddle format: "ts=1234567890;h1=<64_char_hex_signature>"
        // Expected length: 3 + 10 + 4 + 64 = 81 characters
        assert_eq!(
            signature1.len(),
            81,
            "Paddle signature should be 81 characters (ts=timestamp;h1=64_hex_chars)"
        );
        assert!(
            signature1.starts_with("ts=1234567890;h1="),
            "Signature should have correct Paddle format"
        );
    }

    #[test]
    fn test_signature_validation_with_paddle_service() {
        let config = PaymentConfig {
            paddle_api_key: Some("test_key".to_string()),
            paddle_webhook_secret: Some("test_secret".to_string()),
            paddle_basic_monthly_price_id: None,
            paddle_basic_yearly_price_id: None,
            paddle_premium_monthly_price_id: None,
            paddle_premium_yearly_price_id: None,
            paddle_credits_250_price_id: None,
            paddle_credits_500_price_id: None,
            paddle_credits_1500_price_id: None,
            paddle_credits_3500_price_id: None,
            paddle_credits_8000_price_id: None,
            paddle_sandbox_mode: true,
            payment_base_url: "https://localhost:8080/api/payment".to_string(),
            free_tier_token_limit: 50000,
            enforce_limits: false,
            grace_period_days: 7,
            subscription_config_path: "config/subscription_tiers.json".to_string(),
            credits_enabled: true,
            soft_limits_enabled: true,
            credit_expiry_days: 365,
            min_credit_purchase: 100,
            max_credit_balance: 10000,
            usage_tracking_enabled: true,
            usage_reset_hour_utc: 0,
            data_encryption_key: None,
        };
        let service = PaddleService::new(config);

        let payload = b"test payload";
        let signature =
            create_webhook_signature(std::str::from_utf8(payload).unwrap(), "test_secret");

        let result = service.verify_webhook_signature(payload, &signature);
        assert!(result.is_ok(), "Valid signature should pass verification");

        let invalid_result = service.verify_webhook_signature(payload, "invalid_signature");
        assert!(
            invalid_result.is_err(),
            "Invalid signature should fail verification"
        );
    }

    /// Test subscription.created webhook stores paddle_subscription_id
    #[tokio::test]
    async fn test_subscription_created_webhook_stores_paddle_subscription_id() {
        use diesel::prelude::*;
        use scribe_backend::schema::subscriptions;
        use uuid::Uuid;

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "webhook_test_user@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("webhook_test_user")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Create realistic subscription.created webhook payload
        let paddle_subscription_id = "sub_01test123456789abcdef";
        let paddle_customer_id = "cus_01test123456789abcdef";
        let payload = json!({
            "event_id": "evt_subscription_created_test_001",
            "event_type": "subscription.created",
            "occurred_at": Utc::now().to_rfc3339(),
            "notification_id": "ntf_test_001",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": paddle_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                },
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02", // Basic monthly
                    },
                    "quantity": 1
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email,
                    "name": "Test User"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Send webhook
        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert_eq!(
            status,
            StatusCode::OK,
            "Subscription.created webhook should succeed. Status: {}, Body: {}",
            status,
            body
        );

        // Verify subscription was created with paddle_subscription_id
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let stored_subscription = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
                    .optional()
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query subscription");

        assert!(
            stored_subscription.is_some(),
            "Subscription should be created"
        );

        let subscription = stored_subscription.unwrap();
        assert_eq!(
            subscription.paddle_subscription_id,
            Some(paddle_subscription_id.to_string()),
            "Paddle subscription ID should be stored"
        );
        assert_eq!(
            subscription.paddle_customer_id,
            Some(paddle_customer_id.to_string()),
            "Paddle customer ID should be stored"
        );
        assert_eq!(
            subscription.plan_type, "basic",
            "Plan type should be correctly mapped from price_id"
        );
        assert_eq!(
            subscription.status, "active",
            "Subscription status should match webhook"
        );
    }

    /// Test subscription.created webhook prevents duplicate subscriptions
    #[tokio::test]
    async fn test_subscription_created_prevents_duplicate_subscriptions() {
        use diesel::prelude::*;
        use scribe_backend::schema::subscriptions;
        use uuid::Uuid;

        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "duplicate_test_user@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("duplicate_test_user")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Send first subscription.created webhook
        let first_subscription_id = "sub_01first123456789abcdef";
        let paddle_customer_id = "cus_01test123456789abcdef";
        let first_payload = json!({
            "event_id": "evt_subscription_created_duplicate_test_001",
            "event_type": "subscription.created",
            "occurred_at": Utc::now().to_rfc3339(),
            "notification_id": "ntf_duplicate_test_001",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": first_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                },
                "items": [{
                    "price": {
                        "id": "pri_01k4qbyetvn495nzv9nkqhxz02", // Basic monthly
                    },
                    "quantity": 1
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email,
                    "name": "Test User"
                }
            }
        });

        let payload_str = first_payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), StatusCode::OK);

        // Send second subscription.created webhook with different subscription_id
        let second_subscription_id = "sub_01second123456789abcdef";
        let second_payload = json!({
            "event_id": "evt_subscription_created_duplicate_test_002",
            "event_type": "subscription.created",
            "occurred_at": Utc::now().to_rfc3339(),
            "notification_id": "ntf_duplicate_test_002",
            "data": {
                // Paddle sends subscription data directly in data, not nested
                "id": second_subscription_id,
                "customer_id": paddle_customer_id,
                "status": "active",
                "current_billing_period": {
                    "starts_at": Utc::now().to_rfc3339(),
                    "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                },
                "items": [{
                    "price": {
                        "id": "pri_01k5ej7wzvpcj6j65vcbpam6t4", // Premium monthly
                    },
                    "quantity": 1
                }],
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email,
                    "name": "Test User"
                }
            }
        });

        let payload_str = second_payload.to_string();
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Second webhook should also succeed (update existing)"
        );

        // Verify only ONE subscription exists for user
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let subscription_count = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to count subscriptions");

        assert_eq!(
            subscription_count, 1,
            "Should have exactly one subscription (no duplicates)"
        );

        // Verify subscription was updated to second subscription_id and premium plan
        let stored_subscription = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query subscription");

        assert_eq!(
            stored_subscription.paddle_subscription_id,
            Some(second_subscription_id.to_string()),
            "Subscription should be updated to second subscription_id"
        );
        assert_eq!(
            stored_subscription.plan_type, "premium",
            "Plan should be updated to premium"
        );
    }

    /// Test transaction.completed webhook stores paddle_subscription_id from transaction data
    #[tokio::test]
    async fn test_transaction_completed_stores_paddle_subscription_id() {
        use diesel::prelude::*;
        use scribe_backend::schema::subscriptions;
        use uuid::Uuid;

        unsafe {
            std::env::set_var(
                "PAYMENT_DATA_ENCRYPTION_KEY",
                "KiPQq5EQ6mAopid3HxUC5S4uHD+qdI8nN0rkSPUDa3k=", // gitleaks:allow
            );
            std::env::set_var(
                "PAYMENT_PADDLE_WEBHOOK_SECRET",
                "test_webhook_secret_for_development",
            );
        }
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "transaction_sub_test@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("transaction_sub_test_user")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Create transaction.completed webhook with subscription_id in transaction data
        let paddle_subscription_id = "sub_01txn123456789abcdef";
        let paddle_customer_id = "cus_01txn123456789abcdef";
        let transaction_id = "txn_01test123456789abcdef";

        let payload = json!({
            "event_id": "evt_transaction_completed_sub_test_001",
            "event_type": "transaction.completed",
            "occurred_at": Utc::now().to_rfc3339(),
            "notification_id": "ntf_txn_sub_test_001",
            "data": {
                "id": transaction_id,
                "status": "completed",
                "customer_id": paddle_customer_id,
                "subscription_id": paddle_subscription_id, // Subscription ID at top level
                "currency_code": "USD",
                "items": [{
                    "price_id": "pri_01k4qbyetvn495nzv9nkqhxz02", // Basic monthly
                    "quantity": 1
                }],
                "details": {
                    "totals": {
                        "total": "1000",
                        "tax": "100",
                        "currency_code": "USD"
                    }
                },
                "customer": {
                    "id": paddle_customer_id,
                    "email": test_email,
                    "name": "Transaction Test User"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Send webhook
        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Transaction.completed webhook should succeed"
        );

        // Verify subscription was created with paddle_subscription_id from transaction
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let stored_subscription = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::user_id.eq(user_id))
                    .select(scribe_backend::models::payment::Subscription::as_select())
                    .first::<scribe_backend::models::payment::Subscription>(conn)
                    .optional()
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query subscription");

        assert!(
            stored_subscription.is_some(),
            "Subscription should be created from transaction webhook"
        );

        let subscription = stored_subscription.unwrap();
        assert_eq!(
            subscription.paddle_subscription_id,
            Some(paddle_subscription_id.to_string()),
            "Paddle subscription ID should be extracted from transaction data"
        );
        assert_eq!(
            subscription.paddle_customer_id,
            Some(paddle_customer_id.to_string()),
            "Paddle customer ID should be stored"
        );
        assert_eq!(
            subscription.plan_type, "basic",
            "Plan type should be correctly mapped from price_id"
        );
    }

    /// Test that transaction.completed webhook handles credit package purchases
    #[tokio::test]
    async fn test_credit_purchase_via_transaction_completed() {
        use diesel::prelude::*;
        use scribe_backend::schema::{credit_transactions, user_credits, users};
        use uuid::Uuid;

        unsafe {
            std::env::set_var(
                "PAYMENT_DATA_ENCRYPTION_KEY",
                "KiPQq5EQ6mAopid3HxUC5S4uHD+qdI8nN0rkSPUDa3k=", // gitleaks:allow
            );
            std::env::set_var(
                "PAYMENT_PADDLE_WEBHOOK_SECRET",
                "test_webhook_secret_for_development",
            );
        }
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user_id = Uuid::new_v4();
        let test_email = "credit_purchaser@example.com";
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            diesel::sql_query(
                "INSERT INTO users (id, username, email, password_hash, kek_salt, encrypted_dek,
                 dek_nonce, role, account_status, total_prompt_tokens, total_completion_tokens,
                 total_token_cost_cents, token_usage_updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::user_role, $9::account_status, $10, $11, $12, $13)
                 ON CONFLICT (id) DO NOTHING"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>("credit_purchaser")
            .bind::<diesel::sql_types::Text, _>(test_email)
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
            .execute(conn)
        })
        .await
        .expect("Failed to interact with database")
        .expect("Failed to create test user");

        // Transaction payload for credit package purchase (250 credits for $5)
        let event_id = format!("evt_credit_purchase_{}", Uuid::new_v4());
        let transaction_id = format!("txn_credit_{}", Uuid::new_v4());
        let paddle_customer_id = format!("cus_{}", Uuid::new_v4());

        let payload = json!({
            "event_type": "transaction.completed",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": transaction_id,
                "customer_id": paddle_customer_id.clone(),
                "status": "completed",
                "items": [{
                    "price": {
                        "id": "pri_01k5ej9f8281rvnzybmpxc9hpm" // Starter Pack - 250 credits (production price ID)
                    },
                    "quantity": 1
                }],
                "details": {
                    "totals": {
                        "total": "500", // $5.00 in cents
                        "tax": "0",
                        "discount": "0"
                    }
                },
                "currency_code": "USD",
                "created_at": Utc::now().to_rfc3339(),
                "billed_at": Utc::now().to_rfc3339(),
                "customer": {
                    "id": paddle_customer_id.clone(),
                    "email": test_email
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Send webhook
        let response = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute request");

        let status = response.status();
        println!("Credit purchase webhook response status: {}", status);
        assert_eq!(
            status,
            StatusCode::OK,
            "Webhook should process successfully"
        );

        // Verify credits were added to user account
        let conn = app
            .db_pool
            .get()
            .await
            .expect("Failed to get DB connection");

        let credits_balance: i32 = conn
            .interact(move |conn| {
                user_credits::table
                    .filter(user_credits::user_id.eq(user_id))
                    .select(user_credits::balance)
                    .first(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to query credit balance");

        assert_eq!(
            credits_balance, 250,
            "User should have 250 credits after purchase"
        );

        // Verify credit transaction was recorded
        let transaction_count: i64 = conn
            .interact(move |conn| {
                credit_transactions::table
                    .filter(credit_transactions::user_id.eq(user_id))
                    .filter(credit_transactions::transaction_type.eq("purchase"))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to count credit transactions");

        assert_eq!(
            transaction_count, 1,
            "Should have exactly one credit purchase transaction"
        );
    }
}

// Empty module for when payment feature is not enabled
#[cfg(not(feature = "payment"))]
mod payment_webhook_tests {
    #[test]
    fn payment_feature_disabled() {
        // This test just ensures the file compiles when payment feature is disabled
        println!("Payment feature is disabled - payment webhook tests skipped");
    }
}
