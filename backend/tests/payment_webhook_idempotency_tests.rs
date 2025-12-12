#![cfg(feature = "postgres-backend")]
//! Integration tests for Paddle webhook idempotency and replay protection
//!
//! These tests verify that our webhook system properly handles:
//! - Duplicate webhook delivery from Paddle
//! - Concurrent delivery of the same webhook
//! - Replay attacks (malicious re-sending of valid webhooks)
//! - Payload tampering detection
//! - Event ID uniqueness across event types

#[cfg(feature = "payment")]
mod payment_webhook_idempotency_tests {
    use chrono::Utc;
    use diesel::prelude::*;
    use reqwest::{Client, StatusCode};
    use scribe_backend::{
        models::payment::WebhookEvent,
        schema::webhook_events,
        test_helpers::{spawn_app, TestDataGuard},
    };
    use serde_json::json;
    use std::env;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    /// Helper to create a valid webhook signature for testing in Paddle format
    fn create_webhook_signature(payload: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let timestamp = chrono::Utc::now().timestamp();
        let signed_payload = format!("{}:{}", timestamp, payload);

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        format!("ts={};h1={}", timestamp, signature)
    }

    /// Test that sending the same webhook twice results in idempotent handling
    /// First delivery processes normally, second returns success but doesn't reprocess
    #[tokio::test]
    async fn test_duplicate_webhook_delivery_rejected() {
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
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create a subscription.created webhook payload
        let event_id = "evt_duplicate_test_001";
        let payload = json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_duplicate_test_001",
                "status": "active",
                "customer_id": "cus_duplicate_test_001",
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-000000000001"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Send first webhook - should process successfully
        let response1 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature)
            .header("Content-Type", "application/json")
            .body(payload_str.clone())
            .send()
            .await
            .expect("Failed to execute first request");

        assert_eq!(
            response1.status(),
            StatusCode::OK,
            "First webhook should succeed"
        );

        // Verify webhook event was recorded
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let webhook_count: i64 = conn
            .interact(move |conn| {
                webhook_events::table
                    .filter(webhook_events::event_id.eq(event_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count webhooks");

        assert_eq!(
            webhook_count, 1,
            "Should have exactly one webhook event recorded"
        );

        // Send second webhook - identical payload - should be idempotent
        let response2 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute second request");

        assert_eq!(
            response2.status(),
            StatusCode::OK,
            "Second webhook should return idempotent success"
        );

        // Verify still only one webhook event recorded (not two)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let final_webhook_count: i64 = conn
            .interact(move |conn| {
                webhook_events::table
                    .filter(webhook_events::event_id.eq(event_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count webhooks");

        assert_eq!(
            final_webhook_count, 1,
            "Should still have exactly one webhook event (idempotent)"
        );
    }

    /// Test that concurrent delivery of the same webhook is handled safely
    /// Only one should process, others should detect duplicate
    #[tokio::test]
    async fn test_concurrent_webhook_delivery_race_condition() {
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
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let event_id = "evt_concurrent_test_001";
        let payload = json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_concurrent_test_001",
                "status": "active",
                "customer_id": "cus_concurrent_test_001",
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-000000000002"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Create barrier to synchronize 5 concurrent requests
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = vec![];

        // Spawn 5 concurrent tasks sending identical webhook
        for i in 0..5 {
            let app_address = app.address.clone();
            let payload_clone = payload_str.clone();
            let signature_clone = signature.clone();
            let barrier_clone = barrier.clone();

            let handle = tokio::spawn(async move {
                // Wait for all tasks to be ready
                barrier_clone.wait().await;

                // Send webhook simultaneously
                let response = Client::new()
                    .post(&format!("{}/api/payment/webhook/paddle", &app_address))
                    .header("Paddle-Signature", &signature_clone)
                    .header("Content-Type", "application/json")
                    .body(payload_clone)
                    .send()
                    .await
                    .expect(&format!("Failed to execute request {}", i));

                response.status()
            });

            handles.push(handle);
        }

        // Wait for all requests to complete
        let mut statuses = vec![];
        for handle in handles {
            let status = handle.await.expect("Task panicked");
            statuses.push(status);
        }

        // All should return 200 OK (idempotent behavior)
        for status in &statuses {
            assert_eq!(
                *status,
                StatusCode::OK,
                "All concurrent requests should return OK"
            );
        }

        // Verify only ONE webhook event was recorded despite 5 concurrent requests
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let webhook_count: i64 = conn
            .interact(move |conn| {
                webhook_events::table
                    .filter(webhook_events::event_id.eq(event_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count webhooks");

        assert_eq!(
            webhook_count, 1,
            "Should have exactly one webhook event despite concurrent delivery"
        );
    }

    /// Test that replay attacks (re-sending old webhooks) are detected and rejected
    #[tokio::test]
    async fn test_webhook_replay_attack_prevention() {
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
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let event_id = "evt_replay_test_001";
        let payload = json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_replay_test_001",
                "status": "active",
                "customer_id": "cus_replay_test_001",
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-000000000003"
                }
            }
        });

        let payload_str = payload.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature = create_webhook_signature(&payload_str, &webhook_secret);

        // Send original webhook
        let response1 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature)
            .header("Content-Type", "application/json")
            .body(payload_str.clone())
            .send()
            .await
            .expect("Failed to execute first request");

        assert_eq!(response1.status(), StatusCode::OK);

        // Simulate time passing (in real world, this could be hours/days)
        // For test, we just send again immediately

        // Attempt replay attack - re-send same webhook with same signature
        let response2 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send()
            .await
            .expect("Failed to execute second request");

        // Should return OK (idempotent) but not process again
        assert_eq!(
            response2.status(),
            StatusCode::OK,
            "Replay should return idempotent success"
        );

        // Verify only ONE webhook event exists (replay was detected and prevented)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let webhook_count: i64 = conn
            .interact(move |conn| {
                webhook_events::table
                    .filter(webhook_events::event_id.eq(event_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count webhooks");

        assert_eq!(
            webhook_count, 1,
            "Replay attack should be detected and prevented"
        );
    }

    /// Test that payload tampering is detected via hash comparison
    #[tokio::test]
    async fn test_webhook_payload_tampering_after_initial_processing() {
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
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let event_id = "evt_tamper_test_001";

        // Original payload
        let payload1 = json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_tamper_test_001",
                "status": "active",
                "customer_id": "cus_tamper_test_001",
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-000000000004"
                }
            }
        });

        let payload1_str = payload1.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature1 = create_webhook_signature(&payload1_str, &webhook_secret);

        // Send original webhook
        let response1 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature1)
            .header("Content-Type", "application/json")
            .body(payload1_str)
            .send()
            .await
            .expect("Failed to execute first request");

        assert_eq!(response1.status(), StatusCode::OK);

        // Tampered payload - same event_id but modified data
        let payload2 = json!({
            "event_type": "subscription_created",
            "event_id": event_id, // SAME event_id
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_tamper_test_001",
                "status": "active",
                "customer_id": "cus_MALICIOUS_CHANGE", // MODIFIED
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-999999999999" // MODIFIED
                }
            }
        });

        let payload2_str = payload2.to_string();
        let signature2 = create_webhook_signature(&payload2_str, &webhook_secret);

        // Attempt to send tampered webhook (different payload, same event_id)
        let response2 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature2)
            .header("Content-Type", "application/json")
            .body(payload2_str)
            .send()
            .await
            .expect("Failed to execute second request");

        // Should detect payload hash mismatch and reject (400 Bad Request)
        assert_eq!(
            response2.status(),
            StatusCode::BAD_REQUEST,
            "Tampered payload should be rejected with 400"
        );

        let error_body = response2.text().await.expect("Failed to read body");
        assert!(
            error_body.contains("modified payload") || error_body.contains("Duplicate event"),
            "Error should indicate payload tampering: {}",
            error_body
        );
    }

    /// Test that event_id uniqueness is enforced globally (not per-event-type)
    #[tokio::test]
    async fn test_webhook_idempotency_across_event_types() {
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
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let shared_event_id = "evt_shared_id_001";

        // First webhook: subscription_created with this event_id
        let payload1 = json!({
            "event_type": "subscription_created",
            "event_id": shared_event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_shared_001",
                "status": "active",
                "customer_id": "cus_shared_001",
                "custom_data": {
                    "user_id": "00000000-0000-0000-0000-000000000005"
                }
            }
        });

        let payload1_str = payload1.to_string();
        let webhook_secret = env::var("PAYMENT_PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());
        let signature1 = create_webhook_signature(&payload1_str, &webhook_secret);

        let response1 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature1)
            .header("Content-Type", "application/json")
            .body(payload1_str)
            .send()
            .await
            .expect("Failed to execute first request");

        assert_eq!(response1.status(), StatusCode::OK);

        // Second webhook: DIFFERENT event type but SAME event_id
        // In Paddle's system, event_ids are globally unique, but let's verify our system handles this
        let payload2 = json!({
            "event_type": "subscription_updated", // Different type
            "event_id": shared_event_id, // SAME event_id
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "id": "sub_shared_001",
                "status": "active",
                "customer_id": "cus_shared_001"
            }
        });

        let payload2_str = payload2.to_string();
        let signature2 = create_webhook_signature(&payload2_str, &webhook_secret);

        let response2 = Client::new()
            .post(&format!("{}/api/payment/webhook/paddle", &app.address))
            .header("Paddle-Signature", &signature2)
            .header("Content-Type", "application/json")
            .body(payload2_str)
            .send()
            .await
            .expect("Failed to execute second request");

        // Should be rejected as duplicate event_id (idempotent response)
        // In reality, Paddle would never send two different event types with the same event_id,
        // but our system should handle it gracefully
        assert_eq!(
            response2.status(),
            StatusCode::OK,
            "Should return idempotent success even for different event type with same ID"
        );

        // Verify only ONE webhook event recorded (first one wins)
        let conn = app.db_pool.get().await.expect("Failed to get connection");
        let webhook_count: i64 = conn
            .interact(move |conn| {
                webhook_events::table
                    .filter(webhook_events::event_id.eq(shared_event_id))
                    .count()
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to count webhooks");

        assert_eq!(
            webhook_count, 1,
            "Should have exactly one webhook event (event_id is globally unique)"
        );
    }
}

// Empty module for when payment feature is not enabled
#[cfg(not(feature = "payment"))]
mod payment_webhook_idempotency_tests {
    #[test]
    fn payment_feature_disabled() {
        println!("Payment feature is disabled - webhook idempotency tests skipped");
    }
}
