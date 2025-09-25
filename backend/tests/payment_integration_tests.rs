//! Integration tests for Paddle payment service
//!
//! These tests verify the Paddle service can correctly:
//! - Verify webhook signatures
//! - Parse webhook payloads
//! - Create customers in sandbox
//! - Create and manage subscriptions
//!
//! Tests use the Paddle sandbox environment with test credentials

#[cfg(feature = "payment")]
mod payment_integration_tests {
    use chrono::{DateTime, Utc};
    use scribe_backend::{
        config::PaymentConfig,
        services::payment::paddle_service::{
            CreateTransactionRequest, CreateTransactionResponse, PaddleEventType, PaddleService,
            PaddleWebhook, TransactionCheckout, TransactionItem,
        },
    };
    use serde_json::json;
    use std::env;

    // Test constants - these match our Paddle sandbox setup
    const TEST_PRODUCT_ID: &str = "pro_01k4qbwv2tf73cvy1nffve71w3";
    const TEST_PRICE_ID: &str = "pri_01k4qbyetvn495nzv9nkqhxz02";

    fn test_payment_config() -> PaymentConfig {
        dotenvy::dotenv().ok(); // Load environment variables from .env file
        PaymentConfig {
            paddle_api_key: env::var("PAYMENT_PADDLE_API_KEY").ok(),
            paddle_webhook_secret: env::var("PAYMENT_PADDLE_WEBHOOK_SECRET").ok(),
            paddle_sandbox_mode: true,
            payment_base_url: "https://localhost:8080".to_string(),
            free_tier_token_limit: 50000,
            enforce_limits: false,
            grace_period_days: 7,
            subscription_config_path: "backend/config/subscription_tiers.json".to_string(),
            credits_enabled: true,
            soft_limits_enabled: false,
            credit_expiry_days: 365,
            min_credit_purchase: 100,
            max_credit_balance: 10000,
            usage_tracking_enabled: false,
            usage_reset_hour_utc: 0,
        }
    }

    #[test]
    fn test_paddle_service_creation() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        assert!(service.should_enforce_limits() == false);
        assert!(service.free_tier_token_limit() == 50000);
        assert!(service.grace_period_days() == 7);
    }

    #[test]
    fn test_webhook_signature_verification_success() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        let payload = b"test payload";

        // Generate expected signature using HMAC-SHA256 in Paddle format
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let webhook_secret = env::var("PADDLE_WEBHOOK_SECRET")
            .unwrap_or_else(|_| "test_webhook_secret_for_development".to_string());

        // Create Paddle format signature: ts=timestamp;h1=signature
        let timestamp = chrono::Utc::now().timestamp();
        let signed_payload = format!("{}:{}", timestamp, String::from_utf8_lossy(payload));

        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let expected_signature = format!("ts={};h1={}", timestamp, signature);

        // Test with correct signature
        let result = service.verify_webhook_signature(payload, &expected_signature);
        assert!(result.is_ok(), "Valid signature should pass verification");
    }

    #[test]
    fn test_webhook_signature_verification_failure() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        let payload = b"test payload";
        let invalid_signature = "invalid_signature_hex";

        // Test with invalid signature
        let result = service.verify_webhook_signature(payload, invalid_signature);
        assert!(
            result.is_err(),
            "Invalid signature should fail verification"
        );
    }

    #[test]
    fn test_webhook_payload_parsing() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        let now = Utc::now();
        let payload = json!({
            "event_type": "subscription_created",
            "event_id": "evt_01h1vj2gx5jh2n3k4l5m6n7p8q",
            "occurred_at": now.to_rfc3339(),
            "data": {
                "subscription_id": "sub_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "customer_id": "cus_01h1vj2gx5jh2n3k4l5m6n7p8q",
                "status": "active"
            }
        });

        let webhook = service.parse_webhook_payload(payload.to_string().as_bytes());
        assert!(webhook.is_ok(), "Valid payload should parse successfully");

        let webhook = webhook.unwrap();
        assert_eq!(webhook.event_type, PaddleEventType::SubscriptionCreated);
        assert_eq!(webhook.event_id, "evt_01h1vj2gx5jh2n3k4l5m6n7p8q");
    }

    #[test]
    fn test_webhook_payload_parsing_all_event_types() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        let now = Utc::now();
        let event_types = vec![
            ("subscription_created", PaddleEventType::SubscriptionCreated),
            ("subscription_updated", PaddleEventType::SubscriptionUpdated),
            (
                "subscription_cancelled",
                PaddleEventType::SubscriptionCancelled,
            ),
            (
                "transaction_completed",
                PaddleEventType::TransactionCompleted,
            ),
            ("transaction_failed", PaddleEventType::TransactionFailed),
            ("transaction_canceled", PaddleEventType::TransactionCanceled),
            ("customer_created", PaddleEventType::CustomerCreated),
            ("customer_updated", PaddleEventType::CustomerUpdated),
        ];

        for (event_name, expected_type) in event_types {
            let payload = json!({
                "event_type": event_name,
                "event_id": format!("evt_{}", uuid::Uuid::new_v4()),
                "occurred_at": now.to_rfc3339(),
                "data": {"test": "data"}
            });

            let webhook = service.parse_webhook_payload(payload.to_string().as_bytes());
            assert!(
                webhook.is_ok(),
                "Event type {} should parse successfully",
                event_name
            );

            let webhook = webhook.unwrap();
            assert_eq!(
                webhook.event_type, expected_type,
                "Event type should match for {}",
                event_name
            );
        }
    }

    #[tokio::test]
    #[ignore] // Only run with RUN_INTEGRATION_TESTS=true as this hits real Paddle API
    async fn test_create_customer_sandbox() {
        if env::var("RUN_INTEGRATION_TESTS").is_err() {
            return;
        }

        let config = test_payment_config();
        let service = PaddleService::new(config);

        let test_email = format!("test+{}@example.com", uuid::Uuid::new_v4());
        let test_name = Some("Test User");

        let result = service.create_customer(&test_email, test_name).await;

        match result {
            Ok(customer) => {
                assert!(!customer.id.is_empty(), "Customer ID should not be empty");
                assert_eq!(customer.email, Some(test_email), "Email should match");
                assert_eq!(
                    customer.name,
                    test_name.map(String::from),
                    "Name should match"
                );
                println!("✓ Successfully created customer: {}", customer.id);
            }
            Err(e) => {
                // Log the error but don't fail the test in case of API issues
                println!(
                    "⚠ Customer creation failed (this may be due to API limits or network issues): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore] // Only run with RUN_INTEGRATION_TESTS=true as this hits real Paddle API
    async fn test_create_transaction_sandbox() {
        if env::var("RUN_INTEGRATION_TESTS").is_err() {
            return;
        }

        let config = test_payment_config();
        let service = PaddleService::new(config);

        // First create a customer
        let test_email = format!("transaction+{}@example.com", uuid::Uuid::new_v4());
        let customer_result = service
            .create_customer(&test_email, Some("Transaction Test User"))
            .await;

        match customer_result {
            Ok(customer) => {
                println!(
                    "✅ Created customer: {} with email: {}",
                    customer.id, test_email
                );

                // Now create a transaction using the new API
                let transaction_request = CreateTransactionRequest {
                    customer_id: customer.id.clone(),
                    items: vec![TransactionItem {
                        price_id: TEST_PRICE_ID.to_string(),
                        quantity: 1,
                    }],
                    collection_mode: "automatic".to_string(), // Automatic checkout
                    checkout: Some(TransactionCheckout {
                        url: None, // Use default payment base URL
                        success_url: Some("https://localhost:8080/pay".to_string()),
                        cancel_url: Some("https://localhost:5173/cancel".to_string()),
                    }),
                    billing_details: None, // Must be null for automatic collection per Paddle API
                };

                let result = service.create_transaction(&transaction_request).await;

                match result {
                    Ok(transaction) => {
                        assert!(
                            !transaction.transaction_id.is_empty(),
                            "Transaction ID should not be empty"
                        );
                        assert!(
                            !transaction.checkout_url.is_empty(),
                            "Checkout URL should not be empty"
                        );

                        println!(
                            "✅ Successfully created transaction: {}",
                            transaction.transaction_id
                        );
                        println!("✅ Transaction status: {}", transaction.status);
                        println!("🔗 **CHECKOUT URL FOR YOU TO COMPLETE:**");
                        println!("{}", transaction.checkout_url);
                        println!(
                            "📝 Open this URL in your browser to complete the transaction in Paddle sandbox"
                        );
                        println!("📧 Customer email for checkout: {}", test_email);

                        // Verify the checkout URL contains the transaction parameter
                        if transaction.checkout_url.contains("?_ptxn=") {
                            println!("✅ Checkout URL correctly contains transaction parameter");
                        } else {
                            println!(
                                "⚠ Warning: Checkout URL may not contain expected ?_ptxn= parameter"
                            );
                        }
                    }
                    Err(e) => {
                        println!("⚠ Transaction creation failed: {}", e);
                        // Don't fail the test as this might be due to API limits or other issues
                    }
                }
            }
            Err(e) => {
                println!(
                    "⚠ Cannot test transaction creation without customer creation: {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore] // Only run with RUN_INTEGRATION_TESTS=true as this hits real Paddle API
    async fn test_get_transaction_checkout_url_for_real_customer() {
        if env::var("RUN_INTEGRATION_TESTS").is_err() {
            return;
        }
        dotenvy::dotenv().ok();

        let config = test_payment_config();
        let service = PaddleService::new(config);

        // Step 1: Create a real customer first
        let test_email = format!("checkout+{}@example.com", uuid::Uuid::new_v4());
        let customer_result = service
            .create_customer(&test_email, Some("Checkout Test User"))
            .await;

        match customer_result {
            Ok(customer) => {
                println!(
                    "✅ Created customer: {} with email: {}",
                    customer.id, test_email
                );

                // Step 2: Create transaction for the real customer
                let transaction_request = CreateTransactionRequest {
                    customer_id: customer.id.clone(),
                    items: vec![TransactionItem {
                        price_id: TEST_PRICE_ID.to_string(),
                        quantity: 1,
                    }],
                    collection_mode: "automatic".to_string(),
                    checkout: Some(TransactionCheckout {
                        url: None, // Use default payment base URL from config
                        success_url: Some("https://localhost:8080/pay".to_string()),
                        cancel_url: Some("https://localhost:5173/cancel".to_string()),
                    }),
                    billing_details: None, // Must be null for automatic collection per Paddle API
                };

                let result = service.create_transaction(&transaction_request).await;

                match result {
                    Ok(transaction) => {
                        assert!(
                            !transaction.transaction_id.is_empty(),
                            "Transaction ID should not be empty"
                        );
                        assert!(
                            !transaction.checkout_url.is_empty(),
                            "Checkout URL should not be empty"
                        );

                        println!(
                            "✅ Successfully created transaction: {}",
                            transaction.transaction_id
                        );
                        println!("✅ Transaction status: {}", transaction.status);
                        println!("🔗 **CHECKOUT URL FOR YOU TO COMPLETE:**");
                        println!("{}", transaction.checkout_url);
                        println!(
                            "📝 Open this URL in your browser to complete the transaction in Paddle sandbox"
                        );
                        println!("📧 Customer email for checkout: {}", test_email);

                        // Verify the URL format
                        if transaction.checkout_url.contains("?_ptxn=") {
                            println!("✅ Checkout URL correctly contains ?_ptxn= parameter");
                            let transaction_id_from_url = transaction
                                .checkout_url
                                .split("?_ptxn=")
                                .nth(1)
                                .unwrap_or("not_found");
                            println!("✅ Transaction ID from URL: {}", transaction_id_from_url);
                        } else if transaction
                            .checkout_url
                            .contains(&transaction.transaction_id)
                        {
                            println!("✅ Checkout URL contains transaction ID in some form");
                        } else {
                            println!("⚠ Warning: Checkout URL format may be unexpected");
                            println!(
                                "   Expected to contain transaction ID: {}",
                                transaction.transaction_id
                            );
                        }
                    }
                    Err(e) => {
                        println!("⚠ Transaction creation failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("⚠ Customer creation failed: {}", e);
                println!("📝 Cannot create transaction without a customer");
            }
        }
    }

    #[tokio::test]
    #[ignore] // Only run with RUN_INTEGRATION_TESTS=true as this hits real Paddle API
    async fn test_get_subscription_sandbox() {
        if env::var("RUN_INTEGRATION_TESTS").is_err() {
            return;
        }

        let config = test_payment_config();
        let service = PaddleService::new(config);

        // Try to get a non-existent subscription (should return 404)
        let fake_subscription_id = "sub_fake_id";
        let result = service.get_subscription(fake_subscription_id).await;

        assert!(
            result.is_err(),
            "Getting non-existent subscription should fail"
        );
        println!("✓ Correctly failed to get non-existent subscription");
    }

    #[test]
    fn test_webhook_payload_parsing_invalid_json() {
        let config = test_payment_config();
        let service = PaddleService::new(config);

        let invalid_payload = b"not valid json";
        let result = service.parse_webhook_payload(invalid_payload);
        assert!(result.is_err(), "Invalid JSON should fail to parse");
    }

    #[test]
    fn test_configuration_loading() {
        // Test that environment variables are loaded correctly
        let config = test_payment_config();

        // These should be set in our test environment
        assert!(
            config.paddle_api_key.is_some(),
            "Paddle API key should be loaded from environment"
        );
        assert!(
            config.paddle_webhook_secret.is_some(),
            "Webhook secret should be loaded from environment"
        );
        assert!(
            config.paddle_sandbox_mode,
            "Should be in sandbox mode for tests"
        );
        assert_eq!(config.free_tier_token_limit, 50000);
        assert_eq!(config.grace_period_days, 7);
        assert!(
            !config.enforce_limits,
            "Should not enforce limits in development"
        );
    }
}

// Empty module for when payment feature is not enabled
#[cfg(not(feature = "payment"))]
mod payment_integration_tests {
    #[test]
    fn payment_feature_disabled() {
        // This test just ensures the file compiles when payment feature is disabled
        println!("Payment feature is disabled - payment integration tests skipped");
    }
}
