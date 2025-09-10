//! Payment system test helpers
//!
//! This module provides utilities for testing the payment system:
//! - Mock Paddle webhook signature generation
//! - Test data creation for subscriptions and plans
//! - Helper functions for payment flow testing

#[cfg(feature = "payment")]
pub mod payment_test_helpers {
    use chrono::{DateTime, Utc};
    use serde_json::{json, Value};

    /// Test constants for Paddle sandbox
    pub const TEST_PRODUCT_ID: &str = "pro_01k4qbwv2tf73cvy1nffve71w3";
    pub const TEST_PRICE_ID: &str = "pri_01k4qbyetvn495nzv9nkqhxz02";
    pub const TEST_WEBHOOK_SECRET: &str = "test_webhook_secret_for_development";

    /// Generate a valid webhook signature for testing
    ///
    /// Uses HMAC-SHA256 to create a signature that matches what Paddle would send
    pub fn create_webhook_signature(payload: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Create a test subscription_created webhook payload
    pub fn create_subscription_created_payload(
        event_id: &str,
        subscription_id: &str,
        customer_id: &str,
    ) -> Value {
        json!({
            "event_type": "subscription_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "subscription": {
                    "id": subscription_id,
                    "customer_id": customer_id,
                    "status": "active",
                    "current_billing_period": {
                        "starts_at": Utc::now().to_rfc3339(),
                        "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                    },
                    "items": [{
                        "price_id": TEST_PRICE_ID,
                        "quantity": 1
                    }]
                },
                "customer": {
                    "id": customer_id,
                    "email": "test@example.com",
                    "name": "Test User"
                }
            }
        })
    }

    /// Create a test subscription_updated webhook payload
    pub fn create_subscription_updated_payload(
        event_id: &str,
        subscription_id: &str,
        customer_id: &str,
        status: &str,
    ) -> Value {
        json!({
            "event_type": "subscription_updated",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "subscription": {
                    "id": subscription_id,
                    "customer_id": customer_id,
                    "status": status,
                    "current_billing_period": {
                        "starts_at": Utc::now().to_rfc3339(),
                        "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                    },
                    "items": [{
                        "price_id": TEST_PRICE_ID,
                        "quantity": 1
                    }]
                }
            }
        })
    }

    /// Create a test subscription_cancelled webhook payload
    pub fn create_subscription_cancelled_payload(
        event_id: &str,
        subscription_id: &str,
        customer_id: &str,
    ) -> Value {
        json!({
            "event_type": "subscription_cancelled",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "subscription": {
                    "id": subscription_id,
                    "customer_id": customer_id,
                    "status": "cancelled",
                    "canceled_at": Utc::now().to_rfc3339(),
                    "current_billing_period": {
                        "starts_at": Utc::now().to_rfc3339(),
                        "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                    }
                }
            }
        })
    }

    /// Create a test transaction_completed webhook payload
    pub fn create_transaction_completed_payload(
        event_id: &str,
        transaction_id: &str,
        customer_id: &str,
        subscription_id: Option<&str>,
    ) -> Value {
        let mut transaction_data = json!({
            "id": transaction_id,
            "customer_id": customer_id,
            "status": "completed",
            "total": "999",
            "currency_code": "USD",
            "billing_details": {
                "payment_method": {
                    "type": "card"
                }
            }
        });

        if let Some(sub_id) = subscription_id {
            transaction_data["subscription_id"] = json!(sub_id);
        }

        json!({
            "event_type": "transaction_completed",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "transaction": transaction_data
            }
        })
    }

    /// Create a test customer_created webhook payload
    pub fn create_customer_created_payload(
        event_id: &str,
        customer_id: &str,
        email: &str,
    ) -> Value {
        json!({
            "event_type": "customer_created",
            "event_id": event_id,
            "occurred_at": Utc::now().to_rfc3339(),
            "data": {
                "customer": {
                    "id": customer_id,
                    "email": email,
                    "name": "Test User",
                    "created_at": Utc::now().to_rfc3339(),
                    "updated_at": Utc::now().to_rfc3339()
                }
            }
        })
    }

    /// Generate unique test IDs for various entities
    pub fn generate_test_ids() -> TestIds {
        TestIds {
            event_id: format!("evt_test_{}", uuid::Uuid::new_v4()),
            customer_id: format!("cus_test_{}", uuid::Uuid::new_v4()),
            subscription_id: format!("sub_test_{}", uuid::Uuid::new_v4()),
            transaction_id: format!("txn_test_{}", uuid::Uuid::new_v4()),
        }
    }

    /// Container for test entity IDs
    pub struct TestIds {
        pub event_id: String,
        pub customer_id: String,
        pub subscription_id: String,
        pub transaction_id: String,
    }

    /// Create a signed webhook request for testing
    ///
    /// Returns (payload_string, signature) ready for HTTP requests
    pub fn create_signed_webhook_request(payload: &Value, secret: &str) -> (String, String) {
        let payload_string = payload.to_string();
        let signature = create_webhook_signature(&payload_string, secret);
        (payload_string, signature)
    }

    /// Mock Paddle API responses for offline testing
    pub mod mock_responses {
        use serde_json::{json, Value};
        use chrono::Utc;

        /// Mock successful customer creation response
        pub fn customer_created_response(customer_id: &str, email: &str) -> Value {
            json!({
                "data": {
                    "id": customer_id,
                    "email": email,
                    "name": "Test User",
                    "created_at": Utc::now().to_rfc3339(),
                    "updated_at": Utc::now().to_rfc3339()
                }
            })
        }

        /// Mock successful subscription creation response
        pub fn subscription_created_response(subscription_id: &str, checkout_url: Option<&str>) -> Value {
            let mut response = json!({
                "data": {
                    "id": subscription_id,
                    "status": "active",
                    "items": [{
                        "price_id": super::TEST_PRICE_ID,
                        "quantity": 1
                    }]
                }
            });

            if let Some(url) = checkout_url {
                response["data"]["checkout"] = json!({
                    "url": url
                });
            }

            response
        }

        /// Mock subscription retrieval response
        pub fn subscription_details_response(subscription_id: &str, customer_id: &str, status: &str) -> Value {
            json!({
                "data": {
                    "id": subscription_id,
                    "customer_id": customer_id,
                    "status": status,
                    "current_billing_period": {
                        "starts_at": Utc::now().to_rfc3339(),
                        "ends_at": (Utc::now() + chrono::Duration::days(30)).to_rfc3339()
                    },
                    "billing_cycle": {
                        "interval": "month",
                        "frequency": 1
                    },
                    "items": [{
                        "price_id": super::TEST_PRICE_ID,
                        "quantity": 1
                    }],
                    "created_at": Utc::now().to_rfc3339(),
                    "updated_at": Utc::now().to_rfc3339()
                }
            })
        }

        /// Mock error response
        pub fn error_response(error_code: &str, detail: &str) -> Value {
            json!({
                "error": {
                    "type": "request_error",
                    "code": error_code,
                    "detail": detail
                }
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_webhook_signature_generation() {
            let payload = "test payload";
            let secret = "test_secret";
            
            let signature1 = create_webhook_signature(payload, secret);
            let signature2 = create_webhook_signature(payload, secret);
            
            assert_eq!(signature1, signature2, "Signature generation should be deterministic");
            assert!(!signature1.is_empty(), "Signature should not be empty");
            assert_eq!(signature1.len(), 64, "HMAC-SHA256 signature should be 64 hex characters");
        }

        #[test]
        fn test_subscription_created_payload() {
            let test_ids = generate_test_ids();
            let payload = create_subscription_created_payload(
                &test_ids.event_id,
                &test_ids.subscription_id,
                &test_ids.customer_id,
            );

            assert_eq!(payload["event_type"], "subscription_created");
            assert_eq!(payload["event_id"], test_ids.event_id);
            assert_eq!(payload["data"]["subscription"]["id"], test_ids.subscription_id);
            assert_eq!(payload["data"]["customer"]["id"], test_ids.customer_id);
        }

        #[test]
        fn test_signed_webhook_request() {
            let test_ids = generate_test_ids();
            let payload = create_subscription_created_payload(
                &test_ids.event_id,
                &test_ids.subscription_id,
                &test_ids.customer_id,
            );

            let (payload_string, signature) = create_signed_webhook_request(&payload, TEST_WEBHOOK_SECRET);
            
            assert!(!payload_string.is_empty());
            assert!(!signature.is_empty());
            assert_eq!(signature.len(), 64, "Signature should be 64 hex characters");

            // Verify signature is valid
            let expected_signature = create_webhook_signature(&payload_string, TEST_WEBHOOK_SECRET);
            assert_eq!(signature, expected_signature);
        }

        #[test]
        fn test_test_ids_generation() {
            let ids1 = generate_test_ids();
            let ids2 = generate_test_ids();

            // All IDs should be unique
            assert_ne!(ids1.event_id, ids2.event_id);
            assert_ne!(ids1.customer_id, ids2.customer_id);
            assert_ne!(ids1.subscription_id, ids2.subscription_id);
            assert_ne!(ids1.transaction_id, ids2.transaction_id);

            // IDs should have correct prefixes
            assert!(ids1.event_id.starts_with("evt_test_"));
            assert!(ids1.customer_id.starts_with("cus_test_"));
            assert!(ids1.subscription_id.starts_with("sub_test_"));
            assert!(ids1.transaction_id.starts_with("txn_test_"));
        }

        #[test]
        fn test_mock_responses() {
            let customer_response = mock_responses::customer_created_response("cus_123", "test@example.com");
            assert_eq!(customer_response["data"]["id"], "cus_123");
            assert_eq!(customer_response["data"]["email"], "test@example.com");

            let subscription_response = mock_responses::subscription_created_response("sub_123", Some("https://checkout.example.com"));
            assert_eq!(subscription_response["data"]["id"], "sub_123");
            assert_eq!(subscription_response["data"]["checkout"]["url"], "https://checkout.example.com");

            let error_response = mock_responses::error_response("invalid_request", "Missing required field");
            assert_eq!(error_response["error"]["code"], "invalid_request");
            assert_eq!(error_response["error"]["detail"], "Missing required field");
        }
    }
}

// Re-export for convenience
#[cfg(feature = "payment")]
pub use payment_test_helpers::*;

// Empty module when payment feature is disabled
#[cfg(not(feature = "payment"))]
pub mod payment_test_helpers {
    // Placeholder module when payment feature is disabled
}