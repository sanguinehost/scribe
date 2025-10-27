//! Payment system test helpers
//!
//! This module provides utilities for testing the payment system:
//! - Mock Paddle webhook signature generation
//! - Test data creation for subscriptions and plans
//! - Helper functions for payment flow testing

#[cfg(feature = "payment")]
pub mod payment_test_helpers {
    use crate::{
        crypto,
        errors::AppError,
        models::{
            character_card::NewCharacter,
            characters::Character,
            credit::{CreditBalance, CreditTransaction},
            users::{AccountStatus, NewUser, User as DbUser, UserDbQuery, UserRole},
        },
        services::payment::CreditService,
        test_helpers::TestApp,
        DbId,
    };
    use chrono::Utc;
    use diesel::{PgConnection, RunQueryDsl, SelectableHelper};
    use reqwest::Client;
    use secrecy::{ExposeSecret, SecretBox, SecretString};
    use serde_json::{json, Value};
    use uuid::Uuid;

    /// Test constants for Paddle sandbox
    pub const TEST_PRODUCT_ID: &str = "pro_01k4qbwv2tf73cvy1nffve71w3";
    pub const TEST_PRICE_ID: &str = "pri_01k4qbyetvn495nzv9nkqhxz02";
    pub const TEST_WEBHOOK_SECRET: &str = "test_webhook_secret_for_development";

    // ============================================================================
    // User and Character Test Helpers
    // ============================================================================

    /// Creates a test user with a character for testing credit flows
    pub fn create_test_user_with_character(
        conn: &mut PgConnection,
    ) -> Result<(DbUser, Character), AppError> {
        use crate::schema::{characters, users};
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let username = format!("testuser_{}", DbId::new());
        let email = format!("test_{}@example.com", DbId::new());
        let password = "test_password_123";

        // Generate password hash synchronously
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::DatabaseQueryError(format!("Password hashing failed: {}", e)))?
            .to_string();

        let kek_salt = crypto::generate_salt().map_err(|e| {
            AppError::DatabaseQueryError(format!("KEK salt generation failed: {}", e))
        })?;

        let plaintext_dek_box: SecretBox<Vec<u8>> = crypto::generate_dek()
            .map_err(|e| AppError::DatabaseQueryError(format!("DEK generation failed: {}", e)))?;

        let kek = crypto::derive_kek(&SecretString::from(password.to_string()), &kek_salt)
            .map_err(|e| AppError::DatabaseQueryError(format!("KEK derivation failed: {}", e)))?;

        // expose_secret() on SecretBox<Vec<u8>> gives &Vec<u8>
        let (encrypted_dek_bytes, dek_nonce_bytes) =
            crypto::encrypt_gcm(plaintext_dek_box.expose_secret(), &kek).map_err(|e| {
                AppError::DatabaseQueryError(format!("DEK encryption failed: {}", e))
            })?;

        // Create test user with all required fields
        let new_user = NewUser {
            username,
            password_hash,
            email,
            kek_salt,
            encrypted_dek: encrypted_dek_bytes,
            dek_nonce: dek_nonce_bytes,
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
            role: UserRole::User,
            account_status: AccountStatus::Active,
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            total_token_cost_cents: 0,
            tokens_last_reset_at: None,
            token_usage_updated_at: chrono::Utc::now(),
        };

        let user_from_db: UserDbQuery = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(UserDbQuery::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        // Convert UserDbQuery to User
        let user = DbUser::from(user_from_db);

        // Create test character using the correct NewCharacter structure

        let now = Utc::now();
        let character_name = "Test Character".to_string();

        let new_character = NewCharacter {
            user_id: user.id,
            name: character_name.clone(),
            description: Some(format!("Test description for {}", character_name).into_bytes()),
            greeting: Some(format!("Hello! I'm a test character.").into_bytes()),
            example_dialogue: Some(format!("User: Hi\nCharacter: Hello there!").into_bytes()),
            visibility: Some("private".to_string()),
            character_version: Some("2.0".to_string()),
            spec: "test_spec_v2.0".to_string(),
            spec_version: "2.0".to_string(),
            persona: Some(format!("Friendly and helpful test character").into_bytes()),
            world_scenario: Some(format!("Testing environment").into_bytes()),
            avatar: None,
            chat: None,
            created_at: Some(now),
            updated_at: Some(now),
            creation_date: Some(now),
            modification_date: Some(now),
            creator_notes_multilingual: None,
            nickname: None,
            personality: None,
            tags: None,
            greeting_nonce: None,
            definition: None,
            default_voice: None,
            extensions: None,
            category: None,
            definition_visibility: None,
            example_dialogue_nonce: None,
            favorite: None,
            first_message_visibility: None,
            migrated_from: None,
            model_prompt: None,
            model_prompt_visibility: None,
            persona_visibility: None,
            sharing_visibility: None,
            status: None,
            system_prompt_visibility: None,
            system_tags: None,
            token_budget: None,
            usage_hints: None,
            user_persona: None,
            user_persona_visibility: None,
            world_scenario_visibility: None,
            description_nonce: None,
            personality_nonce: None,
            scenario_nonce: None,
            first_mes_nonce: None,
            mes_example_nonce: None,
            creator_notes_nonce: None,
            system_prompt_nonce: None,
            persona_nonce: None,
            world_scenario_nonce: None,
            definition_nonce: None,
            model_prompt_nonce: None,
            user_persona_nonce: None,
            post_history_instructions_nonce: None,
            post_history_instructions: None,
            scenario: None,
            mes_example: None,
            first_mes: None,
            creator_notes: None,
            system_prompt: None,
            alternate_greetings: None,
            creator: None,
            source: None,
            group_only_greetings: None,
            fav: None,
            world: None,
            creator_comment: None,
            creator_comment_nonce: None,
            depth_prompt: None,
            depth_prompt_depth: None,
            depth_prompt_role: None,
            talkativeness: None,
            depth_prompt_ciphertext: None,
            depth_prompt_nonce: None,
            world_ciphertext: None,
            world_nonce: None,
        };

        let character: Character = diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok((user, character))
    }

    /// Creates an authenticated session for a user and returns the session cookie value
    pub async fn create_authenticated_session(
        _app: &TestApp,
        user: &DbUser,
    ) -> Result<String, AppError> {
        // In a real implementation, this would:
        // 1. Create a session in the session store
        // 2. Set up the authentication cookies
        // 3. Return the session ID that can be used in Cookie headers

        // For now, we'll use a simplified approach with the user ID
        // This assumes the auth system can handle this format
        Ok(format!("test_session_user_{}", user.id))
    }

    /// Adds credits to a user using the credit service with proper connection handling
    pub async fn add_credits_to_user(
        app: &TestApp,
        user_id: crate::db::DbId,
        amount: i32,
        description: &str,
    ) -> Result<CreditBalance, AppError> {
        let credit_service = CreditService::new(app.config.clone());
        let description_owned = description.to_string();

        app.db_pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
            .interact(move |conn| {
                credit_service.add_credits(
                    conn,
                    user_id,
                    amount,
                    "test_credit",      // transaction_type
                    &description_owned, // description
                    None,               // reference_id
                    None,               // metadata
                )
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    /// Gets the credit balance for a user
    pub async fn get_user_credit_balance(
        app: &TestApp,
        user_id: crate::db::DbId,
    ) -> Result<CreditBalance, AppError> {
        let credit_service = CreditService::new(app.config.clone());

        app.db_pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
            .interact(move |conn| credit_service.get_balance(conn, user_id))
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    /// Gets transaction history for a user
    pub async fn get_user_transaction_history(
        app: &TestApp,
        user_id: crate::db::DbId,
    ) -> Result<Vec<CreditTransaction>, AppError> {
        let credit_service = CreditService::new(app.config.clone());

        app.db_pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
            .interact(move |conn| credit_service.get_transaction_history(conn, user_id, None, None))
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    /// Initializes user credits account
    pub async fn initialize_user_credits(
        app: &TestApp,
        user_id: crate::db::DbId,
    ) -> Result<CreditBalance, AppError> {
        let credit_service = CreditService::new(app.config.clone());

        app.db_pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
            .interact(move |conn| credit_service.initialize_user_credits(conn, user_id))
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
    }

    /// Helper to make authenticated API requests
    pub async fn make_authenticated_request(
        app: &TestApp,
        session_key: &str,
        method: &str,
        path: &str,
        payload: Option<crate::DbJson>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let client = Client::new();
        let url = format!("{}{}", app.address, path);

        let mut request_builder = match method.to_uppercase().as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => client.get(&url),
        };

        request_builder = request_builder
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Cookie", &format!("session={}", session_key));

        if let Some(payload) = payload {
            request_builder = request_builder.json(&payload);
        }

        request_builder.send().await
    }

    // ============================================================================
    // Webhook Test Helpers
    // ============================================================================

    /// Generate a valid webhook signature for testing
    ///
    /// Uses HMAC-SHA256 to create a signature that matches what Paddle would send
    pub fn create_webhook_signature(payload: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
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
            event_id: format!("evt_test_{}", crate::db::DbId::new_v4()),
            customer_id: format!("cus_test_{}", crate::db::DbId::new_v4()),
            subscription_id: format!("sub_test_{}", crate::db::DbId::new_v4()),
            transaction_id: format!("txn_test_{}", crate::db::DbId::new_v4()),
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
        use chrono::Utc;
        use serde_json::{json, Value};

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
        pub fn subscription_created_response(
            subscription_id: &str,
            checkout_url: Option<&str>,
        ) -> Value {
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
        pub fn subscription_details_response(
            subscription_id: &str,
            customer_id: &str,
            status: &str,
        ) -> Value {
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

            assert_eq!(
                signature1, signature2,
                "Signature generation should be deterministic"
            );
            assert!(!signature1.is_empty(), "Signature should not be empty");
            assert_eq!(
                signature1.len(),
                64,
                "HMAC-SHA256 signature should be 64 hex characters"
            );
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
            assert_eq!(
                payload["data"]["subscription"]["id"],
                test_ids.subscription_id
            );
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

            let (payload_string, signature) =
                create_signed_webhook_request(&payload, TEST_WEBHOOK_SECRET);

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
            let customer_response =
                mock_responses::customer_created_response("cus_123", "test@example.com");
            assert_eq!(customer_response["data"]["id"], "cus_123");
            assert_eq!(customer_response["data"]["email"], "test@example.com");

            let subscription_response = mock_responses::subscription_created_response(
                "sub_123",
                Some("https://checkout.example.com"),
            );
            assert_eq!(subscription_response["data"]["id"], "sub_123");
            assert_eq!(
                subscription_response["data"]["checkout"]["url"],
                "https://checkout.example.com"
            );

            let error_response =
                mock_responses::error_response("invalid_request", "Missing required field");
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
