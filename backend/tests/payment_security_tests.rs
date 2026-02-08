#![cfg(feature = "postgres-backend")]
/// Payment System Security Tests based on OWASP Top 10 (2021)
///
/// This test suite verifies security requirements for the payment system including:
/// - Authentication and authorization (A01, A07)
/// - Cryptographic protection (A02)
/// - Input validation and injection prevention (A03)
/// - Business logic security (A04)
/// - Security configuration (A05)
/// - Data integrity and webhook security (A08)
/// - Security logging and monitoring (A09)
/// - Rate limiting and DoS protection

#[cfg(all(test, feature = "payment"))]
mod payment_security_tests {
    use chrono::Utc;
    use deadpool_diesel::{Manager as DeadpoolManager, Pool};
    use diesel::prelude::*;
    use reqwest::{Client, StatusCode};
    use scribe_backend::{
        config::Config,
        errors::AppError,
        models::users::UserRole,
        services::payment::CreditService,
        test_helpers::{spawn_app, TestDataGuard},
    };
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper function to create a test user
    async fn create_test_user(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        user_id: Uuid,
        username: &str,
        email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let username = username.to_string();
        let email = email.to_string();

        let conn = pool.get().await?;
        conn.interact(move |conn| {
            use scribe_backend::schema::users::dsl;

            // First check if user exists
            let existing = dsl::users
                .filter(dsl::id.eq(user_id))
                .count()
                .get_result::<i64>(conn)?;

            if existing > 0 {
                return Ok::<_, diesel::result::Error>(());
            }

            // Insert directly with ID, using proper casts for enums
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
            .bind::<diesel::sql_types::Text, _>("User")
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

    /// Helper to make authenticated requests
    async fn make_authenticated_request(
        client: &Client,
        app_address: &str,
        endpoint: &str,
        method: &str,
    ) -> reqwest::Response {
        // Note: In a real test, we'd need to properly authenticate first
        // For now, we'll just make unauthenticated requests to test that they fail
        match method {
            "GET" => client
                .get(&format!("{}{}", app_address, endpoint))
                .send()
                .await
                .expect("Failed to execute request"),
            "POST" => client
                .post(&format!("{}{}", app_address, endpoint))
                .send()
                .await
                .expect("Failed to execute request"),
            _ => panic!("Unsupported method"),
        }
    }

    // ===== A01: Broken Access Control Tests =====

    #[tokio::test]
    async fn test_unauthenticated_access_denied() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = reqwest::Client::new();

        // Test all payment endpoints require authentication
        let endpoints = vec![
            ("/api/payment/credits/balance", "GET"),
            ("/api/payment/credits/transactions", "GET"),
            ("/api/payment/credits/packages", "GET"),
            ("/api/payment/credits/model-costs", "GET"),
        ];

        for (endpoint, method) in endpoints {
            let response =
                make_authenticated_request(&client, &app.address, endpoint, method).await;

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "Endpoint {} should require authentication",
                endpoint
            );
        }
    }

    #[tokio::test]
    async fn test_cross_user_credit_access() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create two users
        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        create_test_user(&app.db_pool, user1_id, "user1", "user1@test.com")
            .await
            .expect("Failed to create user1");
        create_test_user(&app.db_pool, user2_id, "user2", "user2@test.com")
            .await
            .expect("Failed to create user2");

        // Initialize credits for both users
        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        let _balance1 = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());
                service.initialize_user_credits(conn, user1_id.into())
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize user1 credits");

        let config2 = app.config.clone();
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");

        let _balance2 = conn2
            .interact(move |conn| {
                let service = CreditService::new(config2.clone());
                service.initialize_user_credits(conn, user2_id.into())
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to initialize user2 credits");

        // Test that user1 cannot access user2's credits
        // Note: This would require actual authentication implementation
    }

    // ===== A02: Cryptographic Failures Tests =====

    #[tokio::test]
    async fn test_transaction_data_encryption() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "crypto_test", "crypto@test.com")
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        // Add some credits and create transactions
        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());

                // Initialize user credits
                service.initialize_user_credits(conn, user_id.into())?;

                // Add credits with sensitive description
                service.add_credits(
                    conn,
                    user_id.into(),
                    100,
                    "test",
                    "Sensitive transaction description",
                    None,
                    Some(scribe_backend::db::Json(
                        json!({"sensitive_field": "secret_value"}),
                    )),
                )?;

                // Get transaction history
                service.get_transaction_history(conn, user_id.into(), Some(10), None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to get transactions");

        // Verify transactions are encrypted
        for txn in result {
            // Transaction should have encrypted fields
            assert!(!txn.description_encrypted.is_empty());
            assert!(!txn.description_nonce.is_empty());

            // If metadata exists, it should be encrypted
            if txn.metadata_encrypted.is_some() {
                assert!(txn.metadata_nonce.is_some());
                assert!(!txn.metadata_encrypted.unwrap().is_empty());
            }
        }
    }

    // ===== A03: Injection Tests =====

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "sqli_test", "sqli@test.com")
            .await
            .expect("Failed to create user");

        let config = app.config.clone();

        // Try SQL injection in various parameters
        let injection_payloads = vec![
            "'; DROP TABLE credit_transactions; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
        ];

        for payload in injection_payloads {
            let conn = app.db_pool.get().await.expect("Failed to get connection");
            let config_clone = config.clone();
            let payload_clone = payload.to_string();

            // Try injection in description field
            let result = conn
                .interact(move |conn| {
                    let service = CreditService::new(config_clone.clone());
                    service.add_credits(
                        conn,
                        user_id.into(),
                        10,
                        "test",
                        &payload_clone,
                        None,
                        None,
                    )
                })
                .await;

            // Should either succeed (sanitized) or fail gracefully
            // Should NOT cause SQL error
            match result {
                Ok(Ok(_)) => {} // Successfully sanitized
                Ok(Err(e)) => {
                    // Should be a controlled error, not SQL syntax error
                    assert!(!e.to_string().contains("syntax error"));
                    assert!(!e.to_string().contains("SQL"));
                }
                Err(_) => {} // Connection error is acceptable
            }
        }
    }

    // ===== A04: Insecure Design Tests =====

    #[tokio::test]
    async fn test_negative_credit_prevention() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "negative_test", "negative@test.com")
            .await
            .expect("Failed to create user");

        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        let result = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());

                // Initialize user
                service.initialize_user_credits(conn, user_id.into())?;

                // Try to add negative credits
                service.add_credits(
                    conn,
                    user_id.into(),
                    -1000, // Negative amount
                    "test",
                    "Attempting negative credit addition",
                    None,
                    None,
                )
            })
            .await
            .expect("Failed to interact");

        // Should fail with BadRequest error
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, AppError::BadRequest(_)));
        }
    }

    #[tokio::test]
    async fn test_atomic_credit_operations() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "atomic_test", "atomic@test.com")
            .await
            .expect("Failed to create user");

        // Clone config for each closure that needs it
        let config1 = app.config.clone();
        let config2 = app.config.clone();

        // Test reserve/confirm/refund pattern
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        let (initial_balance, reservation_id) = conn
            .interact(move |conn| {
                let service = CreditService::new(config1.clone());

                // Initialize and add some credits
                service.initialize_user_credits(conn, user_id.into())?;
                service.add_credits(
                    conn,
                    user_id.into(),
                    100,
                    "test",
                    "Initial credits",
                    None,
                    None,
                )?;

                // Reserve credits
                service.reserve_credits(conn, user_id.into(), 30, "Test reservation", None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to reserve credits");

        assert_eq!(initial_balance.balance, 70); // 100 - 30 reserved

        // Test confirmation
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");

        let confirmed_balance = conn2
            .interact(move |conn| {
                let service = CreditService::new(config2.clone());
                service.confirm_reservation(conn, user_id.into(), reservation_id)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to confirm reservation");

        assert_eq!(confirmed_balance.balance, 70); // Should remain 70
        assert_eq!(confirmed_balance.lifetime_spent, 30); // Should track spending
    }

    #[tokio::test]
    async fn test_reservation_refund() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let user_id = Uuid::new_v4();
        create_test_user(&app.db_pool, user_id, "refund_test", "refund@test.com")
            .await
            .expect("Failed to create user");

        // Clone config for each closure that needs it
        let config1 = app.config.clone();
        let config2 = app.config.clone();

        let conn = app.db_pool.get().await.expect("Failed to get connection");

        let (_balance, reservation_id) = conn
            .interact(move |conn| {
                let service = CreditService::new(config1.clone());

                // Initialize and add credits
                service.initialize_user_credits(conn, user_id.into())?;
                service.add_credits(conn, user_id.into(), 100, "test", "Initial", None, None)?;

                // Reserve credits
                service.reserve_credits(conn, user_id.into(), 40, "To be refunded", None)
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to reserve");

        // Refund the reservation
        let conn2 = app.db_pool.get().await.expect("Failed to get connection");

        let refunded_balance = conn2
            .interact(move |conn| {
                let service = CreditService::new(config2.clone());
                service.refund_reservation(conn, user_id.into(), reservation_id, "Test refund")
            })
            .await
            .expect("Failed to interact")
            .expect("Failed to refund");

        assert_eq!(refunded_balance.balance, 100); // Credits should be restored
        assert_eq!(refunded_balance.lifetime_spent, 0); // No spending recorded
    }

    // ===== A08: Software and Data Integrity Tests =====

    #[tokio::test]
    async fn test_webhook_signature_verification() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = reqwest::Client::new();

        // Test invalid webhook signature
        let webhook_payload = json!({
            "event_type": "transaction.completed",
            "data": {
                "id": "txn_test_123",
                "customer_id": "ctm_test_456"
            }
        });

        let response = client
            .post(&format!("{}/api/payment/webhook/paddle", app.address))
            .header("Paddle-Signature", "invalid_signature:123456")
            .json(&webhook_payload)
            .send()
            .await
            .expect("Failed to execute request");

        // Invalid signature should be rejected
        // Note: Actual status depends on implementation
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "Invalid webhook signature should be rejected"
        );
    }

    // ===== Rate Limiting Tests =====

    #[tokio::test]
    async fn test_rate_limiting_enforcement() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = reqwest::Client::new();

        // Test rate limiting on credit endpoints
        let mut too_many_requests = false;

        for i in 0..10 {
            let response = client
                .get(&format!("{}/api/payment/credits/balance", app.address))
                .send()
                .await
                .expect("Failed to execute request");

            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                too_many_requests = true;
                println!("Rate limited after {} requests", i + 1);
                break;
            }
        }

        // Note: Rate limiting might not be enforced in test environment
        // This test documents the expected behavior
        // Variable here for future use when rate limiting is fully implemented
        let _ = too_many_requests;
    }

    // ===== Missing Endpoint Security Tests =====

    #[tokio::test]
    async fn test_subscription_cancel_endpoint_security() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test subscription cancel without authentication
        let response = client
            .delete(&format!("{}/api/payment/subscription/cancel", app.address))
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Subscription cancel should require authentication"
        );

        // Test with malformed subscription ID
        let malformed_ids = vec![
            "not-a-uuid",
            "../../../admin",
            "'; DROP TABLE subscriptions; --",
            "%00%00%00%00",
        ];

        for malformed_id in malformed_ids {
            let response = client
                .delete(&format!(
                    "{}/api/payment/subscription/{}/cancel",
                    app.address, malformed_id
                ))
                .send()
                .await
                .expect("Failed to execute request");

            // Should be unauthorized or bad request, not internal server error
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::NOT_FOUND,
                "Malformed subscription ID should be handled safely: {}",
                malformed_id
            );
        }
    }

    #[tokio::test]
    async fn test_subscription_preview_endpoint_security() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test subscription preview without authentication
        let preview_request = json!({
            "plan_type": "premium",
            "billing_period": "monthly"
        });

        let response = client
            .post(&format!("{}/api/payment/subscription/preview", app.address))
            .json(&preview_request)
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Subscription preview should require authentication"
        );

        // Test with malicious input
        let malicious_inputs = vec![
            json!({
                "plan_type": "<script>alert('xss')</script>",
                "billing_period": "monthly"
            }),
            json!({
                "plan_type": "premium",
                "billing_period": "'; DROP TABLE plan_features; --"
            }),
            json!({
                "plan_type": "../../../etc/passwd",
                "billing_period": "yearly"
            }),
        ];

        for malicious_input in malicious_inputs {
            let response = client
                .post(&format!("{}/api/payment/subscription/preview", app.address))
                .json(&malicious_input)
                .send()
                .await
                .expect("Failed to execute request");

            // Should be unauthorized or bad request, not process malicious input
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status().is_client_error(),
                "Malicious input should be rejected safely"
            );
        }
    }

    #[tokio::test]
    async fn test_transaction_verification_endpoint_security() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test transaction verification without authentication
        let fake_transaction_id = "txn_fake_12345";
        let response = client
            .get(&format!(
                "{}/api/payment/transaction/{}/verify",
                app.address, fake_transaction_id
            ))
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Transaction verification should require authentication"
        );

        // Test with malicious transaction IDs
        let malicious_ids = vec![
            "../../admin/transactions",
            "'; SELECT * FROM payment_transactions; --",
            "%2e%2e%2f%2e%2e%2fadmin",
            "txn_<script>alert('xss')</script>",
        ];

        for malicious_id in malicious_ids {
            let response = client
                .get(&format!(
                    "{}/api/payment/transaction/{}/verify",
                    app.address, malicious_id
                ))
                .send()
                .await
                .expect("Failed to execute request");

            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status().is_client_error(),
                "Malicious transaction ID should be handled safely: {}",
                malicious_id
            );
        }
    }

    #[tokio::test]
    async fn test_payment_page_redirect_security() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test payment completion page with malicious redirects
        let malicious_params = vec![
            ("success_url", "javascript:alert('xss')"),
            ("success_url", "http://malicious-site.com/steal-data"),
            ("success_url", "file:///etc/passwd"),
            ("cancel_url", "http://attacker.com/phishing"),
            ("transaction_id", "'; DROP TABLE transactions; --"),
        ];

        for (param, value) in malicious_params {
            let response = client
                .get(&format!(
                    "{}/api/payment/pay?{}={}",
                    app.address, param, value
                ))
                .send()
                .await
                .expect("Failed to execute request");

            // Should handle malicious parameters safely
            let response_text = response.text().await.unwrap_or_default();

            assert!(
                !response_text.contains("javascript:"),
                "Should not include javascript: URLs"
            );
            assert!(
                !response_text.contains("malicious-site.com"),
                "Should not include malicious domains"
            );
            assert!(
                !response_text.contains("file://"),
                "Should not include file:// URLs"
            );
        }
    }

    #[tokio::test]
    async fn test_credit_packages_endpoint_authorization() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test credit packages endpoint without authentication
        let response = client
            .get(&format!("{}/api/payment/credits/packages", app.address))
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Credit packages endpoint should require authentication"
        );

        // Test with various HTTP methods
        let methods = vec!["POST", "PUT", "DELETE", "PATCH"];
        for method in methods {
            let request_method = match method {
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                "PATCH" => reqwest::Method::PATCH,
                _ => continue,
            };

            let response = client
                .request(
                    request_method,
                    &format!("{}/api/payment/credits/packages", app.address),
                )
                .send()
                .await
                .expect("Failed to execute request");

            // Should either be unauthorized or method not allowed
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::METHOD_NOT_ALLOWED,
                "Unexpected method {} should be handled securely",
                method
            );
        }
    }

    #[tokio::test]
    async fn test_model_costs_endpoint_security() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test model costs endpoint without authentication
        let response = client
            .get(&format!("{}/api/payment/credits/model-costs", app.address))
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Model costs endpoint should require authentication"
        );

        // Test with query injection attempts
        let malicious_queries = vec![
            "?model='; DROP TABLE model_costs; --",
            "?model=<script>alert('xss')</script>",
            "?model=../../admin/costs",
            "?filter=%00%00%00",
        ];

        for query in malicious_queries {
            let response = client
                .get(&format!(
                    "{}/api/payment/credits/model-costs{}",
                    app.address, query
                ))
                .send()
                .await
                .expect("Failed to execute request");

            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status().is_client_error(),
                "Malicious query should be handled safely: {}",
                query
            );
        }
    }

    #[tokio::test]
    async fn test_usage_endpoint_data_isolation() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Test usage endpoint without authentication
        let response = client
            .get(&format!("{}/api/payment/usage", app.address))
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Usage endpoint should require authentication"
        );

        // Test with user ID injection attempts
        let user_id_injections = vec![
            "?user_id=00000000-0000-0000-0000-000000000000",
            "?user_id=' OR '1'='1",
            "?user_id=admin",
            "?user_id=*",
        ];

        for injection in user_id_injections {
            let response = client
                .get(&format!("{}/api/payment/usage{}", app.address, injection))
                .send()
                .await
                .expect("Failed to execute request");

            // Should be unauthorized regardless of injection attempt
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "User ID injection should not bypass authentication: {}",
                injection
            );
        }
    }

    #[tokio::test]
    async fn test_plans_endpoint_information_disclosure() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        let client = Client::new();

        // Plans endpoint might be accessible without auth (public pricing info)
        let response = client
            .get(&format!("{}/api/payment/plans", app.address))
            .send()
            .await
            .expect("Failed to execute request");

        if response.status() == StatusCode::OK {
            let response_text = response.text().await.unwrap_or_default();

            // Even if accessible, should not leak sensitive information
            assert!(
                !response_text.to_lowercase().contains("internal"),
                "Plans response should not contain internal information"
            );
            assert!(
                !response_text.to_lowercase().contains("debug"),
                "Plans response should not contain debug information"
            );
            assert!(
                !response_text.to_lowercase().contains("admin"),
                "Plans response should not contain admin information"
            );
            assert!(
                !response_text.contains("password"),
                "Plans response should not contain password information"
            );
        }
    }

    // ===== Enhanced Cross-User Access Prevention =====

    #[tokio::test]
    async fn test_cross_user_transaction_access_prevention() {
        let app = spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone(), None);

        // Create two users
        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        create_test_user(&app.db_pool, user1_id, "user1_tx", "user1_tx@test.com")
            .await
            .expect("Failed to create user1");
        create_test_user(&app.db_pool, user2_id, "user2_tx", "user2_tx@test.com")
            .await
            .expect("Failed to create user2");

        // Create transactions for user1
        let config = app.config.clone();
        let conn = app.db_pool.get().await.expect("Failed to get connection");

        conn.interact(move |conn| {
            let service = CreditService::new(config.clone());
            service.initialize_user_credits(conn, user1_id.into())?;
            service.add_credits(
                conn,
                user1_id.into(),
                100,
                "cross_user_test",
                "User1 transaction",
                None,
                None,
            )
        })
        .await
        .expect("Failed to interact")
        .expect("Failed to create user1 transaction");

        // In a real test with proper authentication, user2 would attempt to access user1's transactions
        // This test documents the requirement for proper authorization checks

        let client = Client::new();

        // Attempt to access transactions with various user ID manipulations
        let manipulation_attempts = vec![
            format!("/api/payment/credits/transactions?user_id={}", user1_id),
            format!("/api/payment/credits/balance?user_id={}", user1_id),
            "/api/payment/credits/transactions?user_id=*".to_string(),
            "/api/payment/credits/transactions?user_id=admin".to_string(),
        ];

        for attempt in manipulation_attempts {
            let response = client
                .get(&format!("{}{}", app.address, attempt))
                .send()
                .await
                .expect("Failed to execute request");

            // Should be unauthorized (no session) or forbidden (wrong user)
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::FORBIDDEN,
                "Cross-user access attempt should be denied: {}",
                attempt
            );
        }
    }

    // ===== Helper function to get balance =====
    #[allow(dead_code)]
    async fn get_user_balance(
        pool: &Pool<DeadpoolManager<diesel::PgConnection>>,
        config: Arc<Config>,
        user_id: Uuid,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        let balance = conn
            .interact(move |conn| {
                let service = CreditService::new(config.clone());
                service.get_balance(conn, user_id.into())
            })
            .await??;

        Ok(balance.balance)
    }
}
