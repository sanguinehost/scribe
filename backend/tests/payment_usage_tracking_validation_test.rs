#![cfg(feature = "postgres-backend")]
#![cfg(test)]

#[cfg(feature = "payment")]
use std::collections::HashMap;

#[cfg(feature = "payment")]
use scribe_backend::{
    models::payment::PaymentUsageTracking,
    services::payment::usage_tracking_service::{UsageMetadata, UsageTrackingService},
    services::EncryptionService,
    test_helpers::{db, spawn_app_permissive_rate_limiting, TestDataGuard},
};

#[cfg(feature = "payment")]
use diesel::prelude::*;

#[tokio::test]
#[cfg(feature = "payment")]
async fn test_payment_usage_tracking_direct() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    // Create a real test user (needed for DEK encryption)
    let user_db = db::create_test_user(
        &app.db_pool,
        "test_user".to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();
    tdg.add_user(user_db.id);

    let test_user_id = user_db.id;

    // Create a usage tracking service
    let config = (*app.config).clone();
    let encryption_service = EncryptionService::new();
    let usage_service = UsageTrackingService::new(config, encryption_service);

    // Create metadata
    let mut model_usage = HashMap::new();
    model_usage.insert("gemini-2.5-flash".to_string(), 50);

    let mut feature_usage = HashMap::new();
    feature_usage.insert("chat_message".to_string(), 1);

    let metadata = UsageMetadata {
        model_usage,
        feature_usage,
        request_count: 1,
        last_activity: chrono::Utc::now(),
    };

    // Testing payment usage tracking for test user (not logging actual ID for privacy)

    // Track usage
    let conn = app.db_pool.get().await.unwrap();
    let _tracked = conn
        .interact(move |conn| {
            usage_service.track_usage_sync(
                conn,
                test_user_id,
                None, // no subscription
                50,   // 50 tokens
                Some(metadata),
            )
        })
        .await
        .unwrap()
        .unwrap();

    // Usage tracked successfully - continuing verification

    // Verify the data was stored in payment_usage_tracking table
    let conn = app.db_pool.get().await.unwrap();
    let stored_usage = conn
        .interact(move |conn| {
            use scribe_backend::schema::payment_usage_tracking::dsl::*;
            payment_usage_tracking
                .filter(user_id.eq(test_user_id))
                .first::<PaymentUsageTracking>(conn)
                .optional()
        })
        .await
        .unwrap()
        .unwrap();

    match stored_usage {
        Some(usage) => {
            // ✅ SUCCESS: Payment usage tracking record found
            // Verifying record fields without logging sensitive data

            // Assertions
            assert_eq!(usage.user_id, test_user_id);
            assert_eq!(usage.tokens_used, 50);
            assert!(usage.metadata_encrypted.is_some());
        }
        None => {
            panic!(
                "❌ ERROR: No payment usage tracking record found for user {}",
                test_user_id
            );
        }
    }

    // ✅ Payment usage tracking test completed successfully
}
