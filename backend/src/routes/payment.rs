//! Payment routes and webhook handlers
//!
//! This module provides HTTP endpoints for payment management including:
//! - Subscription management (create, update, cancel)
//! - Usage tracking and limits
//! - Paddle webhook handling
//! - Plan information retrieval

#[cfg(feature = "payment")]
use crate::logging::security_events::SecurityEvent;
#[cfg(feature = "payment")]
use crate::metrics::SECURITY_METRICS;
#[cfg(feature = "payment")]
use crate::privacy::ip_anonymization::extract_and_anonymize_ip;
#[cfg(feature = "payment")]
use crate::privacy::logging::{loggable_user_id, sanitize_json_value, sanitize_personal_info};
#[cfg(feature = "payment")]
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Json as AxumJson},
    routing::{get, post},
    Router,
};
#[cfg(feature = "payment")]
use base64;
#[cfg(feature = "payment")]
use diesel::PgConnection;
#[cfg(feature = "payment")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "payment")]
use std::sync::Arc;
#[cfg(feature = "payment")]
use tracing::{error, info, warn};
#[cfg(feature = "payment")]
use uuid::Uuid;

#[cfg(feature = "payment")]
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::credit::CreditPackage,
    models::payment::{PlanFeatures, Subscription},
    services::payment::{
        audit_service::AuditEventType,
        paddle_service::{
            CreateTransactionRequest, PaddleEventType, PaddleWebhook, TransactionCheckout,
            TransactionItem,
        },
        CreditService, PaddleService, PaymentAuditService, SubscriptionService,
    },
    state::AppState,
};
#[cfg(feature = "payment")]
use axum_login::AuthSession;

#[cfg(feature = "payment")]
type CurrentAuthSession = AuthSession<AuthBackend>;

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct SubscriptionResponse {
    pub subscription: Option<Subscription>,
    pub plan_features: Option<PlanFeatures>,
    pub usage_limits: Option<UsageLimitsResponse>,
    pub customer_portal_url: Option<String>,
}

#[cfg(feature = "payment")]
#[derive(Serialize, Clone)]
pub struct UsageLimitsResponse {
    pub tokens_used_total: i32,
    pub period_start: crate::DbTimestamp,
    pub period_end: crate::DbTimestamp,
    pub is_unlimited: bool,
    // Daily usage fields
    pub daily_message_count: Option<i32>,
    pub is_throttled: Option<bool>,
    pub throttle_delay: Option<i32>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct PlansResponse {
    pub plans: Vec<PlanFeatures>,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct CreateSubscriptionRequest {
    pub plan_type: String,
    pub billing_period: String, // "monthly" or "yearly"
    pub trial_days: Option<i32>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct CreateSubscriptionResponse {
    pub checkout_url: String,
    pub subscription_id: String,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct OrderPreviewRequest {
    pub plan_type: String,
    pub billing_period: String, // "monthly" or "yearly"
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct OrderLineItem {
    pub description: String,
    pub billing_period: String,
    pub amount: f64,
    pub currency: String,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct OrderPreview {
    pub plan_name: String,
    pub plan_type: String,
    pub billing_period: String,
    pub line_items: Vec<OrderLineItem>,
    pub subtotal: f64,
    pub tax_amount: f64,
    pub total_amount: f64,
    pub currency: String,
    pub next_billing_date: String,
    pub savings_message: Option<String>,
    pub cancellation_policy: String,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct CreatePaymentRequest {
    pub plan_type: String,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct CreatePaymentResponse {
    pub transaction_id: String,
    pub checkout_url: String,
    pub status: String,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct CancelSubscriptionRequest {
    pub immediate: Option<bool>,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct PayQuery {
    pub _ptxn: Option<String>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct WebhookResponse {
    pub success: bool,
    pub message: String,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct CreditBalanceResponse {
    pub balance: i32,
    pub lifetime_earned: i32,
    pub lifetime_spent: i32,
    pub last_monthly_grant: Option<crate::DbTimestamp>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct CreditTransactionResponse {
    pub id: crate::db::DbId,
    pub amount: i32,
    pub balance_after: i32,
    pub transaction_type: String,
    pub description: String,             // Decrypted
    pub metadata: Option<crate::DbJson>, // Decrypted
    pub reference_id: Option<String>,
    pub created_at: crate::DbTimestamp,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct CreditPackagesResponse {
    pub packages: Vec<CreditPackage>,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct PurchaseCreditsRequest {
    pub package_id: String,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct PurchaseCreditsResponse {
    pub checkout_url: String,
    pub transaction_id: String,
}

#[cfg(feature = "payment")]
#[derive(Deserialize)]
pub struct TransactionListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct PaymentTransactionResponse {
    pub id: crate::db::DbId,
    pub paddle_transaction_id: String,
    pub status: String,
    pub total_cents: i32,
    pub currency_code: Option<String>,
    pub customer_data: crate::models::payment::CustomerData, // DECRYPTED
    pub items: crate::DbJson,
    pub billed_at: Option<crate::DbTimestamp>,
    pub completed_at: Option<crate::DbTimestamp>,
    pub created_at: Option<crate::DbTimestamp>,
}

/// Helper function to decrypt and convert PaymentTransaction to response DTO
#[cfg(feature = "payment")]
pub async fn payment_transaction_to_response(
    transaction: crate::models::payment::PaymentTransaction,
    encryption_service: &crate::services::encryption_service::EncryptionService,
    encryption_key: &str,
) -> Result<PaymentTransactionResponse, AppError> {
    use base64::Engine;

    // Decode base64 encryption key
    let encryption_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(encryption_key)
        .map_err(|e| AppError::ConfigurationError(format!("Invalid encryption key: {}", e)))?;

    // Decrypt customer data
    let customer_data =
        transaction.decrypt_customer_data(encryption_service, &encryption_key_bytes)?;

    Ok(PaymentTransactionResponse {
        id: transaction.id,
        paddle_transaction_id: transaction.paddle_transaction_id,
        status: transaction.status,
        total_cents: transaction.total_cents,
        currency_code: transaction.currency_code,
        customer_data, // Decrypted
        items: transaction.items,
        billed_at: transaction.billed_at,
        completed_at: transaction.completed_at,
        created_at: transaction.created_at,
    })
}

/// Get current user's subscription information
#[cfg(feature = "payment")]
pub async fn get_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<AxumJson<SubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get database connection
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    // Create subscription service
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone(),
    );

    // Get subscription from database
    let user_id = user.id;
    let subscription_service_clone = subscription_service.clone();
    let mut subscription = conn
        .interact(move |conn| subscription_service_clone.get_user_subscription_sync(conn, user_id))
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get subscription: {}", e)))?;

    // Sync with Paddle if subscription exists
    if let Some(ref sub) = subscription {
        tracing::debug!(
            "Syncing subscription {} with Paddle for real-time status",
            sub.id
        );

        // Create Paddle service for sync
        let paddle_service = crate::services::payment::paddle_service::PaddleService::new(
            (*app_state.config).clone().payment,
        );

        let subscription_service_clone = subscription_service.clone();
        let subscription_clone = sub.clone();
        let synced_subscription = conn
            .interact(move |conn| {
                // Use tokio::task::block_in_place to run async code in sync context
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        subscription_service_clone
                            .sync_subscription_with_paddle(
                                conn,
                                &subscription_clone,
                                &paddle_service,
                            )
                            .await
                    })
                })
            })
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
            })?
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to sync subscription: {}", e))
            })?;

        subscription = synced_subscription;
    }

    // Get plan features if subscription exists
    let plan_features = if let Some(ref sub) = subscription {
        let plan_type = sub.plan_type.clone();
        tracing::debug!(
            "📋 Subscription found for user {}: plan_type='{}', status='{}', id='{}'",
            user.id,
            plan_type,
            sub.status,
            sub.id
        );
        let subscription_service_clone = subscription_service.clone();
        conn.interact(move |conn| {
            subscription_service_clone.get_plan_features_sync(conn, &plan_type)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get plan features: {}", e)))?
    } else {
        tracing::debug!("No subscription found for user {}", user.id);
        // Default to free plan features
        let subscription_service_clone = subscription_service.clone();
        conn.interact(move |conn| subscription_service_clone.get_plan_features_sync(conn, "free"))
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
            })?
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get free plan features: {}", e))
            })?
    };

    // Get daily usage from SoftLimitService
    #[cfg(feature = "payment")]
    let soft_limit_service =
        crate::services::payment::SoftLimitService::new(app_state.config.clone());
    let user_id_for_usage = user.id;

    let (daily_message_count, is_throttled, throttle_delay) = conn
        .interact(move |conn| {
            if let Ok(usage) = soft_limit_service.get_or_create_daily_usage(conn, user_id_for_usage)
            {
                let is_over = usage.soft_limit_triggered_at.is_some();
                let delay = if is_over {
                    soft_limit_service
                        .should_throttle(conn, user_id_for_usage)
                        .unwrap_or(None)
                        .map(|d| d.as_secs() as i32)
                        .unwrap_or(0)
                } else {
                    0
                };
                (usage.message_count as i32, is_over, delay)
            } else {
                (0, false, 0)
            }
        })
        .await
        .unwrap_or((0, false, 0));

    // Calculate usage limits using actual token usage from payment_usage_tracking table
    let usage_limits = if let Some(ref features) = plan_features {
        let usage_tracking_service = crate::services::payment::UsageTrackingService::new(
            (*app_state.config).clone(),
            crate::services::encryption_service::EncryptionService::new(),
        );

        let user_id_for_limits = user.id;
        let usage_result = conn
            .interact(move |conn| {
                usage_tracking_service.get_usage_limits_sync(conn, user_id_for_limits)
            })
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
            })?;

        match usage_result {
            Ok(usage_limit) => {
                Some(UsageLimitsResponse {
                    tokens_used_total: usage_limit.tokens_used_total,
                    period_start: usage_limit.period_start,
                    period_end: usage_limit.period_end,
                    is_unlimited: usage_limit.is_unlimited,
                    // Add daily usage fields
                    daily_message_count: Some(daily_message_count),
                    is_throttled: Some(is_throttled),
                    throttle_delay: Some(throttle_delay),
                })
            }
            Err(e) => {
                warn!(
                    "Failed to get usage limits for user {}: {}",
                    loggable_user_id(user.id),
                    e
                );
                // Fallback to default values without usage data
                Some(UsageLimitsResponse {
                    tokens_used_total: 0, // Unknown usage, default to 0
                    period_start: crate::DbTimestamp::now(),
                    period_end: crate::DbTimestamp::from_datetime(
                        chrono::Utc::now() + chrono::Duration::days(30),
                    ),
                    is_unlimited: features.monthly_token_limit.is_none(),
                    daily_message_count: Some(daily_message_count),
                    is_throttled: Some(is_throttled),
                    throttle_delay: Some(throttle_delay),
                })
            }
        }
    } else {
        None
    };

    // Generate customer portal URL if subscription exists and has paddle_customer_id
    let customer_portal_url = if let Some(ref sub) = subscription {
        if let Some(ref customer_id) = sub.paddle_customer_id {
            // Create Paddle service for portal URL generation
            let paddle_service = crate::services::payment::paddle_service::PaddleService::new(
                (*app_state.config).clone().payment,
            );

            match paddle_service
                .generate_customer_portal_url(customer_id)
                .await
            {
                Ok(portal_url) => {
                    tracing::debug!(
                        "Generated customer portal URL for user {} with customer_id {}",
                        user.id,
                        customer_id
                    );
                    Some(portal_url)
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to generate customer portal URL for user {} with customer_id {}: {}",
                        user.id,
                        customer_id,
                        e
                    );
                    None
                }
            }
        } else {
            tracing::debug!(
                "ℹ️ No Paddle customer ID found for user {} subscription {}",
                user.id,
                sub.id
            );
            None
        }
    } else {
        None
    };

    let response = SubscriptionResponse {
        subscription: subscription.clone(),
        plan_features: plan_features.clone(),
        usage_limits: usage_limits.clone(),
        customer_portal_url,
    };

    tracing::debug!(
        "Sending subscription response for user {}: subscription_exists={}, plan_type={:?}, has_portal_url={}",
        user.id,
        response.subscription.is_some(),
        response.subscription.as_ref().map(|s| &s.plan_type),
        response.customer_portal_url.is_some()
    );

    Ok(AxumJson(response))
}

/// Get available subscription plans
#[cfg(feature = "payment")]
pub async fn get_plans(
    State(_app_state): State<AppState>,
) -> Result<AxumJson<PlansResponse>, AppError> {
    // TODO: This is a simplified implementation for now
    Ok(AxumJson(PlansResponse { plans: vec![] }))
}

/// Get current user's usage information
#[cfg(feature = "payment")]
pub async fn get_usage(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<AxumJson<UsageLimitsResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get database connection
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    // Get daily usage from SoftLimitService
    let soft_limit_service =
        crate::services::payment::SoftLimitService::new(app_state.config.clone());
    let user_id = user.id;

    let (daily_message_count, is_throttled, throttle_delay) = conn
        .interact(move |conn| {
            if let Ok(usage) = soft_limit_service.get_or_create_daily_usage(conn, user_id) {
                let is_over = usage.soft_limit_triggered_at.is_some();
                let delay = if is_over {
                    soft_limit_service
                        .should_throttle(conn, user_id)
                        .unwrap_or(None)
                        .map(|d| d.as_secs() as i32)
                        .unwrap_or(0)
                } else {
                    0
                };
                (usage.message_count as i32, is_over, delay)
            } else {
                (0, false, 0)
            }
        })
        .await
        .unwrap_or((0, false, 0));

    // Get actual token usage from payment_usage_tracking table
    let usage_tracking_service = crate::services::payment::UsageTrackingService::new(
        (*app_state.config).clone(),
        crate::services::encryption_service::EncryptionService::new(),
    );

    let user_id_for_limits = user.id;
    let usage_result = conn
        .interact(move |conn| {
            usage_tracking_service.get_usage_limits_sync(conn, user_id_for_limits)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?;

    match usage_result {
        Ok(usage_limit) => {
            Ok(AxumJson(UsageLimitsResponse {
                tokens_used_total: usage_limit.tokens_used_total,
                period_start: usage_limit.period_start,
                period_end: usage_limit.period_end,
                is_unlimited: usage_limit.is_unlimited,
                // Add daily usage fields
                daily_message_count: Some(daily_message_count),
                is_throttled: Some(is_throttled),
                throttle_delay: Some(throttle_delay),
            }))
        }
        Err(e) => {
            warn!(
                "Failed to get usage limits for user {}: {}",
                loggable_user_id(user.id),
                e
            );
            // Fallback to safe defaults
            Ok(AxumJson(UsageLimitsResponse {
                tokens_used_total: 0,
                period_start: crate::DbTimestamp::now(),
                period_end: crate::DbTimestamp::from_datetime(
                    chrono::Utc::now() + chrono::Duration::days(30),
                ),
                is_unlimited: false,
                daily_message_count: Some(daily_message_count),
                is_throttled: Some(is_throttled),
                throttle_delay: Some(throttle_delay),
            }))
        }
    }
}

/// Create a new payment transaction (replaces direct subscription creation)
#[cfg(feature = "payment")]
pub async fn create_payment(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    AxumJson(request): AxumJson<CreatePaymentRequest>,
) -> Result<AxumJson<CreatePaymentResponse>, AppError> {
    tracing::debug!(
        plan_type = %request.plan_type,
        success_url = %request.success_url.as_deref().unwrap_or("None"),
        cancel_url = %request.cancel_url.as_deref().unwrap_or("None"),
        "Handler entered"
    );

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    tracing::debug!(
        user_id = %loggable_user_id(user.id),
        user_email = %sanitize_personal_info(&user.email),
        user_username = %sanitize_personal_info(&user.username),
        "User authenticated"
    );

    // Create or get existing customer
    tracing::debug!("Creating PaddleService with payment config");
    let paddle_service = PaddleService::new(app_state.config.payment.clone());

    tracing::debug!(
        customer_email = %sanitize_personal_info(&user.email),
        customer_name = %sanitize_personal_info(&user.username),
        "Creating/getting Paddle customer"
    );
    let customer = paddle_service
        .create_customer(&user.email, Some(&user.username))
        .await?;

    tracing::debug!(
        customer_id = %customer.id,
        customer_email = %customer.email.as_ref().map(|e| sanitize_personal_info(e).to_string()).unwrap_or_else(|| "None".to_string()),
        "Paddle customer resolved"
    );

    // Look up plan features from database to get paddle_price_id
    tracing::debug!("Creating subscription service");
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone(),
    );

    tracing::debug!("Getting database connection");
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to get database connection");
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to get database connection");
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    tracing::debug!(plan_type = %request.plan_type, "Looking up plan features");
    let plan_type_clone = request.plan_type.clone();
    let subscription_service_clone = subscription_service.clone();
    let plan_features = conn
        .interact(move |conn| {
            subscription_service_clone.get_plan_features_sync(conn, &plan_type_clone)
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database interaction failed");
            AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
        })?
        .map_err(|e| {
            tracing::error!(error = %e, "Database query failed");
            AppError::DatabaseQueryError(format!("Database query failed: {}", e))
        })?
        .ok_or_else(|| {
            tracing::error!(plan_type = %request.plan_type, "Invalid plan type");
            AppError::BadRequest(format!("Invalid plan type: {}", request.plan_type))
        })?;

    tracing::debug!(
        plan_type = %request.plan_type,
        paddle_price_id = ?plan_features.paddle_price_id,
        "Plan features loaded"
    );

    let price_id = plan_features.paddle_price_id.ok_or_else(|| {
        tracing::error!(plan_type = %request.plan_type, "No paddle_price_id configured for plan");
        AppError::BadRequest(format!(
            "Plan '{}' does not have a configured paddle_price_id",
            request.plan_type
        ))
    })?;

    // Create transaction request
    let transaction_request = CreateTransactionRequest {
        customer_id: customer.id.clone(),
        items: vec![TransactionItem {
            price_id: price_id.to_string(),
            quantity: 1,
        }],
        collection_mode: "automatic".to_string(), // Automatic checkout
        checkout: Some(TransactionCheckout {
            url: None, // Let Paddle generate the hosted checkout URL
            success_url: request.success_url.clone(),
            cancel_url: request.cancel_url.clone(),
        }),
        // billing_details must be null for automatic collection mode per Paddle API
        billing_details: None,
        custom_data: None,
    };

    tracing::debug!(
        customer_id = %customer.id,
        price_id = %price_id,
        collection_mode = %transaction_request.collection_mode,
        success_url = ?request.success_url,
        cancel_url = ?request.cancel_url,
        "About to create Paddle transaction"
    );

    // Create transaction with Paddle
    let transaction = paddle_service
        .create_transaction(&transaction_request)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                customer_id = %customer.id,
                price_id = %price_id,
                "Failed to create Paddle transaction"
            );
            e
        })?;

    tracing::debug!(
        transaction_id = %transaction.transaction_id,
        checkout_url = %transaction.checkout_url,
        status = %transaction.status,
        customer_id = %customer.id,
        "Successfully created transaction, returning response"
    );

    Ok(AxumJson(CreatePaymentResponse {
        transaction_id: transaction.transaction_id,
        checkout_url: transaction.checkout_url,
        status: transaction.status,
    }))
}

/// Verify a transaction and create/update subscription if valid
#[cfg(feature = "payment")]
pub async fn verify_transaction(
    Path(transaction_id): Path<String>,
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<AxumJson<crate::DbJson>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    tracing::debug!(
        "Verifying transaction {} for user {}",
        transaction_id,
        loggable_user_id(user.id)
    );

    // Validate transaction ID format - reject obvious placeholders
    if transaction_id.is_empty()
        || transaction_id == "{transaction_id}"
        || transaction_id == "undefined"
        || transaction_id == "null"
        || transaction_id.len() < 10
    // Paddle transaction IDs are typically much longer
    {
        tracing::warn!(
            "🚫 Invalid transaction ID format: '{}' for user {}",
            transaction_id,
            loggable_user_id(user.id)
        );
        return Ok(AxumJson(crate::db::Json(serde_json::json!({
            "success": false,
            "message": "Invalid transaction ID format",
            "error": "Transaction ID appears to be a placeholder or invalid format"
        }))));
    }

    // First, check if we have the transaction in our database
    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let transaction_id_for_db = transaction_id.clone();
    let user_id_for_check = user.id.clone();
    let stored_transaction = conn
        .interact(move |conn| {
            use crate::models::payment::PaymentTransaction;
            use crate::schema::payment_transactions::dsl::*;
            use diesel::prelude::*;

            payment_transactions
                .filter(paddle_transaction_id.eq(&transaction_id_for_db))
                .filter(user_id.eq(&user_id_for_check))
                .select(PaymentTransaction::as_select())
                .first::<PaymentTransaction>(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    // If we have the transaction in our database and it's completed, use that data
    if let Some(transaction) = stored_transaction {
        tracing::debug!(
            "Found transaction {} in database with status: {}",
            transaction_id,
            transaction.status
        );

        if transaction.status == "completed" {
            // Transaction is already verified and stored
            // Check for existing subscription or create one
            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let user_id_for_sub = user.id.clone();
            let existing_subscription = conn
                .interact(move |conn| {
                    use crate::models::payment::Subscription;
                    use crate::schema::subscriptions::dsl as sub_dsl;
                    use diesel::prelude::*;

                    sub_dsl::subscriptions
                        .filter(sub_dsl::user_id.eq(user_id_for_sub))
                        .filter(sub_dsl::status.ne("cancelled"))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                        .optional()
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))?
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if existing_subscription.is_some() {
                return Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": true,
                    "message": "Transaction already verified and subscription exists",
                    "source": "database"
                }))));
            }

            // Create subscription from stored transaction data
            // Parse plan type from items
            let plan_type = if let Some(item) = transaction.items.as_array().and_then(|a| a.first())
            {
                let price_id = item.get("price_id").and_then(|v| v.as_str()).unwrap_or("");
                match price_id {
                    "pri_01k4qbyetvn495nzv9nkqhxz02" => "basic", // Basic monthly
                    "pri_01k5ejs7h9zmw4d888r3pjjqna" => "basic", // Basic yearly
                    "pri_01k5ej7wzvpcj6j65vcbpam6t4" => "premium", // Premium monthly
                    "pri_01k5ejva0cwqzbtgzd2c9qk0d4" => "premium", // Premium yearly
                    _ => "free",                                 // Default fallback
                }
            } else {
                "free"
            };

            // Extract paddle subscription ID from stored transaction items
            let paddle_subscription_id =
                if let Some(item) = transaction.items.as_array().and_then(|a| a.first()) {
                    item.get("price")
                        .and_then(|price| price.get("subscription_id"))
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("subscription_id").and_then(|v| v.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

            if let Some(ref sub_id) = paddle_subscription_id {
                tracing::debug!(
                    "Extracted paddle_subscription_id: {} from stored transaction {}",
                    sub_id,
                    transaction_id
                );
            }

            let subscription_service = crate::services::payment::SubscriptionService::new(
                (*app_state.config).clone(),
                (*app_state.encryption_service).clone(),
            );

            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let paddle_customer_id = transaction.paddle_customer_id.clone();
            let new_subscription = conn
                .interact(move |conn| {
                    subscription_service.create_subscription_sync(
                        conn,
                        user.id,
                        plan_type,
                        paddle_customer_id,
                        paddle_subscription_id, // Pass extracted subscription ID
                        None,                   // No trial
                    )
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))??;

            tracing::debug!(
                "Created subscription {} from stored transaction {}",
                new_subscription.id,
                transaction_id
            );

            return Ok(AxumJson(crate::db::Json(serde_json::json!({
                "success": true,
                "message": "Transaction verified from database",
                "subscription": {
                    "id": new_subscription.id,
                    "plan_type": new_subscription.plan_type,
                    "status": new_subscription.status
                },
                "source": "database"
            }))));
        }
    }

    // If not in database or not completed, try Paddle API
    tracing::debug!("Transaction not found in database or not completed, checking Paddle API");

    // Create PaddleService to verify transaction
    let paddle_service = PaddleService::new(app_state.config.payment.clone());

    // Verify transaction with Paddle API
    match paddle_service.get_transaction(&transaction_id).await {
        Ok(response) => {
            // Use response directly - get_transaction() already extracts the data field
            let transaction_data = &response;

            tracing::debug!(
                transaction_id = %transaction_id,
                status = ?transaction_data.get("status"),
                "Transaction data retrieved from Paddle"
            );

            // Check if transaction is completed or if it's a valid trial transaction
            let status = transaction_data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            // Extract total from transaction - handle different formats
            let total_str = transaction_data
                .get("totals")
                .and_then(|t| t.get("total"))
                .and_then(|v| v.as_str())
                .unwrap_or("0");

            // Parse total as float to handle "0", "0.0", "0.00" formats
            let is_zero_total = match total_str.parse::<f64>() {
                Ok(amount) => amount == 0.0,
                Err(_) => total_str == "0" || total_str == "0.00",
            };

            // Check if this is a trial transaction (draft status with $0.00 total)
            let is_trial = status == "draft" && is_zero_total;

            tracing::debug!(
                "Transaction status: {}, total: {}, is_trial: {}",
                status,
                total_str,
                is_trial
            );

            if status != "completed" && !is_trial {
                tracing::warn!(
                    "Transaction {} is not completed and not a trial (status: {}, total: {})",
                    transaction_id,
                    status,
                    total_str
                );
                return Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": false,
                    "message": format!("Transaction is not completed: {}", status),
                    "status": status
                }))));
            }

            // Extract customer_id from transaction
            let customer_id = transaction_data
                .get("customer_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::BadRequest("Missing customer_id in transaction".to_string())
                })?
                .to_string();

            // Extract price_id to determine plan type
            let price_id = transaction_data
                .get("items")
                .and_then(|items| items.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("price_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            // Map price_id to plan type
            let plan_type = match price_id {
                "pri_01k4qbyetvn495nzv9nkqhxz02" => "basic", // Basic monthly
                "pri_01k5ejs7h9zmw4d888r3pjjqna" => "basic", // Basic yearly
                "pri_01k5ej7wzvpcj6j65vcbpam6t4" => "premium", // Premium monthly
                "pri_01k5ejva0cwqzbtgzd2c9qk0d4" => "premium", // Premium yearly
                _ => "free",                                 // Default fallback
            };

            // Set trial days if this is a trial transaction
            let trial_days = if is_trial { Some(7) } else { None };

            tracing::debug!(
                "Creating/updating {} subscription for user {} (trial: {})",
                plan_type,
                user.id,
                is_trial
            );

            // Check if user already has a subscription - prevent duplicates
            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let existing_subscription = conn
                .interact(move |conn| {
                    use crate::models::payment::Subscription;
                    use crate::schema::subscriptions::dsl as sub_dsl;
                    use diesel::prelude::*;

                    sub_dsl::subscriptions
                        .filter(sub_dsl::user_id.eq(user.id))
                        .filter(sub_dsl::status.ne("cancelled"))
                        .select(Subscription::as_select())
                        .first::<Subscription>(conn)
                        .optional()
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))?
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if let Some(existing) = existing_subscription {
                tracing::debug!(
                    "User already has an active subscription: {} (status: {}, plan_type: {})",
                    existing.id,
                    existing.status,
                    existing.plan_type
                );

                // DUPLICATE PREVENTION: Check if this transaction has already been processed
                let transaction_id_for_check = transaction_id.clone();
                let existing_processed_transaction = conn
                    .interact(move |conn| {
                        use crate::models::payment::PaymentTransaction;
                        use crate::schema::payment_transactions::dsl::*;
                        use diesel::prelude::*;

                        payment_transactions
                            .filter(paddle_transaction_id.eq(&transaction_id_for_check))
                            .filter(status.eq("completed"))
                            .select(PaymentTransaction::as_select())
                            .first::<PaymentTransaction>(conn)
                            .optional()
                    })
                    .await
                    .map_err(|e| AppError::DbInteractError(e.to_string()))?
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                if existing_processed_transaction.is_some() {
                    tracing::warn!(
                        "🚫 Transaction {} already processed for user {}, preventing duplicate subscription creation",
                        transaction_id,
                        user.id
                    );
                    return Ok(AxumJson(crate::db::Json(serde_json::json!({
                        "success": true,
                        "message": "Transaction already processed",
                        "subscription": {
                            "id": existing.id,
                            "plan_type": existing.plan_type,
                            "status": existing.status,
                            "trial_end": existing.trial_end
                        },
                        "source": "existing"
                    }))));
                }

                // Determine if we should upgrade or prevent duplicate
                let should_upgrade = match (existing.plan_type.as_str(), plan_type) {
                    ("basic", "premium") => true, // Allow upgrade from basic to premium
                    ("free", "basic") => true,    // Allow upgrade from free to basic
                    ("free", "premium") => true,  // Allow upgrade from free to premium
                    (existing_plan, new_plan) if existing_plan == new_plan => {
                        // Same plan - only update if it's a trial or status change
                        is_trial || existing.status != "active"
                    }
                    _ => {
                        tracing::warn!(
                            "🚫 Preventing potential downgrade or duplicate: user {} already has {} subscription, attempting to create {} subscription",
                            user.id,
                            existing.plan_type,
                            plan_type
                        );
                        false
                    }
                };

                if !should_upgrade {
                    return Ok(AxumJson(crate::db::Json(serde_json::json!({
                        "success": true,
                        "message": "User already has an active subscription",
                        "subscription": {
                            "id": existing.id,
                            "plan_type": existing.plan_type,
                            "status": existing.status,
                            "trial_end": existing.trial_end
                        },
                        "source": "existing"
                    }))));
                }

                // Update existing subscription (upgrade scenario)
                let conn = app_state
                    .pool
                    .get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;

                let subscription_status = if is_trial { "trialing" } else { "active" };
                let trial_end_date = if is_trial {
                    Some(chrono::Utc::now() + chrono::Duration::days(7))
                } else {
                    None
                };

                let existing_id = existing.id;
                let plan_type_clone = plan_type.to_string();
                let customer_id_str = customer_id.to_string();
                let subscription_status_str = subscription_status.to_string();

                tracing::debug!(
                    "Upgrading subscription {} from {} to {} for user {}",
                    existing.id,
                    existing.plan_type,
                    plan_type,
                    user.id
                );

                let updated = conn
                    .interact(move |conn| {
                        use crate::models::payment::Subscription;
                        use crate::schema::subscriptions::dsl as sub_dsl;
                        use diesel::prelude::*;

                        // Build update based on whether we have trial_end_date
                        if let Some(trial_end) = trial_end_date {
                            diesel::update(sub_dsl::subscriptions.find(existing_id))
                                .set((
                                    sub_dsl::plan_type.eq(plan_type_clone),
                                    sub_dsl::paddle_customer_id.eq(Some(customer_id_str)),
                                    sub_dsl::status.eq(subscription_status_str),
                                    sub_dsl::trial_end.eq(Some(trial_end)),
                                    sub_dsl::updated_at.eq(chrono::Utc::now()),
                                ))
                                .returning(Subscription::as_returning())
                                .get_result::<Subscription>(conn)
                        } else {
                            diesel::update(sub_dsl::subscriptions.find(existing_id))
                                .set((
                                    sub_dsl::plan_type.eq(plan_type_clone),
                                    sub_dsl::paddle_customer_id.eq(Some(customer_id_str)),
                                    sub_dsl::status.eq(subscription_status_str),
                                    sub_dsl::updated_at.eq(chrono::Utc::now()),
                                ))
                                .returning(Subscription::as_returning())
                                .get_result::<Subscription>(conn)
                        }
                    })
                    .await
                    .map_err(|e| AppError::DbInteractError(e.to_string()))?
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": true,
                    "message": if is_trial { "Trial subscription updated successfully" } else { "Subscription upgraded successfully" },
                    "subscription": {
                        "id": updated.id,
                        "plan_type": updated.plan_type,
                        "status": updated.status,
                        "trial_end": updated.trial_end
                    }
                }))))
            } else {
                // Create new subscription
                let subscription_service = crate::services::payment::SubscriptionService::new(
                    (*app_state.config).clone(),
                    (*app_state.encryption_service).clone(),
                );

                let conn = app_state
                    .pool
                    .get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;

                let new_subscription = conn
                    .interact(move |conn| {
                        subscription_service.create_subscription_sync(
                            conn,
                            user.id,
                            plan_type,
                            Some(customer_id.to_string()),
                            None, // No paddle subscription ID for transaction-based billing
                            trial_days, // Pass trial_days if this is a trial
                        )
                    })
                    .await
                    .map_err(|e| AppError::DbInteractError(e.to_string()))??;

                tracing::debug!(
                    "Successfully created {} subscription {} for user {}",
                    if is_trial { "trial" } else { "active" },
                    new_subscription.id,
                    user.id
                );

                Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": true,
                    "message": if is_trial { "Trial subscription created successfully" } else { "Subscription created successfully" },
                    "subscription": {
                        "id": new_subscription.id,
                        "plan_type": new_subscription.plan_type,
                        "status": new_subscription.status,
                        "trial_end": new_subscription.trial_end
                    }
                }))))
            }
        }
        Err(e) => {
            let error_str = e.to_string();

            // Check if this is a 404 error from Paddle (transaction not found)
            if error_str.contains("404") {
                tracing::warn!(
                    "🔍 Transaction {} not found in Paddle API (404) for user {}",
                    transaction_id,
                    loggable_user_id(user.id)
                );

                return Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": false,
                    "message": "Transaction not found",
                    "error": "External service error: Paddle API error: 404 Not Found - Transaction does not exist or is not accessible"
                }))));
            }

            // Check if this is an authentication/authorization error
            if error_str.contains("401") || error_str.contains("403") {
                tracing::error!(
                    "🚫 Paddle API authentication/authorization error for transaction {}: {}",
                    transaction_id,
                    e
                );

                return Ok(AxumJson(crate::db::Json(serde_json::json!({
                    "success": false,
                    "message": "Payment service authentication error",
                    "error": "External service error: Unable to authenticate with payment processor"
                }))));
            }

            // Generic error logging and response
            tracing::error!("Failed to verify transaction {}: {}", transaction_id, e);

            // Still return a response but indicate verification failed
            Ok(AxumJson(crate::db::Json(serde_json::json!({
                "success": false,
                "message": format!("Failed to verify transaction: {}", e),
                "error": e.to_string()
            }))))
        }
    }
}

/// Preview order before checkout
#[cfg(feature = "payment")]
pub async fn preview_order(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    AxumJson(request): AxumJson<OrderPreviewRequest>,
) -> Result<AxumJson<OrderPreview>, AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get database connection
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    // Create subscription service
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone(),
    );

    // Get plan features for the requested plan
    let plan_type = request.plan_type.clone();
    let subscription_service_clone = subscription_service.clone();
    let plan_features = conn
        .interact(move |conn| subscription_service_clone.get_plan_features_sync(conn, &plan_type))
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get plan features: {}", e)))?
        .ok_or_else(|| AppError::BadRequest(format!("Invalid plan type: {}", request.plan_type)))?;

    // Determine pricing based on billing period
    let is_yearly = request.billing_period == "yearly";

    // Simple pricing logic - in production, this should query Paddle's API
    // or be stored in database alongside the price IDs
    let (amount, savings_message) = match (request.plan_type.as_str(), is_yearly) {
        ("basic", false) => (10.0, None),
        ("basic", true) => (100.0, Some("Save $20 per year".to_string())),
        ("premium", false) => (25.0, None),
        ("premium", true) => (250.0, Some("Save $50 per year".to_string())),
        _ => {
            // For free plan or unknown plans
            (0.0, None)
        }
    };

    // Calculate next billing date
    let next_billing_date = if is_yearly {
        chrono::Utc::now() + chrono::Duration::days(365)
    } else {
        chrono::Utc::now() + chrono::Duration::days(30)
    };

    // Create order preview
    let billing_period_text = if is_yearly {
        "Annual billing"
    } else {
        "Monthly billing"
    };

    let order_preview = OrderPreview {
        plan_name: plan_features.display_name.clone(),
        plan_type: request.plan_type.clone(),
        billing_period: request.billing_period.clone(),
        line_items: vec![OrderLineItem {
            description: format!("{} Plan", plan_features.display_name),
            billing_period: billing_period_text.to_string(),
            amount,
            currency: "USD".to_string(),
        }],
        subtotal: amount,
        tax_amount: 0.0, // TODO: Calculate tax based on user location
        total_amount: amount,
        currency: "USD".to_string(),
        next_billing_date: next_billing_date.to_rfc3339(),
        savings_message,
        cancellation_policy: "Cancel anytime. No cancellation fees.".to_string(),
    };

    Ok(AxumJson(order_preview))
}

/// Create a new subscription for the user (legacy - now uses transactions)
#[cfg(feature = "payment")]
pub async fn create_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    AxumJson(request): AxumJson<CreateSubscriptionRequest>,
) -> Result<AxumJson<CreateSubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get database connection
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    // Create subscription service
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone(),
    );

    // Get plan features to validate the plan type and get price_id
    let plan_type = request.plan_type.clone();
    let subscription_service_clone = subscription_service.clone();
    let plan_features = conn
        .interact(move |conn| subscription_service_clone.get_plan_features_sync(conn, &plan_type))
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get plan features: {}", e)))?
        .ok_or_else(|| AppError::BadRequest(format!("Invalid plan type: {}", request.plan_type)))?;

    // Select the appropriate price ID based on billing period
    let price_id = if request.billing_period == "yearly" {
        plan_features.paddle_price_id_yearly.ok_or_else(|| {
            AppError::BadRequest("Yearly pricing not available for this plan".to_string())
        })?
    } else {
        plan_features.paddle_price_id.ok_or_else(|| {
            AppError::BadRequest("Monthly pricing not available for this plan".to_string())
        })?
    };

    // Create Paddle service
    let paddle_service = PaddleService::new(app_state.config.payment.clone());

    // Create or get customer
    let customer = paddle_service
        .create_customer(&user.email, Some(&user.username))
        .await?;

    // Create transaction request for subscription
    let transaction_request = CreateTransactionRequest {
        customer_id: customer.id.clone(),
        items: vec![TransactionItem {
            price_id,
            quantity: 1,
        }],
        collection_mode: "automatic".to_string(),
        checkout: Some(TransactionCheckout {
            url: None,
            success_url: Some(format!(
                "{}/pricing/success",
                app_state.config.frontend_base_url
            )),
            cancel_url: Some(format!("{}/pricing", app_state.config.frontend_base_url)),
        }),
        billing_details: None,
        custom_data: None,
    };

    // Create transaction with Paddle
    let transaction = paddle_service
        .create_transaction(&transaction_request)
        .await?;

    Ok(AxumJson(CreateSubscriptionResponse {
        checkout_url: transaction.checkout_url,
        subscription_id: transaction.transaction_id, // Using transaction_id as subscription identifier
    }))
}

/// Cancel user's subscription
#[cfg(feature = "payment")]
pub async fn cancel_subscription(
    auth_session: CurrentAuthSession,
    State(_app_state): State<AppState>,
    AxumJson(_request): AxumJson<CancelSubscriptionRequest>,
) -> Result<AxumJson<SubscriptionResponse>, AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // TODO: This is a simplified implementation for now
    Ok(AxumJson(SubscriptionResponse {
        subscription: None,
        plan_features: None,
        usage_limits: None,
        customer_portal_url: None,
    }))
}

/// Reactivate user's subscription
#[cfg(feature = "payment")]
pub async fn reactivate_subscription(
    auth_session: CurrentAuthSession,
    State(_app_state): State<AppState>,
) -> Result<AxumJson<SubscriptionResponse>, AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // TODO: This is a simplified implementation for now
    Ok(AxumJson(SubscriptionResponse {
        subscription: None,
        plan_features: None,
        usage_limits: None,
        customer_portal_url: None,
    }))
}

/// Handle Paddle webhooks
#[cfg(feature = "payment")]
pub async fn paddle_webhook(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<AxumJson<WebhookResponse>, AppError> {
    // Start timing webhook processing (for security monitoring)
    let start_time = std::time::Instant::now();

    // Extract and anonymize client IP for security monitoring
    let client_ip = extract_and_anonymize_ip(&headers);

    tracing::info!(
        client_ip = %client_ip,
        "Received Paddle webhook"
    );

    // Log webhook metadata for debugging (payload contains PII and is not logged)
    tracing::debug!("Received webhook payload of {} bytes", body.len());

    // Log all headers for debugging
    tracing::debug!("Webhook headers: {:?}", headers);

    // 1. Check for Paddle-Signature header
    let signature = headers
        .get("Paddle-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("WEBHOOK ERROR: Missing Paddle-Signature header");
            AppError::BadRequest("Missing Paddle-Signature header".to_string())
        })?;

    tracing::debug!("Found signature: {}", signature);

    // 2. Create PaddleService to verify signature
    let paddle_service = PaddleService::new(app_state.config.payment.clone());
    tracing::debug!("Created PaddleService for signature verification");

    // 3. Verify webhook signature
    if let Err(e) = paddle_service.verify_webhook_signature(&body, signature) {
        tracing::error!(
            client_ip = %client_ip,
            "WEBHOOK ERROR: Signature verification failed: {}", e
        );

        // SECURITY MONITORING: Record webhook signature failure
        SECURITY_METRICS.record_webhook_signature_failure();

        // Log security event for attack detection
        let security_event = SecurityEvent::WebhookSignatureFailure {
            timestamp: crate::DbTimestamp::now(),
            ip_address: client_ip.clone(),
            endpoint: "/webhook/paddle".to_string(),
            user_agent: headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        };

        if let Ok(json) = security_event.to_json() {
            tracing::warn!(event_type = "security_event", severity = "P1", "{}", json);
        }

        return Err(e);
    }
    tracing::info!("Webhook signature verified successfully");

    // Create audit service for logging webhook events
    let audit_service = PaymentAuditService::new();

    // 4. Try to parse as generic JSON first to see the structure
    match serde_json::from_slice::<crate::DbJson>(&body) {
        Ok(raw_json) => {
            // Log sanitized structure (removes PII)
            let sanitized_json = sanitize_json_value(&raw_json);
            tracing::debug!(
                "Sanitized JSON structure: {}",
                serde_json::to_string_pretty(&sanitized_json).unwrap_or("unparseable".to_string())
            );

            // Check for different possible event_type field names
            if let Some(event_type) = raw_json.get("event_type") {
                tracing::debug!("Found event_type: {}", event_type);
            }
            if let Some(event_type) = raw_json.get("eventType") {
                tracing::debug!("Found eventType: {}", event_type);
            }
            if let Some(event_type) = raw_json.get("type") {
                tracing::debug!("Found type: {}", event_type);
            }
        }
        Err(e) => {
            tracing::error!("WEBHOOK ERROR: Cannot parse as JSON at all: {}", e);
            return Err(AppError::BadRequest(format!("Invalid JSON: {}", e)));
        }
    }

    // 5. Parse JSON payload as PaddleWebhook
    let webhook_data: PaddleWebhook = serde_json::from_slice(&body).map_err(|e| {
        tracing::error!("WEBHOOK ERROR: Failed to parse as PaddleWebhook: {}", e);
        AppError::BadRequest(format!("Invalid PaddleWebhook payload: {}", e))
    })?;

    tracing::debug!(
        "Successfully parsed webhook data: event_type={:?}, event_id={}",
        webhook_data.event_type,
        webhook_data.event_id
    );

    // ========================================================================
    // IDEMPOTENCY CHECK - Prevent duplicate webhook processing
    // ========================================================================
    // Calculate payload hash for tamper detection
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body.as_ref());
    let payload_hash = hex::encode(hasher.finalize());

    // Check if this event has already been processed
    let event_id = &webhook_data.event_id;
    let event_type_str = format!("{:?}", webhook_data.event_type);

    tracing::debug!(
        event_id = %event_id,
        event_type = %event_type_str,
        payload_hash = %payload_hash,
        "Checking for duplicate webhook event"
    );

    let conn_idempotency = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let event_id_clone = event_id.clone();
    let existing_event = conn_idempotency
        .interact(move |conn| {
            use crate::models::payment::WebhookEvent;
            use crate::schema::webhook_events::dsl;
            use diesel::prelude::*;

            dsl::webhook_events
                .filter(dsl::event_id.eq(event_id_clone))
                .select(WebhookEvent::as_select())
                .first::<WebhookEvent>(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to check for duplicate webhook: {}", e))
        })?;

    if let Some(existing) = existing_event {
        // Event already processed - check if payload and event type match
        if existing.payload_hash != payload_hash {
            // Payload hash mismatch detected
            if existing.event_type == event_type_str {
                // Same event_type but different payload = Tampering attempt
                tracing::warn!(
                    event_id = %event_id,
                    event_type = %event_type_str,
                    expected_hash = %existing.payload_hash,
                    received_hash = %payload_hash,
                    "Webhook replay detected with modified payload - rejecting"
                );
                return Err(AppError::BadRequest(
                    "Duplicate event_id with modified payload".to_string(),
                ));
            } else {
                // Different event_type = Shouldn't happen in Paddle but handle gracefully
                tracing::warn!(
                    event_id = %event_id,
                    original_event_type = %existing.event_type,
                    new_event_type = %event_type_str,
                    "Duplicate event_id across different event types detected (unusual but handling gracefully)"
                );
            }
        }

        // Return idempotent success (webhook already processed or duplicate event_id)
        tracing::info!(
            event_id = %event_id,
            event_type = %event_type_str,
            original_processed_at = %existing.processed_at,
            payload_match = %(existing.payload_hash == payload_hash),
            "Webhook already processed - returning idempotent success"
        );

        return Ok(AxumJson(WebhookResponse {
            success: true,
            message: "Webhook already processed (idempotent)".to_string(),
        }));
    }

    tracing::debug!(
        event_id = %event_id,
        "Webhook event is new - proceeding with processing"
    );

    // Log webhook event to audit log (privacy-focused)
    {
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let event_type_str = format!("{:?}", webhook_data.event_type);
        let external_ref = webhook_data
            .data
            .get("transaction")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Err(e) = conn
            .interact(move |conn| {
                audit_service.log_webhook_event(conn, &event_type_str, external_ref.as_deref())
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))
            .and_then(|r| r)
        {
            error!("Failed to audit log webhook event: {}", e);
            // Don't fail the webhook processing if audit logging fails
        }
    }

    // Clone app_state for event recording after processing
    let app_state_for_recording = app_state.clone();

    // 6. Process webhook based on event type
    match webhook_data.event_type {
        PaddleEventType::TransactionCompleted => {
            tracing::info!("Processing TransactionCompleted webhook");
            process_transaction_completed(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionCreated => {
            tracing::info!("Processing SubscriptionCreated webhook");
            process_subscription_created(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionUpdated => {
            tracing::info!("Processing SubscriptionUpdated webhook");
            process_subscription_updated(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionCancelled => {
            tracing::info!("Processing SubscriptionCancelled webhook");
            process_subscription_cancelled(app_state, &webhook_data).await?;
        }
        _ => {
            tracing::debug!(
                "Webhook event type {:?} not processed - acknowledged",
                webhook_data.event_type
            );
        }
    }

    tracing::info!("Webhook processed successfully");

    // ========================================================================
    // RECORD WEBHOOK EVENT - For idempotency tracking
    // ========================================================================
    // Record successful processing in webhook_events table
    let conn_record = app_state_for_recording
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let event_id_for_insert = event_id.clone();
    let event_type_for_insert = event_type_str.clone();
    let signature_for_insert = signature.to_string();
    let payload_hash_for_insert = payload_hash.clone();

    match conn_record
        .interact(move |conn| {
            use crate::models::payment::NewWebhookEvent;
            use crate::schema::webhook_events;
            use diesel::prelude::*;

            let new_event = NewWebhookEvent {
                event_id: event_id_for_insert,
                event_type: event_type_for_insert,
                paddle_signature: signature_for_insert,
                payload_hash: payload_hash_for_insert,
                processing_status: "processed".to_string(),
            };

            diesel::insert_into(webhook_events::table)
                .values(&new_event)
                .execute(conn)
        })
        .await
    {
        Ok(Ok(_)) => {
            tracing::info!(
                event_id = %event_id,
                event_type = %event_type_str,
                "Webhook event recorded for idempotency tracking"
            );
        }
        Ok(Err(e)) => {
            // This could fail if there's a race condition and another request
            // already inserted the same event_id (UNIQUE constraint violation)
            // That's OK - it means idempotency worked at the database level
            tracing::warn!(
                event_id = %event_id,
                "Failed to record webhook event (likely race condition with duplicate): {}",
                e
            );
            // Don't fail the request - the webhook was processed successfully
        }
        Err(e) => {
            tracing::error!(
                event_id = %event_id,
                "Failed to interact with database for event recording: {}",
                e
            );
            // Don't fail the request - the webhook was processed successfully
        }
    }

    // SECURITY MONITORING: Record webhook processing time
    let processing_duration = start_time.elapsed().as_secs_f64();
    SECURITY_METRICS.record_webhook_processing_time(processing_duration);

    tracing::info!(
        client_ip = %client_ip,
        processing_duration_seconds = processing_duration,
        "Webhook processed successfully"
    );

    Ok(AxumJson(WebhookResponse {
        success: true,
        message: "Webhook processed successfully".to_string(),
    }))
}

/// Handle payment completion page (/pay endpoint with ?_ptxn= parameter)
#[cfg(feature = "payment")]
pub async fn handle_pay_page(
    Query(query): Query<PayQuery>,
    State(app_state): State<AppState>,
) -> Result<axum::response::Response, AppError> {
    if let Some(transaction_id) = query._ptxn {
        tracing::debug!(
            "Payment completion detected for transaction: {}",
            transaction_id
        );

        // TODO: In the future, we could:
        // 1. Verify the transaction status with Paddle API
        // 2. Update local subscription records
        // 3. Redirect to success/failure page based on status
        // For now, we'll redirect to the frontend with the transaction ID

        // Fixed: Include /pay in the redirect URL to land on the correct page
        let redirect_url = format!(
            "{}/pay?transaction_id={}&status=success",
            app_state.config.frontend_base_url, transaction_id
        );

        let response = axum::response::Redirect::permanent(&redirect_url);
        Ok(response.into_response())
    } else {
        // No transaction parameter - this might be the initial payment page load
        // Redirect to frontend payment page
        let redirect_url = format!("{}/pay", app_state.config.frontend_base_url);
        let response = axum::response::Redirect::permanent(&redirect_url);
        Ok(response.into_response())
    }
}

/// Process transaction.completed webhook event
#[cfg(feature = "payment")]
async fn process_transaction_completed(
    app_state: AppState,
    webhook_data: &PaddleWebhook,
) -> Result<(), AppError> {
    tracing::debug!(
        "Processing transaction.completed webhook: {}",
        webhook_data.event_id
    );

    // Paddle sends transaction data directly in the data field (not nested under data.transaction)
    tracing::debug!("Step 1: Using webhook data directly as transaction");
    let transaction_data = &webhook_data.data;

    let transaction_id = transaction_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing transaction ID in webhook".to_string()))?
        .to_string();

    let customer_id = transaction_data
        .get("customer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing customer_id in webhook".to_string()))?
        .to_string();

    let status = transaction_data
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    tracing::debug!(
        "Transaction details - ID: {}, Customer: {}, Status: {}",
        transaction_id,
        customer_id,
        status
    );

    // Only process completed transactions
    if status != "completed" {
        tracing::debug!(
            "Transaction {} not completed (status: {}), skipping",
            transaction_id,
            status
        );
        return Ok(());
    }

    // Extract customer email for fallback user lookup
    tracing::debug!("Step 1a: Extracting customer email");
    let customer_email = webhook_data
        .data
        .get("customer")
        .and_then(|c| c.get("email"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(ref email) = customer_email {
        tracing::debug!(
            customer_email = %sanitize_personal_info(email),
            "Step 1a complete: Customer email found"
        );
    } else {
        tracing::debug!("Step 1a complete: No customer email found");
    }

    // Extract custom_data.user_id for additional fallback user lookup
    tracing::debug!("Step 1b: Extracting custom_data.user_id");
    let custom_data_user_id = transaction_data
        .get("custom_data")
        .and_then(|cd| cd.get("user_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| crate::db::DbId::parse_str(s).ok());
    if let Some(ref uid) = custom_data_user_id {
        tracing::debug!(
            custom_data_user_id = %uid,
            "Step 1b complete: custom_data.user_id found"
        );
    } else {
        tracing::debug!("Step 1b complete: No custom_data.user_id found");
    }

    // Find user by paddle_customer_id or email
    tracing::debug!(
        "Step 2: Finding user by paddle_customer_id: {}",
        customer_id
    );
    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let customer_id_for_closure = customer_id.clone();
    let customer_email_for_closure = customer_email.clone();
    let custom_data_user_id_for_closure = custom_data_user_id;

    use crate::schema::{payment_transactions, subscriptions, users};
    use diesel::prelude::*;

    let user_id = conn
        .interact(
            move |conn| -> Result<crate::db::DbId, diesel::result::Error> {
                // Try to find user from existing subscriptions
                if let Ok(subscription) = subscriptions::table
                    .filter(subscriptions::paddle_customer_id.eq(&customer_id_for_closure))
                    .select(subscriptions::user_id)
                    .first::<crate::db::DbId>(conn)
                {
                    tracing::debug!("Found user from existing subscription");
                    return Ok(subscription);
                }

                // Try to find user from payment transactions
                if let Ok(transaction) = payment_transactions::table
                    .filter(payment_transactions::paddle_customer_id.eq(&customer_id_for_closure))
                    .select(payment_transactions::user_id)
                    .first::<crate::db::DbId>(conn)
                {
                    tracing::debug!("Found user from payment transaction");
                    return Ok(transaction);
                }

                // Fallback: Try to find user by email
                if let Some(ref email) = customer_email_for_closure {
                    if let Ok(user) = users::table
                        .filter(users::email.eq(email))
                        .select(users::id)
                        .first::<crate::db::DbId>(conn)
                    {
                        tracing::debug!("Found user by email fallback");
                        return Ok(user);
                    }
                }

                // Fallback: Try to find user by custom_data.user_id
                if let Some(user_id) = custom_data_user_id_for_closure {
                    if let Ok(user) = users::table
                        .filter(users::id.eq(user_id))
                        .select(users::id)
                        .first::<crate::db::DbId>(conn)
                    {
                        tracing::debug!("Found user by custom_data.user_id fallback");
                        return Ok(user);
                    }
                }

                Err(diesel::result::Error::NotFound)
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Step 2 FAILED: Database interaction error: {}", e);
            AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
        })?;

    let user_id = match user_id {
        Ok(id) => {
            tracing::debug!("Step 2 complete: Found user_id: {}", id);
            id
        }
        Err(e) => {
            tracing::warn!(
                "Step 2: Could not find user for paddle_customer_id: {} (error: {:?}), skipping transaction processing",
                customer_id,
                e
            );
            return Ok(());
        }
    };

    // Get the full user record
    tracing::debug!("Step 3: Fetching full user record for user_id: {}", user_id);
    let user = match conn
        .interact(move |conn| crate::auth::find_user_by_id(conn, user_id))
        .await
    {
        Ok(Ok(user)) => {
            tracing::debug!("Step 3 complete: User found");
            user
        }
        Ok(Err(e)) => {
            tracing::error!(
                "Step 3 FAILED: User not found for user_id: {} (error: {:?})",
                user_id,
                e
            );
            return Ok(());
        }
        Err(e) => {
            return Err(AppError::DbInteractError(e.to_string()));
        }
    };

    tracing::debug!(
        "Found user {} for transaction {}",
        loggable_user_id(user.id),
        transaction_id
    );

    // Store transaction in our database for future verification
    {
        use crate::models::payment::NewPaymentTransaction;
        use crate::schema::payment_transactions;
        // use crate::auth::session_dek::SessionDek;
        use diesel::prelude::*;

        // Get payment encryption key from configuration
        // Note: We use a system-level encryption key rather than user DEK because
        // webhooks arrive without user authentication context
        let payment_key = app_state
            .config
            .payment
            .data_encryption_key
            .as_ref()
            .ok_or_else(|| {
                tracing::error!("Payment data encryption key not configured");
                AppError::ConfigurationError(
                    "Payment data encryption key not configured".to_string(),
                )
            })?;

        // Decode base64 key to bytes
        let payment_key_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payment_key)
                .map_err(|e| {
                    tracing::error!("Failed to decode payment encryption key: {}", e);
                    AppError::ConfigurationError(format!(
                        "Invalid payment encryption key format: {}",
                        e
                    ))
                })?;

        // Extract transaction details
        let total_cents = transaction_data
            .get("details")
            .and_then(|d| d.get("totals"))
            .and_then(|t| t.get("total"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        let tax_cents = transaction_data
            .get("details")
            .and_then(|d| d.get("totals"))
            .and_then(|t| t.get("tax"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let discount_cents = transaction_data
            .get("details")
            .and_then(|d| d.get("totals"))
            .and_then(|t| t.get("discount"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let currency_code = transaction_data
            .get("currency_code")
            .and_then(|v| v.as_str())
            .unwrap_or("USD")
            .to_string();

        let collection_mode = transaction_data
            .get("collection_mode")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let checkout_id = transaction_data
            .get("checkout")
            .and_then(|c| c.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let items = crate::db::Json(
            transaction_data
                .get("items")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        );

        // Prepare customer data for encryption (PII)
        let customer_data = serde_json::json!({
            "email": user.email.clone(),
            "name": transaction_data.get("customer").and_then(|c| c.get("name")),
            "billing_details": transaction_data.get("billing_details")
        });

        // Serialize customer data to JSON string for encryption
        let customer_data_json = serde_json::to_string(&customer_data)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        // Encrypt customer data with AES-256-GCM
        let (customer_data_encrypted, customer_data_nonce) = app_state
            .encryption_service
            .encrypt(&customer_data_json, &payment_key_bytes)?;

        tracing::debug!(
            transaction_id = %transaction_id,
            encrypted_size = customer_data_encrypted.len(),
            "Successfully encrypted customer data for transaction"
        );

        // Serialize full transaction data for encryption (for debugging/reconciliation)
        let paddle_data_json = serde_json::to_string(&transaction_data)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        // Encrypt full transaction data with AES-256-GCM
        let (paddle_data_encrypted, paddle_data_nonce) = app_state
            .encryption_service
            .encrypt(&paddle_data_json, &payment_key_bytes)?;

        tracing::debug!(
            transaction_id = %transaction_id,
            encrypted_size = paddle_data_encrypted.len(),
            "Successfully encrypted paddle transaction data"
        );

        // Parse timestamps
        let billed_at = transaction_data
            .get("billed_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| crate::DbTimestamp::from_datetime(dt.with_timezone(&chrono::Utc)));

        let completed_at = transaction_data
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| crate::DbTimestamp::from_datetime(dt.with_timezone(&chrono::Utc)));

        let new_transaction = NewPaymentTransaction {
            paddle_transaction_id: transaction_id.clone(),
            user_id: user.id,
            status: status.clone(),
            collection_mode,
            total_cents,
            tax_cents,
            discount_cents,
            currency_code: Some(currency_code),
            paddle_customer_id: Some(customer_id.clone()),
            customer_data_encrypted: Some(customer_data_encrypted),
            customer_data_nonce: Some(customer_data_nonce),
            items,
            checkout_id,
            billed_at,
            completed_at,
            paddle_data_encrypted: Some(paddle_data_encrypted),
            paddle_data_nonce: Some(paddle_data_nonce),
        };

        // Insert into database
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| {
            diesel::insert_into(payment_transactions::table)
                .values(&new_transaction)
                .execute(conn)
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to store transaction: {}", e)))?;

        tracing::debug!(
            "Successfully stored transaction {} in database",
            transaction_id
        );
    }

    // Extract price_id to determine plan type
    // Note: Paddle webhooks have two possible structures:
    // 1. Nested: items[0].price.id (newer structure)
    // 2. Flat: items[0].price_id (older structure)
    let price_data = transaction_data
        .get("items")
        .and_then(|items| items.as_array())
        .and_then(|items| items.first())
        .and_then(|item| {
            // Try nested structure first (items[0].price.id)
            item.get("price")
                .and_then(|price| price.get("id"))
                .and_then(|v| v.as_str())
                // Fallback to flat structure (items[0].price_id)
                .or_else(|| item.get("price_id").and_then(|v| v.as_str()))
        })
        .unwrap_or("unknown");

    // Map price_id to plan type (based on database plan_features table)
    let plan_type = match price_data {
        // Basic plan price IDs
        "pri_01k4qbyetvn495nzv9nkqhxz02" => "basic", // Basic monthly
        "pri_01k5ejs7h9zmw4d888r3pjjqna" => "basic", // Basic yearly

        // Premium plan price IDs
        "pri_01k5ej7wzvpcj6j65vcbpam6t4" => "premium", // Premium monthly
        "pri_01k5ejva0cwqzbtgzd2c9qk0d4" => "premium", // Premium yearly

        // Fallback patterns
        price_id if price_id.contains("basic") => "basic",
        price_id if price_id.contains("premium") => "premium",
        price_id if price_id.contains("enterprise") => "enterprise",
        _ => "free", // Default to free plan for unknown price IDs
    };

    // Extract Paddle subscription ID from transaction data
    // Try multiple possible locations where Paddle might include subscription_id
    let paddle_subscription_id = transaction_data
        .get("subscription_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            // Try looking in items array for subscription-based pricing
            transaction_data
                .get("items")
                .and_then(|items| items.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("price"))
                .and_then(|price| price.get("subscription_id"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            // Try looking directly in billing_details
            transaction_data
                .get("billing_details")
                .and_then(|bd| bd.get("subscription_id"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    if let Some(ref sub_id) = paddle_subscription_id {
        tracing::debug!(
            "Extracted paddle_subscription_id: {} from transaction {}",
            sub_id,
            transaction_id
        );
    } else {
        tracing::debug!(
            "No paddle_subscription_id found in transaction {} - checking if this is a credit purchase",
            transaction_id
        );

        // Primary: Check credit package mappings from config (resilient like subscription flow)
        // This protects against database sync issues and provides guaranteed uptime for core products
        let credit_package = if Some(price_data)
            == app_state
                .config
                .payment
                .paddle_credits_250_price_id
                .as_deref()
        {
            Some(("250 Credits", 250))
        } else if Some(price_data)
            == app_state
                .config
                .payment
                .paddle_credits_500_price_id
                .as_deref()
        {
            Some(("550 Credits", 550))
        } else if Some(price_data)
            == app_state
                .config
                .payment
                .paddle_credits_1500_price_id
                .as_deref()
        {
            Some(("1500 Credits", 1500))
        } else if Some(price_data)
            == app_state
                .config
                .payment
                .paddle_credits_3500_price_id
                .as_deref()
        {
            Some(("3500 Credits", 3500))
        } else if Some(price_data)
            == app_state
                .config
                .payment
                .paddle_credits_8000_price_id
                .as_deref()
        {
            Some(("8000 Credits", 8000))
        } else {
            None
        };

        if let Some((package_name, credits)) = credit_package {
            tracing::info!(
                "Credit purchase detected (config mapping): {} ({} credits) for user {} in transaction {}",
                package_name,
                credits,
                loggable_user_id(user.id),
                transaction_id
            );

            // Add credits to user account using config values
            let credit_service =
                crate::services::payment::CreditService::new(app_state.config.clone());

            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let user_id_for_credits = user.id;
            let credits_to_add = credits;
            let package_name_clone = package_name.to_string();
            let transaction_id_clone = transaction_id.clone();

            let add_credits_result = conn
                .interact(move |conn| {
                    credit_service.add_credits(
                        conn,
                        user_id_for_credits,
                        credits_to_add,
                        "purchase",
                        &format!("Credit package purchase: {}", package_name_clone),
                        Some(transaction_id_clone),
                        None,
                    )
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))?;

            // Log error if credit addition failed
            if let Err(e) = add_credits_result {
                tracing::error!(
                    "Failed to add credits for transaction {}: {:?}",
                    transaction_id,
                    e
                );
                return Err(e);
            }

            tracing::info!(
                "Successfully added {} credits to user {} from transaction {} (config mapping)",
                credits,
                loggable_user_id(user.id),
                transaction_id
            );

            // Credit purchase handled, no subscription to create
            return Ok(());
        }

        // Fallback: Check database for credit package purchase (maintains flexibility for dynamic pricing)
        let conn_credit_check = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let price_data_for_credit_check = price_data.to_string();
        let credit_package_result = conn_credit_check
            .interact(move |conn| {
                use crate::models::credit::CreditPackage;
                use crate::schema::credit_packages::dsl;
                use diesel::prelude::*;

                dsl::credit_packages
                    .filter(dsl::paddle_price_id.eq(&price_data_for_credit_check))
                    .filter(dsl::active.eq(true))
                    .select(CreditPackage::as_select())
                    .first::<CreditPackage>(conn)
                    .optional()
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        if let Some(credit_package) = credit_package_result {
            tracing::info!(
                "Credit purchase detected: {} ({} credits) for user {} in transaction {}",
                credit_package.name,
                credit_package.credits,
                loggable_user_id(user.id),
                transaction_id
            );

            // Add credits to user account
            let credit_service =
                crate::services::payment::CreditService::new(app_state.config.clone());

            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let user_id_for_credits = user.id;
            let credits_to_add = credit_package.credits;
            let package_name = credit_package.name.clone();
            let transaction_id_clone = transaction_id.clone();

            let add_credits_result = conn
                .interact(move |conn| {
                    credit_service.add_credits(
                        conn,
                        user_id_for_credits,
                        credits_to_add,
                        "purchase",
                        &format!("Credit package purchase: {}", package_name),
                        Some(transaction_id_clone),
                        None,
                    )
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))?;

            // Log error if credit addition failed
            if let Err(e) = add_credits_result {
                tracing::error!(
                    "Failed to add credits for transaction {}: {:?}",
                    transaction_id,
                    e
                );
                return Err(e);
            }

            tracing::info!(
                "Successfully added {} credits to user {} from transaction {}",
                credit_package.credits,
                loggable_user_id(user.id),
                transaction_id
            );

            // Credit purchase handled, no subscription to create
            return Ok(());
        } else {
            tracing::warn!(
                "Transaction {} has no subscription_id and doesn't match any credit package (price_id: {})",
                transaction_id,
                price_data
            );
        }
    }

    // Check for existing active subscription to prevent duplicates
    let conn_duplicate_check = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let existing_subscription = conn_duplicate_check
        .interact(move |conn| {
            use crate::models::payment::Subscription;
            use crate::schema::subscriptions::dsl as sub_dsl;
            use diesel::prelude::*;

            sub_dsl::subscriptions
                .filter(sub_dsl::user_id.eq(user.id))
                .filter(sub_dsl::status.ne("cancelled"))
                .select(Subscription::as_select())
                .first::<Subscription>(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    if let Some(existing) = existing_subscription {
        tracing::warn!(
            "User {} already has an active subscription {} ({}), webhook for transaction {} will update existing subscription",
            user.id,
            existing.id,
            existing.plan_type,
            transaction_id
        );

        // Update existing subscription instead of creating a duplicate

        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let existing_id = existing.id;
        let plan_type_str = plan_type.to_string();
        let customer_id_str = customer_id.to_string();
        let paddle_sub_id_clone = paddle_subscription_id.clone();

        // Detect trial-to-paid conversion for payment tracking
        let is_trial_to_paid = existing.status == "trialing";
        let has_ever_paid_for_update = if is_trial_to_paid {
            Some(true)
        } else {
            existing.has_ever_paid.or(Some(false))
        };
        let first_payment_date_for_update = if is_trial_to_paid {
            Some(crate::DbTimestamp::now())
        } else {
            existing.first_payment_date
        };

        if is_trial_to_paid {
            tracing::info!(
                "Trial-to-paid conversion via transaction for subscription {} (user: {}, transaction: {})",
                existing.id,
                loggable_user_id(user.id),
                transaction_id
            );
        }

        tracing::debug!(
            "Updating existing subscription {} from {} to {} for user {} (paddle_subscription_id: {:?})",
            existing.id,
            existing.plan_type,
            plan_type,
            user.id,
            paddle_subscription_id
        );

        let updated_subscription = conn
            .interact(move |conn| {
                use crate::models::payment::Subscription;
                use crate::schema::subscriptions::dsl as sub_dsl;
                use diesel::prelude::*;

                diesel::update(sub_dsl::subscriptions.find(existing_id))
                    .set((
                        sub_dsl::plan_type.eq(plan_type_str),
                        sub_dsl::paddle_customer_id.eq(Some(customer_id_str)),
                        sub_dsl::paddle_subscription_id.eq(paddle_sub_id_clone),
                        sub_dsl::status.eq("active"),
                        sub_dsl::has_ever_paid.eq(has_ever_paid_for_update),
                        sub_dsl::first_payment_date.eq(first_payment_date_for_update),
                        sub_dsl::updated_at.eq(chrono::Utc::now()),
                    ))
                    .returning(Subscription::as_returning())
                    .get_result::<Subscription>(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        tracing::debug!(
            "Successfully updated existing subscription {} for user {} from transaction {}",
            updated_subscription.id,
            loggable_user_id(user.id),
            transaction_id
        );
    } else {
        tracing::debug!(
            "Creating new {} subscription for user {} (price_id: {})",
            plan_type,
            user.id,
            price_data
        );

        // Create subscription record
        let subscription_service = crate::services::payment::SubscriptionService::new(
            (*app_state.config).clone(),
            (*app_state.encryption_service).clone(),
        );

        let conn_clone = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let paddle_sub_id_for_create = paddle_subscription_id.clone();
        let subscription = conn_clone
            .interact(move |conn| {
                subscription_service.create_subscription_sync(
                    conn,
                    user.id,
                    plan_type,
                    Some(customer_id.clone()),
                    paddle_sub_id_for_create, // Pass extracted paddle subscription ID
                    None,                     // No trial for transaction-based billing
                )
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))??;

        tracing::debug!(
            "Successfully created subscription {} for user {} from transaction {}",
            subscription.id,
            loggable_user_id(user.id),
            transaction_id
        );
    }

    // Log successful payment event to audit log
    {
        // Get amount from transaction data
        let total_cents = transaction_data
            .get("details")
            .and_then(|d| d.get("totals"))
            .and_then(|t| t.get("total"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        let audit_service = PaymentAuditService::new();
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        if let Err(e) = conn
            .interact(move |conn| {
                audit_service.log_payment_event(
                    conn,
                    user.id,
                    total_cents,
                    true, // success
                    None, // no error code
                    Some(&transaction_id),
                )
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))
            .and_then(|r| r)
        {
            error!("Failed to audit log payment event: {}", e);
            // Don't fail the webhook processing if audit logging fails
        }
    }

    // Grant monthly credits for the subscription tier
    // This ensures users immediately receive their tier's monthly allocation
    {
        tracing::debug!(
            "Granting monthly credits for {} tier to user {}",
            plan_type,
            loggable_user_id(user.id)
        );

        let credit_service = CreditService::new(app_state.config.clone());
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let user_id_for_credits = user.id;
        let plan_type_for_credits = plan_type.to_string();

        match conn
            .interact(move |conn| {
                credit_service.grant_monthly_credits(
                    conn,
                    user_id_for_credits,
                    &plan_type_for_credits,
                )
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))
            .and_then(|r| r)
        {
            Ok(balance) => {
                tracing::info!(
                    "Successfully granted monthly credits to user {}. New balance: {}",
                    loggable_user_id(user.id),
                    balance.balance
                );
            }
            Err(e) => {
                error!(
                    "Failed to grant monthly credits for user {} ({}): {}",
                    loggable_user_id(user.id),
                    plan_type,
                    e
                );
                // Don't fail the webhook if credit granting fails
                // The scheduler will retry later
            }
        }
    }

    Ok(())
}

/// Process subscription.created webhook event
#[cfg(feature = "payment")]
async fn process_subscription_created(
    app_state: AppState,
    webhook_data: &PaddleWebhook,
) -> Result<(), AppError> {
    tracing::debug!(
        "Processing subscription.created webhook: {}",
        webhook_data.event_id
    );

    // Extract subscription data from the webhook payload
    // For subscription.created events, the subscription data is directly in the data field
    // NOT nested under data.subscription (Paddle sends the entity directly in data)
    tracing::debug!("Step 1: Extracting subscription data from webhook");
    let subscription_data = &webhook_data.data;
    tracing::debug!("Step 1 complete: Using subscription data directly from data field");

    tracing::debug!("Step 2: Extracting subscription ID");
    let subscription_id = subscription_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("Missing 'id' field in subscription data");
            AppError::BadRequest("Missing subscription ID in webhook".to_string())
        })?
        .to_string();
    tracing::debug!("Step 2 complete: Subscription ID: {}", subscription_id);

    tracing::debug!("Step 3: Extracting customer ID");
    let customer_id = subscription_data
        .get("customer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("Missing 'customer_id' field in subscription data");
            AppError::BadRequest("Missing customer_id in webhook".to_string())
        })?
        .to_string();
    tracing::debug!("Step 3 complete: Customer ID: {}", customer_id);

    tracing::debug!("Step 4: Extracting status");
    let status = subscription_data
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    tracing::debug!("Step 4 complete: Status: {}", status);

    tracing::debug!(
        "Subscription details - ID: {}, Customer: {}, Status: {}",
        subscription_id,
        customer_id,
        status
    );

    // Extract plan type from subscription items
    tracing::debug!("Step 5: Extracting plan type from subscription items");
    let plan_type = subscription_data
        .get("items")
        .and_then(|items| items.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("price"))
        .and_then(|price| price.get("id"))
        .and_then(|v| v.as_str())
        .map(|price_id| {
            match price_id {
                // Basic plan price IDs
                "pri_01k4qbyetvn495nzv9nkqhxz02" => "basic", // Basic monthly
                "pri_01k5ejs7h9zmw4d888r3pjjqna" => "basic", // Basic yearly

                // Premium plan price IDs
                "pri_01k5ej7wzvpcj6j65vcbpam6t4" => "premium", // Premium monthly
                "pri_01k5ejva0cwqzbtgzd2c9qk0d4" => "premium", // Premium yearly

                // Fallback patterns
                price_id if price_id.contains("basic") => "basic",
                price_id if price_id.contains("premium") => "premium",
                price_id if price_id.contains("enterprise") => "enterprise",
                _ => "free", // Default to free plan for unknown price IDs
            }
        })
        .unwrap_or("free");

    tracing::debug!("Step 5 complete: Mapped to plan type: {}", plan_type);

    // Extract trial information - calculate trial days if subscription is in trialing status
    tracing::debug!("Step 6: Extracting trial information (status: {})", status);
    let trial_days = if status == "trialing" {
        subscription_data
            .get("scheduled_change")
            .and_then(|sc| sc.get("effective_at"))
            .or_else(|| subscription_data.get("next_billed_at"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|trial_end_dt| {
                let trial_end = trial_end_dt.with_timezone(&chrono::Utc);
                let now = chrono::Utc::now();
                let duration = trial_end.signed_duration_since(now);
                duration.num_days() as i32
            })
    } else {
        None
    };

    if let Some(days) = trial_days {
        tracing::debug!(
            "Step 6 complete: Subscription has {} days remaining in trial",
            days
        );
    } else {
        tracing::debug!("Step 6 complete: No trial period (status: {})", status);
    }

    // Extract trial_end date (actual DateTime, not just days)
    tracing::debug!("Step 6a: Extracting trial_end date");
    let trial_end = if status == "trialing" {
        subscription_data
            .get("scheduled_change")
            .and_then(|sc| sc.get("effective_at"))
            .or_else(|| subscription_data.get("next_billed_at"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
    } else {
        None
    };

    if let Some(end) = &trial_end {
        tracing::debug!("Step 6a complete: Trial ends at: {}", end);
    } else {
        tracing::debug!("Step 6a complete: No trial_end date");
    }

    // Extract current billing period dates
    tracing::debug!("Step 6b: Extracting current_period_start and current_period_end");
    let current_period_start = subscription_data
        .get("current_billing_period")
        .and_then(|cbp| cbp.get("starts_at"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let current_period_end = subscription_data
        .get("current_billing_period")
        .and_then(|cbp| cbp.get("ends_at"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if let (Some(start), Some(end)) = (&current_period_start, &current_period_end) {
        tracing::debug!("Step 6b complete: Billing period: {} to {}", start, end);
    } else {
        tracing::debug!("Step 6b complete: No billing period dates found");
    }

    // Extract customer email for fallback user lookup
    tracing::debug!("Step 6c: Extracting customer email");
    let customer_email = webhook_data
        .data
        .get("customer")
        .and_then(|c| c.get("email"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(ref email) = customer_email {
        tracing::debug!(
            customer_email = %sanitize_personal_info(email),
            "Step 6c complete: Customer email found"
        );
    } else {
        tracing::debug!("Step 6c complete: No customer email found");
    }

    // Find user by paddle_customer_id or email
    tracing::debug!("Step 7: Getting database connection from pool");
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        tracing::error!("Step 7 FAILED: Failed to get DB connection: {}", e);
        AppError::DbPoolError(e.to_string())
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        tracing::error!("Step 7 FAILED: Failed to get DB connection: {}", e);
        AppError::DbPoolError(e.to_string())
    })?;
    tracing::debug!("Step 7 complete: Database connection obtained");

    // Look up user by paddle_customer_id from existing subscriptions or transactions, or by email
    tracing::debug!(
        "Step 8: Finding user by paddle_customer_id: {}",
        customer_id
    );
    let customer_id_for_closure = customer_id.clone();
    let customer_email_for_closure = customer_email.clone();

    use crate::schema::{payment_transactions, subscriptions, users};
    use diesel::prelude::*;

    let user_id = conn
        .interact(
            move |conn| -> Result<crate::db::DbId, diesel::result::Error> {
                // Try to find user from existing subscriptions
                if let Ok(subscription) = subscriptions::table
                    .filter(subscriptions::paddle_customer_id.eq(&customer_id_for_closure))
                    .select(subscriptions::user_id)
                    .first::<crate::db::DbId>(conn)
                {
                    tracing::debug!("Found user from existing subscription");
                    return Ok(subscription);
                }

                // Try to find user from payment transactions
                if let Ok(transaction) = payment_transactions::table
                    .filter(payment_transactions::paddle_customer_id.eq(&customer_id_for_closure))
                    .select(payment_transactions::user_id)
                    .first::<crate::db::DbId>(conn)
                {
                    tracing::debug!("Found user from payment transaction");
                    return Ok(transaction);
                }

                // Fallback: Try to find user by email
                if let Some(ref email) = customer_email_for_closure {
                    if let Ok(user) = users::table
                        .filter(users::email.eq(email))
                        .select(users::id)
                        .first::<crate::db::DbId>(conn)
                    {
                        tracing::debug!("Found user by email fallback");
                        return Ok(user);
                    }
                }

                Err(diesel::result::Error::NotFound)
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Step 8 FAILED: Database interaction error: {}", e);
            AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
        })?;

    let user_id = match user_id {
        Ok(id) => {
            tracing::debug!("Step 8 complete: Found user_id: {}", id);
            id
        }
        Err(e) => {
            tracing::warn!(
                "Step 8: Could not find user for paddle_customer_id: {} (error: {:?}), skipping subscription creation",
                customer_id,
                e
            );
            return Ok(());
        }
    };

    // Get the full user record
    tracing::debug!("Step 9: Fetching full user record for user_id: {}", user_id);
    let user = match conn
        .interact(move |conn| crate::auth::find_user_by_id(conn, user_id))
        .await
    {
        Ok(Ok(user)) => {
            tracing::debug!("Step 9 complete: User found");
            user
        }
        Ok(Err(e)) => {
            tracing::error!(
                "Step 9 FAILED: User not found for user_id: {} (error: {:?})",
                user_id,
                e
            );
            return Ok(());
        }
        Err(e) => {
            tracing::error!("Step 9 FAILED: Database interaction error: {}", e);
            return Err(AppError::DbInteractError(e.to_string()));
        }
    };

    tracing::debug!(
        "Found user {} for subscription {}",
        loggable_user_id(user.id),
        subscription_id
    );

    // Check for existing active subscription to prevent duplicates
    tracing::debug!("Step 10: Checking for existing active subscription");
    let conn_duplicate_check = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        tracing::error!(
            "Step 10 FAILED: Failed to get DB connection for duplicate check: {}",
            e
        );
        AppError::DbPoolError(e.to_string())
    })?;

    let user_id_for_check = user.id;
    let existing_subscription = conn_duplicate_check
        .interact(move |conn| {
            use crate::models::payment::Subscription;
            use crate::schema::subscriptions::dsl as sub_dsl;
            use diesel::prelude::*;

            sub_dsl::subscriptions
                .filter(sub_dsl::user_id.eq(user_id_for_check))
                .filter(sub_dsl::status.ne("cancelled"))
                .select(Subscription::as_select())
                .first::<Subscription>(conn)
                .optional()
        })
        .await
        .map_err(|e| {
            tracing::error!(
                "Step 10 FAILED: Database interaction error during duplicate check: {}",
                e
            );
            AppError::DbInteractError(e.to_string())
        })?
        .map_err(|e| {
            tracing::error!(
                "Step 10 FAILED: Database query error during duplicate check: {}",
                e
            );
            AppError::DatabaseQueryError(e.to_string())
        })?;

    if let Some(existing) = existing_subscription {
        tracing::debug!(
            "Step 10 complete: Found existing active subscription {} ({}) for user {}",
            existing.id,
            existing.plan_type,
            user.id
        );
        tracing::warn!(
            "User {} already has an active subscription {} ({}), webhook for subscription {} will update existing subscription",
            user.id,
            existing.id,
            existing.plan_type,
            subscription_id
        );

        // Update existing subscription instead of creating a duplicate
        tracing::debug!(
            "Step 11: Updating existing subscription {} to plan {} with Paddle subscription ID {}",
            existing.id,
            plan_type,
            subscription_id
        );
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
            tracing::error!(
                "Step 11 FAILED: Failed to get DB connection for update: {}",
                e
            );
            AppError::DbPoolError(e.to_string())
        })?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
            tracing::error!(
                "Step 11 FAILED: Failed to get DB connection for update: {}",
                e
            );
            AppError::DbPoolError(e.to_string())
        })?;

        let existing_id = existing.id;
        let plan_type_str = plan_type.to_string();
        let customer_id_str = customer_id.clone();
        let subscription_id_str = subscription_id.clone();

        // Prepare date fields for update
        // current_period_start and current_period_end are required fields, so provide defaults if not in webhook
        let now = chrono::Utc::now();
        let period_start_for_update = current_period_start.unwrap_or(now);
        let period_end_for_update = current_period_end.unwrap_or(now + chrono::Duration::days(30));
        // trial_end is optional, so None is valid
        let trial_end_for_update = trial_end;

        tracing::debug!(
            "Updating existing subscription {} from {} to {} for user {} (paddle_subscription_id: {})",
            existing.id,
            existing.plan_type,
            plan_type,
            user.id,
            subscription_id
        );
        tracing::debug!(
            "Date fields for update - trial_end: {:?}, period_start: {}, period_end: {}",
            trial_end_for_update,
            period_start_for_update,
            period_end_for_update
        );

        let updated_subscription = conn
            .interact(move |conn| {
                use crate::models::payment::Subscription;
                use crate::schema::subscriptions::dsl as sub_dsl;
                use diesel::prelude::*;

                diesel::update(sub_dsl::subscriptions.find(existing_id))
                    .set((
                        sub_dsl::plan_type.eq(plan_type_str),
                        sub_dsl::paddle_customer_id.eq(Some(customer_id_str)),
                        sub_dsl::paddle_subscription_id.eq(Some(subscription_id_str)),
                        sub_dsl::status.eq(&status),
                        sub_dsl::trial_end.eq(trial_end_for_update),
                        sub_dsl::current_period_start.eq(period_start_for_update),
                        sub_dsl::current_period_end.eq(period_end_for_update),
                        sub_dsl::updated_at.eq(chrono::Utc::now()),
                    ))
                    .returning(Subscription::as_returning())
                    .get_result::<Subscription>(conn)
            })
            .await
            .map_err(|e| {
                tracing::error!(
                    "Step 11 FAILED: Database interaction error during update: {}",
                    e
                );
                AppError::DbInteractError(e.to_string())
            })?
            .map_err(|e| {
                tracing::error!("Step 11 FAILED: Database query error during update: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        tracing::debug!(
            "Step 11 complete: Successfully updated subscription {} (plan_type: {}, paddle_subscription_id: {})",
            updated_subscription.id,
            updated_subscription.plan_type,
            updated_subscription
                .paddle_subscription_id
                .as_ref()
                .unwrap_or(&"None".to_string())
        );
        tracing::debug!(
            "Successfully updated existing subscription {} for user {} from subscription.created webhook",
            updated_subscription.id,
            loggable_user_id(user.id)
        );
    } else {
        tracing::debug!(
            "Step 10 complete: No existing active subscription found for user {}",
            user.id
        );
        tracing::debug!(
            "Creating new {} subscription for user {} from subscription.created webhook",
            plan_type,
            user.id
        );

        // Create subscription record
        tracing::debug!(
            "Step 11: Creating new subscription for user {} with plan {}",
            user.id,
            plan_type
        );
        let subscription_service = crate::services::payment::SubscriptionService::new(
            (*app_state.config).clone(),
            (*app_state.encryption_service).clone(),
        );

        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
            tracing::error!(
                "Step 11 FAILED: Failed to get DB connection for create: {}",
                e
            );
            AppError::DbPoolError(e.to_string())
        })?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
            tracing::error!(
                "Step 11 FAILED: Failed to get DB connection for create: {}",
                e
            );
            AppError::DbPoolError(e.to_string())
        })?;

        // Clone subscription_id for logging after closure
        let subscription_id_for_service = subscription_id.clone();
        let subscription = conn
            .interact(move |conn| {
                subscription_service.create_subscription_sync(
                    conn,
                    user.id,
                    plan_type,
                    Some(customer_id),
                    Some(subscription_id_for_service.clone()), // Pass Paddle subscription ID
                    trial_days,                                // Pass trial days if present
                )
            })
            .await
            .map_err(|e| {
                tracing::error!(
                    "Step 11 FAILED: Database interaction error during create: {}",
                    e
                );
                AppError::DbInteractError(e.to_string())
            })?
            .map_err(|e| {
                tracing::error!("Step 11 FAILED: Subscription creation error: {}", e);
                e
            })?;

        tracing::debug!(
            "Step 11 complete: Successfully created subscription {} (plan_type: {}, paddle_subscription_id: {})",
            subscription.id,
            subscription.plan_type,
            subscription
                .paddle_subscription_id
                .as_ref()
                .unwrap_or(&"None".to_string())
        );
        tracing::debug!(
            "Successfully created subscription {} for user {} from subscription.created webhook",
            subscription.id,
            loggable_user_id(user.id)
        );
    }

    tracing::debug!(
        "process_subscription_created completed successfully for subscription {}",
        subscription_id
    );
    Ok(())
}

/// Process subscription.updated webhook event
#[cfg(feature = "payment")]
async fn process_subscription_updated(
    app_state: AppState,
    webhook_data: &PaddleWebhook,
) -> Result<(), AppError> {
    tracing::debug!(
        "Processing subscription.updated webhook: {}",
        webhook_data.event_id
    );

    // Extract subscription data from the webhook payload
    // Paddle sends the subscription data directly in the data field, not nested
    let subscription_data = &webhook_data.data;

    let paddle_subscription_id = subscription_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing subscription ID in webhook".to_string()))?
        .to_string();

    let status = subscription_data
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing subscription status in webhook".to_string()))?
        .to_string();

    tracing::debug!(
        "Subscription update details - ID: {}, Status: {}",
        paddle_subscription_id,
        status
    );

    // Extract trial_end date (actual DateTime, not just days)
    let trial_end = if status == "trialing" {
        subscription_data
            .get("scheduled_change")
            .and_then(|sc| sc.get("effective_at"))
            .or_else(|| subscription_data.get("next_billed_at"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
    } else {
        None
    };

    // Extract current billing period dates
    let current_period_start = subscription_data
        .get("current_billing_period")
        .and_then(|cbp| cbp.get("starts_at"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let current_period_end = subscription_data
        .get("current_billing_period")
        .and_then(|cbp| cbp.get("ends_at"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if let Some(end) = &trial_end {
        tracing::debug!("Trial ends at: {}", end);
    }
    if let (Some(start), Some(end)) = (&current_period_start, &current_period_end) {
        tracing::debug!("Billing period: {} to {}", start, end);
    }

    // Find subscription by paddle_subscription_id
    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let paddle_subscription_id_for_closure = paddle_subscription_id.clone();
    let subscription = conn
        .interact(move |conn| {
            use crate::schema::subscriptions;
            use diesel::prelude::*;
            subscriptions::table
                .filter(
                    subscriptions::paddle_subscription_id.eq(&paddle_subscription_id_for_closure),
                )
                .select(crate::models::payment::Subscription::as_select())
                .first(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    if let Some(subscription) = subscription {
        tracing::debug!(
            "Found subscription {} for paddle_subscription_id: {}, updating",
            subscription.id,
            paddle_subscription_id
        );

        // Update subscription with new data
        let subscription_id = subscription.id;
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // Determine cancel_at_period_end based on status
        // Note: Paddle uses "canceled" (US spelling) not "cancelled" (UK spelling)
        let cancel_at_period_end = status == "canceled";

        // Prepare date fields for the closure
        // Keep existing values if not provided in webhook
        let trial_end_for_update = trial_end
            .map(crate::DbTimestamp::from_datetime)
            .or(subscription.trial_end);
        let period_start_for_update = current_period_start
            .map(crate::DbTimestamp::from_datetime)
            .unwrap_or(subscription.current_period_start);
        let period_end_for_update = current_period_end
            .map(crate::DbTimestamp::from_datetime)
            .unwrap_or(subscription.current_period_end);

        // Detect trial-to-paid conversion and set payment tracking fields
        // When status transitions from "trialing" to "active", this is the first payment
        let is_trial_conversion = subscription.status == "trialing" && status == "active";
        let has_ever_paid_for_update = if is_trial_conversion {
            Some(true)
        } else {
            subscription.has_ever_paid
        };
        let first_payment_date_for_update = if is_trial_conversion {
            Some(period_start_for_update)
        } else {
            subscription.first_payment_date
        };

        if is_trial_conversion {
            tracing::info!(
                "Trial-to-paid conversion detected for subscription {} (paddle_subscription_id: {})",
                subscription.id,
                paddle_subscription_id
            );
        }

        // Clone status for use in the closure and later logging
        let status_for_update = status.clone();

        // Calculate grace_period_end if status is past_due
        let grace_period_end_for_update: Option<crate::DbTimestamp> = if status == "past_due" {
            let grace_period_days = app_state.config.payment.grace_period_days as i64;
            Some(crate::DbTimestamp::from_datetime(
                chrono::Utc::now() + chrono::Duration::days(grace_period_days),
            ))
        } else if status == "active" {
            // Clear grace_period_end when subscription becomes active again
            None
        } else {
            // Keep existing value - we'll handle this by not updating the field
            subscription.grace_period_end
        };

        let updated_subscription = conn
            .interact(move |conn| {
                use crate::schema::subscriptions;
                use diesel::prelude::*;
                diesel::update(subscriptions::table.find(subscription_id))
                    .set((
                        subscriptions::status.eq(&status_for_update),
                        subscriptions::trial_end.eq(trial_end_for_update),
                        subscriptions::current_period_start.eq(period_start_for_update),
                        subscriptions::current_period_end.eq(period_end_for_update),
                        subscriptions::cancel_at_period_end.eq(cancel_at_period_end),
                        subscriptions::has_ever_paid.eq(has_ever_paid_for_update),
                        subscriptions::first_payment_date.eq(first_payment_date_for_update),
                        subscriptions::grace_period_end.eq(grace_period_end_for_update),
                        subscriptions::updated_at.eq(chrono::Utc::now()),
                    ))
                    .returning(crate::models::payment::Subscription::as_returning())
                    .get_result(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        tracing::debug!(
            "Successfully updated subscription {} (paddle_subscription_id: {}, status: {})",
            updated_subscription.id,
            paddle_subscription_id,
            status
        );

        // PLAN CHANGE DETECTION: Check if price_id indicates a plan change
        if let Some(items) = subscription_data.get("items").and_then(|v| v.as_array()) {
            if let Some(first_item) = items.first() {
                if let Some(price_id) = first_item
                    .get("price")
                    .and_then(|p| p.get("id"))
                    .and_then(|id| id.as_str())
                {
                    tracing::debug!("Detected price_id in subscription.updated: {}", price_id);

                    // Map price_id to plan_type
                    match map_price_id_to_plan(price_id, &app_state.config) {
                        Ok(new_plan) => {
                            let old_plan = &updated_subscription.plan_type;

                            // Only process if plan actually changed
                            if new_plan != *old_plan {
                                tracing::info!(
                                    "Plan change detected: {} -> {} for user {}",
                                    old_plan,
                                    new_plan,
                                    updated_subscription.user_id
                                );

                                // Determine upgrade or downgrade
                                match is_higher_tier(&new_plan, old_plan) {
                                    Ok(is_upgrade) => {
                                        let conn = crate::db::get_conn(&app_state.pool)
                                            .await
                                            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

                                        let credit_service =
                                            Arc::new(CreditService::new(app_state.config.clone()));
                                        let audit_service = Arc::new(PaymentAuditService::new());
                                        let subscription_for_handler = updated_subscription.clone();
                                        let new_plan_clone = new_plan.clone();
                                        let old_plan_clone = old_plan.clone();
                                        let config_clone = app_state.config.clone();

                                        if is_upgrade {
                                            // Handle immediate upgrade
                                            if let Err(e) = conn
                                                .interact(move |conn| {
                                                    handle_plan_upgrade(
                                                        conn,
                                                        &subscription_for_handler,
                                                        &new_plan_clone,
                                                        &old_plan_clone,
                                                        &config_clone,
                                                        &credit_service,
                                                        &audit_service,
                                                    )
                                                })
                                                .await
                                                .map_err(|e| {
                                                    AppError::DbInteractError(e.to_string())
                                                })?
                                            {
                                                error!(
                                                    "Failed to process plan upgrade {} -> {}: {}",
                                                    old_plan, new_plan, e
                                                );
                                                // Don't block webhook processing on upgrade failure
                                            }
                                        } else {
                                            // Handle scheduled downgrade
                                            if let Err(e) = conn
                                                .interact(move |conn| {
                                                    handle_plan_downgrade(
                                                        conn,
                                                        &subscription_for_handler,
                                                        &new_plan_clone,
                                                        &old_plan_clone,
                                                        &audit_service,
                                                    )
                                                })
                                                .await
                                                .map_err(|e| {
                                                    AppError::DbInteractError(e.to_string())
                                                })?
                                            {
                                                error!(
                                                    "Failed to schedule plan downgrade {} -> {}: {}",
                                                    old_plan, new_plan, e
                                                );
                                                // Don't block webhook processing on downgrade failure
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to determine upgrade/downgrade for {} -> {}: {}",
                                            old_plan, new_plan, e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to map price_id {} to plan_type: {}. Continuing with status update only.",
                                price_id, e
                            );
                            // Continue processing - the status update was successful
                        }
                    }
                }
            }
        }

        // Log update in audit log
        use crate::services::payment::PaymentAuditService;
        let audit_service = PaymentAuditService::new();
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let user_id = subscription.user_id;
        let audit_event_type = match status.as_str() {
            "active" => crate::services::payment::AuditEventType::SubscriptionActivated,
            "canceled" => crate::services::payment::AuditEventType::SubscriptionCancelled,
            "paused" => crate::services::payment::AuditEventType::SubscriptionPaused,
            _ => crate::services::payment::AuditEventType::SubscriptionUpdated,
        };

        if let Err(e) = conn
            .interact(move |conn| {
                audit_service.log_subscription_event(
                    conn,
                    user_id,
                    audit_event_type,
                    Some(&paddle_subscription_id),
                )
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))
            .and_then(|r| r)
        {
            tracing::error!("Failed to audit log subscription update: {}", e);
            // Don't fail the webhook processing if audit logging fails
        }

        // Grant monthly credits on trial-to-paid conversion or subscription activation
        if is_trial_conversion || (status == "active" && subscription.status != "active") {
            tracing::debug!(
                "Granting monthly credits for {} tier to user {} (trial_conversion: {}, activation: {})",
                subscription.plan_type,
                loggable_user_id(subscription.user_id),
                is_trial_conversion,
                status == "active" && subscription.status != "active"
            );

            let credit_service = CreditService::new(app_state.config.clone());
            let conn = app_state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let user_id_for_credits = subscription.user_id;
            let plan_type_for_credits = subscription.plan_type.clone();

            match conn
                .interact(move |conn| {
                    credit_service.grant_monthly_credits(
                        conn,
                        user_id_for_credits,
                        &plan_type_for_credits,
                    )
                })
                .await
                .map_err(|e| AppError::DbInteractError(e.to_string()))
                .and_then(|r| r)
            {
                Ok(balance) => {
                    tracing::info!(
                        "Successfully granted monthly credits to user {}. New balance: {}",
                        loggable_user_id(subscription.user_id),
                        balance.balance
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to grant monthly credits for user {} ({}): {}",
                        loggable_user_id(subscription.user_id),
                        subscription.plan_type,
                        e
                    );
                    // Don't fail the webhook if credit granting fails
                    // The scheduler will retry later
                }
            }
        }
    } else {
        tracing::warn!(
            "Subscription not found for paddle_subscription_id: {}, ignoring update webhook",
            paddle_subscription_id
        );
    }

    Ok(())
}

/// Map Paddle price_id to plan_type by reading subscription_tiers.json
#[cfg(feature = "payment")]
fn map_price_id_to_plan(
    price_id: &str,
    config: &crate::config::Config,
) -> Result<String, AppError> {
    let config_path = &config.payment.subscription_config_path;
    let config_str = std::fs::read_to_string(config_path).map_err(|e| {
        AppError::ConfigurationError(format!("Failed to load subscription config: {}", e))
    })?;

    let tiers: crate::DbJson = serde_json::from_str(&config_str).map_err(|e| {
        AppError::ConfigurationError(format!("Invalid subscription config JSON: {}", e))
    })?;

    // Search all tiers for matching price_id
    if let Some(tiers_obj) = tiers["tiers"].as_object() {
        for (tier_name, tier_data) in tiers_obj {
            // Check monthly price_id
            if let Some(monthly_id) = tier_data
                .get("paddle_price_id_monthly")
                .and_then(|v| v.as_str())
            {
                if monthly_id == price_id {
                    return Ok(tier_name.to_string());
                }
            }
            // Check yearly price_id
            if let Some(yearly_id) = tier_data
                .get("paddle_price_id_yearly")
                .and_then(|v| v.as_str())
            {
                if yearly_id == price_id {
                    return Ok(tier_name.to_string());
                }
            }
        }
    }

    Err(AppError::BadRequest(format!(
        "Unknown price_id: {}",
        price_id
    )))
}

/// Check if new_plan is higher tier than old_plan
#[cfg(feature = "payment")]
fn is_higher_tier(new_plan: &str, old_plan: &str) -> Result<bool, AppError> {
    let tier_order = vec!["free", "basic", "premium"];

    let new_idx = tier_order
        .iter()
        .position(|&p| p == new_plan)
        .ok_or_else(|| AppError::BadRequest(format!("Unknown plan: {}", new_plan)))?;

    let old_idx = tier_order
        .iter()
        .position(|&p| p == old_plan)
        .ok_or_else(|| AppError::BadRequest(format!("Unknown plan: {}", old_plan)))?;

    Ok(new_idx > old_idx)
}

/// Calculate credit difference between plans for upgrades
#[cfg(feature = "payment")]
fn calculate_credit_difference(
    old_plan: &str,
    new_plan: &str,
    config: &crate::config::Config,
) -> Result<i32, AppError> {
    let config_path = &config.payment.subscription_config_path;
    let config_str = std::fs::read_to_string(config_path).map_err(|e| {
        AppError::ConfigurationError(format!("Failed to load subscription config: {}", e))
    })?;

    let tiers: crate::DbJson = serde_json::from_str(&config_str).map_err(|e| {
        AppError::ConfigurationError(format!("Invalid subscription config JSON: {}", e))
    })?;

    let old_credits = tiers["tiers"][old_plan]["credits"]["included_monthly"]
        .as_i64()
        .unwrap_or(0) as i32;

    let new_credits = tiers["tiers"][new_plan]["credits"]["included_monthly"]
        .as_i64()
        .unwrap_or(0) as i32;

    Ok(new_credits - old_credits)
}

/// Handle immediate plan upgrade with credit adjustment
#[cfg(feature = "payment")]
fn handle_plan_upgrade(
    conn: &mut PgConnection,
    subscription: &Subscription,
    new_plan: &str,
    old_plan: &str,
    config: &crate::config::Config,
    credit_service: &Arc<CreditService>,
    audit_service: &Arc<PaymentAuditService>,
) -> Result<(), AppError> {
    use crate::schema::subscriptions::dsl::*;
    use diesel::prelude::*;

    info!(
        "Processing immediate upgrade: {} -> {} for user {}",
        old_plan, new_plan, subscription.user_id
    );

    // 1. Calculate credit difference (only if positive - don't remove credits)
    let credit_diff = calculate_credit_difference(old_plan, new_plan, config)?;

    if credit_diff > 0 {
        // Add upgrade bonus credits
        credit_service.add_credits(
            conn,
            subscription.user_id,
            credit_diff,
            "plan_upgrade",
            "Credits added from plan upgrade",
            subscription.paddle_subscription_id.clone(),
            None,
        )?;

        info!(
            "Added {} upgrade bonus credits for user {}",
            credit_diff, subscription.user_id
        );
    }

    // 2. Update subscription to new plan (clear any pending downgrades)
    diesel::update(subscriptions.find(subscription.id))
        .set((
            plan_type.eq(new_plan),
            scheduled_plan_change.eq::<Option<String>>(None),
            scheduled_change_date.eq::<Option<crate::DbTimestamp>>(None),
            updated_at.eq(chrono::Utc::now()),
        ))
        .execute(conn)
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    // 3. Audit log the upgrade
    audit_service.log_plan_change(
        conn,
        subscription.user_id,
        AuditEventType::PlanUpgraded,
        old_plan,
        new_plan,
        subscription.paddle_subscription_id.as_deref(),
    )?;

    info!(
        "Upgrade completed: {} -> {} for user {}",
        old_plan, new_plan, subscription.user_id
    );

    Ok(())
}

/// Handle scheduled plan downgrade (preserve access until period end)
#[cfg(feature = "payment")]
fn handle_plan_downgrade(
    conn: &mut PgConnection,
    subscription: &Subscription,
    new_plan: &str,
    old_plan: &str,
    audit_service: &Arc<PaymentAuditService>,
) -> Result<(), AppError> {
    use crate::schema::subscriptions::dsl::*;
    use diesel::prelude::*;

    info!(
        "Scheduling downgrade: {} -> {} for user {} at period end {}",
        old_plan, new_plan, subscription.user_id, subscription.current_period_end
    );

    // 1. Schedule downgrade for period end (don't apply immediately)
    diesel::update(subscriptions.find(subscription.id))
        .set((
            scheduled_plan_change.eq(new_plan),
            scheduled_change_date.eq(subscription.current_period_end),
            updated_at.eq(chrono::Utc::now()),
        ))
        .execute(conn)
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    // 2. Audit log the scheduled downgrade
    audit_service.log_plan_change_scheduled(
        conn,
        subscription.user_id,
        old_plan,
        new_plan,
        subscription.current_period_end,
        subscription.paddle_subscription_id.as_deref(),
    )?;

    info!(
        "Downgrade scheduled: {} -> {} for user {} at {}",
        old_plan, new_plan, subscription.user_id, subscription.current_period_end
    );

    Ok(())
}

/// Process subscription.cancelled webhook event
#[cfg(feature = "payment")]
async fn process_subscription_cancelled(
    app_state: AppState,
    webhook_data: &PaddleWebhook,
) -> Result<(), AppError> {
    tracing::debug!(
        "Processing subscription.cancelled webhook: {}",
        webhook_data.event_id
    );

    // Extract subscription data from the webhook payload
    // Paddle sends the subscription data directly in the data field, not nested
    let subscription_data = &webhook_data.data;

    let paddle_subscription_id = subscription_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing subscription ID in webhook".to_string()))?
        .to_string();

    let status = subscription_data
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("cancelled")
        .to_string();

    tracing::debug!(
        "Subscription cancellation details - ID: {}, Status: {}",
        paddle_subscription_id,
        status
    );

    // Find subscription by paddle_subscription_id

    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let paddle_subscription_id_for_closure = paddle_subscription_id.clone();
    let subscription = conn
        .interact(move |conn| {
            use crate::schema::subscriptions;
            use diesel::prelude::*;
            subscriptions::table
                .filter(
                    subscriptions::paddle_subscription_id.eq(&paddle_subscription_id_for_closure),
                )
                .select(crate::models::payment::Subscription::as_select())
                .first(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    if let Some(subscription) = subscription {
        tracing::debug!(
            "Found subscription {} for paddle_subscription_id: {}, cancelling",
            subscription.id,
            paddle_subscription_id
        );

        // Update subscription status to cancelled
        let subscription_id = subscription.id;
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let updated_subscription = conn
            .interact(move |conn| {
                use crate::schema::subscriptions;
                use diesel::prelude::*;
                diesel::update(subscriptions::table.find(subscription_id))
                    .set((
                        subscriptions::status.eq("cancelled"),
                        subscriptions::cancel_at_period_end.eq(true),
                        subscriptions::updated_at.eq(chrono::Utc::now()),
                    ))
                    .returning(crate::models::payment::Subscription::as_returning())
                    .get_result(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        tracing::debug!(
            "Successfully cancelled subscription {} (paddle_subscription_id: {})",
            updated_subscription.id,
            paddle_subscription_id
        );

        // Log cancellation in audit log
        use crate::services::payment::PaymentAuditService;
        let audit_service = PaymentAuditService::new();
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let user_id = subscription.user_id;
        if let Err(e) = conn
            .interact(move |conn| {
                audit_service.log_subscription_event(
                    conn,
                    user_id,
                    crate::services::payment::AuditEventType::SubscriptionCancelled,
                    Some(&paddle_subscription_id),
                )
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))
            .and_then(|r| r)
        {
            tracing::error!("Failed to audit log subscription cancellation: {}", e);
            // Don't fail the webhook processing if audit logging fails
        }
    } else {
        tracing::warn!(
            "Subscription not found for paddle_subscription_id: {}, ignoring cancellation webhook",
            paddle_subscription_id
        );
    }

    Ok(())
}

/// Get current user's credit balance
#[cfg(feature = "payment")]
pub async fn get_credit_balance(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<AxumJson<CreditBalanceResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let credit_service = CreditService::new(app_state.config.clone());

    let user_id = user.id;
    let balance = conn
        .interact(move |conn| credit_service.get_balance(conn, user_id))
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get credit balance: {}", e))
        })?;

    Ok(AxumJson(CreditBalanceResponse {
        balance: balance.balance,
        lifetime_earned: balance.lifetime_earned,
        lifetime_spent: balance.lifetime_spent,
        last_monthly_grant: balance.last_monthly_grant,
    }))
}

/// Purchase credits
#[cfg(feature = "payment")]
pub async fn purchase_credits(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    AxumJson(request): AxumJson<PurchaseCreditsRequest>,
) -> Result<AxumJson<PurchaseCreditsResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get credit package details
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let package_id = request.package_id.clone();
    let package: CreditPackage = conn
        .interact(move |conn| {
            use crate::schema::credit_packages::dsl;
            use diesel::prelude::*;

            dsl::credit_packages
                .filter(dsl::package_id.eq(&package_id))
                .filter(dsl::active.eq(true))
                .first(conn)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::NotFound(format!("Credit package not found: {}", e)))?;

    // Create Paddle transaction for credit purchase
    let paddle_service = PaddleService::new(app_state.config.payment.clone());

    // Create or get customer
    let customer = paddle_service
        .create_customer(&user.email, Some(&user.username))
        .await?;

    // Create transaction with custom_data containing user_id and user_email for webhook lookup
    let custom_data = serde_json::json!({
        "user_id": user.id.to_string(),
        "user_email": user.email.clone(),
        "source": "purchase_credits",
        "package_id": package.package_id.clone(),
        "credits": package.credits,
    });

    let transaction_request = CreateTransactionRequest {
        customer_id: customer.id.clone(),
        items: vec![TransactionItem {
            price_id: package.paddle_price_id.ok_or_else(|| {
                AppError::BadRequest("Package not configured for purchase".to_string())
            })?,
            quantity: 1,
        }],
        collection_mode: "automatic".to_string(),
        checkout: Some(TransactionCheckout {
            url: None,
            success_url: Some(format!(
                "{}/credits/success",
                app_state.config.frontend_base_url
            )),
            cancel_url: Some(format!("{}/credits", app_state.config.frontend_base_url)),
        }),
        billing_details: None,
        custom_data: Some(crate::db::Json(custom_data)),
    };

    let transaction = paddle_service
        .create_transaction(&transaction_request)
        .await?;

    Ok(AxumJson(PurchaseCreditsResponse {
        checkout_url: transaction.checkout_url,
        transaction_id: transaction.transaction_id,
    }))
}

/// Get available credit packages
#[cfg(feature = "payment")]
pub async fn get_credit_packages(
    State(app_state): State<AppState>,
) -> Result<AxumJson<CreditPackagesResponse>, AppError> {
    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let packages = conn
        .interact(|conn| {
            use crate::schema::credit_packages::dsl;
            use diesel::prelude::*;

            dsl::credit_packages
                .filter(dsl::active.eq(true))
                .order(dsl::credits.asc())
                .select(CreditPackage::as_select())
                .load::<CreditPackage>(conn)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get credit packages: {}", e))
        })?;

    Ok(AxumJson(CreditPackagesResponse { packages }))
}

/// Get user's credit transaction history
#[cfg(feature = "payment")]
pub async fn get_credit_transactions(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    Query(query): Query<TransactionListQuery>,
) -> Result<AxumJson<Vec<CreditTransactionResponse>>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let credit_service = CreditService::new(app_state.config.clone());

    let user_id = user.id;
    let limit = query.limit;
    let offset = query.offset;

    // Get encrypted transactions
    let transactions = conn
        .interact(move |conn| credit_service.get_transaction_history(conn, user_id, limit, offset))
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get transactions: {}", e)))?;

    // Decrypt transactions for response
    let mut decrypted_transactions = Vec::new();
    for transaction in transactions {
        let conn = app_state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let user_id = user.id;
        let credit_service_clone = CreditService::new(app_state.config.clone());
        let transaction_clone = transaction.clone();

        let (description, metadata) = conn
            .interact(move |conn| {
                credit_service_clone.decrypt_transaction_data(
                    conn,
                    user_id,
                    &transaction_clone,
                    None, // In production, would pass session DEK
                )
            })
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Database interaction failed: {}", e))
            })?
            .unwrap_or_else(|_| {
                // If decryption fails, use placeholder text
                ("Transaction description unavailable".to_string(), None)
            });

        decrypted_transactions.push(CreditTransactionResponse {
            id: transaction.id,
            amount: transaction.amount,
            balance_after: transaction.balance_after,
            transaction_type: transaction.transaction_type,
            description,
            metadata,
            reference_id: transaction.reference_id,
            created_at: transaction
                .created_at
                .unwrap_or_else(crate::DbTimestamp::now),
        });
    }

    Ok(AxumJson(decrypted_transactions))
}

/// Get user's payment transaction history
#[cfg(feature = "payment")]
pub async fn get_payment_transactions(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    Query(query): Query<TransactionListQuery>,
) -> Result<AxumJson<Vec<PaymentTransactionResponse>>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get encryption key
    let encryption_key = app_state
        .config
        .payment
        .data_encryption_key
        .as_ref()
        .ok_or_else(|| {
            AppError::ConfigurationError("Payment data encryption key not configured".to_string())
        })?;

    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let user_id = user.id;
    let limit = query.limit.unwrap_or(50).min(100); // Max 100
    let offset = query.offset.unwrap_or(0);

    // Query payment transactions for user
    let transactions = conn
        .interact(move |conn| {
            use crate::models::payment::PaymentTransaction;
            use crate::schema::payment_transactions::dsl::*;
            use diesel::prelude::*;

            payment_transactions
                .filter(crate::schema::payment_transactions::dsl::user_id.eq(user_id))
                .order(created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(PaymentTransaction::as_select())
                .load::<PaymentTransaction>(conn)
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    // Decrypt and convert to response DTOs
    let mut responses = Vec::new();
    for transaction in transactions {
        let response = payment_transaction_to_response(
            transaction,
            &app_state.encryption_service,
            encryption_key,
        )
        .await?;
        responses.push(response);
    }

    tracing::debug!(
        transaction_count = responses.len(),
        user_id = %loggable_user_id(user.id),
        "Retrieved and decrypted payment transactions for user"
    );

    Ok(AxumJson(responses))
}

/// Get a single payment transaction by ID
#[cfg(feature = "payment")]
pub async fn get_payment_transaction(
    Path(transaction_id): Path<crate::db::DbId>,
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<AxumJson<PaymentTransactionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Get encryption key
    let encryption_key = app_state
        .config
        .payment
        .data_encryption_key
        .as_ref()
        .ok_or_else(|| {
            AppError::ConfigurationError("Payment data encryption key not configured".to_string())
        })?;

    #[cfg(feature = "postgres-backend")]
    let conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = crate::db::get_conn(&app_state.pool).await.map_err(|e| {
        AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e))
    })?;

    let user_id = user.id;

    // Query transaction - ensure it belongs to the user
    let transaction = conn
        .interact(move |conn| {
            use crate::models::payment::PaymentTransaction;
            use crate::schema::payment_transactions::dsl::*;
            use diesel::prelude::*;

            payment_transactions
                .filter(id.eq(transaction_id))
                .filter(crate::schema::payment_transactions::dsl::user_id.eq(user_id))
                .select(PaymentTransaction::as_select())
                .first::<PaymentTransaction>(conn)
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Payment transaction not found".to_string())
            }
            _ => AppError::DatabaseQueryError(e.to_string()),
        })?;

    // Decrypt and convert to response
    let response =
        payment_transaction_to_response(transaction, &app_state.encryption_service, encryption_key)
            .await?;

    tracing::debug!(
        transaction_id = %transaction_id,
        user_id = %loggable_user_id(user.id),
        "Retrieved and decrypted payment transaction"
    );

    Ok(AxumJson(response))
}

/// Get model credit costs configuration
#[cfg(feature = "payment")]
pub async fn get_model_costs(
    State(_app_state): State<AppState>,
) -> Result<AxumJson<crate::DbJson>, AppError> {
    use std::fs;

    // Load the subscription tiers configuration
    let config_path = "backend/config/subscription_tiers.json";
    let config_str = fs::read_to_string(config_path).map_err(|e| {
        AppError::InternalServerErrorGeneric(format!("Failed to read config: {}", e))
    })?;

    let config: crate::DbJson = serde_json::from_str(&config_str).map_err(|e| {
        AppError::InternalServerErrorGeneric(format!("Failed to parse config: {}", e))
    })?;

    // Extract model costs and token pricing
    let model_costs = config["credit_system"]["model_costs"].clone();
    let token_pricing = config["credit_system"]["token_pricing"].clone();

    // Build response
    let response = serde_json::json!({
        "model_costs": model_costs,
        "token_pricing": token_pricing,
        "credits_enabled": config["feature_flags"]["credits_enabled"],
        "context_multipliers": config["credit_system"]["context_multipliers"]
    });

    Ok(AxumJson(crate::db::Json(response)))
}

/// Create authenticated payment routes (require login)
#[cfg(feature = "payment")]
pub fn payment_routes() -> Router<AppState> {
    use crate::middleware::{
        credit_purchase_rate_limit_middleware, subscription_rate_limit_middleware,
    };
    use axum::middleware::from_fn;

    Router::new()
        .route("/subscription", get(get_subscription))
        .route("/subscription", post(create_subscription))
        .route(
            "/subscription/cancel",
            post(cancel_subscription).layer(from_fn(subscription_rate_limit_middleware)),
        )
        .route(
            "/subscription/reactivate",
            post(reactivate_subscription).layer(from_fn(subscription_rate_limit_middleware)),
        )
        .route("/subscription/preview", post(preview_order)) // Order preview endpoint
        .route(
            "/payment",
            post(create_payment).layer(from_fn(credit_purchase_rate_limit_middleware)),
        ) // Rate limit payment creation
        .route("/transaction/{id}/verify", get(verify_transaction)) // Transaction verification endpoint
        .route("/transactions", get(get_payment_transactions)) // Payment transaction history
        .route("/transaction/{id}", get(get_payment_transaction)) // Get single payment transaction
        .route("/plans", get(get_plans))
        .route("/usage", get(get_usage))
        // Credit endpoints
        .route("/credits/balance", get(get_credit_balance))
        .route(
            "/credits/purchase",
            post(purchase_credits).layer(from_fn(credit_purchase_rate_limit_middleware)),
        ) // Rate limit credit purchases
        .route("/credits/packages", get(get_credit_packages))
        .route("/credits/transactions", get(get_credit_transactions))
        .route("/credits/model-costs", get(get_model_costs))
}

/// Create public payment webhook routes (no authentication required)
#[cfg(feature = "payment")]
pub fn payment_webhook_routes() -> Router<AppState> {
    use crate::middleware::webhook_rate_limit_middleware;
    use axum::middleware::from_fn;

    tracing::debug!("Creating payment webhook routes");
    Router::new()
        .route(
            "/webhook/paddle",
            post(paddle_webhook).layer(from_fn(webhook_rate_limit_middleware)),
        ) // Rate limit webhooks
        .route("/pay", get(handle_pay_page)) // Handle Paddle payment completion redirects
}

// Non-payment version returns empty router
#[cfg(not(feature = "payment"))]
pub fn payment_routes() -> axum::Router<crate::state::AppState> {
    axum::Router::new()
}

#[cfg(not(feature = "payment"))]
pub fn payment_webhook_routes() -> axum::Router<crate::state::AppState> {
    axum::Router::new()
}
