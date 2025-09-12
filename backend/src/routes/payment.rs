//! Payment routes and webhook handlers
//!
//! This module provides HTTP endpoints for payment management including:
//! - Subscription management (create, update, cancel)
//! - Usage tracking and limits
//! - Paddle webhook handling
//! - Plan information retrieval

#[cfg(feature = "payment")]
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
#[cfg(feature = "payment")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "payment")]
use uuid::Uuid;

#[cfg(feature = "payment")]
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::payment::{PlanFeatures, Subscription, SubscriptionStatus},
    services::payment::{
        paddle_service::{CreateTransactionRequest, CreateTransactionResponse, TransactionItem, TransactionCheckout, PaddleWebhook, PaddleEventType},
        PaddleService, SubscriptionService, UsageTrackingService
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
}

#[cfg(feature = "payment")]
#[derive(Serialize)]
pub struct UsageLimitsResponse {
    pub tokens_remaining: i32,
    pub tokens_limit: i32,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub period_end: chrono::DateTime<chrono::Utc>,
    pub is_unlimited: bool,
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
    pub trial_days: Option<i32>,
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

/// Get current user's subscription information
#[cfg(feature = "payment")]
pub async fn get_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // Get database connection
    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e)))?;
    
    // Create subscription service
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone()
    );
    
    // Get subscription from database
    let user_id = user.id;
    let subscription_service_clone = subscription_service.clone();
    let subscription = conn
        .interact(move |conn| {
            futures::executor::block_on(subscription_service_clone.get_user_subscription(conn, user_id))
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get subscription: {}", e)))?;
    
    // Get plan features if subscription exists
    let plan_features = if let Some(ref sub) = subscription {
        let plan_type = sub.plan_type.clone();
        let subscription_service_clone = subscription_service.clone();
        conn
            .interact(move |conn| {
                futures::executor::block_on(subscription_service_clone.get_plan_features(conn, &plan_type))
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get plan features: {}", e)))?
    } else {
        // Default to free plan features
        let subscription_service_clone = subscription_service.clone();
        conn
            .interact(move |conn| {
                futures::executor::block_on(subscription_service_clone.get_plan_features(conn, "free"))
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get free plan features: {}", e)))?
    };
    
    // Calculate usage limits
    let usage_limits = if let Some(ref features) = plan_features {
        // For now, return simple usage limits calculation
        // In a real system, this would query actual usage from usage_tracking table
        let now = chrono::Utc::now();
        let period_start = now;
        let period_end = now + chrono::Duration::days(30);
        
        Some(UsageLimitsResponse {
            tokens_remaining: features.monthly_token_limit.unwrap_or(0),
            tokens_limit: features.monthly_token_limit.unwrap_or(0),
            period_start,
            period_end,
            is_unlimited: features.monthly_token_limit.is_none(),
        })
    } else {
        None
    };
    
    Ok(Json(SubscriptionResponse {
        subscription,
        plan_features,
        usage_limits,
    }))
}

/// Get available subscription plans
#[cfg(feature = "payment")]
pub async fn get_plans(State(app_state): State<AppState>) -> Result<Json<PlansResponse>, AppError> {
    // TODO: This is a simplified implementation for now
    Ok(Json(PlansResponse { plans: vec![] }))
}

/// Get current user's usage information
#[cfg(feature = "payment")]
pub async fn get_usage(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<Json<UsageLimitsResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // TODO: This is a simplified implementation for now
    Ok(Json(UsageLimitsResponse {
        tokens_remaining: 0,
        tokens_limit: 0,
        period_start: chrono::Utc::now(),
        period_end: chrono::Utc::now(),
        is_unlimited: false,
    }))
}

/// Create a new payment transaction (replaces direct subscription creation)
#[cfg(feature = "payment")]
pub async fn create_payment(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    Json(request): Json<CreatePaymentRequest>,
) -> Result<Json<CreatePaymentResponse>, AppError> {
    tracing::info!("🎯 CREATE_PAYMENT HANDLER ENTERED - plan_type: {}", request.plan_type);
    
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    tracing::info!("🎯 CREATE_PAYMENT - User authenticated: {}", user.id);

    // Create or get existing customer
    let paddle_service = PaddleService::new(app_state.config.payment.clone());
    let customer = paddle_service
        .create_customer(&user.email, Some(&user.username))
        .await?;

    // Look up plan features from database to get paddle_price_id
    let subscription_service = SubscriptionService::new(
        (*app_state.config).clone(),
        (*app_state.encryption_service).clone()
    );
    
    let conn = app_state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e)))?;
    
    let plan_type_clone = request.plan_type.clone();
    let subscription_service_clone = subscription_service.clone();
    let plan_features = conn
        .interact(move |conn| {
            futures::executor::block_on(subscription_service_clone.get_plan_features(conn, &plan_type_clone))
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Database query failed: {}", e)))?
        .ok_or_else(|| AppError::BadRequest(format!("Invalid plan type: {}", request.plan_type)))?;
    
    let price_id = plan_features
        .paddle_price_id
        .ok_or_else(|| AppError::BadRequest(format!("Plan '{}' does not have a configured paddle_price_id", request.plan_type)))?;

    // Create transaction request
    let transaction_request = CreateTransactionRequest {
        customer_id: customer.id,
        items: vec![TransactionItem {
            price_id: price_id.to_string(),
            quantity: 1,
        }],
        collection_mode: "automatic".to_string(), // Automatic checkout
        checkout: Some(TransactionCheckout {
            url: None, // Use default payment base URL
            success_url: request.success_url.clone(),
            cancel_url: request.cancel_url.clone(),
        }),
    };

    // Create transaction with Paddle
    let transaction = paddle_service
        .create_transaction(&transaction_request)
        .await?;

    Ok(Json(CreatePaymentResponse {
        transaction_id: transaction.transaction_id,
        checkout_url: transaction.checkout_url,
        status: transaction.status,
    }))
}

/// Create a new subscription for the user (legacy - now uses transactions)
#[cfg(feature = "payment")]
pub async fn create_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    Json(request): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // TODO: This is a simplified implementation for now
    // In the future, this should map plan_type to price_id and use create_payment
    Ok(Json(SubscriptionResponse {
        subscription: None,
        plan_features: None,
        usage_limits: None,
    }))
}

/// Cancel user's subscription
#[cfg(feature = "payment")]
pub async fn cancel_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
    Json(request): Json<CancelSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // TODO: This is a simplified implementation for now
    Ok(Json(SubscriptionResponse {
        subscription: None,
        plan_features: None,
        usage_limits: None,
    }))
}

/// Reactivate user's subscription
#[cfg(feature = "payment")]
pub async fn reactivate_subscription(
    auth_session: CurrentAuthSession,
    State(app_state): State<AppState>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // TODO: This is a simplified implementation for now
    Ok(Json(SubscriptionResponse {
        subscription: None,
        plan_features: None,
        usage_limits: None,
    }))
}

/// Handle Paddle webhooks
#[cfg(feature = "payment")]
pub async fn paddle_webhook(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<WebhookResponse>, AppError> {
    tracing::info!("🎯 PADDLE WEBHOOK HANDLER CALLED - Received Paddle webhook");
    
    // 1. Check for Paddle-Signature header
    let signature = headers
        .get("Paddle-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing Paddle-Signature header".to_string()))?;

    // 2. Create PaddleService to verify signature
    let paddle_service = PaddleService::new(app_state.config.payment.clone());
    
    // 3. Verify webhook signature
    paddle_service.verify_webhook_signature(&body, signature)?;
    
    // 4. Parse JSON payload as PaddleWebhook
    let webhook_data: PaddleWebhook = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON payload: {}", e)))?;
    
    tracing::info!("🎯 Processing webhook event: {:?} with ID: {}", 
        webhook_data.event_type, webhook_data.event_id);
    
    // 5. Process webhook based on event type
    match webhook_data.event_type {
        PaddleEventType::TransactionCompleted => {
            process_transaction_completed(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionCreated => {
            process_subscription_created(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionUpdated => {
            process_subscription_updated(app_state, &webhook_data).await?;
        }
        PaddleEventType::SubscriptionCancelled => {
            process_subscription_cancelled(app_state, &webhook_data).await?;
        }
        _ => {
            tracing::info!("🎯 Webhook event type {:?} not processed - acknowledged", 
                webhook_data.event_type);
        }
    }
    
    tracing::info!("🎯 Webhook processed successfully");
    
    Ok(Json(WebhookResponse {
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
        tracing::info!("🎯 Payment completion detected for transaction: {}", transaction_id);
        
        // TODO: In the future, we could:
        // 1. Verify the transaction status with Paddle API
        // 2. Update local subscription records
        // 3. Redirect to success/failure page based on status
        // For now, we'll redirect to the frontend with the transaction ID
        
        let redirect_url = format!("{}?transaction_id={}&status=success", 
            app_state.config.frontend_base_url, transaction_id);
        
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
    webhook_data: &PaddleWebhook
) -> Result<(), AppError> {
    tracing::info!("🎯 Processing transaction.completed webhook: {}", webhook_data.event_id);
    
    // Extract transaction data from the webhook payload
    let transaction_data = webhook_data.data.get("transaction")
        .ok_or_else(|| AppError::BadRequest("Missing transaction data in webhook".to_string()))?;
    
    let transaction_id = transaction_data.get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing transaction ID in webhook".to_string()))?;
    
    let customer_id = transaction_data.get("customer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing customer_id in webhook".to_string()))?;
    
    let status = transaction_data.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    tracing::info!("🎯 Transaction details - ID: {}, Customer: {}, Status: {}", 
        transaction_id, customer_id, status);
    
    // Only process completed transactions
    if status != "completed" {
        tracing::info!("🎯 Transaction {} not completed (status: {}), skipping", transaction_id, status);
        return Ok(());
    }
    
    // For now, we need the customer's email to find the user
    // In a real implementation, we'd store customer_id -> user_id mapping
    // For transaction-based payments (no subscriptions), we might create a subscription record
    // based on the transaction details and price_id
    
    tracing::info!("🎯 Transaction {} completed successfully but subscription creation not yet implemented", transaction_id);
    
    Ok(())
}

/// Process subscription.created webhook event
#[cfg(feature = "payment")]
async fn process_subscription_created(
    app_state: AppState,
    webhook_data: &PaddleWebhook
) -> Result<(), AppError> {
    tracing::info!("🎯 Processing subscription.created webhook: {}", webhook_data.event_id);
    
    // For subscription-based billing (future enhancement)
    tracing::info!("🎯 Subscription creation processing not yet implemented");
    
    Ok(())
}

/// Process subscription.updated webhook event
#[cfg(feature = "payment")]
async fn process_subscription_updated(
    app_state: AppState,
    webhook_data: &PaddleWebhook
) -> Result<(), AppError> {
    tracing::info!("🎯 Processing subscription.updated webhook: {}", webhook_data.event_id);
    
    // For subscription updates (status changes, renewals, etc.)
    tracing::info!("🎯 Subscription update processing not yet implemented");
    
    Ok(())
}

/// Process subscription.cancelled webhook event
#[cfg(feature = "payment")]
async fn process_subscription_cancelled(
    app_state: AppState,
    webhook_data: &PaddleWebhook
) -> Result<(), AppError> {
    tracing::info!("🎯 Processing subscription.cancelled webhook: {}", webhook_data.event_id);
    
    // For subscription cancellations
    tracing::info!("🎯 Subscription cancellation processing not yet implemented");
    
    Ok(())
}

/// Create authenticated payment routes (require login)
#[cfg(feature = "payment")]
pub fn payment_routes() -> Router<AppState> {
    Router::new()
        .route("/subscription", get(get_subscription))
        .route("/subscription", post(create_subscription))
        .route("/subscription/cancel", post(cancel_subscription))
        .route("/subscription/reactivate", post(reactivate_subscription))
        .route("/payment", post(create_payment)) // New transaction-based payment endpoint
        .route("/plans", get(get_plans))
        .route("/usage", get(get_usage))
}

/// Create public payment webhook routes (no authentication required)
#[cfg(feature = "payment")]
pub fn payment_webhook_routes() -> Router<AppState> {
    tracing::info!("🎯 Creating payment webhook routes");
    Router::new()
        .route("/webhook/paddle", post(paddle_webhook))
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