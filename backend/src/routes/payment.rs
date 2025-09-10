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
        paddle_service::{CreateTransactionRequest, CreateTransactionResponse, TransactionItem, TransactionCheckout},
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
    pub price_id: String,
    pub return_url: Option<String>,
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
    // TODO: This is a simplified implementation for now
    // The full implementation would use the payment services, but they need to be 
    // refactored to work with the deadpool connection pattern
    
    Ok(Json(SubscriptionResponse {
        subscription: None, // TODO: Implement subscription lookup
        plan_features: None, // TODO: Implement plan features lookup
        usage_limits: None,  // TODO: Implement usage limits calculation
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
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    // Create or get existing customer
    let paddle_service = PaddleService::new(app_state.config.payment.clone());
    let customer = paddle_service
        .create_customer(&user.email, Some(&user.username))
        .await?;

    // Create transaction request
    let transaction_request = CreateTransactionRequest {
        customer_id: customer.id,
        items: vec![TransactionItem {
            price_id: request.price_id,
            quantity: 1,
        }],
        collection_mode: "automatic".to_string(), // Automatic checkout
        checkout: request.return_url.map(|url| TransactionCheckout {
            url: None, // Use default payment base URL
            success_url: Some(url),
            cancel_url: None,
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
    
    // 4. Parse JSON payload
    let _webhook_data: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON payload: {}", e)))?;
    
    // 5. Process webhook (TODO: implement actual processing)
    tracing::info!("🎯 Webhook signature verified and payload parsed successfully");
    
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

// TODO: Implement webhook handlers when payment services are integrated with deadpool pattern

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