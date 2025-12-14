//! Paddle payment service for subscription and payment management
//!
//! This service handles interaction with Paddle's API for:
//! - Customer management
//! - Subscription creation and management
//! - Webhook signature verification
//! - Transaction handling

use crate::config::PaymentConfig;
use crate::errors::AppError;
use crate::services::encryption_service::EncryptionService;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Paddle service for payment processing
#[derive(Clone)]
pub struct PaddleService {
    config: PaymentConfig,
    client: reqwest::Client,
    encryption_service: EncryptionService,
}

/// Paddle webhook event types
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum PaddleEventType {
    SubscriptionCreated,
    SubscriptionUpdated,
    SubscriptionCancelled,
    TransactionCompleted,
    TransactionFailed,
    TransactionCanceled,
    CustomerCreated,
    CustomerUpdated,
}

impl<'de> Deserialize<'de> for PaddleEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            // Snake case variants
            "subscription_created" | "subscription.created" => {
                Ok(PaddleEventType::SubscriptionCreated)
            }
            "subscription_updated" | "subscription.updated" => {
                Ok(PaddleEventType::SubscriptionUpdated)
            }
            "subscription_cancelled"
            | "subscription.cancelled"
            | "subscription_canceled"
            | "subscription.canceled" => Ok(PaddleEventType::SubscriptionCancelled),
            "transaction_completed" | "transaction.completed" => {
                Ok(PaddleEventType::TransactionCompleted)
            }
            "transaction_failed" | "transaction.failed" => Ok(PaddleEventType::TransactionFailed),
            "transaction_canceled" | "transaction.canceled" => {
                Ok(PaddleEventType::TransactionCanceled)
            }
            "customer_created" | "customer.created" => Ok(PaddleEventType::CustomerCreated),
            "customer_updated" | "customer.updated" => Ok(PaddleEventType::CustomerUpdated),
            _ => {
                tracing::warn!("Unknown Paddle event type received: {}", s);
                Err(serde::de::Error::unknown_variant(
                    &s,
                    &[
                        "subscription_created",
                        "subscription.created",
                        "subscription_updated",
                        "subscription.updated",
                        "subscription_cancelled",
                        "subscription.cancelled",
                        "transaction_completed",
                        "transaction.completed",
                        "transaction_failed",
                        "transaction.failed",
                        "transaction_canceled",
                        "transaction.canceled",
                        "customer_created",
                        "customer.created",
                        "customer_updated",
                        "customer.updated",
                    ],
                ))
            }
        }
    }
}

/// Paddle webhook payload structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleWebhook {
    #[serde(alias = "eventType", alias = "type")]
    pub event_type: PaddleEventType,
    #[serde(alias = "eventId", alias = "id")]
    pub event_id: String,
    #[serde(alias = "occurredAt", alias = "timestamp")]
    pub occurred_at: crate::DbTimestamp,
    pub data: crate::DbJson,
}

/// Paddle subscription data structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleSubscription {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    pub current_billing_period: Option<PaddleBillingPeriod>,
    pub billing_cycle: Option<PaddleBillingCycle>,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
    pub items: Vec<PaddleSubscriptionItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_dates: Option<PaddleTrialDates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_change: Option<crate::DbJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_urls: Option<crate::DbJson>,
}

/// Paddle billing period
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleBillingPeriod {
    pub starts_at: crate::DbTimestamp,
    pub ends_at: crate::DbTimestamp,
}

/// Paddle trial dates
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleTrialDates {
    pub starts_at: crate::DbTimestamp,
    pub ends_at: crate::DbTimestamp,
}

/// Paddle billing cycle
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleBillingCycle {
    pub interval: String, // "month", "year", etc.
    pub frequency: i32,
}

/// Paddle subscription item
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleSubscriptionItem {
    pub status: String,
    pub quantity: i32,
    pub recurring: bool,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previously_billed_at: Option<crate::DbTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_billed_at: Option<crate::DbTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_dates: Option<PaddleTrialDates>,
    pub price: PaddlePrice,     // Full price object (was: price_id: String)
    pub product: PaddleProduct, // Full product object
}

/// Legacy Paddle transaction data (for webhook processing)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleLegacyTransaction {
    pub id: String,
    pub customer_id: String,
    pub subscription_id: Option<String>,
    pub status: String,
    pub total: String,
    pub currency_code: String,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
}

/// Paddle customer data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleCustomer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
}

/// Create transaction request (replaces subscription request)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTransactionRequest {
    pub customer_id: String,
    pub items: Vec<TransactionItem>,
    pub collection_mode: String, // "automatic" for checkout, "manual" for invoice
    pub checkout: Option<TransactionCheckout>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_details: Option<TransactionBillingDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<crate::DbJson>,
}

/// Transaction item
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionItem {
    pub price_id: String,
    pub quantity: i32,
}

/// Transaction checkout configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionCheckout {
    pub url: Option<String>, // Override default payment URL
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
}

/// Transaction billing details (only for manual collection mode)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionBillingDetails {
    pub payment_terms: PaymentTerms,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_checkout: Option<bool>,
}

/// Payment terms for manual collection mode
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentTerms {
    pub interval: String, // "day", "week", "month", "year"
    pub frequency: i32,   // Number of intervals
}

/// Create transaction response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTransactionResponse {
    pub transaction_id: String,
    pub checkout_url: String,
    pub status: String,
}

/// Paddle transaction structure (for API responses)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleTransaction {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    pub collection_mode: String,
    pub checkout: Option<PaddleTransactionCheckout>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_url: Option<String>, // Paddle returns this at the root level for automatic collection mode
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
    pub items: Vec<PaddleTransactionItem>,
}

/// Paddle transaction checkout details
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleTransactionCheckout {
    pub url: Option<String>,
}

/// Paddle transaction item (from API response)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleTransactionItem {
    pub price: PaddlePrice, // Nested price object from Paddle API
    pub quantity: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proration: Option<crate::DbJson>,
}

/// Paddle price information within transaction items
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddlePrice {
    pub id: String,
    pub description: String,
    #[serde(rename = "type")]
    pub price_type: String,
    pub name: Option<String>,
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_cycle: Option<crate::DbJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_period: Option<crate::DbJson>,
    pub tax_mode: String,
    pub unit_price: crate::DbJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_price_overrides: Option<Vec<crate::DbJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<crate::DbJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<crate::DbJson>,
    pub status: String,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_meta: Option<crate::DbJson>,
}

/// Paddle product information within subscription items
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleProduct {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub product_type: String,
    pub tax_category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<crate::DbJson>,
    pub status: String,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp,
}

/// Legacy - keep for backward compatibility
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateSubscriptionRequest {
    pub customer_id: String,
    pub price_id: String,
    pub return_url: Option<String>,
}

/// Legacy - keep for backward compatibility
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateSubscriptionResponse {
    pub subscription_id: String,
    pub checkout_url: Option<String>,
}

/// Generic Paddle API response wrapper
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleApiResponse<T> {
    pub data: T,
    pub meta: crate::DbJson,
}

impl PaddleService {
    /// Create a new PaddleService instance
    pub fn new(config: PaymentConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            encryption_service: EncryptionService::new(),
        }
    }

    /// Verify webhook signature
    ///
    /// # Errors
    ///
    /// Returns `AppError::InvalidWebhookSignature` if signature verification fails
    pub fn verify_webhook_signature(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), AppError> {
        let webhook_secret = self.config.paddle_webhook_secret.as_ref().ok_or_else(|| {
            tracing::error!("Paddle webhook secret not configured in PaymentConfig");
            AppError::ConfigurationError("Paddle webhook secret not configured".to_string())
        })?;

        // Log webhook secret info for debugging (don't log actual secret)
        tracing::info!(
            "Using webhook secret of length: {} chars",
            webhook_secret.len()
        );
        tracing::info!(
            "Webhook secret starts with: {}...",
            &webhook_secret.chars().take(4).collect::<String>()
        );

        // Parse Paddle signature format: "ts=<timestamp>;h1=<signature>"
        tracing::debug!("Raw signature header: {}", signature);

        let mut timestamp = None;
        let mut h1_signature = None;

        for part in signature.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "ts" => timestamp = Some(value),
                    "h1" => h1_signature = Some(value),
                    _ => {
                        tracing::debug!("Unknown signature component: {}={}", key, value);
                    }
                }
            }
        }

        let timestamp = timestamp.ok_or_else(|| {
            tracing::error!("Missing timestamp in signature");
            AppError::InvalidWebhookSignature("Missing timestamp in signature".to_string())
        })?;

        let h1_signature = h1_signature.ok_or_else(|| {
            tracing::error!("Missing h1 signature component");
            AppError::InvalidWebhookSignature("Missing h1 signature component".to_string())
        })?;

        tracing::debug!("Parsed timestamp: {}", timestamp);
        tracing::debug!("Parsed h1 signature: {}", h1_signature);

        // Create signed payload: timestamp:request_body
        let payload_string = String::from_utf8_lossy(payload);
        let signed_payload = format!("{}:{}", timestamp, payload_string);
        tracing::debug!("Signed payload length: {} bytes", signed_payload.len());

        // Use HMAC-SHA256 to verify the signature
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes()).map_err(|e| {
            tracing::error!("Invalid webhook secret format: {}", e);
            AppError::InvalidWebhookSignature(format!("Invalid webhook secret: {}", e))
        })?;

        mac.update(signed_payload.as_bytes());

        // Paddle sends signatures as hex-encoded strings
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        tracing::debug!("Expected h1 signature: {}", expected_signature);

        // Compare h1 signature in constant time
        use subtle::ConstantTimeEq;
        let received_bytes = hex::decode(h1_signature).map_err(|e| {
            tracing::error!("Failed to decode h1 signature: {}", e);
            AppError::InvalidWebhookSignature("Invalid h1 signature format".to_string())
        })?;
        let expected_bytes = hex::decode(&expected_signature).map_err(|e| {
            tracing::error!("Failed to decode expected signature: {}", e);
            AppError::InvalidWebhookSignature("Invalid expected signature format".to_string())
        })?;

        if received_bytes.ct_eq(&expected_bytes).into() {
            tracing::debug!("Webhook signature verification SUCCESS");
            Ok(())
        } else {
            tracing::error!("Signature verification FAILED");
            tracing::error!("Expected: {}", expected_signature);
            tracing::error!("Received: {}", h1_signature);
            Err(AppError::InvalidWebhookSignature(
                "Signature mismatch".to_string(),
            ))
        }
    }

    /// Parse webhook payload
    ///
    /// # Errors
    ///
    /// Returns `AppError::JsonParseError` if payload parsing fails
    pub fn parse_webhook_payload(&self, payload: &[u8]) -> Result<PaddleWebhook, AppError> {
        serde_json::from_slice(payload).map_err(|e| {
            AppError::JsonParseError(format!("Failed to parse webhook payload: {}", e))
        })
    }

    /// Create a Paddle customer or get existing one
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn create_customer(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> Result<PaddleCustomer, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let mut payload = HashMap::new();
        payload.insert("email", email);
        if let Some(name) = name {
            payload.insert("name", name);
        }

        let response = self
            .client
            .post(&format!("{}/customers", base_url))
            .bearer_auth(api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                AppError::ExternalServiceError(format!("Paddle API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();

            // Check if this is a "customer_already_exists" error
            if error_body.contains("customer_already_exists") {
                // Try to extract the existing customer ID from the error message
                if let Some(customer_id) = self.extract_customer_id_from_error(&error_body) {
                    info!(customer_id = %customer_id, email = %email, "Using existing Paddle customer");
                    return Ok(PaddleCustomer {
                        id: customer_id,
                        email: Some(email.to_string()),
                        name: name.map(|s| s.to_string()),
                        created_at: crate::DbTimestamp::now(),
                        updated_at: crate::DbTimestamp::now(),
                    });
                }
            }

            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();

        // Paddle wraps the response in a "data" field
        let wrapper: PaddleApiResponse<PaddleCustomer> = serde_json::from_str(&response_text)
            .map_err(|e| {
                AppError::JsonParseError(format!(
                    "Failed to parse customer response '{}': {}",
                    response_text, e
                ))
            })?;
        let customer = wrapper.data;

        info!(customer_id = %customer.id, email = %email, "Created Paddle customer");
        Ok(customer)
    }

    /// Extract customer ID from "customer_already_exists" error message
    fn extract_customer_id_from_error(&self, error_body: &str) -> Option<String> {
        // Error format: "customer email conflicts with customer of id ctm_01k4w5czs63fx0jb421rz6n45z"
        if let Ok(error_json) = serde_json::from_str::<crate::DbJson>(error_body) {
            if let Some(detail) = error_json["error"]["detail"].as_str() {
                // Look for pattern "customer of id <customer_id>"
                if let Some(start) = detail.find("customer of id ") {
                    let id_start = start + "customer of id ".len();
                    let id_part = &detail[id_start..];
                    // Customer IDs end at the first whitespace or end of string
                    let customer_id = id_part.split_whitespace().next().unwrap_or("");
                    if !customer_id.is_empty() && customer_id.starts_with("ctm_") {
                        return Some(customer_id.to_string());
                    }
                }
            }
        }
        None
    }

    /// Create a transaction for checkout
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn create_transaction(
        &self,
        request: &CreateTransactionRequest,
    ) -> Result<CreateTransactionResponse, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        // Log comprehensive debugging information
        debug!(
            sandbox_mode = %self.config.paddle_sandbox_mode,
            base_url = %base_url,
            api_key_prefix = %&api_key[..std::cmp::min(12, api_key.len())],
            customer_id = %request.customer_id,
            collection_mode = %request.collection_mode,
            items_count = %request.items.len(),
            payment_base_url = %self.config.payment_base_url,
            "Preparing Paddle transaction creation request"
        );

        // Log the full request payload (but mask sensitive data)
        let request_json = serde_json::to_string_pretty(request)
            .unwrap_or_else(|_| "Failed to serialize request".to_string());
        debug!(
            request_payload = %request_json,
            "Paddle transaction request payload"
        );

        let response = self
            .client
            .post(&format!("{}/transactions", base_url))
            .bearer_auth(api_key)
            .json(request)
            .send()
            .await
            .map_err(|e| {
                error!(
                    error = %e,
                    base_url = %base_url,
                    "Paddle API request failed during HTTP call"
                );
                AppError::ExternalServiceError(format!("Paddle API request failed: {}", e))
            })?;

        let status = response.status();
        let headers = response.headers().clone();

        debug!(
            status = %status,
            headers = ?headers,
            "Received response from Paddle API"
        );

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            error!(
                status = %status,
                error_body = %error_body,
                base_url = %base_url,
                customer_id = %request.customer_id,
                "Paddle API returned error response"
            );
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error ({}): {}",
                status, error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();

        debug!(
            response_body = %response_text,
            "Raw response body from Paddle API"
        );

        // DETAILED LOGGING: Parse response as raw JSON first to see structure
        if let Ok(raw_json) = serde_json::from_str::<crate::DbJson>(&response_text) {
            info!(
                raw_json = %serde_json::to_string_pretty(&raw_json).unwrap_or_else(|_| "Invalid JSON".to_string()),
                "RAW PADDLE RESPONSE STRUCTURE"
            );

            // Check if data field exists
            if let Some(data) = raw_json.get("data") {
                info!("DATA FIELD EXISTS in Paddle response");

                // Check checkout field specifically
                if let Some(checkout) = data.get("checkout") {
                    info!(
                        checkout_field = %serde_json::to_string(checkout).unwrap_or_else(|_| "Invalid checkout".to_string()),
                        "CHECKOUT FIELD FOUND in data"
                    );
                } else {
                    warn!("NO CHECKOUT FIELD found in data object");
                }
            } else {
                warn!("NO DATA FIELD found in Paddle response");
            }
        } else {
            error!("Failed to parse response as JSON: {}", response_text);
        }

        // Paddle wraps the response in a "data" field
        let wrapper: PaddleApiResponse<PaddleTransaction> = serde_json::from_str(&response_text)
            .map_err(|e| {
                error!(
                    error = %e,
                    response_text = %response_text,
                    "Failed to parse Paddle transaction response"
                );
                AppError::JsonParseError(format!(
                    "Failed to parse transaction response '{}': {}",
                    response_text, e
                ))
            })?;

        let transaction = wrapper.data;

        info!(
            transaction_id = %transaction.id,
            transaction_status = %transaction.status,
            transaction_checkout = ?transaction.checkout,
            "PARSED PADDLE TRANSACTION"
        );

        // Extract checkout URL from transaction with detailed logging
        // Paddle returns checkout_url at root level for automatic collection mode
        let checkout_url = if let Some(url) = &transaction.checkout_url {
            info!(checkout_url = %url, "Found checkout URL from Paddle at root level");
            url.clone()
        } else if let Some(checkout) = &transaction.checkout {
            info!("Transaction has checkout field, checking for nested URL");
            match &checkout.url {
                Some(url) => {
                    info!(checkout_url = %url, "Found checkout URL from Paddle in checkout field");
                    url.clone()
                }
                None => {
                    warn!("Checkout field exists but URL is None - using fallback");
                    let fallback_url = format!(
                        "{}/pay?_ptxn={}",
                        &self.config.payment_base_url, transaction.id
                    );
                    info!(
                        fallback_url = %fallback_url,
                        transaction_id = %transaction.id,
                        payment_base_url = %self.config.payment_base_url,
                        "Using fallback checkout URL (checkout field exists but no URL)"
                    );
                    fallback_url
                }
            }
        } else {
            warn!(
                "No checkout_url at root level and no checkout field in transaction - using fallback"
            );
            let fallback_url = format!(
                "{}/pay?_ptxn={}",
                &self.config.payment_base_url, transaction.id
            );
            info!(
                fallback_url = %fallback_url,
                transaction_id = %transaction.id,
                payment_base_url = %self.config.payment_base_url,
                "Using fallback checkout URL (no checkout data found)"
            );
            fallback_url
        };

        let transaction_response = CreateTransactionResponse {
            transaction_id: transaction.id.clone(),
            checkout_url: checkout_url.clone(),
            status: transaction.status.clone(),
        };

        info!(
            transaction_id = %transaction_response.transaction_id,
            customer_id = %request.customer_id,
            checkout_url = %checkout_url,
            status = %transaction_response.status,
            "Successfully created Paddle transaction"
        );

        Ok(transaction_response)
    }

    /// Create a subscription
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn create_subscription(
        &self,
        request: &CreateSubscriptionRequest,
    ) -> Result<CreateSubscriptionResponse, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let response = self
            .client
            .post(&format!("{}/subscriptions", base_url))
            .bearer_auth(api_key)
            .json(request)
            .send()
            .await
            .map_err(|e| {
                AppError::ExternalServiceError(format!("Paddle API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();

        // Log the raw response to understand the structure
        debug!(
            response_body = %response_text,
            "Raw subscription creation response from Paddle API"
        );

        let wrapper: PaddleApiResponse<PaddleSubscription> = serde_json::from_str(&response_text)
            .map_err(|e| {
            AppError::JsonParseError(format!(
                "Failed to parse subscription response '{}': {}",
                response_text, e
            ))
        })?;

        // For subscription creation, Paddle typically doesn't return a checkout URL
        // since subscriptions are created after successful payment.
        // However, we can check the response for any additional checkout information.
        let checkout_url = if let Ok(raw_json) =
            serde_json::from_str::<crate::DbJson>(&response_text)
        {
            // Check if there's any checkout URL in the response
            raw_json.get("data")
                .and_then(|data| data.get("checkout_url"))
                .and_then(|url| url.as_str())
                .map(|url| {
                    info!(checkout_url = %url, "Found checkout URL in subscription response");
                    url.to_string()
                })
                .or_else(|| {
                    // Check for nested checkout object
                    raw_json.get("data")
                        .and_then(|data| data.get("checkout"))
                        .and_then(|checkout| checkout.get("url"))
                        .and_then(|url| url.as_str())
                        .map(|url| {
                            info!(checkout_url = %url, "Found checkout URL in subscription checkout field");
                            url.to_string()
                        })
                })
        } else {
            None
        };

        let subscription_response = CreateSubscriptionResponse {
            subscription_id: wrapper.data.id.clone(),
            checkout_url,
        };

        info!(
            subscription_id = %subscription_response.subscription_id,
            customer_id = %request.customer_id,
            "Created Paddle subscription"
        );
        Ok(subscription_response)
    }

    /// Get subscription details
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<PaddleSubscription, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let response = self
            .client
            .get(&format!("{}/subscriptions/{}", base_url, subscription_id))
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|e| {
                AppError::ExternalServiceError(format!("Paddle API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();

        let wrapper: PaddleApiResponse<PaddleSubscription> = serde_json::from_str(&response_text)
            .map_err(|e| {
            AppError::JsonParseError(format!(
                "Failed to parse subscription response '{}': {}",
                response_text, e
            ))
        })?;
        let subscription = wrapper.data;

        debug!(subscription_id = %subscription_id, "Retrieved Paddle subscription");
        Ok(subscription)
    }

    /// Get a transaction by ID from Paddle
    pub async fn get_transaction(&self, transaction_id: &str) -> Result<crate::DbJson, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let api_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let url = format!("{}/transactions/{}", api_url, transaction_id);

        tracing::info!("Getting transaction {} from Paddle API", transaction_id);

        let response = self
            .client
            .get(&url)
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to get transaction from Paddle: {}", e);
                AppError::ExternalServiceError(format!(
                    "Failed to get transaction from Paddle: {}",
                    e
                ))
            })?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            tracing::error!("Failed to read Paddle response: {}", e);
            AppError::ExternalServiceError(format!("Failed to read Paddle response: {}", e))
        })?;

        tracing::info!(
            "Paddle transaction response status: {}, body: {}",
            status,
            response_text
        );

        if !status.is_success() {
            tracing::error!("Paddle API error (status {}): {}", status, response_text);
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {} - {}",
                status, response_text
            )));
        }

        // Parse response as JSON
        let response_json: crate::DbJson = serde_json::from_str(&response_text).map_err(|e| {
            tracing::error!("Failed to parse Paddle response: {}", e);
            AppError::ExternalServiceError(format!("Failed to parse Paddle response: {}", e))
        })?;

        // Extract data field if it exists
        if let Some(data) = response_json.get("data") {
            Ok(data.clone())
        } else {
            Ok(response_json)
        }
    }

    /// Cancel a subscription
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn cancel_subscription(
        &self,
        subscription_id: &str,
        effective_from: Option<&str>, // "next_billing_period" or "immediately"
    ) -> Result<(), AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let mut payload = HashMap::new();
        if let Some(effective_from) = effective_from {
            payload.insert("effective_from", effective_from);
        }

        let response = self
            .client
            .post(&format!(
                "{}/subscriptions/{}/cancel",
                base_url, subscription_id
            ))
            .bearer_auth(api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                AppError::ExternalServiceError(format!("Paddle API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        info!(subscription_id = %subscription_id, "Cancelled Paddle subscription");
        Ok(())
    }

    /// Check if payment limits should be enforced
    pub fn should_enforce_limits(&self) -> bool {
        self.config.enforce_limits
    }

    /// Get free tier token limit
    pub fn free_tier_token_limit(&self) -> i64 {
        self.config.free_tier_token_limit
    }

    /// Get grace period in days
    pub fn grace_period_days(&self) -> i32 {
        self.config.grace_period_days
    }

    /// Generate customer portal authentication token and URL
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn generate_customer_portal_url(
        &self,
        customer_id: &str,
    ) -> Result<String, AppError> {
        let api_key = self.config.paddle_api_key.as_ref().ok_or_else(|| {
            AppError::ConfigurationError("Paddle API key not configured".to_string())
        })?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        // Create customer auth token request (customer_id in URL path, not body)
        let response = self
            .client
            .post(&format!(
                "{}/customers/{}/auth-tokens",
                base_url, customer_id
            ))
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|e| {
                error!(
                    error = %e,
                    customer_id = %customer_id,
                    "Failed to create customer auth token"
                );
                AppError::ExternalServiceError(format!(
                    "Failed to create customer auth token: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            error!(
                status = %status,
                error_body = %error_body,
                customer_id = %customer_id,
                "Paddle customer auth token API error"
            );
            return Err(AppError::ExternalServiceError(format!(
                "Paddle customer auth token API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();
        debug!(
            response_body = %response_text,
            customer_id = %customer_id,
            "Raw customer auth token response from Paddle API"
        );

        // Parse the response to extract the token
        let response_json: crate::DbJson = serde_json::from_str(&response_text).map_err(|e| {
            error!(
                error = %e,
                response_text = %response_text,
                "Failed to parse customer auth token response"
            );
            AppError::JsonParseError(format!(
                "Failed to parse customer auth token response: {}",
                e
            ))
        })?;

        // Extract the customer auth token from the response
        let auth_token = response_json
            .get("data")
            .and_then(|data| data.get("customer_auth_token"))
            .and_then(|token| token.as_str())
            .ok_or_else(|| {
                error!(
                    response_json = %response_json,
                    "Customer auth token not found in Paddle response"
                );
                AppError::ExternalServiceError(
                    "Customer auth token not found in response".to_string(),
                )
            })?;

        // Generate the customer portal URL with the token
        let portal_base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-vendors.paddle.com"
        } else {
            "https://vendors.paddle.com"
        };

        let portal_url = format!("{}?token={}", portal_base_url, auth_token);

        info!(
            customer_id = %customer_id,
            portal_url = %portal_url,
            sandbox_mode = %self.config.paddle_sandbox_mode,
            "Generated customer portal URL"
        );

        Ok(portal_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PaymentConfig {
        PaymentConfig {
            paddle_api_key: Some("test_api_key".to_string()),
            paddle_webhook_secret: Some("test_webhook_secret".to_string()),
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
            data_encryption_key: None,
            webhook_event_retention_days: 90,
        }
    }

    #[test]
    fn test_paddle_service_creation() {
        let config = test_config();
        let service = PaddleService::new(config);

        assert!(service.should_enforce_limits() == false);
        assert!(service.free_tier_token_limit() == 50000);
        assert!(service.grace_period_days() == 7);
    }

    #[tokio::test]
    async fn test_webhook_signature_verification() {
        let config = test_config();
        let service = PaddleService::new(config);

        let payload = b"test payload";

        // This will fail because we need proper HMAC calculation
        // But it tests the error path
        let result = service.verify_webhook_signature(payload, "invalid_signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_payload_parsing() {
        let config = test_config();
        let service = PaddleService::new(config);

        let payload = r#"{
            "event_type": "subscription_created",
            "event_id": "evt_123",
            "occurred_at": "2025-01-01T00:00:00Z",
            "data": {"subscription_id": "sub_123"}
        }"#;

        let webhook = service.parse_webhook_payload(payload.as_bytes());
        assert!(webhook.is_ok());

        let webhook = webhook.unwrap();
        assert_eq!(webhook.event_type, PaddleEventType::SubscriptionCreated);
        assert_eq!(webhook.event_id, "evt_123");
    }
}
