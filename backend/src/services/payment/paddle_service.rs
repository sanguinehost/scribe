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
use uuid::Uuid;

/// Paddle service for payment processing
#[derive(Clone)]
pub struct PaddleService {
    config: PaymentConfig,
    client: reqwest::Client,
    encryption_service: EncryptionService,
}

/// Paddle webhook event types
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaddleEventType {
    SubscriptionCreated,
    SubscriptionUpdated,
    SubscriptionCancelled,
    TransactionCompleted,
    TransactionFailed,
    CustomerCreated,
    CustomerUpdated,
}

/// Paddle webhook payload structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleWebhook {
    pub event_type: PaddleEventType,
    pub event_id: String,
    pub occurred_at: DateTime<Utc>,
    pub data: serde_json::Value,
}

/// Paddle subscription data structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleSubscription {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    pub current_billing_period: Option<PaddleBillingPeriod>,
    pub billing_cycle: Option<PaddleBillingCycle>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub items: Vec<PaddleSubscriptionItem>,
}

/// Paddle billing period
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleBillingPeriod {
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
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
    pub price_id: String,
    pub quantity: i32,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paddle customer data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaddleCustomer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create transaction request (replaces subscription request)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTransactionRequest {
    pub customer_id: String,
    pub items: Vec<TransactionItem>,
    pub collection_mode: String, // "automatic" for checkout, "manual" for invoice
    pub checkout: Option<TransactionCheckout>,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    pub proration: Option<serde_json::Value>,
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
    pub billing_cycle: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_period: Option<serde_json::Value>,
    pub tax_mode: String,
    pub unit_price: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_price_overrides: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<serde_json::Value>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_meta: Option<serde_json::Value>,
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
    pub meta: serde_json::Value,
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
        let webhook_secret = self
            .config
            .paddle_webhook_secret
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle webhook secret not configured".to_string()))?;

        // Use HMAC-SHA256 to verify the signature
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .map_err(|e| AppError::InvalidWebhookSignature(format!("Invalid webhook secret: {}", e)))?;
        
        mac.update(payload);
        
        // Paddle sends signatures as hex-encoded strings
        let expected_signature = hex::encode(mac.finalize().into_bytes());
        
        // Compare signatures in constant time
        use subtle::ConstantTimeEq;
        let signature_bytes = hex::decode(signature)
            .map_err(|_| AppError::InvalidWebhookSignature("Invalid signature format".to_string()))?;
        let expected_bytes = hex::decode(&expected_signature)
            .map_err(|_| AppError::InvalidWebhookSignature("Invalid expected signature format".to_string()))?;
            
        if signature_bytes.ct_eq(&expected_bytes).into() {
            Ok(())
        } else {
            Err(AppError::InvalidWebhookSignature("Signature mismatch".to_string()))
        }
    }

    /// Parse webhook payload
    ///
    /// # Errors
    ///
    /// Returns `AppError::JsonParseError` if payload parsing fails
    pub fn parse_webhook_payload(&self, payload: &[u8]) -> Result<PaddleWebhook, AppError> {
        serde_json::from_slice(payload)
            .map_err(|e| AppError::JsonParseError(format!("Failed to parse webhook payload: {}", e)))
    }

    /// Create a Paddle customer
    ///
    /// # Errors
    ///
    /// Returns `AppError` if the Paddle API request fails
    pub async fn create_customer(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> Result<PaddleCustomer, AppError> {
        let api_key = self
            .config
            .paddle_api_key
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle API key not configured".to_string()))?;

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
            .map_err(|e| AppError::ExternalServiceError(format!("Paddle API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();
        
        // Paddle wraps the response in a "data" field
        let wrapper: PaddleApiResponse<PaddleCustomer> = serde_json::from_str(&response_text)
            .map_err(|e| AppError::JsonParseError(format!("Failed to parse customer response '{}': {}", response_text, e)))?;
        let customer = wrapper.data;

        info!(customer_id = %customer.id, email = %email, "Created Paddle customer");
        Ok(customer)
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
        let api_key = self
            .config
            .paddle_api_key
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle API key not configured".to_string()))?;

        let base_url = if self.config.paddle_sandbox_mode {
            "https://sandbox-api.paddle.com"
        } else {
            "https://api.paddle.com"
        };

        let response = self
            .client
            .post(&format!("{}/transactions", base_url))
            .bearer_auth(api_key)
            .json(request)
            .send()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Paddle API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();
        
        // Paddle wraps the response in a "data" field
        let wrapper: PaddleApiResponse<PaddleTransaction> = serde_json::from_str(&response_text)
            .map_err(|e| AppError::JsonParseError(format!("Failed to parse transaction response '{}': {}", response_text, e)))?;
        
        let transaction = wrapper.data;
        
        // Extract checkout URL from transaction
        let checkout_url = transaction.checkout
            .and_then(|checkout| checkout.url)
            .unwrap_or_else(|| format!("{}/pay?_ptxn={}", 
                &self.config.payment_base_url, 
                transaction.id));

        let transaction_response = CreateTransactionResponse {
            transaction_id: transaction.id.clone(),
            checkout_url,
            status: transaction.status.clone(),
        };

        info!(
            transaction_id = %transaction_response.transaction_id,
            customer_id = %request.customer_id,
            "Created Paddle transaction"
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
        let api_key = self
            .config
            .paddle_api_key
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle API key not configured".to_string()))?;

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
            .map_err(|e| AppError::ExternalServiceError(format!("Paddle API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();
        
        let wrapper: PaddleApiResponse<PaddleSubscription> = serde_json::from_str(&response_text)
            .map_err(|e| AppError::JsonParseError(format!("Failed to parse subscription response '{}': {}", response_text, e)))?;
        
        let subscription_response = CreateSubscriptionResponse {
            subscription_id: wrapper.data.id.clone(),
            checkout_url: None, // TODO: Extract checkout URL if present in response
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
        let api_key = self
            .config
            .paddle_api_key
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle API key not configured".to_string()))?;

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
            .map_err(|e| AppError::ExternalServiceError(format!("Paddle API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Paddle API error: {}",
                error_body
            )));
        }

        let response_text = response.text().await.unwrap_or_default();
        
        let wrapper: PaddleApiResponse<PaddleSubscription> = serde_json::from_str(&response_text)
            .map_err(|e| AppError::JsonParseError(format!("Failed to parse subscription response '{}': {}", response_text, e)))?;
        let subscription = wrapper.data;

        debug!(subscription_id = %subscription_id, "Retrieved Paddle subscription");
        Ok(subscription)
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
        let api_key = self
            .config
            .paddle_api_key
            .as_ref()
            .ok_or_else(|| AppError::ConfigurationError("Paddle API key not configured".to_string()))?;

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
            .post(&format!("{}/subscriptions/{}/cancel", base_url, subscription_id))
            .bearer_auth(api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Paddle API request failed: {}", e)))?;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PaymentConfig {
        PaymentConfig {
            paddle_api_key: Some("test_api_key".to_string()),
            paddle_webhook_secret: Some("test_webhook_secret".to_string()),
            paddle_sandbox_mode: true,
            free_tier_token_limit: 50000,
            enforce_limits: false,
            grace_period_days: 7,
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