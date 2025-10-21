use crate::DbDateTime;
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use crate::DbJson as JsonValue;
use std::fmt;
use crate::DbUuid as Uuid;

use crate::schema::{payment_transactions, payment_usage_tracking, plan_features, subscriptions};

/// Subscription status types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    Cancelled,
    PastDue,
    Incomplete,
}

impl fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Trialing => write!(f, "trialing"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::PastDue => write!(f, "past_due"),
            Self::Incomplete => write!(f, "incomplete"),
        }
    }
}

impl From<&str> for SubscriptionStatus {
    fn from(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "trialing" => Self::Trialing,
            "cancelled" => Self::Cancelled,
            "past_due" => Self::PastDue,
            "incomplete" => Self::Incomplete,
            _ => Self::Incomplete,
        }
    }
}

/// Plan types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanType {
    Free,
    Premium,
    Pro,
    Enterprise,
}

impl fmt::Display for PlanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => write!(f, "free"),
            Self::Premium => write!(f, "premium"),
            Self::Pro => write!(f, "pro"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl From<&str> for PlanType {
    fn from(s: &str) -> Self {
        match s {
            "free" => Self::Free,
            "premium" => Self::Premium,
            "pro" => Self::Pro,
            "enterprise" => Self::Enterprise,
            _ => Self::Free,
        }
    }
}

/// Subscription model for database queries
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = subscriptions)]
pub struct Subscription {
    pub id: crate::DbUuid,
    pub user_id: crate::DbUuid,
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: String,
    pub status: String,
    pub current_period_start: DbDateTime,
    pub current_period_end: DbDateTime,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DbDateTime>,
    pub created_at: Option<DbDateTime>,
    pub updated_at: Option<DbDateTime>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DbDateTime>,
    pub paddle_sync_attempted: bool,
    pub first_payment_date: Option<DbDateTime>,
    pub has_ever_paid: Option<bool>,
    pub cancellation_date: Option<DbDateTime>,
    pub trial_start_date: Option<DbDateTime>,
    pub last_payment_date: Option<DbDateTime>,
    pub grace_period_end: Option<DbDateTime>,
    pub scheduled_plan_change: Option<String>,
    pub scheduled_change_date: Option<DbDateTime>,
}

/// New subscription for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = subscriptions)]
pub struct NewSubscription {
    pub id: crate::DbUuid,
    pub user_id: crate::DbUuid,
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: String,
    pub status: String,
    pub current_period_start: DbDateTime,
    pub current_period_end: DbDateTime,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DbDateTime>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DbDateTime>,
    pub paddle_sync_attempted: bool,
    pub first_payment_date: Option<DbDateTime>,
    pub has_ever_paid: Option<bool>,
    pub cancellation_date: Option<DbDateTime>,
    pub trial_start_date: Option<DbDateTime>,
    pub last_payment_date: Option<DbDateTime>,
    pub grace_period_end: Option<DbDateTime>,
    pub scheduled_plan_change: Option<String>,
    pub scheduled_change_date: Option<DbDateTime>,
}

/// Update subscription for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = subscriptions)]
pub struct UpdateSubscription {
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: Option<String>,
    pub status: Option<String>,
    pub current_period_start: Option<DbDateTime>,
    pub current_period_end: Option<DbDateTime>,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DbDateTime>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DbDateTime>,
    pub grace_period_end: Option<DbDateTime>,
    pub scheduled_plan_change: Option<String>,
    pub scheduled_change_date: Option<DbDateTime>,
}

/// Plan features model for database queries
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = plan_features)]
pub struct PlanFeatures {
    pub plan_type: String,
    pub monthly_token_limit: Option<i32>,
    pub characters_limit: Option<i32>,
    pub lorebooks_limit: Option<i32>,
    pub price_cents: Option<i32>,
    pub paddle_price_id: Option<String>,
    pub features: Option<JsonValue>,
    pub display_name: String,
    pub description: Option<String>,
    pub created_at: Option<DbDateTime>,
    pub updated_at: Option<DbDateTime>,
    pub paddle_price_id_yearly: Option<String>,
    pub max_context_tokens: Option<i32>,
}

/// Payment usage tracking model for database queries
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = payment_usage_tracking)]
pub struct PaymentUsageTracking {
    pub id: crate::DbUuid,
    pub user_id: crate::DbUuid,
    pub subscription_id: Option<crate::DbUuid>,
    pub tokens_used: i32,
    pub tokens_limit: Option<i32>,
    pub period_start: DbDateTime,
    pub period_end: DbDateTime,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub created_at: Option<DbDateTime>,
}

/// New payment usage tracking for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = payment_usage_tracking)]
pub struct NewPaymentUsageTracking {
    pub id: crate::DbUuid,
    pub user_id: crate::DbUuid,
    pub subscription_id: Option<crate::DbUuid>,
    pub tokens_used: i32,
    pub tokens_limit: Option<i32>,
    pub period_start: DbDateTime,
    pub period_end: DbDateTime,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
}

/// Update payment usage tracking for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = payment_usage_tracking)]
pub struct UpdatePaymentUsageTracking {
    pub tokens_used: Option<i32>,
    pub tokens_limit: Option<i32>,
    pub period_start: Option<DbDateTime>,
    pub period_end: Option<DbDateTime>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
}

/// Payment transaction record from Paddle
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = payment_transactions)]
pub struct PaymentTransaction {
    pub id: crate::DbUuid,
    pub paddle_transaction_id: String,
    pub user_id: crate::DbUuid,
    pub status: String,
    pub collection_mode: Option<String>,
    pub total_cents: i32,
    pub tax_cents: Option<i32>,
    pub discount_cents: Option<i32>,
    pub currency_code: Option<String>,
    pub paddle_customer_id: Option<String>,
    pub customer_data_encrypted: Option<Vec<u8>>,
    pub customer_data_nonce: Option<Vec<u8>>,
    pub items: JsonValue,
    pub checkout_id: Option<String>,
    pub billed_at: Option<DbDateTime>,
    pub completed_at: Option<DbDateTime>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
    pub created_at: Option<DbDateTime>,
    pub updated_at: Option<DbDateTime>,
}

/// New payment transaction for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = payment_transactions)]
pub struct NewPaymentTransaction {
    pub paddle_transaction_id: String,
    pub user_id: crate::DbUuid,
    pub status: String,
    pub collection_mode: Option<String>,
    pub total_cents: i32,
    pub tax_cents: Option<i32>,
    pub discount_cents: Option<i32>,
    pub currency_code: Option<String>,
    pub paddle_customer_id: Option<String>,
    pub customer_data_encrypted: Option<Vec<u8>>,
    pub customer_data_nonce: Option<Vec<u8>>,
    pub items: JsonValue,
    pub checkout_id: Option<String>,
    pub billed_at: Option<DbDateTime>,
    pub completed_at: Option<DbDateTime>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
}

/// Update payment transaction for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = payment_transactions)]
pub struct UpdatePaymentTransaction {
    pub status: Option<String>,
    pub billed_at: Option<DbDateTime>,
    pub completed_at: Option<DbDateTime>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
    pub updated_at: Option<DbDateTime>,
}

/// Decrypted customer data from payment transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerData {
    pub email: String,
    pub name: Option<JsonValue>,
    pub billing_details: Option<JsonValue>,
}

#[cfg(feature = "payment")]
impl PaymentTransaction {
    /// Decrypt customer data using the payment encryption key
    ///
    /// # Arguments
    /// * `encryption_service` - The encryption service for decryption
    /// * `encryption_key_bytes` - The payment data encryption key (decoded from base64)
    ///
    /// # Returns
    /// * `Ok(CustomerData)` - The decrypted customer data
    /// * `Err(AppError)` - If decryption fails or data is missing
    pub fn decrypt_customer_data(
        &self,
        encryption_service: &crate::services::encryption_service::EncryptionService,
        encryption_key_bytes: &[u8],
    ) -> Result<CustomerData, crate::errors::AppError> {
        use crate::errors::AppError;

        // Check if encrypted data exists
        let customer_data_encrypted = self
            .customer_data_encrypted
            .as_ref()
            .ok_or_else(|| AppError::NotFound("Customer data not found".to_string()))?;

        let customer_data_nonce = self
            .customer_data_nonce
            .as_ref()
            .ok_or_else(|| AppError::NotFound("Customer data nonce not found".to_string()))?;

        // Decrypt the data
        let decrypted_bytes = encryption_service.decrypt(
            customer_data_encrypted,
            customer_data_nonce,
            encryption_key_bytes,
        )?;

        // Parse the decrypted JSON
        let customer_data: CustomerData =
            serde_json::from_slice(&decrypted_bytes).map_err(|e| {
                AppError::SerializationError(format!("Failed to parse customer data: {}", e))
            })?;

        Ok(customer_data)
    }
}

// ============================================================================
// Webhook Event Models (for idempotency and replay protection)
// ============================================================================

/// Represents a processed webhook event for idempotency tracking
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::webhook_events)]
pub struct WebhookEvent {
    pub id: crate::DbUuid,
    pub event_id: String,
    pub event_type: String,
    pub paddle_signature: String,
    pub payload_hash: String,
    pub processed_at: DbDateTime,
    pub processing_status: String,
    pub created_at: DbDateTime,
}

/// New webhook event for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::webhook_events)]
pub struct NewWebhookEvent {
    pub event_id: String,
    pub event_type: String,
    pub paddle_signature: String,
    pub payload_hash: String,
    pub processing_status: String,
}
