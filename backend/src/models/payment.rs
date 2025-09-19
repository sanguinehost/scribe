use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::fmt;
use uuid::Uuid;

use crate::schema::{payment_usage_tracking, payment_transactions, plan_features, subscriptions};

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
    pub id: Uuid,
    pub user_id: Uuid,
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: String,
    pub status: String,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DateTime<Utc>>,
}

/// New subscription for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = subscriptions)]
pub struct NewSubscription {
    pub id: Uuid,
    pub user_id: Uuid,
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: String,
    pub status: String,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DateTime<Utc>>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DateTime<Utc>>,
}

/// Update subscription for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = subscriptions)]
pub struct UpdateSubscription {
    pub paddle_customer_id: Option<String>,
    pub paddle_subscription_id: Option<String>,
    pub plan_type: Option<String>,
    pub status: Option<String>,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: Option<bool>,
    pub trial_end: Option<DateTime<Utc>>,
    pub credits_allocated_this_period: Option<bool>,
    pub soft_limit_override: Option<i32>,
    pub last_credit_grant: Option<DateTime<Utc>>,
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
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub paddle_price_id_yearly: Option<String>,
}

/// Payment usage tracking model for database queries
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = payment_usage_tracking)]
pub struct PaymentUsageTracking {
    pub id: Uuid,
    pub user_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub tokens_used: i32,
    pub tokens_limit: Option<i32>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub created_at: Option<DateTime<Utc>>,
}

/// New payment usage tracking for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = payment_usage_tracking)]
pub struct NewPaymentUsageTracking {
    pub id: Uuid,
    pub user_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub tokens_used: i32,
    pub tokens_limit: Option<i32>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
}

/// Update payment usage tracking for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = payment_usage_tracking)]
pub struct UpdatePaymentUsageTracking {
    pub tokens_used: Option<i32>,
    pub tokens_limit: Option<i32>,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
}

/// Payment transaction record from Paddle
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = payment_transactions)]
pub struct PaymentTransaction {
    pub id: Uuid,
    pub paddle_transaction_id: String,
    pub user_id: Uuid,
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
    pub billed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// New payment transaction for database insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = payment_transactions)]
pub struct NewPaymentTransaction {
    pub paddle_transaction_id: String,
    pub user_id: Uuid,
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
    pub billed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
}

/// Update payment transaction for database updates
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = payment_transactions)]
pub struct UpdatePaymentTransaction {
    pub status: Option<String>,
    pub billed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub paddle_data_encrypted: Option<Vec<u8>>,
    pub paddle_data_nonce: Option<Vec<u8>>,
    pub updated_at: Option<DateTime<Utc>>,
}