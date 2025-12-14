use crate::db::DbId;
use crate::db::DbTimestamp;
use chrono::{DateTime, NaiveDate, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

// ============================================================================
// Credit Balance
// ============================================================================

/// User's current credit balance and lifetime statistics
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, AsChangeset)]
#[diesel(table_name = crate::schema::user_credits)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct CreditBalance {
    pub user_id: crate::db::DbId,
    pub balance: i32,
    pub lifetime_earned: i32,
    pub lifetime_spent: i32,
    pub last_monthly_grant: Option<DbTimestamp>,
    pub created_at: Option<DbTimestamp>,
    pub updated_at: Option<DbTimestamp>,
    /// Version number for optimistic concurrency control
    /// Incremented on each update to prevent race conditions
    pub version: i32,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::user_credits)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewCreditBalance {
    pub user_id: crate::db::DbId,
    pub balance: i32,
    pub lifetime_earned: i32,
    pub lifetime_spent: i32,
    pub last_monthly_grant: Option<DbTimestamp>,
}

// ============================================================================
// Credit Transactions
// ============================================================================

/// Record of a credit transaction (encrypted sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::credit_transactions)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct CreditTransaction {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub amount: i32,
    pub balance_after: i32,
    pub transaction_type: String,
    pub description_encrypted: Vec<u8>,
    pub description_nonce: Vec<u8>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub reference_id: Option<String>,
    pub created_at: Option<DbTimestamp>,
    pub expires_at: Option<DbTimestamp>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credit_transactions)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewCreditTransaction {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub amount: i32,
    pub balance_after: i32,
    pub transaction_type: String,
    pub description_encrypted: Vec<u8>,
    pub description_nonce: Vec<u8>,
    pub metadata_encrypted: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub reference_id: Option<String>,
    pub created_at: Option<DbTimestamp>,
    pub expires_at: Option<DbTimestamp>,
}

/// Decrypted version for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditTransactionDto {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub amount: i32,
    pub balance_after: i32,
    pub transaction_type: String,
    pub description: String,
    pub metadata: Option<crate::DbJson>,
    pub reference_id: Option<String>,
    pub created_at: DbTimestamp,
    pub expires_at: Option<DbTimestamp>,
}

// ============================================================================
// Daily Usage Tracking
// ============================================================================

/// Daily usage statistics for soft limits
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, AsChangeset)]
#[diesel(table_name = crate::schema::daily_usage_tracking)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct DailyUsage {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub date: NaiveDate,
    pub message_count: i32,
    pub token_count: i64,
    pub model_breakdown: Option<crate::DbJson>,
    pub soft_limit_triggered_at: Option<i32>,
    pub created_at: Option<DbTimestamp>,
    pub updated_at: Option<DbTimestamp>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::daily_usage_tracking)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewDailyUsage {
    pub user_id: crate::db::DbId,
    pub date: NaiveDate,
    pub message_count: i32,
    pub token_count: i64,
    pub model_breakdown: Option<crate::DbJson>,
    pub soft_limit_triggered_at: Option<i32>,
}

/// Daily usage statistics DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUsageDto {
    pub date: NaiveDate,
    pub message_count: i32,
    pub token_count: i64,
    pub model_breakdown: crate::DbJson,
    pub soft_limit_triggered: bool,
    pub soft_limit_triggered_at: Option<i32>,
}

// ============================================================================
// Credit Packages
// ============================================================================

/// Available credit packages for purchase
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::credit_packages)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct CreditPackage {
    pub id: crate::db::DbId,
    pub package_id: String,
    pub name: String,
    pub credits: i32,
    pub price_cents: i32,
    pub bonus_percentage: Option<i32>,
    pub paddle_price_id: Option<String>,
    pub active: Option<bool>,
    pub display_order: Option<i32>,
    pub created_at: Option<DbTimestamp>,
    pub updated_at: Option<DbTimestamp>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credit_packages)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewCreditPackage {
    pub package_id: String,
    pub name: String,
    pub credits: i32,
    pub price_cents: i32,
    pub bonus_percentage: Option<i32>,
    pub paddle_price_id: Option<String>,
    pub active: Option<bool>,
    pub display_order: Option<i32>,
}

/// Credit package DTO for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditPackageDto {
    pub package_id: String,
    pub name: String,
    pub credits: i32,
    pub price_cents: i32,
    pub bonus_percentage: i32,
    pub total_credits: i32,
    pub price_per_credit: f64,
    pub paddle_price_id: Option<String>,
}

impl From<CreditPackage> for CreditPackageDto {
    fn from(package: CreditPackage) -> Self {
        let bonus = package.bonus_percentage.unwrap_or(0);
        let total_credits = package.credits + (package.credits * bonus / 100);
        let price_per_credit = package.price_cents as f64 / total_credits as f64 / 100.0;

        Self {
            package_id: package.package_id,
            name: package.name,
            credits: package.credits,
            price_cents: package.price_cents,
            bonus_percentage: bonus,
            total_credits,
            price_per_credit,
            paddle_price_id: package.paddle_price_id,
        }
    }
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to check if user has sufficient credits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckCreditsRequest {
    pub required_credits: i32,
}

/// Response with credit balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditBalanceResponse {
    pub balance: i32,
    pub lifetime_earned: i32,
    pub lifetime_spent: i32,
    pub last_monthly_grant: Option<DbTimestamp>,
}

impl From<CreditBalance> for CreditBalanceResponse {
    fn from(balance: CreditBalance) -> Self {
        Self {
            balance: balance.balance,
            lifetime_earned: balance.lifetime_earned,
            lifetime_spent: balance.lifetime_spent,
            last_monthly_grant: balance.last_monthly_grant,
        }
    }
}

/// Response for credit sufficiency check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditCheckResponse {
    pub has_sufficient_credits: bool,
    pub current_balance: i32,
    pub required_credits: i32,
}

/// Request to use credits for premium model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseCreditsRequest {
    pub model: String,
    pub session_id: crate::db::DbId,
    pub message_id: Option<crate::db::DbId>,
}

/// Response after using credits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseCreditsResponse {
    pub credits_used: i32,
    pub remaining_balance: i32,
    pub transaction_id: crate::db::DbId,
}
