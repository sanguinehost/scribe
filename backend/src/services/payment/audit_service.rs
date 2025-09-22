//! Privacy-focused audit logging for payment operations
//!
//! This service implements minimal audit logging with strong privacy protections:
//! - User IDs are hashed (not reversible without the original UUID)
//! - No personally identifiable information (PII) is logged
//! - Automatic purging of old records (30 days by default)
//! - Only essential financial events are tracked

use crate::errors::AppError;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Privacy-focused payment audit logger
#[derive(Clone)]
pub struct PaymentAuditService {
    retention_days: i64,
}

/// Event types that we track (minimal set for compliance)
#[derive(Debug, Clone, Copy, Serialize)]
pub enum AuditEventType {
    CreditAdded,
    CreditDeducted,
    SubscriptionCreated,
    SubscriptionCancelled,
    PaymentProcessed,
    PaymentFailed,
    WebhookReceived,
}

impl AuditEventType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CreditAdded => "credit_added",
            Self::CreditDeducted => "credit_deducted",
            Self::SubscriptionCreated => "subscription_created",
            Self::SubscriptionCancelled => "subscription_cancelled",
            Self::PaymentProcessed => "payment_processed",
            Self::PaymentFailed => "payment_failed",
            Self::WebhookReceived => "webhook_received",
        }
    }

    fn category(&self) -> &'static str {
        match self {
            Self::CreditAdded | Self::CreditDeducted => "credit",
            Self::SubscriptionCreated | Self::SubscriptionCancelled => "subscription",
            Self::PaymentProcessed | Self::PaymentFailed => "payment",
            Self::WebhookReceived => "webhook",
        }
    }
}

/// Minimal audit log entry
#[derive(Queryable, Insertable)]
#[diesel(table_name = crate::schema::payment_audit_logs)]
pub struct PaymentAuditLog {
    pub id: Uuid,
    pub user_id_hash: String,
    pub event_type: String,
    pub amount: Option<i32>,
    pub event_category: String,
    pub success: bool,
    pub error_code: Option<String>,
    pub external_reference_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl PaymentAuditService {
    /// Create a new audit service with default 30-day retention
    pub fn new() -> Self {
        Self { retention_days: 30 }
    }

    /// Create with custom retention period
    pub fn with_retention_days(days: i64) -> Self {
        Self {
            retention_days: days,
        }
    }

    /// Hash a user ID for privacy (one-way, non-reversible)
    fn hash_user_id(user_id: &Uuid) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Hash an external reference (e.g., Paddle transaction ID)
    fn hash_reference(reference: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(reference.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Log a credit operation (add or deduct)
    pub fn log_credit_operation(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        event_type: AuditEventType,
        amount: i32,
    ) -> Result<(), AppError> {
        use crate::schema::payment_audit_logs;

        let log_entry = PaymentAuditLog {
            id: Uuid::new_v4(),
            user_id_hash: Self::hash_user_id(&user_id),
            event_type: event_type.as_str().to_string(),
            amount: Some(amount),
            event_category: event_type.category().to_string(),
            success: true,
            error_code: None,
            external_reference_hash: None,
            created_at: Utc::now(),
        };

        diesel::insert_into(payment_audit_logs::table)
            .values(&log_entry)
            .execute(conn)
            .map_err(|e| {
                error!("Failed to insert audit log: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        debug!(
            "Audit logged: {} for amount {}",
            event_type.as_str(),
            amount
        );
        Ok(())
    }

    /// Log a subscription event
    pub fn log_subscription_event(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        event_type: AuditEventType,
        external_ref: Option<&str>,
    ) -> Result<(), AppError> {
        use crate::schema::payment_audit_logs;

        let log_entry = PaymentAuditLog {
            id: Uuid::new_v4(),
            user_id_hash: Self::hash_user_id(&user_id),
            event_type: event_type.as_str().to_string(),
            amount: None,
            event_category: event_type.category().to_string(),
            success: true,
            error_code: None,
            external_reference_hash: external_ref.map(Self::hash_reference),
            created_at: Utc::now(),
        };

        diesel::insert_into(payment_audit_logs::table)
            .values(&log_entry)
            .execute(conn)
            .map_err(|e| {
                error!("Failed to insert audit log: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        debug!("Audit logged: {}", event_type.as_str());
        Ok(())
    }

    /// Log a payment event (success or failure)
    pub fn log_payment_event(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        amount_cents: i32,
        success: bool,
        error_code: Option<&str>,
        external_ref: Option<&str>,
    ) -> Result<(), AppError> {
        use crate::schema::payment_audit_logs;

        let event_type = if success {
            AuditEventType::PaymentProcessed
        } else {
            AuditEventType::PaymentFailed
        };

        let log_entry = PaymentAuditLog {
            id: Uuid::new_v4(),
            user_id_hash: Self::hash_user_id(&user_id),
            event_type: event_type.as_str().to_string(),
            amount: Some(amount_cents),
            event_category: event_type.category().to_string(),
            success,
            error_code: error_code.map(|s| s.to_string()),
            external_reference_hash: external_ref.map(Self::hash_reference),
            created_at: Utc::now(),
        };

        diesel::insert_into(payment_audit_logs::table)
            .values(&log_entry)
            .execute(conn)
            .map_err(|e| {
                error!("Failed to insert audit log: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        if success {
            debug!("Payment success logged: {} cents", amount_cents);
        } else {
            debug!("Payment failure logged: {:?}", error_code);
        }
        Ok(())
    }

    /// Log a webhook event (minimal info only)
    pub fn log_webhook_event(
        &self,
        conn: &mut PgConnection,
        event_type: &str,
        external_ref: Option<&str>,
    ) -> Result<(), AppError> {
        use crate::schema::payment_audit_logs;

        // For webhooks, we don't have a user_id, so we use a static hash
        let log_entry = PaymentAuditLog {
            id: Uuid::new_v4(),
            user_id_hash: Self::hash_reference("webhook_system"),
            event_type: format!("webhook_{}", event_type),
            amount: None,
            event_category: "webhook".to_string(),
            success: true,
            error_code: None,
            external_reference_hash: external_ref.map(Self::hash_reference),
            created_at: Utc::now(),
        };

        diesel::insert_into(payment_audit_logs::table)
            .values(&log_entry)
            .execute(conn)
            .map_err(|e| {
                error!("Failed to insert audit log: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        debug!("Webhook event logged: {}", event_type);
        Ok(())
    }

    /// Purge old audit logs (privacy protection)
    pub fn purge_old_logs(&self, conn: &mut PgConnection) -> Result<usize, AppError> {
        use crate::schema::payment_audit_logs::dsl::*;

        let cutoff_date = Utc::now() - Duration::days(self.retention_days);

        let deleted = diesel::delete(payment_audit_logs)
            .filter(created_at.lt(cutoff_date))
            .execute(conn)
            .map_err(|e| {
                error!("Failed to purge old audit logs: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        if deleted > 0 {
            info!(
                "Purged {} old audit logs (>{}d old)",
                deleted, self.retention_days
            );
        }

        Ok(deleted)
    }

    /// Get aggregated statistics (no individual user data)
    pub fn get_aggregate_stats(
        &self,
        conn: &mut PgConnection,
        hours: i64,
    ) -> Result<AggregateStats, AppError> {
        use crate::schema::payment_audit_logs::dsl::*;

        let since = Utc::now() - Duration::hours(hours);

        // Count events by type
        let total_events: i64 = payment_audit_logs
            .filter(created_at.ge(since))
            .count()
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let successful_payments: i64 = payment_audit_logs
            .filter(created_at.ge(since))
            .filter(event_type.eq("payment_processed"))
            .filter(success.eq(true))
            .count()
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let failed_payments: i64 = payment_audit_logs
            .filter(created_at.ge(since))
            .filter(event_type.eq("payment_failed"))
            .count()
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(AggregateStats {
            period_hours: hours,
            total_events: total_events as u64,
            successful_payments: successful_payments as u64,
            failed_payments: failed_payments as u64,
        })
    }
}

/// Aggregate statistics only - no individual user data
#[derive(Debug, Serialize)]
pub struct AggregateStats {
    pub period_hours: i64,
    pub total_events: u64,
    pub successful_payments: u64,
    pub failed_payments: u64,
}

impl Default for PaymentAuditService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_hashing() {
        let user_id1 = Uuid::new_v4();
        let user_id2 = Uuid::new_v4();

        let hash1a = PaymentAuditService::hash_user_id(&user_id1);
        let hash1b = PaymentAuditService::hash_user_id(&user_id1);
        let hash2 = PaymentAuditService::hash_user_id(&user_id2);

        // Same ID produces same hash
        assert_eq!(hash1a, hash1b);

        // Different IDs produce different hashes
        assert_ne!(hash1a, hash2);

        // Hash is always 64 characters (SHA-256 hex)
        assert_eq!(hash1a.len(), 64);
        assert_eq!(hash2.len(), 64);
    }

    #[test]
    fn test_reference_hashing() {
        let ref1 = "paddle_transaction_123";
        let ref2 = "paddle_transaction_456";

        let hash1 = PaymentAuditService::hash_reference(ref1);
        let hash2 = PaymentAuditService::hash_reference(ref2);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }
}
