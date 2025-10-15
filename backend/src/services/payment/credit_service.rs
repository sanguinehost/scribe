use crate::config::Config;
use crate::crypto::{decrypt_gcm, encrypt_gcm};
use crate::errors::AppError;
use crate::metrics::SECURITY_METRICS;
use crate::models::credit::{
    CreditBalance, CreditTransaction, NewCreditBalance, NewCreditTransaction,
};
use crate::models::users::UserDbQuery;
use crate::privacy::logging::loggable_user_id;
use crate::schema::{credit_transactions, users};
use crate::services::payment::{AuditEventType, PaymentAuditService};
use chrono::{Datelike, Duration, Utc};
use diesel::prelude::*;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Service for managing user credits and credit transactions
///
/// This service handles:
/// - Credit balance management with encryption
/// - Credit purchases
/// - Credit consumption
/// - Monthly credit grants for subscriptions
/// - Transaction history with user DEK encryption
/// - Privacy-focused audit logging
#[derive(Clone)]
pub struct CreditService {
    config: Arc<Config>,
    audit_service: PaymentAuditService,
}

/// Helper struct for encrypted transaction data
struct EncryptedTransactionData {
    description_encrypted: Vec<u8>,
    description_nonce: Vec<u8>,
    metadata_encrypted: Option<Vec<u8>>,
    metadata_nonce: Option<Vec<u8>>,
}

/// Statistics from credit expiry cleanup operation
#[derive(Debug, Clone)]
pub struct CleanupStats {
    pub users_affected: i32,
    pub credits_expired: i32,
}

impl CreditService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            audit_service: PaymentAuditService::new(),
        }
    }

    /// Check if credit system is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.payment.credits_enabled
    }

    /// Get user's current credit balance
    pub fn get_balance(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::user_credits::dsl;

        let balance = dsl::user_credits
            .find(user_id)
            .first::<CreditBalance>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to get credit balance: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Return existing balance or create new one with 0 credits
        match balance {
            Some(b) => Ok(b),
            None => self.initialize_user_credits(conn, user_id),
        }
    }

    /// Get user's available credit balance (excluding expired credits)
    pub fn get_available_balance(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<i32, AppError> {
        use diesel::dsl::sum;
        use diesel::sql_types::{Integer, Nullable};

        let available_balance: Option<i64> = credit_transactions::table
            .filter(credit_transactions::user_id.eq(user_id))
            .filter(
                credit_transactions::expires_at
                    .is_null()
                    .or(credit_transactions::expires_at.gt(Utc::now())),
            )
            .select(sum(credit_transactions::amount))
            .first(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to get available credit balance: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .flatten();

        Ok(available_balance.unwrap_or(0) as i32)
    }

    /// Get user's expired credit balance
    pub fn get_expired_balance(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<i32, AppError> {
        use diesel::dsl::sum;

        let expired_balance: Option<i64> = credit_transactions::table
            .filter(credit_transactions::user_id.eq(user_id))
            .filter(credit_transactions::expires_at.is_not_null())
            .filter(credit_transactions::expires_at.le(Utc::now()))
            .select(sum(credit_transactions::amount))
            .first(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to get expired credit balance: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .flatten();

        Ok(expired_balance.unwrap_or(0) as i32)
    }

    /// Cleanup expired credits for a user or all users
    ///
    /// Recalculates user_credits.balance to exclude expired credits.
    /// Transaction history is preserved for audit trail.
    ///
    /// # Arguments
    /// * `user_id` - If Some(user_id), cleanup for that user. If None, cleanup for all users.
    ///
    /// # Returns
    /// CleanupStats with users_affected and credits_expired
    pub fn cleanup_expired_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Option<Uuid>,
    ) -> Result<CleanupStats, AppError> {
        use crate::schema::user_credits::dsl;

        let mut users_affected = 0;
        let mut total_credits_expired = 0;

        // Get list of users to process
        let user_ids: Vec<Uuid> = if let Some(uid) = user_id {
            vec![uid]
        } else {
            dsl::user_credits
                .select(dsl::user_id)
                .load(conn)
                .map_err(|e| {
                    error!("Failed to get user list for cleanup: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?
        };

        for uid in user_ids {
            // Calculate available balance (non-expired credits)
            let available = self.get_available_balance(conn, uid)?;
            let expired = self.get_expired_balance(conn, uid)?;

            // Skip if no expired credits
            if expired == 0 {
                continue;
            }

            // Update user balance to reflect only non-expired credits
            diesel::update(dsl::user_credits)
                .filter(dsl::user_id.eq(uid))
                .set(dsl::balance.eq(available))
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to update balance during cleanup: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            users_affected += 1;
            total_credits_expired += expired;

            // Log cleanup action to audit trail
            if let Err(e) = self.audit_service.log_credit_operation(
                conn,
                uid,
                AuditEventType::CreditExpired,
                expired,
            ) {
                warn!("Failed to log credit expiry cleanup: {}", e);
            }

            info!(
                "Cleaned up {} expired credits for user {} (new balance: {})",
                expired, uid, available
            );
        }

        Ok(CleanupStats {
            users_affected,
            credits_expired: total_credits_expired,
        })
    }

    /// Initialize credit account for new user
    pub fn initialize_user_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::user_credits;

        let new_balance = NewCreditBalance {
            user_id,
            balance: 0,
            lifetime_earned: 0,
            lifetime_spent: 0,
            last_monthly_grant: None,
        };

        let result = diesel::insert_into(user_credits::table)
            .values(&new_balance)
            .get_result(conn)
            .map_err(|e| {
                error!("Failed to initialize user credits: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Log the credit initialization in audit log (privacy-focused)
        // Don't fail the transaction if audit logging fails
        if let Err(e) = self.audit_service.log_credit_operation(
            conn,
            user_id,
            AuditEventType::CreditAdded,
            0, // Initial balance is 0
        ) {
            warn!("Failed to log credit initialization audit event: {}", e);
        }

        Ok(result)
    }

    pub fn add_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        amount: i32,
        transaction_type: &str,
        description: &str,
        reference_id: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<CreditBalance, AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest(
                "Credit system is not enabled".to_string(),
            ));
        }

        use crate::schema::user_credits;

        conn.transaction(|conn| {
            // Get current balance with row-level lock
            let mut balance = user_credits::table
                .filter(user_credits::user_id.eq(user_id))
                .for_update()
                .first::<CreditBalance>(conn)
                .map_err(|e| match e {
                    diesel::NotFound => {
                        AppError::NotFound("User credit balance not found".to_string())
                    }
                    _ => {
                        error!("Failed to get credit balance for update: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })?;

            // Check max balance limit (based on available credits, excluding expired)
            let available_balance = self.get_available_balance(conn, user_id)?;
            let max_limit = self.config.payment.max_credit_balance as i32;

            // Reject if adding credits would exceed maximum limit
            if available_balance + amount > max_limit {
                return Err(AppError::BadRequest(format!(
                    "Adding {} credits would exceed maximum limit of {} (current balance: {})",
                    amount, max_limit, available_balance
                )));
            }

            let amount_to_add = amount;

            // Calculate new balance
            let new_balance = available_balance + amount_to_add;

            // Encrypt transaction data with user DEK
            let encrypted_data =
                self.encrypt_transaction_data(conn, user_id, description, metadata.clone())?;

            // Create transaction record
            let created_at = Utc::now();
            let expires_at = if self.config.payment.credit_expiry_days > 0 {
                Some(created_at + Duration::days(self.config.payment.credit_expiry_days as i64))
            } else {
                None // Credits never expire if expiry_days = 0
            };

            let transaction = NewCreditTransaction {
                id: Uuid::new_v4(),
                user_id,
                amount: amount_to_add,
                balance_after: new_balance,
                transaction_type: transaction_type.to_string(),
                description_encrypted: encrypted_data.description_encrypted,
                description_nonce: encrypted_data.description_nonce,
                metadata_encrypted: encrypted_data.metadata_encrypted,
                metadata_nonce: encrypted_data.metadata_nonce,
                reference_id: reference_id.clone(),
                created_at: Some(created_at),
                expires_at,
            };

            diesel::insert_into(crate::schema::credit_transactions::table)
                .values(&transaction)
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to insert credit transaction: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            // Update balance (atomic with optimistic locking)
            // Set last_monthly_grant if this is a monthly grant transaction
            let rows_updated = if transaction_type == "monthly_grant" {
                diesel::update(user_credits::table)
                    .filter(user_credits::user_id.eq(user_id))
                    .filter(user_credits::version.eq(balance.version)) // Optimistic lock check
                    .set((
                        user_credits::balance.eq(new_balance),
                        user_credits::lifetime_earned.eq(balance.lifetime_earned + amount_to_add),
                        user_credits::last_monthly_grant.eq(Some(Utc::now())),
                        user_credits::version.eq(balance.version + 1),
                        user_credits::updated_at.eq(Utc::now()),
                    ))
                    .execute(conn)
                    .map_err(|e| {
                        error!("Failed to update credit balance: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    })?
            } else {
                diesel::update(user_credits::table)
                    .filter(user_credits::user_id.eq(user_id))
                    .filter(user_credits::version.eq(balance.version)) // Optimistic lock check
                    .set((
                        user_credits::balance.eq(new_balance),
                        user_credits::lifetime_earned.eq(balance.lifetime_earned + amount_to_add),
                        user_credits::version.eq(balance.version + 1),
                        user_credits::updated_at.eq(Utc::now()),
                    ))
                    .execute(conn)
                    .map_err(|e| {
                        error!("Failed to update credit balance: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    })?
            };

            if rows_updated == 0 {
                return Err(AppError::Conflict(
                    "Credit balance was modified by another transaction".to_string(),
                ));
            }

            // Log the credit addition in audit log (privacy-focused)
            if let Err(e) = self.audit_service.log_credit_operation(
                conn,
                user_id,
                AuditEventType::CreditAdded,
                amount_to_add,
            ) {
                error!("Failed to audit log credit addition: {}", e);
            }

            // SECURITY MONITORING: Record credit operation for anomaly detection
            let user_hash = loggable_user_id(user_id);
            SECURITY_METRICS.record_credit_operation(
                &user_hash.to_string(),
                "add",
                amount_to_add as f64,
            );

            // Update and return the balance
            balance.balance = new_balance;
            balance.lifetime_earned += amount_to_add;
            balance.version += 1;
            if transaction_type == "monthly_grant" {
                balance.last_monthly_grant = Some(Utc::now());
            }

            debug!(
                "Added {} credits for user {} (new balance: {})",
                amount_to_add, user_id, new_balance
            );

            Ok(balance)
        })
    }

    /// Deduct credits from user account (usage)
    pub fn deduct_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        amount: i32,
        description: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<CreditBalance, AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest(
                "Credit system is not enabled".to_string(),
            ));
        }

        if amount <= 0 {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        const MAX_RETRIES: u32 = 3;

        for attempt in 0..MAX_RETRIES {
            // Get current balance
            let balance = self.get_balance(conn, user_id)?;
            let current_version = balance.version;

            // Check available balance (excluding expired credits)
            let available_balance = self.get_available_balance(conn, user_id)?;

            if available_balance < amount {
                let expired_balance = self.get_expired_balance(conn, user_id)?;
                return Err(AppError::InsufficientCredits {
                    required: amount,
                    available: available_balance,
                    expired: if expired_balance > 0 {
                        Some(expired_balance)
                    } else {
                        None
                    },
                });
            }

            // Calculate new balance
            let new_balance = balance.balance - amount;

            // Encrypt transaction data with user DEK
            let encrypted_data =
                self.encrypt_transaction_data(conn, user_id, description, metadata.clone())?;

            // Create transaction record (negative amount for deduction)
            let transaction = NewCreditTransaction {
                id: Uuid::new_v4(),
                user_id,
                amount: -amount, // Negative for deductions
                balance_after: new_balance,
                transaction_type: "usage".to_string(),
                description_encrypted: encrypted_data.description_encrypted,
                description_nonce: encrypted_data.description_nonce,
                metadata_encrypted: encrypted_data.metadata_encrypted,
                metadata_nonce: encrypted_data.metadata_nonce,
                reference_id: None,
                created_at: Some(Utc::now()),
                expires_at: None, // Deductions don't have expiry
            };

            // Insert transaction first
            diesel::insert_into(credit_transactions::table)
                .values(&transaction)
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to insert credit transaction: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            // Atomic update with version check (optimistic locking)
            use crate::schema::user_credits::dsl;
            let rows_updated = diesel::update(dsl::user_credits)
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::version.eq(current_version))
                .set((
                    dsl::balance.eq(new_balance),
                    dsl::lifetime_spent.eq(balance.lifetime_spent + amount),
                    dsl::version.eq(current_version + 1),
                    dsl::updated_at.eq(Some(Utc::now())),
                ))
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to update credit balance atomically: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            if rows_updated == 1 {
                // Success - version matched, update applied
                let updated_balance = dsl::user_credits.find(user_id).first(conn).map_err(|e| {
                    error!("Failed to retrieve updated balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                // Log the credit deduction in audit log (privacy-focused)
                if let Err(e) = self.audit_service.log_credit_operation(
                    conn,
                    user_id,
                    AuditEventType::CreditDeducted,
                    amount,
                ) {
                    error!("Failed to audit log credit deduction: {}", e);
                }

                // SECURITY MONITORING: Record credit deduction for anomaly detection
                let user_hash = loggable_user_id(user_id);
                SECURITY_METRICS.record_credit_operation(
                    &user_hash.to_string(),
                    "deduct",
                    amount as f64,
                );

                return Ok(updated_balance);
            }

            // Version conflict - retry
            if attempt < MAX_RETRIES - 1 {
                warn!(
                    "Version conflict on deduct_credits (user: {}, attempt: {}), retrying...",
                    user_id,
                    attempt + 1
                );
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1) as u64));
            }
        }

        // All retries exhausted
        error!(
            "Deduct credits failed after {} retries due to version conflicts (user: {})",
            MAX_RETRIES, user_id
        );
        Err(AppError::Conflict(
            "Credit deduction failed due to concurrent modifications. Please try again."
                .to_string(),
        ))
    }

    pub fn reserve_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        amount: i32,
        description: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(CreditBalance, Uuid), AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest(
                "Credit system is not enabled".to_string(),
            ));
        }

        if amount <= 0 {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        const MAX_RETRIES: u32 = 3;
        let reservation_id = Uuid::new_v4();

        for attempt in 0..MAX_RETRIES {
            // Get current balance WITHOUT row lock (optimistic locking approach)
            use crate::schema::user_credits::dsl;
            let balance_option = dsl::user_credits
                .find(user_id)
                .first(conn)
                .optional()
                .map_err(|e| {
                    error!("Failed to query credit balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            let balance: CreditBalance = match balance_option {
                Some(b) => b,
                None => {
                    // Create initial balance if not exists
                    let new_balance = NewCreditBalance {
                        user_id,
                        balance: 0,
                        lifetime_earned: 0,
                        lifetime_spent: 0,
                        last_monthly_grant: None,
                    };

                    diesel::insert_into(dsl::user_credits)
                        .values(&new_balance)
                        .get_result::<CreditBalance>(conn)
                        .map_err(|e| {
                            error!("Failed to create initial credit balance: {}", e);
                            AppError::DatabaseQueryError(e.to_string())
                        })?
                }
            };

            let current_version = balance.version;

            // Check sufficient balance
            if balance.balance < amount {
                return Err(AppError::BadRequest(format!(
                    "Insufficient credits. Balance: {}, Required: {}",
                    balance.balance, amount
                )));
            }

            // Calculate new balance
            let new_balance = balance.balance - amount;

            // Encrypt transaction data with user DEK
            let mut metadata_with_status = metadata.clone().unwrap_or_else(|| json!({}));
            metadata_with_status["status"] = json!("pending");
            metadata_with_status["reservation_id"] = json!(reservation_id.to_string());

            let encrypted_data = self.encrypt_transaction_data(
                conn,
                user_id,
                description,
                Some(metadata_with_status),
            )?;

            // Create pending transaction record
            let transaction = NewCreditTransaction {
                id: reservation_id,
                user_id,
                amount: -amount, // Negative for deductions
                balance_after: new_balance,
                transaction_type: "pending".to_string(),
                description_encrypted: encrypted_data.description_encrypted,
                description_nonce: encrypted_data.description_nonce,
                metadata_encrypted: encrypted_data.metadata_encrypted,
                metadata_nonce: encrypted_data.metadata_nonce,
                reference_id: Some(reservation_id.to_string()),
                created_at: Some(Utc::now()),
                expires_at: None, // Reservations don't have expiry
            };

            // Atomic update with version check (optimistic locking)
            let rows_updated = diesel::update(dsl::user_credits)
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::version.eq(current_version))
                .set((
                    dsl::balance.eq(new_balance),
                    dsl::version.eq(current_version + 1),
                    dsl::updated_at.eq(Some(Utc::now())),
                ))
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to update credit balance atomically: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            if rows_updated == 1 {
                // Success - version matched, update applied
                // Insert pending transaction
                diesel::insert_into(credit_transactions::table)
                    .values(&transaction)
                    .execute(conn)
                    .map_err(|e| {
                        error!("Failed to insert pending credit transaction: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    })?;

                // Get updated balance to return
                let updated_balance = dsl::user_credits.find(user_id).first(conn).map_err(|e| {
                    error!("Failed to retrieve updated balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                // Log the credit reservation in audit log (privacy-focused)
                // Don't fail the transaction if audit logging fails
                if let Err(e) = self.audit_service.log_credit_operation(
                    conn,
                    user_id,
                    AuditEventType::CreditDeducted,
                    amount,
                ) {
                    warn!("Failed to log credit reservation audit event: {}", e);
                }

                info!(
                    "Reserved {} credits for user {} (reservation: {}, attempt: {})",
                    amount,
                    user_id,
                    reservation_id,
                    attempt + 1
                );

                return Ok((updated_balance, reservation_id));
            }

            // Version conflict - another transaction modified the balance
            if attempt < MAX_RETRIES - 1 {
                warn!(
                    "Version conflict on credit reservation (user: {}, attempt: {}), retrying...",
                    user_id,
                    attempt + 1
                );
                // Exponential backoff: 10ms, 20ms, 30ms
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1) as u64));
            }
        }

        // All retries exhausted
        error!(
            "Credit reservation failed after {} retries due to version conflicts (user: {})",
            MAX_RETRIES, user_id
        );
        Err(AppError::Conflict(
            "Credit reservation failed due to concurrent modifications. Please try again."
                .to_string(),
        ))
    }

    /// Confirm a credit reservation (converts pending to confirmed)
    pub fn confirm_reservation(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        reservation_id: Uuid,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::credit_transactions::dsl;

        // Find the pending transaction
        let transaction: CreditTransaction = dsl::credit_transactions
            .filter(dsl::id.eq(reservation_id))
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::transaction_type.eq("pending"))
            .first(conn)
            .map_err(|e| {
                error!(
                    "Failed to find pending transaction {}: {}",
                    reservation_id, e
                );
                AppError::NotFound(format!("Reservation {} not found", reservation_id))
            })?;

        // Update transaction to confirmed
        diesel::update(dsl::credit_transactions.find(reservation_id))
            .set(dsl::transaction_type.eq("usage"))
            .execute(conn)
            .map_err(|e| {
                error!("Failed to confirm reservation {}: {}", reservation_id, e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Update lifetime spent
        use crate::schema::user_credits;
        let mut balance: CreditBalance = user_credits::dsl::user_credits
            .find(user_id)
            .first(conn)
            .map_err(|e| {
                error!("Failed to get balance for confirmation: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        balance.lifetime_spent += transaction.amount.abs();
        balance.updated_at = Some(Utc::now());

        let updated_balance: CreditBalance =
            diesel::update(user_credits::dsl::user_credits.find(user_id))
                .set(&balance)
                .get_result(conn)
                .map_err(|e| {
                    error!("Failed to update lifetime spent: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

        // Log the confirmed credit deduction in audit log
        if let Err(e) = self.audit_service.log_credit_operation(
            conn,
            user_id,
            AuditEventType::CreditDeducted,
            transaction.amount.abs(),
        ) {
            error!("Failed to audit log confirmed credit deduction: {}", e);
        }

        info!(
            "Confirmed credit reservation {} for user {}",
            reservation_id, user_id
        );

        Ok(updated_balance)
    }

    /// Refund a credit reservation (returns credits and marks transaction as refunded)
    pub fn refund_reservation(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        reservation_id: Uuid,
        reason: &str,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::credit_transactions::dsl;

        // Find the pending transaction
        let transaction: CreditTransaction = dsl::credit_transactions
            .filter(dsl::id.eq(reservation_id))
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::transaction_type.eq("pending"))
            .first(conn)
            .map_err(|e| {
                error!(
                    "Failed to find pending transaction for refund {}: {}",
                    reservation_id, e
                );
                AppError::NotFound(format!("Reservation {} not found", reservation_id))
            })?;

        let refund_amount = transaction.amount.abs();

        // Update transaction to refunded
        diesel::update(dsl::credit_transactions.find(reservation_id))
            .set(dsl::transaction_type.eq("refunded"))
            .execute(conn)
            .map_err(|e| {
                error!(
                    "Failed to mark reservation as refunded {}: {}",
                    reservation_id, e
                );
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Return credits to user balance
        use crate::schema::user_credits;
        let mut balance: CreditBalance = user_credits::dsl::user_credits
            .find(user_id)
            .first(conn)
            .map_err(|e| {
                error!("Failed to get balance for refund: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        balance.balance += refund_amount;
        balance.updated_at = Some(Utc::now());

        let updated_balance: CreditBalance =
            diesel::update(user_credits::dsl::user_credits.find(user_id))
                .set(&balance)
                .get_result(conn)
                .map_err(|e| {
                    error!("Failed to refund credits: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

        // Create refund transaction record
        let refund_description = format!("Refund: {}", reason);
        let encrypted_data = self.encrypt_transaction_data(
            conn,
            user_id,
            &refund_description,
            Some(json!({
                "original_reservation": reservation_id.to_string(),
                "reason": reason
            })),
        )?;

        let created_at = Utc::now();
        let expires_at = if self.config.payment.credit_expiry_days > 0 {
            Some(created_at + Duration::days(self.config.payment.credit_expiry_days as i64))
        } else {
            None // Credits never expire if expiry_days = 0
        };

        let refund_transaction = NewCreditTransaction {
            id: Uuid::new_v4(),
            user_id,
            amount: refund_amount as i32, // Positive for refunds
            balance_after: updated_balance.balance,
            transaction_type: "refund".to_string(),
            description_encrypted: encrypted_data.description_encrypted,
            description_nonce: encrypted_data.description_nonce,
            metadata_encrypted: encrypted_data.metadata_encrypted,
            metadata_nonce: encrypted_data.metadata_nonce,
            reference_id: Some(reservation_id.to_string()),
            created_at: Some(created_at),
            expires_at,
        };

        diesel::insert_into(credit_transactions::table)
            .values(&refund_transaction)
            .execute(conn)
            .map_err(|e| {
                error!("Failed to insert refund transaction: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        info!(
            "Refunded {} credits for reservation {} (user: {}, reason: {})",
            refund_amount, reservation_id, user_id, reason
        );

        Ok(updated_balance)
    }

    /// Adjust a pending reservation to reflect actual usage (partial refund)
    /// This is used when actual token usage is less than the upfront reservation
    pub fn adjust_reservation_to_actual_cost(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        reservation_id: Uuid,
        actual_cost: i32,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::credit_transactions::dsl;

        // Find the pending transaction
        let transaction: CreditTransaction = dsl::credit_transactions
            .filter(dsl::id.eq(reservation_id))
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::transaction_type.eq("pending"))
            .first(conn)
            .map_err(|e| {
                error!(
                    "Failed to find pending transaction for adjustment {}: {}",
                    reservation_id, e
                );
                AppError::NotFound(format!("Reservation {} not found", reservation_id))
            })?;

        let reserved_amount = transaction.amount.abs();

        // If actual cost is greater than or equal to reserved, no adjustment needed
        if actual_cost >= reserved_amount {
            info!(
                reservation_id = %reservation_id,
                reserved = reserved_amount,
                actual = actual_cost,
                "Actual cost >= reserved amount, no adjustment needed"
            );
            return self.get_balance(conn, user_id);
        }

        let refund_amount = reserved_amount - actual_cost;

        // Update the pending transaction to reflect actual cost
        diesel::update(dsl::credit_transactions.find(reservation_id))
            .set(dsl::amount.eq(-(actual_cost))) // Negative for deduction
            .execute(conn)
            .map_err(|e| {
                error!(
                    "Failed to adjust reservation amount {}: {}",
                    reservation_id, e
                );
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Return the difference to user balance
        use crate::schema::user_credits;
        let mut balance: CreditBalance = user_credits::dsl::user_credits
            .find(user_id)
            .first(conn)
            .map_err(|e| {
                error!("Failed to get balance for adjustment: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        balance.balance += refund_amount;
        balance.updated_at = Some(Utc::now());

        let updated_balance: CreditBalance =
            diesel::update(user_credits::dsl::user_credits.find(user_id))
                .set(&balance)
                .get_result(conn)
                .map_err(|e| {
                    error!("Failed to adjust user balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

        info!(
            reservation_id = %reservation_id,
            user_id = %user_id,
            reserved = reserved_amount,
            actual = actual_cost,
            refunded = refund_amount,
            new_balance = updated_balance.balance,
            "Adjusted reservation to actual cost"
        );

        Ok(updated_balance)
    }

    /// Grant monthly credits based on subscription tier
    pub fn grant_monthly_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        tier: &str,
    ) -> Result<CreditBalance, AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest(
                "Credit system is not enabled".to_string(),
            ));
        }

        // Load subscription tiers config
        let tier_config = self.load_subscription_tier_config(tier)?;
        let monthly_credits = tier_config["credits"]["included_monthly"]
            .as_u64()
            .ok_or_else(|| AppError::BadRequest("Invalid tier configuration".to_string()))?
            as i32;

        if monthly_credits == 0 {
            // No credits for this tier (e.g., free tier)
            return self.get_balance(conn, user_id);
        }

        // Check if already granted this month
        let balance = self.get_balance(conn, user_id)?;
        if let Some(last_grant) = balance.last_monthly_grant {
            let now = Utc::now();
            if last_grant.date_naive().month() == now.date_naive().month()
                && last_grant.date_naive().year() == now.date_naive().year()
            {
                debug!("Monthly credits already granted for user {}", user_id);
                return Ok(balance);
            }
        }

        // Grant credits
        self.add_credits(
            conn,
            user_id,
            monthly_credits,
            "monthly_grant",
            &format!("Monthly credit grant for {} tier", tier),
            None,
            Some(json!({
                "tier": tier,
                "credits": monthly_credits
            })),
        )
    }

    /// Load subscription tier configuration
    fn load_subscription_tier_config(&self, tier: &str) -> Result<serde_json::Value, AppError> {
        let config_path = &self.config.payment.subscription_config_path;
        let config_str = std::fs::read_to_string(config_path).map_err(|e| {
            AppError::ConfigurationError(format!("Failed to load subscription config: {}", e))
        })?;

        let config: serde_json::Value = serde_json::from_str(&config_str).map_err(|e| {
            AppError::ConfigurationError(format!("Invalid subscription config: {}", e))
        })?;

        config["tiers"][tier]
            .as_object()
            .ok_or_else(|| AppError::BadRequest(format!("Invalid tier: {}", tier)))
            .map(|o| serde_json::Value::Object(o.clone()))
    }

    /// Get transaction history for a user
    pub fn get_transaction_history(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<CreditTransaction>, AppError> {
        use crate::schema::credit_transactions::dsl;

        let mut query = dsl::credit_transactions
            .filter(dsl::user_id.eq(user_id))
            .order(dsl::created_at.desc())
            .into_boxed();

        if let Some(l) = limit {
            query = query.limit(l);
        }

        if let Some(o) = offset {
            query = query.offset(o);
        }

        let transactions = query.load::<CreditTransaction>(conn).map_err(|e| {
            error!("Failed to get transaction history: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?;

        // Note: We return encrypted transactions here
        // The API layer should decrypt them before sending to client
        Ok(transactions)
    }

    /// Check if user has sufficient credits for an operation
    pub fn has_sufficient_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        required_credits: i32,
    ) -> Result<bool, AppError> {
        let balance = self.get_balance(conn, user_id)?;
        Ok(balance.balance >= required_credits)
    }

    /// Process credit purchase from Paddle webhook
    pub fn process_credit_purchase(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        package_id: &str,
        paddle_transaction_id: &str,
    ) -> Result<CreditBalance, AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest(
                "Credit system is not enabled".to_string(),
            ));
        }

        // Load credit package config
        use crate::schema::credit_packages::dsl;
        let package: crate::models::credit::CreditPackage = dsl::credit_packages
            .filter(dsl::package_id.eq(package_id))
            .filter(dsl::active.eq(true))
            .first(conn)
            .map_err(|e| {
                error!("Failed to find credit package: {}", e);
                AppError::NotFound(format!("Credit package {} not found", package_id))
            })?;

        // Calculate total credits (base + bonus)
        let bonus_credits = (package.credits * package.bonus_percentage.unwrap_or(0)) / 100;
        let total_credits = package.credits + bonus_credits;

        // Add credits to user account
        let result = self.add_credits(
            conn,
            user_id,
            total_credits,
            "purchase",
            &format!("Purchased {} credit package", package.name),
            Some(paddle_transaction_id.to_string()),
            Some(json!({
                "package_id": package_id,
                "base_credits": package.credits,
                "bonus_credits": bonus_credits,
                "total_credits": total_credits,
                "price_cents": package.price_cents
            })),
        )?;

        // Log the payment processed event (separate from credit addition)
        if let Err(e) = self.audit_service.log_payment_event(
            conn,
            user_id,
            package.price_cents,
            true, // success
            None, // no error code
            Some(paddle_transaction_id),
        ) {
            error!("Failed to audit log payment event: {}", e);
        }

        Ok(result)
    }

    /// Encrypt transaction data with user's DEK
    ///
    /// In a production system, this would use the user's decrypted DEK from their session.
    /// For now, we use a deterministic key derivation based on the user's encrypted DEK.
    fn encrypt_transaction_data(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        description: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<EncryptedTransactionData, AppError> {
        // Get user's encrypted DEK from database
        let user: UserDbQuery = users::table.find(user_id).first(conn).map_err(|e| {
            error!("Failed to get user for encryption: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?;

        // Derive a credit-specific key using HMAC
        // In production, you would:
        // 1. Get the decrypted DEK from the user's session (passed as a parameter)
        // 2. Use that DEK directly to encrypt the transaction data
        // For demonstration, we'll use HMAC to derive a key from the encrypted DEK
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Use a fixed context string for credit transactions
        let context = format!("credit_transactions_{}", user_id);

        // Create HMAC with the encrypted DEK as the key
        // Note: This is a simplified approach for demonstration
        let mut mac =
            HmacSha256::new_from_slice(&user.encrypted_dek[..32.min(user.encrypted_dek.len())])
                .map_err(|e| {
                    error!("Failed to create HMAC for key derivation: {}", e);
                    AppError::EncryptionError("Failed to derive credit key".to_string())
                })?;

        mac.update(context.as_bytes());
        let key_material = mac.finalize().into_bytes();
        let credit_key = SecretBox::new(Box::new(key_material.to_vec()));

        // Encrypt description
        let (description_encrypted, description_nonce) =
            encrypt_gcm(description.as_bytes(), &credit_key).map_err(|e| {
                error!("Failed to encrypt transaction description: {}", e);
                AppError::EncryptionError("Failed to encrypt transaction description".to_string())
            })?;

        // Encrypt metadata if present
        let (metadata_encrypted, metadata_nonce) = if let Some(meta) = metadata {
            let meta_str = serde_json::to_string(&meta)
                .map_err(|e| AppError::SerializationError(e.to_string()))?;

            let (encrypted, nonce) =
                encrypt_gcm(meta_str.as_bytes(), &credit_key).map_err(|e| {
                    error!("Failed to encrypt transaction metadata: {}", e);
                    AppError::EncryptionError("Failed to encrypt transaction metadata".to_string())
                })?;

            (Some(encrypted), Some(nonce))
        } else {
            (None, None)
        };

        info!(
            "Successfully encrypted credit transaction data for user {}",
            user_id
        );

        Ok(EncryptedTransactionData {
            description_encrypted,
            description_nonce,
            metadata_encrypted,
            metadata_nonce,
        })
    }

    /// Decrypt transaction data for API response
    ///
    /// In production, this should always receive the session DEK.
    /// The fallback derivation is only for demonstration/testing.
    pub fn decrypt_transaction_data(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        transaction: &CreditTransaction,
        session_dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<(String, Option<serde_json::Value>), AppError> {
        // Derive the credit key (same as in encrypt_transaction_data)
        let credit_key = if let Some(dek) = session_dek {
            // In production, use the session DEK to derive a credit-specific key
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let context = format!("credit_transactions_{}", user_id);
            let mut mac = HmacSha256::new_from_slice(dek.expose_secret()).map_err(|e| {
                error!("Failed to create HMAC for key derivation: {}", e);
                AppError::DecryptionError("Failed to derive credit key".to_string())
            })?;

            mac.update(context.as_bytes());
            let key_material = mac.finalize().into_bytes();
            SecretBox::new(Box::new(key_material.to_vec()))
        } else {
            // Fallback: derive the same key we used for encryption
            let user: UserDbQuery = users::table.find(user_id).first(conn).map_err(|e| {
                error!("Failed to get user for decryption: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let context = format!("credit_transactions_{}", user_id);
            let mut mac =
                HmacSha256::new_from_slice(&user.encrypted_dek[..32.min(user.encrypted_dek.len())])
                    .map_err(|e| {
                        error!("Failed to create HMAC for key derivation: {}", e);
                        AppError::DecryptionError("Failed to derive credit key".to_string())
                    })?;

            mac.update(context.as_bytes());
            let key_material = mac.finalize().into_bytes();
            SecretBox::new(Box::new(key_material.to_vec()))
        };

        // Decrypt description
        let description_bytes = decrypt_gcm(
            &transaction.description_encrypted,
            &transaction.description_nonce,
            &credit_key,
        )
        .map_err(|e| {
            error!("Failed to decrypt transaction description: {}", e);
            AppError::DecryptionError("Failed to decrypt transaction description".to_string())
        })?;

        let description =
            String::from_utf8(description_bytes.expose_secret().clone()).map_err(|e| {
                error!("Failed to convert decrypted description to string: {}", e);
                AppError::DecryptionError("Invalid UTF-8 in decrypted description".to_string())
            })?;

        // Decrypt metadata if present
        let metadata = if let (Some(encrypted), Some(nonce)) =
            (&transaction.metadata_encrypted, &transaction.metadata_nonce)
        {
            let metadata_bytes = decrypt_gcm(encrypted, nonce, &credit_key).map_err(|e| {
                error!("Failed to decrypt transaction metadata: {}", e);
                AppError::DecryptionError("Failed to decrypt transaction metadata".to_string())
            })?;

            let metadata_str =
                String::from_utf8(metadata_bytes.expose_secret().clone()).map_err(|e| {
                    error!("Failed to convert decrypted metadata to string: {}", e);
                    AppError::DecryptionError("Invalid UTF-8 in decrypted metadata".to_string())
                })?;

            Some(serde_json::from_str(&metadata_str).map_err(|e| {
                error!("Failed to parse decrypted metadata as JSON: {}", e);
                AppError::DecryptionError("Invalid JSON in decrypted metadata".to_string())
            })?)
        } else {
            None
        };

        Ok((description, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{TestDataGuard, spawn_app};

    #[tokio::test]
    async fn test_credit_balance_lifecycle() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone(), app.test_db_name.clone());

        // Create a test user to satisfy foreign key constraint
        let test_user = crate::test_helpers::db::create_test_user(
            &app.db_pool,
            "test_credit_user".to_string(),
            "password123".to_string(),
        )
        .await
        .unwrap();
        let user_id = test_user.id;

        let conn = app.db_pool.get().await.unwrap();
        let credit_service = CreditService::new(app.config.clone());

        // Initialize credits
        let credit_service_clone = credit_service.clone();
        let balance = conn
            .interact(move |conn| credit_service_clone.initialize_user_credits(conn, user_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(balance.balance, 0);

        // Add credits
        let credit_service_clone = credit_service.clone();
        let balance = conn
            .interact(move |conn| {
                credit_service_clone.add_credits(
                    conn,
                    user_id,
                    100,
                    "test",
                    "Test credit addition",
                    None,
                    None,
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(balance.balance, 100);
        assert_eq!(balance.lifetime_earned, 100);

        // Deduct credits
        let credit_service_clone = credit_service.clone();
        let balance = conn
            .interact(move |conn| {
                credit_service_clone.deduct_credits(conn, user_id, 30, "Test usage", None)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(balance.balance, 70);
        assert_eq!(balance.lifetime_spent, 30);

        // Check insufficient credits
        let credit_service_clone = credit_service.clone();
        let result = conn
            .interact(move |conn| {
                credit_service_clone.deduct_credits(conn, user_id, 100, "Too much", None)
            })
            .await
            .unwrap();
        assert!(result.is_err());
    }
}
