use crate::config::Config;
use crate::crypto::{decrypt_gcm, encrypt_gcm};
use crate::errors::AppError;
use crate::models::credit::{CreditBalance, CreditTransaction, NewCreditTransaction};
use crate::models::users::UserDbQuery;
use crate::schema::{credit_transactions, user_credits, users};
use crate::services::payment::{PaymentAuditService, AuditEventType};
use chrono::{DateTime, Utc, Datelike};
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
            None => {
                self.initialize_user_credits(conn, user_id)
            }
        }
    }

    /// Initialize credit account for new user
    pub fn initialize_user_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<CreditBalance, AppError> {
        use crate::schema::user_credits;
        use crate::models::credit::NewCreditBalance;

        let new_balance = NewCreditBalance {
            user_id,
            balance: 0,
            lifetime_earned: 0,
            lifetime_spent: 0,
            last_monthly_grant: None,
        };

        diesel::insert_into(user_credits::table)
            .values(&new_balance)
            .get_result(conn)
            .map_err(|e| {
                error!("Failed to initialize user credits: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })
    }

    /// Add credits to user account (purchase, grant, refund)
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
            return Err(AppError::BadRequest("Credit system is not enabled".to_string()));
        }

        if amount <= 0 {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        // Get current balance
        let mut balance = self.get_balance(conn, user_id)?;

        // Update balance
        let new_balance = balance.balance + amount;

        // Check max balance limit
        if new_balance > self.config.payment.max_credit_balance as i32 {
            return Err(AppError::BadRequest(format!(
                "Credit balance would exceed maximum limit of {}",
                self.config.payment.max_credit_balance
            )));
        }

        // Encrypt transaction data with user DEK
        let encrypted_data = self.encrypt_transaction_data(conn, user_id, description, metadata)?;

        // Create transaction record
        let transaction = NewCreditTransaction {
            id: Uuid::new_v4(),
            user_id,
            amount,
            balance_after: new_balance,
            transaction_type: transaction_type.to_string(),
            description_encrypted: encrypted_data.description_encrypted,
            description_nonce: encrypted_data.description_nonce,
            metadata_encrypted: encrypted_data.metadata_encrypted,
            metadata_nonce: encrypted_data.metadata_nonce,
            reference_id,
            created_at: Some(Utc::now()),
        };

        // Update balance and record transaction in a single transaction
        let result = conn.transaction::<_, AppError, _>(|conn| {
            // Insert transaction
            diesel::insert_into(credit_transactions::table)
                .values(&transaction)
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to insert credit transaction: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            // Update user balance
            use crate::schema::user_credits::dsl;
            balance.balance = new_balance;
            balance.lifetime_earned += amount;
            balance.updated_at = Some(Utc::now());

            if transaction_type == "monthly_grant" {
                balance.last_monthly_grant = Some(Utc::now());
            }

            diesel::update(dsl::user_credits.find(user_id))
                .set(&balance)
                .get_result(conn)
                .map_err(|e| {
                    error!("Failed to update credit balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })
        })?;

        // Log the credit addition in audit log (privacy-focused)
        // Don't fail the transaction if audit logging fails
        if let Err(e) = self.audit_service.log_credit_operation(
            conn,
            user_id,
            AuditEventType::CreditAdded,
            amount,
        ) {
            error!("Failed to audit log credit addition: {}", e);
        }

        Ok(result)
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
            return Err(AppError::BadRequest("Credit system is not enabled".to_string()));
        }

        if amount <= 0 {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        // Get current balance
        let mut balance = self.get_balance(conn, user_id)?;

        // Check sufficient balance
        if balance.balance < amount {
            return Err(AppError::BadRequest(format!(
                "Insufficient credits. Balance: {}, Required: {}",
                balance.balance, amount
            )));
        }

        // Update balance
        let new_balance = balance.balance - amount;

        // Encrypt transaction data with user DEK
        let encrypted_data = self.encrypt_transaction_data(conn, user_id, description, metadata)?;

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
        };

        // Update balance and record transaction
        let result = conn.transaction::<_, AppError, _>(|conn| {
            // Insert transaction
            diesel::insert_into(credit_transactions::table)
                .values(&transaction)
                .execute(conn)
                .map_err(|e| {
                    error!("Failed to insert credit transaction: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            // Update user balance
            use crate::schema::user_credits::dsl;
            balance.balance = new_balance;
            balance.lifetime_spent += amount;
            balance.updated_at = Some(Utc::now());

            diesel::update(dsl::user_credits.find(user_id))
                .set(&balance)
                .get_result(conn)
                .map_err(|e| {
                    error!("Failed to update credit balance: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })
        })?;

        // Log the credit deduction in audit log (privacy-focused)
        // Don't fail the transaction if audit logging fails
        if let Err(e) = self.audit_service.log_credit_operation(
            conn,
            user_id,
            AuditEventType::CreditDeducted,
            amount,
        ) {
            error!("Failed to audit log credit deduction: {}", e);
        }

        Ok(result)
    }

    /// Grant monthly credits based on subscription tier
    pub fn grant_monthly_credits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        tier: &str,
    ) -> Result<CreditBalance, AppError> {
        if !self.is_enabled() {
            return Err(AppError::BadRequest("Credit system is not enabled".to_string()));
        }

        // Load subscription tiers config
        let tier_config = self.load_subscription_tier_config(tier)?;
        let monthly_credits = tier_config["credits"]["included_monthly"].as_u64()
            .ok_or_else(|| AppError::BadRequest("Invalid tier configuration".to_string()))? as i32;

        if monthly_credits == 0 {
            // No credits for this tier (e.g., free tier)
            return self.get_balance(conn, user_id);
        }

        // Check if already granted this month
        let balance = self.get_balance(conn, user_id)?;
        if let Some(last_grant) = balance.last_monthly_grant {
            let now = Utc::now();
            if last_grant.date_naive().month() == now.date_naive().month()
                && last_grant.date_naive().year() == now.date_naive().year() {
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
        let config_str = std::fs::read_to_string(config_path)
            .map_err(|e| AppError::ConfigurationError(format!("Failed to load subscription config: {}", e)))?;

        let config: serde_json::Value = serde_json::from_str(&config_str)
            .map_err(|e| AppError::ConfigurationError(format!("Invalid subscription config: {}", e)))?;

        config["tiers"][tier].as_object()
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

        let transactions = query
            .load::<CreditTransaction>(conn)
            
            .map_err(|e| {
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
            return Err(AppError::BadRequest("Credit system is not enabled".to_string()));
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
        let user: UserDbQuery = users::table
            .find(user_id)
            .first(conn)
            .map_err(|e| {
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
        let mut mac = HmacSha256::new_from_slice(&user.encrypted_dek[..32.min(user.encrypted_dek.len())])
            .map_err(|e| {
                error!("Failed to create HMAC for key derivation: {}", e);
                AppError::EncryptionError("Failed to derive credit key".to_string())
            })?;

        mac.update(context.as_bytes());
        let key_material = mac.finalize().into_bytes();
        let credit_key = SecretBox::new(Box::new(key_material.to_vec()));

        // Encrypt description
        let (description_encrypted, description_nonce) = encrypt_gcm(
            description.as_bytes(),
            &credit_key,
        ).map_err(|e| {
            error!("Failed to encrypt transaction description: {}", e);
            AppError::EncryptionError("Failed to encrypt transaction description".to_string())
        })?;

        // Encrypt metadata if present
        let (metadata_encrypted, metadata_nonce) = if let Some(meta) = metadata {
            let meta_str = serde_json::to_string(&meta)
                .map_err(|e| AppError::SerializationError(e.to_string()))?;

            let (encrypted, nonce) = encrypt_gcm(
                meta_str.as_bytes(),
                &credit_key,
            ).map_err(|e| {
                error!("Failed to encrypt transaction metadata: {}", e);
                AppError::EncryptionError("Failed to encrypt transaction metadata".to_string())
            })?;

            (Some(encrypted), Some(nonce))
        } else {
            (None, None)
        };

        info!("Successfully encrypted credit transaction data for user {}", user_id);

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
            let mut mac = HmacSha256::new_from_slice(dek.expose_secret())
                .map_err(|e| {
                    error!("Failed to create HMAC for key derivation: {}", e);
                    AppError::DecryptionError("Failed to derive credit key".to_string())
                })?;

            mac.update(context.as_bytes());
            let key_material = mac.finalize().into_bytes();
            SecretBox::new(Box::new(key_material.to_vec()))
        } else {
            // Fallback: derive the same key we used for encryption
            let user: UserDbQuery = users::table
                .find(user_id)
                .first(conn)
                .map_err(|e| {
                    error!("Failed to get user for decryption: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let context = format!("credit_transactions_{}", user_id);
            let mut mac = HmacSha256::new_from_slice(&user.encrypted_dek[..32.min(user.encrypted_dek.len())])
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
        ).map_err(|e| {
            error!("Failed to decrypt transaction description: {}", e);
            AppError::DecryptionError("Failed to decrypt transaction description".to_string())
        })?;

        let description = String::from_utf8(description_bytes.expose_secret().clone())
            .map_err(|e| {
                error!("Failed to convert decrypted description to string: {}", e);
                AppError::DecryptionError("Invalid UTF-8 in decrypted description".to_string())
            })?;

        // Decrypt metadata if present
        let metadata = if let (Some(encrypted), Some(nonce)) =
            (&transaction.metadata_encrypted, &transaction.metadata_nonce) {
            let metadata_bytes = decrypt_gcm(
                encrypted,
                nonce,
                &credit_key,
            ).map_err(|e| {
                error!("Failed to decrypt transaction metadata: {}", e);
                AppError::DecryptionError("Failed to decrypt transaction metadata".to_string())
            })?;

            let metadata_str = String::from_utf8(metadata_bytes.expose_secret().clone())
                .map_err(|e| {
                    error!("Failed to convert decrypted metadata to string: {}", e);
                    AppError::DecryptionError("Invalid UTF-8 in decrypted metadata".to_string())
                })?;

            Some(serde_json::from_str(&metadata_str)
                .map_err(|e| {
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
    use crate::test_helpers::{spawn_app, TestDataGuard};

    #[test]
    fn test_credit_balance_lifecycle() {
        let app = spawn_app();
        let _test_guard = TestDataGuard::new(&app.test_id);

        let mut conn = app.db_pool.get().unwrap();
        let user_id = Uuid::new_v4();

        let credit_service = CreditService::new(
            app.config.clone(),
        );

        // Initialize credits
        let balance = credit_service.initialize_user_credits(&mut conn, user_id).unwrap();
        assert_eq!(balance.balance, 0);

        // Add credits
        let balance = credit_service.add_credits(
            &mut conn,
            user_id,
            100,
            "test",
            "Test credit addition",
            None,
            None,
        ).unwrap();
        assert_eq!(balance.balance, 100);
        assert_eq!(balance.lifetime_earned, 100);

        // Deduct credits
        let balance = credit_service.deduct_credits(
            &mut conn,
            user_id,
            30,
            "Test usage",
            None,
        ).unwrap();
        assert_eq!(balance.balance, 70);
        assert_eq!(balance.lifetime_spent, 30);

        // Check insufficient credits
        let result = credit_service.deduct_credits(
            &mut conn,
            user_id,
            100,
            "Too much",
            None,
        );
        assert!(result.is_err());
    }
}