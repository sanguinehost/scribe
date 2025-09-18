use crate::config::Config;
use crate::errors::AppError;
use crate::models::credit::{CreditBalance, CreditTransaction, NewCreditTransaction};
use crate::schema::{credit_transactions, user_credits};
use chrono::{DateTime, Utc, Datelike};
use diesel::prelude::*;
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Service for managing user credits and credit transactions
///
/// This service handles:
/// - Credit balance management
/// - Credit purchases
/// - Credit consumption
/// - Monthly credit grants for subscriptions
/// - Transaction history
///
/// Note: Encryption is planned but not yet implemented - data is stored in plaintext.
#[derive(Clone)]
pub struct CreditService {
    config: Arc<Config>,
}

impl CreditService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
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

        // TODO: Implement user-specific key encryption when user key management is added
        // For now, store unencrypted with placeholder nonce
        warn!("Credit transaction encryption not yet implemented - storing placeholder data");
        let description_encrypted = description.as_bytes().to_vec();
        let description_nonce = vec![0u8; 12]; // Placeholder nonce

        let (metadata_encrypted, metadata_nonce) = if let Some(meta) = metadata {
            let meta_str = serde_json::to_string(&meta)
                .map_err(|e| AppError::SerializationError(e.to_string()))?;
            (Some(meta_str.as_bytes().to_vec()), Some(vec![0u8; 12]))
        } else {
            (None, None)
        };

        // Create transaction record
        let transaction = NewCreditTransaction {
            id: Uuid::new_v4(),
            user_id,
            amount,
            balance_after: new_balance,
            transaction_type: transaction_type.to_string(),
            description_encrypted,
            description_nonce,
            metadata_encrypted,
            metadata_nonce,
            reference_id,
            created_at: Some(Utc::now()),
        };

        // Update balance and record transaction in a single transaction
        conn.transaction::<_, AppError, _>(|conn| {
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

        // TODO: Implement user-specific key encryption when user key management is added
        // For now, store unencrypted with placeholder nonce
        warn!("Credit transaction encryption not yet implemented - storing placeholder data");
        let description_encrypted = description.as_bytes().to_vec();
        let description_nonce = vec![0u8; 12]; // Placeholder nonce

        let (metadata_encrypted, metadata_nonce) = if let Some(meta) = metadata {
            let meta_str = serde_json::to_string(&meta)
                .map_err(|e| AppError::SerializationError(e.to_string()))?;
            (Some(meta_str.as_bytes().to_vec()), Some(vec![0u8; 12]))
        } else {
            (None, None)
        };

        // Create transaction record (negative amount for deduction)
        let transaction = NewCreditTransaction {
            id: Uuid::new_v4(),
            user_id,
            amount: -amount, // Negative for deductions
            balance_after: new_balance,
            transaction_type: "usage".to_string(),
            description_encrypted,
            description_nonce,
            metadata_encrypted,
            metadata_nonce,
            reference_id: None,
            created_at: Some(Utc::now()),
        };

        // Update balance and record transaction
        conn.transaction::<_, AppError, _>(|conn| {
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
        })
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
        self.add_credits(
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
        )
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