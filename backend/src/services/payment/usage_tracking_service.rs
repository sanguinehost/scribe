//! Usage tracking service for payment and subscription limits
//!
//! This service tracks token usage, enforces subscription limits, and manages
//! usage periods for billing purposes. Integrates with the encryption service
//! to protect sensitive usage metadata.

#[cfg(feature = "payment")]
use crate::{
    config::Config,
    crypto::encrypt_gcm,
    errors::AppError,
    models::payment::{NewPaymentUsageTracking, PaymentUsageTracking, UpdatePaymentUsageTracking},
    schema::{payment_usage_tracking, users},
    services::EncryptionService,
};
#[cfg(feature = "payment")]
use chrono::{DateTime, Datelike, Duration, Utc};
#[cfg(feature = "payment")]
use diesel::{PgConnection, prelude::*};
#[cfg(feature = "payment")]
use secrecy::{ExposeSecret, SecretBox};
#[cfg(feature = "payment")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "payment")]
use tracing::{error, info};
#[cfg(feature = "payment")]
use uuid::Uuid;

#[cfg(feature = "payment")]
#[derive(Debug, Serialize, Deserialize)]
pub struct UsageMetadata {
    pub model_usage: std::collections::HashMap<String, i32>,
    pub feature_usage: std::collections::HashMap<String, i32>,
    pub request_count: i32,
    pub last_activity: DateTime<Utc>,
}

#[cfg(feature = "payment")]
#[derive(Debug)]
pub struct UsageLimit {
    pub tokens_used_total: i32,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub is_unlimited: bool,
}

#[cfg(feature = "payment")]
#[derive(Clone)]
pub struct UsageTrackingService {
    config: Config,
    encryption_service: EncryptionService,
}

#[cfg(feature = "payment")]
impl UsageTrackingService {
    pub fn new(config: Config, encryption_service: EncryptionService) -> Self {
        Self {
            config,
            encryption_service,
        }
    }

    /// Track token usage for a user
    pub async fn track_usage(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        subscription_id: Option<Uuid>,
        tokens_used: i32,
        metadata: Option<UsageMetadata>,
    ) -> Result<PaymentUsageTracking, AppError> {
        self.track_usage_sync(conn, user_id, subscription_id, tokens_used, metadata)
    }

    /// Track token usage for a user (sync version)
    pub fn track_usage_sync(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        subscription_id: Option<Uuid>,
        tokens_used: i32,
        metadata: Option<UsageMetadata>,
    ) -> Result<PaymentUsageTracking, AppError> {
        let now = Utc::now();
        let period_start = self.get_period_start(now);
        let period_end = self.get_period_end(period_start);

        // Try to find existing usage record for this period
        if let Some(existing) = self.get_current_usage_sync(conn, user_id, subscription_id)? {
            // Update existing record
            let new_total = existing.tokens_used + tokens_used;

            let (encrypted_metadata, metadata_nonce) = if let Some(meta) = metadata {
                // Encrypt the metadata using the user's DEK
                let (encrypted, nonce) = self.encrypt_usage_metadata(conn, user_id, &meta)?;
                (Some(encrypted), Some(nonce))
            } else {
                (None, None)
            };

            let updates = UpdatePaymentUsageTracking {
                tokens_used: Some(new_total),
                tokens_limit: None, // Keep existing limit
                period_start: None, // Keep existing period
                period_end: None,   // Keep existing period
                metadata_encrypted: encrypted_metadata,
                metadata_nonce,
            };

            let updated = diesel::update(payment_usage_tracking::table.find(existing.id))
                .set(&updates)
                .returning(PaymentUsageTracking::as_returning())
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            return Ok(updated);
        }

        // Create new usage record
        let tokens_limit = self.get_token_limit_for_user_sync(conn, user_id)?;

        let (metadata_encrypted, metadata_nonce) = if let Some(meta) = metadata {
            // Encrypt the metadata using the user's DEK
            let (encrypted, nonce) = self.encrypt_usage_metadata(conn, user_id, &meta)?;
            (Some(encrypted), Some(nonce))
        } else {
            (None, None)
        };

        let new_usage = NewPaymentUsageTracking {
            id: Uuid::new_v4(),
            user_id,
            subscription_id,
            tokens_used,
            tokens_limit: Some(tokens_limit),
            period_start,
            period_end,
            metadata_encrypted,
            metadata_nonce,
        };

        let usage = diesel::insert_into(payment_usage_tracking::table)
            .values(&new_usage)
            .returning(PaymentUsageTracking::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(usage)
    }

    /// Get current usage for a user in the current period
    pub async fn get_current_usage(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        subscription_id: Option<Uuid>,
    ) -> Result<Option<PaymentUsageTracking>, AppError> {
        self.get_current_usage_sync(conn, user_id, subscription_id)
    }

    /// Get current usage for a user in the current period (sync version)
    pub fn get_current_usage_sync(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        subscription_id: Option<Uuid>,
    ) -> Result<Option<PaymentUsageTracking>, AppError> {
        let now = Utc::now();
        let period_start = self.get_period_start(now);
        let period_end = self.get_period_end(period_start);

        let mut query = payment_usage_tracking::table
            .filter(payment_usage_tracking::user_id.eq(user_id))
            .filter(payment_usage_tracking::period_start.eq(period_start))
            .filter(payment_usage_tracking::period_end.eq(period_end))
            .into_boxed();

        if let Some(sub_id) = subscription_id {
            query = query.filter(payment_usage_tracking::subscription_id.eq(sub_id));
        } else {
            query = query.filter(payment_usage_tracking::subscription_id.is_null());
        }

        let usage = query
            .first::<PaymentUsageTracking>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(usage)
    }

    /// Get usage limits for a user
    pub async fn get_usage_limits(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<UsageLimit, AppError> {
        self.get_usage_limits_sync(conn, user_id)
    }

    /// Get usage limits for a user (sync version)
    pub fn get_usage_limits_sync(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<UsageLimit, AppError> {
        let now = Utc::now();
        let period_start = self.get_period_start(now);
        let period_end = self.get_period_end(period_start);

        // Get current usage
        let current_usage = self
            .get_current_usage_sync(conn, user_id, None)?
            .map(|u| u.tokens_used)
            .unwrap_or(0);

        // Get token limit based on subscription
        let tokens_limit = self.get_token_limit_for_user_sync(conn, user_id)?;
        let is_unlimited = tokens_limit < 0;

        Ok(UsageLimit {
            tokens_used_total: current_usage,
            period_start,
            period_end,
            is_unlimited,
        })
    }

    /// Check if user has enough tokens for a request
    pub async fn can_use_tokens(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        _tokens_needed: i32,
    ) -> Result<bool, AppError> {
        if !self.config.payment.enforce_limits {
            return Ok(true);
        }

        let limits = self.get_usage_limits(conn, user_id).await?;

        if limits.is_unlimited {
            return Ok(true);
        }

        // Since we removed token limits, this method should be updated
        // For now, just check if unlimited or if we're under a reasonable threshold
        Ok(limits.is_unlimited || limits.tokens_used_total < 1000000) // 1M token reasonable threshold
    }

    /// Get usage history for a user
    pub async fn get_usage_history(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<PaymentUsageTracking>, AppError> {
        let mut query = payment_usage_tracking::table
            .filter(payment_usage_tracking::user_id.eq(user_id))
            .order(payment_usage_tracking::period_start.desc())
            .into_boxed();

        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        let history = query
            .load::<PaymentUsageTracking>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(history)
    }

    /// Decrypt usage metadata
    pub async fn decrypt_usage_metadata(
        &self,
        conn: &mut PgConnection,
        usage: &PaymentUsageTracking,
    ) -> Result<Option<UsageMetadata>, AppError> {
        if let (Some(encrypted_data), Some(nonce)) =
            (&usage.metadata_encrypted, &usage.metadata_nonce)
        {
            // Decrypt the metadata using the user's DEK
            let metadata =
                self.decrypt_usage_metadata_with_key(conn, usage.user_id, encrypted_data, nonce)?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    /// Reset usage for testing purposes
    pub async fn reset_usage_for_period(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        period_start: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let period_end = self.get_period_end(period_start);

        diesel::delete(
            payment_usage_tracking::table
                .filter(payment_usage_tracking::user_id.eq(user_id))
                .filter(payment_usage_tracking::period_start.eq(period_start))
                .filter(payment_usage_tracking::period_end.eq(period_end)),
        )
        .execute(conn)
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(())
    }

    /// Get aggregated usage statistics
    pub async fn get_usage_stats(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        months_back: i32,
    ) -> Result<Vec<(DateTime<Utc>, i32)>, AppError> {
        let cutoff = Utc::now() - Duration::days(months_back as i64 * 30);

        let stats: Vec<(DateTime<Utc>, i32)> = payment_usage_tracking::table
            .filter(payment_usage_tracking::user_id.eq(user_id))
            .filter(payment_usage_tracking::period_start.ge(cutoff))
            .select((
                payment_usage_tracking::period_start,
                payment_usage_tracking::tokens_used,
            ))
            .order(payment_usage_tracking::period_start.asc())
            .load::<(DateTime<Utc>, i32)>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(stats)
    }

    /// Get token limit for a user based on their subscription
    async fn get_token_limit_for_user(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<i32, AppError> {
        self.get_token_limit_for_user_sync(conn, user_id)
    }

    /// Get token limit for a user based on their subscription (sync version)
    fn get_token_limit_for_user_sync(
        &self,
        _conn: &mut PgConnection,
        _user_id: Uuid,
    ) -> Result<i32, AppError> {
        // This would integrate with the subscription service to get the user's plan
        // For now, we'll return the free tier limit from config
        let payment_config = &self.config.payment;

        // In a real implementation, this would:
        // 1. Get user's subscription
        // 2. Get plan features
        // 3. Return the monthly token limit
        // For now, return the free tier limit
        Ok(payment_config.free_tier_token_limit as i32)
    }

    /// Get the start of the current billing period
    fn get_period_start(&self, date: DateTime<Utc>) -> DateTime<Utc> {
        // Monthly billing periods starting from the first of the month
        let naive_date = date.date_naive();
        let first_of_month = naive_date.with_day(1).unwrap();
        first_of_month.and_hms_opt(0, 0, 0).unwrap().and_utc()
    }

    /// Get the end of the billing period
    fn get_period_end(&self, period_start: DateTime<Utc>) -> DateTime<Utc> {
        // End of month
        let next_month = if period_start.month() == 12 {
            period_start
                .with_year(period_start.year() + 1)
                .unwrap()
                .with_month(1)
                .unwrap()
        } else {
            period_start.with_month(period_start.month() + 1).unwrap()
        };

        next_month - Duration::seconds(1)
    }

    /// Encrypt usage metadata with user's DEK
    ///
    /// This follows the same pattern as the credit service for consistency.
    /// Uses HMAC-based key derivation from the user's encrypted DEK.
    fn encrypt_usage_metadata(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        metadata: &UsageMetadata,
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        // Get user's encrypted DEK from database
        let encrypted_dek: Vec<u8> = users::table
            .find(user_id)
            .select(users::encrypted_dek)
            .first(conn)
            .map_err(|e| {
                error!("Failed to get user for usage metadata encryption: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Derive a usage-tracking-specific key using HMAC
        // In production, you would:
        // 1. Get the decrypted DEK from the user's session (passed as a parameter)
        // 2. Use that DEK directly to encrypt the metadata
        // For demonstration, we'll use HMAC to derive a key from the encrypted DEK
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Use a fixed context string for usage tracking
        let context = format!("usage_tracking_{}", user_id);

        // Create HMAC with the encrypted DEK as the key
        let mut mac = HmacSha256::new_from_slice(&encrypted_dek[..32.min(encrypted_dek.len())])
            .map_err(|e| {
                error!(
                    "Failed to create HMAC for usage tracking key derivation: {}",
                    e
                );
                AppError::EncryptionError("Failed to derive usage tracking key".to_string())
            })?;

        mac.update(context.as_bytes());
        let key_material = mac.finalize().into_bytes();
        let usage_key = SecretBox::new(Box::new(key_material.to_vec()));

        // Serialize and encrypt metadata
        let metadata_str = serde_json::to_string(metadata)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        let (encrypted, nonce) = encrypt_gcm(metadata_str.as_bytes(), &usage_key).map_err(|e| {
            error!("Failed to encrypt usage metadata: {}", e);
            AppError::EncryptionError("Failed to encrypt usage metadata".to_string())
        })?;

        info!("Successfully encrypted usage metadata for user {}", user_id);

        Ok((encrypted, nonce))
    }

    /// Decrypt usage metadata with user's DEK
    ///
    /// This follows the same pattern as the credit service for consistency.
    /// Uses HMAC-based key derivation from the user's encrypted DEK.
    fn decrypt_usage_metadata_with_key(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        encrypted_data: &[u8],
        nonce: &[u8],
    ) -> Result<UsageMetadata, AppError> {
        // Get user's encrypted DEK from database
        let encrypted_dek: Vec<u8> = users::table
            .find(user_id)
            .select(users::encrypted_dek)
            .first(conn)
            .map_err(|e| {
                error!("Failed to get user for usage metadata decryption: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        // Derive the same usage-tracking-specific key using HMAC
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Use the same context string as encryption
        let context = format!("usage_tracking_{}", user_id);

        // Create HMAC with the encrypted DEK as the key
        let mut mac = HmacSha256::new_from_slice(&encrypted_dek[..32.min(encrypted_dek.len())])
            .map_err(|e| {
                error!(
                    "Failed to create HMAC for usage tracking key derivation: {}",
                    e
                );
                AppError::EncryptionError("Failed to derive usage tracking key".to_string())
            })?;

        mac.update(context.as_bytes());
        let key_material = mac.finalize().into_bytes();
        let usage_key = SecretBox::new(Box::new(key_material.to_vec()));

        // Decrypt the metadata
        let decrypted =
            crate::crypto::decrypt_gcm(encrypted_data, nonce, &usage_key).map_err(|e| {
                error!("Failed to decrypt usage metadata: {}", e);
                AppError::DecryptionError("Failed to decrypt usage metadata".to_string())
            })?;

        // Deserialize the metadata
        let metadata_str = String::from_utf8(decrypted.expose_secret().clone()).map_err(|e| {
            AppError::DecryptionError(format!("Invalid UTF-8 in decrypted metadata: {}", e))
        })?;

        let metadata: UsageMetadata = serde_json::from_str(&metadata_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to deserialize metadata: {}", e))
        })?;

        info!("Successfully decrypted usage metadata for user {}", user_id);

        Ok(metadata)
    }
}

#[cfg(not(feature = "payment"))]
pub struct UsageTrackingService;

#[cfg(not(feature = "payment"))]
impl UsageTrackingService {
    pub fn new(
        _config: crate::config::Config,
        _encryption_service: crate::services::EncryptionService,
    ) -> Self {
        Self
    }
}
