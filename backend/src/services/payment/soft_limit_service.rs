use crate::config::Config;
use crate::errors::AppError;
use crate::models::credit::{DailyUsage, NewDailyUsage};
use crate::models::payment::Subscription;
use crate::schema::daily_usage_tracking;
use chrono::{DateTime, Timelike, Utc};
use diesel::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use uuid::Uuid;

/// Service for managing daily usage soft limits
///
/// This service handles:
/// - Daily message and token tracking
/// - Soft limit enforcement with progressive throttling
/// - Daily usage reset at configured hour
/// - Model-specific usage breakdown
#[derive(Clone)]
pub struct SoftLimitService {
    config: Arc<Config>,
}

impl SoftLimitService {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Check if soft limits are enabled
    pub fn is_enabled(&self) -> bool {
        self.config.payment.soft_limits_enabled
    }

    /// Get daily limit for a subscription tier
    pub fn get_daily_limit(&self, tier: &str) -> i32 {
        // Load from subscription config
        let config_path = &self.config.payment.subscription_config_path;
        if let Ok(config_str) = std::fs::read_to_string(config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
                // Look for daily_messages in the limits section
                if let Some(limit) = config["tiers"][tier]["limits"]["daily_messages"].as_i64() {
                    return limit as i32;
                }
            }
        }

        // Default limits by tier (matching config file values)
        match tier.to_lowercase().as_str() {
            "free" => 20, // Updated to match config
            "basic" => 100,
            "premium" => 200,
            _ => 20, // Default to free tier limit
        }
    }

    /// Get or create today's usage record
    pub fn get_or_create_daily_usage(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<DailyUsage, AppError> {
        let today = Utc::now().naive_utc().date();

        use crate::schema::daily_usage_tracking::dsl;

        // Try to get existing record
        let existing = dsl::daily_usage_tracking
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::date.eq(today))
            .first::<DailyUsage>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to get daily usage: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        match existing {
            Some(usage) => Ok(usage),
            None => {
                // Create new record
                let new_usage = NewDailyUsage {
                    user_id,
                    date: today,
                    message_count: 0,
                    token_count: 0,
                    model_breakdown: Some(json!({})),
                    soft_limit_triggered_at: None,
                };

                diesel::insert_into(daily_usage_tracking::table)
                    .values(&new_usage)
                    .get_result(conn)
                    .map_err(|e| {
                        error!("Failed to create daily usage: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    })
            }
        }
    }

    /// Record message usage
    pub fn record_usage(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        model: &str,
        token_count: i64,
    ) -> Result<DailyUsage, AppError> {
        if !self.is_enabled() {
            // If soft limits are disabled, we still track usage for analytics
            // but don't enforce limits
        }

        let mut usage = self.get_or_create_daily_usage(conn, user_id)?;

        // Update counts
        usage.message_count += 1;
        usage.token_count += token_count;

        // Update model breakdown
        let mut breakdown = usage.model_breakdown.clone().unwrap_or_else(|| json!({}));
        let model_count = breakdown[model].as_i64().unwrap_or(0);
        breakdown[model] = json!(model_count + 1);
        usage.model_breakdown = Some(breakdown);

        // Check if soft limit should trigger
        if self.is_enabled() && usage.soft_limit_triggered_at.is_none() {
            // Get user's subscription to determine tier
            let subscription = self.get_user_subscription(conn, user_id)?;

            // Check for soft limit override first
            let daily_limit = if let Some(ref sub) = subscription {
                if let Some(override_limit) = sub.soft_limit_override {
                    override_limit
                } else {
                    self.get_daily_limit(&sub.plan_type)
                }
            } else {
                self.get_daily_limit("free")
            };

            if usage.message_count >= daily_limit {
                usage.soft_limit_triggered_at = Some(usage.message_count);
                info!(
                    "Soft limit triggered for user {} at message {}",
                    user_id, usage.message_count
                );
            }
        }

        usage.updated_at = Some(Utc::now());

        // Save updated usage
        use crate::schema::daily_usage_tracking::dsl;
        diesel::update(dsl::daily_usage_tracking.find(usage.id))
            .set(&usage)
            .get_result(conn)
            .map_err(|e| {
                error!("Failed to update daily usage: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })
    }

    /// Check if user should be throttled
    pub fn should_throttle(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Option<Duration>, AppError> {
        if !self.is_enabled() {
            return Ok(None);
        }

        let usage = self.get_or_create_daily_usage(conn, user_id)?;

        // Check if soft limit was triggered
        if let Some(_triggered_at) = usage.soft_limit_triggered_at {
            // Get user's subscription
            let subscription = self.get_user_subscription(conn, user_id)?;

            // Check for soft limit override first
            let daily_limit = if let Some(ref sub) = subscription {
                if let Some(override_limit) = sub.soft_limit_override {
                    override_limit
                } else {
                    self.get_daily_limit(&sub.plan_type)
                }
            } else {
                self.get_daily_limit("free")
            };
            let messages_over_limit = usage.message_count - daily_limit;

            // Progressive throttling: 2-5 seconds based on how far over limit
            let delay_seconds = match messages_over_limit {
                0..=10 => 2,
                11..=25 => 3,
                26..=50 => 4,
                _ => 5,
            };

            debug!(
                "Throttling user {} for {} seconds ({}% over limit)",
                user_id,
                delay_seconds,
                (messages_over_limit * 100 / daily_limit)
            );

            Ok(Some(Duration::from_secs(delay_seconds as u64)))
        } else {
            Ok(None)
        }
    }

    /// Get user's current subscription
    fn get_user_subscription(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Option<Subscription>, AppError> {
        use crate::schema::subscriptions::dsl;

        dsl::subscriptions
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::status.eq("active"))
            .select(Subscription::as_select())
            .first::<Subscription>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to get user subscription: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })
    }

    /// Check if usage should be reset (new day)
    pub fn should_reset_usage(&self, last_reset: Option<DateTime<Utc>>) -> bool {
        let now = Utc::now();
        let reset_hour = self.config.payment.usage_reset_hour_utc as u32;

        // If no last reset, should reset
        if last_reset.is_none() {
            return true;
        }

        let last = last_reset.unwrap();

        // Check if we've crossed the reset hour boundary
        if now.date_naive() > last.date_naive() {
            // New day
            return true;
        }

        // Same day, check if we've crossed the reset hour
        if now.date_naive() == last.date_naive() {
            if last.time().hour() < reset_hour && now.time().hour() >= reset_hour {
                return true;
            }
        }

        false
    }

    /// Get usage statistics for a user
    pub fn get_usage_stats(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        days: Option<i64>,
    ) -> Result<Vec<DailyUsage>, AppError> {
        use crate::schema::daily_usage_tracking::dsl;

        let mut query = dsl::daily_usage_tracking
            .filter(dsl::user_id.eq(user_id))
            .order(dsl::date.desc())
            .into_boxed();

        if let Some(d) = days {
            let start_date = Utc::now().naive_utc().date() - chrono::Duration::days(d);
            query = query.filter(dsl::date.ge(start_date));
        }

        query.load::<DailyUsage>(conn).map_err(|e| {
            error!("Failed to get usage stats: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })
    }

    /// Get remaining messages for today
    pub fn get_remaining_messages(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Option<i32>, AppError> {
        if !self.is_enabled() {
            return Ok(None); // No limit when disabled
        }

        let usage = self.get_or_create_daily_usage(conn, user_id)?;

        // Get user's subscription
        let subscription = self.get_user_subscription(conn, user_id)?;

        // Check for soft limit override first
        let daily_limit = if let Some(ref sub) = subscription {
            if let Some(override_limit) = sub.soft_limit_override {
                override_limit
            } else {
                self.get_daily_limit(&sub.plan_type)
            }
        } else {
            self.get_daily_limit("free")
        };

        let remaining = (daily_limit - usage.message_count).max(0);

        Ok(Some(remaining))
    }

    /// Override soft limit for a specific user (admin function)
    pub fn set_soft_limit_override(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        override_limit: Option<i32>,
    ) -> Result<(), AppError> {
        use crate::schema::subscriptions::dsl;

        diesel::update(
            dsl::subscriptions
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::status.eq("active")),
        )
        .set(dsl::soft_limit_override.eq(override_limit))
        .execute(conn)
        .map_err(|e| {
            error!("Failed to set soft limit override: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{TestDataGuard, spawn_app};

    #[tokio::test]
    async fn test_soft_limit_tracking() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());

        // Create a test user to satisfy foreign key constraint
        let test_user = crate::test_helpers::db::create_test_user(
            &app.db_pool,
            "test_soft_limit_user".to_string(),
            "password123".to_string(),
        )
        .await
        .unwrap();
        let user_id = test_user.id;

        let conn = app.db_pool.get().await.unwrap();
        let service = SoftLimitService::new(app.config.clone());

        // Record usage
        let service_clone = service.clone();
        let usage = conn
            .interact(move |conn| {
                service_clone.record_usage(conn, user_id, "gemini-2.5-flash", 1000)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.message_count, 1);
        assert_eq!(usage.token_count, 1000);

        // Record more usage
        let service_clone = service.clone();
        let usage = conn
            .interact(move |conn| {
                service_clone.record_usage(conn, user_id, "gemini-2.5-flash", 500)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.message_count, 2);
        assert_eq!(usage.token_count, 1500);

        // Check model breakdown
        let breakdown = usage.model_breakdown.unwrap();
        assert_eq!(breakdown["gemini-2.5-flash"], 2);
    }

    #[tokio::test]
    async fn test_throttle_calculation() {
        let app = spawn_app(false, false, false).await;
        let service = SoftLimitService::new(app.config.clone());

        // Test progressive throttling based on tier limits
        assert_eq!(service.get_daily_limit("free"), 20);
        assert_eq!(service.get_daily_limit("basic"), 100);
        assert_eq!(service.get_daily_limit("premium"), 200);
    }
}
