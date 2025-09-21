//! Subscription management service
//!
//! This service handles subscription lifecycle management including creation, updates,
//! cancellation, and status tracking. Integrates with the Paddle service for payment
//! processing while maintaining local subscription state.

#[cfg(feature = "payment")]
use crate::{
    config::Config,
    errors::AppError,
    models::payment::{
        NewSubscription, PlanFeatures, PlanType, Subscription, SubscriptionStatus,
        UpdateSubscription,
    },
    schema::{plan_features, subscriptions},
    services::EncryptionService,
};
#[cfg(feature = "payment")]
use chrono::{DateTime, Duration, Utc};
#[cfg(feature = "payment")]
use diesel::{PgConnection, prelude::*};
#[cfg(feature = "payment")]
use uuid::Uuid;

#[cfg(feature = "payment")]
#[derive(Clone)]
pub struct SubscriptionService {
    config: Config,
    encryption_service: EncryptionService,
}

#[cfg(feature = "payment")]
impl SubscriptionService {
    pub fn new(config: Config, encryption_service: EncryptionService) -> Self {
        Self {
            config,
            encryption_service,
        }
    }

    /// Create a new subscription for a user
    pub async fn create_subscription(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        plan_type: &str,
        paddle_customer_id: Option<String>,
        paddle_subscription_id: Option<String>,
        trial_days: Option<i32>,
    ) -> Result<Subscription, AppError> {
        let now = Utc::now();
        let trial_end = trial_days.map(|days| now + Duration::days(days as i64));

        // Default subscription period (1 month for non-trial, or trial period)
        let period_start = now;
        let period_end = if let Some(trial_end) = trial_end {
            trial_end
        } else {
            now + Duration::days(30) // Default 30-day period
        };

        let status = if trial_end.is_some() {
            SubscriptionStatus::Trialing.to_string()
        } else {
            SubscriptionStatus::Active.to_string()
        };

        let new_subscription = NewSubscription {
            id: Uuid::new_v4(),
            user_id,
            paddle_customer_id,
            paddle_subscription_id,
            plan_type: plan_type.to_string(),
            status,
            current_period_start: period_start,
            current_period_end: period_end,
            cancel_at_period_end: Some(false),
            trial_end,
            credits_allocated_this_period: Some(false),
            soft_limit_override: None,
            last_credit_grant: None,
        };

        let subscription = diesel::insert_into(subscriptions::table)
            .values(&new_subscription)
            .returning(Subscription::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscription)
    }

    /// Get subscription by user ID
    pub async fn get_user_subscription(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Option<Subscription>, AppError> {
        let subscription = subscriptions::table
            .filter(subscriptions::user_id.eq(user_id))
            .filter(subscriptions::status.ne("cancelled"))
            .order(subscriptions::created_at.desc())
            .first::<Subscription>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscription)
    }

    /// Get subscription by ID
    pub async fn get_subscription(
        &self,
        conn: &mut PgConnection,
        subscription_id: Uuid,
    ) -> Result<Option<Subscription>, AppError> {
        let subscription = subscriptions::table
            .find(subscription_id)
            .first::<Subscription>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscription)
    }

    /// Get subscription by Paddle subscription ID
    pub async fn get_subscription_by_paddle_id(
        &self,
        conn: &mut PgConnection,
        paddle_subscription_id: &str,
    ) -> Result<Option<Subscription>, AppError> {
        let subscription = subscriptions::table
            .filter(subscriptions::paddle_subscription_id.eq(paddle_subscription_id))
            .first::<Subscription>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscription)
    }

    /// Update subscription status and details
    pub async fn update_subscription(
        &self,
        conn: &mut PgConnection,
        subscription_id: Uuid,
        updates: UpdateSubscription,
    ) -> Result<Subscription, AppError> {
        let update_data = updates;
        // UpdateSubscription doesn't track updated_at (handled by DB)

        let subscription = diesel::update(subscriptions::table.find(subscription_id))
            .set(&update_data)
            .returning(Subscription::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscription)
    }

    /// Cancel subscription at period end
    pub async fn cancel_subscription(
        &self,
        conn: &mut PgConnection,
        subscription_id: Uuid,
        immediate: bool,
    ) -> Result<Subscription, AppError> {
        let updates = if immediate {
            UpdateSubscription {
                status: Some(SubscriptionStatus::Cancelled.to_string()),
                cancel_at_period_end: Some(true),
                ..Default::default()
            }
        } else {
            UpdateSubscription {
                cancel_at_period_end: Some(true),
                ..Default::default()
            }
        };

        self.update_subscription(conn, subscription_id, updates)
            .await
    }

    /// Reactivate a cancelled subscription
    pub async fn reactivate_subscription(
        &self,
        conn: &mut PgConnection,
        subscription_id: Uuid,
    ) -> Result<Subscription, AppError> {
        let updates = UpdateSubscription {
            status: Some(SubscriptionStatus::Active.to_string()),
            cancel_at_period_end: Some(false),
            ..Default::default()
        };

        self.update_subscription(conn, subscription_id, updates)
            .await
    }

    /// Update subscription period (for renewals)
    pub async fn update_subscription_period(
        &self,
        conn: &mut PgConnection,
        subscription_id: Uuid,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<Subscription, AppError> {
        let updates = UpdateSubscription {
            current_period_start: Some(period_start),
            current_period_end: Some(period_end),
            status: Some(SubscriptionStatus::Active.to_string()),
            ..Default::default()
        };

        self.update_subscription(conn, subscription_id, updates)
            .await
    }

    /// Check if subscription is active
    pub fn is_subscription_active(&self, subscription: &Subscription) -> bool {
        let status = SubscriptionStatus::from(subscription.status.as_str());
        matches!(
            status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing
        )
    }

    /// Check if subscription is in trial period
    pub fn is_trial_active(&self, subscription: &Subscription) -> bool {
        if let Some(trial_end) = subscription.trial_end {
            trial_end > Utc::now()
        } else {
            false
        }
    }

    /// Get plan features for a subscription
    pub async fn get_plan_features(
        &self,
        conn: &mut PgConnection,
        plan_type: &str,
    ) -> Result<Option<PlanFeatures>, AppError> {
        let features = plan_features::table
            .find(plan_type)
            .first::<PlanFeatures>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(features)
    }

    /// Get all available plans
    pub async fn get_available_plans(
        &self,
        conn: &mut PgConnection,
    ) -> Result<Vec<PlanFeatures>, AppError> {
        let plans = plan_features::table
            .order(plan_features::price_cents.asc().nulls_first())
            .load::<PlanFeatures>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(plans)
    }

    /// Process subscription webhook from Paddle
    pub async fn process_webhook_subscription_update(
        &self,
        conn: &mut PgConnection,
        paddle_subscription_id: &str,
        status: &str,
        period_start: Option<DateTime<Utc>>,
        period_end: Option<DateTime<Utc>>,
        plan_id: Option<&str>,
    ) -> Result<Option<Subscription>, AppError> {
        if let Some(subscription) = self
            .get_subscription_by_paddle_id(conn, paddle_subscription_id)
            .await?
        {
            let mut updates = UpdateSubscription {
                status: Some(status.to_string()),
                ..Default::default()
            };

            if let (Some(start), Some(end)) = (period_start, period_end) {
                updates.current_period_start = Some(start);
                updates.current_period_end = Some(end);
            }

            if let Some(plan_id) = plan_id {
                // Map Paddle plan ID to our plan type if needed
                updates.plan_type = Some(self.map_paddle_plan_to_type(plan_id));
            }

            let updated_subscription = self
                .update_subscription(conn, subscription.id, updates)
                .await?;

            Ok(Some(updated_subscription))
        } else {
            tracing::warn!(
                "Received webhook for unknown subscription: {}",
                paddle_subscription_id
            );
            Ok(None)
        }
    }

    /// Map Paddle plan ID to our internal plan type
    fn map_paddle_plan_to_type(&self, paddle_plan_id: &str) -> String {
        // This would typically map Paddle price IDs to our plan types
        // For now, we'll use a simple mapping - in production this should
        // be configurable or stored in the database
        match paddle_plan_id {
            id if id.contains("free") => PlanType::Free.to_string(),
            id if id.contains("pro") => PlanType::Pro.to_string(),
            id if id.contains("enterprise") => PlanType::Enterprise.to_string(),
            _ => {
                tracing::warn!(
                    "Unknown Paddle plan ID: {}, defaulting to free",
                    paddle_plan_id
                );
                PlanType::Free.to_string()
            }
        }
    }

    /// Get subscriptions expiring soon (for renewal reminders)
    pub async fn get_expiring_subscriptions(
        &self,
        conn: &mut PgConnection,
        days_ahead: i32,
    ) -> Result<Vec<Subscription>, AppError> {
        let cutoff_date = Utc::now() + Duration::days(days_ahead as i64);

        let subscriptions = subscriptions::table
            .filter(subscriptions::status.eq(SubscriptionStatus::Active.to_string()))
            .filter(subscriptions::current_period_end.le(cutoff_date))
            .filter(subscriptions::cancel_at_period_end.eq(false))
            .load::<Subscription>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(subscriptions)
    }
}

#[cfg(feature = "payment")]
impl Default for UpdateSubscription {
    fn default() -> Self {
        Self {
            paddle_customer_id: None,
            paddle_subscription_id: None,
            plan_type: None,
            status: None,
            current_period_start: None,
            current_period_end: None,
            cancel_at_period_end: None,
            trial_end: None,
            credits_allocated_this_period: None,
            soft_limit_override: None,
            last_credit_grant: None,
        }
    }
}

#[cfg(not(feature = "payment"))]
pub struct SubscriptionService;

#[cfg(not(feature = "payment"))]
impl SubscriptionService {
    pub fn new(
        _config: crate::config::Config,
        _encryption_service: crate::services::EncryptionService,
    ) -> Self {
        Self
    }
}
