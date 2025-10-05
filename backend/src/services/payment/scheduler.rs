//! Scheduled job system for payment-related tasks
//!
//! Handles periodic tasks such as:
//! - Monthly credit allocation for subscribers
//! - Daily usage reset at midnight UTC
//! - Subscription renewal processing
//! - Expired subscription cleanup
//! - Credit expiry cleanup (daily)

use chrono::{Datelike, NaiveTime, Timelike, Utc};
use deadpool_diesel::Pool;
use diesel::prelude::*;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    errors::AppError,
    models::payment::{Subscription, SubscriptionStatus},
    schema::{daily_usage_tracking, subscriptions, users, webhook_events},
    services::{
        encryption_service::EncryptionService,
        payment::{CreditService, SubscriptionService, UsageTrackingService},
    },
};

/// Payment scheduler service that manages all periodic payment tasks
pub struct PaymentScheduler {
    config: Arc<Config>,
    pool: Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    credit_service: Arc<CreditService>,
    subscription_service: Arc<SubscriptionService>,
    usage_service: Arc<UsageTrackingService>,
}

impl PaymentScheduler {
    pub fn new(
        config: Arc<Config>,
        pool: Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    ) -> Self {
        let credit_service = Arc::new(CreditService::new(config.clone()));
        let subscription_service = Arc::new(SubscriptionService::new(
            config.as_ref().clone(),
            EncryptionService::new(),
        ));
        let usage_service = Arc::new(UsageTrackingService::new(
            config.as_ref().clone(),
            EncryptionService::new(),
        ));

        Self {
            config,
            pool,
            credit_service,
            subscription_service,
            usage_service,
        }
    }

    /// Start all scheduled tasks
    pub async fn start(self: Arc<Self>) {
        info!("Starting payment scheduler service");

        // Clone Arc references for each task
        let scheduler_for_daily = self.clone();
        let scheduler_for_monthly = self.clone();
        let scheduler_for_renewal = self.clone();
        let scheduler_for_cleanup = self.clone();

        // Task 1: Daily usage reset at midnight UTC
        tokio::spawn(async move {
            scheduler_for_daily.run_daily_reset_task().await;
        });

        // Task 2: Monthly credit allocation on 1st of each month
        tokio::spawn(async move {
            scheduler_for_monthly.run_monthly_credit_task().await;
        });

        // Task 3: Subscription renewal check every 30 minutes
        tokio::spawn(async move {
            scheduler_for_renewal.run_subscription_renewal_task().await;
        });

        // Task 4: Webhook event cleanup (daily)
        tokio::spawn(async move {
            scheduler_for_cleanup.run_webhook_cleanup_task().await;
        });

        // Task 5: Credit expiry cleanup (daily)
        let scheduler_for_credit_cleanup = self.clone();
        tokio::spawn(async move {
            scheduler_for_credit_cleanup
                .run_credit_expiry_cleanup_task()
                .await;
        });

        // Task 6: Scheduled plan changes (daily)
        let scheduler_for_plan_changes = self.clone();
        tokio::spawn(async move {
            scheduler_for_plan_changes
                .run_scheduled_plan_changes_task()
                .await;
        });

        info!("Payment scheduler tasks started");
    }

    /// Daily usage reset task - runs at midnight UTC
    async fn run_daily_reset_task(&self) {
        loop {
            // Calculate time until next midnight UTC
            let now = Utc::now();
            let tomorrow_midnight = (now + chrono::Duration::days(1))
                .date_naive()
                .and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
                .and_utc();

            let duration_until_midnight = tomorrow_midnight - now;
            let sleep_duration = Duration::from_secs(duration_until_midnight.num_seconds() as u64);

            info!(
                "Daily usage reset scheduled for {} (in {} seconds)",
                tomorrow_midnight,
                duration_until_midnight.num_seconds()
            );

            // Sleep until midnight
            tokio::time::sleep(sleep_duration).await;

            // Execute reset
            if let Err(e) = self.reset_daily_usage().await {
                error!("Failed to reset daily usage: {}", e);
            } else {
                info!("Daily usage reset completed successfully");
            }

            // Sleep for 1 minute to avoid running multiple times
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    /// Monthly credit allocation task - runs on 1st of each month at 00:00 UTC
    async fn run_monthly_credit_task(&self) {
        loop {
            // Calculate time until next 1st of month at midnight UTC
            let now = Utc::now();
            let next_month_start = if now.day() == 1 && now.hour() < 1 {
                // If it's the 1st but before 1 AM, run today
                now.date_naive()
                    .and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
                    .and_utc()
            } else {
                // Otherwise, wait until next month
                let next_month = if now.month() == 12 {
                    now.with_month(1)
                        .unwrap()
                        .with_year(now.year() + 1)
                        .unwrap()
                } else {
                    now.with_month(now.month() + 1).unwrap()
                };

                next_month
                    .with_day(1)
                    .unwrap()
                    .date_naive()
                    .and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
                    .and_utc()
            };

            let duration_until_next = next_month_start - now;
            let sleep_duration =
                Duration::from_secs(duration_until_next.num_seconds().max(0) as u64);

            info!(
                "Monthly credit allocation scheduled for {} (in {} hours)",
                next_month_start,
                duration_until_next.num_hours()
            );

            // Sleep until next allocation time
            tokio::time::sleep(sleep_duration).await;

            // Execute credit allocation
            if let Err(e) = self.allocate_monthly_credits().await {
                error!("Failed to allocate monthly credits: {}", e);
            } else {
                info!("Monthly credit allocation completed successfully");
            }

            // Sleep for 1 hour to avoid running multiple times
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    /// Subscription renewal task - runs every 30 minutes
    async fn run_subscription_renewal_task(&self) {
        let mut interval = interval(Duration::from_secs(30 * 60)); // 30 minutes

        loop {
            interval.tick().await;

            if let Err(e) = self.process_subscription_renewals().await {
                error!("Failed to process subscription renewals: {}", e);
            } else {
                info!("Subscription renewal check completed");
            }
        }
    }

    /// Reset daily usage counters for all users
    async fn reset_daily_usage(&self) -> Result<(), AppError> {
        info!(
            "Starting daily usage reset at {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );
        let conn = self.pool.get().await?;
        let today = Utc::now().date_naive();

        conn.interact(move |conn| {
            // Archive yesterday's usage before reset
            let _yesterday = today - chrono::Duration::days(1);
            info!(
                "Resetting daily usage for date: {} (deleting records before this date)",
                today
            );

            // Delete old daily_usage_tracking records from previous days
            // This allows fresh records to be created for today with correct date
            let reset_count = diesel::delete(daily_usage_tracking::table)
                .filter(daily_usage_tracking::date.lt(today))
                .execute(conn)?;

            info!(
                "Successfully deleted {} old daily usage records",
                reset_count
            );

            // Update user last_daily_usage_reset timestamps
            let user_update_count = diesel::update(users::table)
                .set(users::last_daily_usage_reset.eq(Utc::now()))
                .execute(conn)?;

            info!(
                "Updated last_daily_usage_reset for {} users",
                user_update_count
            );

            Ok::<_, diesel::result::Error>(())
        })
        .await
        .map_err(|e| {
            error!("Database error during daily usage reset: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?
        .map_err(|e| {
            error!("Failed to reset daily usage: {}", e);
            AppError::DatabaseQueryError(e.to_string())
        })?;

        info!(
            "Daily usage reset completed successfully at {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );
        Ok(())
    }

    /// Allocate monthly credits to all active subscribers
    async fn allocate_monthly_credits(&self) -> Result<(), AppError> {
        let conn = self.pool.get().await?;
        let credit_service = self.credit_service.clone();

        // Get all active subscriptions
        let active_subscriptions = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::status.eq_any(vec![
                        SubscriptionStatus::Active.to_string(),
                        SubscriptionStatus::Trialing.to_string(),
                    ]))
                    .filter(
                        subscriptions::last_credit_grant
                            .is_null()
                            .or(subscriptions::last_credit_grant
                                .lt(Utc::now() - chrono::Duration::days(25))),
                    )
                    .select(Subscription::as_select())
                    .load::<Subscription>(conn)
            })
            .await
            .map_err(|e| {
                error!("Failed to fetch active subscriptions: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to query subscriptions: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        info!(
            "Processing monthly credits for {} active subscriptions",
            active_subscriptions.len()
        );

        // Allocate credits for each subscription
        for subscription in active_subscriptions {
            let conn = self.pool.get().await?;
            let credit_service = credit_service.clone();
            let user_id = subscription.user_id;
            let plan_type = subscription.plan_type.clone();
            let plan_type_for_log = plan_type.clone();
            let subscription_id = subscription.id;

            match conn
                .interact(move |conn| {
                    // Grant credits based on plan
                    let result = credit_service.grant_monthly_credits(conn, user_id, &plan_type);

                    // Update last_credit_grant timestamp
                    if result.is_ok() {
                        diesel::update(subscriptions::table.find(subscription_id))
                            .set(subscriptions::last_credit_grant.eq(Utc::now()))
                            .execute(conn)?;
                    }

                    result
                })
                .await
            {
                Ok(Ok(_)) => {
                    info!(
                        "Successfully allocated monthly credits for user {} (plan: {})",
                        user_id, plan_type_for_log
                    );
                }
                Ok(Err(e)) => {
                    error!("Failed to allocate credits for user {}: {}", user_id, e);
                }
                Err(e) => {
                    error!(
                        "Database error allocating credits for user {}: {}",
                        user_id, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Process subscription renewals and handle expired subscriptions
    async fn process_subscription_renewals(&self) -> Result<(), AppError> {
        let conn = self.pool.get().await?;

        // Get subscriptions that need renewal processing
        let subscriptions_to_process = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::current_period_end.lt(Utc::now()).and(
                        subscriptions::status.eq_any(vec![
                            SubscriptionStatus::Active.to_string(),
                            SubscriptionStatus::Trialing.to_string(),
                        ]),
                    ))
                    .select(Subscription::as_select())
                    .load::<Subscription>(conn)
            })
            .await
            .map_err(|e| {
                error!("Failed to fetch subscriptions for renewal: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to query subscriptions: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        info!(
            "Processing {} subscriptions for renewal/expiration",
            subscriptions_to_process.len()
        );

        for subscription in subscriptions_to_process {
            let conn = self.pool.get().await?;
            let subscription_id = subscription.id;
            let grace_period_days = self.config.payment.grace_period_days as i64;

            // Check if subscription is past grace period
            let days_overdue =
                (Utc::now().signed_duration_since(subscription.current_period_end)).num_days();

            if days_overdue > grace_period_days {
                // Expire the subscription
                conn.interact(move |conn| {
                    diesel::update(subscriptions::table.find(subscription_id))
                        .set((
                            subscriptions::status.eq(SubscriptionStatus::Cancelled.to_string()),
                            subscriptions::updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                })
                .await
                .map_err(|e| {
                    error!("Failed to expire subscription {}: {}", subscription_id, e);
                    AppError::DatabaseQueryError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Database error expiring subscription: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                warn!(
                    "Expired subscription {} for user {} (overdue by {} days)",
                    subscription_id, subscription.user_id, days_overdue
                );
            } else if subscription.cancel_at_period_end.unwrap_or(false) {
                // Cancel the subscription
                conn.interact(move |conn| {
                    diesel::update(subscriptions::table.find(subscription_id))
                        .set((
                            subscriptions::status.eq(SubscriptionStatus::Cancelled.to_string()),
                            subscriptions::updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                })
                .await
                .map_err(|e| {
                    error!("Failed to cancel subscription {}: {}", subscription_id, e);
                    AppError::DatabaseQueryError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Database error cancelling subscription: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                info!(
                    "Cancelled subscription {} for user {} as requested",
                    subscription_id, subscription.user_id
                );
            } else {
                // Mark as past due during grace period
                // Calculate grace_period_end based on current_period_end + grace_period_days
                let grace_period_end =
                    subscription.current_period_end + chrono::Duration::days(grace_period_days);

                conn.interact(move |conn| {
                    diesel::update(subscriptions::table.find(subscription_id))
                        .set((
                            subscriptions::status.eq(SubscriptionStatus::PastDue.to_string()),
                            subscriptions::grace_period_end.eq(Some(grace_period_end)),
                            subscriptions::updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                })
                .await
                .map_err(|e| {
                    error!(
                        "Failed to mark subscription as past due {}: {}",
                        subscription_id, e
                    );
                    AppError::DatabaseQueryError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Database error updating subscription: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                warn!(
                    "Marked subscription {} as past due (grace period: {} days remaining, ends: {})",
                    subscription_id,
                    grace_period_days - days_overdue,
                    grace_period_end
                );
            }
        }

        Ok(())
    }

    /// Webhook event cleanup task - runs daily
    async fn run_webhook_cleanup_task(&self) {
        let mut interval = interval(Duration::from_secs(24 * 60 * 60)); // 24 hours

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_old_webhook_events().await {
                error!("Failed to clean up webhook events: {}", e);
            } else {
                info!("Webhook event cleanup completed");
            }
        }
    }

    /// Clean up old webhook events based on retention period
    pub async fn cleanup_old_webhook_events(&self) -> Result<(), AppError> {
        let retention_days = self.config.payment.webhook_event_retention_days;
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days);

        info!(
            "Starting webhook event cleanup (retention: {} days, cutoff: {})",
            retention_days,
            cutoff_date.format("%Y-%m-%d %H:%M:%S UTC")
        );

        let conn = self.pool.get().await?;
        let deleted_count = conn
            .interact(move |conn| {
                diesel::delete(webhook_events::table)
                    .filter(webhook_events::created_at.lt(cutoff_date))
                    .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database error during webhook cleanup: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to delete old webhook events: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        info!(
            "Successfully deleted {} webhook events older than {} days",
            deleted_count, retention_days
        );

        Ok(())
    }

    /// Credit expiry cleanup task - runs daily
    async fn run_credit_expiry_cleanup_task(&self) {
        let mut interval = interval(Duration::from_secs(24 * 60 * 60)); // 24 hours

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_credits().await {
                error!("Failed to clean up expired credits: {}", e);
            } else {
                info!("Credit expiry cleanup completed");
            }
        }
    }

    /// Clean up expired credits for all users
    pub async fn cleanup_expired_credits(&self) -> Result<(), AppError> {
        info!(
            "Starting credit expiry cleanup at {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        let conn = self.pool.get().await?;
        let credit_service = self.credit_service.clone();

        // Cleanup expired credits for all users
        let stats = conn
            .interact(move |conn| credit_service.cleanup_expired_credits(conn, None))
            .await
            .map_err(|e| {
                error!("Database error during credit expiry cleanup: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to cleanup expired credits: {}", e);
                e
            })?;

        info!(
            "Successfully cleaned up {} expired credits for {} users",
            stats.credits_expired, stats.users_affected
        );

        Ok(())
    }

    /// Scheduled plan changes task - runs daily
    async fn run_scheduled_plan_changes_task(&self) {
        let mut interval = interval(Duration::from_secs(24 * 60 * 60)); // 24 hours

        loop {
            interval.tick().await;

            if let Err(e) = self.apply_scheduled_plan_changes().await {
                error!("Failed to apply scheduled plan changes: {}", e);
            } else {
                info!("Scheduled plan changes check completed");
            }
        }
    }

    /// Apply scheduled plan changes that are due
    pub async fn apply_scheduled_plan_changes(&self) -> Result<(), AppError> {
        use crate::services::payment::audit_service::{AuditEventType, PaymentAuditService};

        info!(
            "Checking for scheduled plan changes at {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        let conn = self.pool.get().await?;

        // Get all subscriptions with scheduled changes that are due
        let subscriptions_with_changes = conn
            .interact(move |conn| {
                subscriptions::table
                    .filter(subscriptions::scheduled_plan_change.is_not_null())
                    .filter(subscriptions::scheduled_change_date.le(Utc::now()))
                    .select(Subscription::as_select())
                    .load::<Subscription>(conn)
            })
            .await
            .map_err(|e| {
                error!(
                    "Failed to fetch subscriptions with scheduled changes: {}",
                    e
                );
                AppError::DatabaseQueryError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to query subscriptions: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;

        if subscriptions_with_changes.is_empty() {
            info!("No scheduled plan changes due");
            return Ok(());
        }

        info!(
            "Processing {} scheduled plan changes",
            subscriptions_with_changes.len()
        );

        let audit_service = Arc::new(PaymentAuditService::new());

        // Process each scheduled change
        for subscription in subscriptions_with_changes {
            let conn = self.pool.get().await?;

            let subscription_id = subscription.id;
            let user_id = subscription.user_id;
            let old_plan = subscription.plan_type.clone();
            let new_plan = subscription
                .scheduled_plan_change
                .clone()
                .unwrap_or_default();
            let paddle_subscription_id = subscription.paddle_subscription_id.clone();

            info!(
                "Applying scheduled plan change for user {}: {} -> {}",
                user_id, old_plan, new_plan
            );

            let audit_service_for_task = audit_service.clone();
            let old_plan_for_log = old_plan.clone();
            let new_plan_for_log = new_plan.clone();

            match conn
                .interact(move |conn| {
                    // 1. Update subscription to new plan
                    diesel::update(subscriptions::table.find(subscription_id))
                        .set((
                            subscriptions::plan_type.eq(&new_plan),
                            subscriptions::scheduled_plan_change.eq::<Option<String>>(None),
                            subscriptions::scheduled_change_date
                                .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                            subscriptions::updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // 2. Audit log the downgrade
                    audit_service_for_task.log_plan_change(
                        conn,
                        user_id,
                        AuditEventType::PlanDowngraded,
                        &old_plan,
                        &new_plan,
                        paddle_subscription_id.as_deref(),
                    )?;

                    Ok::<_, AppError>(())
                })
                .await
            {
                Ok(Ok(_)) => {
                    info!(
                        "Successfully applied plan change for user {}: {} -> {}",
                        user_id, old_plan_for_log, new_plan_for_log
                    );
                }
                Ok(Err(e)) => {
                    error!(
                        "Failed to apply plan change for user {}: {} -> {} - {}",
                        user_id, old_plan_for_log, new_plan_for_log, e
                    );
                    // Continue with other subscriptions
                }
                Err(e) => {
                    error!(
                        "Database error applying plan change for user {}: {}",
                        user_id, e
                    );
                    // Continue with other subscriptions
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_scheduler_creation() {
        // Test that scheduler can be created with valid config
        // This would require proper test setup with mock pool and config
    }
}
