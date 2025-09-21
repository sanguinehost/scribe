//! Scheduled job system for payment-related tasks
//!
//! Handles periodic tasks such as:
//! - Monthly credit allocation for subscribers
//! - Daily usage reset at midnight UTC
//! - Subscription renewal processing
//! - Expired subscription cleanup

use chrono::{DateTime, Datelike, NaiveTime, Timelike, Utc};
use deadpool_diesel::Pool;
use diesel::prelude::*;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    errors::AppError,
    models::payment::{NewSubscription, Subscription, SubscriptionStatus},
    schema::{daily_usage_tracking, subscriptions, user_credits, users},
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
        let conn = self.pool.get().await?;
        let today = Utc::now().date_naive();

        conn.interact(move |conn| {
            // Archive yesterday's usage before reset
            let yesterday = today - chrono::Duration::days(1);

            // Update all daily_usage_tracking records from yesterday
            let reset_count = diesel::update(daily_usage_tracking::table)
                .filter(daily_usage_tracking::date.lt(today))
                .set((
                    daily_usage_tracking::message_count.eq(0),
                    daily_usage_tracking::token_count.eq(0i64),
                    daily_usage_tracking::soft_limit_triggered_at.eq(Option::<i32>::None),
                    daily_usage_tracking::updated_at.eq(Utc::now()),
                ))
                .execute(conn)?;

            info!("Reset daily usage for {} records", reset_count);

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
        })
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
                conn.interact(move |conn| {
                    diesel::update(subscriptions::table.find(subscription_id))
                        .set((
                            subscriptions::status.eq(SubscriptionStatus::PastDue.to_string()),
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
                    "Marked subscription {} as past due (grace period: {} days remaining)",
                    subscription_id,
                    grace_period_days - days_overdue
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        // Test that scheduler can be created with valid config
        // This would require proper test setup with mock pool and config
    }
}
