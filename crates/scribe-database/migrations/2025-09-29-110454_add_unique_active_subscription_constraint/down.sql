-- Remove the unique constraint for active subscriptions per user

DROP INDEX idx_subscriptions_unique_active_user;
