-- Remove payment tables in reverse dependency order

-- Drop indexes first
DROP INDEX IF EXISTS idx_payment_usage_tracking_period;
DROP INDEX IF EXISTS idx_payment_usage_tracking_subscription_id;
DROP INDEX IF EXISTS idx_payment_usage_tracking_user_id;

DROP INDEX IF EXISTS idx_payments_created_at;
DROP INDEX IF EXISTS idx_payments_status;
DROP INDEX IF EXISTS idx_payments_subscription_id;
DROP INDEX IF EXISTS idx_payments_user_id;

DROP INDEX IF EXISTS idx_subscriptions_status;
DROP INDEX IF EXISTS idx_subscriptions_paddle_subscription_id;
DROP INDEX IF EXISTS idx_subscriptions_user_id;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS payment_usage_tracking;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS plan_features;
