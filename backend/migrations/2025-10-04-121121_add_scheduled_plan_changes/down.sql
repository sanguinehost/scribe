-- Rollback scheduled plan change tracking

DROP INDEX IF EXISTS idx_subscriptions_scheduled_change;

ALTER TABLE subscriptions
DROP COLUMN IF EXISTS scheduled_plan_change,
DROP COLUMN IF EXISTS scheduled_change_date;
