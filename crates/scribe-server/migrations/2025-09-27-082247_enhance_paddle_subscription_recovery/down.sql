-- Rollback Enhanced Paddle Subscription Recovery Migration
-- This reverts the changes made in the up migration

-- Drop the recovery optimization indexes
DROP INDEX IF EXISTS idx_subscriptions_needs_paddle_recovery;
DROP INDEX IF EXISTS idx_subscriptions_paddle_id_lookup;

-- Reset paddle_sync_attempted flags that were modified by this migration
-- Note: We only reset those that were specifically marked by this migration
-- We don't want to affect legitimate sync attempts that happened after this migration
UPDATE subscriptions
SET paddle_sync_attempted = TRUE
WHERE paddle_customer_id IS NOT NULL
  AND paddle_subscription_id IS NULL;

-- Log the rollback
DO $$
DECLARE
    affected_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO affected_count
    FROM subscriptions
    WHERE paddle_customer_id IS NOT NULL
      AND paddle_subscription_id IS NULL;

    RAISE NOTICE 'PADDLE_RECOVERY: ROLLBACK COMPLETE';
    RAISE NOTICE 'PADDLE_RECOVERY: Reset paddle_sync_attempted for % subscriptions', affected_count;
    RAISE NOTICE 'PADDLE_RECOVERY: Removed recovery optimization indexes';
END $$;
