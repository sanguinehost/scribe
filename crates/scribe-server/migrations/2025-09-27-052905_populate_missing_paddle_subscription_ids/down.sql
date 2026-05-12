-- Reverse the migration changes

-- Drop the index
DROP INDEX IF EXISTS idx_subscriptions_paddle_sync_recovery;

-- Remove the tracking column
ALTER TABLE subscriptions DROP COLUMN IF EXISTS paddle_sync_attempted;
