-- Add unique constraint to prevent multiple active subscriptions per user
-- This constraint only applies to active subscriptions (not cancelled ones)

-- Create a partial unique index that only applies to non-cancelled subscriptions
-- Note: CONCURRENTLY removed because Diesel runs migrations in transactions
CREATE UNIQUE INDEX idx_subscriptions_unique_active_user
ON subscriptions (user_id)
WHERE status != 'cancelled';

-- Add comment explaining the constraint
COMMENT ON INDEX idx_subscriptions_unique_active_user IS
'Ensures a user can only have one active subscription (excluding cancelled ones)';
