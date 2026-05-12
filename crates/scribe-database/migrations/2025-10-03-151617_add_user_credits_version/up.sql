-- Add version column to user_credits table for optimistic concurrency control
-- This fixes the critical race condition in credit reservation system
--
-- Issue: Under high concurrency (100+ concurrent operations), all reservations
-- succeed but balance updates are lost due to write skew anomaly.
--
-- Solution: Optimistic locking with version numbers
-- - Each update increments version
-- - UPDATE WHERE version = old_version prevents lost updates
-- - Conflicts trigger retry with exponential backoff

ALTER TABLE user_credits
ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- Create index for version-based queries (performance optimization)
CREATE INDEX idx_user_credits_version ON user_credits(user_id, version);

-- Add helpful comment
COMMENT ON COLUMN user_credits.version IS 'Optimistic locking version number - incremented on each update to prevent race conditions';
