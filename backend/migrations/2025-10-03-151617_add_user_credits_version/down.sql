-- Rollback: Remove version column from user_credits table
-- This reverts the optimistic locking implementation

DROP INDEX IF EXISTS idx_user_credits_version;
ALTER TABLE user_credits DROP COLUMN version;
