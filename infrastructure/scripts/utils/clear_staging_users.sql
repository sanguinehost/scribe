-- Clear all users and related data from staging database
-- This will cascade to delete all related records

-- First, clear verification tokens
DELETE FROM email_verification_tokens;

-- Then clear all users (this will cascade to other related tables)
DELETE FROM users;

-- Reset any sequences if needed
-- ALTER SEQUENCE users_id_seq RESTART WITH 1;

-- Verify tables are empty
SELECT COUNT(*) as remaining_users FROM users;
SELECT COUNT(*) as remaining_tokens FROM email_verification_tokens;