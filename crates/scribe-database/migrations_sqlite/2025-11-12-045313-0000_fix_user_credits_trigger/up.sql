-- Fix broken trigger that references non-existent 'id' column
-- The user_credits table has 'user_id' as PRIMARY KEY, not 'id'

-- Drop the broken trigger
DROP TRIGGER IF EXISTS update_user_credits_updated_at;

-- Recreate with correct column reference
CREATE TRIGGER update_user_credits_updated_at
    BEFORE UPDATE ON user_credits
    FOR EACH ROW
BEGIN
    UPDATE user_credits SET updated_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id;
END;
