-- Rollback: Recreate the original broken trigger
-- (Not recommended, but included for migration completeness)

DROP TRIGGER IF EXISTS update_user_credits_updated_at;

CREATE TRIGGER update_user_credits_updated_at
    BEFORE UPDATE ON user_credits
    FOR EACH ROW
BEGIN
    UPDATE user_credits SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.user_id;
END;
