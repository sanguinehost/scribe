-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.547169
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Ensure TEXT-ossp extension is available
-- CREATE EXTENSION IF NOT EXISTS "TEXT-ossp"; -- Removed: SQLite does not support extensions

-- 1. Change primary key from INTEGER to TEXT for lorebook_entries table
ALTER TABLE lorebook_entries ADD COLUMN id_uuid TEXT ;
ALTER TABLE lorebook_entries DROP COLUMN id CASCADE; -- CASCADE will drop dependent objects like the old PK constraint
ALTER TABLE lorebook_entries RENAME COLUMN id_uuid TO id;
ALTER TABLE lorebook_entries ADD PRIMARY KEY (id);

-- 2. Change lorebook_id from INTEGER to TEXT
-- First, drop the old foreign key constraint if it exists
ALTER TABLE lorebook_entries DROP CONSTRAINT IF EXISTS lorebook_entries_lorebook_id_fkey;

ALTER TABLE lorebook_entries ADD COLUMN lorebook_id_uuid TEXT;
-- Data migration for lorebook_id would be needed here if there was existing data.
-- For now, assuming new setup or data loss is acceptable for these old tables.
ALTER TABLE lorebook_entries DROP COLUMN lorebook_id;
ALTER TABLE lorebook_entries RENAME COLUMN lorebook_id_uuid TO lorebook_id;
ALTER TABLE lorebook_entries ALTER COLUMN lorebook_id SET NOT NULL;
ALTER TABLE lorebook_entries ADD CONSTRAINT fk_lorebook_entries_lorebook_id FOREIGN KEY (lorebook_id) REFERENCES lorebooks(id) ON DELETE CASCADE;

-- 3. Drop old columns not in the new design
ALTER TABLE lorebook_entries
DROP COLUMN IF EXISTS keys,
DROP COLUMN IF EXISTS extensions,
DROP COLUMN IF EXISTS case_sensitive,
DROP COLUMN IF EXISTS use_regex,
DROP COLUMN IF EXISTS priority,
DROP COLUMN IF EXISTS entry_id, -- `original_sillytavern_uid` is the replacement if needed
DROP COLUMN IF EXISTS selective,
DROP COLUMN IF EXISTS secondary_keys,
DROP COLUMN IF EXISTS position; -- `placement_hint` is the replacement

-- 4. Add new columns as per the design document
ALTER TABLE lorebook_entries
ADD COLUMN user_id TEXT,
ADD COLUMN original_sillytavern_uid INTEGER,
ADD COLUMN entry_title_ciphertext BLOB,
ADD COLUMN entry_title_nonce BLOB,
ADD COLUMN keys_text_ciphertext BLOB,
ADD COLUMN keys_text_nonce BLOB,
ADD COLUMN content_ciphertext BLOB, -- This replaces the old 'content' TEXT column
ADD COLUMN content_nonce BLOB,
ADD COLUMN comment_ciphertext BLOB, -- This replaces the old 'comment' TEXT column
ADD COLUMN comment_nonce BLOB,
ADD COLUMN is_constant BOOLEAN DEFAULT false, -- This replaces the old 'constant' BOOLEAN column
ADD COLUMN placement_hint TEXT,
ADD COLUMN sillytavern_metadata_ciphertext BLOB,
ADD COLUMN sillytavern_metadata_nonce BLOB;

-- Set NOT NULL constraints for new columns that require it
ALTER TABLE lorebook_entries
ALTER COLUMN user_id SET NOT NULL,
ALTER COLUMN entry_title_ciphertext SET NOT NULL,
ALTER COLUMN entry_title_nonce SET NOT NULL,
ALTER COLUMN keys_text_ciphertext SET NOT NULL,
ALTER COLUMN keys_text_nonce SET NOT NULL,
ALTER COLUMN content_ciphertext SET NOT NULL,
ALTER COLUMN content_nonce SET NOT NULL,
ALTER COLUMN is_constant SET NOT NULL;
-- Note: original_sillytavern_uid, comment_ciphertext, comment_nonce, sillytavern_metadata_ciphertext, sillytavern_metadata_nonce are nullable

-- Add foreign key for user_id
ALTER TABLE lorebook_entries
ADD CONSTRAINT fk_lorebook_entries_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- 5. Adjust existing columns
-- Rename 'enabled' to 'is_enabled' and set default
ALTER TABLE lorebook_entries RENAME COLUMN enabled TO is_enabled;
ALTER TABLE lorebook_entries ALTER COLUMN is_enabled SET DEFAULT true;

-- Drop old 'content' and 'comment' TEXT columns as they are replaced by BLOB versions
ALTER TABLE lorebook_entries DROP COLUMN IF EXISTS content;
ALTER TABLE lorebook_entries DROP COLUMN IF EXISTS comment;

-- Drop old 'constant' BOOLEAN column as it's replaced by 'is_constant'
ALTER TABLE lorebook_entries DROP COLUMN IF EXISTS constant;


-- Ensure 'insertion_order' has the new default
ALTER TABLE lorebook_entries ALTER COLUMN insertion_order SET DEFAULT 100;

-- Ensure created_at and updated_at are present and have defaults
ALTER TABLE lorebook_entries
ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

-- Ensure the updated_at trigger is in place
DROP TRIGGER IF EXISTS set_updated_at ON lorebook_entries;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebook_entries
FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at();

-- Recreate index on lorebook_id if it was dropped (it was on an INTEGER column before)
DROP INDEX IF EXISTS idx_lorebook_entries_lorebook_id;
CREATE INDEX idx_lorebook_entries_lorebook_id ON lorebook_entries (lorebook_id);
