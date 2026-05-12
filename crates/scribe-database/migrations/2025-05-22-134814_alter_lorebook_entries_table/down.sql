BEGIN;

-- Remove foreign key constraints added in up.sql
ALTER TABLE lorebook_entries DROP CONSTRAINT IF EXISTS fk_lorebook_entries_lorebook_id;
ALTER TABLE lorebook_entries DROP CONSTRAINT IF EXISTS fk_lorebook_entries_user_id;

-- Remove new columns
ALTER TABLE lorebook_entries
DROP COLUMN IF EXISTS user_id,
DROP COLUMN IF EXISTS original_sillytavern_uid,
DROP COLUMN IF EXISTS entry_title_ciphertext,
DROP COLUMN IF EXISTS entry_title_nonce,
DROP COLUMN IF EXISTS keys_text_ciphertext,
DROP COLUMN IF EXISTS keys_text_nonce,
DROP COLUMN IF EXISTS content_ciphertext,
DROP COLUMN IF EXISTS content_nonce,
DROP COLUMN IF EXISTS comment_ciphertext,
DROP COLUMN IF EXISTS comment_nonce,
-- DROP COLUMN IF EXISTS is_constant, -- This was a rename of 'constant'
DROP COLUMN IF EXISTS placement_hint,
DROP COLUMN IF EXISTS sillytavern_metadata_ciphertext,
DROP COLUMN IF EXISTS sillytavern_metadata_nonce;

-- Add back old columns (referencing 00000000000000_diesel_initial_setup/up.sql)
ALTER TABLE lorebook_entries
ADD COLUMN keys TEXT[],
ADD COLUMN content TEXT, -- Will be set to NOT NULL later
ADD COLUMN extensions JSONB,
ADD COLUMN case_sensitive BOOLEAN,
ADD COLUMN use_regex BOOLEAN, -- Will be set to NOT NULL later
ADD COLUMN constant BOOLEAN, -- This is what 'is_constant' was renamed from
ADD COLUMN name VARCHAR(255), -- This was present in old schema, but not explicitly dropped if new design had 'entry_title'
ADD COLUMN priority INTEGER,
ADD COLUMN entry_id VARCHAR(255),
ADD COLUMN comment TEXT,
ADD COLUMN selective BOOLEAN,
ADD COLUMN secondary_keys TEXT[],
ADD COLUMN position VARCHAR(50);

-- Set NOT NULL for re-added columns that were NOT NULL
ALTER TABLE lorebook_entries
ALTER COLUMN keys SET NOT NULL,
ALTER COLUMN content SET NOT NULL,
ALTER COLUMN use_regex SET NOT NULL;
-- Note: 'name' was nullable in old schema.

-- Rename 'is_enabled' back to 'enabled'
ALTER TABLE lorebook_entries RENAME COLUMN is_enabled TO enabled;
ALTER TABLE lorebook_entries ALTER COLUMN enabled DROP DEFAULT; -- Old 'enabled' had no default in initial schema

-- Revert 'insertion_order' default (old schema had no explicit default, but was NOT NULL)
ALTER TABLE lorebook_entries ALTER COLUMN insertion_order DROP DEFAULT;


-- Revert lorebook_id from UUID to INTEGER
-- Drop the UUID lorebook_id column
ALTER TABLE lorebook_entries DROP COLUMN lorebook_id;
-- Add back the INTEGER lorebook_id column
ALTER TABLE lorebook_entries ADD COLUMN lorebook_id INTEGER;
ALTER TABLE lorebook_entries ALTER COLUMN lorebook_id SET NOT NULL;
-- Re-add the foreign key constraint to the (now SERIAL) lorebooks.id
-- This assumes lorebooks.id has been reverted to SERIAL in its own down migration
ALTER TABLE lorebook_entries ADD CONSTRAINT lorebook_entries_lorebook_id_fkey FOREIGN KEY (lorebook_id) REFERENCES lorebooks(id) ON DELETE CASCADE;


-- Revert primary key from UUID to SERIAL
ALTER TABLE lorebook_entries DROP CONSTRAINT IF EXISTS lorebook_entries_pkey;
ALTER TABLE lorebook_entries DROP COLUMN id;
ALTER TABLE lorebook_entries ADD COLUMN id SERIAL PRIMARY KEY;

-- Ensure created_at and updated_at are present and have defaults
ALTER TABLE lorebook_entries
ALTER COLUMN created_at SET DEFAULT NOW(),
ALTER COLUMN updated_at SET DEFAULT NOW();

-- Ensure the updated_at trigger is in place
DROP TRIGGER IF EXISTS set_updated_at ON lorebook_entries;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebook_entries
FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at();

-- Recreate index on lorebook_id (now INTEGER)
DROP INDEX IF EXISTS idx_lorebook_entries_lorebook_id;
CREATE INDEX idx_lorebook_entries_lorebook_id ON lorebook_entries (lorebook_id);

COMMIT;
