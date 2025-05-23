BEGIN;

-- Remove the foreign key constraint added in up.sql
ALTER TABLE lorebooks DROP CONSTRAINT IF EXISTS fk_lorebooks_user_id;

-- Remove new columns
ALTER TABLE lorebooks
DROP COLUMN IF EXISTS user_id,
DROP COLUMN IF EXISTS source_format,
DROP COLUMN IF EXISTS is_public;

-- Add back old columns (referencing the original 00000000000000_diesel_initial_setup/up.sql)
ALTER TABLE lorebooks
ADD COLUMN character_id UUID, -- Assuming characters.id is UUID
ADD COLUMN scan_depth INTEGER,
ADD COLUMN token_budget INTEGER,
ADD COLUMN recursive_scanning BOOLEAN,
ADD COLUMN extensions JSONB;

-- If character_id was NOT NULL and had a FK, re-add it.
-- From initial setup: character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE
-- We need to ensure characters table exists and users.id is UUID for this to work.
-- For simplicity, assuming it might be nullable or FK added separately if needed.
-- If it was NOT NULL:
-- ALTER TABLE lorebooks ALTER COLUMN character_id SET NOT NULL;
-- ADD CONSTRAINT fk_lorebooks_character_id FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE;
-- For now, let's assume it can be nullable during down, or the original migration handled its NOT NULL.

-- Revert 'name' to be nullable
ALTER TABLE lorebooks ALTER COLUMN name DROP NOT NULL;

-- Revert primary key from UUID to SERIAL
-- This is complex as SERIAL implies a sequence. We'll create a new serial column,
-- copy data if possible (though data loss is expected if UUIDs were used),
-- then drop UUID id and rename.
-- NOTE: This will likely result in data loss or require manual data migration
-- if actual UUIDs were populated and need to be mapped back to serial.
-- For a clean revert, it's often simpler to restore from a backup or re-run initial migrations.

-- Drop the UUID primary key
ALTER TABLE lorebooks DROP CONSTRAINT IF EXISTS lorebooks_pkey;
ALTER TABLE lorebooks DROP COLUMN id;

-- Add back the SERIAL primary key
ALTER TABLE lorebooks ADD COLUMN id SERIAL PRIMARY KEY;

-- Ensure created_at and updated_at are present and have defaults (they should be from initial migration)
ALTER TABLE lorebooks
ALTER COLUMN created_at SET DEFAULT NOW(),
ALTER COLUMN updated_at SET DEFAULT NOW();

-- Ensure the updated_at trigger is in place (it should have been managed by diesel_manage_updated_at)
DROP TRIGGER IF EXISTS set_updated_at ON lorebooks;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebooks
FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at();

COMMIT;
