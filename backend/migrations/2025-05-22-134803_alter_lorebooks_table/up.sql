-- Ensure uuid-ossp extension is available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop the foreign key constraint from lorebook_entries referencing lorebooks.id
-- This constraint will be recreated in the alter_lorebook_entries_table migration with the correct UUID type.
-- Assuming default naming convention: lorebook_entries_lorebook_id_fkey
ALTER TABLE lorebook_entries DROP CONSTRAINT IF EXISTS lorebook_entries_lorebook_id_fkey;

-- 1. Change primary key from SERIAL to UUID for lorebooks table
ALTER TABLE lorebooks ADD COLUMN id_uuid UUID DEFAULT uuid_generate_v4();

-- Drop the old serial primary key. This also drops the primary key constraint.
ALTER TABLE lorebooks DROP COLUMN id CASCADE; -- CASCADE will drop dependent objects like the old PK constraint
ALTER TABLE lorebooks RENAME COLUMN id_uuid TO id;
ALTER TABLE lorebooks ADD PRIMARY KEY (id);

-- 2. Drop old columns not in the new design
ALTER TABLE lorebooks
DROP COLUMN IF EXISTS character_id,
DROP COLUMN IF EXISTS scan_depth,
DROP COLUMN IF EXISTS token_budget,
DROP COLUMN IF EXISTS recursive_scanning,
DROP COLUMN IF EXISTS extensions;

-- 3. Add new columns as per the design document
ALTER TABLE lorebooks
ADD COLUMN user_id UUID,
ADD COLUMN source_format VARCHAR(255),
ADD COLUMN is_public BOOLEAN DEFAULT false;

-- Set NOT NULL constraints for new columns
ALTER TABLE lorebooks
ALTER COLUMN user_id SET NOT NULL,
ALTER COLUMN source_format SET NOT NULL,
ALTER COLUMN is_public SET NOT NULL;

-- Add foreign key for user_id
ALTER TABLE lorebooks
ADD CONSTRAINT fk_lorebooks_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- 4. Adjust existing columns if necessary
-- Ensure 'name' is NOT NULL (original was nullable, new design implies NOT NULL)
ALTER TABLE lorebooks ALTER COLUMN name SET NOT NULL;
-- 'description' TEXT remains nullable (optional in new design)

-- Ensure created_at and updated_at are present and have defaults (they should be from initial migration)
ALTER TABLE lorebooks
ALTER COLUMN created_at SET DEFAULT NOW(),
ALTER COLUMN updated_at SET DEFAULT NOW();

-- Ensure the updated_at trigger is in place
DROP TRIGGER IF EXISTS set_updated_at ON lorebooks;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebooks
FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at();
