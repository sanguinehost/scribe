-- Drop the new table and its dependencies
DROP TABLE IF EXISTS user_assets;

-- Remove the added fields from character_assets
ALTER TABLE character_assets DROP COLUMN IF EXISTS data;
ALTER TABLE character_assets DROP COLUMN IF EXISTS content_type;
ALTER TABLE character_assets ALTER COLUMN uri SET NOT NULL;
