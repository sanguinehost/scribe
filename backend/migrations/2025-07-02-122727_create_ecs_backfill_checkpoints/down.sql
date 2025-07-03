-- Drop the checkpoints table and related objects
DROP TRIGGER IF EXISTS update_ecs_backfill_checkpoints_updated_at ON ecs_backfill_checkpoints;
DROP FUNCTION IF EXISTS update_ecs_backfill_checkpoints_updated_at();
DROP TABLE IF EXISTS ecs_backfill_checkpoints;