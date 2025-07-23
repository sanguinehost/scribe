-- Rollback world_enrichment_tasks table for Epic 8

-- Drop trigger first
DROP TRIGGER IF EXISTS world_enrichment_tasks_updated_at_trigger ON world_enrichment_tasks;

-- Drop function
DROP FUNCTION IF EXISTS update_world_enrichment_tasks_updated_at();

-- Drop table (indexes are dropped automatically)
DROP TABLE IF EXISTS world_enrichment_tasks;
