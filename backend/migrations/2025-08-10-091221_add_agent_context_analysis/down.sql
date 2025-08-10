-- Drop agent_context_analysis table and related objects
DROP TRIGGER IF EXISTS update_agent_context_analysis_updated_at ON agent_context_analysis;
DROP FUNCTION IF EXISTS update_agent_context_analysis_updated_at();
DROP TABLE IF EXISTS agent_context_analysis;
