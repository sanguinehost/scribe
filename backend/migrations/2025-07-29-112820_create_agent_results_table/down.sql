-- Drop agent_results table and associated objects

DROP VIEW IF EXISTS unretrieved_agent_results;
DROP FUNCTION IF EXISTS mark_agent_results_retrieved(UUID, UUID, TIMESTAMPTZ);
DROP TABLE IF EXISTS agent_results;