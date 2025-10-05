-- Remove max_context_tokens column from plan_features table

ALTER TABLE plan_features DROP COLUMN max_context_tokens;
