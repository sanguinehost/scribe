-- Remove yearly price ID column from plan_features table
ALTER TABLE plan_features
DROP COLUMN paddle_price_id_yearly;
