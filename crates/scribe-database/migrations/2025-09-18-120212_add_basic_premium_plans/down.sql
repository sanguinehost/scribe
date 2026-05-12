-- Remove basic and premium plan types
DELETE FROM plan_features WHERE plan_type IN ('basic', 'premium');
