-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.901767
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert credit package Paddle price IDs back to placeholders

UPDATE credit_packages SET paddle_price_id = 'pri_credits_250' WHERE package_id = 'credits_250';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_550' WHERE package_id = 'credits_550';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_1500' WHERE package_id = 'credits_1500';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_3500' WHERE package_id = 'credits_3500';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_8000' WHERE package_id = 'credits_8000';
