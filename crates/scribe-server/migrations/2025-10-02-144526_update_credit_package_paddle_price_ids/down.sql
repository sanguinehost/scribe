-- Revert credit package Paddle price IDs back to placeholders

UPDATE credit_packages SET paddle_price_id = 'pri_credits_250' WHERE package_id = 'credits_250';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_550' WHERE package_id = 'credits_550';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_1500' WHERE package_id = 'credits_1500';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_3500' WHERE package_id = 'credits_3500';
UPDATE credit_packages SET paddle_price_id = 'pri_credits_8000' WHERE package_id = 'credits_8000';
