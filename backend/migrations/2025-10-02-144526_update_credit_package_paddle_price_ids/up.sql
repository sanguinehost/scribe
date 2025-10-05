-- Update credit package Paddle price IDs from placeholders to real production IDs
-- These IDs correspond to the actual Paddle price IDs from the .env file

UPDATE credit_packages SET paddle_price_id = 'pri_01k5ej9f8281rvnzybmpxc9hpm' WHERE package_id = 'credits_250';
UPDATE credit_packages SET paddle_price_id = 'pri_01k5ejc7dkwxfty64nfvenj8yq' WHERE package_id = 'credits_550';
UPDATE credit_packages SET paddle_price_id = 'pri_01k5ejdg0hzzem86wzd28zmd2q' WHERE package_id = 'credits_1500';
UPDATE credit_packages SET paddle_price_id = 'pri_01k5ejenme5xjtje37jwfpbxe2' WHERE package_id = 'credits_3500';
UPDATE credit_packages SET paddle_price_id = 'pri_01k5ejfy6t65v6d28fqf0c4kmr' WHERE package_id = 'credits_8000';
