-- Revert 8000 credits package price ID to old value

UPDATE credit_packages
SET paddle_price_id = 'pri_01k5ejfy6t65v6d28fqf0c4kmr'
WHERE package_id = 'credits_8000';
