-- Fix 8000 credits package price ID to match Paddle sandbox
-- Previous value: pri_01k5ejfy6t65v6d28fqf0c4kmr
-- Correct value: pri_01k5ejfzhtg7a696jneszwmqmz

UPDATE credit_packages
SET paddle_price_id = 'pri_01k5ejfzhtg7a696jneszwmqmz'
WHERE package_id = 'credits_8000';
