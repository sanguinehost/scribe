-- This migration cannot be safely reverted because removing NOT NULL constraints
-- would allow NULL values that could break application logic.
-- If you need to revert, you'll need to manually recreate the tables without the constraints.

SELECT 'This migration cannot be automatically reverted.' AS error;
