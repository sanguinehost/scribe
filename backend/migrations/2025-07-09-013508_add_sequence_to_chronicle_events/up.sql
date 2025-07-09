-- Add sequence number field to chronicle_events table
-- This ensures we can maintain exact processing order regardless of async timing
ALTER TABLE chronicle_events ADD COLUMN sequence_number INTEGER;

-- Create an index for efficient ordering by sequence
CREATE INDEX idx_chronicle_events_sequence ON chronicle_events(chronicle_id, sequence_number);

-- Update existing records to have sequential numbering based on created_at
-- This migration ensures existing events get proper sequence numbers
UPDATE chronicle_events 
SET sequence_number = subquery.row_number
FROM (
    SELECT id, 
           ROW_NUMBER() OVER (PARTITION BY chronicle_id ORDER BY created_at, id) as row_number
    FROM chronicle_events
) AS subquery
WHERE chronicle_events.id = subquery.id;

-- Make the sequence_number column NOT NULL after setting values
ALTER TABLE chronicle_events ALTER COLUMN sequence_number SET NOT NULL;
