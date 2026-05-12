-- Alter chat_messages table
ALTER TABLE chat_messages
ALTER COLUMN content TYPE BYTEA USING content::bytea;

-- Alter characters table
ALTER TABLE characters
ALTER COLUMN description TYPE BYTEA USING description::bytea,
ALTER COLUMN personality TYPE BYTEA USING personality::bytea,
ALTER COLUMN scenario TYPE BYTEA USING scenario::bytea,
ALTER COLUMN first_mes TYPE BYTEA USING first_mes::bytea,
ALTER COLUMN mes_example TYPE BYTEA USING mes_example::bytea;
