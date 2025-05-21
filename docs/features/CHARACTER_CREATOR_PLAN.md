# Plan: Manual Character Creation and Editing Features

This document outlines the plan for implementing manual character creation (without PNG upload) and enhancing character editing capabilities, including per-chat overrides.

## I. Backend Changes

### A. Manual Character Creation (e.g., `POST /api/characters`)

1.  **Request DTO:**
    *   Define a new Data Transfer Object (DTO) for the request payload. This DTO will largely mirror the structure of `CharacterCardDataV3` as defined in the character card specifications.
    *   User-provided `name`, `description`, and `first_mes` will be used directly (these are considered the minimum from a user experience perspective).
    *   Other fields from `CharacterCardDataV3` (e.g., `personality`, `scenario`, `tags`, `alternate_greetings`, `system_prompt`, `creator_notes`, etc.) will be accepted if provided by the client.

2.  **Handler Logic:**
    *   Accept the DTO from the request.
    *   Construct a `NewCharacter` database model instance.
        *   Set `spec` to `"chara_card_v3"`.
        *   Set `spec_version` to `"3.0"`.
        *   Populate fields using values from the DTO.
        *   For fields not present in the DTO but part of the `CharacterCardDataV3` spec or our database model, apply defaults:
            *   `extensions`: Default to an empty JSON object (`{}`).
            *   `group_only_greetings`: Default to an empty array (`[]`).
            *   `assets`: Default to a representation of `[{ type: 'icon', uri: 'ccdefault:', name: 'main', ext: 'png' }]`. If the database schema allows `assets` to be entirely optional for a character, this could also mean not creating any asset records if none are specified. This needs careful handling during the `NewCharacter` to database mapping.
            *   Other string fields (e.g., `personality`, `scenario` if not provided): Default to empty strings if the database column is not nullable.
            *   Other array fields (e.g., `tags`, `alternate_greetings` if not provided): Default to empty arrays if the database column is not nullable.
    *   Perform encryption for all sensitive fields (e.g., `description`, `personality`, `first_mes`, `system_prompt`) using the `SessionDek` and `EncryptionService`. This will be similar to the encryption logic in the existing `upload_character_handler`.
    *   Save the populated and encrypted `NewCharacter` instance to the `characters` database table.
    *   Return the newly created character, decrypted, as a `CharacterDataForClient` object with a `201 CREATED` status.

### B. Database-Wide Character Editing (e.g., `PUT /api/characters/:id` or `PATCH /api/characters/:id`)

1.  **Request DTO:**
    *   Define a DTO for the update payload. All fields in this DTO should be optional to allow clients to send partial updates (only the fields they want to change).

2.  **Handler Logic:**
    *   Fetch the existing `Character` record from the database using the `id` from the path.
    *   Verify that the authenticated user is the owner of this character.
    *   For each field present in the update DTO:
        *   If the corresponding database field is encrypted (e.g., `description`, `personality`):
            *   Decrypt the current value from the database (if it exists and has a nonce).
            *   Apply the update from the DTO to the decrypted value.
            *   Re-encrypt the new, modified value. Store both the new encrypted value and its new nonce in the `Character` model instance.
        *   If the field is not encrypted:
            *   Apply the update from the DTO directly to the `Character` model instance.
    *   Update the `modification_date` field in the `characters` table to the current timestamp.
    *   Save the changes to the `Character` record in the database.
    *   Return the updated character, decrypted, as a `CharacterDataForClient` object.

### C. Per-Chat Character Editing (Using an Overrides Table - Option A)

1.  **New Database Table: `chat_character_overrides`**
    *   `id`: UUID (Primary Key)
    *   `chat_session_id`: UUID (Foreign Key referencing `chat_sessions.id`, indexed)
    *   `original_character_id`: UUID (Foreign Key referencing `characters.id`, indexed)
    *   `field_name`: VARCHAR(255) (Stores the name of the overridden field, e.g., "description", "personality", "first_mes")
    *   `overridden_value`: BYTEA (Stores the encrypted value of the overridden field)
    *   `overridden_value_nonce`: BYTEA (Nonce for the `overridden_value`)
    *   `created_at`: TIMESTAMPTZ (Default to current timestamp)
    *   `updated_at`: TIMESTAMPTZ (Default to current timestamp, auto-update on modification)
    *   *Constraint:* Add a unique constraint on (`chat_session_id`, `original_character_id`, `field_name`) to ensure only one override per field for a specific character within a specific chat session.

2.  **New API Endpoint (e.g., `POST /api/chats/:session_id/character/overrides`)**
    *   **Request Payload:** A JSON object like `{ "field_name": "description", "value": "New chat-specific description" }`.
        *   Initially, `field_name` will support "description", "personality", and "first_mes".
    *   **Handler Logic:**
        *   Verify that the authenticated user owns the chat session identified by `:session_id`.
        *   Retrieve the `original_character_id` associated with the `chat_session_id` from the `chat_sessions` table.
        *   Encrypt the provided `value` using the `SessionDek` and `EncryptionService`.
        *   Perform an "upsert" operation (insert or update if exists) into the `chat_character_overrides` table for the given `chat_session_id`, `original_character_id`, and `field_name` with the new encrypted value and nonce.
        *   Return a success response, possibly including the details of the created/updated override.

3.  **Modify Character Loading Logic for Chat Contexts:**
    *   When character data is fetched in a context specific to a chat session (e.g., when loading a chat for interaction, or potentially by enhancing `get_character_handler` to accept an optional `session_id` query parameter):
        *   Fetch the base `Character` record using its ID.
        *   Query the `chat_character_overrides` table for any override records matching the current `chat_session_id` and the base `character_id`.
        *   When preparing the `CharacterDataForClient` (or a similar structure used for chat context):
            *   First, decrypt all fields from the base `Character` object as is currently done.
            *   Then, iterate through the potential overridable fields (initially `description`, `personality`, `first_mes`):
                *   If an override record exists in the fetched `chat_character_overrides` for that specific field:
                    *   Decrypt the `overridden_value` from that override record.
                    *   Use this decrypted override value in the `CharacterDataForClient` object, replacing the value that came from the base character.
            *   The resulting `CharacterDataForClient` object will then represent the "effective" character state for that specific chat session.

## II. CLI Changes

### A. General Approach

*   New subcommands will be integrated into the existing CLI structure, likely under `sanguine character ...` and `sanguine chat ...`.
*   Both wizard-style (interactive menu-driven) and one-liner command options will be implemented for user convenience and admin scripting.

### B. Manual Character Creation

1.  **One-Liner Command:**
    *   Syntax: `sanguine character create --name "Character Name" --description "Details about the character..." --first-mes "Initial greeting!" [--personality "..."] [--scenario "..."] [--tags "tag1,tag2"] ...` (other fields from `CharacterCardDataV3` as optional flags).
    *   Action: This command will construct the appropriate JSON payload based on the provided arguments and call the new backend API endpoint for manual character creation.

2.  **Wizard (Interactive Mode):**
    *   Integration: Add a "Create New Character (Manual)" option to the `sanguine character` menu in [`cli/src/main.rs`](cli/src/main.rs).
    *   Flow:
        *   Prompt the user step-by-step for `name` (mandatory).
        *   Prompt for `description` (mandatory).
        *   Prompt for `first_mes` (mandatory).
        *   Offer to add optional fields one by one or in categories (e.g., "Add personality?", "Add scenario?", "Add tags?").
        *   Compile all user inputs into the DTO structure and call the backend API.

### C. Database-Wide Character Editing

1.  **One-Liner Command:**
    *   Syntax: `sanguine character edit --id <character_uuid> [--name "New Character Name"] [--description "Updated description..."] ...` (any editable field as an optional flag).
    *   Action: Constructs a partial update JSON payload and calls the backend API for editing characters.

2.  **Wizard (Interactive Mode):**
    *   Integration: Add an "Edit Existing Character" option to the `sanguine character` menu.
    *   Flow:
        *   Prompt for the Character ID to edit.
        *   Fetch and display the current (decrypted) character details.
        *   Present a menu of fields that can be edited.
        *   Allow the user to select a field and input its new value. Repeat for multiple fields if desired.
        *   Compile the changes into a partial update DTO and call the backend API.

### D. Per-Chat Character Editing

1.  **One-Liner Command:**
    *   Syntax: `sanguine chat edit-character --session-id <session_uuid> --field <field_to_edit> --value "New Value for this chat"`
    *   Examples:
        *   `sanguine chat edit-character --session-id xxxxx-xxxx-xxxx-xxxx --field description --value "A temporary description just for this specific chat."`
        *   `sanguine chat edit-character --session-id yyyyy-yyyy-yyyy-yyyy --field personality --value "Slightly more inquisitive for this conversation."`
    *   Action: This command will call the new backend API endpoint for creating/updating character overrides for the specified chat session and field.

2.  **Wizard (Interactive Mode):**
    *   Integration: Add an "Edit Character for Specific Session" option to the `sanguine chat` menu.
    *   Flow:
        *   Prompt for the Chat Session ID.
        *   Fetch and display the current "effective" character details for that session (this means fetching the base character and then applying any existing overrides, all decrypted).
        *   Present a list of fields that can be overridden for the chat (initially `description`, `personality`, `first_mes`).
        *   Allow the user to select a field and provide the new value for that specific chat session.
        *   Call the backend API to create/update the override.

## III. High-Level Data Flow & Components Diagram

```mermaid
graph TD
    subgraph CLI
        direction LR
        CLI_Wizard[CLI Wizard (Interactive Menus)]
        CLI_OneLiner[CLI One-Liners]
    end

    subgraph Backend API [/api]
        direction TB
        EP_ManualCreate["POST /characters <br> (Accepts DTO with char data)"]
        EP_EditChar["PUT /characters/:id <br> (Accepts DTO with fields to update)"]
        EP_ChatOverride["POST /chats/:sid/character/overrides <br> (Accepts field_name, value)"]
        EP_GetChar["GET /characters/fetch/:id <br> (Modified to check overrides)"]
    end

    subgraph Backend Services
        direction TB
        CharService[Character Service Logic <br> (Handles DTOs, encryption, DB interaction)]
        EncryptService[Encryption Service <br> (Uses SessionDek)]
    end

    subgraph Database
        direction TB
        DB_Chars[Characters Table <br> (id, user_id, name, encrypted_fields..., nonces...)]
        DB_ChatSessions[Chat Sessions Table <br> (id, user_id, character_id, system_prompt...)]
        DB_ChatOverrides[NEW: Chat Character Overrides Table <br> (id, chat_session_id, original_character_id, field_name, overridden_value, nonce)]
    end

    User --> CLI_Wizard
    User --> CLI_OneLiner

    CLI_Wizard --> EP_ManualCreate
    CLI_Wizard --> EP_EditChar
    CLI_Wizard --> EP_ChatOverride

    CLI_OneLiner --> EP_ManualCreate
    CLI_OneLiner --> EP_EditChar
    CLI_OneLiner --> EP_ChatOverride

    EP_ManualCreate --> CharService
    EP_EditChar --> CharService
    EP_ChatOverride --> CharService
    EP_GetChar --> CharService

    CharService -- Uses --> EncryptService
    CharService -- Interacts with --> DB_Chars
    CharService -- Interacts with --> DB_ChatSessions
    CharService -- Interacts with --> DB_ChatOverrides

    DB_ChatOverrides -- FK --> DB_ChatSessions
    DB_ChatOverrides -- FK --> DB_Chars
    DB_ChatSessions -- FK --> DB_Chars
```

## IV. Future Considerations / Refinements During Implementation

*   **Exact DTO Structures:** Finalize the precise structure of DTOs for API request/response bodies, ensuring they align with frontend needs and backend processing capabilities.
*   **Error Handling:** Implement robust error handling for all new API endpoints, especially around encryption/decryption failures, database errors, and validation issues.
*   **CLI Data Fetching for Wizards:** Determine how the CLI wizards will efficiently fetch and display existing character/override data before prompting for edits.
*   **Default Values for `CharacterCardDataV3`:** Create a comprehensive list of default values for all fields in `CharacterCardDataV3` to be used during manual creation when a field is not provided by the user.
*   **`assets` Field in Manual Creation:** For the initial implementation of manual creation, the `assets` field will likely default to the standard icon or be empty. Full asset management via manual JSON input is complex and can be a future enhancement if needed. The primary goal is text-based card creation.
*   **Transaction Management:** Ensure database operations (especially those involving multiple steps like fetch-decrypt-update-encrypt-save) are handled within transactions where appropriate to maintain data integrity.
*   **Performance:** For character loading in chat contexts, monitor the performance impact of fetching base characters plus their overrides. Optimize queries as needed.