# Plan: Implement CharacterService for Manual Character Operations

The goal is to create a `CharacterService` that encapsulates the business logic for manually creating and editing characters. This involves refactoring existing logic from `backend/src/routes/characters.rs` into this new service, promoting better code organization and reusability.

## I. Define `CharacterService` Structure

1.  **Create `backend/src/services/character_service.rs`**:
    *   Define the `CharacterService` struct.
    *   It will take `PgPool` (for database access) and `Arc<EncryptionService>` (for encryption/decryption) as dependencies, similar to `ChatOverrideService`.
    *   Implement a `new(db_pool: PgPool, encryption_service: Arc<EncryptionService>) -> Self` constructor.

    ```rust
    // backend/src/services/character_service.rs
    use std::sync::Arc;
    use uuid::Uuid;
    use diesel::prelude::*; // For Result<T, Error> type in DB operations
    use chrono::Utc;

    use crate::auth::session_dek::SessionDek;
    use crate::errors::AppError;
    use crate::models::character_card::NewCharacter;
    use crate::models::characters::{Character, CharacterDataForClient};
    use crate::models::character_dto::{CharacterCreateDto, CharacterUpdateDto};
    use crate::schema::characters; // For table access
    use crate::services::encryption_service::EncryptionService;
    use crate::PgPool; // Diesel connection pool

    #[derive(Clone)]
    pub struct CharacterService {
        db_pool: PgPool,
        encryption_service: Arc<EncryptionService>,
    }

    impl CharacterService {
        pub fn new(db_pool: PgPool, encryption_service: Arc<EncryptionService>) -> Self {
            Self { db_pool, encryption_service }
        }

        // Service methods will be defined here
    }
    ```

2.  **Register `CharacterService`**:
    *   Add `pub mod character_service;` to `backend/src/services/mod.rs`.
    *   Add `pub use character_service::CharacterService;` to `backend/src/services/mod.rs`.
    *   `CharacterService` will likely be instantiated directly in handlers, similar to `ChatOverrideService`.

## II. Implement Manual Character Creation in `CharacterService`

1.  **Define `create_character_manually` method**:
    *   Signature:
        ```rust
        pub async fn create_character_manually(
            &self,
            user_id_val: Uuid,
            create_dto: CharacterCreateDto,
            dek: &SessionDek,
        ) -> Result<CharacterDataForClient, AppError>
        ```
    *   **Logic (refactored from `create_character_handler` in `backend/src/routes/characters.rs`)**:
        1.  Validate DTO (`create_dto.validate()`).
        2.  Construct `NewCharacter` from `create_dto`, setting `spec` to `"chara_card_v3"`, `spec_version` to `"3.0"`, and applying defaults as per `docs/CHARACTER_CREATOR_PLAN.md`. `avatar` in `NewCharacter` will be `None` initially.
        3.  Encrypt sensitive fields in `NewCharacter` using a private helper `_encrypt_string_field_with_nonce` (see section IV).
        4.  Insert `NewCharacter` into `characters` table via `self.db_pool.interact`.
        5.  Fetch the full `Character` record and convert to `CharacterDataForClient` using `character.into_decrypted_for_client(Some(dek)).await?`.

## III. Implement Character Editing in `CharacterService`

1.  **Define `update_character_details` method**:
    *   Signature:
        ```rust
        pub async fn update_character_details(
            &self,
            character_id_to_update: Uuid,
            user_id_val: Uuid,
            update_dto: CharacterUpdateDto,
            dek: &SessionDek,
        ) -> Result<CharacterDataForClient, AppError>
        ```
    *   **Logic (refactored from `update_character_handler` in `backend/src/routes/characters.rs`)**:
        1.  Fetch `Character` by `character_id_to_update` and `user_id_val` for ownership check.
        2.  Apply updates from `update_dto`:
            *   For non-encrypted fields, update `Character` instance directly.
            *   For encrypted fields, use a private helper `_update_optional_encrypted_string_field` (see section IV).
        3.  Update `character.updated_at = Utc::now()` and `character.modification_date = Some(Utc::now())`.
        4.  Save changes to `Character` record via `self.db_pool.interact`.
        5.  Convert returned `Character` to `CharacterDataForClient`.

## IV. Define Private Helper Methods in `CharacterService`

1.  **`_encrypt_string_field_with_nonce`**:
    *   Signature: `async fn _encrypt_string_field_with_nonce(&self, plaintext: &str, dek_key: &[u8]) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), AppError>`
    *   Encrypts non-empty plaintext, returns `(Some(ciphertext), Some(nonce))` or `(None, None)`.

2.  **`_update_optional_encrypted_string_field`**:
    *   Signature: `async fn _update_optional_encrypted_string_field(&self, dto_field_value: &Option<String>, dek_key: &[u8], current_ciphertext: &mut Option<Vec<u8>>, current_nonce: &mut Option<Vec<u8>>) -> Result<(), AppError>`
    *   Updates character's encrypted field and nonce based on DTO's plaintext value. If DTO value is empty string, clears field/nonce.

## V. Refactor Route Handlers in `backend/src/routes/characters.rs`

1.  **Update `create_character_handler`**: Instantiate `CharacterService` and call `character_service.create_character_manually(...)`.
2.  **Update `update_character_handler`**: Instantiate `CharacterService` and call `character_service.update_character_details(...)`.
3.  **Review `upload_character_handler`**: The `encrypt_field!` macro is self-contained. No immediate changes planned here unless `CharacterService` or `EncryptionService` is added to `AppState`.

## VI. Mermaid Diagram of Proposed Service Interaction

```mermaid
graph TD
    subgraph Client_Subgraph ["Client"]
        Client_API_Request["API Request (DTO)"]
    end

    subgraph Backend_API_Subgraph ["Backend API /api/characters"]
        Svc_Route_CreateCharacter["POST / (create_character_handler)"]
        Svc_Route_UpdateCharacter["PUT /:id (update_character_handler)"]
    end

    subgraph Backend_Services_Subgraph ["Backend Services"]
        Svc_CharService["CharacterService (create, update, helpers)"]
        Svc_EncryptService["EncryptionService (encrypt, decrypt)"]
    end

    subgraph Database_Models_Subgraph ["Database Models"]
        Model_NewCharacter["NewCharacter (Insertable)"]
        Model_Character["Character (Queryable, AsChangeset)"]
        Model_ClientData["CharacterDataForClient (Decrypted)"]
        Model_CreateDto["CharacterCreateDto"]
        Model_UpdateDto["CharacterUpdateDto"]
    end

    subgraph Database_Subgraph ["Database"]
        DB_Chars["characters Table"]
    end

    Client_API_Request -- "Contains DTO" --> Svc_Route_CreateCharacter
    Client_API_Request -- "Contains DTO" --> Svc_Route_UpdateCharacter

    Svc_Route_CreateCharacter -- "Uses DTO, UserID, DEK" --> Svc_CharService
    Svc_Route_UpdateCharacter -- "Uses DTO, CharID, UserID, DEK" --> Svc_CharService

    Svc_CharService -- "Uses" --> Svc_EncryptService
    Svc_CharService -- "Constructs/Modifies" --> Model_NewCharacter
    Svc_CharService -- "Fetches/Modifies" --> Model_Character
    Svc_CharService -- "Converts to" --> Model_ClientData

    Model_NewCharacter -- "Maps from" --> Model_CreateDto
    Model_Character -- "Updated by" --> Model_UpdateDto

    Svc_CharService -- "Inserts (NewCharacter)" --> DB_Chars
    Svc_CharService -- "Updates (Character)" --> DB_Chars
    Svc_CharService -- "Fetches (Character)" --> DB_Chars

    Model_Character -- "Converts to" --> Model_ClientData