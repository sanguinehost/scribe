use std::sync::Arc;

use deadpool_diesel::postgres::Pool as DeadpoolPgPool; // Changed from sqlx::PgPool
use uuid::Uuid;
use chrono::{DateTime, Utc}; // For timestamps
use secrecy::ExposeSecret; // For DEK
use tracing::{info, instrument}; // For logging

use crate::auth::session_dek::SessionDek;
use crate::services::encryption_service::EncryptionService;
use crate::errors::AppError;
use crate::models::character_card::NewCharacter;
use crate::models::characters::{Character, CharacterDataForClient};
use crate::models::character_dto::{CharacterCreateDto, CharacterUpdateDto}; // Added CharacterUpdateDto
use crate::schema::characters; // For characters::table, characters::id
use crate::schema::characters::dsl::{id as character_dsl_id, user_id as character_dsl_user_id}; // for explicit column access
use diesel::prelude::*; // For .values(), .returning(), .get_result(), etc.
use diesel::result::Error as DieselError; // Added DieselError
use diesel::RunQueryDsl; // Explicitly for insert_into, select, find
use diesel::SelectableHelper;
use diesel_json; // For Json<Value> type in Diesel models
use serde_json; // For json!({}) macro

#[derive(Clone)]
pub struct CharacterService {
    db_pool: DeadpoolPgPool, // Changed from sqlx::PgPool
    encryption_service: Arc<EncryptionService>,
}

impl CharacterService {
    pub fn new(db_pool: DeadpoolPgPool, encryption_service: Arc<EncryptionService>) -> Self { // Changed db_pool type
        Self {
            db_pool,
            encryption_service,
        }
    }

    /// Encrypts a non-empty plaintext string using the provided Data Encryption Key (DEK).
    ///
    /// If the plaintext is empty, returns `Ok((None, None))` indicating no encryption was performed
    /// and the fields should be cleared.
    /// Otherwise, returns `Ok((Some(ciphertext), Some(nonce)))`.
    async fn _encrypt_string_field_with_nonce(
        &self,
        plaintext: &str,
        dek_key: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), AppError> {
        if plaintext.is_empty() {
            Ok((None, None))
        } else {
            // Corrected: pass plaintext as &str if EncryptionService::encrypt expects it
            let (ciphertext, nonce) = self
                .encryption_service
                .encrypt(plaintext, dek_key)
                .await?;
            Ok((Some(ciphertext), Some(nonce)))
        }
    }

    /// Updates a character's optional encrypted string field and its corresponding nonce
    /// based on the provided DTO field value and Data Encryption Key (DEK).
    ///
    /// - If `dto_field_value` is `Some(plaintext)`:
    ///   - If `plaintext` is empty, `current_ciphertext` and `current_nonce` are set to `None`.
    ///   - If `plaintext` is not empty, it's encrypted, and `current_ciphertext` and
    ///     `current_nonce` are updated with the new encrypted data and nonce.
    /// - If `dto_field_value` is `None`, no changes are made to `current_ciphertext` or `current_nonce`.
    async fn _update_optional_encrypted_string_field(
        &self,
        dto_field_value: &Option<String>,
        dek_key: &[u8],
        current_ciphertext: &mut Option<Vec<u8>>,
        current_nonce: &mut Option<Vec<u8>>,
    ) -> Result<(), AppError> {
        if let Some(plaintext_value) = dto_field_value {
            if plaintext_value.is_empty() {
                *current_ciphertext = None;
                *current_nonce = None;
            } else {
                let (encrypted_data, nonce_data) = self
                    ._encrypt_string_field_with_nonce(plaintext_value, dek_key)
                    .await?;
                *current_ciphertext = encrypted_data;
                *current_nonce = nonce_data;
            }
        }
        // If dto_field_value is None, do nothing as per the logic.
        Ok(())
    }

    #[instrument(skip(self, create_dto, dek), err)]
    pub async fn create_character_manually(
        &self,
        user_id_val: Uuid,
        create_dto: CharacterCreateDto,
        dek: &SessionDek,
    ) -> Result<CharacterDataForClient, AppError> {
        // Validate the DTO
        create_dto.validate().map_err(AppError::BadRequest)?;

        let dek_key_bytes = dek.0.expose_secret().as_slice();

        // Encrypt fields from DTO using the service's helper method
        let (description_enc, description_nonce_enc) = self
            ._encrypt_string_field_with_nonce(
                create_dto.description.as_deref().expect("Description guaranteed by validation"),
                dek_key_bytes,
            )
            .await?;
        let (personality_enc, personality_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.personality, dek_key_bytes)
            .await?;
        let (scenario_enc, scenario_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.scenario, dek_key_bytes)
            .await?;
        let (first_mes_enc, first_mes_nonce_enc) = self
            ._encrypt_string_field_with_nonce(
                create_dto.first_mes.as_deref().expect("First message guaranteed by validation"),
                dek_key_bytes,
            )
            .await?;
        let (mes_example_enc, mes_example_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.mes_example, dek_key_bytes)
            .await?;
        let (creator_notes_enc, creator_notes_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.creator_notes, dek_key_bytes)
            .await?;
        let (system_prompt_enc, system_prompt_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.system_prompt, dek_key_bytes)
            .await?;
        let (post_history_instructions_enc, post_history_instructions_nonce_enc) = self
            ._encrypt_string_field_with_nonce(&create_dto.post_history_instructions, dek_key_bytes)
            .await?;

        // Create a NewCharacter from the DTO
        let new_character_for_db = NewCharacter {
            user_id: user_id_val,
            name: create_dto.name.expect("Name should be present after validation"),
            spec: "chara_card_v3".to_string(),
            spec_version: "3.0".to_string(),
            description: description_enc,
            description_nonce: description_nonce_enc,
            personality: personality_enc,
            personality_nonce: personality_nonce_enc,
            scenario: scenario_enc,
            scenario_nonce: scenario_nonce_enc,
            first_mes: first_mes_enc,
            first_mes_nonce: first_mes_nonce_enc,
            mes_example: mes_example_enc,
            mes_example_nonce: mes_example_nonce_enc,
            creator_notes: creator_notes_enc,
            creator_notes_nonce: creator_notes_nonce_enc,
            system_prompt: system_prompt_enc,
            system_prompt_nonce: system_prompt_nonce_enc,
            post_history_instructions: post_history_instructions_enc,
            post_history_instructions_nonce: post_history_instructions_nonce_enc,
            tags: if create_dto.tags.is_empty() { None } else { Some(create_dto.tags.into_iter().map(Some).collect()) },
            creator: if create_dto.creator.is_empty() { None } else { Some(create_dto.creator) },
            character_version: if create_dto.character_version.is_empty() { None } else { Some(create_dto.character_version) },
            alternate_greetings: if create_dto.alternate_greetings.is_empty() { None } else { Some(create_dto.alternate_greetings.into_iter().map(Some).collect()) },
            creator_notes_multilingual: create_dto.creator_notes_multilingual.map(|j| diesel_json::Json(j.0)),
            nickname: create_dto.nickname,
            source: create_dto.source.and_then(|s_vec| if s_vec.is_empty() { None } else { Some(s_vec.into_iter().map(Some).collect()) }),
            group_only_greetings: if create_dto.group_only_greetings.is_empty() { None } else { Some(create_dto.group_only_greetings.into_iter().map(Some).collect()) },
            creation_date: create_dto.creation_date.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            modification_date: create_dto.modification_date.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            extensions: Some(create_dto.extensions.map(|j| diesel_json::Json(j.0)).unwrap_or_else(|| diesel_json::Json(serde_json::json!({})))),
            persona: None,
            persona_nonce: None,
            world_scenario: None,
            world_scenario_nonce: None,
            avatar: None,
            chat: None,
            greeting: None,
            greeting_nonce: None,
            definition: None,
            definition_nonce: None,
            default_voice: None,
            category: None,
            definition_visibility: None,
            example_dialogue: None,
            example_dialogue_nonce: None,
            favorite: None,
            first_message_visibility: None,
            migrated_from: None,
            model_prompt: None,
            model_prompt_nonce: None,
            model_prompt_visibility: None,
            persona_visibility: None,
            sharing_visibility: None,
            status: None,
            system_prompt_visibility: None,
            system_tags: None,
            token_budget: None,
            usage_hints: None,
            user_persona: None,
            user_persona_nonce: None,
            user_persona_visibility: None,
            visibility: None,
            world_scenario_visibility: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        info!(character_name = %new_character_for_db.name, user_id = %user_id_val, "Attempting to insert manually created character into DB for user");

        let conn = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!("Failed to get DB connection from pool: {}", e))
        })?;

        let returned_id: Uuid = conn
            .interact(move |conn_insert_block| {
                diesel::insert_into(characters::table)
                    .values(new_character_for_db)
                    .returning(characters::id)
                    .get_result::<Uuid>(conn_insert_block)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Insert interaction error: {}", e))
            })?
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Insert DB error: {}", e))
            })?;

        info!(character_id = %returned_id, "Character basic info returned after manual insertion");

        // Fetch the inserted character to return its full data
        let conn_fetch = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!("Failed to get DB connection from pool for fetch: {}", e))
        })?;
        
        let inserted_character: Character = conn_fetch
            .interact(move |conn_select_block| {
                characters::table
                    .find(returned_id)
                    .select(Character::as_select())
                    .get_result::<Character>(conn_select_block)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {}", e))
            })?
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Fetch DB error: {}", e))
            })?;

        info!(character_id = %inserted_character.id, "Character manually created and saved (full data fetched)");

        // Convert to client format with decryption
        let client_character_data = inserted_character
            .into_decrypted_for_client(Some(&dek.0))
            .await?;

        Ok(client_character_data)
    }

    #[instrument(skip(self, update_dto, dek), err)]
    #[allow(clippy::too_many_lines)] // Allow for now, consider refactoring if it becomes too complex
    pub async fn update_character_details(
        &self,
        character_id_to_update: Uuid,
        user_id_val: Uuid, // For ownership check
        update_dto: CharacterUpdateDto,
        dek: &SessionDek,
    ) -> Result<CharacterDataForClient, AppError> {
        info!(character_id = %character_id_to_update, user_id = %user_id_val, "Attempting to update character in CharacterService");

        // Fetch the existing character from the database to verify ownership
        let conn_fetch = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!("Failed to get DB connection from pool for fetch: {}", e))
        })?;
        
        let mut existing_character: Character = conn_fetch
            .interact(move |conn_select_block| {
                characters::table
                    .filter(character_dsl_id.eq(character_id_to_update).and(character_dsl_user_id.eq(user_id_val)))
                    .select(Character::as_select())
                    .get_result::<Character>(conn_select_block)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {}", e))
            })?
            .map_err(|e| match e {
                DieselError::NotFound => AppError::NotFound(format!(
                    "Character {} not found or not owned by user {}",
                    character_id_to_update, user_id_val
                )),
                _ => AppError::DatabaseQueryError(format!("Fetch DB error: {}", e)),
            })?;

        info!(character_id = %character_id_to_update, "Found character to update, applying changes");

        let dek_key_bytes = dek.0.expose_secret().as_slice();

        // Apply updates from DTO
        if let Some(name_val) = update_dto.name {
            existing_character.name = name_val;
        }

        // Encrypted fields
        self._update_optional_encrypted_string_field(&update_dto.description, dek_key_bytes, &mut existing_character.description, &mut existing_character.description_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.personality, dek_key_bytes, &mut existing_character.personality, &mut existing_character.personality_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.scenario, dek_key_bytes, &mut existing_character.scenario, &mut existing_character.scenario_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.first_mes, dek_key_bytes, &mut existing_character.first_mes, &mut existing_character.first_mes_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.mes_example, dek_key_bytes, &mut existing_character.mes_example, &mut existing_character.mes_example_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.creator_notes, dek_key_bytes, &mut existing_character.creator_notes, &mut existing_character.creator_notes_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.system_prompt, dek_key_bytes, &mut existing_character.system_prompt, &mut existing_character.system_prompt_nonce).await?;
        self._update_optional_encrypted_string_field(&update_dto.post_history_instructions, dek_key_bytes, &mut existing_character.post_history_instructions, &mut existing_character.post_history_instructions_nonce).await?;
        
        // Non-encrypted fields
        if let Some(tags_val) = update_dto.tags {
            existing_character.tags = if tags_val.is_empty() { None } else { Some(tags_val.into_iter().map(Some).collect()) };
        }
        if let Some(creator_val) = update_dto.creator {
            existing_character.creator = if creator_val.is_empty() { None } else { Some(creator_val) };
        }
        if let Some(cv_val) = update_dto.character_version {
            existing_character.character_version = if cv_val.is_empty() { None } else { Some(cv_val) };
        }
        if let Some(ag_val) = update_dto.alternate_greetings {
            existing_character.alternate_greetings = if ag_val.is_empty() { None } else { Some(ag_val.into_iter().map(Some).collect()) };
        }
        if let Some(cnm_val) = update_dto.creator_notes_multilingual {
            existing_character.creator_notes_multilingual = Some(cnm_val.0);
        }
        if let Some(nick_val) = update_dto.nickname {
            existing_character.nickname = Some(nick_val);
        }
        if let Some(source_val) = update_dto.source {
            existing_character.source = if source_val.is_empty() { None } else { Some(source_val.into_iter().map(Some).collect()) };
        }
        if let Some(gog_val) = update_dto.group_only_greetings {
            existing_character.group_only_greetings = if gog_val.is_empty() { None } else { Some(gog_val.into_iter().map(Some).collect()) };
        }
        if let Some(cd_ts) = update_dto.creation_date {
            existing_character.creation_date = DateTime::from_timestamp(cd_ts, 0);
        }
        if let Some(md_ts) = update_dto.modification_date {
            existing_character.modification_date = DateTime::from_timestamp(md_ts, 0);
        }
        if let Some(ext_val) = update_dto.extensions {
            existing_character.extensions = Some(ext_val.0);
        }

        // Always update the 'updated_at' timestamp
        existing_character.updated_at = Utc::now();
        // Update modification_date if it wasn't explicitly provided in the DTO
        if update_dto.modification_date.is_none() {
            existing_character.modification_date = Some(Utc::now());
        }

        // Save the updated character
        let conn_update = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!("Failed to get DB connection from pool for update: {}", e))
        })?;
        
        let updated_character_db: Character = conn_update
            .interact(move |conn_update_block| {
                diesel::update(characters::table.find(character_id_to_update))
                    .set(&existing_character) // Pass the modified existing_character by reference
                    .returning(Character::as_select())
                    .get_result::<Character>(conn_update_block)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Update interaction error: {}", e))
            })?
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Update DB error: {}", e))
            })?;

        info!(character_id = %character_id_to_update, "Character updated successfully in CharacterService");

        // Convert to client format with decryption
        let client_character_data = updated_character_db
            .into_decrypted_for_client(Some(&dek.0))
            .await?;

        Ok(client_character_data)
    }
}

// TODO: Add unit tests for these helper methods in a new test module,
// e.g., backend/tests/character_service_tests.rs or inline here.
// Tests should cover:
// - _encrypt_string_field_with_nonce:
//   - Empty plaintext
//   - Non-empty plaintext
//   - Encryption service error
// - _update_optional_encrypted_string_field:
//   - dto_field_value is None (no change)
//   - dto_field_value is Some("") (fields cleared)
//   - dto_field_value is Some("text") (fields updated)
//   - Encryption error during update
// TODO: Add unit tests for create_character_manually
//   - Successful creation
//   - DTO validation failure
//   - Encryption failure
//   - DB insertion failure
//   - DB fetch failure
//   - Decryption failure post-fetch