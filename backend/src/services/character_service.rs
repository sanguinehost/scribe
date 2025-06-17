use std::sync::Arc;

use chrono::{DateTime, Utc}; // For timestamps
use deadpool_diesel::postgres::Pool as DeadpoolPgPool; // Changed from sqlx::PgPool
use secrecy::ExposeSecret; // For DEK
use tracing::{info, instrument, warn};
use uuid::Uuid; // For logging

use crate::auth::session_dek::SessionDek;
use crate::errors::AppError;
use crate::models::character_card::NewCharacter;
use crate::models::character_dto::{CharacterCreateDto, CharacterUpdateDto}; // Added CharacterUpdateDto
use crate::models::characters::{Character, CharacterDataForClient};
use crate::schema::characters; // For characters::table, characters::id
use crate::schema::characters::dsl::{id as character_dsl_id, user_id as character_dsl_user_id}; // for explicit column access
use crate::services::encryption_service::EncryptionService;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper,
    result::Error as DieselError,
}; // For .values(), .returning(), .get_result(), etc.
use diesel_json; // For Json<Value> type in Diesel models
use serde_json; // For json!({}) macro

/// Type alias for the complex return type of encrypted field operations
type EncryptedFieldResult = (Option<Vec<u8>>, Option<Vec<u8>>);

#[derive(Clone)]
pub struct CharacterService {
    db_pool: DeadpoolPgPool, // Changed from sqlx::PgPool
    encryption_service: Arc<EncryptionService>,
}

impl CharacterService {
    #[must_use]
    pub fn new(db_pool: DeadpoolPgPool, encryption_service: Arc<EncryptionService>) -> Self {
        // Changed db_pool type
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
    fn encrypt_string_field_with_nonce(
        &self,
        plaintext: &str,
        dek_key: &[u8],
    ) -> Result<EncryptedFieldResult, AppError> {
        if plaintext.is_empty() {
            Ok((None, None))
        } else {
            // Corrected: pass plaintext as &str if EncryptionService::encrypt expects it
            let (ciphertext, nonce) = self.encryption_service.encrypt(plaintext, dek_key)?;
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
    fn update_optional_encrypted_string_field(
        &self,
        dto_field_value: Option<&String>,
        dek_key: &[u8],
        current_ciphertext: &mut Option<Vec<u8>>,
        current_nonce: &mut Option<Vec<u8>>,
    ) -> Result<(), AppError> {
        if let Some(plaintext_value) = dto_field_value {
            if plaintext_value.is_empty() {
                *current_ciphertext = None;
                *current_nonce = None;
            } else {
                let (encrypted_data, nonce_data) =
                    self.encrypt_string_field_with_nonce(plaintext_value, dek_key)?;
                *current_ciphertext = encrypted_data;
                *current_nonce = nonce_data;
            }
        }
        // If dto_field_value is None, do nothing as per the logic.
        Ok(())
    }

    /// Creates a new character manually with the provided data and encryption.
    ///
    /// # Errors
    ///
    /// Returns `AppError::BadRequest` if the DTO validation fails,
    /// encryption service errors if field encryption fails,
    /// `AppError::DbPoolError` if database connection cannot be obtained,
    /// `AppError::InternalServerErrorGeneric` if database interaction fails,
    /// `AppError::DatabaseQueryError` if the insert or fetch operation fails.
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
        let (description_enc, description_nonce_enc) = self.encrypt_string_field_with_nonce(
            create_dto
                .description
                .as_deref()
                .expect("Description guaranteed by validation"),
            dek_key_bytes,
        )?;
        let (personality_enc, personality_nonce_enc) =
            self.encrypt_string_field_with_nonce(&create_dto.personality, dek_key_bytes)?;
        let (scenario_enc, scenario_nonce_enc) =
            self.encrypt_string_field_with_nonce(&create_dto.scenario, dek_key_bytes)?;
        let (first_mes_enc, first_mes_nonce_enc) = self.encrypt_string_field_with_nonce(
            create_dto
                .first_mes
                .as_deref()
                .expect("First message guaranteed by validation"),
            dek_key_bytes,
        )?;
        let (mes_example_enc, mes_example_nonce_enc) =
            self.encrypt_string_field_with_nonce(&create_dto.mes_example, dek_key_bytes)?;
        let (creator_notes_enc, creator_notes_nonce_enc) =
            self.encrypt_string_field_with_nonce(&create_dto.creator_notes, dek_key_bytes)?;
        let (system_prompt_enc, system_prompt_nonce_enc) =
            self.encrypt_string_field_with_nonce(&create_dto.system_prompt, dek_key_bytes)?;
        let (post_history_instructions_enc, post_history_instructions_nonce_enc) = self
            .encrypt_string_field_with_nonce(
                &create_dto.post_history_instructions,
                dek_key_bytes,
            )?;

        // Create a NewCharacter from the DTO
        let mut new_character_for_db = NewCharacter {
            user_id: user_id_val,
            name: create_dto
                .name
                .expect("Name should be present after validation"),
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
            tags: if create_dto.tags.is_empty() {
                None
            } else {
                Some(create_dto.tags.into_iter().map(Some).collect())
            },
            creator: if create_dto.creator.is_empty() {
                None
            } else {
                Some(create_dto.creator)
            },
            character_version: if create_dto.character_version.is_empty() {
                None
            } else {
                Some(create_dto.character_version)
            },
            alternate_greetings: if create_dto.alternate_greetings.is_empty() {
                None
            } else {
                Some(
                    create_dto
                        .alternate_greetings
                        .into_iter()
                        .map(Some)
                        .collect(),
                )
            },
            creator_notes_multilingual: create_dto
                .creator_notes_multilingual
                .map(|j| diesel_json::Json(j.0)),
            nickname: create_dto.nickname,
            source: create_dto.source.and_then(|s_vec| {
                if s_vec.is_empty() {
                    None
                } else {
                    Some(s_vec.into_iter().map(Some).collect())
                }
            }),
            group_only_greetings: if create_dto.group_only_greetings.is_empty() {
                None
            } else {
                Some(
                    create_dto
                        .group_only_greetings
                        .into_iter()
                        .map(Some)
                        .collect(),
                )
            },
            creation_date: create_dto
                .creation_date
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            modification_date: create_dto
                .modification_date
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            extensions: Some(create_dto.extensions.map_or_else(
                || diesel_json::Json(serde_json::json!({})),
                |j| diesel_json::Json(j.0),
            )),
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
            fav: create_dto.fav,
            world: create_dto.world.clone(),
            creator_comment: None, // Will be encrypted below
            creator_comment_nonce: None,
            depth_prompt: None, // The raw text, will be used for encryption
            depth_prompt_depth: create_dto.depth_prompt_depth,
            depth_prompt_role: create_dto.depth_prompt_role.clone(),
            talkativeness: None, // Not supported yet (group chat feature)
            depth_prompt_ciphertext: None, // Will be encrypted below
            depth_prompt_nonce: None,
            world_ciphertext: None, // Will be encrypted below
            world_nonce: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        // Encrypt SillyTavern v3 fields
        // Encrypt creator_comment if provided
        if let Some(creator_comment_text) = create_dto.creator_comment.as_ref() {
            if !creator_comment_text.is_empty() {
                let (ciphertext, nonce) =
                    self.encrypt_string_field_with_nonce(creator_comment_text, dek_key_bytes)?;
                new_character_for_db.creator_comment = ciphertext;
                new_character_for_db.creator_comment_nonce = nonce;
            }
        }

        // Encrypt depth_prompt if provided
        if let Some(depth_prompt_text) = create_dto.depth_prompt.as_ref() {
            if !depth_prompt_text.is_empty() {
                let (ciphertext, nonce) =
                    self.encrypt_string_field_with_nonce(depth_prompt_text, dek_key_bytes)?;
                new_character_for_db.depth_prompt_ciphertext = ciphertext;
                new_character_for_db.depth_prompt_nonce = nonce;
            }
        }

        // Encrypt world field if provided
        if let Some(world_text) = create_dto.world.as_ref() {
            if !world_text.is_empty() {
                let (ciphertext, nonce) =
                    self.encrypt_string_field_with_nonce(world_text, dek_key_bytes)?;
                new_character_for_db.world_ciphertext = ciphertext;
                new_character_for_db.world_nonce = nonce;
            }
        }

        info!(character_name = %new_character_for_db.name, user_id = %user_id_val, "Attempting to insert manually created character into DB for user");

        let conn = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
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
                AppError::InternalServerErrorGeneric(format!("Insert interaction error: {e}"))
            })?
            .map_err(|e| AppError::DatabaseQueryError(format!("Insert DB error: {e}")))?;

        info!(character_id = %returned_id, "Character basic info returned after manual insertion");

        // Fetch the inserted character to return its full data
        let conn_fetch = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!(
                "Failed to get DB connection from pool for fetch: {e}"
            ))
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
                AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {e}"))
            })?
            .map_err(|e| AppError::DatabaseQueryError(format!("Fetch DB error: {e}")))?;

        info!(character_id = %inserted_character.id, "Character manually created and saved (full data fetched)");

        // Handle lorebook association if world field is provided
        let mut associated_lorebook_ids = Vec::new();
        if let Some(world_id) = create_dto.world.as_ref() {
            if !world_id.is_empty() {
                // Try to parse the world ID as a UUID
                if let Ok(lorebook_uuid) = Uuid::parse_str(world_id) {
                    // Verify lorebook exists and belongs to user
                    use crate::schema::lorebooks;
                    let conn_check = self.db_pool.get().await.map_err(|e| {
                        AppError::DbPoolError(format!("Failed to get DB connection: {e}"))
                    })?;

                    let lorebook_exists = conn_check
                        .interact(move |conn_sync| {
                            lorebooks::table
                                .filter(lorebooks::id.eq(lorebook_uuid))
                                .filter(lorebooks::user_id.eq(user_id_val))
                                .count()
                                .get_result::<i64>(conn_sync)
                                .map(|count| count > 0)
                        })
                        .await
                        .map_err(|e| {
                            AppError::DbInteractError(format!("DB interaction failed: {e}"))
                        })?
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    if lorebook_exists {
                        // Create association
                        use crate::models::lorebooks::NewCharacterLorebook;
                        use crate::schema::character_lorebooks;

                        let new_association = NewCharacterLorebook {
                            character_id: returned_id,
                            lorebook_id: lorebook_uuid,
                            user_id: user_id_val,
                            created_at: Some(Utc::now()),
                            updated_at: Some(Utc::now()),
                        };

                        let conn_insert = self.db_pool.get().await.map_err(|e| {
                            AppError::DbPoolError(format!("Failed to get DB connection: {e}"))
                        })?;

                        conn_insert
                            .interact(move |conn_sync| {
                                diesel::insert_into(character_lorebooks::table)
                                    .values(&new_association)
                                    .execute(conn_sync)
                            })
                            .await
                            .map_err(|e| {
                                AppError::DbInteractError(format!("DB interaction failed: {e}"))
                            })?
                            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                        info!(character_id = %returned_id, lorebook_id = %lorebook_uuid, "Successfully associated lorebook with character");
                        associated_lorebook_ids.push(lorebook_uuid);
                    } else {
                        warn!(character_id = %returned_id, lorebook_id = %lorebook_uuid, "Lorebook not found or not owned by user");
                    }
                } else {
                    warn!(character_id = %returned_id, world = %world_id, "Invalid lorebook UUID in world field");
                }
            }
        }

        // Convert to client format with decryption
        let client_character_data =
            inserted_character.into_decrypted_for_client(Some(&dek.0), associated_lorebook_ids)?;

        Ok(client_character_data)
    }

    #[instrument(skip(self, update_dto, dek), err)]
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
            AppError::DbPoolError(format!(
                "Failed to get DB connection from pool for fetch: {e}"
            ))
        })?;

        let mut existing_character: Character = conn_fetch
            .interact(move |conn_select_block| {
                characters::table
                    .filter(
                        character_dsl_id
                            .eq(character_id_to_update)
                            .and(character_dsl_user_id.eq(user_id_val)),
                    )
                    .select(Character::as_select())
                    .get_result::<Character>(conn_select_block)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {e}"))
            })?
            .map_err(|e| match e {
                DieselError::NotFound => AppError::NotFound(format!(
                    "Character {character_id_to_update} not found or not owned by user {user_id_val}"
                )),
                _ => AppError::DatabaseQueryError(format!("Fetch DB error: {e}")),
            })?;

        info!(character_id = %character_id_to_update, "Found character to update, applying changes");

        let dek_key_bytes = dek.0.expose_secret().as_slice();

        // Apply updates from DTO
        if let Some(name_val) = update_dto.name {
            existing_character.name = name_val;
        }

        // Encrypted fields
        self.update_optional_encrypted_string_field(
            update_dto.description.as_ref(),
            dek_key_bytes,
            &mut existing_character.description,
            &mut existing_character.description_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.personality.as_ref(),
            dek_key_bytes,
            &mut existing_character.personality,
            &mut existing_character.personality_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.scenario.as_ref(),
            dek_key_bytes,
            &mut existing_character.scenario,
            &mut existing_character.scenario_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.first_mes.as_ref(),
            dek_key_bytes,
            &mut existing_character.first_mes,
            &mut existing_character.first_mes_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.mes_example.as_ref(),
            dek_key_bytes,
            &mut existing_character.mes_example,
            &mut existing_character.mes_example_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.creator_notes.as_ref(),
            dek_key_bytes,
            &mut existing_character.creator_notes,
            &mut existing_character.creator_notes_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.system_prompt.as_ref(),
            dek_key_bytes,
            &mut existing_character.system_prompt,
            &mut existing_character.system_prompt_nonce,
        )?;
        self.update_optional_encrypted_string_field(
            update_dto.post_history_instructions.as_ref(),
            dek_key_bytes,
            &mut existing_character.post_history_instructions,
            &mut existing_character.post_history_instructions_nonce,
        )?;

        // Non-encrypted fields
        if let Some(tags_val) = update_dto.tags {
            existing_character.tags = if tags_val.is_empty() {
                None
            } else {
                Some(tags_val.into_iter().map(Some).collect())
            };
        }
        if let Some(creator_val) = update_dto.creator {
            existing_character.creator = if creator_val.is_empty() {
                None
            } else {
                Some(creator_val)
            };
        }
        if let Some(cv_val) = update_dto.character_version {
            existing_character.character_version = if cv_val.is_empty() {
                None
            } else {
                Some(cv_val)
            };
        }
        if let Some(ag_val) = update_dto.alternate_greetings {
            existing_character.alternate_greetings = if ag_val.is_empty() {
                None
            } else {
                Some(ag_val.into_iter().map(Some).collect())
            };
        }
        if let Some(cnm_val) = update_dto.creator_notes_multilingual {
            existing_character.creator_notes_multilingual = Some(cnm_val.0);
        }
        if let Some(nick_val) = update_dto.nickname {
            existing_character.nickname = Some(nick_val);
        }
        if let Some(source_val) = update_dto.source {
            existing_character.source = if source_val.is_empty() {
                None
            } else {
                Some(source_val.into_iter().map(Some).collect())
            };
        }
        if let Some(gog_val) = update_dto.group_only_greetings {
            existing_character.group_only_greetings = if gog_val.is_empty() {
                None
            } else {
                Some(gog_val.into_iter().map(Some).collect())
            };
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

        // Handle SillyTavern v3 fields
        if let Some(fav_val) = update_dto.fav {
            existing_character.fav = Some(fav_val);
        }
        if let Some(ref world_val) = update_dto.world {
            existing_character.world = if world_val.is_empty() {
                None
            } else {
                Some(world_val.clone())
            };
            // Also encrypt into world_ciphertext
            if !world_val.is_empty() {
                let (ciphertext, nonce) =
                    self.encrypt_string_field_with_nonce(&world_val, dek_key_bytes)?;
                existing_character.world_ciphertext = ciphertext;
                existing_character.world_nonce = nonce;
            } else {
                existing_character.world_ciphertext = None;
                existing_character.world_nonce = None;
            }
        }
        if let Some(depth_prompt_depth_val) = update_dto.depth_prompt_depth {
            existing_character.depth_prompt_depth = Some(depth_prompt_depth_val);
        }
        if let Some(depth_prompt_role_val) = update_dto.depth_prompt_role {
            existing_character.depth_prompt_role = Some(depth_prompt_role_val);
        }

        // Handle encrypted SillyTavern v3 fields
        self.update_optional_encrypted_string_field(
            update_dto.creator_comment.as_ref(),
            dek_key_bytes,
            &mut existing_character.creator_comment,
            &mut existing_character.creator_comment_nonce,
        )?;

        // Handle depth_prompt - this goes into depth_prompt_ciphertext field
        if let Some(depth_prompt_val) = update_dto.depth_prompt.as_ref() {
            if depth_prompt_val.is_empty() {
                existing_character.depth_prompt_ciphertext = None;
                existing_character.depth_prompt_nonce = None;
            } else {
                let (ciphertext, nonce) =
                    self.encrypt_string_field_with_nonce(depth_prompt_val, dek_key_bytes)?;
                existing_character.depth_prompt_ciphertext = ciphertext;
                existing_character.depth_prompt_nonce = nonce;
            }
        }

        // Always update the 'updated_at' timestamp
        existing_character.updated_at = Utc::now();
        // Update modification_date if it wasn't explicitly provided in the DTO
        if update_dto.modification_date.is_none() {
            existing_character.modification_date = Some(Utc::now());
        }

        // Save the updated character
        let conn_update = self.db_pool.get().await.map_err(|e| {
            AppError::DbPoolError(format!(
                "Failed to get DB connection from pool for update: {e}"
            ))
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
                AppError::InternalServerErrorGeneric(format!("Update interaction error: {e}"))
            })?
            .map_err(|e| AppError::DatabaseQueryError(format!("Update DB error: {e}")))?;

        info!(character_id = %character_id_to_update, "Character updated successfully in CharacterService");

        // Fetch all existing lorebook associations for this character
        use crate::schema::character_lorebooks;
        let conn_fetch_lorebooks = self
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(format!("Failed to get DB connection: {e}")))?;

        let mut associated_lorebook_ids: Vec<Uuid> = conn_fetch_lorebooks
            .interact(move |conn_sync| {
                character_lorebooks::table
                    .filter(character_lorebooks::character_id.eq(character_id_to_update))
                    .filter(character_lorebooks::user_id.eq(user_id_val))
                    .select(character_lorebooks::lorebook_id)
                    .load::<Uuid>(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Failed to fetch lorebooks: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get lorebooks: {e}")))?;

        // Handle lorebook association if world field was updated
        if let Some(world_val) = update_dto.world.as_ref() {
            // For backward compatibility with the 'world' field, we'll replace all lorebooks with the single one specified
            // TODO: In the future, add a separate endpoint for managing multiple lorebooks

            // First, remove any existing lorebook associations for this character
            let conn_delete =
                self.db_pool.get().await.map_err(|e| {
                    AppError::DbPoolError(format!("Failed to get DB connection: {e}"))
                })?;

            let _ = conn_delete
                .interact(move |conn_sync| {
                    diesel::delete(
                        character_lorebooks::table
                            .filter(character_lorebooks::character_id.eq(character_id_to_update))
                            .filter(character_lorebooks::user_id.eq(user_id_val)),
                    )
                    .execute(conn_sync)
                })
                .await;

            // Clear the existing associations
            associated_lorebook_ids.clear();

            // If a new world ID is provided, create the association
            if !world_val.is_empty() {
                if let Ok(lorebook_uuid) = Uuid::parse_str(world_val) {
                    // Verify lorebook exists and belongs to user
                    use crate::schema::lorebooks;
                    let conn_check = self.db_pool.get().await.map_err(|e| {
                        AppError::DbPoolError(format!("Failed to get DB connection: {e}"))
                    })?;

                    let lorebook_exists = conn_check
                        .interact(move |conn_sync| {
                            lorebooks::table
                                .filter(lorebooks::id.eq(lorebook_uuid))
                                .filter(lorebooks::user_id.eq(user_id_val))
                                .count()
                                .get_result::<i64>(conn_sync)
                                .map(|count| count > 0)
                        })
                        .await
                        .map_err(|e| {
                            AppError::DbInteractError(format!("DB interaction failed: {e}"))
                        })?
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    if lorebook_exists {
                        // Create association
                        use crate::models::lorebooks::NewCharacterLorebook;

                        let new_association = NewCharacterLorebook {
                            character_id: character_id_to_update,
                            lorebook_id: lorebook_uuid,
                            user_id: user_id_val,
                            created_at: Some(Utc::now()),
                            updated_at: Some(Utc::now()),
                        };

                        let conn_insert = self.db_pool.get().await.map_err(|e| {
                            AppError::DbPoolError(format!("Failed to get DB connection: {e}"))
                        })?;

                        match conn_insert
                            .interact(move |conn_sync| {
                                diesel::insert_into(character_lorebooks::table)
                                    .values(&new_association)
                                    .execute(conn_sync)
                            })
                            .await
                        {
                            Ok(_) => {
                                info!(character_id = %character_id_to_update, lorebook_id = %lorebook_uuid, "Successfully associated lorebook with character");
                                associated_lorebook_ids.push(lorebook_uuid);
                            }
                            Err(e) => {
                                warn!(character_id = %character_id_to_update, lorebook_id = %lorebook_uuid, error = %e, "Failed to associate lorebook with character");
                                // Continue without failing the character update
                            }
                        }
                    } else {
                        warn!(character_id = %character_id_to_update, lorebook_id = %lorebook_uuid, "Lorebook not found or not owned by user");
                    }
                } else {
                    warn!(character_id = %character_id_to_update, world = %world_val, "Invalid lorebook UUID in world field");
                }
            }
        }

        // Convert to client format with decryption
        let client_character_data = updated_character_db
            .into_decrypted_for_client(Some(&dek.0), associated_lorebook_ids)?;

        Ok(client_character_data)
    }
}

// TODO: Add unit tests for these helper methods in a new test module,
// e.g., backend/tests/character_service_tests.rs or inline here.
// Tests should cover:
// - encrypt_string_field_with_nonce:
//   - Empty plaintext
//   - Non-empty plaintext
//   - Encryption service error
// - update_optional_encrypted_string_field:
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
