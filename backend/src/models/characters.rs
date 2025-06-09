// backend/src/models/characters.rs
use crate::errors::AppError;
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Associations, Identifiable, Insertable, Queryable, Selectable};
use diesel_json::Json;
use secrecy::{ExposeSecret, SecretBox}; // Corrected: SecretVec -> SecretBox
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid; // For error handling

use crate::models::users::User;
use crate::schema::characters;
use crate::services::character_parser::ParsedCharacterCard;
// For encryption/decryption
// use crate::crypto::decrypt_gcm; // Will be replaced by EncryptionService
use crate::services::encryption_service::EncryptionService; // Added

#[derive(
    Queryable,
    Selectable,
    Identifiable,
    Associations,
    Insertable,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    AsChangeset,
)] // Removed Debug for custom impl
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = crate::schema::characters)]
#[diesel(treat_none_as_null = true)] // Added for AsChangeset with Option fields
pub struct Character {
    pub id: Uuid,
    pub user_id: Uuid,
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<Vec<u8>>,
    pub personality: Option<Vec<u8>>,
    pub scenario: Option<Vec<u8>>,
    pub first_mes: Option<Vec<u8>>,
    pub mes_example: Option<Vec<u8>>,
    pub creator_notes: Option<Vec<u8>>,
    pub system_prompt: Option<Vec<u8>>,
    pub post_history_instructions: Option<Vec<u8>>,
    pub tags: Option<Vec<Option<String>>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<serde_json::Value>,
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub persona: Option<Vec<u8>>,
    pub world_scenario: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub chat: Option<String>,
    pub greeting: Option<Vec<u8>>,
    pub definition: Option<Vec<u8>>,
    pub default_voice: Option<String>,
    pub extensions: Option<serde_json::Value>,
    pub data_id: Option<i32>,
    pub category: Option<String>,
    pub definition_visibility: Option<String>,
    pub depth: Option<i32>,
    pub example_dialogue: Option<Vec<u8>>,
    pub favorite: Option<bool>,
    pub first_message_visibility: Option<String>,
    pub height: Option<BigDecimal>,
    pub last_activity: Option<DateTime<Utc>>,
    pub migrated_from: Option<String>,
    pub model_prompt: Option<Vec<u8>>,
    pub model_prompt_visibility: Option<String>,
    pub model_temperature: Option<BigDecimal>,
    pub num_interactions: Option<i64>,
    pub permanence: Option<BigDecimal>,
    pub persona_visibility: Option<String>,
    pub revision: Option<i32>,
    pub sharing_visibility: Option<String>,
    pub status: Option<String>,
    pub system_prompt_visibility: Option<String>,
    pub system_tags: Option<Vec<Option<String>>>,
    pub token_budget: Option<i32>,
    pub usage_hints: Option<serde_json::Value>,
    pub user_persona: Option<Vec<u8>>,
    pub user_persona_visibility: Option<String>,
    pub visibility: Option<String>,
    pub weight: Option<BigDecimal>,
    pub world_scenario_visibility: Option<String>,
    pub description_nonce: Option<Vec<u8>>,
    pub personality_nonce: Option<Vec<u8>>,
    pub scenario_nonce: Option<Vec<u8>>,
    pub first_mes_nonce: Option<Vec<u8>>,
    pub mes_example_nonce: Option<Vec<u8>>,
    pub creator_notes_nonce: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub persona_nonce: Option<Vec<u8>>,
    pub world_scenario_nonce: Option<Vec<u8>>,
    pub greeting_nonce: Option<Vec<u8>>,
    pub definition_nonce: Option<Vec<u8>>,
    pub example_dialogue_nonce: Option<Vec<u8>>,
    pub model_prompt_nonce: Option<Vec<u8>>,
    pub user_persona_nonce: Option<Vec<u8>>,
    pub post_history_instructions_nonce: Option<Vec<u8>>,
    pub fav: Option<bool>,
    pub world: Option<String>,
    pub creator_comment: Option<Vec<u8>>,
    pub creator_comment_nonce: Option<Vec<u8>>,
    pub depth_prompt: Option<Vec<u8>>,
    pub depth_prompt_depth: Option<i32>,
    pub depth_prompt_role: Option<String>,
    pub talkativeness: Option<BigDecimal>,
    pub depth_prompt_ciphertext: Option<Vec<u8>>,
    pub depth_prompt_nonce: Option<Vec<u8>>,
    pub world_ciphertext: Option<Vec<u8>>,
    pub world_nonce: Option<Vec<u8>>,
}

impl std::fmt::Debug for Character {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("Character");
        self.add_basic_fields(&mut debug_struct);
        self.add_encrypted_fields(&mut debug_struct);
        self.add_metadata_fields(&mut debug_struct);
        self.add_remaining_fields(&mut debug_struct);
        debug_struct.finish()
    }
}

impl Character {
    fn add_basic_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("spec", &self.spec)
            .field("spec_version", &self.spec_version)
            .field("name", &"[REDACTED]");
    }

    fn add_encrypted_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field(
                "description",
                &self.description.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "personality",
                &self.personality.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "scenario",
                &self.scenario.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "first_mes",
                &self.first_mes.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "mes_example",
                &self.mes_example.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "creator_notes",
                &self.creator_notes.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "post_history_instructions",
                &self
                    .post_history_instructions
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            );
    }

    fn add_metadata_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field("tags", &self.tags.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("creator", &self.creator.as_ref().map(|_| "[REDACTED]"))
            .field("character_version", &self.character_version)
            .field(
                "alternate_greetings",
                &self.alternate_greetings.as_ref().map(|_| "[REDACTED_LIST]"),
            )
            .field("nickname", &self.nickname.as_ref().map(|_| "[REDACTED]"))
            .field(
                "creator_notes_multilingual",
                &self
                    .creator_notes_multilingual
                    .as_ref()
                    .map(|_| "[REDACTED_JSON]"),
            )
            .field("source", &self.source.as_ref().map(|_| "[REDACTED_LIST]"))
            .field(
                "group_only_greetings",
                &self
                    .group_only_greetings
                    .as_ref()
                    .map(|_| "[REDACTED_LIST]"),
            )
            .field("creation_date", &self.creation_date)
            .field("modification_date", &self.modification_date)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at);
    }

    fn add_remaining_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        self.add_more_encrypted_fields(debug_struct);
        self.add_visibility_and_settings_fields(debug_struct);
        self.add_nonce_fields(debug_struct);
    }

    fn add_more_encrypted_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field(
                "persona",
                &self.persona.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "world_scenario",
                &self.world_scenario.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field("avatar", &self.avatar.as_ref().map(|_| "[REDACTED]"))
            .field("chat", &self.chat.as_ref().map(|_| "[REDACTED]"))
            .field(
                "greeting",
                &self.greeting.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "definition",
                &self.definition.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "example_dialogue",
                &self.example_dialogue.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "model_prompt",
                &self.model_prompt.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "user_persona",
                &self.user_persona.as_ref().map(|_| "[REDACTED_BYTES]"),
            );
    }

    fn add_visibility_and_settings_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field("default_voice", &self.default_voice)
            .field(
                "extensions",
                &self.extensions.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .field("data_id", &self.data_id)
            .field("category", &self.category)
            .field("definition_visibility", &self.definition_visibility)
            .field("depth", &self.depth)
            .field("favorite", &self.favorite)
            .field("first_message_visibility", &self.first_message_visibility)
            .field("height", &self.height)
            .field("last_activity", &self.last_activity)
            .field("migrated_from", &self.migrated_from)
            .field("model_prompt_visibility", &self.model_prompt_visibility)
            .field("model_temperature", &self.model_temperature)
            .field("num_interactions", &self.num_interactions)
            .field("permanence", &self.permanence)
            .field("persona_visibility", &self.persona_visibility)
            .field("revision", &self.revision)
            .field("sharing_visibility", &self.sharing_visibility)
            .field("status", &self.status)
            .field("system_prompt_visibility", &self.system_prompt_visibility)
            .field(
                "system_tags",
                &self.system_tags.as_ref().map(|_| "[REDACTED_LIST]"),
            )
            .field("token_budget", &self.token_budget)
            .field(
                "usage_hints",
                &self.usage_hints.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .field("user_persona_visibility", &self.user_persona_visibility)
            .field("visibility", &self.visibility)
            .field("weight", &self.weight)
            .field("world_scenario_visibility", &self.world_scenario_visibility);
    }

    fn add_nonce_fields(&self, debug_struct: &mut std::fmt::DebugStruct<'_, '_>) {
        debug_struct
            .field(
                "description_nonce",
                &self.description_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "personality_nonce",
                &self.personality_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "scenario_nonce",
                &self.scenario_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "first_mes_nonce",
                &self.first_mes_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "mes_example_nonce",
                &self.mes_example_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "creator_notes_nonce",
                &self
                    .creator_notes_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "system_prompt_nonce",
                &self
                    .system_prompt_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "persona_nonce",
                &self.persona_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "world_scenario_nonce",
                &self
                    .world_scenario_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "greeting_nonce",
                &self.greeting_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "definition_nonce",
                &self.definition_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "example_dialogue_nonce",
                &self
                    .example_dialogue_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "model_prompt_nonce",
                &self.model_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "user_persona_nonce",
                &self.user_persona_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "post_history_instructions_nonce",
                &self
                    .post_history_instructions_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field("fav", &self.fav)
            .field("world", &self.world.as_ref().map(|_| "[REDACTED]"))
            .field(
                "creator_comment",
                &self.creator_comment.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "creator_comment_nonce",
                &self
                    .creator_comment_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "depth_prompt",
                &self.depth_prompt.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field("depth_prompt_depth", &self.depth_prompt_depth)
            .field(
                "depth_prompt_role",
                &self.depth_prompt_role.as_ref().map(|_| "[REDACTED]"),
            )
            .field("talkativeness", &self.talkativeness)
            .field(
                "depth_prompt_ciphertext",
                &self
                    .depth_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "depth_prompt_nonce",
                &self.depth_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "world_ciphertext",
                &self.world_ciphertext.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "world_nonce",
                &self.world_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            );
    }
}

impl Character {
    /// Encrypts the description field if plaintext is provided and a DEK is available.
    /// Updates `self.description` and `self.description_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_description_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_opt: Option<String>,
    ) -> Result<(), AppError> {
        match plaintext_opt {
            Some(plaintext) if !plaintext.is_empty() => {
                let (ciphertext, nonce) = crate::crypto::encrypt_gcm(plaintext.as_bytes(), dek)
                    .map_err(|e| {
                        AppError::EncryptionError(format!("Failed to encrypt description: {e}"))
                    })?;
                self.description = Some(ciphertext);
                self.description_nonce = Some(nonce);
            }
            _ => {
                // If plaintext is None or empty, clear the encrypted fields
                self.description = None;
                self.description_nonce = None;
            }
        }
        Ok(())
    }

    /// Convert this Character into a json-friendly `ClientCharacter` response
    /// If DEK is available, decrypt encrypted fields
    ///
    /// # Errors
    /// Returns `AppError` if decryption fails or character parsing fails
    pub fn into_client_character(
        self,
        dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ClientCharacter, AppError> {
        let encryption_service = EncryptionService; // Instantiate service

        let mut client_char = ClientCharacter {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            description: String::new(), // Will be populated below
            concept: self.spec.clone(),
            // Get system_prompt if available, otherwise empty string
            voice_instructions: String::new(), // Will populate below
            created_at: self.created_at,
            updated_at: self.updated_at,
            is_favorite: self.favorite.unwrap_or(false),
            category: self.category.clone().unwrap_or_default(),
            chat_history_limit: self.token_budget.unwrap_or(100),
            system_prompt: String::new(), // Will populate below
            avatar_id: None,              // Will try to convert from self.avatar
        };

        // Attempt to convert avatar string to UUID if present
        if let Some(avatar_str) = &self.avatar {
            if let Ok(uuid) = Uuid::parse_str(avatar_str) {
                client_char.avatar_id = Some(uuid);
            }
        }

        // Decrypt system_prompt if available
        if let (Some(dek_val), Some(system_prompt_data), Some(system_prompt_nonce_val)) =
            (dek, &self.system_prompt, &self.system_prompt_nonce)
        {
            if !system_prompt_data.is_empty() {
                let decrypted_bytes = encryption_service
                    .decrypt(
                        system_prompt_data,
                        system_prompt_nonce_val,
                        dek_val.expose_secret(),
                    )
                    .map_err(|e| {
                        AppError::EncryptionError(format!("Failed to decrypt system_prompt: {e}"))
                    })?;

                client_char.system_prompt = String::from_utf8(decrypted_bytes).map_err(|e| {
                    AppError::EncryptionError(format!(
                        "Invalid UTF-8 in decrypted system_prompt: {e}"
                    ))
                })?;
            }
        } else if let Some(_system_prompt) = &self.system_prompt {
            // If no DEK but we have system prompt, show encrypted placeholder
            client_char.system_prompt = "[Encrypted]".to_string();
        }

        // Use voice_instructions or persona for client's voice_instructions
        if let (Some(dek_val), Some(voice_data), Some(voice_nonce)) =
            (dek, &self.persona, &self.persona_nonce)
        {
            if !voice_data.is_empty() {
                let decrypted_bytes = encryption_service
                    .decrypt(voice_data, voice_nonce, dek_val.expose_secret())
                    .map_err(|e| {
                        AppError::EncryptionError(format!("Failed to decrypt voice data: {e}"))
                    })?;

                client_char.voice_instructions =
                    String::from_utf8(decrypted_bytes).map_err(|e| {
                        AppError::EncryptionError(format!(
                            "Invalid UTF-8 in decrypted voice data: {e}"
                        ))
                    })?;
            }
        } else if let Some(_voice_data) = &self.persona {
            // Check if persona data exists even if no DEK
            client_char.voice_instructions = "[Encrypted]".to_string();
        } else {
            // Default voice instructions if no persona data at all
            client_char.voice_instructions = "Default voice settings".to_string();
        }

        // Only try to decrypt description if we have both encrypted data, a nonce, and the DEK
        if let (Some(dek_val), Some(nonce_val), Some(description_data)) =
            (dek, &self.description_nonce, &self.description)
        {
            if !description_data.is_empty() {
                // Decrypt the description field
                let decrypted_bytes = encryption_service
                    .decrypt(description_data, nonce_val, dek_val.expose_secret())
                    .map_err(|e| {
                        AppError::EncryptionError(format!("Failed to decrypt description: {e}"))
                    })?;

                // Convert bytes to UTF-8 string
                let decrypted_text = String::from_utf8(decrypted_bytes).map_err(|e| {
                    AppError::EncryptionError(format!(
                        "Invalid UTF-8 in decrypted description: {e}"
                    ))
                })?;

                client_char.description = decrypted_text;
            }
        } else if self.description.is_some() {
            // Check only if description data exists
            // If data exists but we couldn't decrypt (either missing DEK or missing nonce), show placeholder
            client_char.description = "[Encrypted]".to_string();
        } else {
            // If no data or no nonce, leave as empty or default (already initialized)
            // client_char.description is already String::new()
        }

        Ok(client_char)
    }
}

#[derive(Debug)]
struct DecryptedCharacterFields {
    description: Option<String>,
    personality: Option<String>,
    scenario: Option<String>,
    first_mes: Option<String>,
    mes_example: Option<String>,
    creator_notes: Option<String>,
    system_prompt: Option<String>,
    post_history_instructions: Option<String>,
    persona: Option<String>,
    world_scenario: Option<String>,
    greeting: Option<String>,
    definition: Option<String>,
    example_dialogue: Option<String>,
    model_prompt: Option<String>,
    user_persona: Option<String>,
    creator_comment: Option<String>,
    depth_prompt: Option<String>,
    world: Option<String>,
}

impl Character {
    /// Convert this Character into a `CharacterDataForClient` response
    /// This is similar to `into_client_character` but with a more detailed output format
    ///
    /// # Errors
    /// Returns `AppError` if decryption fails or character parsing fails
    pub fn into_decrypted_for_client(
        self,
        dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<CharacterDataForClient, AppError> {
        let decrypted_fields = self.decrypt_character_fields(dek)?;
        Ok(self.build_client_character(decrypted_fields))
    }

    fn decrypt_character_fields(
        &self,
        dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<DecryptedCharacterFields, AppError> {
        let encryption_service = EncryptionService;

        Ok(DecryptedCharacterFields {
            description: Self::decrypt_field(
                self.description.as_ref(),
                self.description_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            personality: Self::decrypt_field(
                self.personality.as_ref(),
                self.personality_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            scenario: Self::decrypt_field(
                self.scenario.as_ref(),
                self.scenario_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            first_mes: Self::decrypt_field(
                self.first_mes.as_ref(),
                self.first_mes_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            mes_example: Self::decrypt_field(
                self.mes_example.as_ref(),
                self.mes_example_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            creator_notes: Self::decrypt_field(
                self.creator_notes.as_ref(),
                self.creator_notes_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            system_prompt: Self::decrypt_field(
                self.system_prompt.as_ref(),
                self.system_prompt_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            post_history_instructions: Self::decrypt_field(
                self.post_history_instructions.as_ref(),
                self.post_history_instructions_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            persona: Self::decrypt_field(
                self.persona.as_ref(),
                self.persona_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            world_scenario: Self::decrypt_field(
                self.world_scenario.as_ref(),
                self.world_scenario_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            greeting: Self::decrypt_field(
                self.greeting.as_ref(),
                self.greeting_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            definition: Self::decrypt_field(
                self.definition.as_ref(),
                self.definition_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            example_dialogue: Self::decrypt_field(
                self.example_dialogue.as_ref(),
                self.example_dialogue_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            model_prompt: Self::decrypt_field(
                self.model_prompt.as_ref(),
                self.model_prompt_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            user_persona: Self::decrypt_field(
                self.user_persona.as_ref(),
                self.user_persona_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            creator_comment: Self::decrypt_field(
                self.creator_comment.as_ref(),
                self.creator_comment_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            depth_prompt: Self::decrypt_field(
                self.depth_prompt_ciphertext.as_ref(),
                self.depth_prompt_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
            world: Self::decrypt_field(
                self.world_ciphertext.as_ref(),
                self.world_nonce.as_ref(),
                dek,
                &encryption_service,
            )?,
        })
    }

    fn decrypt_field(
        data: Option<&Vec<u8>>,
        nonce: Option<&Vec<u8>>,
        dek: Option<&SecretBox<Vec<u8>>>,
        encryption_service: &EncryptionService,
    ) -> Result<Option<String>, AppError> {
        match (data, nonce, dek) {
            (Some(data), Some(nonce), Some(dek_val)) if !data.is_empty() => {
                let decrypted_bytes =
                    encryption_service.decrypt(data, nonce, dek_val.expose_secret())?;
                let decrypted_string = String::from_utf8(decrypted_bytes).map_err(|e| {
                    AppError::EncryptionError(format!("Invalid UTF-8 for field: {e}"))
                })?;
                Ok(if decrypted_string.is_empty() {
                    Some(String::new())
                } else {
                    Some(decrypted_string)
                })
            }
            (Some(data), Some(_), None) if !data.is_empty() => Ok(Some("[Encrypted]".to_string())),
            _ => Ok(Some(String::new())),
        }
    }

    fn build_client_character(
        self,
        decrypted_fields: DecryptedCharacterFields,
    ) -> CharacterDataForClient {
        let default_empty_string_if_none =
            |opt: Option<String>| -> Option<String> { opt.or_else(|| Some(String::new())) };

        CharacterDataForClient {
            id: self.id,
            user_id: self.user_id,
            spec: self.spec,
            spec_version: self.spec_version,
            name: self.name,
            description: decrypted_fields.description,
            personality: decrypted_fields.personality,
            scenario: decrypted_fields.scenario,
            first_mes: decrypted_fields.first_mes,
            mes_example: decrypted_fields.mes_example,
            creator_notes: decrypted_fields.creator_notes,
            system_prompt: decrypted_fields.system_prompt,
            post_history_instructions: decrypted_fields.post_history_instructions,
            tags: self.tags.or_else(|| Some(Vec::new())),
            creator: default_empty_string_if_none(self.creator),
            character_version: default_empty_string_if_none(self.character_version),
            alternate_greetings: self
                .alternate_greetings
                .map(|greetings| {
                    greetings
                        .into_iter()
                        .filter_map(|opt_greeting| opt_greeting)
                        .collect()
                })
                .or_else(|| Some(Vec::new())),
            nickname: default_empty_string_if_none(self.nickname),
            creator_notes_multilingual: self
                .creator_notes_multilingual
                .map(Json)
                .or_else(|| Some(Json(serde_json::json!({})))),
            source: self.source.or_else(|| Some(Vec::new())),
            group_only_greetings: self.group_only_greetings.or_else(|| Some(Vec::new())),
            creation_date: self.creation_date,
            modification_date: self.modification_date,
            created_at: self.created_at,
            updated_at: self.updated_at,
            persona: decrypted_fields.persona,
            world_scenario: decrypted_fields.world_scenario,
            avatar: self.avatar.and_then(|asset_id_str| {
                asset_id_str
                    .parse::<i32>()
                    .ok()
                    .map(|asset_id| format!("/api/characters/{}/assets/{}", self.id, asset_id))
            }),
            chat: default_empty_string_if_none(self.chat),
            greeting: decrypted_fields.greeting,
            definition: decrypted_fields.definition,
            default_voice: default_empty_string_if_none(self.default_voice),
            extensions: self
                .extensions
                .map(Json)
                .or_else(|| Some(Json(serde_json::json!({})))),
            data_id: self.data_id,
            category: default_empty_string_if_none(self.category),
            definition_visibility: default_empty_string_if_none(self.definition_visibility),
            depth: self.depth,
            example_dialogue: decrypted_fields.example_dialogue,
            favorite: self.favorite,
            first_message_visibility: default_empty_string_if_none(self.first_message_visibility),
            height: self.height,
            last_activity: self.last_activity,
            migrated_from: default_empty_string_if_none(self.migrated_from),
            model_prompt: decrypted_fields.model_prompt,
            model_prompt_visibility: default_empty_string_if_none(self.model_prompt_visibility),
            model_temperature: self.model_temperature,
            num_interactions: self.num_interactions,
            permanence: self.permanence,
            persona_visibility: default_empty_string_if_none(self.persona_visibility),
            revision: self.revision,
            sharing_visibility: default_empty_string_if_none(self.sharing_visibility),
            status: default_empty_string_if_none(self.status),
            system_prompt_visibility: default_empty_string_if_none(self.system_prompt_visibility),
            system_tags: self.system_tags.or_else(|| Some(Vec::new())),
            token_budget: self.token_budget,
            usage_hints: self
                .usage_hints
                .map(Json)
                .or_else(|| Some(Json(serde_json::json!({})))),
            user_persona: decrypted_fields.user_persona,
            user_persona_visibility: default_empty_string_if_none(self.user_persona_visibility),
            visibility: default_empty_string_if_none(self.visibility),
            weight: self.weight,
            world_scenario_visibility: default_empty_string_if_none(self.world_scenario_visibility),
            fav: self.fav,
            world: self.world.or(decrypted_fields.world),
            creator_comment: decrypted_fields.creator_comment,
            depth_prompt: decrypted_fields.depth_prompt,
            depth_prompt_depth: self.depth_prompt_depth,
            depth_prompt_role: self.depth_prompt_role,
            talkativeness: self.talkativeness,
        }
    }
}

// Represents the data structure for a character when sent to the client (frontend)
// Fields that are encrypted in the DB should be String here (decrypted form).
#[derive(Serialize, Deserialize, Clone, PartialEq)] // Removed Debug
pub struct CharacterDataForClient {
    pub id: Uuid,
    pub user_id: Uuid,
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<String>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<Json<JsonValue>>,
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub persona: Option<String>,
    pub world_scenario: Option<String>,
    pub avatar: Option<String>,
    pub chat: Option<String>,
    pub greeting: Option<String>,
    pub definition: Option<String>,
    pub default_voice: Option<String>,
    pub extensions: Option<Json<JsonValue>>,
    pub data_id: Option<i32>,
    pub category: Option<String>,
    pub definition_visibility: Option<String>,
    pub depth: Option<i32>,
    pub example_dialogue: Option<String>,
    pub favorite: Option<bool>,
    pub first_message_visibility: Option<String>,
    pub height: Option<BigDecimal>,
    pub last_activity: Option<DateTime<Utc>>,
    pub migrated_from: Option<String>,
    pub model_prompt: Option<String>,
    pub model_prompt_visibility: Option<String>,
    pub model_temperature: Option<BigDecimal>,
    pub num_interactions: Option<i64>,
    pub permanence: Option<BigDecimal>,
    pub persona_visibility: Option<String>,
    pub revision: Option<i32>,
    pub sharing_visibility: Option<String>,
    pub status: Option<String>,
    pub system_prompt_visibility: Option<String>,
    pub system_tags: Option<Vec<Option<String>>>,
    pub token_budget: Option<i32>,
    pub usage_hints: Option<Json<JsonValue>>,
    pub user_persona: Option<String>,
    pub user_persona_visibility: Option<String>,
    pub visibility: Option<String>,
    pub weight: Option<BigDecimal>,
    pub world_scenario_visibility: Option<String>,
    pub fav: Option<bool>,
    pub world: Option<String>,
    pub creator_comment: Option<String>,
    pub depth_prompt: Option<String>,
    pub depth_prompt_depth: Option<i32>,
    pub depth_prompt_role: Option<String>,
    pub talkativeness: Option<BigDecimal>,
}

impl std::fmt::Debug for CharacterDataForClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterDataForClient")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("spec", &"[REDACTED]")
            .field("spec_version", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("personality", &"[REDACTED]")
            .field("scenario", &"[REDACTED]")
            .field("first_mes", &"[REDACTED]")
            .field("mes_example", &"[REDACTED]")
            .field("creator_notes", &"[REDACTED]")
            .field("system_prompt", &"[REDACTED]")
            .field("post_history_instructions", &"[REDACTED]")
            .field("tags", &"[REDACTED]")
            .field("creator", &"[REDACTED]")
            .field("character_version", &"[REDACTED]")
            .field("alternate_greetings", &"[REDACTED]")
            .field("nickname", &"[REDACTED]")
            .field("creator_notes_multilingual", &"[REDACTED]")
            .field("source", &"[REDACTED]")
            .field("group_only_greetings", &"[REDACTED]")
            .field("creation_date", &self.creation_date)
            .field("modification_date", &self.modification_date)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("persona", &"[REDACTED]")
            .field("world_scenario", &"[REDACTED]")
            .field("avatar", &"[REDACTED]")
            .field("chat", &"[REDACTED]")
            .field("greeting", &"[REDACTED]")
            .field("definition", &"[REDACTED]")
            .field("default_voice", &"[REDACTED]")
            .field("extensions", &"[REDACTED]")
            .field("data_id", &self.data_id)
            .field("category", &"[REDACTED]")
            .field("definition_visibility", &"[REDACTED]")
            .field("depth", &self.depth)
            .field("example_dialogue", &"[REDACTED]")
            .field("favorite", &self.favorite)
            .field("first_message_visibility", &"[REDACTED]")
            .field("height", &self.height)
            .field("last_activity", &self.last_activity)
            .field("migrated_from", &"[REDACTED]")
            .field("model_prompt", &"[REDACTED]")
            .field("model_prompt_visibility", &"[REDACTED]")
            .field("model_temperature", &self.model_temperature)
            .field("num_interactions", &self.num_interactions)
            .field("permanence", &self.permanence)
            .field("persona_visibility", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("sharing_visibility", &"[REDACTED]")
            .field("status", &"[REDACTED]")
            .field("system_prompt_visibility", &"[REDACTED]")
            .field("system_tags", &"[REDACTED]")
            .field("token_budget", &self.token_budget)
            .field("usage_hints", &"[REDACTED]")
            .field("user_persona", &"[REDACTED]")
            .field("user_persona_visibility", &"[REDACTED]")
            .field("visibility", &"[REDACTED]")
            .field("weight", &self.weight)
            .field("world_scenario_visibility", &"[REDACTED]")
            .field("fav", &self.fav)
            .field("world", &"[REDACTED]")
            .field("creator_comment", &"[REDACTED]")
            .field("depth_prompt", &"[REDACTED]")
            .field("depth_prompt_depth", &self.depth_prompt_depth)
            .field("depth_prompt_role", &"[REDACTED]")
            .field("talkativeness", &self.talkativeness)
            .finish()
    }
}

// Represents fields that can be updated from a parsed card
// Using Option<&'a str> allows updating only provided fields
// without allocating new Strings.
#[derive(Default)] // Removed Debug for custom impl
pub struct UpdatableCharacter<'a> {
    pub spec: Option<&'a str>,
    pub spec_version: Option<&'a str>,
    pub name: Option<&'a str>,
    pub description: Option<&'a [u8]>,
    pub personality: Option<&'a [u8]>,
    pub first_mes: Option<&'a [u8]>,
    pub mes_example: Option<&'a [u8]>,
    pub scenario: Option<&'a [u8]>,
    pub system_prompt: Option<&'a str>,
    pub creator_notes: Option<&'a str>,
    // Use Vec<&'a str> for slices of strings
    pub tags: Option<Vec<&'a str>>,
    pub creator: Option<&'a str>,
    pub character_version: Option<&'a str>,
    pub alternate_greetings: Option<Vec<&'a str>>,
    // JSON needs separate handling, maybe Option<&'a Value>?
    // pub metadata_json: Option<&'a Value>, // Correct type?
    // Map other DB fields if needed
}

impl std::fmt::Debug for UpdatableCharacter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdatableCharacter")
            .field("spec", &self.spec.map(|_| "[REDACTED]"))
            .field("spec_version", &self.spec_version.map(|_| "[REDACTED]"))
            .field("name", &self.name.map(|_| "[REDACTED]"))
            .field("description", &self.description.map(|_| "[REDACTED_BYTES]"))
            .field("personality", &self.personality.map(|_| "[REDACTED_BYTES]"))
            .field("first_mes", &self.first_mes.map(|_| "[REDACTED_BYTES]"))
            .field("mes_example", &self.mes_example.map(|_| "[REDACTED_BYTES]"))
            .field("scenario", &self.scenario.map(|_| "[REDACTED_BYTES]"))
            .field("system_prompt", &self.system_prompt.map(|_| "[REDACTED]"))
            .field("creator_notes", &self.creator_notes.map(|_| "[REDACTED]"))
            .field("tags", &self.tags.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("creator", &self.creator.map(|_| "[REDACTED]"))
            .field(
                "character_version",
                &self.character_version.map(|_| "[REDACTED]"),
            )
            .field(
                "alternate_greetings",
                &self.alternate_greetings.as_ref().map(|_| "[REDACTED_LIST]"),
            )
            .finish()
    }
}

impl<'a> From<&'a ParsedCharacterCard> for UpdatableCharacter<'a> {
    fn from(parsed_card: &'a ParsedCharacterCard) -> Self {
        match parsed_card {
            ParsedCharacterCard::V3(card_v3) => {
                // Corrected map_string helper
                let map_bytes = |s: &'a String| -> Option<&'a [u8]> {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.as_bytes())
                    }
                };
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                // Corrected map_vec helper
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(std::string::String::as_str) // Use as_str()
                        .collect(); // Compiler should infer Vec<&str>
                    if mapped.is_empty() {
                        None
                    } else {
                        Some(mapped)
                    }
                };

                Self {
                    spec: Some(&card_v3.spec),
                    spec_version: Some(&card_v3.spec_version),
                    name: card_v3.data.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_bytes(&card_v3.data.description),
                    personality: map_bytes(&card_v3.data.personality),
                    first_mes: map_bytes(&card_v3.data.first_mes),
                    mes_example: map_bytes(&card_v3.data.mes_example),
                    scenario: map_bytes(&card_v3.data.scenario),
                    system_prompt: map_string(&card_v3.data.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&card_v3.data.creator_notes),
                    tags: map_vec(&card_v3.data.tags),
                    creator: map_string(&card_v3.data.creator),
                    character_version: map_string(&card_v3.data.character_version),
                    alternate_greetings: map_vec(&card_v3.data.alternate_greetings),
                }
            }
            ParsedCharacterCard::V2Fallback(data_v2) => {
                let map_bytes = |s: &'a String| -> Option<&'a [u8]> {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.as_bytes())
                    }
                };
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(std::string::String::as_str) // Use as_str()
                        .collect();
                    if mapped.is_empty() {
                        None
                    } else {
                        Some(mapped)
                    }
                };

                Self {
                    spec: None,
                    spec_version: None,
                    name: data_v2.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_bytes(&data_v2.description),
                    personality: map_bytes(&data_v2.personality),
                    first_mes: map_bytes(&data_v2.first_mes),
                    mes_example: map_bytes(&data_v2.mes_example),
                    scenario: map_bytes(&data_v2.scenario),
                    system_prompt: map_string(&data_v2.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&data_v2.creator_notes),
                    tags: map_vec(&data_v2.tags),
                    creator: map_string(&data_v2.creator),
                    character_version: map_string(&data_v2.character_version),
                    alternate_greetings: map_vec(&data_v2.alternate_greetings),
                }
            }
        }
    }
}

// Represents the core metadata of a character, stored in the DB
#[derive(Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Clone)] // Removed Debug
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = characters)]
pub struct CharacterMetadata {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<Vec<u8>>,
    pub description_nonce: Option<Vec<u8>>,
    pub personality: Option<Vec<u8>>,
    pub personality_nonce: Option<Vec<u8>>,
    pub scenario: Option<Vec<u8>>,
    pub scenario_nonce: Option<Vec<u8>>,
    pub mes_example: Option<Vec<u8>>,
    pub mes_example_nonce: Option<Vec<u8>>,
    pub creator_comment: Option<Vec<u8>>,
    pub creator_comment_nonce: Option<Vec<u8>>,
    pub first_mes: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for CharacterMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterMetadata")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &"[REDACTED]")
            .field(
                "description",
                &self.description.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "description_nonce",
                &self.description_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "first_mes",
                &self.first_mes.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl CharacterMetadata {
    /// Decrypt the description field if available
    ///
    /// # Errors
    /// Returns `AppError` if decryption fails
    pub fn decrypt_description(
        &self,
        dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<Option<String>, AppError> {
        match (dek, &self.description, &self.description_nonce) {
            (Some(dek_val), Some(description_data), Some(nonce_val)) => {
                if description_data.is_empty() {
                    return Ok(Some(String::new()));
                }

                let encryption_service = EncryptionService;
                let decrypted_bytes = encryption_service
                    .decrypt(description_data, nonce_val, dek_val.expose_secret())
                    .map_err(|e| {
                        AppError::EncryptionError(format!(
                            "Failed to decrypt character description: {e}"
                        ))
                    })?;

                let decrypted_text = String::from_utf8(decrypted_bytes).map_err(|e| {
                    AppError::EncryptionError(format!(
                        "Invalid UTF-8 in decrypted character description: {e}"
                    ))
                })?;

                Ok(Some(decrypted_text))
            }
            (None, Some(_), Some(_)) => {
                // Encrypted data exists but no DEK provided
                Ok(Some("[Encrypted - DEK not available]".to_string()))
            }
            _ => {
                // No description data or missing components
                Ok(None)
            }
        }
    }
}

// Helper function to create a dummy Character instance
#[must_use]
pub fn create_dummy_character() -> Character {
    // Made pub for potential use in other tests
    let now = Utc::now();
    let user_uuid = Uuid::new_v4();
    Character {
        id: Uuid::new_v4(),
        user_id: user_uuid,
        spec: "chara_card_v3_spec".to_string(),
        spec_version: "1.0.0".to_string(),
        name: "Dummy Character".to_string(),
        description: None,
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
        created_at: now,
        updated_at: now,
        persona: None,
        world_scenario: None,
        avatar: None,
        chat: None,
        greeting: None,
        definition: None,
        default_voice: None,
        extensions: None,
        data_id: None,
        category: None,
        definition_visibility: None,
        depth: None,
        example_dialogue: None,
        favorite: None,
        first_message_visibility: None,
        height: None,
        last_activity: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        model_temperature: None,
        num_interactions: None,
        permanence: None,
        persona_visibility: None,
        revision: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        visibility: None,
        weight: None,
        world_scenario_visibility: None,
        description_nonce: None,
        personality_nonce: None,
        scenario_nonce: None,
        first_mes_nonce: None,
        mes_example_nonce: None,
        creator_notes_nonce: None,
        system_prompt_nonce: None,
        persona_nonce: None,
        world_scenario_nonce: None,
        greeting_nonce: None,
        definition_nonce: None,
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        post_history_instructions_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    }
}

// Client-side Character representation (for JSON responses)
#[derive(Serialize, Deserialize, Clone)] // Removed Debug
pub struct ClientCharacter {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: String,
    pub concept: String,
    pub voice_instructions: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_favorite: bool,
    pub category: String,
    pub chat_history_limit: i32,
    pub system_prompt: String,
    pub avatar_id: Option<Uuid>,
}

impl std::fmt::Debug for ClientCharacter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCharacter")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("concept", &"[REDACTED]") // Assuming concept might contain sensitive user input
            .field("voice_instructions", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("is_favorite", &self.is_favorite)
            .field("category", &self.category) // Category is likely non-sensitive
            .field("chat_history_limit", &self.chat_history_limit)
            .field("system_prompt", &"[REDACTED]")
            .field("avatar_id", &self.avatar_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::character_card::{CharacterCardDataV3, CharacterCardV3};
    use crate::services::character_parser::ParsedCharacterCard;
    use ring::rand::{SecureRandom, SystemRandom};
    use secrecy::SecretBox; // For testing encryption/decryption - Corrected import // For generating a dummy DEK
    use std::collections::HashMap;

    // Helper function to generate a dummy DEK for testing
    fn generate_dummy_dek() -> SecretBox<Vec<u8>> {
        // Corrected return type
        let mut key_bytes = vec![0u8; 32]; // AES-256-GCM needs a 32-byte key
        let rng = SystemRandom::new();
        rng.fill(&mut key_bytes).unwrap();
        SecretBox::new(Box::new(key_bytes))
    }

    #[test]
    fn test_character_debug() {
        let character = create_dummy_character();
        let debug_output = format!("{character:?}");
        assert!(debug_output.contains("name: \"[REDACTED]\""));
        assert!(debug_output.starts_with("Character {"));
        assert!(debug_output.ends_with('}'));
    }

    #[test]
    fn test_character_clone() {
        let character1 = create_dummy_character();
        let character1_clone = &character1;

        // Verify they are identical after cloning
        assert_eq!(character1.id, character1_clone.id);
        assert_eq!(character1.name, character1_clone.name);
        assert_eq!(character1.name, "Dummy Character");
    }

    #[tokio::test]
    async fn test_description_encryption_and_decryption_via_client_conversion() {
        let mut character = create_dummy_character();
        let dek = generate_dummy_dek();
        let original_description = "This is a secret description.".to_string();

        // Encrypt the description
        character
            .encrypt_description_field(&dek, Some(original_description.clone()))
            .unwrap();

        // Check that description and nonce are Some
        assert!(character.description.is_some());
        assert!(character.description_nonce.is_some());

        // Convert to ClientCharacter with DEK
        let client_char = character.clone().into_client_character(Some(&dek)).unwrap();
        assert_eq!(client_char.description, original_description);

        // Test with empty description
        let mut char_empty_desc = create_dummy_character();
        char_empty_desc
            .encrypt_description_field(&dek, Some(String::new()))
            .unwrap();
        assert!(char_empty_desc.description.is_none()); // Empty string leads to None
        assert!(char_empty_desc.description_nonce.is_none());
        let client_empty_desc = char_empty_desc.into_client_character(Some(&dek)).unwrap();
        assert_eq!(client_empty_desc.description, "");

        // Test with inconsistent nonce (simulated by no nonce)
        let mut char_inconsistent_nonce = create_dummy_character();
        char_inconsistent_nonce
            .encrypt_description_field(&dek, Some("data".to_string()))
            .unwrap();
        char_inconsistent_nonce.description_nonce = None; // Simulate missing nonce
        let client_inconsistent_nonce = char_inconsistent_nonce
            .clone()
            .into_client_character(Some(&dek))
            .unwrap();
        // Expect placeholder because decryption should fail or be skipped due to missing nonce
        assert_eq!(client_inconsistent_nonce.description, "[Encrypted]");

        // Test with None description (after encryption was for Some(""))
        let mut char_none_desc = create_dummy_character();
        char_none_desc
            .encrypt_description_field(&dek, Some(String::new()))
            .unwrap(); // Clears fields
        let client_none_desc = char_none_desc.into_client_character(Some(&dek)).unwrap();
        assert_eq!(client_none_desc.description, ""); // Should be empty string

        // Convert to ClientCharacter without DEK
        let mut char_no_dek = create_dummy_character();
        char_no_dek
            .encrypt_description_field(&dek, Some(original_description))
            .unwrap();
        let client_no_dek = char_no_dek.into_client_character(None).unwrap();
        assert_eq!(client_no_dek.description, "[Encrypted]");

        // Test with no description data at all
        let char_no_desc = create_dummy_character(); // description and nonce are None by default
        let client_data_no_desc = char_no_desc
            .clone()
            .into_decrypted_for_client(Some(&dek))
            .unwrap();
        // Print out the actual value for debugging
        println!("Description value: {:?}", client_data_no_desc.description);
        assert_eq!(client_data_no_desc.description, Some(String::new())); // Expect Some("") instead of None
        let client_data_no_desc_no_dek = char_no_desc.into_decrypted_for_client(None).unwrap();
        assert_eq!(client_data_no_desc_no_dek.description, Some(String::new())); // Expect Some("") instead of None
    }

    #[tokio::test]
    async fn test_into_decrypted_for_client() {
        let mut character = create_dummy_character();
        let dek = generate_dummy_dek();
        let original_description = "Test Description".to_string();
        let original_persona = "Test Persona".to_string();

        // Encrypt some fields directly for testing (as encrypt_field! macro would)
        let (desc_ct, desc_n) =
            crate::crypto::encrypt_gcm(original_description.as_bytes(), &dek).unwrap();
        character.description = Some(desc_ct);
        character.description_nonce = Some(desc_n);

        let (pers_ct, pers_n) =
            crate::crypto::encrypt_gcm(original_persona.as_bytes(), &dek).unwrap();
        character.persona = Some(pers_ct);
        character.persona_nonce = Some(pers_n);

        // With DEK
        let client_data_with_dek = character
            .clone()
            .into_decrypted_for_client(Some(&dek))
            .unwrap();
        assert_eq!(
            client_data_with_dek.description.as_deref(),
            Some(original_description.as_str())
        );
        assert_eq!(
            client_data_with_dek.persona.as_deref(),
            Some(original_persona.as_str())
        );

        // Without DEK
        let client_data_without_dek = character.into_decrypted_for_client(None).unwrap();
        assert_eq!(
            client_data_without_dek.description.as_deref(),
            Some("[Encrypted]")
        );
        assert_eq!(
            client_data_without_dek.persona.as_deref(),
            Some("[Encrypted]")
        );

        // Test with no description data (should be None)
        let char_no_desc = create_dummy_character(); // description and nonce are None by default
        let client_data_no_desc = char_no_desc
            .clone()
            .into_decrypted_for_client(Some(&dek))
            .unwrap();
        // Print out the actual value for debugging
        println!("Description value: {:?}", client_data_no_desc.description);
        assert_eq!(client_data_no_desc.description, Some(String::new())); // Expect Some("") instead of None
        let client_data_no_desc_no_dek = char_no_desc.into_decrypted_for_client(None).unwrap();
        assert_eq!(client_data_no_desc_no_dek.description, Some(String::new())); // Expect Some("") instead of None
    }

    // Helper function to create a dummy V3 card
    fn create_dummy_v3_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V3(CharacterCardV3 {
            spec: "chara_card_v3_spec".to_string(),
            spec_version: "1.0.0".to_string(),
            data: CharacterCardDataV3 {
                name: Some("Test V3 Name".to_string()),
                description: "V3 Description".to_string(),
                personality: String::new(), // Empty string
                first_mes: "V3 First Message".to_string(),
                mes_example: "V3 Example".to_string(),
                scenario: String::new(),
                system_prompt: "V3 System".to_string(),
                creator_notes: "V3 Creator Notes".to_string(),
                tags: vec!["tag1".to_string(), String::new(), "tag3".to_string()], // Include empty tag
                creator: "V3 Creator".to_string(),
                character_version: "v1.2".to_string(),
                alternate_greetings: vec!["Hi".to_string(), "Hello".to_string()],
                // Explicitly add missing fields with default values
                post_history_instructions: String::default(),
                character_book: None,
                assets: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: Vec::default(),
                creation_date: None,
                modification_date: None,
                extensions: HashMap::default(), // Keep extensions
            },
            ..Default::default()
        })
    }

    // Helper function to create a dummy V2 card
    fn create_dummy_v2_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V2Fallback(CharacterCardDataV3 {
            // V2 uses the V3 data struct as fallback
            name: Some("Test V2 Name".to_string()),
            description: "V2 Description".to_string(),
            personality: "V2 Personality".to_string(),
            first_mes: String::new(), // Empty string
            mes_example: "V2 Example".to_string(),
            scenario: "V2 Scenario".to_string(),
            system_prompt: String::new(),
            creator_notes: "V2 Creator Notes".to_string(),
            tags: vec!["v2tag1".to_string()],
            creator: "V2 Creator".to_string(),
            character_version: "v1.1".to_string(),
            alternate_greetings: vec![], // Empty vec
            // Fields specific to V2 or common fields used as fallback
            // These fields aren't part of CharacterCardDataV3 struct, so remove them or handle differently if needed
            // greeting: Some("V2 Greeting".to_string()),
            // avatar: Some("v2_avatar.png".to_string()),
            // chat: None,
            // ... other V2 fields if they exist in the struct
            ..Default::default() // Use default for remaining fields in CharacterCardDataV3
        })
    }

    #[test]
    fn test_updatable_character_from_v3_card() {
        let v3_card = create_dummy_v3_card();
        let updatable = UpdatableCharacter::from(&v3_card);

        assert_eq!(updatable.spec, Some("chara_card_v3_spec"));
        assert_eq!(updatable.spec_version, Some("1.0.0"));
        assert_eq!(updatable.name, Some("Test V3 Name"));
        assert_eq!(updatable.description, Some(b"V3 Description" as &[u8]));
        assert_eq!(updatable.personality, None); // Empty string maps to None
        assert_eq!(updatable.first_mes, Some(b"V3 First Message" as &[u8]));
        assert_eq!(updatable.mes_example, Some(b"V3 Example" as &[u8]));
        assert_eq!(updatable.scenario, None); // Empty string maps to None
        assert_eq!(updatable.system_prompt, Some("V3 System"));
        assert_eq!(updatable.creator_notes, Some("V3 Creator Notes"));
        assert_eq!(updatable.tags, Some(vec!["tag1", "tag3"])); // Empty tag is filtered out
        assert_eq!(updatable.creator, Some("V3 Creator"));
        assert_eq!(updatable.character_version, Some("v1.2"));
        assert_eq!(updatable.alternate_greetings, Some(vec!["Hi", "Hello"]));
    }

    #[test]
    fn test_updatable_character_from_v2_card() {
        let v2_card = create_dummy_v2_card();
        let updatable = UpdatableCharacter::from(&v2_card);

        assert_eq!(updatable.spec, None); // No spec in V2
        assert_eq!(updatable.spec_version, None); // No spec_version in V2
        assert_eq!(updatable.name, Some("Test V2 Name"));
        assert_eq!(updatable.description, Some(b"V2 Description" as &[u8]));
        assert_eq!(updatable.personality, Some(b"V2 Personality" as &[u8]));
        assert_eq!(updatable.first_mes, None); // Empty string maps to None
        assert_eq!(updatable.mes_example, Some(b"V2 Example" as &[u8]));
        assert_eq!(updatable.scenario, Some(b"V2 Scenario" as &[u8]));
        assert_eq!(updatable.system_prompt, None); // Empty string maps to None
        assert_eq!(updatable.creator_notes, Some("V2 Creator Notes"));
        assert_eq!(updatable.tags, Some(vec!["v2tag1"]));
        assert_eq!(updatable.creator, Some("V2 Creator"));
        assert_eq!(updatable.character_version, Some("v1.1"));
        assert_eq!(updatable.alternate_greetings, None); // Empty vec maps to None
    }

    #[test]
    fn test_character_metadata_serde() {
        let dt = Utc::now();
        let uuid = Uuid::new_v4();
        let user_uuid = Uuid::new_v4();

        let metadata = CharacterMetadata {
            id: uuid,
            user_id: user_uuid,
            name: "Test Character".to_string(),
            description: Some(b"A test description".to_vec()),
            description_nonce: None,
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
            first_mes: None,
            created_at: dt,
            updated_at: dt,
        };

        // Serialize
        let json_string = serde_json::to_string(&metadata).expect("Serialization failed");
        println!("Serialized JSON: {json_string}"); // Optional: print for debugging

        // Deserialize
        let deserialized_metadata: CharacterMetadata =
            serde_json::from_str(&json_string).expect("Deserialization failed");

        // Assert equality (Direct comparison should work due to Clone, PartialEq)
        assert_eq!(metadata.id, deserialized_metadata.id);
        assert_eq!(metadata.user_id, deserialized_metadata.user_id);
        assert_eq!(metadata.name, deserialized_metadata.name);
        assert_eq!(metadata.description, deserialized_metadata.description);
        assert_eq!(metadata.first_mes, deserialized_metadata.first_mes);
        // Note: Comparing DateTime<Utc> directly might be flaky due to precision differences
        // after serialization/deserialization. Comparing timestamps is safer.
        assert_eq!(
            metadata.created_at.timestamp_millis(),
            deserialized_metadata.created_at.timestamp_millis()
        );
        assert_eq!(
            metadata.updated_at.timestamp_millis(),
            deserialized_metadata.updated_at.timestamp_millis()
        );
    }
}
