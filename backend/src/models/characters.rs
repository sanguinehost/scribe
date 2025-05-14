// backend/src/models/characters.rs
#![allow(dead_code)] // Allow dead code for fields not yet actively used
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use bigdecimal::BigDecimal;
use diesel_json::Json;
use secrecy::{ExposeSecret, SecretBox}; // Corrected: SecretVec -> SecretBox
use crate::errors::AppError; // For error handling

use crate::models::users::User;
use crate::schema::characters;
use crate::services::character_parser::ParsedCharacterCard;
// For encryption/decryption
// use crate::crypto::decrypt_gcm; // Will be replaced by EncryptionService
use crate::services::encryption_service::EncryptionService; // Added

#[derive(
    Queryable, Selectable, Identifiable, Associations, Insertable, Serialize, Deserialize, Debug, Clone, PartialEq,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = crate::schema::characters)]
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
}

impl Character {
    /// Encrypts the description field if plaintext is provided and a DEK is available.
    /// Updates self.description and self.description_nonce.
    pub fn encrypt_description_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_opt: Option<String>,
    ) -> Result<(), AppError> {
        match plaintext_opt {
            Some(plaintext) if !plaintext.is_empty() => {
                let (ciphertext, nonce) = crate::crypto::encrypt_gcm(plaintext.as_bytes(), dek)
                    .map_err(|e| AppError::EncryptionError(format!("Failed to encrypt description: {}", e)))?;
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

    /// Convert this Character into a json-friendly ClientCharacter response
    /// If DEK is available, decrypt encrypted fields
    pub async fn into_client_character(self, dek: Option<&SecretBox<Vec<u8>>>) -> Result<ClientCharacter, AppError> {
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
            avatar_id: None, // Will try to convert from self.avatar
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
                    .decrypt(system_prompt_data, system_prompt_nonce_val, dek_val.expose_secret())
                    .await
                    .map_err(|e| AppError::EncryptionError(format!("Failed to decrypt system_prompt: {}", e)))?;
                
                client_char.system_prompt = String::from_utf8(decrypted_bytes)
                    .map_err(|e| AppError::EncryptionError(format!("Invalid UTF-8 in decrypted system_prompt: {}", e)))?;
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
                    .await
                    .map_err(|e| AppError::EncryptionError(format!("Failed to decrypt voice data: {}", e)))?;
                
                client_char.voice_instructions = String::from_utf8(decrypted_bytes)
                    .map_err(|e| AppError::EncryptionError(format!("Invalid UTF-8 in decrypted voice data: {}", e)))?;
            }
        } else if let Some(_voice_data) = &self.persona { // Check if persona data exists even if no DEK
             client_char.voice_instructions = "[Encrypted]".to_string();
        } else {
            // Default voice instructions if no persona data at all
            client_char.voice_instructions = "Default voice settings".to_string();
        }

        // Only try to decrypt description if we have both encrypted data, a nonce, and the DEK
        if let (Some(dek_val), Some(nonce_val), Some(description_data)) = (dek, &self.description_nonce, &self.description) {
            if !description_data.is_empty() {
                // Decrypt the description field
                let decrypted_bytes = encryption_service
                    .decrypt(description_data, nonce_val, dek_val.expose_secret())
                    .await
                    .map_err(|e| AppError::EncryptionError(format!("Failed to decrypt description: {}", e)))?;

                // Convert bytes to UTF-8 string
                let decrypted_text = String::from_utf8(decrypted_bytes)
                    .map_err(|e| AppError::EncryptionError(format!("Invalid UTF-8 in decrypted description: {}", e)))?;
                
                client_char.description = decrypted_text;
            }
        } else if self.description.is_some() { // Check only if description data exists
             // If data exists but we couldn't decrypt (either missing DEK or missing nonce), show placeholder
            client_char.description = "[Encrypted]".to_string();
        } else {
            // If no data or no nonce, leave as empty or default (already initialized)
            // client_char.description is already String::new()
        }

        Ok(client_char)
    }

    /// Convert this Character into a CharacterDataForClient response
    /// This is similar to into_client_character but with a more detailed output format
    pub async fn into_decrypted_for_client(self, dek: Option<&SecretBox<Vec<u8>>>) -> Result<CharacterDataForClient, AppError> {
        let encryption_service = EncryptionService; // Instantiate service

        // Helper macro to reduce boilerplate for decryption
        macro_rules! decrypt_field {
            ($self_field:expr, $self_nonce:expr, $dek_opt:expr) => {
                match ($self_field, $self_nonce, $dek_opt) {
                    (Some(data), Some(nonce), Some(dek_val)) if !data.is_empty() => {
                        let decrypted_bytes_res = encryption_service
                            .decrypt(data, nonce, dek_val.expose_secret())
                            .await;
                        match decrypted_bytes_res {
                            Ok(decrypted_bytes) => {
                                String::from_utf8(decrypted_bytes)
                                    .map(Some)
                                    .map_err(|e| AppError::EncryptionError(format!("Invalid UTF-8 for field: {}", e)))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    (Some(data), Some(_), None) if !data.is_empty() => Ok(Some("[Encrypted]".to_string())),
                    _ => Ok(None),
                }
            };
        }

        let client_char = CharacterDataForClient {
            id: self.id,
            user_id: self.user_id,
            spec: self.spec,
            spec_version: self.spec_version,
            name: self.name,
            description: decrypt_field!(&self.description, &self.description_nonce, dek)?,
            personality: decrypt_field!(&self.personality, &self.personality_nonce, dek)?,
            scenario: decrypt_field!(&self.scenario, &self.scenario_nonce, dek)?,
            first_mes: decrypt_field!(&self.first_mes, &self.first_mes_nonce, dek)?,
            mes_example: decrypt_field!(&self.mes_example, &self.mes_example_nonce, dek)?,
            creator_notes: decrypt_field!(&self.creator_notes, &self.creator_notes_nonce, dek)?,
            system_prompt: decrypt_field!(&self.system_prompt, &self.system_prompt_nonce, dek)?,
            post_history_instructions: decrypt_field!(&self.post_history_instructions, &self.post_history_instructions_nonce, dek)?,
            tags: self.tags,
            creator: self.creator,
            character_version: self.character_version,
            alternate_greetings: self.alternate_greetings,
            nickname: self.nickname,
            creator_notes_multilingual: self.creator_notes_multilingual.map(Json),
            source: self.source,
            group_only_greetings: self.group_only_greetings,
            creation_date: self.creation_date,
            modification_date: self.modification_date,
            created_at: self.created_at,
            updated_at: self.updated_at,
            persona: decrypt_field!(&self.persona, &self.persona_nonce, dek)?,
            world_scenario: decrypt_field!(&self.world_scenario, &self.world_scenario_nonce, dek)?,
            avatar: self.avatar,
            chat: self.chat,
            greeting: decrypt_field!(&self.greeting, &self.greeting_nonce, dek)?,
            definition: decrypt_field!(&self.definition, &self.definition_nonce, dek)?,
            default_voice: self.default_voice,
            extensions: self.extensions.map(Json),
            data_id: self.data_id,
            category: self.category,
            definition_visibility: self.definition_visibility,
            depth: self.depth,
            example_dialogue: decrypt_field!(&self.example_dialogue, &self.example_dialogue_nonce, dek)?,
            favorite: self.favorite,
            first_message_visibility: self.first_message_visibility,
            height: self.height,
            last_activity: self.last_activity,
            migrated_from: self.migrated_from,
            model_prompt: decrypt_field!(&self.model_prompt, &self.model_prompt_nonce, dek)?,
            model_prompt_visibility: self.model_prompt_visibility,
            model_temperature: self.model_temperature,
            num_interactions: self.num_interactions,
            permanence: self.permanence,
            persona_visibility: self.persona_visibility,
            revision: self.revision,
            sharing_visibility: self.sharing_visibility,
            status: self.status,
            system_prompt_visibility: self.system_prompt_visibility,
            system_tags: self.system_tags,
            token_budget: self.token_budget,
            usage_hints: self.usage_hints.map(Json),
            user_persona: decrypt_field!(&self.user_persona, &self.user_persona_nonce, dek)?,
            user_persona_visibility: self.user_persona_visibility,
            visibility: self.visibility,
            weight: self.weight,
            world_scenario_visibility: self.world_scenario_visibility,
        };

        Ok(client_char)
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
    pub alternate_greetings: Option<Vec<Option<String>>>,
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
}

impl std::fmt::Debug for CharacterDataForClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterDataForClient")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("spec", &self.spec)
            .field("spec_version", &self.spec_version)
            .field("name", &"[REDACTED]") // Redacting name
            .field("description", &self.description.as_ref().map(|_| "[REDACTED]"))
            .field("personality", &self.personality.as_ref().map(|_| "[REDACTED]"))
            .field("scenario", &self.scenario.as_ref().map(|_| "[REDACTED]"))
            .field("first_mes", &self.first_mes.as_ref().map(|_| "[REDACTED]"))
            .field("mes_example", &self.mes_example.as_ref().map(|_| "[REDACTED]"))
            .field("creator_notes", &self.creator_notes.as_ref().map(|_| "[REDACTED]"))
            .field("system_prompt", &self.system_prompt.as_ref().map(|_| "[REDACTED]"))
            .field("post_history_instructions", &self.post_history_instructions.as_ref().map(|_| "[REDACTED]"))
            .field("tags", &self.tags.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("creator", &self.creator.as_ref().map(|_| "[REDACTED]"))
            .field("character_version", &self.character_version)
            .field("alternate_greetings", &self.alternate_greetings.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("nickname", &self.nickname.as_ref().map(|_| "[REDACTED]"))
            .field("creator_notes_multilingual", &self.creator_notes_multilingual.as_ref().map(|_| "[REDACTED_JSON]"))
            .field("source", &self.source.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("group_only_greetings", &self.group_only_greetings.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("creation_date", &self.creation_date)
            .field("modification_date", &self.modification_date)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("persona", &self.persona.as_ref().map(|_| "[REDACTED]"))
            .field("world_scenario", &self.world_scenario.as_ref().map(|_| "[REDACTED]"))
            .field("avatar", &self.avatar)
            .field("chat", &self.chat.as_ref().map(|_| "[REDACTED]"))
            .field("greeting", &self.greeting.as_ref().map(|_| "[REDACTED]"))
            .field("definition", &self.definition.as_ref().map(|_| "[REDACTED]"))
            .field("default_voice", &self.default_voice)
            .field("extensions", &self.extensions.as_ref().map(|_| "[REDACTED_JSON]"))
            .field("data_id", &self.data_id)
            .field("category", &self.category)
            .field("definition_visibility", &self.definition_visibility)
            .field("depth", &self.depth)
            .field("example_dialogue", &self.example_dialogue.as_ref().map(|_| "[REDACTED]"))
            .field("favorite", &self.favorite)
            .field("first_message_visibility", &self.first_message_visibility)
            .field("height", &self.height)
            .field("last_activity", &self.last_activity)
            .field("migrated_from", &self.migrated_from)
            .field("model_prompt", &self.model_prompt.as_ref().map(|_| "[REDACTED]"))
            .field("model_prompt_visibility", &self.model_prompt_visibility)
            .field("model_temperature", &self.model_temperature)
            .field("num_interactions", &self.num_interactions)
            .field("permanence", &self.permanence)
            .field("persona_visibility", &self.persona_visibility)
            .field("revision", &self.revision)
            .field("sharing_visibility", &self.sharing_visibility)
            .field("status", &self.status)
            .field("system_prompt_visibility", &self.system_prompt_visibility)
            .field("system_tags", &self.system_tags.as_ref().map(|_| "[REDACTED_LIST]"))
            .field("token_budget", &self.token_budget)
            .field("usage_hints", &self.usage_hints.as_ref().map(|_| "[REDACTED_JSON]"))
            .field("user_persona", &self.user_persona.as_ref().map(|_| "[REDACTED]"))
            .field("user_persona_visibility", &self.user_persona_visibility)
            .field("visibility", &self.visibility)
            .field("weight", &self.weight)
            .field("world_scenario_visibility", &self.world_scenario_visibility)
            .finish()
    }
}

// Represents fields that can be updated from a parsed card
// Using Option<&'a str> allows updating only provided fields
// without allocating new Strings.
#[derive(Debug, Default)]
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

impl<'a> From<&'a ParsedCharacterCard> for UpdatableCharacter<'a> {
    fn from(parsed_card: &'a ParsedCharacterCard) -> Self {
        match parsed_card {
            ParsedCharacterCard::V3(card_v3) => {
                // Corrected map_string helper
                let map_bytes = |s: &'a String| -> Option<&'a [u8]> {
                    if s.is_empty() { None } else { Some(s.as_bytes()) }
                };
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                // Corrected map_vec helper
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.as_str()) // Use as_str()
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
                    if s.is_empty() { None } else { Some(s.as_bytes()) }
                };
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.as_str()) // Use as_str()
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
#[derive(
    Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Debug, Clone,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = characters)]
pub struct CharacterMetadata {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<Vec<u8>>,
    pub description_nonce: Option<Vec<u8>>, // Added nonce field
    pub first_mes: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Add other V2/V3 fields needed for listing/selection if necessary
    // pub persona: Option<String>,
    // pub greeting: Option<String>,
    // pub example_dialogue: Option<String>,
    // ... other fields extracted from the card
}

// Helper function to create a dummy Character instance
pub fn create_dummy_character() -> Character { // Made pub for potential use in other tests
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
    }
}

// Client-side Character representation (for JSON responses)
#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::character_card::{CharacterCardDataV3, CharacterCardV3};
    use crate::services::character_parser::ParsedCharacterCard;
    use secrecy::SecretBox; // For testing encryption/decryption - Corrected import
    use ring::rand::{SystemRandom, SecureRandom}; // For generating a dummy DEK

    // Helper function to generate a dummy DEK for testing
    fn generate_dummy_dek() -> SecretBox<Vec<u8>> { // Corrected return type
        let mut key_bytes = vec![0u8; 32]; // AES-256-GCM needs a 32-byte key
        let rng = SystemRandom::new();
        rng.fill(&mut key_bytes).unwrap();
        SecretBox::new(Box::new(key_bytes))
    }

    #[test]
    fn test_character_debug() {
        let character = create_dummy_character();
        let debug_output = format!("{:?}", character);
        assert!(debug_output.contains("Dummy Character"));
        assert!(debug_output.starts_with("Character {"));
        assert!(debug_output.ends_with("}"));
    }

    #[test]
    fn test_character_clone() {
        let character1 = create_dummy_character();
        let character2 = character1.clone();
        assert_eq!(character1, character2);
    }

    #[tokio::test]
    async fn test_description_encryption_and_decryption_via_client_conversion() {
        let mut character = create_dummy_character();
        let dek = generate_dummy_dek();
        let original_description = "This is a secret description.".to_string();

        // Encrypt the description
        character.encrypt_description_field(&dek, Some(original_description.clone())).unwrap();

        // Check that description and nonce are Some
        assert!(character.description.is_some());
        assert!(character.description_nonce.is_some());

        // Convert to ClientCharacter with DEK
        let client_char = character.clone().into_client_character(Some(&dek)).await.unwrap();
        assert_eq!(client_char.description, original_description);

        // Test with empty description
        let mut char_empty_desc = create_dummy_character();
        char_empty_desc.encrypt_description_field(&dek, Some("".to_string())).unwrap();
        assert!(char_empty_desc.description.is_none()); // Empty string leads to None
        assert!(char_empty_desc.description_nonce.is_none());
        let client_empty_desc = char_empty_desc.into_client_character(Some(&dek)).await.unwrap();
        assert_eq!(client_empty_desc.description, "");

        // Test with inconsistent nonce (simulated by no nonce)
        let mut char_inconsistent_nonce = create_dummy_character();
        char_inconsistent_nonce.encrypt_description_field(&dek, Some("data".to_string())).unwrap();
        char_inconsistent_nonce.description_nonce = None; // Simulate missing nonce
        let client_inconsistent_nonce = char_inconsistent_nonce.clone().into_client_character(Some(&dek)).await.unwrap();
        // Expect placeholder because decryption should fail or be skipped due to missing nonce
        assert_eq!(client_inconsistent_nonce.description, "[Encrypted]");

        // Test with None description (after encryption was for Some(""))
        let mut char_none_desc = create_dummy_character();
        char_none_desc.encrypt_description_field(&dek, Some("".to_string())).unwrap(); // Clears fields
        let client_none_desc = char_none_desc.into_client_character(Some(&dek)).await.unwrap();
        assert_eq!(client_none_desc.description, ""); // Should be empty string

        // Convert to ClientCharacter without DEK
        let mut char_no_dek = create_dummy_character();
        char_no_dek.encrypt_description_field(&dek, Some(original_description.clone())).unwrap();
        let client_no_dek = char_no_dek.into_client_character(None).await.unwrap();
        assert_eq!(client_no_dek.description, "[Encrypted]");

        // Test with no description data at all
        let char_no_desc = create_dummy_character(); // description and nonce are None by default
        let client_no_desc = char_no_desc.into_client_character(None).await.unwrap();
        assert_eq!(client_no_desc.description, ""); // Expect empty string, not "[Encrypted]"
    }

    #[tokio::test]
    async fn test_into_decrypted_for_client() {
        let mut character = create_dummy_character();
        let dek = generate_dummy_dek();
        let original_description = "Test Description".to_string();
        let original_persona = "Test Persona".to_string();

        // Encrypt some fields directly for testing (as encrypt_field! macro would)
        let (desc_ct, desc_n) = crate::crypto::encrypt_gcm(original_description.as_bytes(), &dek).unwrap();
        character.description = Some(desc_ct);
        character.description_nonce = Some(desc_n);

        let (pers_ct, pers_n) = crate::crypto::encrypt_gcm(original_persona.as_bytes(), &dek).unwrap();
        character.persona = Some(pers_ct);
        character.persona_nonce = Some(pers_n);

        // With DEK
        let client_data_with_dek = character.clone().into_decrypted_for_client(Some(&dek)).await.unwrap();
        assert_eq!(client_data_with_dek.description.as_deref(), Some(original_description.as_str()));
        assert_eq!(client_data_with_dek.persona.as_deref(), Some(original_persona.as_str()));

        // Without DEK
        let client_data_without_dek = character.clone().into_decrypted_for_client(None).await.unwrap();
        assert_eq!(client_data_without_dek.description.as_deref(), Some("[Encrypted]"));
        assert_eq!(client_data_without_dek.persona.as_deref(), Some("[Encrypted]"));

        // Test with no description data (should be None)
        let char_no_desc = create_dummy_character(); // description and nonce are None by default
        let client_data_no_desc = char_no_desc.clone().into_decrypted_for_client(Some(&dek)).await.unwrap();
        assert_eq!(client_data_no_desc.description, None);
        let client_data_no_desc_no_dek = char_no_desc.clone().into_decrypted_for_client(None).await.unwrap();
        assert_eq!(client_data_no_desc_no_dek.description, None);
    }

    // Helper function to create a dummy V3 card
    fn create_dummy_v3_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V3(CharacterCardV3 {
            spec: "chara_card_v3_spec".to_string(),
            spec_version: "1.0.0".to_string(),
            data: CharacterCardDataV3 {
                name: Some("Test V3 Name".to_string()),
                description: "V3 Description".to_string(),
                personality: "".to_string(), // Empty string
                first_mes: "V3 First Message".to_string(),
                mes_example: "V3 Example".to_string(),
                scenario: "".to_string(),
                system_prompt: "V3 System".to_string(),
                creator_notes: "V3 Creator Notes".to_string(),
                tags: vec!["tag1".to_string(), "".to_string(), "tag3".to_string()], // Include empty tag
                creator: "V3 Creator".to_string(),
                character_version: "v1.2".to_string(),
                alternate_greetings: vec!["Hi".to_string(), "Hello".to_string()],
                // Explicitly add missing fields with default values
                post_history_instructions: Default::default(),
                character_book: None,
                assets: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: Default::default(),
                creation_date: None,
                modification_date: None,
                extensions: Default::default(), // Keep extensions
            },
        })
    }

    // Helper function to create a dummy V2 card
    fn create_dummy_v2_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V2Fallback(CharacterCardDataV3 {
            // V2 uses the V3 data struct as fallback
            name: Some("Test V2 Name".to_string()),
            description: "V2 Description".to_string(),
            personality: "V2 Personality".to_string(),
            first_mes: "".to_string(), // Empty string
            mes_example: "V2 Example".to_string(),
            scenario: "V2 Scenario".to_string(),
            system_prompt: "".to_string(),
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
        assert_eq!(updatable.description, Some("V3 Description".as_bytes()));
        assert_eq!(updatable.personality, None); // Empty string maps to None
        assert_eq!(updatable.first_mes, Some("V3 First Message".as_bytes()));
        assert_eq!(updatable.mes_example, Some("V3 Example".as_bytes()));
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
        assert_eq!(updatable.description, Some("V2 Description".as_bytes()));
        assert_eq!(updatable.personality, Some("V2 Personality".as_bytes()));
        assert_eq!(updatable.first_mes, None); // Empty string maps to None
        assert_eq!(updatable.mes_example, Some("V2 Example".as_bytes()));
        assert_eq!(updatable.scenario, Some("V2 Scenario".as_bytes()));
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
            description: Some("A test description".as_bytes().to_vec()),
            description_nonce: None, // Added missing field
            first_mes: None,
            created_at: dt,
            updated_at: dt,
        };

        // Serialize
        let json_string = serde_json::to_string(&metadata).expect("Serialization failed");
        println!("Serialized JSON: {}", json_string); // Optional: print for debugging

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
