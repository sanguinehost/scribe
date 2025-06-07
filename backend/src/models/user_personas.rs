use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Associations, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::users::User;
use crate::services::encryption_service::EncryptionService;
use secrecy::{ExposeSecret, SecretBox};

#[derive(Debug)]
struct DecryptedPersonaFields {
    description: String,
    personality: Option<String>,
    scenario: Option<String>,
    first_mes: Option<String>,
    mes_example: Option<String>,
    system_prompt: Option<String>,
    post_history_instructions: Option<String>,
}

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
    // Debug, // Removed Debug, will use custom impl
    AsChangeset,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = crate::schema::user_personas)]
#[diesel(treat_none_as_null = true)]
pub struct UserPersona {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,                               // In schema.rs: Varchar
    pub description: Vec<u8>,                       // In schema.rs: Bytea (NOT NULL)
    pub spec: Option<String>,                       // In schema.rs: Nullable<Varchar>
    pub spec_version: Option<String>,               // In schema.rs: Nullable<Varchar>
    pub personality: Option<Vec<u8>>,               // In schema.rs: Nullable<Bytea>
    pub scenario: Option<Vec<u8>>,                  // In schema.rs: Nullable<Bytea>
    pub first_mes: Option<Vec<u8>>,                 // In schema.rs: Nullable<Bytea>
    pub mes_example: Option<Vec<u8>>,               // In schema.rs: Nullable<Bytea>
    pub system_prompt: Option<Vec<u8>>,             // In schema.rs: Nullable<Bytea>
    pub post_history_instructions: Option<Vec<u8>>, // In schema.rs: Nullable<Bytea>
    pub tags: Option<Vec<Option<String>>>,          // In schema.rs: Nullable<Array<Nullable<Text>>>
    pub avatar: Option<String>,                     // In schema.rs: Nullable<Varchar>

    // Nonces
    pub description_nonce: Option<Vec<u8>>, // In schema.rs: Nullable<Bytea> - but tied to non-nullable description
    pub personality_nonce: Option<Vec<u8>>,
    pub scenario_nonce: Option<Vec<u8>>,
    pub first_mes_nonce: Option<Vec<u8>>,
    pub mes_example_nonce: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub post_history_instructions_nonce: Option<Vec<u8>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for UserPersona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPersona")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name) // Name is not considered secret
            .field("description", &"[REDACTED_BYTES]")
            .field("spec", &self.spec)
            .field("spec_version", &self.spec_version)
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
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "post_history_instructions",
                &self
                    .post_history_instructions
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field("tags", &self.tags.as_ref().map(|_| "[REDACTED_LIST]"))
            .field(
                "avatar",
                &self.avatar.as_ref().map(|_| "[REDACTED_AVATAR_URL_OR_ID]"),
            )
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
                "system_prompt_nonce",
                &self
                    .system_prompt_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field(
                "post_history_instructions_nonce",
                &self
                    .post_history_instructions_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UserPersonaDataForClient {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: String, // Decrypted
    pub spec: Option<String>,
    pub spec_version: Option<String>,
    pub personality: Option<String>,               // Decrypted
    pub scenario: Option<String>,                  // Decrypted
    pub first_mes: Option<String>,                 // Decrypted
    pub mes_example: Option<String>,               // Decrypted
    pub system_prompt: Option<String>,             // Decrypted
    pub post_history_instructions: Option<String>, // Decrypted
    pub tags: Option<Vec<Option<String>>>,
    pub avatar: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserPersona {
    /// Decrypts an optional field if both ciphertext and nonce are present.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if decryption fails or if ciphertext/nonce mismatch occurs
    fn decrypt_optional_field(
        encryption_service: &EncryptionService,
        dek: &SecretBox<Vec<u8>>,
        ciphertext: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        field_name_for_error: &str,
    ) -> Result<Option<String>, AppError> {
        match (ciphertext, nonce) {
            (Some(ct), Some(n)) => {
                if ct.is_empty() && n.is_empty() {
                    // Convention for empty encrypted field
                    return Ok(Some(String::new()));
                } else if ct.is_empty() || n.is_empty() {
                    // Invalid state
                    return Err(AppError::DecryptionError(format!(
                        "Mismatched ciphertext/nonce for {field_name_for_error}: one is empty, the other is not."
                    )));
                }

                let decrypted_bytes = encryption_service
                    .decrypt(&ct, &n, dek.expose_secret().as_slice())
                    .map_err(|e| {
                        AppError::DecryptionError(format!(
                            "Failed to decrypt {field_name_for_error}: {e}"
                        ))
                    })?;
                String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                    AppError::DecryptionError(format!(
                        "Invalid UTF-8 for {field_name_for_error}: {e}"
                    ))
                })
            }
            (None, None) => Ok(None), // Field was not set
            (Some(_), None) => Err(AppError::DecryptionError(format!(
                "Ciphertext present but nonce missing for {field_name_for_error}"
            ))),
            (None, Some(_)) => Err(AppError::DecryptionError(format!(
                "Nonce present but ciphertext missing for {field_name_for_error}"
            ))),
        }
    }

    /// Converts this `UserPersonaData` into a `UserPersonaDataForClient` by decrypting encrypted fields.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if decryption fails or required encryption fields are missing
    pub fn into_data_for_client(
        self,
        dek_opt: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<UserPersonaDataForClient, AppError> {
        if let Some(dek) = dek_opt {
            self.decrypt_and_build_client_data(dek)
        } else {
            Ok(self.build_plaintext_client_data())
        }
    }

    fn decrypt_and_build_client_data(
        self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<UserPersonaDataForClient, AppError> {
        let encryption_service = EncryptionService::new();
        let decrypted_fields = self.decrypt_all_fields(&encryption_service, dek)?;
        Ok(self.build_client_data_with_fields(decrypted_fields))
    }

    fn decrypt_all_fields(
        &self,
        encryption_service: &EncryptionService,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<DecryptedPersonaFields, AppError> {
        Ok(DecryptedPersonaFields {
            description: self.decrypt_required_description_field(encryption_service, dek)?,
            personality: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.personality.clone(),
                self.personality_nonce.clone(),
                "personality",
            )?,
            scenario: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.scenario.clone(),
                self.scenario_nonce.clone(),
                "scenario",
            )?,
            first_mes: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.first_mes.clone(),
                self.first_mes_nonce.clone(),
                "first_mes",
            )?,
            mes_example: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.mes_example.clone(),
                self.mes_example_nonce.clone(),
                "mes_example",
            )?,
            system_prompt: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.system_prompt.clone(),
                self.system_prompt_nonce.clone(),
                "system_prompt",
            )?,
            post_history_instructions: Self::decrypt_optional_field(
                encryption_service,
                dek,
                self.post_history_instructions.clone(),
                self.post_history_instructions_nonce.clone(),
                "post_history_instructions",
            )?,
        })
    }

    fn decrypt_required_description_field(
        &self,
        encryption_service: &EncryptionService,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<String, AppError> {
        let desc_nonce = self.description_nonce.as_ref().ok_or_else(|| {
            AppError::DecryptionError(
                "Description nonce is missing for non-optional field".to_string(),
            )
        })?;
        let description_val = encryption_service.decrypt(
            &self.description,
            desc_nonce,
            dek.expose_secret().as_slice(),
        )?;
        String::from_utf8(description_val)
            .map_err(|e| AppError::DecryptionError(format!("Invalid UTF-8 for description: {e}")))
    }

    fn build_plaintext_client_data(mut self) -> UserPersonaDataForClient {
        // When no DEK is provided, encrypted fields should show as "[Encrypted]" rather than
        // trying to interpret encrypted bytes as UTF-8
        let decrypted_fields = DecryptedPersonaFields {
            description: if self.description.is_empty() {
                String::new()
            } else {
                "[Encrypted]".to_string()
            },
            personality: self.personality.take().map(|p| {
                if p.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
            scenario: self.scenario.take().map(|s| {
                if s.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
            first_mes: self.first_mes.take().map(|f| {
                if f.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
            mes_example: self.mes_example.take().map(|m| {
                if m.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
            system_prompt: self.system_prompt.take().map(|s| {
                if s.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
            post_history_instructions: self.post_history_instructions.take().map(|p| {
                if p.is_empty() {
                    String::new()
                } else {
                    "[Encrypted]".to_string()
                }
            }),
        };
        self.build_client_data_with_fields(decrypted_fields)
    }

    fn build_client_data_with_fields(
        self,
        fields: DecryptedPersonaFields,
    ) -> UserPersonaDataForClient {
        UserPersonaDataForClient {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            description: fields.description,
            spec: self.spec,
            spec_version: self.spec_version,
            personality: fields.personality,
            scenario: fields.scenario,
            first_mes: fields.first_mes,
            mes_example: fields.mes_example,
            system_prompt: fields.system_prompt,
            post_history_instructions: fields.post_history_instructions,
            tags: self.tags,
            avatar: self.avatar.and_then(|asset_id_str| {
                asset_id_str.parse::<i32>().ok().map(|asset_id| {
                    format!("/api/personas/{}/assets/{}", self.id, asset_id)
                })
            }),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
pub struct CreateUserPersonaDto {
    pub name: String,        // Name is mandatory for creation
    pub description: String, // Description is mandatory for creation
    pub spec: Option<String>,
    pub spec_version: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub avatar: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
pub struct UpdateUserPersonaDto {
    pub name: Option<String>,
    pub description: Option<String>,
    pub spec: Option<String>,
    pub spec_version: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub avatar: Option<String>,
}

// TODO: Implement custom Debug formatting to redact sensitive fields
// TODO: Add CreateUserPersonaDto and UpdateUserPersonaDto

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use chrono::Utc;
    use secrecy::SecretBox;
    use serde_json;
    use uuid::Uuid;

    fn generate_dummy_dek_for_persona_tests() -> SecretBox<Vec<u8>> {
        // Use a fixed, known key for reproducible tests if needed, or random for general tests.
        // For this unit test, a fixed key is fine.
        let key_bytes = vec![0u8; 32]; // 32 bytes for AES-256
        SecretBox::new(Box::new(key_bytes))
    }

    fn create_dummy_user_persona_encrypted() -> UserPersona {
        UserPersona {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Persona".to_string(),
            description: vec![1, 2, 3], // Dummy encrypted data
            spec: Some("user_persona_v1".to_string()),
            spec_version: Some("1.0.0".to_string()),
            personality: Some(vec![4, 5, 6]),
            scenario: None,
            first_mes: None,
            mes_example: None,
            system_prompt: None,
            post_history_instructions: None,
            tags: Some(vec![Some("tag1".to_string()), Some("tag2".to_string())]),
            avatar: Some("avatar.png".to_string()),
            description_nonce: Some(vec![7, 8, 9]),
            personality_nonce: Some(vec![10, 11, 12]),
            scenario_nonce: None,
            first_mes_nonce: None,
            mes_example_nonce: None,
            system_prompt_nonce: None,
            post_history_instructions_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_user_persona_serde() {
        let persona = create_dummy_user_persona_encrypted();
        let serialized = serde_json::to_string(&persona).unwrap();
        let deserialized: UserPersona = serde_json::from_str(&serialized).unwrap();
        assert_eq!(persona, deserialized);
    }

    fn create_dummy_user_persona_data_for_client() -> UserPersonaDataForClient {
        UserPersonaDataForClient {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Persona Client".to_string(),
            description: "This is a test description.".to_string(),
            spec: Some("user_persona_v1_client".to_string()),
            spec_version: Some("1.0.1".to_string()),
            personality: Some("Friendly and helpful.".to_string()),
            scenario: None,
            first_mes: None,
            mes_example: None,
            system_prompt: None,
            post_history_instructions: None,
            tags: Some(vec![Some("client_tag1".to_string())]),
            avatar: Some("client_avatar.png".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_user_persona_data_for_client_serde() {
        let client_data = create_dummy_user_persona_data_for_client();
        let serialized = serde_json::to_string(&client_data).unwrap();
        let deserialized: UserPersonaDataForClient = serde_json::from_str(&serialized).unwrap();
        assert_eq!(client_data, deserialized);
    }

    // TODO: Add encryption/decryption tests using mocked EncryptionService
    // This test covers the decryption part of the model
    /// Helper function to create test persona with encrypted data
    fn create_test_persona(dek: &SecretBox<Vec<u8>>) -> (UserPersona, String, String) {
        let original_description = "This is the main description.".to_string();
        let original_personality = "A very curious individual.".to_string();

        // Manually encrypt fields to simulate what the service would do before saving
        let (desc_ct, desc_n) = crypto::encrypt_gcm(original_description.as_bytes(), dek).unwrap();
        let (pers_ct, pers_n) = crypto::encrypt_gcm(original_personality.as_bytes(), dek).unwrap();

        let persona = UserPersona {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Encrypted Persona".to_string(),
            description: desc_ct,
            description_nonce: Some(desc_n),
            spec: Some("spec_enc".to_string()),
            spec_version: Some("1.0_enc".to_string()),
            personality: Some(pers_ct),
            personality_nonce: Some(pers_n),
            scenario: None, // Test with a None field too
            scenario_nonce: None,
            first_mes: None,
            first_mes_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            system_prompt: None,
            system_prompt_nonce: None,
            post_history_instructions: None,
            post_history_instructions_nonce: None,
            tags: None,
            avatar: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        (persona, original_description, original_personality)
    }

    #[test]
    fn test_user_persona_into_data_for_client() {
        let dek = generate_dummy_dek_for_persona_tests();

        // Test with DEK - fresh instance
        let (persona_with_dek, original_description, original_personality) =
            create_test_persona(&dek);
        let client_data_with_dek = persona_with_dek.into_data_for_client(Some(&dek)).unwrap();
        assert_eq!(client_data_with_dek.description, original_description);
        assert_eq!(client_data_with_dek.personality, Some(original_personality));
        assert_eq!(client_data_with_dek.scenario, None);
        assert_eq!(client_data_with_dek.name, "Encrypted Persona");

        // Test without DEK - fresh instance, no cloning needed
        let (persona_without_dek, _, _) = create_test_persona(&dek);
        let client_data_without_dek = persona_without_dek.into_data_for_client(None).unwrap();
        assert_eq!(
            client_data_without_dek.description,
            "[Encrypted]".to_string()
        );
        assert_eq!(
            client_data_without_dek.personality,
            Some("[Encrypted]".to_string())
        );
        assert_eq!(client_data_without_dek.scenario, None);

        // Test scenario: description was empty originally
        let create_empty_desc_persona = || {
            let (empty_desc_ct, empty_desc_n) = crypto::encrypt_gcm(b"", &dek).unwrap();
            UserPersona {
                description: empty_desc_ct,
                description_nonce: Some(empty_desc_n),
                personality: None, // No personality
                personality_nonce: None,
                ..create_dummy_user_persona_encrypted() // Fill other fields
            }
        };

        let client_empty_desc_with_dek = create_empty_desc_persona()
            .into_data_for_client(Some(&dek))
            .unwrap();
        assert_eq!(client_empty_desc_with_dek.description, "");
        assert_eq!(client_empty_desc_with_dek.personality, None);

        // No cloning needed - fresh instance
        let client_empty_desc_without_dek = create_empty_desc_persona()
            .into_data_for_client(None)
            .unwrap();
        assert_eq!(
            client_empty_desc_without_dek.description,
            "[Encrypted]".to_string()
        );
        assert_eq!(client_empty_desc_without_dek.personality, None);
    }

    #[test]
    fn test_create_user_persona_dto_serde() {
        let dto = CreateUserPersonaDto {
            name: "New Persona".to_string(),
            description: "A fresh start.".to_string(),
            spec: Some("spec_create".to_string()),
            spec_version: None,
            personality: Some("Curious".to_string()),
            scenario: None,
            first_mes: None,
            mes_example: None,
            system_prompt: None,
            post_history_instructions: None,
            tags: Some(vec![Some("new".to_string())]),
            avatar: None,
        };
        let serialized = serde_json::to_string(&dto).unwrap();
        let deserialized: CreateUserPersonaDto = serde_json::from_str(&serialized).unwrap();
        assert_eq!(dto, deserialized);
    }

    #[test]
    fn test_update_user_persona_dto_serde() {
        let dto = UpdateUserPersonaDto {
            name: Some("Updated Persona Name".to_string()),
            description: None,
            spec: Some("spec_update".to_string()),
            personality: Some("Wiser".to_string()),
            scenario: None,
            first_mes: None,
            mes_example: Some("Updated example".to_string()),
            system_prompt: None,
            post_history_instructions: None,
            tags: Some(vec![Some("updated".to_string())]),
            avatar: Some("new_avatar.jpg".to_string()),
            spec_version: Some("1.1.0".to_string()),
        };
        let serialized = serde_json::to_string(&dto).unwrap();
        let deserialized: UpdateUserPersonaDto = serde_json::from_str(&serialized).unwrap();
        assert_eq!(dto, deserialized);
    }
}
