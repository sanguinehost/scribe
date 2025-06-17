use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl};
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid; // Added for logging

use crate::errors::AppError;
use crate::models::user_personas::{
    CreateUserPersonaDto, UpdateUserPersonaDto, UserPersona, UserPersonaDataForClient,
};
use crate::models::users::{User, UserDbQuery};
use crate::schema::{user_personas::dsl as user_personas_dsl, users::dsl as users_dsl};
use crate::services::encryption_service::EncryptionService;
use crate::state::DbPool;

// Type alias for encrypted field result
type EncryptedFieldResult = Result<(Option<Vec<u8>>, Option<Vec<u8>>), AppError>;

#[derive(Clone)]
pub struct UserPersonaService {
    db_pool: DbPool,
    encryption_service: Arc<EncryptionService>,
}

impl UserPersonaService {
    #[must_use]
    pub const fn new(db_pool: DbPool, encryption_service: Arc<EncryptionService>) -> Self {
        Self {
            db_pool,
            encryption_service,
        }
    }

    fn encrypt_optional_string_for_db(
        &self,
        plaintext_opt: Option<String>,
        dek: &SecretBox<Vec<u8>>,
    ) -> EncryptedFieldResult {
        match plaintext_opt {
            Some(plaintext) if !plaintext.is_empty() => {
                let (ciphertext, nonce) = self
                    .encryption_service
                    .encrypt(&plaintext, dek.expose_secret().as_slice())?;
                Ok((Some(ciphertext), Some(nonce)))
            }
            _ => Ok((None, None)), // Empty or None string results in None for data and nonce
        }
    }

    /// Creates a new user persona with encrypted sensitive fields.
    ///
    /// # Errors
    ///
    /// Returns `AppError::BadRequest` if validation fails (name length, spec length),
    /// encryption service errors if field encryption fails,
    /// `AppError::DbPoolError` if database connection fails,
    /// `AppError::InternalServerErrorGeneric` if database interaction fails,
    /// `AppError::DatabaseQueryError` if the database insert operation fails.
    #[tracing::instrument(skip(self, current_user, dek, create_dto), err)]
    pub async fn create_user_persona(
        &self,
        current_user: &User,
        dek: &SecretBox<Vec<u8>>,
        create_dto: CreateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, AppError> {
        // Basic validation (more can be added via a validator crate if complex)
        if create_dto.name.is_empty() || create_dto.name.len() > 255 {
            return Err(AppError::BadRequest(
                "Persona name must be between 1 and 255 characters.".to_string(),
            ));
        }
        if create_dto.description.is_empty() {
            // For now, let's allow empty description, but typically this would be validated.
            // If not allowed: return Err(AppError::BadRequest("Persona description cannot be empty.".to_string()));
        }
        if let Some(spec) = &create_dto.spec {
            if spec.len() > 100 {
                return Err(AppError::BadRequest("Spec max length is 100.".to_string()));
            }
        }
        // Add other DTO field validations as necessary

        let (description_ciphertext, description_nonce_val) = self
            .encryption_service
            .encrypt(&create_dto.description, dek.expose_secret().as_slice())?;

        let (personality_ct, personality_n) =
            self.encrypt_optional_string_for_db(create_dto.personality, dek)?;
        let (scenario_ct, scenario_n) =
            self.encrypt_optional_string_for_db(create_dto.scenario, dek)?;
        let (first_mes_ct, first_mes_n) =
            self.encrypt_optional_string_for_db(create_dto.first_mes, dek)?;
        let (mes_example_ct, mes_example_n) =
            self.encrypt_optional_string_for_db(create_dto.mes_example, dek)?;
        let (system_prompt_ct, system_prompt_n) =
            self.encrypt_optional_string_for_db(create_dto.system_prompt, dek)?;
        let (post_history_instructions_ct, post_history_instructions_n) =
            self.encrypt_optional_string_for_db(create_dto.post_history_instructions, dek)?;

        let new_persona_db = UserPersona {
            id: Uuid::new_v4(),
            user_id: current_user.id,
            name: create_dto.name,
            description: description_ciphertext,
            description_nonce: Some(description_nonce_val), // Nonce must be Some if description is encrypted
            spec: create_dto.spec,
            spec_version: create_dto.spec_version,
            personality: personality_ct,
            personality_nonce: personality_n,
            scenario: scenario_ct,
            scenario_nonce: scenario_n,
            first_mes: first_mes_ct,
            first_mes_nonce: first_mes_n,
            mes_example: mes_example_ct,
            mes_example_nonce: mes_example_n,
            system_prompt: system_prompt_ct,
            system_prompt_nonce: system_prompt_n,
            post_history_instructions: post_history_instructions_ct,
            post_history_instructions_nonce: post_history_instructions_n,
            tags: create_dto.tags,
            avatar: create_dto.avatar,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let pool = self.db_pool.clone();
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let inserted_persona = conn
            .interact(move |db_conn| {
                diesel::insert_into(user_personas_dsl::user_personas)
                    .values(&new_persona_db)
                    .get_result::<UserPersona>(db_conn)
                    .map_err(AppError::from) // Convert DieselError to AppError
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("DB interact join error: {e}"))
            })??; // Flatten Result<Result<T, E1>, E2>

        tracing::info!(user_id = %current_user.id, persona_id = %inserted_persona.id, "Successfully created user persona");

        inserted_persona.into_data_for_client(Some(dek))
    }

    #[tracing::instrument(skip(self, current_user, dek_opt), err)]
    pub async fn get_user_persona(
        &self,
        current_user: &User,
        dek_opt: Option<&SecretBox<Vec<u8>>>,
        persona_id: Uuid,
    ) -> Result<UserPersonaDataForClient, AppError> {
        let pool = self.db_pool.clone();
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let found_persona_db = conn
            .interact(move |db_conn| {
                user_personas_dsl::user_personas
                    .filter(user_personas_dsl::id.eq(persona_id))
                    .first::<UserPersona>(db_conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for get_user_persona: {e}"
                ))
            })??;

        match found_persona_db {
            Some(persona_db) => {
                if persona_db.user_id != current_user.id {
                    tracing::warn!(
                        current_user_id = %current_user.id,
                        target_persona_id = %persona_db.id,
                        target_persona_user_id = %persona_db.user_id,
                        "User attempted to access a persona they do not own."
                    );
                    return Err(AppError::Forbidden(
                        "Access denied to user persona".to_string(),
                    ));
                }
                tracing::info!(user_id = %current_user.id, persona_id = %persona_db.id, "Successfully fetched user persona, attempting conversion to client data.");
                persona_db.into_data_for_client(dek_opt)
            }
            None => Err(AppError::NotFound(format!(
                "User persona with ID {persona_id} not found"
            ))),
        }
    }

    #[tracing::instrument(skip(self, current_user, dek), err)]
    pub async fn list_user_personas(
        &self,
        current_user: &User,
        dek: &SecretBox<Vec<u8>>, // DEK is required to decrypt for the list
    ) -> Result<Vec<UserPersonaDataForClient>, AppError> {
        let pool = self.db_pool.clone();
        let user_id_for_query = current_user.id;
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let personas_db = conn
            .interact(move |db_conn| {
                user_personas_dsl::user_personas
                    .filter(user_personas_dsl::user_id.eq(user_id_for_query))
                    .order(user_personas_dsl::updated_at.desc()) // Example ordering
                    .load::<UserPersona>(db_conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for list_user_personas: {e}"
                ))
            })??;

        let mut personas_for_client = Vec::new();
        for persona_db in personas_db {
            let persona_id_for_log = persona_db.id; // Clone for logging before move
            match persona_db.into_data_for_client(Some(dek)) {
                Ok(client_data) => personas_for_client.push(client_data),
                Err(e) => {
                    tracing::error!(
                        user_id = %current_user.id,
                        persona_id = %persona_id_for_log,
                        error = ?e,
                        "Failed to decrypt persona during list operation. Skipping this persona."
                    );
                    // Optionally, collect these errors or return a partial success indicator
                }
            }
        }
        tracing::info!(user_id = %current_user.id, count = personas_for_client.len(), "Successfully listed and decrypted user personas");
        Ok(personas_for_client)
    }

    #[tracing::instrument(skip(self, current_user, dek, update_dto), err)]
    pub async fn update_user_persona(
        &self,
        current_user: &User,
        dek: &SecretBox<Vec<u8>>,
        persona_id: Uuid,
        update_dto: UpdateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, AppError> {
        let pool = self.db_pool.clone();
        let conn_fetch = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let persona_to_update_db = conn_fetch
            .interact(move |db_conn| {
                user_personas_dsl::user_personas
                    .filter(user_personas_dsl::id.eq(persona_id))
                    .first::<UserPersona>(db_conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for update_user_persona (fetch): {e}"
                ))
            })??;

        let Some(mut persona) = persona_to_update_db else {
            return Err(AppError::NotFound(format!(
                "User persona with ID {persona_id} not found for update"
            )));
        };

        if persona.user_id != current_user.id {
            tracing::warn!(
                current_user_id = %current_user.id,
                target_persona_id = %persona.id,
                target_persona_user_id = %persona.user_id,
                "User attempted to update a persona they do not own."
            );
            return Err(AppError::Forbidden(
                "Access denied to update user persona".to_string(),
            ));
        }

        let mut changed = false;

        // Apply updates from DTO
        if let Some(name_val) = update_dto.name {
            if persona.name != name_val {
                persona.name = name_val;
                changed = true;
            }
        }
        if let Some(spec_val) = update_dto.spec {
            if persona.spec.as_ref() != Some(&spec_val) {
                persona.spec = Some(spec_val);
                changed = true;
            }
        }
        if let Some(spec_version_val) = update_dto.spec_version {
            if persona.spec_version.as_ref() != Some(&spec_version_val) {
                persona.spec_version = Some(spec_version_val);
                changed = true;
            }
        }
        if let Some(tags_val) = update_dto.tags {
            if persona.tags.as_ref() != Some(&tags_val) {
                persona.tags = Some(tags_val);
                changed = true;
            }
        }
        if let Some(avatar_val) = update_dto.avatar {
            if persona.avatar.as_ref() != Some(&avatar_val) {
                persona.avatar = Some(avatar_val);
                changed = true;
            }
        }

        // Macro to handle updates for optional encrypted fields
        macro_rules! update_optional_encrypted_field {
            ($field_name:ident, $nonce_field_name:ident) => {
                // Get the Option<String> from the DTO.
                let dto_field_value = update_dto.$field_name.clone(); // This is Option<String>

                // Encrypt it. If dto_field_value is None or Some(""),
                // encrypt_optional_string_for_db returns (None, None) which clears the field.
                // If dto_field_value is Some("text"), this encrypts "text".
                let (new_ct, new_n) = self.encrypt_optional_string_for_db(dto_field_value, dek)?;

                // Check if the current DB values differ from the new (potentially None) values.
                if persona.$field_name != new_ct || persona.$nonce_field_name != new_n {
                    persona.$field_name = new_ct;
                    persona.$nonce_field_name = new_n;
                    changed = true;
                }
                // If the DTO field was not present (e.g. if UpdateUserPersonaDto used Option<Option<String>>
                // and the outer Option was None), then we would skip. But with Option<String>,
                // None means "clear", Some("") means "clear", and Some("text") means "update".
                // The logic above correctly handles all these cases for Option<String> DTO fields.
            };
        }

        // Apply for description (mandatory, but handled differently with its own nonce)
        // Apply for description. If update_dto.description is None or an empty string, encrypt an empty string.
        // Otherwise, encrypt the provided string.
        let string_to_encrypt_for_description = update_dto.description.as_deref().unwrap_or("");
        let (new_description_ct, new_description_n) = self.encryption_service.encrypt(
            string_to_encrypt_for_description,
            dek.expose_secret().as_slice(),
        )?;

        if persona.description != new_description_ct
            || persona.description_nonce != Some(new_description_n.clone())
        {
            persona.description = new_description_ct;
            persona.description_nonce = Some(new_description_n);
            changed = true;
        }

        update_optional_encrypted_field!(personality, personality_nonce);
        update_optional_encrypted_field!(scenario, scenario_nonce);
        update_optional_encrypted_field!(first_mes, first_mes_nonce);
        update_optional_encrypted_field!(mes_example, mes_example_nonce);
        update_optional_encrypted_field!(system_prompt, system_prompt_nonce);
        update_optional_encrypted_field!(
            post_history_instructions,
            post_history_instructions_nonce
        );

        if !changed {
            tracing::debug!(user_id = %current_user.id, %persona_id, "No changes detected for user persona update. Returning existing.");
            return persona.into_data_for_client(Some(dek));
        }

        persona.updated_at = chrono::Utc::now();

        // Get a new connection instance from the cloned pool for the update interaction
        // pool was cloned at the start of the function. We need a connection from it.
        let conn_update = self
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let updated_persona_db = conn_update
            .interact(move |db_conn| {
                // Changed conn to db_conn
                diesel::update(user_personas_dsl::user_personas.find(persona_id))
                    .set(&persona) // UserPersona derives AsChangeset
                    .get_result::<UserPersona>(db_conn) // Changed conn to db_conn
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for update_user_persona (update): {e}"
                ))
            })??;

        tracing::info!(user_id = %current_user.id, persona_id = %updated_persona_db.id, "Successfully updated user persona");
        updated_persona_db.into_data_for_client(Some(dek))
    }

    #[tracing::instrument(skip(self, current_user), err)]
    pub async fn delete_user_persona(
        &self,
        current_user: &User,
        persona_id: Uuid,
    ) -> Result<(), AppError> {
        let pool = self.db_pool.clone();

        // First, fetch to verify ownership before deleting
        let conn_fetch = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let persona_to_delete_opt = conn_fetch
            .interact(move |db_conn| {
                // Changed conn to db_conn
                user_personas_dsl::user_personas
                    .filter(user_personas_dsl::id.eq(persona_id))
                    .first::<UserPersona>(db_conn) // Changed conn to db_conn
                    .optional()
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for delete_user_persona (fetch): {e}"
                ))
            })??;

        match persona_to_delete_opt {
            Some(persona) => {
                if persona.user_id != current_user.id {
                    tracing::warn!(
                        current_user_id = %current_user.id,
                        target_persona_id = %persona.id,
                        target_persona_user_id = %persona.user_id,
                        "User attempted to delete a persona they do not own."
                    );
                    return Err(AppError::Forbidden(
                        "Access denied to delete user persona".to_string(),
                    ));
                }

                // Proceed with deletion
                // Get a new connection instance from the cloned pool for the delete interaction
                // pool was cloned at the start of the function.
                let conn_delete = self
                    .db_pool
                    .get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;
                let num_deleted = conn_delete
                    .interact(move |db_conn| {
                        // Changed conn to db_conn
                        diesel::delete(
                            user_personas_dsl::user_personas
                                .filter(user_personas_dsl::id.eq(persona_id)), // Ensure we use persona_id from outer scope
                        )
                        .execute(db_conn) // Changed conn to db_conn
                        .map_err(AppError::from)
                    })
                    .await
                    .map_err(|e| {
                        AppError::InternalServerErrorGeneric(format!(
                            "DB interact join error for delete_user_persona (delete): {e}"
                        ))
                    })??;

                if num_deleted == 0 {
                    // This case should ideally not be reached if the fetch & ownership check passed,
                    // unless there was a race condition (persona deleted between fetch and delete query).
                    tracing::warn!(user_id = %current_user.id, %persona_id, "Delete operation affected 0 rows, though persona was fetched and owned.");
                    Err(AppError::NotFound(format!(
                        "User persona with ID {persona_id} not found during delete, or already deleted."
                    )))
                } else {
                    tracing::info!(user_id = %current_user.id, %persona_id, "Successfully deleted user persona");
                    Ok(())
                }
            }
            None => Err(AppError::NotFound(format!(
                "User persona with ID {persona_id} not found for deletion."
            ))),
        }
    }

    #[tracing::instrument(skip(pool), err)]
    pub async fn set_default_persona(
        pool: &DbPool, // Changed to pass pool directly as it's a static-like method now
        user_id_val: Uuid,
        persona_id_val: Option<Uuid>,
    ) -> Result<User, AppError> {
        // Return the updated User
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let updated_user_db_query = conn
            .interact(move |db_conn| {
                diesel::update(users_dsl::users.find(user_id_val))
                    .set(users_dsl::default_persona_id.eq(persona_id_val))
                    .get_result::<UserDbQuery>(db_conn) // Fetch UserDbQuery
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for set_default_persona: {e}"
                ))
            })??;

        tracing::info!(user_id = %user_id_val, default_persona_id = ?persona_id_val, "Successfully set default persona for user");

        // Convert UserDbQuery to User before returning
        // This assumes User::from(UserDbQuery) handles DEK decryption or sets it to None appropriately.
        // If DEK is needed, it must be fetched and passed here. For now, assuming it's not needed for this response.
        Ok(User::from(updated_user_db_query))
    }

    // Helper to fetch a persona by ID and user ID, ensuring ownership.
    // This can be used by the route handler before calling set_default_persona.
    #[tracing::instrument(skip(pool), err)]
    pub async fn get_user_persona_by_id_and_user_id(
        pool: &DbPool,
        persona_id_val: Uuid,
        user_id_val: Uuid,
    ) -> Result<Option<UserPersona>, AppError> {
        debug!(%persona_id_val, %user_id_val, "Attempting to get user persona by ID and user ID");
        let conn = pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let persona_result = conn
            .interact(move |db_conn| {
                user_personas_dsl::user_personas
                    .filter(user_personas_dsl::id.eq(persona_id_val))
                    .filter(user_personas_dsl::user_id.eq(user_id_val))
                    .first::<UserPersona>(db_conn)
                    .optional()
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interact join error for get_user_persona_by_id_and_user_id: {e}"
                ))
            })??;

        debug!(
            ?persona_result,
            "Result of database query in get_user_persona_by_id_and_user_id"
        );
        Ok(persona_result)
    }
}

// TODO: Add unit tests for UserPersonaService methods
