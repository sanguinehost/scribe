use super::*;
use super::get_user_from_session;

impl LorebookService {
    pub async fn associate_lorebook_to_character(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        character_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        let user = get_user_from_session(auth_session)?;

        // Verify both character and lorebook belong to the user
        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // Check character ownership
        use crate::schema::characters;
        let character_exists = conn
            .interact(move |conn_sync| {
                characters::table
                    .filter(characters::id.eq(character_id))
                    .filter(characters::user_id.eq(user.id))
                    .count()
                    .get_result::<i64>(conn_sync)
                    .map(|count| count > 0)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        if !character_exists {
            return Err(AppError::NotFound(
                "Character not found or access denied".to_string(),
            ));
        }

        // Check lorebook ownership
        let lorebook_exists = conn
            .interact({
                let user_id = user.id;
                move |conn_sync| {
                    lorebooks::table
                        .filter(lorebooks::id.eq(lorebook_id))
                        .filter(lorebooks::user_id.eq(user_id))
                        .count()
                        .get_result::<i64>(conn_sync)
                        .map(|count| count > 0)
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        if !lorebook_exists {
            return Err(AppError::NotFound(
                "Lorebook not found or access denied".to_string(),
            ));
        }

        // Create association
        use crate::models::NewCharacterLorebook;
        use crate::schema::character_lorebooks;

        let new_association = NewCharacterLorebook {
            character_id,
            lorebook_id,
            user_id: user.id,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        conn.interact(move |conn_sync| {
            diesel::insert_into(character_lorebooks::table)
                .values(&new_association)
                .execute(conn_sync)
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(())
    }

    /// Lists all lorebooks associated with a character
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::NotFound` if the character doesn't exist,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn list_character_lorebooks(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        character_id: Uuid,
    ) -> Result<Vec<LorebookResponse>, AppError> {
        let user = get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebooks = conn
            .interact(move |conn_sync| {
                use crate::schema::character_lorebooks;

                character_lorebooks::table
                    .inner_join(
                        lorebooks::table.on(lorebooks::id.eq(character_lorebooks::lorebook_id)),
                    )
                    .filter(character_lorebooks::character_id.eq(character_id))
                    .filter(character_lorebooks::user_id.eq(user.id))
                    .select(Lorebook::as_select())
                    .load::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(lorebooks
            .into_iter()
            .map(|lb| LorebookResponse {
                id: lb.id,
                user_id: lb.user_id,
                name: lb.name,
                description: lb.description,
                source_format: lb.source_format,
                is_public: lb.is_public,
                created_at: lb.created_at,
                updated_at: lb.updated_at,
            })
            .collect())
    }

    /// Creates or updates a character lorebook override for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn set_character_lorebook_override(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
        lorebook_id: Uuid,
        action: String, // "disable" or "enable"
    ) -> Result<(), AppError> {
        let user = get_user_from_session(auth_session)?;
        let user_id = user.id;

        // Validate action
        if !matches!(action.as_str(), "disable" | "enable") {
            return Err(AppError::BadRequest(
                "Action must be 'disable' or 'enable'".to_string(),
            ));
        }

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let action_clone = action.clone();
        conn.interact(move |conn_sync| {
            use crate::schema::chat_character_lorebook_overrides::dsl;
            use diesel::upsert::excluded;

            // Use upsert to insert or update the override
            diesel::insert_into(dsl::chat_character_lorebook_overrides)
                .values(
                    &crate::models::lorebooks::NewChatCharacterLorebookOverride {
                        chat_session_id,
                        lorebook_id,
                        user_id,
                        action: action_clone,
                        created_at: None, // Use DB default
                        updated_at: None, // Use DB default
                    },
                )
                .on_conflict((dsl::chat_session_id, dsl::lorebook_id))
                .do_update()
                .set((
                    dsl::action.eq(excluded(dsl::action)),
                    dsl::updated_at.eq(excluded(dsl::updated_at)),
                ))
                .execute(conn_sync)
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
        .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        info!(
            "Successfully set character lorebook override for chat [REDACTED_UUID], lorebook [REDACTED_UUID], action: {}",
            action
        );
        Ok(())
    }

    /// Removes a character lorebook override for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn remove_character_lorebook_override(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        let user = get_user_from_session(auth_session)?;
        let user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let rows_deleted = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_character_lorebook_overrides::dsl;
                diesel::delete(
                    dsl::chat_character_lorebook_overrides
                        .filter(dsl::chat_session_id.eq(chat_session_id))
                        .filter(dsl::lorebook_id.eq(lorebook_id))
                        .filter(dsl::user_id.eq(user_id)),
                )
                .execute(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        if rows_deleted == 0 {
            return Err(AppError::NotFound(
                "Character lorebook override not found".to_string(),
            ));
        }

        info!(
            "Successfully removed character lorebook override for chat [REDACTED_UUID], lorebook [REDACTED_UUID]"
        );
        Ok(())
    }

    /// Gets all character lorebook overrides for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn get_character_lorebook_overrides(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
    ) -> Result<Vec<crate::models::lorebooks::ChatCharacterLorebookOverride>, AppError> {
        let user = get_user_from_session(auth_session)?;
        let user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let overrides = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_character_lorebook_overrides::dsl;
                dsl::chat_character_lorebook_overrides
                    .filter(dsl::chat_session_id.eq(chat_session_id))
                    .filter(dsl::user_id.eq(user_id))
                    .select(crate::models::lorebooks::ChatCharacterLorebookOverride::as_select())
                    .load::<crate::models::lorebooks::ChatCharacterLorebookOverride>(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        Ok(overrides)
    }
}
