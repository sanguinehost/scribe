use super::get_user_from_session;
use super::*;
#[cfg(feature = "sqlite-backend")]
use crate::db::pool_helpers::{SqliteInteractExt, SqlitePoolExt};

impl LorebookService {
    pub async fn associate_lorebook_to_character(
        &self,
        auth: &UnifiedAuth,
        character_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        let user = get_user_from_unified_auth(auth)?;

        // Check character ownership
        use crate::schema::characters;
        let character_exists = crate::db::with_conn(&self.pool, move |conn_sync| {
            characters::table
                .filter(characters::id.eq(character_id))
                .filter(characters::user_id.eq(user.id))
                .count()
                .get_result::<i64>(conn_sync)
                .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
                .map(|count| count > 0)
        })
        .await?;

        if !character_exists {
            return Err(AppError::NotFound(
                "Character not found or access denied".to_string(),
            ));
        }

        // Check lorebook ownership
        let lorebook_exists = crate::db::with_conn(&self.pool, {
            let user_id = user.id;
            move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id))
                    .filter(lorebooks::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn_sync)
                    .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
                    .map(|count| count > 0)
            }
        })
        .await?;

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
            created_at: Some(Utc::now().into()),
            updated_at: Some(Utc::now().into()),
        };

        crate::db::with_conn(&self.pool, move |conn_sync| {
            diesel::insert_into(character_lorebooks::table)
                .values(&new_association)
                .execute(conn_sync)
                .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        Ok(())
    }

    /// Lists all lorebooks associated with a character
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::NotFound` if the character doesn't exist,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth), fields(user_id = ?auth.user().map(|u| u.id)))]
    pub async fn list_character_lorebooks(
        &self,
        auth: &UnifiedAuth,
        character_id: crate::db::DbId,
    ) -> Result<Vec<LorebookResponse>, AppError> {
        let user = get_user_from_unified_auth(auth)?;

        let lorebooks = crate::db::with_conn(&self.pool, move |conn_sync| {
            use crate::schema::character_lorebooks;

            character_lorebooks::table
                .inner_join(lorebooks::table.on(lorebooks::id.eq(character_lorebooks::lorebook_id)))
                .filter(character_lorebooks::character_id.eq(character_id))
                .filter(character_lorebooks::user_id.eq(user.id))
                .select(Lorebook::as_select())
                .load::<Lorebook>(conn_sync)
                .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

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
    #[instrument(skip(self, auth), fields(user_id = ?auth.user().map(|u| u.id)))]
    pub async fn set_character_lorebook_override(
        &self,
        auth: &UnifiedAuth,
        chat_session_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
        action: String, // "disable" or "enable"
    ) -> Result<(), AppError> {
        let user = get_user_from_unified_auth(auth)?;
        let user_id = user.id;

        // Validate action
        if !matches!(action.as_str(), "disable" | "enable") {
            return Err(AppError::BadRequest(
                "Action must be 'disable' or 'enable'".to_string(),
            ));
        }

        let action_clone = action.clone();
        crate::db::with_conn(&self.pool, move |conn_sync| {
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
                .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        info!(
            "Successfully set character lorebook override for chat [REDACTED_UUID], lorebook [REDACTED_UUID], action: {}",
            action
        );
        Ok(())
    }

    /// Removes a character lorebook override for a specific chat session
    #[instrument(skip(self, auth), fields(user_id = ?auth.user().map(|u| u.id)))]
    pub async fn remove_character_lorebook_override(
        &self,
        auth: &UnifiedAuth,
        chat_session_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        let user = get_user_from_unified_auth(auth)?;
        let user_id = user.id;

        let rows_deleted = crate::db::with_conn(&self.pool, move |conn_sync| {
            use crate::schema::chat_character_lorebook_overrides::dsl;
            diesel::delete(
                dsl::chat_character_lorebook_overrides
                    .filter(dsl::chat_session_id.eq(chat_session_id))
                    .filter(dsl::lorebook_id.eq(lorebook_id))
                    .filter(dsl::user_id.eq(user_id)),
            )
            .execute(conn_sync)
            .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

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
    #[instrument(skip(self, auth), fields(user_id = ?auth.user().map(|u| u.id)))]
    pub async fn get_character_lorebook_overrides(
        &self,
        auth: &UnifiedAuth,
        chat_session_id: crate::db::DbId,
    ) -> Result<Vec<crate::models::lorebooks::ChatCharacterLorebookOverride>, AppError> {
        let user = get_user_from_unified_auth(auth)?;
        let user_id = user.id;

        let overrides = crate::db::with_conn(&self.pool, move |conn_sync| {
            use crate::schema::chat_character_lorebook_overrides::dsl;
            dsl::chat_character_lorebook_overrides
                .filter(dsl::chat_session_id.eq(chat_session_id))
                .filter(dsl::user_id.eq(user_id))
                .load::<crate::models::lorebooks::ChatCharacterLorebookOverride>(conn_sync)
                .map_err(|e: diesel::result::Error| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        Ok(overrides)
    }
}
