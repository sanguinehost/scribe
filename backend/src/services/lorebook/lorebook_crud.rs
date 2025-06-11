use super::*;
use super::get_user_from_session;

impl LorebookService {
    /// Creates a new lorebook for the authenticated user.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur,
    /// database-related errors if the lorebook insertion fails.
    #[instrument(skip(self, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn create_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>, // Changed to AuthBackend
        payload: CreateLorebookPayload,
    ) -> Result<LorebookResponse, AppError> {
        debug!(?payload, "Attempting to create lorebook");
        let user = get_user_from_session(auth_session)?;

        let new_lorebook_id = Uuid::new_v4();
        let current_time = Utc::now();

        let new_lorebook_db = crate::models::NewLorebook {
            id: new_lorebook_id,
            user_id: user.id,
            name: payload.name,
            description: payload.description,
            source_format: "scribe_v1".to_string(), // Default for API created
            is_public: false,                       // Default to private
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let inserted_lorebook = conn
            .interact(move |conn_sync| {
                diesel::insert_into(lorebooks::table)
                    .values(&new_lorebook_db)
                    .returning(Lorebook::as_returning()) // Specify returning columns
                    .get_result::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while inserting lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while creating lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to insert lorebook into DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to create lorebook in DB: {e}"
                ))
            })?;

        info!("Successfully created lorebook [REDACTED_UUID] for user [REDACTED_UUID]");

        Ok(LorebookResponse {
            id: inserted_lorebook.id,
            user_id: inserted_lorebook.user_id,
            name: inserted_lorebook.name,
            description: inserted_lorebook.description,
            source_format: inserted_lorebook.source_format,
            is_public: inserted_lorebook.is_public,
            created_at: inserted_lorebook.created_at,
            updated_at: inserted_lorebook.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn list_lorebooks(
        &self,
        auth_session: &AuthSession<AuthBackend>,
    ) -> Result<Vec<LorebookResponse>, AppError> {
        debug!("Attempting to list lorebooks");
        let user = get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebooks_db = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::user_id.eq(user.id))
                    .order(lorebooks::updated_at.desc()) // Or by name, or created_at
                    .select(Lorebook::as_select()) // Ensure selected columns match the struct
                    .load::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while listing lorebooks: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while listing lorebooks: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to list lorebooks from DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to list lorebooks from DB: {e}"
                ))
            })?;

        let lorebook_responses = lorebooks_db
            .into_iter()
            .map(|lb| LorebookResponse {
                id: lb.id,
                user_id: lb.user_id,
                name: lb.name,               // No decryption needed for Lorebook name
                description: lb.description, // No decryption needed for Lorebook description
                source_format: lb.source_format,
                is_public: lb.is_public,
                created_at: lb.created_at,
                updated_at: lb.updated_at,
            })
            .collect();

        Ok(lorebook_responses)
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn get_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
    ) -> Result<LorebookResponse, AppError> {
        debug!(%lorebook_id, "Attempting to get lorebook");
        let user = get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebook_db = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional() // Makes it return Result<Option<Lorebook>, _>
            })
            .await
            .map_err(|e| {
                error!("Interaction error while getting lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while getting lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to get lorebook from DB: {:?}", e);
                // This specific error might indicate a problem beyond just "not found"
                // but for now, we'll let the None case handle typical not found.
                AppError::DatabaseQueryError(e.to_string())
            })?;

        match lorebook_db {
            Some(lb) => {
                if lb.user_id != user.id {
                    // If the lorebook exists but belongs to another user, treat as Not Found
                    // to avoid leaking information about resource existence.
                    // Alternatively, could return AppError::Forbidden.
                    error!(
                        "User [REDACTED_UUID] attempted to access lorebook [REDACTED_UUID] owned by user [REDACTED_UUID]"
                    );
                    return Err(AppError::NotFound(format!(
                        "Lorebook with ID {lorebook_id} not found."
                    )));
                }
                Ok(LorebookResponse {
                    id: lb.id,
                    user_id: lb.user_id,
                    name: lb.name,
                    description: lb.description,
                    source_format: lb.source_format,
                    is_public: lb.is_public,
                    created_at: lb.created_at,
                    updated_at: lb.updated_at,
                })
            }
            None => Err(AppError::NotFound(format!(
                "Lorebook with ID {lorebook_id} not found."
            ))),
        }
    }

    #[instrument(skip(self, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn update_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
        payload: UpdateLorebookPayload,
    ) -> Result<LorebookResponse, AppError> {
        debug!(?payload, "Attempting to update lorebook");

        // 1. Get current user
        let user = get_user_from_session(auth_session)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // 2. Fetch lorebook by id and check ownership
        let updated_lorebook = conn
            .interact(move |conn| {
                use crate::schema::lorebooks::dsl::{
                    description, id, lorebooks, name, updated_at, user_id,
                };

                // First verify the lorebook exists and belongs to the user
                let existing_lorebook = lorebooks
                    .filter(id.eq(lorebook_id))
                    .filter(user_id.eq(user.id))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                if let Some(existing) = existing_lorebook {
                    // User owns this lorebook, proceed with update
                    // Build the update dynamically based on what fields are provided
                    let update_query = diesel::update(lorebooks.filter(id.eq(lorebook_id)));

                    // Only update fields that are provided (Some)
                    let new_name = payload.name.unwrap_or(existing.name);
                    let new_description = payload.description.or(existing.description);

                    let _rows_updated = update_query
                        .set((
                            name.eq(new_name),
                            description.eq(new_description),
                            updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Fetch the updated lorebook with proper column ordering
                    let updated = lorebooks
                        .filter(id.eq(lorebook_id))
                        .select(Lorebook::as_select())
                        .first::<Lorebook>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    tracing::info!(
                        "Successfully updated lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
                    );
                    Ok(updated)
                } else {
                    // Check if lorebook exists but belongs to another user
                    let exists = lorebooks
                        .filter(id.eq(lorebook_id))
                        .select(id)
                        .first::<Uuid>(conn)
                        .optional()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    if exists.is_some() {
                        Err(AppError::Forbidden("Access denied to lorebook".to_string()))
                    } else {
                        Err(AppError::NotFound("Lorebook not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))??;

        // 6. Map to LorebookResponse
        Ok(LorebookResponse {
            id: updated_lorebook.id,
            user_id: updated_lorebook.user_id,
            name: updated_lorebook.name,
            description: updated_lorebook.description,
            source_format: updated_lorebook.source_format,
            is_public: updated_lorebook.is_public,
            created_at: updated_lorebook.created_at,
            updated_at: updated_lorebook.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn delete_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        debug!("Attempting to delete lorebook");

        // 1. Get current user
        let user = get_user_from_session(auth_session)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // 2. Delete lorebook and verify ownership in a single transaction

        // Perform database deletion first
        conn
            .interact(move |conn| {
                use crate::schema::lorebooks::dsl::{id, lorebooks, user_id};

                // First verify the lorebook exists and belongs to the user
                let lorebook_owner = lorebooks
                    .filter(id.eq(lorebook_id))
                    .select(user_id)
                    .first::<Uuid>(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                match lorebook_owner {
                    Some(owner_id) if owner_id == user.id => {
                        // User owns this lorebook
                        // Due to foreign key constraints with CASCADE DELETE,
                        // deleting the lorebook will automatically delete:
                        // - All lorebook_entries
                        // - All chat_session_lorebooks associations

                        diesel::delete(
                            lorebooks
                                .filter(id.eq(lorebook_id))
                                .filter(user_id.eq(user.id)),
                        )
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                        tracing::info!(
                            "Successfully deleted lorebook [REDACTED_UUID] from database for user [REDACTED_UUID]"
                        );
                        Ok(())
                    }
                    Some(_) => {
                        // Lorebook exists but belongs to another user
                        Err(AppError::Forbidden("Access denied to lorebook".to_string()))
                    }
                    None => {
                        // Lorebook doesn't exist
                        Err(AppError::NotFound("Lorebook not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))??; // Propagate the error

        // After successful database deletion, clean up vector embeddings
        tracing::info!(
            "Cleaning up vector embeddings for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
        );

        let vector_filter = Filter {
            must: vec![
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "lorebook_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(lorebook_id.to_string())),
                        }),
                        ..Default::default()
                    })),
                },
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "user_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(user.id.to_string())),
                        }),
                        ..Default::default()
                    })),
                },
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "source_type".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                        }),
                        ..Default::default()
                    })),
                },
            ],
            ..Default::default()
        };

        // Delete vector embeddings
        if let Err(e) = self
            .qdrant_service
            .delete_points_by_filter(vector_filter)
            .await
        {
            // Log the error but don't fail the entire operation since DB deletion succeeded
            error!(
                error = %e,
                lorebook_id = "[REDACTED_UUID]",
                user_id = "[REDACTED_UUID]",
                "Failed to delete vector embeddings for lorebook, but database deletion succeeded"
            );
        } else {
            tracing::info!(
                "Successfully deleted vector embeddings for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
            );
        }

        tracing::info!(
            "Successfully completed full deletion (database + vectors) for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
        );

        Ok(())
    }

}
