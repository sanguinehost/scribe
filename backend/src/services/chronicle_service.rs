use deadpool_diesel::postgres::Pool as DeadpoolPgPool;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper,
    result::Error as DieselError, OptionalExtension,
};
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::chronicle::{
    PlayerChronicle, NewPlayerChronicle, UpdatePlayerChronicle, PlayerChronicleWithCounts,
    CreateChronicleRequest, UpdateChronicleRequest,
};
use crate::models::chronicle_event::{
    ChronicleEvent, NewChronicleEvent, EventFilter, EventOrderBy,
    CreateEventRequest,
};
use crate::services::{ChronicleDeduplicationService, DeduplicationConfig};
use crate::schema::{player_chronicles, chronicle_events, chat_sessions};

/// ChronicleService handles all Chronicle-related database operations
#[derive(Clone)]
pub struct ChronicleService {
    db_pool: DeadpoolPgPool,
}

impl ChronicleService {
    #[must_use]
    pub fn new(db_pool: DeadpoolPgPool) -> Self {
        Self { db_pool }
    }

    // --- Chronicle CRUD Operations ---

    /// Create a new chronicle for a user
    #[instrument(skip(self), fields(user_id = %user_id, name = %request.name))]
    pub async fn create_chronicle(
        &self,
        user_id: Uuid,
        request: CreateChronicleRequest,
    ) -> Result<PlayerChronicle, AppError> {
        let mut new_chronicle: NewPlayerChronicle = request.into();
        new_chronicle.user_id = user_id;

        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let chronicle = conn
            .interact(move |conn| {
                diesel::insert_into(player_chronicles::table)
                    .values(&new_chronicle)
                    .returning(PlayerChronicle::as_returning())
                    .get_result(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when creating chronicle: {}", e);
                AppError::DbInteractError(format!("Failed to create chronicle: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when creating chronicle: {}", e);
                match e {
                    DieselError::DatabaseError(_, ref info) => {
                        if info.message().contains("duplicate") || info.message().contains("unique") {
                            AppError::Conflict("A chronicle with this name already exists".to_string())
                        } else {
                            AppError::DatabaseQueryError(format!("Failed to create chronicle: {e}"))
                        }
                    }
                    _ => AppError::DatabaseQueryError(format!("Failed to create chronicle: {e}")),
                }
            })?;

        info!("Created chronicle {} for user {}", chronicle.id, user_id);
        Ok(chronicle)
    }

    /// Get all chronicles for a user
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn get_user_chronicles(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PlayerChronicle>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let chronicles = conn
            .interact(move |conn| {
                player_chronicles::table
                    .filter(player_chronicles::user_id.eq(user_id))
                    .order(player_chronicles::updated_at.desc())
                    .select(PlayerChronicle::as_select())
                    .load(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting user chronicles: {}", e);
                AppError::DbInteractError(format!("Failed to get chronicles: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting user chronicles: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get chronicles: {e}"))
            })?;

        info!("Retrieved {} chronicles for user {}", chronicles.len(), user_id);
        Ok(chronicles)
    }

    /// Get chronicles with event and chat session counts
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn get_user_chronicles_with_counts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PlayerChronicleWithCounts>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let results = conn
            .interact(move |conn| {
                // Note: This query might need optimization with proper joins
                // For now, we'll get chronicles and then count separately
                let chronicles: Vec<PlayerChronicle> = player_chronicles::table
                    .filter(player_chronicles::user_id.eq(user_id))
                    .order(player_chronicles::updated_at.desc())
                    .select(PlayerChronicle::as_select())
                    .load(conn)?;

                let mut chronicles_with_counts = Vec::new();

                for chronicle in chronicles {
                    // Count events
                    let event_count: i64 = chronicle_events::table
                        .filter(chronicle_events::chronicle_id.eq(chronicle.id))
                        .count()
                        .get_result(conn)?;

                    // Count linked chat sessions
                    let chat_session_count: i64 = chat_sessions::table
                        .filter(chat_sessions::player_chronicle_id.eq(chronicle.id))
                        .count()
                        .get_result(conn)?;

                    chronicles_with_counts.push(PlayerChronicleWithCounts {
                        chronicle,
                        event_count,
                        chat_session_count,
                    });
                }

                Ok::<Vec<PlayerChronicleWithCounts>, DieselError>(chronicles_with_counts)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting chronicles with counts: {}", e);
                AppError::DbInteractError(format!("Failed to get chronicles with counts: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting chronicles with counts: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get chronicles with counts: {e}"))
            })?;

        info!("Retrieved {} chronicles with counts for user {}", results.len(), user_id);
        Ok(results)
    }

    /// Get a specific chronicle by ID, ensuring user ownership
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn get_chronicle(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<PlayerChronicle, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let chronicle = conn
            .interact(move |conn| {
                player_chronicles::table
                    .filter(
                        player_chronicles::id.eq(chronicle_id)
                            .and(player_chronicles::user_id.eq(user_id))
                    )
                    .select(PlayerChronicle::as_select())
                    .first(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting chronicle: {}", e);
                AppError::DbInteractError(format!("Failed to get chronicle: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting chronicle: {}", e);
                match e {
                    DieselError::NotFound => AppError::NotFound("Chronicle not found".to_string()),
                    _ => AppError::DatabaseQueryError(format!("Failed to get chronicle: {e}")),
                }
            })?;

        info!("Retrieved chronicle {} for user {}", chronicle_id, user_id);
        Ok(chronicle)
    }

    /// Update a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn update_chronicle(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        request: UpdateChronicleRequest,
    ) -> Result<PlayerChronicle, AppError> {
        let update: UpdatePlayerChronicle = request.into();
        
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let chronicle = conn
            .interact(move |conn| {
                let target = player_chronicles::table.filter(
                    player_chronicles::id.eq(chronicle_id)
                        .and(player_chronicles::user_id.eq(user_id))
                );

                // Use pattern matching to handle the different update combinations
                match (&update.name, &update.description) {
                    (Some(name), Some(description)) => {
                        diesel::update(target)
                            .set((
                                player_chronicles::name.eq(name),
                                player_chronicles::description.eq(description),
                                player_chronicles::updated_at.eq(diesel::dsl::now)
                            ))
                            .returning(PlayerChronicle::as_returning())
                            .get_result(conn)
                    }
                    (Some(name), None) => {
                        diesel::update(target)
                            .set((
                                player_chronicles::name.eq(name),
                                player_chronicles::updated_at.eq(diesel::dsl::now)
                            ))
                            .returning(PlayerChronicle::as_returning())
                            .get_result(conn)
                    }
                    (None, Some(description)) => {
                        diesel::update(target)
                            .set((
                                player_chronicles::description.eq(description),
                                player_chronicles::updated_at.eq(diesel::dsl::now)
                            ))
                            .returning(PlayerChronicle::as_returning())
                            .get_result(conn)
                    }
                    (None, None) => {
                        // Only update the timestamp
                        diesel::update(target)
                            .set(player_chronicles::updated_at.eq(diesel::dsl::now))
                            .returning(PlayerChronicle::as_returning())
                            .get_result(conn)
                    }
                }
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when updating chronicle: {}", e);
                AppError::DbInteractError(format!("Failed to update chronicle: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when updating chronicle: {}", e);
                match e {
                    DieselError::NotFound => AppError::NotFound("Chronicle not found".to_string()),
                    _ => AppError::DatabaseQueryError(format!("Failed to update chronicle: {e}")),
                }
            })?;

        info!("Updated chronicle {} for user {}", chronicle_id, user_id);
        Ok(chronicle)
    }

    /// Delete a chronicle and all its events
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn delete_chronicle(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<(), AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let deleted_count = conn
            .interact(move |conn| {
                // Note: chronicle_events will be deleted by CASCADE
                diesel::delete(
                    player_chronicles::table.filter(
                        player_chronicles::id.eq(chronicle_id)
                            .and(player_chronicles::user_id.eq(user_id))
                    )
                )
                .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when deleting chronicle: {}", e);
                AppError::DbInteractError(format!("Failed to delete chronicle: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when deleting chronicle: {}", e);
                AppError::DatabaseQueryError(format!("Failed to delete chronicle: {e}"))
            })?;

        if deleted_count == 0 {
            return Err(AppError::NotFound("Chronicle not found".to_string()));
        }

        info!("Deleted chronicle {} for user {}", chronicle_id, user_id);
        Ok(())
    }

    // --- Event Operations ---

    /// Create a new event in a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id, event_type = %request.event_type))]
    pub async fn create_event(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        request: CreateEventRequest,
        session_dek: Option<&crate::auth::session_dek::SessionDek>,
    ) -> Result<ChronicleEvent, AppError> {
        // First verify chronicle ownership
        self.get_chronicle(user_id, chronicle_id).await?;

        let mut new_event: NewChronicleEvent = request.into();
        new_event.chronicle_id = chronicle_id;
        new_event.user_id = user_id;

        // Encrypt the summary and keywords if DEK is provided
        if let Some(dek) = session_dek {
            // Encrypt summary
            let summary_bytes = new_event.summary.as_bytes();
            match crate::crypto::encrypt_gcm(summary_bytes, &dek.0) {
                Ok((ciphertext, nonce)) => {
                    new_event.summary_encrypted = Some(ciphertext);
                    new_event.summary_nonce = Some(nonce);
                    // Replace plaintext with placeholder - we MUST NOT store actual plaintext in the database
                    new_event.summary = "[ENCRYPTED]".to_string();
                    tracing::debug!(event_type = %new_event.event_type, "Encrypted chronicle event summary");
                }
                Err(e) => {
                    error!(error = %e, event_type = %new_event.event_type, "Failed to encrypt chronicle event summary");
                    return Err(AppError::CryptoError(format!("Failed to encrypt event summary: {}", e)));
                }
            }
            
            // Encrypt keywords if present
            if let Some(ref keywords_vec) = new_event.keywords {
                // Convert Vec<Option<String>> to Vec<String> for serialization
                let keywords: Vec<String> = keywords_vec.iter()
                    .filter_map(|opt| opt.clone())
                    .collect();
                
                if !keywords.is_empty() {
                    let keywords_json = serde_json::to_string(&keywords)
                        .map_err(|e| AppError::SerializationError(format!("Failed to serialize keywords: {}", e)))?;
                    
                    match crate::crypto::encrypt_gcm(keywords_json.as_bytes(), &dek.0) {
                        Ok((ciphertext, nonce)) => {
                            new_event.keywords_encrypted = Some(ciphertext);
                            new_event.keywords_nonce = Some(nonce);
                            // Clear plaintext keywords - we MUST NOT store plaintext in the database
                            new_event.keywords = Some(vec![Some("[ENCRYPTED]".to_string())]);
                            tracing::debug!(event_type = %new_event.event_type, "Encrypted chronicle event keywords");
                        }
                        Err(e) => {
                            error!(error = %e, event_type = %new_event.event_type, "Failed to encrypt chronicle event keywords");
                            // Don't fail if keyword encryption fails - keywords are optional
                            tracing::warn!("Continuing without encrypted keywords");
                        }
                    }
                }
            }
        }

        // Create temporary event for deduplication check
        let temp_event = ChronicleEvent {
            id: Uuid::new_v4(), // Temporary ID
            chronicle_id: new_event.chronicle_id,
            user_id: new_event.user_id,
            event_type: new_event.event_type.clone(),
            summary: new_event.summary.clone(),
            source: new_event.source.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            summary_encrypted: new_event.summary_encrypted.clone(),
            summary_nonce: new_event.summary_nonce.clone(),
            timestamp_iso8601: new_event.timestamp_iso8601,
            keywords: new_event.keywords.clone(),
            keywords_encrypted: new_event.keywords_encrypted.clone(),
            keywords_nonce: new_event.keywords_nonce.clone(),
            chat_session_id: new_event.chat_session_id,
        };

        // Check for duplicates before inserting
        let dedup_service = ChronicleDeduplicationService::new(self.db_pool.clone(), None);
        // Removed debug output
        match dedup_service.check_for_duplicates(&temp_event).await {
            Ok(duplicate_result) => {
                tracing::debug!(
                    "Duplicate check result: is_duplicate={}, confidence={}, reasoning={}",
                    duplicate_result.is_duplicate,
                    duplicate_result.confidence,
                    duplicate_result.reasoning
                );
                if duplicate_result.is_duplicate {
                    tracing::warn!(
                        event_id = %temp_event.id,
                        duplicate_id = ?duplicate_result.duplicate_event_id,
                        confidence = duplicate_result.confidence,
                        reasoning = %duplicate_result.reasoning,
                        "Duplicate event detected, skipping creation"
                    );
                    
                    // Return the existing duplicate event instead of creating a new one
                    if let Some(duplicate_id) = duplicate_result.duplicate_event_id {
                        tracing::debug!("Returning existing duplicate event: {}", duplicate_id);
                        return self.get_event(user_id, duplicate_id).await;
                    }
                }
            }
            Err(e) => {
                // Log the error but don't fail the event creation
                tracing::warn!(error = %e, "Failed to check for duplicates, proceeding with event creation");
            }
        }

        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let event = conn
            .interact(move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&new_event)
                    .returning(ChronicleEvent::as_returning())
                    .get_result(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when creating event: {}", e);
                AppError::DbInteractError(format!("Failed to create event: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when creating event: {}", e);
                AppError::DatabaseQueryError(format!("Failed to create event: {e}"))
            })?;

        info!("Created event {} in chronicle {} for user {}", event.id, chronicle_id, user_id);
        Ok(event)
    }

    /// Get events for a chronicle with filtering
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn get_chronicle_events(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        filter: EventFilter,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        // First verify chronicle ownership
        self.get_chronicle(user_id, chronicle_id).await?;

        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let events = conn
            .interact(move |conn| {
                let mut query = chronicle_events::table
                    .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                    .into_boxed();

                // Apply filters
                if let Some(event_type) = filter.event_type {
                    query = query.filter(chronicle_events::event_type.eq(event_type));
                }

                if let Some(source) = filter.source {
                    query = query.filter(chronicle_events::source.eq(source.to_string()));
                }

                // Apply ordering
                match filter.order_by.unwrap_or(EventOrderBy::CreatedAtDesc) {
                    EventOrderBy::CreatedAtAsc => query = query.order(chronicle_events::created_at.asc()),
                    EventOrderBy::CreatedAtDesc => query = query.order(chronicle_events::created_at.desc()),
                    EventOrderBy::UpdatedAtAsc => query = query.order(chronicle_events::updated_at.asc()),
                    EventOrderBy::UpdatedAtDesc => query = query.order(chronicle_events::updated_at.desc()),
                    EventOrderBy::TimestampAsc => query = query.order(chronicle_events::timestamp_iso8601.asc()),
                    EventOrderBy::TimestampDesc => query = query.order(chronicle_events::timestamp_iso8601.desc()),
                }

                // Apply pagination
                if let Some(offset) = filter.offset {
                    query = query.offset(offset);
                }

                if let Some(limit) = filter.limit {
                    query = query.limit(limit);
                }

                query.select(ChronicleEvent::as_select()).load(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting events: {}", e);
                AppError::DbInteractError(format!("Failed to get events: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting events: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get events: {e}"))
            })?;

        info!("Retrieved {} events for chronicle {} for user {}", events.len(), chronicle_id, user_id);
        Ok(events)
    }

    /// Get a specific event
    #[instrument(skip(self), fields(user_id = %user_id, event_id = %event_id))]
    pub async fn get_event(
        &self,
        user_id: Uuid,
        event_id: Uuid,
    ) -> Result<ChronicleEvent, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let event = conn
            .interact(move |conn| {
                chronicle_events::table
                    .filter(
                        chronicle_events::id.eq(event_id)
                            .and(chronicle_events::user_id.eq(user_id))
                    )
                    .select(ChronicleEvent::as_select())
                    .first(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting event: {}", e);
                AppError::DbInteractError(format!("Failed to get event: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting event: {}", e);
                match e {
                    DieselError::NotFound => AppError::NotFound("Event not found".to_string()),
                    _ => AppError::DatabaseQueryError(format!("Failed to get event: {e}")),
                }
            })?;

        info!("Retrieved event {} for user {}", event_id, user_id);
        Ok(event)
    }

    /// Delete an event
    #[instrument(skip(self), fields(user_id = %user_id, event_id = %event_id))]
    pub async fn delete_event(
        &self,
        user_id: Uuid,
        event_id: Uuid,
    ) -> Result<(), AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let deleted_count = conn
            .interact(move |conn| {
                diesel::delete(
                    chronicle_events::table.filter(
                        chronicle_events::id.eq(event_id)
                            .and(chronicle_events::user_id.eq(user_id))
                    )
                )
                .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when deleting event: {}", e);
                AppError::DbInteractError(format!("Failed to delete event: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when deleting event: {}", e);
                AppError::DatabaseQueryError(format!("Failed to delete event: {e}"))
            })?;

        if deleted_count == 0 {
            return Err(AppError::NotFound("Event not found".to_string()));
        }

        info!("Deleted event {} for user {}", event_id, user_id);
        Ok(())
    }

    /// Get all events for a specific chat session (for cleanup purposes)
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id))]
    pub async fn get_events_for_chat_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let events = conn
            .interact(move |conn| {
                chronicle_events::table
                    .filter(
                        chronicle_events::user_id.eq(user_id)
                            .and(chronicle_events::chat_session_id.eq(Some(session_id)))
                    )
                    .select(ChronicleEvent::as_select())
                    .load(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting events for chat session: {}", e);
                AppError::DbInteractError(format!("Failed to get events for chat session: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting events for chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get events for chat session: {e}"))
            })?;

        info!("Retrieved {} events for chat session {} for user {}", events.len(), session_id, user_id);
        Ok(events)
    }

    /// Delete all events associated with a chat session (for chat deletion cleanup)
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id))]
    pub async fn delete_events_for_chat_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<usize, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let deleted_count = conn
            .interact(move |conn| {
                diesel::delete(
                    chronicle_events::table.filter(
                        chronicle_events::user_id.eq(user_id)
                            .and(chronicle_events::chat_session_id.eq(Some(session_id)))
                    )
                )
                .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when deleting events for chat session: {}", e);
                AppError::DbInteractError(format!("Failed to delete events for chat session: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when deleting events for chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to delete events for chat session: {e}"))
            })?;

        info!("Deleted {} events for chat session {} for user {}", deleted_count, session_id, user_id);
        Ok(deleted_count)
    }

    /// Link a chat session to a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id, chronicle_id = %chronicle_id))]
    pub async fn link_chat_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<(), AppError> {
        // First verify chronicle ownership
        self.get_chronicle(user_id, chronicle_id).await?;

        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let updated_count = conn
            .interact(move |conn| {
                diesel::update(
                    chat_sessions::table.filter(
                        chat_sessions::id.eq(session_id)
                            .and(chat_sessions::user_id.eq(user_id))
                    )
                )
                .set(chat_sessions::player_chronicle_id.eq(Some(chronicle_id)))
                .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when linking chat session: {}", e);
                AppError::DbInteractError(format!("Failed to link chat session: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when linking chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to link chat session: {e}"))
            })?;

        if updated_count == 0 {
            return Err(AppError::NotFound("Chat session not found".to_string()));
        }

        info!("Linked chat session {} to chronicle {} for user {}", session_id, chronicle_id, user_id);
        Ok(())
    }

    /// Get the character name for a chat session
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_chat_session_character_name(
        &self,
        session_id: Uuid,
    ) -> Result<Option<String>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        // First get the character_id from the chat session
        let character_id: Option<Uuid> = conn
            .interact(move |conn| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .select(chat_sessions::character_id)
                    .first::<Option<Uuid>>(conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting character_id: {}", e);
                AppError::DbInteractError(format!("Failed to get character_id: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting character_id: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get character_id: {e}"))
            })?
            .flatten();

        // If we have a character_id, get the character name
        let character_name = if let Some(char_id) = character_id {
            let conn = self.db_pool.get().await.map_err(|e| {
                error!("Failed to get database connection: {}", e);
                AppError::DbPoolError(format!("Connection pool error: {e}"))
            })?;
            
            conn.interact(move |conn| {
                use crate::schema::characters;
                
                characters::table
                    .filter(characters::id.eq(char_id))
                    .select(characters::name)
                    .first::<String>(conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting character name: {}", e);
                AppError::DbInteractError(format!("Failed to get character name: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting character name: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get character name: {e}"))
            })?
        } else {
            None
        };

        info!("Chat session {} has character_name: {:?}", session_id, character_name);
        Ok(character_name)
    }

    /// Get the chronicle ID linked to a chat session
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_chat_session_chronicle(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Uuid>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let chronicle_id = conn
            .interact(move |conn| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .select(chat_sessions::player_chronicle_id)
                    .first::<Option<Uuid>>(conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when getting chat session chronicle: {}", e);
                AppError::DbInteractError(format!("Failed to get chat session chronicle: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when getting chat session chronicle: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get chat session chronicle: {e}"))
            })?
            .flatten();

        info!("Chat session {} has chronicle_id: {:?}", session_id, chronicle_id);
        Ok(chronicle_id)
    }

    /// Unlink a chat session from a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id))]
    pub async fn unlink_chat_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let updated_count = conn
            .interact(move |conn| {
                diesel::update(
                    chat_sessions::table.filter(
                        chat_sessions::id.eq(session_id)
                            .and(chat_sessions::user_id.eq(user_id))
                    )
                )
                .set(chat_sessions::player_chronicle_id.eq(None::<Uuid>))
                .execute(conn)
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when unlinking chat session: {}", e);
                AppError::DbInteractError(format!("Failed to unlink chat session: {e}"))
            })?
            .map_err(|e| {
                error!("Diesel error when unlinking chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to unlink chat session: {e}"))
            })?;

        if updated_count == 0 {
            return Err(AppError::NotFound("Chat session not found".to_string()));
        }

        info!("Unlinked chat session {} from chronicle for user {}", session_id, user_id);
        Ok(())
    }

    /// Get analysis information for chat deletion decisions
    /// Returns chronicle details including event counts and relationships
    #[instrument(skip(self), fields(user_id = %user_id, chat_session_id = %chat_session_id))]
    pub async fn get_chat_deletion_analysis(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
    ) -> Result<Option<ChronicleAnalysisInfo>, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let analysis = conn
            .interact(move |conn| -> Result<Option<ChronicleAnalysisInfo>, AppError> {
                use crate::schema::{chat_sessions, chronicle_events, player_chronicles};
                use diesel::dsl::count;

                // First, get the chronicle ID from the chat session
                let chronicle_id_opt: Option<Uuid> = chat_sessions::table
                    .filter(
                        chat_sessions::id
                            .eq(chat_session_id)
                            .and(chat_sessions::user_id.eq(user_id)),
                    )
                    .select(chat_sessions::player_chronicle_id)
                    .first(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get chat session: {e}")))?;

                let chronicle_id = match chronicle_id_opt {
                    Some(id) => id,
                    None => return Ok(None), // Chat has no chronicle
                };

                // Get chronicle basic info
                let chronicle: PlayerChronicle = player_chronicles::table
                    .filter(player_chronicles::id.eq(chronicle_id))
                    .filter(player_chronicles::user_id.eq(user_id))
                    .first(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get chronicle: {e}")))?;

                // Count total events in chronicle
                let total_events: i64 = chronicle_events::table
                    .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                    .count()
                    .get_result(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to count total events: {e}")))?;

                // Count events created by this specific chat
                let events_from_this_chat: i64 = chronicle_events::table
                    .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                    .filter(chronicle_events::chat_session_id.eq(chat_session_id))
                    .count()
                    .get_result(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to count chat events: {e}")))?;

                // Count other chats using this chronicle
                let other_chats_using_chronicle: i64 = chat_sessions::table
                    .filter(chat_sessions::player_chronicle_id.eq(chronicle_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .filter(chat_sessions::id.ne(chat_session_id)) // Exclude the current chat
                    .count()
                    .get_result(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to count other chats: {e}")))?;

                let can_delete_chronicle = other_chats_using_chronicle == 0;

                Ok(Some(ChronicleAnalysisInfo {
                    id: chronicle.id,
                    name: chronicle.name,
                    total_events: total_events as i32,
                    events_from_this_chat: events_from_this_chat as i32,
                    other_chats_using_chronicle: other_chats_using_chronicle as i32,
                    can_delete_chronicle,
                }))
            })
            .await
            .map_err(|e| {
                error!("Database interaction error during deletion analysis: {}", e);
                AppError::DbInteractError(format!("Failed to analyze chronicle: {e}"))
            })??;

        Ok(analysis)
    }

    /// Disassociate chronicle events from a chat session (nullify chat_session_id)
    /// Used for "disassociate" deletion strategy where events are preserved but unlinked
    #[instrument(skip(self), fields(user_id = %user_id, chat_session_id = %chat_session_id))]
    pub async fn disassociate_events_from_chat(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
    ) -> Result<i32, AppError> {
        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        let updated_count = conn
            .interact(move |conn| {
                // TODO: Add ownership verification once the Chat Queryable issue is resolved
                // For now, we trust the caller to verify ownership at the API level
                
                // Disassociate the events by setting chat_session_id to NULL
                diesel::update(chronicle_events::table)
                    .filter(chronicle_events::chat_session_id.eq(chat_session_id))
                    .set(chronicle_events::chat_session_id.eq(None::<Uuid>))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to disassociate events: {e}")))
            })
            .await
            .map_err(|e| {
                error!("Database interaction error when disassociating events: {}", e);
                AppError::DbInteractError(format!("Failed to disassociate events: {e}"))
            })??;

        info!("Disassociated {} events from chat session {} for user {}", updated_count, chat_session_id, user_id);
        Ok(updated_count as i32)
    }

    /// Delete chronicle and all its events
    /// Used for "delete_chronicle" deletion strategy
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn delete_chronicle_completely(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<(), AppError> {
        // First verify user owns the chronicle
        let _chronicle = self.get_chronicle(user_id, chronicle_id).await?;

        let conn = self.db_pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AppError::DbPoolError(format!("Connection pool error: {e}"))
        })?;

        conn.interact(move |conn| {
            // Delete the chronicle (CASCADE will delete all chronicle_events)
            diesel::delete(player_chronicles::table)
                .filter(player_chronicles::id.eq(chronicle_id))
                .filter(player_chronicles::user_id.eq(user_id))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(format!("Failed to delete chronicle: {e}")))
        })
        .await
        .map_err(|e| {
            error!("Database interaction error when deleting chronicle: {}", e);
            AppError::DbInteractError(format!("Failed to delete chronicle: {e}"))
        })??;

        info!("Successfully deleted chronicle {} and all its events for user {}", chronicle_id, user_id);
        Ok(())
    }
}

/// Information about a chronicle for deletion analysis
#[derive(Debug, Clone)]
pub struct ChronicleAnalysisInfo {
    pub id: Uuid,
    pub name: String,
    pub total_events: i32,
    pub events_from_this_chat: i32,
    pub other_chats_using_chronicle: i32,
    pub can_delete_chronicle: bool,
}