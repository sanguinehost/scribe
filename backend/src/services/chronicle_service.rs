use crate::db::DbId;
use crate::db::DbPool;
use diesel::query_dsl::JoinOnDsl;
use diesel::{
    result::Error as DieselError, AsChangeset, BoolExpressionMethods, ExpressionMethods,
    OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper,
};
use tracing::{error, info, instrument};

use crate::auth::session_dek::SessionDek;
use crate::errors::AppError;
use crate::models::chronicle::{
    CreateChronicleRequest, NewPlayerChronicle, PlayerChronicle, PlayerChronicleWithCounts,
    UpdateChronicleRequest, UpdatePlayerChronicle,
};
use crate::models::chronicle_event::{
    ChronicleEvent, CreateEventRequest, EventFilter, EventOrderBy, EventSource, NewChronicleEvent,
};
use crate::models::cognitive_memory::{
    CognitivePayload, NewCharacterOpinion, NewEntityObservation,
};
use crate::models::OptionalStringArray;
use crate::schema::{
    character_opinions, chat_messages, chat_sessions, chronicle_events, cognitive_core_memory,
    cognitive_facts, entity_observations, message_variants, player_chronicles,
};
use crate::services::ChronicleDeduplicationService;

use crate::llm::AiClient;
use std::sync::Arc;

/// ChronicleService handles all Chronicle-related database operations
#[derive(Clone)]
pub struct ChronicleService {
    db_pool: DbPool,
    ai_client: Arc<dyn AiClient>,
}

impl ChronicleService {
    #[must_use]
    pub fn new(db_pool: DbPool, ai_client: Arc<dyn AiClient>) -> Self {
        Self { db_pool, ai_client }
    }

    /// Helper to insert chronicle event and query it back (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn insert_event_sync(
        conn: &mut crate::db::DbConnection,
        event: &NewChronicleEvent,
        event_id: DbId,
    ) -> Result<ChronicleEvent, AppError> {
        use diesel::prelude::*;

        diesel::insert_into(chronicle_events::table)
            .values(event)
            .execute(conn)
            .map_err(|e| {
                error!(
                    "Diesel error when creating event: {}. Variant ID: {:?}, Chat Session ID: {:?}",
                    e, event.message_variant_id, event.chat_session_id
                );
                AppError::DatabaseQueryError(format!("Failed to create event: {e}"))
            })?;

        chronicle_events::table
            .find(event_id)
            .select(ChronicleEvent::as_select())
            .first::<ChronicleEvent>(conn)
            .map_err(|e| {
                error!("Failed to query event after insert: {}", e);
                AppError::DatabaseQueryError(format!("Failed to query event: {e}"))
            })
    }

    /// Helper to get chronicle by ID with ownership check (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn get_chronicle_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
        chronicle_id: DbId,
    ) -> Result<PlayerChronicle, AppError> {
        use diesel::prelude::*;

        player_chronicles::table
            .filter(
                player_chronicles::id
                    .eq(chronicle_id)
                    .and(player_chronicles::user_id.eq(user_id)),
            )
            .first(conn)
            .map_err(|e| {
                error!(
                    "Diesel error when getting chronicle {} for user {}: {}",
                    chronicle_id, user_id, e
                );
                match e {
                    DieselError::NotFound => AppError::NotFound("Chronicle not found".to_string()),
                    _ => AppError::DatabaseQueryError(format!("Failed to get chronicle: {e}")),
                }
            })
    }

    /// Helper to get ancestor variant IDs (avoids E0275 Sized overflow)
    fn get_ancestor_variant_ids(
        conn: &mut crate::db::DbConnection,
        variant_id: crate::db::DbId,
    ) -> Result<Vec<crate::db::DbId>, AppError> {
        use crate::schema::{chat_messages, message_variants};
        use diesel::prelude::*;

        // 1. Get target message info from variant
        let (target_msg_id, _target_variant_index) = message_variants::table
            .find(variant_id)
            .select((
                message_variants::parent_message_id,
                message_variants::variant_index,
            ))
            .first::<(crate::db::DbId, i32)>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get variant info: {e}"))
            })?;

        // 2. Get session info from target message
        let (session_id, target_created_at) = chat_messages::table
            .find(target_msg_id)
            .select((chat_messages::session_id, chat_messages::created_at))
            .first::<(crate::db::DbId, crate::db::DbTimestamp)>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get message info: {e}"))
            })?;

        // 3. Get previous messages in session
        // We want messages created BEFORE the target message
        let previous_messages = chat_messages::table
            .filter(chat_messages::session_id.eq(session_id))
            .filter(chat_messages::created_at.lt(target_created_at))
            .select((chat_messages::id, chat_messages::current_variant_index))
            .load::<(crate::db::DbId, i32)>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get previous messages: {e}"))
            })?;

        // 4. Get variant IDs for previous messages
        // We need to find variant IDs where (parent_message_id, variant_index) matches
        let prev_msg_ids: Vec<crate::db::DbId> =
            previous_messages.iter().map(|(id, _)| *id).collect();

        #[cfg(feature = "sqlite-backend")]
        let candidate_variants = {
            let prev_msg_ids_raw: Vec<String> =
                prev_msg_ids.iter().map(|id| id.to_string()).collect();
            message_variants::table
                .filter(message_variants::parent_message_id.eq_any(prev_msg_ids_raw))
                .select((
                    message_variants::id,
                    message_variants::parent_message_id,
                    message_variants::variant_index,
                ))
                .load::<(String, String, i32)>(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to get candidate variants: {e}"))
                })?
        };

        #[cfg(feature = "sqlite-backend")]
        let candidate_variants = candidate_variants
            .into_iter()
            .map(|(id_str, p_id_str, idx)| {
                (
                    crate::db::DbId::parse_str(&id_str).unwrap(),
                    crate::db::DbId::parse_str(&p_id_str).unwrap(),
                    idx,
                )
            })
            .collect::<Vec<_>>();

        #[cfg(feature = "postgres-backend")]
        let candidate_variants = {
            let prev_msg_ids_raw: Vec<uuid::Uuid> =
                prev_msg_ids.iter().map(|id| id.into_uuid()).collect();
            message_variants::table
                .filter(message_variants::parent_message_id.eq_any(prev_msg_ids_raw))
                .select((
                    message_variants::id,
                    message_variants::parent_message_id,
                    message_variants::variant_index,
                ))
                .load::<(uuid::Uuid, uuid::Uuid, i32)>(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to get candidate variants: {e}"))
                })?
                .into_iter()
                .map(|(id, p_id, idx)| {
                    (
                        crate::db::DbId::from_uuid(id),
                        crate::db::DbId::from_uuid(p_id),
                        idx,
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut allowed_ids = Vec::new();

        // Add the active variant itself
        allowed_ids.push(variant_id);

        // Add the correct variant for each previous message
        for (msg_id, current_index) in previous_messages {
            if let Some((var_id, _, _)) = candidate_variants
                .iter()
                .find(|(_, p_id, v_idx)| *p_id == msg_id && *v_idx == current_index)
            {
                allowed_ids.push(*var_id);
            }
        }

        Ok(allowed_ids)
    }

    /// Helper to get event by ID with ownership check (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn get_event_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
        event_id: DbId,
    ) -> Result<ChronicleEvent, AppError> {
        use diesel::prelude::*;

        chronicle_events::table
            .filter(
                chronicle_events::id
                    .eq(event_id)
                    .and(chronicle_events::user_id.eq(user_id)),
            )
            .select(ChronicleEvent::as_select())
            .first::<ChronicleEvent>(conn)
            .map_err(|e| {
                error!("Diesel error when getting event: {}", e);
                match e {
                    DieselError::NotFound => AppError::NotFound("Event not found".to_string()),
                    _ => AppError::DatabaseQueryError(format!("Failed to get event: {e}")),
                }
            })
    }

    /// Helper to insert chronicle and query it back (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn insert_chronicle_sync(
        conn: &mut crate::db::DbConnection,
        chronicle: &NewPlayerChronicle,
        chronicle_id: DbId,
    ) -> Result<PlayerChronicle, AppError> {
        use diesel::prelude::*;

        diesel::insert_into(player_chronicles::table)
            .values(chronicle)
            .execute(conn)
            .map_err(|e| {
                error!("Diesel error when creating chronicle: {}", e);
                match e {
                    DieselError::DatabaseError(_, ref info) => {
                        if info.message().contains("duplicate") || info.message().contains("unique")
                        {
                            AppError::Conflict(
                                "A chronicle with this name already exists".to_string(),
                            )
                        } else {
                            AppError::DatabaseQueryError(format!("Failed to create chronicle: {e}"))
                        }
                    }
                    _ => AppError::DatabaseQueryError(format!("Failed to create chronicle: {e}")),
                }
            })?;

        player_chronicles::table
            .find(chronicle_id)
            .first(conn)
            .map_err(|e| {
                error!("Failed to query chronicle after insert: {}", e);
                AppError::DatabaseQueryError(format!("Failed to query chronicle: {e}"))
            })
    }

    /// Helper to list user chronicles (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn list_user_chronicles_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
    ) -> Result<Vec<PlayerChronicle>, AppError> {
        use diesel::prelude::*;

        player_chronicles::table
            .filter(player_chronicles::user_id.eq(user_id))
            .order(player_chronicles::updated_at.desc())
            .load(conn)
            .map_err(|e| {
                error!("Diesel error when getting user chronicles: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get chronicles: {e}"))
            })
    }

    /// Helper to list user chronicles with counts (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn list_user_chronicles_with_counts_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
    ) -> Result<Vec<PlayerChronicleWithCounts>, AppError> {
        use diesel::prelude::*;

        // Load all chronicles for the user
        let chronicles: Vec<PlayerChronicle> = player_chronicles::table
            .filter(player_chronicles::user_id.eq(user_id))
            .order(player_chronicles::updated_at.desc())
            .load(conn)
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load chronicles: {e}")))?;

        let mut chronicles_with_counts = Vec::new();

        for chronicle in chronicles {
            // Count events - only count events where:
            // 1. message_variant_id is NULL (manually added events), OR
            // 2. variant_index matches current_variant_index (active variant events)
            let event_count: i64 =
                chronicle_events::table
                    .left_join(message_variants::table)
                    .left_join(
                        chat_messages::table
                            .on(message_variants::parent_message_id.eq(chat_messages::id)),
                    )
                    .filter(chronicle_events::chronicle_id.eq(chronicle.id))
                    .filter(chronicle_events::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ))
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count events: {e}"))
                    })?;

            // Count linked chat sessions
            let chat_session_count: i64 = chat_sessions::table
                .filter(chat_sessions::player_chronicle_id.eq(chronicle.id))
                .count()
                .get_result(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to count sessions: {e}"))
                })?;

            chronicles_with_counts.push(PlayerChronicleWithCounts {
                chronicle,
                event_count,
                chat_session_count,
            });
        }

        Ok(chronicles_with_counts)
    }

    /// Helper to list events for chat session (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn list_events_for_session_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
        session_id: DbId,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        use diesel::prelude::*;

        chronicle_events::table
            .filter(
                chronicle_events::user_id
                    .eq(user_id)
                    .and(chronicle_events::chat_session_id.eq(Some(session_id))),
            )
            .select(ChronicleEvent::as_select())
            .load::<ChronicleEvent>(conn)
            .map_err(|e| {
                error!("Diesel error when getting events for chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to get events for chat session: {e}"))
            })
    }

    /// Helper to get chat deletion analysis (avoids E0275 Sized overflow)
    #[cfg(feature = "sqlite-backend")]
    fn get_deletion_analysis_sync(
        conn: &mut crate::db::DbConnection,
        user_id: DbId,
        chat_session_id: DbId,
    ) -> Result<Option<ChronicleAnalysisInfo>, AppError> {
        use crate::schema::{chat_sessions, chronicle_events, player_chronicles};
        use diesel::prelude::*;

        // First, get the chronicle ID from the chat session
        let chronicle_id_opt: Option<DbId> = chat_sessions::table
            .filter(
                chat_sessions::id
                    .eq(chat_session_id)
                    .and(chat_sessions::user_id.eq(user_id)),
            )
            .select(chat_sessions::player_chronicle_id)
            .first(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get chat session: {e}"))
            })?;

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
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to count total events: {e}"))
            })?;

        // Count events created by this specific chat
        let events_from_this_chat: i64 = chronicle_events::table
            .filter(chronicle_events::chronicle_id.eq(chronicle_id))
            .filter(chronicle_events::chat_session_id.eq(chat_session_id))
            .count()
            .get_result(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to count chat events: {e}"))
            })?;

        // Count other chats using this chronicle
        let other_chats_using_chronicle: i64 = chat_sessions::table
            .filter(chat_sessions::player_chronicle_id.eq(chronicle_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .filter(chat_sessions::id.ne(chat_session_id)) // Exclude the current chat
            .count()
            .get_result(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to count other chats: {e}"))
            })?;

        let can_delete_chronicle = other_chats_using_chronicle == 0;

        Ok(Some(ChronicleAnalysisInfo {
            id: chronicle.id,
            name: chronicle.name,
            total_events: total_events as i32,
            events_from_this_chat: events_from_this_chat as i32,
            other_chats_using_chronicle: other_chats_using_chronicle as i32,
            can_delete_chronicle,
        }))
    }

    // --- Chronicle CRUD Operations ---

    /// Create a new chronicle for a user
    #[instrument(skip(self), fields(user_id = %user_id, name = %request.name))]
    pub async fn create_chronicle(
        &self,
        user_id: crate::db::DbId,
        request: CreateChronicleRequest,
    ) -> Result<PlayerChronicle, AppError> {
        let mut new_chronicle: NewPlayerChronicle = request.into();
        new_chronicle.user_id = user_id;

        #[cfg(feature = "postgres-backend")]
        let chronicle = {
            crate::db::with_conn(&self.db_pool, move |conn| {
                diesel::insert_into(player_chronicles::table)
                    .values(&new_chronicle)
                    .returning(PlayerChronicle::as_returning())
                    .get_result(conn)
                    .map_err(|e| {
                        error!("Diesel error when creating chronicle: {}", e);
                        match e {
                            DieselError::DatabaseError(_, ref info) => {
                                if info.message().contains("duplicate")
                                    || info.message().contains("unique")
                                {
                                    AppError::Conflict(
                                        "A chronicle with this name already exists".to_string(),
                                    )
                                } else {
                                    AppError::DatabaseQueryError(format!(
                                        "Failed to create chronicle: {e}"
                                    ))
                                }
                            }
                            _ => AppError::DatabaseQueryError(format!(
                                "Failed to create chronicle: {e}"
                            )),
                        }
                    })
            })
            .await?
        };

        #[cfg(feature = "sqlite-backend")]
        let chronicle = {
            // Generate ID for SQLite (no RETURNING support)
            let chronicle_id = crate::db::DbId::new_v4();
            new_chronicle.id = Some(chronicle_id);

            crate::db::with_conn(&self.db_pool, move |conn| {
                Self::insert_chronicle_sync(conn, &new_chronicle, chronicle_id)
            })
            .await?
        };

        info!("Created chronicle {} for user {}", chronicle.id, user_id);
        Ok(chronicle)
    }

    /// Get all chronicles for a user
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn get_user_chronicles(
        &self,
        user_id: crate::db::DbId,
    ) -> Result<Vec<PlayerChronicle>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let chronicles = crate::db::with_conn(&self.db_pool, move |conn| {
            let target = player_chronicles::table.filter(player_chronicles::user_id.eq(user_id));
            target
                .order(player_chronicles::updated_at.desc())
                .load(conn)
                .map_err(|e| {
                    error!("Diesel error when getting user chronicles: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to get chronicles: {e}"))
                })
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let chronicles = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::list_user_chronicles_sync(conn, user_id)
        })
        .await?;

        info!(
            "Retrieved {} chronicles for user {}",
            chronicles.len(),
            user_id
        );
        Ok(chronicles)
    }

    /// Get chronicles with event and chat session counts
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn get_user_chronicles_with_counts(
        &self,
        user_id: crate::db::DbId,
    ) -> Result<Vec<PlayerChronicleWithCounts>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let results = crate::db::with_conn(&self.db_pool, move |conn| {
            // Note: This query might need optimization with proper joins
            // For now, we'll get chronicles and then count separately
            let chronicles: Vec<PlayerChronicle> = player_chronicles::table
                .filter(player_chronicles::user_id.eq(user_id))
                .order(player_chronicles::updated_at.desc())
                .load(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to load chronicles: {e}"))
                })?;

            let mut chronicles_with_counts = Vec::new();

            for chronicle in chronicles {
                // Count events - only count events where:
                // 1. message_variant_id is NULL (manually added events), OR
                // 2. variant_index matches current_variant_index (active variant events)
                let event_count: i64 = chronicle_events::table
                    .left_join(message_variants::table)
                    .left_join(
                        chat_messages::table
                            .on(message_variants::parent_message_id.eq(chat_messages::id)),
                    )
                    .filter(chronicle_events::chronicle_id.eq(chronicle.id))
                    .filter(chronicle_events::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ))
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count events: {e}"))
                    })?;

                // Count linked chat sessions
                let chat_session_count: i64 = chat_sessions::table
                    .filter(chat_sessions::player_chronicle_id.eq(chronicle.id))
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count sessions: {e}"))
                    })?;

                chronicles_with_counts.push(PlayerChronicleWithCounts {
                    chronicle,
                    event_count,
                    chat_session_count,
                });
            }

            Ok(chronicles_with_counts)
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let results = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::list_user_chronicles_with_counts_sync(conn, user_id)
        })
        .await?;

        info!(
            "Retrieved {} chronicles with counts for user {}",
            results.len(),
            user_id
        );
        Ok(results)
    }

    /// Get a specific chronicle by ID, ensuring user ownership
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn get_chronicle(
        &self,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
    ) -> Result<PlayerChronicle, AppError> {
        #[cfg(feature = "postgres-backend")]
        let chronicle = crate::db::with_conn(&self.db_pool, move |conn| {
            player_chronicles::table
                .filter(
                    player_chronicles::id
                        .eq(chronicle_id)
                        .and(player_chronicles::user_id.eq(user_id)),
                )
                .first(conn)
                .map_err(|e| {
                    error!("Diesel error when getting chronicle: {}", e);
                    match e {
                        DieselError::NotFound => {
                            AppError::NotFound("Chronicle not found".to_string())
                        }
                        _ => AppError::DatabaseQueryError(format!("Failed to get chronicle: {e}")),
                    }
                })
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let chronicle = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::get_chronicle_sync(conn, user_id, chronicle_id)
        })
        .await?;

        info!("Retrieved chronicle {} for user {}", chronicle_id, user_id);
        Ok(chronicle)
    }

    /// Update a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn update_chronicle(
        &self,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        request: UpdateChronicleRequest,
    ) -> Result<PlayerChronicle, AppError> {
        let update: UpdatePlayerChronicle = request.into();

        #[cfg(feature = "postgres-backend")]
        let chronicle = {
            crate::db::with_conn(&self.db_pool, move |conn| {
                let target = player_chronicles::table.filter(
                    player_chronicles::id
                        .eq(chronicle_id)
                        .and(player_chronicles::user_id.eq(user_id)),
                );

                // Use pattern matching to handle the different update combinations
                let result = match (&update.name, &update.description) {
                    (Some(name), Some(description)) => diesel::update(target)
                        .set((
                            player_chronicles::name.eq(name),
                            player_chronicles::description.eq(description),
                            player_chronicles::updated_at.eq(diesel::dsl::now),
                        ))
                        .returning(PlayerChronicle::as_returning())
                        .get_result(conn),
                    (Some(name), None) => diesel::update(target)
                        .set((
                            player_chronicles::name.eq(name),
                            player_chronicles::updated_at.eq(diesel::dsl::now),
                        ))
                        .returning(PlayerChronicle::as_returning())
                        .get_result(conn),
                    (None, Some(description)) => diesel::update(target)
                        .set((
                            player_chronicles::description.eq(description),
                            player_chronicles::updated_at.eq(diesel::dsl::now),
                        ))
                        .returning(PlayerChronicle::as_returning())
                        .get_result(conn),
                    (None, None) => {
                        // Only update the timestamp
                        diesel::update(target)
                            .set(player_chronicles::updated_at.eq(diesel::dsl::now))
                            .returning(PlayerChronicle::as_returning())
                            .get_result(conn)
                    }
                };

                result.map_err(|e| {
                    error!("Diesel error when updating chronicle: {}", e);
                    match e {
                        DieselError::NotFound => {
                            AppError::NotFound("Chronicle not found".to_string())
                        }
                        _ => {
                            AppError::DatabaseQueryError(format!("Failed to update chronicle: {e}"))
                        }
                    }
                })
            })
            .await?
        };

        #[cfg(feature = "sqlite-backend")]
        let chronicle = {
            crate::db::with_conn(&self.db_pool, move |conn| {
                let target = player_chronicles::table.filter(
                    player_chronicles::id
                        .eq(chronicle_id)
                        .and(player_chronicles::user_id.eq(user_id)),
                );

                // SQLite doesn't support RETURNING, execute update and query back
                let rows_updated = match (&update.name, &update.description) {
                    (Some(name), Some(description)) => diesel::update(target)
                        .set((
                            player_chronicles::name.eq(name),
                            player_chronicles::description.eq(description),
                            player_chronicles::updated_at.eq(crate::db::DbTimestamp::now()),
                        ))
                        .execute(conn),
                    (Some(name), None) => diesel::update(target)
                        .set((
                            player_chronicles::name.eq(name),
                            player_chronicles::updated_at.eq(crate::db::DbTimestamp::now()),
                        ))
                        .execute(conn),
                    (None, Some(description)) => diesel::update(target)
                        .set((
                            player_chronicles::description.eq(description),
                            player_chronicles::updated_at.eq(crate::db::DbTimestamp::now()),
                        ))
                        .execute(conn),
                    (None, None) => diesel::update(target)
                        .set(player_chronicles::updated_at.eq(crate::db::DbTimestamp::now()))
                        .execute(conn),
                }
                .map_err(|e| {
                    error!("Diesel error when updating chronicle: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to update chronicle: {e}"))
                })?;

                // Check if any rows were updated
                if rows_updated == 0 {
                    return Err(AppError::NotFound("Chronicle not found".to_string()));
                }

                // Query back the updated chronicle
                player_chronicles::table
                    .find(chronicle_id)
                    .first(conn)
                    .map_err(|e| {
                        error!("Failed to query chronicle after update: {}", e);
                        match e {
                            DieselError::NotFound => {
                                AppError::NotFound("Chronicle not found".to_string())
                            }
                            _ => AppError::DatabaseQueryError(format!(
                                "Failed to query chronicle: {e}"
                            )),
                        }
                    })
            })
            .await?
        };

        info!("Updated chronicle {} for user {}", chronicle_id, user_id);
        Ok(chronicle)
    }

    /// Delete a chronicle and all its events
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn delete_chronicle(
        &self,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        let deleted_count = crate::db::with_conn(&self.db_pool, move |conn| {
            // Note: chronicle_events will be deleted by CASCADE
            let target = player_chronicles::table
                .filter(player_chronicles::id.eq(chronicle_id))
                .filter(player_chronicles::user_id.eq(user_id));

            diesel::delete(target).execute(conn).map_err(|e| {
                error!("Diesel error when deleting chronicle: {}", e);
                AppError::DatabaseQueryError(format!("Failed to delete chronicle: {e}"))
            })
        })
        .await?;

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
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        request: CreateEventRequest,
        session_dek: Option<&crate::auth::session_dek::SessionDek>,
    ) -> Result<ChronicleEvent, AppError> {
        // First verify chronicle ownership
        tracing::debug!(
            "Verifying ownership for chronicle {} and user {}",
            chronicle_id,
            user_id
        );
        self.get_chronicle(user_id, chronicle_id).await?;

        let mut new_event: NewChronicleEvent = request.into();
        new_event.chronicle_id = chronicle_id;
        new_event.user_id = user_id;

        // Create a temporary event for deduplication check using plaintext summary
        let temp_event = ChronicleEvent {
            id: new_event.id,
            chronicle_id,
            user_id,
            event_type: new_event.event_type.clone(),
            summary: new_event.summary.clone(), // Still plaintext here
            source: new_event.source.clone(),
            message_variant_id: new_event.message_variant_id,
            created_at: new_event.timestamp_iso8601,
            updated_at: new_event.timestamp_iso8601,
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: new_event.timestamp_iso8601,
            keywords: Some(new_event.keywords.clone()),
            keywords_encrypted: None,
            keywords_nonce: None,
            chat_session_id: new_event.chat_session_id,
            #[cfg(feature = "sqlite-backend")]
            event_data: None,
        };

        // Check for duplicates
        let dedup_service =
            ChronicleDeduplicationService::new(self.db_pool.clone(), self.ai_client.clone(), None);
        match dedup_service
            .check_for_duplicates(&temp_event, session_dek)
            .await
        {
            Ok(result) => {
                if result.is_duplicate {
                    tracing::info!(
                        "Skipping duplicate event creation: {} is duplicate of {:?} (confidence: {:.2})",
                        temp_event.id,
                        result.duplicate_event_id,
                        result.confidence
                    );
                    // Return the duplicate event if we can find it, or just the temp one marked as existing
                    return Ok(temp_event);
                }
            }
            Err(e) => {
                error!("Failed to check for duplicates: {}", e);
                // Continue with creation on error
            }
        }

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
                    return Err(AppError::CryptoError(format!(
                        "Failed to encrypt event summary: {}",
                        e
                    )));
                }
            }

            // Encrypt keywords if present
            // Encrypt keywords if present
            {
                let keywords_vec = &new_event.keywords.0;
                // Convert Vec<Option<String>> to Vec<String> for serialization
                let keywords: Vec<String> =
                    keywords_vec.iter().filter_map(|opt| opt.clone()).collect();

                if !keywords.is_empty() {
                    let keywords_json = serde_json::to_string(&keywords).map_err(|e| {
                        AppError::SerializationError(format!("Failed to serialize keywords: {}", e))
                    })?;

                    match crate::crypto::encrypt_gcm(keywords_json.as_bytes(), &dek.0) {
                        Ok((ciphertext, nonce)) => {
                            new_event.keywords_encrypted = Some(ciphertext);
                            new_event.keywords_nonce = Some(nonce);
                            // Clear plaintext keywords - we MUST NOT store plaintext in the database
                            new_event.keywords = OptionalStringArray::from_vec(vec![Some(
                                "[ENCRYPTED]".to_string(),
                            )]);
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

        // ID is now handled by NewChronicleEvent builder/default

        #[cfg(feature = "postgres-backend")]
        let event = {
            crate::db::with_conn(&self.db_pool, move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&new_event)
                    .returning(ChronicleEvent::as_returning())
                    .get_result(conn)
                    .map_err(|e| {
                        error!("Diesel error when creating event: {}", e);
                        AppError::DatabaseQueryError(format!("Failed to create event: {e}"))
                    })
            })
            .await?
        };

        #[cfg(feature = "sqlite-backend")]
        let event = {
            let event_id = new_event.id;
            crate::db::with_conn(&self.db_pool, move |conn| {
                Self::insert_event_sync(conn, &new_event, event_id)
            })
            .await?
        };

        info!(
            "Created event {} in chronicle {} for user {}. Variant ID: {:?}, Chat Session ID: {:?}",
            event.id, chronicle_id, user_id, event.message_variant_id, event.chat_session_id
        );
        Ok(event)
    }

    /// Get events for a chronicle with filtering
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn get_chronicle_events(
        &self,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
        filter: EventFilter,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        // First verify chronicle ownership
        self.get_chronicle(user_id, chronicle_id).await?;

        let events = crate::db::with_conn(&self.db_pool, move |conn| {
            let mut query = chronicle_events::table
                .left_join(message_variants::table)
                .left_join(
                    chat_messages::table
                        .on(message_variants::parent_message_id.eq(chat_messages::id)),
                )
                .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                .into_boxed();

            // Apply variant filtering
            if let Some(active_variant_id) = filter.active_variant_id {
                // Ancestry filtering: only show events from the active path
                let allowed_ids = Self::get_ancestor_variant_ids(conn, active_variant_id)?;
                #[cfg(feature = "sqlite-backend")]
                let allowed_ids_raw: Vec<String> =
                    allowed_ids.into_iter().map(|id| id.to_string()).collect();
                #[cfg(feature = "postgres-backend")]
                let allowed_ids_raw: Vec<uuid::Uuid> =
                    allowed_ids.into_iter().map(|id| id.into_uuid()).collect();

                query = query.filter(
                    chronicle_events::message_variant_id
                        .is_null()
                        .or(chronicle_events::message_variant_id.eq_any(allowed_ids_raw)),
                );
            } else {
                // Default filtering: show events from the currently selected variants
                query =
                    query.filter(chronicle_events::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ));
            }

            // Apply filters
            if let Some(event_type) = filter.event_type {
                query = query.filter(chronicle_events::event_type.eq(event_type));
            }

            if let Some(source) = filter.source {
                query = query.filter(chronicle_events::source.eq(source.to_string()));
            }

            // Apply ordering
            match filter.order_by.unwrap_or(EventOrderBy::CreatedAtDesc) {
                EventOrderBy::CreatedAtAsc => {
                    query = query.order(chronicle_events::created_at.asc())
                }
                EventOrderBy::CreatedAtDesc => {
                    query = query.order(chronicle_events::created_at.desc())
                }
                EventOrderBy::UpdatedAtAsc => {
                    query = query.order(chronicle_events::updated_at.asc())
                }
                EventOrderBy::UpdatedAtDesc => {
                    query = query.order(chronicle_events::updated_at.desc())
                }
                EventOrderBy::TimestampAsc => {
                    query = query.order(chronicle_events::timestamp_iso8601.asc())
                }
                EventOrderBy::TimestampDesc => {
                    query = query.order(chronicle_events::timestamp_iso8601.desc())
                }
            }

            // Apply pagination
            if let Some(offset) = filter.offset {
                query = query.offset(offset);
            }

            if let Some(limit) = filter.limit {
                query = query.limit(limit);
            }

            query
                .select(ChronicleEvent::as_select())
                .load::<ChronicleEvent>(conn)
                .map_err(|e| {
                    error!("Diesel error when getting events: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to get events: {e}"))
                })
        })
        .await?;

        info!(
            "Retrieved {} events for chronicle {} for user {}",
            events.len(),
            chronicle_id,
            user_id
        );
        Ok(events)
    }

    /// Get a specific event
    #[instrument(skip(self), fields(user_id = %user_id, event_id = %event_id))]
    pub async fn get_event(
        &self,
        user_id: crate::db::DbId,
        event_id: crate::db::DbId,
    ) -> Result<ChronicleEvent, AppError> {
        #[cfg(feature = "postgres-backend")]
        let event = crate::db::with_conn(&self.db_pool, move |conn| {
            chronicle_events::table
                .filter(
                    chronicle_events::id
                        .eq(event_id)
                        .and(chronicle_events::user_id.eq(user_id)),
                )
                .first(conn)
                .map_err(|e| {
                    error!("Diesel error when getting event: {}", e);
                    match e {
                        DieselError::NotFound => AppError::NotFound("Event not found".to_string()),
                        _ => AppError::DatabaseQueryError(format!("Failed to get event: {e}")),
                    }
                })
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let event = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::get_event_sync(conn, user_id, event_id)
        })
        .await?;

        info!("Retrieved event {} for user {}", event_id, user_id);
        Ok(event)
    }

    /// Update an event
    #[instrument(skip(self), fields(user_id = %user_id, event_id = %event_id))]
    pub async fn update_event(
        &self,
        user_id: crate::db::DbId,
        event_id: crate::db::DbId,
        request: crate::models::chronicle_event::UpdateEventRequest,
        session_dek: Option<&crate::auth::session_dek::SessionDek>,
    ) -> Result<ChronicleEvent, AppError> {
        use crate::models::chronicle_event::UpdateChronicleEvent;

        // First verify ownership
        self.get_event(user_id, event_id).await?;

        let mut update: UpdateChronicleEvent = request.into();

        // Handle encryption if DEK is provided
        let (summary_encrypted, summary_nonce) = if let Some(dek) = session_dek {
            if let Some(summary) = &update.summary {
                match crate::crypto::encrypt_gcm(summary.as_bytes(), &dek.0) {
                    Ok((ciphertext, nonce)) => {
                        // Clear plaintext summary
                        update.summary = Some("[ENCRYPTED]".to_string());
                        (Some(ciphertext), Some(nonce))
                    }
                    Err(e) => {
                        error!("Failed to encrypt summary update: {}", e);
                        return Err(AppError::CryptoError(format!(
                            "Failed to encrypt summary: {}",
                            e
                        )));
                    }
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let (keywords_encrypted, keywords_nonce) = if let Some(dek) = session_dek {
            if let Some(keywords) = &update.keywords {
                let keywords_json = serde_json::to_string(keywords).map_err(|e| {
                    AppError::SerializationError(format!("Failed to serialize keywords: {}", e))
                })?;

                match crate::crypto::encrypt_gcm(keywords_json.as_bytes(), &dek.0) {
                    Ok((ciphertext, nonce)) => {
                        // Clear plaintext keywords
                        update.keywords = Some(vec!["[ENCRYPTED]".to_string()]);
                        (Some(ciphertext), Some(nonce))
                    }
                    Err(e) => {
                        error!("Failed to encrypt keywords update: {}", e);
                        // Warn but continue? Or fail? Let's fail to be safe.
                        return Err(AppError::CryptoError(format!(
                            "Failed to encrypt keywords: {}",
                            e
                        )));
                    }
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        #[cfg(feature = "postgres-backend")]
        let event = crate::db::with_conn(&self.db_pool, move |conn| {
            let target = chronicle_events::table.filter(
                chronicle_events::id
                    .eq(event_id)
                    .and(chronicle_events::user_id.eq(user_id)),
            );

            // We have to construct the update manually because we have extra fields (encrypted ones)
            // that are not in UpdateChronicleEvent
            // This is getting complicated because we can't easily chain .set() calls conditionally
            // with different types in Diesel without a lot of boilerplate.
            // A simpler approach is to fetch, update in memory, and save back? No, race conditions.
            // Or just use direct diesel calls for each field.

            // Let's try to use a struct that has all fields, including Optionals.
            // But we don't have one that matches exactly what we want to update.

            // Alternative: Use multiple update calls? No, transactional.

            // Let's use the fact that we can pass a tuple to .set()
            // But the tuple needs to be fixed size.

            // We will use a custom struct for the update that includes the encrypted fields
            #[derive(AsChangeset)]
            #[diesel(table_name = chronicle_events)]
            struct FullEventUpdate {
                event_type: Option<String>,
                summary: Option<String>,
                source: Option<String>,
                keywords: Option<OptionalStringArray>,
                summary_encrypted: Option<Vec<u8>>,
                summary_nonce: Option<Vec<u8>>,
                keywords_encrypted: Option<Vec<u8>>,
                keywords_nonce: Option<Vec<u8>>,
                updated_at: crate::db::DbTimestamp,
            }

            let full_update = FullEventUpdate {
                event_type: update.event_type,
                summary: update.summary,
                source: update.source.map(|s| s.to_string()),
                keywords: update.keywords.map(OptionalStringArray::from_strings),
                summary_encrypted,
                summary_nonce,
                keywords_encrypted,
                keywords_nonce,
                updated_at: crate::db::DbTimestamp::now(),
            };

            diesel::update(target)
                .set(&full_update)
                .returning(ChronicleEvent::as_returning())
                .get_result(conn)
                .map_err(|e| {
                    error!("Diesel error when updating event: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to update event: {e}"))
                })
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let event = crate::db::with_conn(&self.db_pool, move |conn| {
            let target = chronicle_events::table.filter(
                chronicle_events::id
                    .eq(event_id)
                    .and(chronicle_events::user_id.eq(user_id)),
            );

            // Define the struct locally for SQLite too
            #[derive(AsChangeset)]
            #[diesel(table_name = chronicle_events)]
            struct FullEventUpdate {
                event_type: Option<String>,
                summary: Option<String>,
                source: Option<String>,
                keywords: Option<OptionalStringArray>,
                summary_encrypted: Option<Vec<u8>>,
                summary_nonce: Option<Vec<u8>>,
                keywords_encrypted: Option<Vec<u8>>,
                keywords_nonce: Option<Vec<u8>>,
                updated_at: crate::db::DbTimestamp,
            }

            let full_update = FullEventUpdate {
                event_type: update.event_type,
                summary: update.summary,
                source: update.source.map(|s| s.to_string()),
                keywords: update
                    .keywords
                    .map(|k| OptionalStringArray(k.into_iter().map(Some).collect())),
                summary_encrypted,
                summary_nonce,
                keywords_encrypted,
                keywords_nonce,
                updated_at: crate::db::DbTimestamp::now(),
            };

            diesel::update(target)
                .set(&full_update)
                .execute(conn)
                .map_err(|e| {
                    error!("Diesel error when updating event: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to update event: {e}"))
                })?;

            // Fetch back
            chronicle_events::table
                .find(event_id)
                .first(conn)
                .map_err(|e| {
                    error!("Failed to query event after update: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to query event: {e}"))
                })
        })
        .await?;

        Ok(event)
    }
    #[instrument(skip(self), fields(user_id = %user_id, event_id = %event_id))]
    pub async fn delete_event(
        &self,
        user_id: crate::db::DbId,
        event_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        let deleted_count = crate::db::with_conn(&self.db_pool, move |conn| {
            diesel::delete(
                chronicle_events::table.filter(
                    chronicle_events::id
                        .eq(event_id)
                        .and(chronicle_events::user_id.eq(user_id)),
                ),
            )
            .execute(conn)
            .map_err(|e| {
                error!("Diesel error when deleting event: {}", e);
                AppError::DatabaseQueryError(format!("Failed to delete event: {e}"))
            })
        })
        .await?;

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
        user_id: crate::db::DbId,
        session_id: crate::db::DbId,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let events = crate::db::with_conn(&self.db_pool, move |conn| {
            chronicle_events::table
                .filter(
                    chronicle_events::user_id
                        .eq(user_id)
                        .and(chronicle_events::chat_session_id.eq(Some(session_id))),
                )
                .load(conn)
                .map_err(|e| {
                    error!("Diesel error when getting events for chat session: {}", e);
                    AppError::DatabaseQueryError(format!(
                        "Failed to get events for chat session: {e}"
                    ))
                })
        })
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let events = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::list_events_for_session_sync(conn, user_id, session_id)
        })
        .await?;

        info!(
            "Retrieved {} events for chat session {} for user {}",
            events.len(),
            session_id,
            user_id
        );
        Ok(events)
    }

    /// Delete all events associated with a chat session (for chat deletion cleanup)
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id))]
    pub async fn delete_events_for_chat_session(
        &self,
        user_id: crate::db::DbId,
        session_id: crate::db::DbId,
    ) -> Result<usize, AppError> {
        let deleted_count = crate::db::with_conn(&self.db_pool, move |conn| {
            diesel::delete(
                chronicle_events::table.filter(
                    chronicle_events::user_id
                        .eq(user_id)
                        .and(chronicle_events::chat_session_id.eq(Some(session_id))),
                ),
            )
            .execute(conn)
            .map_err(|e| {
                error!("Diesel error when deleting events for chat session: {}", e);
                AppError::DatabaseQueryError(format!(
                    "Failed to delete events for chat session: {e}"
                ))
            })
        })
        .await?;

        info!(
            "Deleted {} events for chat session {} for user {}",
            deleted_count, session_id, user_id
        );
        Ok(deleted_count)
    }

    /// Link a chat session to a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id, chronicle_id = %chronicle_id))]
    pub async fn link_chat_session(
        &self,
        user_id: crate::db::DbId,
        session_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        // First verify chronicle ownership
        self.get_chronicle(user_id, chronicle_id).await?;

        let updated_count = crate::db::with_conn(&self.db_pool, move |conn| {
            diesel::update(
                chat_sessions::table.filter(
                    chat_sessions::id
                        .eq(session_id)
                        .and(chat_sessions::user_id.eq(user_id)),
                ),
            )
            .set(chat_sessions::player_chronicle_id.eq(Some(chronicle_id)))
            .execute(conn)
            .map_err(|e| {
                error!("Diesel error when linking chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to link chat session: {e}"))
            })
        })
        .await?;

        if updated_count == 0 {
            return Err(AppError::NotFound("Chat session not found".to_string()));
        }

        info!(
            "Linked chat session {} to chronicle {} for user {}",
            session_id, chronicle_id, user_id
        );
        Ok(())
    }

    /// Get the character name for a chat session
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_chat_session_character_name(
        &self,
        session_id: crate::db::DbId,
    ) -> Result<Option<String>, AppError> {
        // First get the character_id from the chat session
        let character_id: Option<crate::db::DbId> =
            crate::db::with_conn(&self.db_pool, move |conn| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .select(chat_sessions::character_id)
                    .first::<Option<crate::db::DbId>>(conn)
                    .optional()
                    .map_err(|e| {
                        error!("Diesel error when getting character_id: {}", e);
                        AppError::DatabaseQueryError(format!("Failed to get character_id: {e}"))
                    })
            })
            .await?
            .flatten();

        // If we have a character_id, get the character name
        let character_name = if let Some(char_id) = character_id {
            crate::db::with_conn(&self.db_pool, move |conn| {
                use crate::schema::characters;

                characters::table
                    .filter(characters::id.eq(char_id))
                    .select(characters::name)
                    .first::<String>(conn)
                    .optional()
                    .map_err(|e| {
                        error!("Diesel error when getting character name: {}", e);
                        AppError::DatabaseQueryError(format!("Failed to get character name: {e}"))
                    })
            })
            .await?
        } else {
            None
        };

        info!(
            "Chat session {} has character_name: {:?}",
            session_id, character_name
        );
        Ok(character_name)
    }

    /// Get the chronicle ID linked to a chat session
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_chat_session_chronicle(
        &self,
        session_id: crate::db::DbId,
    ) -> Result<Option<crate::db::DbId>, AppError> {
        let chronicle_id = crate::db::with_conn(&self.db_pool, move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::player_chronicle_id)
                .first::<Option<crate::db::DbId>>(conn)
                .optional()
                .map_err(|e| {
                    error!("Diesel error when getting chat session chronicle: {}", e);
                    AppError::DatabaseQueryError(format!(
                        "Failed to get chat session chronicle: {e}"
                    ))
                })
        })
        .await?
        .flatten();

        info!(
            "Chat session {} has chronicle_id: {:?}",
            session_id, chronicle_id
        );
        Ok(chronicle_id)
    }

    /// Unlink a chat session from a chronicle
    #[instrument(skip(self), fields(user_id = %user_id, session_id = %session_id))]
    pub async fn unlink_chat_session(
        &self,
        user_id: crate::db::DbId,
        session_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        let updated_count = crate::db::with_conn(&self.db_pool, move |conn| {
            diesel::update(
                chat_sessions::table.filter(
                    chat_sessions::id
                        .eq(session_id)
                        .and(chat_sessions::user_id.eq(user_id)),
                ),
            )
            .set(chat_sessions::player_chronicle_id.eq(None::<crate::db::DbId>))
            .execute(conn)
            .map_err(|e| {
                error!("Diesel error when unlinking chat session: {}", e);
                AppError::DatabaseQueryError(format!("Failed to unlink chat session: {e}"))
            })
        })
        .await?;

        if updated_count == 0 {
            return Err(AppError::NotFound("Chat session not found".to_string()));
        }

        info!(
            "Unlinked chat session {} from chronicle for user {}",
            session_id, user_id
        );
        Ok(())
    }

    /// Get the message variant ID for a specific message and variant index
    #[instrument(skip(self), fields(message_id = %message_id, variant_index = %variant_index))]
    pub async fn get_message_variant_id(
        &self,
        message_id: crate::db::DbId,
        variant_index: i32,
    ) -> Result<Option<crate::db::DbId>, AppError> {
        use crate::schema::message_variants;
        use diesel::prelude::*;

        let variant_id = crate::db::with_conn(&self.db_pool, move |conn| {
            message_variants::table
                .filter(
                    message_variants::parent_message_id
                        .eq(message_id)
                        .and(message_variants::variant_index.eq(variant_index)),
                )
                .select(message_variants::id)
                .first::<crate::db::DbId>(conn)
                .optional()
                .map_err(|e| {
                    error!("Diesel error when getting message variant ID: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to get message variant ID: {e}"))
                })
        })
        .await?;

        Ok(variant_id)
    }

    /// Get analysis information for chat deletion decisions
    /// Returns chronicle details including event counts and relationships
    #[instrument(skip(self), fields(user_id = %user_id, chat_session_id = %chat_session_id))]
    pub async fn get_chat_deletion_analysis(
        &self,
        user_id: crate::db::DbId,
        chat_session_id: crate::db::DbId,
    ) -> Result<Option<ChronicleAnalysisInfo>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let analysis = crate::db::with_conn(
            &self.db_pool,
            move |conn| -> Result<Option<ChronicleAnalysisInfo>, AppError> {
                use crate::schema::{chat_sessions, chronicle_events, player_chronicles};

                // First, get the chronicle ID from the chat session
                let chronicle_id_opt: Option<crate::db::DbId> = chat_sessions::table
                    .filter(
                        chat_sessions::id
                            .eq(chat_session_id)
                            .and(chat_sessions::user_id.eq(user_id)),
                    )
                    .select(chat_sessions::player_chronicle_id)
                    .first(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to get chat session: {e}"))
                    })?;

                let chronicle_id = match chronicle_id_opt {
                    Some(id) => id,
                    None => return Ok(None), // Chat has no chronicle
                };

                // Get chronicle basic info
                let chronicle: PlayerChronicle = player_chronicles::table
                    .filter(player_chronicles::id.eq(chronicle_id))
                    .filter(player_chronicles::user_id.eq(user_id))
                    .first(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to get chronicle: {e}"))
                    })?;

                // Count total events in chronicle
                let total_events: i64 = chronicle_events::table
                    .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count total events: {e}"))
                    })?;

                // Count events created by this specific chat
                let events_from_this_chat: i64 = chronicle_events::table
                    .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                    .filter(chronicle_events::chat_session_id.eq(chat_session_id))
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count chat events: {e}"))
                    })?;

                // Count other chats using this chronicle
                let other_chats_using_chronicle: i64 = chat_sessions::table
                    .filter(chat_sessions::player_chronicle_id.eq(chronicle_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .filter(chat_sessions::id.ne(chat_session_id)) // Exclude the current chat
                    .count()
                    .get_result(conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to count other chats: {e}"))
                    })?;

                let can_delete_chronicle = other_chats_using_chronicle == 0;

                Ok(Some(ChronicleAnalysisInfo {
                    id: chronicle.id,
                    name: chronicle.name,
                    total_events: total_events as i32,
                    events_from_this_chat: events_from_this_chat as i32,
                    other_chats_using_chronicle: other_chats_using_chronicle as i32,
                    can_delete_chronicle,
                }))
            },
        )
        .await?;

        #[cfg(feature = "sqlite-backend")]
        let analysis = crate::db::with_conn(&self.db_pool, move |conn| {
            Self::get_deletion_analysis_sync(conn, user_id, chat_session_id)
        })
        .await?;

        Ok(analysis)
    }

    /// Disassociate chronicle events from a chat session (nullify chat_session_id)
    /// Used for "disassociate" deletion strategy where events are preserved but unlinked
    #[instrument(skip(self), fields(user_id = %user_id, chat_session_id = %chat_session_id))]
    pub async fn disassociate_events_from_chat(
        &self,
        user_id: crate::db::DbId,
        chat_session_id: crate::db::DbId,
    ) -> Result<i32, AppError> {
        let updated_count = crate::db::with_conn(&self.db_pool, move |conn| {
            // TODO: Add ownership verification once the Chat Queryable issue is resolved
            // For now, we trust the caller to verify ownership at the API level

            // Disassociate the events by setting chat_session_id to NULL
            diesel::update(chronicle_events::table)
                .filter(chronicle_events::chat_session_id.eq(chat_session_id))
                .set(chronicle_events::chat_session_id.eq(None::<crate::db::DbId>))
                .execute(conn)
                .map_err(|e| {
                    error!("Diesel error when disassociating events: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to disassociate events: {e}"))
                })
        })
        .await?;

        info!(
            "Disassociated {} events from chat session {} for user {}",
            updated_count, chat_session_id, user_id
        );
        Ok(updated_count as i32)
    }

    /// Delete chronicle and all its events
    /// Used for "delete_chronicle" deletion strategy
    #[instrument(skip(self), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn delete_chronicle_completely(
        &self,
        user_id: crate::db::DbId,
        chronicle_id: crate::db::DbId,
    ) -> Result<(), AppError> {
        // First verify user owns the chronicle
        let _chronicle = self.get_chronicle(user_id, chronicle_id).await?;

        crate::db::with_conn(&self.db_pool, move |conn| {
            // Delete the chronicle (CASCADE will delete all chronicle_events)
            diesel::delete(player_chronicles::table)
                .filter(player_chronicles::id.eq(chronicle_id))
                .filter(player_chronicles::user_id.eq(user_id))
                .execute(conn)
                .map_err(|e| {
                    error!("Diesel error when deleting chronicle: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to delete chronicle: {e}"))
                })
        })
        .await?;

        info!(
            "Successfully deleted chronicle {} and all its events for user {}",
            chronicle_id, user_id
        );
        Ok(())
    }

    /// Process a cognitive update (Retain Pipeline)
    #[allow(clippy::too_many_arguments)]
    pub async fn process_cognitive_update(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        chat_session_id: Option<DbId>,
        message_variant_id: Option<DbId>,
        payload: CognitivePayload,
        session_dek: &SessionDek,
        state: Arc<crate::state::AppState>,
        game_time: Option<serde_json::Value>,
    ) -> Result<(), AppError> {
        info!(
            "Processing cognitive update for chronicle {} (significance: {})",
            chronicle_id, payload.significance_score
        );

        // 1. Strict Post-Filter (Significance Gate)
        if payload.significance_score < 0.4 {
            info!(
                "Cognitive update skipped: significance score {} < 0.4",
                payload.significance_score
            );
            return Ok(());
        }

        // 2. Create Chronicle Event (Episodic Memory)
        let event_request = CreateEventRequest {
            event_type: if payload.should_create_event {
                "NARRATIVE.EVENT".to_string()
            } else {
                "COGNITIVE.UPDATE".to_string()
            },
            summary: payload.summary.clone(),
            source: EventSource::AiExtracted,
            keywords: Some(payload.keywords.clone()),
            timestamp_iso8601: None,
            chat_session_id,
            message_variant_id,
        };

        self.create_event(user_id, chronicle_id, event_request, Some(session_dek))
            .await?;

        // 3. Process Facts (Hindsight Retain)
        for extraction in payload.facts {
            let fact_id = DbId::new();
            if let Err(e) = self
                .retain_cognitive_fact(
                    user_id,
                    chronicle_id,
                    fact_id,
                    extraction.clone(),
                    session_dek,
                    message_variant_id,
                )
                .await
            {
                error!("Failed to retain cognitive fact: {}", e);
            }

            // Trigger embedding for semantic search
            let fact_text = format!("{}", extraction);
            if let Err(e) = state
                .embedding_pipeline_service
                .process_and_embed_cognitive_fact(
                    state.clone(),
                    user_id,
                    fact_id,
                    chronicle_id,
                    &fact_text,
                    game_time.clone(),
                    message_variant_id,
                )
                .await
            {
                error!("Failed to embed cognitive fact: {}", e);
            }
        }

        // 4. Process Opinions (Semantic Memory - Upsert by Topic)
        for extraction in payload.opinions {
            self.retain_character_opinion(
                user_id,
                chronicle_id,
                extraction,
                payload.significance_score,
                session_dek,
                state.clone(),
                message_variant_id,
            )
            .await?;
        }

        // 5. Process Observations (Semantic Memory - Vector-First Entity Resolution)
        for extraction in payload.observations {
            self.retain_entity_observation(
                user_id,
                chronicle_id,
                extraction,
                payload.significance_score,
                session_dek,
                state.clone(),
                message_variant_id,
            )
            .await?;
        }

        // 6. Update Core Memory if delta is present (TITANS/MIRAS)
        if let Some(delta) = payload.core_memory_delta {
            if let Err(e) = self
                .update_core_memory(user_id, chronicle_id, delta, session_dek)
                .await
            {
                error!("Failed to update core memory: {}", e);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_character_opinion(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        extraction: crate::models::cognitive_memory::OpinionExtraction,
        significance: f32,
        session_dek: &SessionDek,
        state: Arc<crate::state::AppState>,
        message_variant_id: Option<DbId>,
    ) -> Result<(), AppError> {
        use crate::crypto::{encrypt_gcm, generate_hmac};

        let dek_bytes = session_dek.expose_bytes();
        let perspective_hash = generate_hmac(&extraction.perspective, dek_bytes);

        // --- Upsert by Topic (Forgetting Gate) ---
        // Search for existing opinions with high similarity (> 0.95)
        let similar_opinions = state
            .embedding_pipeline_service
            .retrieve_similar_opinions(
                state.clone(),
                user_id,
                &extraction.opinion,
                1,
                message_variant_id,
            )
            .await?;

        if let Some((score, meta)) = similar_opinions.first() {
            if *score > 0.95 {
                info!(
                    %user_id,
                    opinion_id = %meta.opinion_id,
                    score,
                    "Found highly similar opinion, triggering Forgetting Gate (Upsert by Topic)"
                );

                // Delete old opinion from DB
                #[cfg(feature = "postgres-backend")]
                {
                    let conn = self
                        .db_pool
                        .get()
                        .await
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                    let opinion_id_clone = meta.opinion_id;
                    conn.interact(move |conn| {
                        diesel::delete(
                            character_opinions::table
                                .filter(character_opinions::id.eq(opinion_id_clone)),
                        )
                        .execute(conn)
                    })
                    .await
                    .map_err(|e| AppError::DbInteractError(e.to_string()))?
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                }
                #[cfg(feature = "sqlite-backend")]
                {
                    let mut conn = self
                        .db_pool
                        .get()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                    diesel::delete(
                        character_opinions::table
                            .filter(character_opinions::id.eq(meta.opinion_id)),
                    )
                    .execute(&mut conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                }

                // Delete old opinion from Vector Store
                state
                    .embedding_pipeline_service
                    .delete_opinion_vector(state.clone(), meta.opinion_id, user_id)
                    .await?;
            }
        }

        let (perspective_encrypted, perspective_nonce) =
            encrypt_gcm(extraction.perspective.as_bytes(), &session_dek.0)?;

        let (opinion_encrypted, opinion_nonce) =
            encrypt_gcm(extraction.opinion.as_bytes(), &session_dek.0)?;

        let now = chrono::Utc::now();
        let opinion_id = DbId::new();
        let new_opinion = NewCharacterOpinion {
            id: opinion_id,
            user_id,
            chronicle_id,
            perspective_hash,
            perspective_encrypted,
            perspective_nonce,
            opinion_encrypted,
            opinion_nonce,
            confidence: extraction.confidence,
            significance,
            created_at: now.into(),
            updated_at: now.into(),
            message_variant_id,
        };

        #[cfg(feature = "postgres-backend")]
        {
            let conn = self
                .db_pool
                .get()
                .await
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            conn.interact(move |conn| {
                diesel::insert_into(character_opinions::table)
                    .values(&new_opinion)
                    .execute(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }
        #[cfg(feature = "sqlite-backend")]
        {
            let mut conn = self
                .db_pool
                .get()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            diesel::insert_into(character_opinions::table)
                .values(&new_opinion)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }

        // Embed the opinion for vector search
        state
            .embedding_pipeline_service
            .process_and_embed_opinion(
                state.clone(),
                user_id,
                opinion_id,
                &extraction.opinion,
                message_variant_id,
            )
            .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_entity_observation(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        extraction: crate::models::cognitive_memory::ObservationExtraction,
        significance: f32,
        session_dek: &SessionDek,
        state: Arc<crate::state::AppState>,
        message_variant_id: Option<DbId>,
    ) -> Result<(), AppError> {
        use crate::crypto::{encrypt_gcm, generate_hmac};

        let dek_bytes = session_dek.expose_bytes();

        // Vector-First Entity Resolution
        let similar_entities = state
            .embedding_pipeline_service
            .retrieve_similar_entities(
                state.clone(),
                user_id,
                &extraction.entity_name,
                1,
                message_variant_id,
            )
            .await?;

        let entity_name_hash = if let Some((score, meta)) = similar_entities.first() {
            if *score > 0.89 {
                info!(
                    "Entity resolution: matched '{}' to existing entity with score {}",
                    extraction.entity_name, score
                );
                meta.entity_name_hash.clone()
            } else {
                let hash = generate_hmac(&extraction.entity_name, dek_bytes);
                state
                    .embedding_pipeline_service
                    .process_and_embed_entity(
                        state.clone(),
                        user_id,
                        &extraction.entity_name,
                        &hash,
                        message_variant_id,
                    )
                    .await?;
                hash
            }
        } else {
            let hash = generate_hmac(&extraction.entity_name, dek_bytes);
            state
                .embedding_pipeline_service
                .process_and_embed_entity(
                    state.clone(),
                    user_id,
                    &extraction.entity_name,
                    &hash,
                    message_variant_id,
                )
                .await?;
            hash
        };

        let (entity_name_encrypted, entity_name_nonce) =
            encrypt_gcm(extraction.entity_name.as_bytes(), &session_dek.0)?;

        let (observation_encrypted, observation_nonce) =
            encrypt_gcm(extraction.observation.as_bytes(), &session_dek.0)?;

        let now = chrono::Utc::now();
        let new_observation = NewEntityObservation {
            id: DbId::new(),
            user_id,
            chronicle_id,
            entity_name_hash,
            entity_name_encrypted,
            entity_name_nonce,
            observation_encrypted,
            observation_nonce,
            confidence: extraction.confidence,
            significance,
            created_at: now.into(),
            updated_at: now.into(),
            message_variant_id,
        };

        #[cfg(feature = "postgres-backend")]
        {
            let conn = self
                .db_pool
                .get()
                .await
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            conn.interact(move |conn| {
                diesel::insert_into(entity_observations::table)
                    .values(&new_observation)
                    .execute(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }
        #[cfg(feature = "sqlite-backend")]
        {
            let mut conn = self
                .db_pool
                .get()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            diesel::insert_into(entity_observations::table)
                .values(&new_observation)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }

        Ok(())
    }

    /// Get the core memory for a chronicle
    pub async fn get_core_memory(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
    ) -> Result<Option<crate::models::cognitive_memory::CoreMemory>, AppError> {
        use crate::models::cognitive_memory::CoreMemory;

        crate::db::with_conn(&self.db_pool, move |conn| {
            cognitive_core_memory::table
                .filter(
                    cognitive_core_memory::user_id
                        .eq(user_id)
                        .and(cognitive_core_memory::chronicle_id.eq(chronicle_id)),
                )
                .order(cognitive_core_memory::updated_at.desc())
                .first::<CoreMemory>(conn)
                .optional()
                .map_err(|e| {
                    error!("Diesel error when getting core memory: {}", e);
                    AppError::DatabaseQueryError(format!("Failed to get core memory: {e}"))
                })
        })
        .await
    }

    /// Retain a cognitive fact (Hindsight 5D Fact)
    pub async fn retain_cognitive_fact(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        fact_id: DbId,
        extraction: crate::models::cognitive_memory::ExtractedFact,
        session_dek: &SessionDek,
        message_variant_id: Option<DbId>,
    ) -> Result<(), AppError> {
        use crate::crypto::encrypt_gcm;
        use crate::models::cognitive_memory::NewCognitiveFact;

        let (who_encrypted, who_nonce) = encrypt_gcm(extraction.who.as_bytes(), &session_dek.0)?;
        let (what_encrypted, what_nonce) = encrypt_gcm(extraction.what.as_bytes(), &session_dek.0)?;
        let (where_encrypted, where_nonce) =
            encrypt_gcm(extraction.r#where.as_bytes(), &session_dek.0)?;
        let (when_encrypted, when_nonce) = encrypt_gcm(extraction.when.as_bytes(), &session_dek.0)?;
        let (why_encrypted, why_nonce) = encrypt_gcm(extraction.why.as_bytes(), &session_dek.0)?;

        let now = chrono::Utc::now();
        let new_fact = NewCognitiveFact {
            id: fact_id,
            user_id,
            chronicle_id,
            who_encrypted,
            who_nonce,
            what_encrypted,
            what_nonce,
            where_encrypted,
            where_nonce,
            when_encrypted,
            when_nonce,
            why_encrypted,
            why_nonce,
            fact_type: extraction.fact_type,
            confidence: extraction.confidence,
            significance: extraction.significance,
            created_at: now.into(),
            message_variant_id,
        };

        #[cfg(feature = "postgres-backend")]
        {
            let conn = self
                .db_pool
                .get()
                .await
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            conn.interact(move |conn| {
                diesel::insert_into(cognitive_facts::table)
                    .values(&new_fact)
                    .execute(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }
        #[cfg(feature = "sqlite-backend")]
        {
            let mut conn = self
                .db_pool
                .get()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            diesel::insert_into(cognitive_facts::table)
                .values(&new_fact)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }

        Ok(())
    }

    /// Update the core memory for a chronicle (TITANS/MIRAS Neural State)
    pub async fn update_core_memory(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        new_state: String,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        use crate::crypto::encrypt_gcm;
        use crate::models::cognitive_memory::NewCoreMemory;

        let (memory_state_encrypted, memory_state_nonce) =
            encrypt_gcm(new_state.as_bytes(), &session_dek.0)?;

        let now = chrono::Utc::now();
        let new_memory = NewCoreMemory {
            id: DbId::new(),
            user_id,
            chronicle_id,
            memory_state_encrypted,
            memory_state_nonce,
            version: 1, // TODO: Increment version if updating existing
            updated_at: now.into(),
        };

        #[cfg(feature = "postgres-backend")]
        {
            let conn = self
                .db_pool
                .get()
                .await
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            conn.interact(move |conn| {
                diesel::insert_into(cognitive_core_memory::table)
                    .values(&new_memory)
                    .execute(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }
        #[cfg(feature = "sqlite-backend")]
        {
            let mut conn = self
                .db_pool
                .get()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            diesel::insert_into(cognitive_core_memory::table)
                .values(&new_memory)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        }

        Ok(())
    }
}

/// Information about a chronicle for deletion analysis
#[derive(Debug, Clone)]
pub struct ChronicleAnalysisInfo {
    pub id: crate::db::DbId,
    pub name: String,
    pub total_events: i32,
    pub events_from_this_chat: i32,
    pub other_chats_using_chronicle: i32,
    pub can_delete_chronicle: bool,
}
