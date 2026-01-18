use crate::auth::session_dek::SessionDek;
use crate::db::DbId;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::cognitive_memory::{CharacterOpinion, CognitiveFact, EntityObservation};
use crate::schema::{
    character_opinions, chat_messages, cognitive_facts, entity_observations, message_variants,
};
use crate::services::hybrid_token_counter::CountingMode;
use crate::state::AppState;
use diesel::prelude::*;
use std::sync::Arc;
use tracing::{debug, info, instrument};

pub struct RecallPipeline {
    db_pool: DbPool,
}

impl RecallPipeline {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    /// Retrieves relevant cognitive context (Opinions and Observations) for a query.
    #[instrument(skip(self, session_dek, state), fields(user_id = %user_id, chronicle_id = %chronicle_id))]
    pub async fn recall_context(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        query: &str,
        session_dek: &SessionDek,
        state: Arc<AppState>,
        target_actors: Option<Vec<String>>, // Added for actor-specific filtering
        max_game_time_day: Option<i64>,     // Added for temporal filtering
        active_variant_id: Option<DbId>,    // Added for variant-aware retrieval
    ) -> Result<String, AppError> {
        info!("Recalling cognitive context for query: {}", query);

        // 0. Hindsight Head: Search for Cognitive Facts via Vector DB
        let similar_facts = state
            .embedding_pipeline_service
            .retrieve_similar_facts(
                state.clone(),
                user_id,
                chronicle_id,
                query,
                5,
                max_game_time_day,
                active_variant_id,
            )
            .await?;

        let mut matching_facts = Vec::new();
        let mut other_facts = Vec::new();
        for (score, meta) in similar_facts {
            if score > 0.55 {
                // Lowered threshold for facts
                if let Some(fact) = self
                    .get_fact_by_id(user_id, chronicle_id, meta.fact_id)
                    .await?
                {
                    let mut is_match = false;
                    // If target_actors is provided, prioritize facts involving them
                    if let Some(ref actors) = target_actors {
                        if let Ok(decrypted) = fact.decrypt(session_dek) {
                            if actors.iter().any(|a| {
                                decrypted.who.to_lowercase().contains(&a.to_lowercase())
                                    || decrypted.what.to_lowercase().contains(&a.to_lowercase())
                            }) {
                                is_match = true;
                            }
                        }
                    }

                    if is_match {
                        matching_facts.push(fact);
                    } else {
                        other_facts.push(fact);
                    }
                }
            }
        }
        let mut facts = matching_facts;
        facts.extend(other_facts);

        // 1. Dogmatic Head: Search for Opinions via Vector DB
        let similar_opinions = state
            .embedding_pipeline_service
            .retrieve_similar_opinions(state.clone(), user_id, query, 5, active_variant_id)
            .await?;

        let mut matching_opinions = Vec::new();
        let mut other_opinions = Vec::new();
        for (score, meta) in similar_opinions {
            if score > 0.65 {
                // Lowered threshold
                if let Some(opinion) = self
                    .get_opinion_by_id(user_id, chronicle_id, meta.opinion_id)
                    .await?
                {
                    let mut is_match = false;
                    // If target_actors is provided, prioritize opinions from/about them
                    if let Some(ref actors) = target_actors {
                        if let Ok(decrypted) = opinion.decrypt(session_dek) {
                            if actors
                                .iter()
                                .any(|a| decrypted.to_lowercase().contains(&a.to_lowercase()))
                            {
                                is_match = true;
                            }
                        }
                    }

                    if is_match {
                        matching_opinions.push(opinion);
                    } else {
                        other_opinions.push(opinion);
                    }
                }
            }
        }
        let mut opinions = matching_opinions;
        opinions.extend(other_opinions);

        // --- Dedup-on-Read for Opinions ---
        // Group by perspective_hash and take the latest
        use std::collections::HashMap;
        let mut latest_opinions: HashMap<String, CharacterOpinion> = HashMap::new();
        for op in opinions {
            let entry = latest_opinions
                .entry(op.perspective_hash.clone())
                .or_insert_with(|| op.clone());
            if op.created_at > entry.created_at {
                *entry = op;
            }
        }
        let mut final_opinions: Vec<CharacterOpinion> = latest_opinions.into_values().collect();
        final_opinions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // 2. State Head: Search for Entities via Vector DB, then fetch Observations
        let similar_entities = state
            .embedding_pipeline_service
            .retrieve_similar_entities(state.clone(), user_id, query, 5, active_variant_id)
            .await?;

        let mut observations = Vec::new();
        for (score, meta) in similar_entities {
            if score > 0.70 {
                let entity_obs = self
                    .get_observations_by_hash(user_id, chronicle_id, &meta.entity_name_hash)
                    .await?;
                observations.extend(entity_obs);
            }
        }

        // --- Dedup-on-Read for Observations ---
        // Group by entity_name_hash and take the latest
        let mut latest_observations: HashMap<String, EntityObservation> = HashMap::new();
        for obs in observations {
            let entry = latest_observations
                .entry(obs.entity_name_hash.clone())
                .or_insert_with(|| obs.clone());
            if obs.created_at > entry.created_at {
                *entry = obs;
            }
        }
        let mut final_observations: Vec<EntityObservation> =
            latest_observations.into_values().collect();
        final_observations.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // 3. Decrypt and Format
        let mut context_parts = Vec::new();
        let mut current_tokens: usize = 0;
        const TOKEN_LIMIT: usize = 1000; // Increased limit for richer context

        // Add Current Game Time header if available
        if let Some(day) = max_game_time_day {
            context_parts.push(format!("### Current Game Time: Day {}", day));
            context_parts.push("".to_string());
        }

        // Format Facts (Hindsight)
        if !facts.is_empty() {
            context_parts.push("### Narrative Facts".to_string());
            for fact in facts {
                if let Ok(decrypted) = fact.decrypt(session_dek) {
                    let entry = format!("- {}", decrypted);
                    let estimate = state
                        .token_counter
                        .count_tokens(&entry, CountingMode::LocalOnly, None)
                        .await?;
                    let tokens = estimate.total;
                    if current_tokens + tokens > TOKEN_LIMIT {
                        break;
                    }
                    context_parts.push(entry);
                    current_tokens += tokens;
                }
            }
        }

        // Format Opinions
        if !final_opinions.is_empty() {
            context_parts.push("### Character Opinions".to_string());
            for op in final_opinions {
                if let Ok(decrypted) = op.decrypt(session_dek) {
                    let entry = format!("- {}", decrypted);
                    let estimate = state
                        .token_counter
                        .count_tokens(&entry, CountingMode::LocalOnly, None)
                        .await?;
                    let tokens = estimate.total;
                    if current_tokens + tokens > TOKEN_LIMIT {
                        break;
                    }
                    context_parts.push(entry);
                    current_tokens += tokens;
                }
            }
        }

        // Format Observations
        if !final_observations.is_empty() && current_tokens < TOKEN_LIMIT {
            if !context_parts.is_empty() {
                context_parts.push("".to_string());
            }
            context_parts.push("### Entity Observations".to_string());
            for obs in final_observations {
                if let Ok(decrypted) = obs.decrypt(session_dek) {
                    let entry = format!("- {}", decrypted);
                    let estimate = state
                        .token_counter
                        .count_tokens(&entry, CountingMode::LocalOnly, None)
                        .await?;
                    let tokens = estimate.total;
                    if current_tokens + tokens > TOKEN_LIMIT {
                        break;
                    }
                    context_parts.push(entry);
                    current_tokens += tokens;
                }
            }
        }

        let context = context_parts.join("\n");
        debug!(
            "Recalled cognitive context ({} chars, ~{} tokens)",
            context.len(),
            current_tokens
        );

        Ok(context)
    }

    async fn get_opinion_by_id(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        opinion_id: DbId,
    ) -> Result<Option<CharacterOpinion>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&self.db_pool).await?;

        #[cfg(feature = "postgres-backend")]
        let result = conn
            .interact(move |conn| {
                character_opinions::table
                    .left_join(message_variants::table)
                    .left_join(
                        chat_messages::table
                            .on(message_variants::parent_message_id.eq(chat_messages::id)),
                    )
                    .filter(character_opinions::user_id.eq(user_id))
                    .filter(character_opinions::chronicle_id.eq(chronicle_id))
                    .filter(character_opinions::id.eq(opinion_id))
                    .filter(character_opinions::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ))
                    .select(CharacterOpinion::as_select())
                    .first::<CharacterOpinion>(conn)
                    .optional()
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        #[cfg(feature = "sqlite-backend")]
        let result = {
            let opinion_opt = character_opinions::table
                .filter(character_opinions::user_id.eq(user_id))
                .filter(character_opinions::chronicle_id.eq(chronicle_id))
                .filter(character_opinions::id.eq(opinion_id))
                .first::<CharacterOpinion>(&mut conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if let Some(opinion) = opinion_opt {
                if let Some(variant_id) = opinion.message_variant_id.clone() {
                    let is_active = message_variants::table
                        .inner_join(chat_messages::table)
                        .filter(message_variants::id.eq(variant_id))
                        .filter(
                            message_variants::variant_index
                                .eq(chat_messages::current_variant_index),
                        )
                        .select(message_variants::id)
                        .first::<crate::db::DbId>(&mut conn)
                        .optional()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                        .is_some();

                    if is_active {
                        Some(opinion)
                    } else {
                        None
                    }
                } else {
                    Some(opinion)
                }
            } else {
                None
            }
        };

        Ok(result)
    }

    async fn get_observations_by_hash(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        entity_name_hash: &str,
    ) -> Result<Vec<EntityObservation>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&self.db_pool).await?;
        let entity_name_hash = entity_name_hash.to_string();

        #[cfg(feature = "postgres-backend")]
        let results = conn
            .interact(move |conn| {
                entity_observations::table
                    .left_join(message_variants::table)
                    .left_join(
                        chat_messages::table
                            .on(message_variants::parent_message_id.eq(chat_messages::id)),
                    )
                    .filter(entity_observations::user_id.eq(user_id))
                    .filter(entity_observations::chronicle_id.eq(chronicle_id))
                    .filter(entity_observations::entity_name_hash.eq(&entity_name_hash))
                    .filter(entity_observations::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ))
                    .order(entity_observations::created_at.desc())
                    .limit(5)
                    .select(EntityObservation::as_select())
                    .load::<EntityObservation>(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        #[cfg(feature = "sqlite-backend")]
        let results = {
            // Fetch potential candidates (fetch more than needed to account for filtering)
            let candidates = entity_observations::table
                .filter(entity_observations::user_id.eq(user_id))
                .filter(entity_observations::chronicle_id.eq(chronicle_id))
                .filter(entity_observations::entity_name_hash.eq(&entity_name_hash))
                .order(entity_observations::created_at.desc())
                .limit(20) // Fetch more to allow for filtering
                .load::<EntityObservation>(&mut conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let mut valid_results = Vec::new();
            for obs in candidates {
                if let Some(variant_id) = obs.message_variant_id.clone() {
                    let is_active = message_variants::table
                        .inner_join(chat_messages::table)
                        .filter(message_variants::id.eq(variant_id))
                        .filter(
                            message_variants::variant_index
                                .eq(chat_messages::current_variant_index),
                        )
                        .select(message_variants::id)
                        .first::<crate::db::DbId>(&mut conn)
                        .optional()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                        .is_some();

                    if is_active {
                        valid_results.push(obs);
                    }
                } else {
                    valid_results.push(obs);
                }

                if valid_results.len() >= 5 {
                    break;
                }
            }
            valid_results
        };

        Ok(results)
    }

    pub async fn get_fact_by_id(
        &self,
        user_id: DbId,
        chronicle_id: DbId,
        fact_id: DbId,
    ) -> Result<Option<CognitiveFact>, AppError> {
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        #[cfg(feature = "postgres-backend")]
        let conn = crate::db::get_conn(&self.db_pool).await?;
        #[cfg(feature = "sqlite-backend")]
        let mut conn = crate::db::get_conn(&self.db_pool).await?;

        #[cfg(feature = "postgres-backend")]
        let result = conn
            .interact(move |conn| {
                cognitive_facts::table
                    .left_join(message_variants::table)
                    .left_join(
                        chat_messages::table
                            .on(message_variants::parent_message_id.eq(chat_messages::id)),
                    )
                    .filter(cognitive_facts::user_id.eq(user_id))
                    .filter(cognitive_facts::chronicle_id.eq(chronicle_id))
                    .filter(cognitive_facts::id.eq(fact_id))
                    .filter(cognitive_facts::message_variant_id.is_null().or(
                        message_variants::variant_index.eq(chat_messages::current_variant_index),
                    ))
                    .select(CognitiveFact::as_select())
                    .first::<CognitiveFact>(conn)
                    .optional()
            })
            .await
            .map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        #[cfg(feature = "sqlite-backend")]
        let result = {
            let fact_opt = cognitive_facts::table
                .filter(cognitive_facts::user_id.eq(user_id))
                .filter(cognitive_facts::chronicle_id.eq(chronicle_id))
                .filter(cognitive_facts::id.eq(fact_id))
                .first::<CognitiveFact>(&mut conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if let Some(fact) = fact_opt {
                if let Some(variant_id) = fact.message_variant_id.clone() {
                    let is_active = message_variants::table
                        .inner_join(chat_messages::table)
                        .filter(message_variants::id.eq(variant_id))
                        .filter(
                            message_variants::variant_index
                                .eq(chat_messages::current_variant_index),
                        )
                        .select(message_variants::id)
                        .first::<crate::db::DbId>(&mut conn)
                        .optional()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?
                        .is_some();

                    if is_active {
                        Some(fact)
                    } else {
                        None
                    }
                } else {
                    Some(fact)
                }
            } else {
                None
            }
        };

        Ok(result)
    }
}
