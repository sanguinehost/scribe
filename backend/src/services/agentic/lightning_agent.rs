use crate::errors::AppError;
use crate::services::progressive_cache::{
    ProgressiveCacheService, Context, ImmediateContext, EnhancedContext, FullContext,
};
use crate::auth::session_dek::SessionDek;
use crate::schema::characters;
use crate::services::ecs_entity_manager::EcsEntityManager;
use crate::services::agent_results_service::AgentResultsService;
use crate::models::agent_results::{AgentResultQuery, AgentType, OperationType};
use crate::models::agent_results::DecryptedAgentResult;
use diesel::prelude::*;
use deadpool_diesel::postgres::Pool as PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, instrument};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tokio::time::timeout;

/// Lightning Agent - Cache-first agent for sub-2-second context retrieval
/// 
/// This agent is designed exclusively for rapid context retrieval without any
/// analysis or processing. It progressively retrieves cached context layers
/// to provide the fastest possible response to the operational layer.
#[derive(Clone)]
pub struct LightningAgent {
    cache_service: Arc<ProgressiveCacheService>,
    redis_client: Option<Arc<redis::Client>>, // Optional Redis for caching
    redis_enabled: bool,
    redis_timeout_ms: u64,
    db_pool: PgPool,
    entity_manager: Arc<EcsEntityManager>,
    agent_results_service: Arc<AgentResultsService>,
}

/// Progressive context retrieved by the Lightning Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressiveContext {
    /// The actual context data (Full, Enhanced, Immediate, or Minimal)
    pub context: Context,
    /// Time taken to retrieve the context in milliseconds
    pub retrieval_time_ms: u64,
    /// Which cache layer was hit (if any)
    pub cache_layer: CacheLayer,
    /// Quality score of the context (1.0 = full, 0.0 = minimal)
    pub quality_score: f32,
    /// Session ID for tracking
    pub session_id: Uuid,
    /// User ID for tracking
    pub user_id: Uuid,
}

/// Indicates which cache layer provided the context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CacheLayer {
    Full,
    Enhanced,
    Immediate,
    Minimal,
    None,
}

impl LightningAgent {
    /// Create a new Lightning Agent
    pub fn new(
        cache_service: Arc<ProgressiveCacheService>,
        redis_client: Option<Arc<redis::Client>>,
        redis_enabled: bool,
        redis_timeout_ms: u64,
        db_pool: PgPool,
        entity_manager: Arc<EcsEntityManager>,
        agent_results_service: Arc<AgentResultsService>,
    ) -> Self {
        Self {
            cache_service,
            redis_client,
            redis_enabled,
            redis_timeout_ms,
            db_pool,
            entity_manager,
            agent_results_service,
        }
    }

    /// Retrieve progressive context with strict timeout enforcement
    /// 
    /// This method attempts to retrieve the richest available context
    /// within a 500ms timeout window. It falls through cache layers
    /// from Full -> Enhanced -> Immediate -> Minimal, and progressively
    /// enriches the context with agent results from background processing.
    #[instrument(skip(self, session_dek), fields(session_id = %session_id, user_id = %user_id))]
    pub async fn retrieve_progressive_context(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<ProgressiveContext, AppError> {
        let start = Instant::now();
        
        // Launch both cache retrieval and agent results retrieval concurrently
        // This ensures we maximize our chances of enriching the context within the time budget
        let cache_future = timeout(
            Duration::from_millis(300),
            self.cache_service.get_context(session_id)
        );
        
        let agent_results_future = self.retrieve_relevant_agent_results(
            session_id,
            user_id,
            session_dek
        );
        
        // Execute both futures concurrently
        let (context_result, agent_results_result) = tokio::join!(cache_future, agent_results_future);
        
        // Process cache results
        let (mut context, cache_layer) = match context_result {
            Ok(Ok(ctx)) => {
                let layer = match &ctx {
                    Context::Full(_) => CacheLayer::Full,
                    Context::Enhanced(_) => CacheLayer::Enhanced,
                    Context::Immediate(_) => CacheLayer::Immediate,
                    Context::Minimal => CacheLayer::Minimal,
                };
                (ctx, layer)
            }
            Ok(Err(e)) => {
                warn!("Cache retrieval error: {}", e);
                (Context::Minimal, CacheLayer::None)
            }
            Err(_) => {
                warn!("Cache retrieval timeout after 300ms");
                (Context::Minimal, CacheLayer::None)
            }
        };
        
        // Process agent results and integrate into context
        match agent_results_result {
            Ok(agent_results) if !agent_results.is_empty() => {
                info!("Enriching context with {} agent results", agent_results.len());
                context = self.integrate_agent_results_into_context(context, agent_results);
            }
            Ok(_) => {
                debug!("No new agent results to integrate");
            }
            Err(e) => {
                warn!("Failed to retrieve agent results: {}", e);
            }
        }
        
        let quality_score = match &context {
            Context::Full(_) => 1.0,
            Context::Enhanced(_) => 0.7,
            Context::Immediate(_) => 0.4,
            Context::Minimal => 0.1,
        };
        
        let retrieval_time_ms = start.elapsed().as_millis() as u64;
        
        debug!(
            "Lightning context retrieval: {}ms, layer: {:?}, quality: {}",
            retrieval_time_ms, cache_layer, quality_score
        );
        
        // Log performance metrics
        if retrieval_time_ms > 200 {
            warn!(
                "Lightning retrieval exceeded 200ms target: {}ms",
                retrieval_time_ms
            );
        }
        
        Ok(ProgressiveContext {
            context,
            retrieval_time_ms,
            cache_layer,
            quality_score,
            session_id,
            user_id,
        })
    }

    /// Retrieve relevant agent results for progressive enrichment
    /// 
    /// This method selectively fetches agent results that are relevant to the current
    /// roleplay context based on session and timing. It retrieves unretrieved results
    /// from the background orchestration to progressively enrich the lightning agent's
    /// responses.
    #[instrument(skip(self, session_dek), fields(session_id = %session_id, user_id = %user_id))]
    pub async fn retrieve_relevant_agent_results(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<Vec<DecryptedAgentResult>, AppError> {
        let start = Instant::now();
        
        // Query for unretrieved agent results from the current session
        // This ensures we only get new insights from the background orchestration
        let query = AgentResultQuery {
            session_id: Some(session_id),
            user_id: Some(user_id),
            agent_types: None, // Get all agent types
            operation_types: None, // Get all operation types
            unretrieved_only: true, // Only get results not yet used by lightning agent
            since_timestamp: None, // Get all unretrieved results
            limit: Some(50), // Reasonable limit to avoid overwhelming the lightning agent
        };
        
        // Retrieve with timeout to maintain lightning speed
        let results = timeout(
            Duration::from_millis(300), // 300ms timeout for agent results retrieval
            self.agent_results_service.retrieve_agent_results(query, session_dek)
        ).await;
        
        let decrypted_results = match results {
            Ok(Ok(results)) => {
                debug!(
                    "Retrieved {} agent results in {}ms",
                    results.len(),
                    start.elapsed().as_millis()
                );
                results
            }
            Ok(Err(e)) => {
                warn!("Failed to retrieve agent results: {}", e);
                Vec::new()
            }
            Err(_) => {
                warn!("Agent results retrieval timeout after 300ms");
                Vec::new()
            }
        };
        
        // Mark retrieved results as used to prevent re-processing
        if !decrypted_results.is_empty() {
            let mark_result = self.agent_results_service
                .mark_results_retrieved(session_id, user_id, None)
                .await;
            
            if let Err(e) = mark_result {
                warn!("Failed to mark agent results as retrieved: {}", e);
            }
        }
        
        Ok(decrypted_results)
    }

    /// Integrate agent results into the context for progressive enrichment
    /// 
    /// This method takes agent results and integrates them into the appropriate
    /// context layer based on their relevance and type. This enables progressive
    /// enrichment where subsequent lightning agent calls have access to background
    /// processing results.
    pub fn integrate_agent_results_into_context(
        &self,
        base_context: Context,
        agent_results: Vec<DecryptedAgentResult>,
    ) -> Context {
        if agent_results.is_empty() {
            return base_context;
        }

        debug!("Integrating {} agent results into context", agent_results.len());

        // Group results by agent type for organized integration
        let mut perception_insights = Vec::new();
        let mut tactical_insights = Vec::new();
        let mut strategic_insights = Vec::new();

        for result in agent_results {
            match result.agent_type.as_str() {
                "Perception" => {
                    perception_insights.push(result.result.clone());
                }
                "Tactical" => {
                    tactical_insights.push(result.result.clone());
                }
                "Strategic" => {
                    strategic_insights.push(result.result.clone());
                }
                _ => {
                    debug!("Unknown agent type: {:?}", result.agent_type);
                }
            }
        }

        // For now, we'll add insights as additional context to existing structures
        // In a future iteration, we might want to create specialized fields for agent insights
        match base_context {
            Context::Full(mut full) => {
                // TODO: Integrate insights into FullContext structure
                Context::Full(full)
            }
            Context::Enhanced(mut enhanced) => {
                // TODO: Integrate insights into EnhancedContext structure
                Context::Enhanced(enhanced)
            }
            Context::Immediate(immediate) => {
                // For immediate context, we can create an enhanced context with agent insights
                let mut visible_entities = Vec::new();
                let mut active_threads = Vec::new();

                // Extract entity information from perception insights
                for insight in &perception_insights {
                    if let Some(entities) = insight.get("entities").and_then(|e| e.as_array()) {
                        for entity in entities {
                            if let Some(name) = entity.get("name").and_then(|n| n.as_str()) {
                                visible_entities.push(crate::services::progressive_cache::EntitySummary {
                                    entity_id: Uuid::new_v4(), // Placeholder
                                    name: name.to_string(),
                                    description: entity.get("description")
                                        .and_then(|d| d.as_str())
                                        .unwrap_or("").to_string(),
                                    entity_type: entity.get("type")
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("unknown").to_string(),
                                });
                            }
                        }
                    }
                }

                // Extract narrative threads from strategic insights
                for insight in &strategic_insights {
                    if let Some(threads) = insight.get("narrative_threads").and_then(|t| t.as_array()) {
                        for thread in threads {
                            if let Some(description) = thread.get("description").and_then(|d| d.as_str()) {
                                active_threads.push(crate::services::progressive_cache::NarrativeThread {
                                    thread_id: Uuid::new_v4(), // Placeholder
                                    description: description.to_string(),
                                    priority: thread.get("priority")
                                        .and_then(|p| p.as_f64())
                                        .unwrap_or(0.5) as f32,
                                });
                            }
                        }
                    }
                }

                let enhanced = crate::services::progressive_cache::EnhancedContext {
                    immediate,
                    visible_entities,
                    location_details: crate::services::progressive_cache::Location {
                        location_id: Uuid::new_v4(), // Placeholder
                        name: "Current Location".to_string(),
                        description: "Location enriched with agent insights".to_string(),
                        scale: "local".to_string(),
                    },
                    character_relationships: Vec::new(), // TODO: Extract from agent results
                    active_narrative_threads: active_threads,
                };
                Context::Enhanced(enhanced)
            }
            Context::Minimal => {
                // For minimal context, stay minimal unless we have very relevant insights
                base_context
            }
        }
    }

    /// Build minimal prompt for when no cache is available
    pub fn build_minimal_prompt(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> String {
        format!(
            "Continue the conversation naturally. Session: {}, User: {}",
            session_id, user_id
        )
    }

    /// Build immediate prompt from immediate context
    pub fn build_immediate_prompt(
        &self,
        immediate: &ImmediateContext,
    ) -> String {
        let recent_summary = immediate.recent_messages
            .iter()
            .map(|m| format!("- {}", m.summary))
            .collect::<Vec<_>>()
            .join("\n");
        
        format!(
            "Current location: {}\nActive character: {}\n\nRecent conversation:\n{}",
            immediate.current_location_name,
            immediate.active_character_name
                .as_deref()
                .unwrap_or("None"),
            recent_summary
        )
    }

    /// Build enhanced prompt from enhanced context
    pub fn build_enhanced_prompt(
        &self,
        enhanced: &EnhancedContext,
    ) -> String {
        let base = self.build_immediate_prompt(&enhanced.immediate);
        
        let entities = enhanced.visible_entities
            .iter()
            .map(|e| format!("- {}: {}", e.name, e.description))
            .collect::<Vec<_>>()
            .join("\n");
        
        let relationships = enhanced.character_relationships
            .iter()
            .map(|r| format!("- {} with {}: {}", r.relationship_type, r.target_name, r.strength))
            .collect::<Vec<_>>()
            .join("\n");
        
        let threads = enhanced.active_narrative_threads
            .iter()
            .map(|t| format!("- {}: {}", t.thread_id, t.description))
            .collect::<Vec<_>>()
            .join("\n");
        
        format!(
            "{}\n\nLocation details: {} - {}\n\nVisible entities:\n{}\n\nRelationships:\n{}\n\nActive narrative threads:\n{}",
            base,
            enhanced.location_details.name,
            enhanced.location_details.description,
            entities,
            relationships,
            threads
        )
    }

    /// Build rich prompt from full context
    pub fn build_rich_prompt(
        &self,
        full: &FullContext,
    ) -> String {
        let base = self.build_enhanced_prompt(&full.enhanced);
        
        let salience_summary = full.entity_salience_scores
            .iter()
            .filter(|(_, score)| score.score > 0.5)
            .map(|(id, score)| format!("- {}: {:.2} ({})", id, score.score, score.reason))
            .collect::<Vec<_>>()
            .join("\n");
        
        let memory_summary = full.memory_associations
            .iter()
            .take(5) // Limit to most relevant
            .map(|m| format!("- {}: {}", m.memory_type, m.content))
            .collect::<Vec<_>>()
            .join("\n");
        
        format!(
            "{}\n\nImportant entities (by salience):\n{}\n\nRelevant memories:\n{}\n\nNarrative state: {}",
            base,
            salience_summary,
            memory_summary,
            full.narrative_state.current_phase
        )
    }

    /// Convert context to prompt string based on type
    pub fn context_to_prompt(&self, context: &Context) -> String {
        match context {
            Context::Full(full) => self.build_rich_prompt(full),
            Context::Enhanced(enhanced) => self.build_enhanced_prompt(enhanced),
            Context::Immediate(immediate) => self.build_immediate_prompt(immediate),
            Context::Minimal => self.build_minimal_prompt(Uuid::new_v4(), Uuid::new_v4()),
        }
    }

    /// Check cache health for monitoring
    pub async fn check_cache_health(&self) -> Result<CacheHealth, AppError> {
        let start = Instant::now();
        
        // Check Redis health only if enabled and available
        let redis_healthy = if self.redis_enabled {
            if let Some(redis_client) = &self.redis_client {
                match redis_client.get_multiplexed_async_connection().await {
                    Ok(mut conn) => {
                        let ping_result: Result<String, _> = redis::cmd("PING")
                            .query_async(&mut conn)
                            .await;
                        ping_result.is_ok()
                    }
                    Err(e) => {
                        warn!("Redis connection failed: {}", e);
                        false
                    }
                }
            } else {
                warn!("Redis enabled but no client configured");
                false
            }
        } else {
            true // Redis disabled, consider healthy
        };
        
        let response_time_ms = start.elapsed().as_millis() as u64;
        
        Ok(CacheHealth {
            redis_healthy,
            response_time_ms,
            cache_service_healthy: true, // Assume healthy if we got this far
        })
    }


    /// Resolve character name from UUID
    async fn resolve_character_name(&self, character_id: Uuid, user_id: Uuid) -> Result<String, AppError> {
        let db_pool = self.db_pool.clone();
        let character_name = db_pool
            .get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e)))?
            .interact(move |conn| {
                characters::table
                    .filter(characters::id.eq(character_id))
                    .filter(characters::user_id.eq(user_id))
                    .select(characters::name)
                    .first::<String>(conn)
            })
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query character: {}", e)))?;
        
        Ok(character_name)
    }

    /// Resolve entity name from UUID using ECS system
    async fn resolve_entity_name(&self, entity_id: Uuid, user_id: Uuid) -> Result<String, AppError> {
        // Get the entity and its components
        let entity_result = self.entity_manager
            .get_entity(user_id, entity_id)
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get entity: {}", e)))?;
        
        if let Some(entity) = entity_result {
            // Look for a Name component in the components vec
            for component in &entity.components {
                if component.component_type == "Name" {
                    if let Some(name) = component.component_data.get("name").and_then(|v| v.as_str()) {
                        return Ok(name.to_string());
                    }
                }
            }
        }
        
        // Fallback to a generic name if no Name component found
        Ok(format!("Entity-{}", entity_id.to_string().split('-').next().unwrap_or("unknown")))
    }

    /// Warm cache for a new session
    /// 
    /// This method pre-populates the immediate context cache for a new session
    /// to ensure fast first response. It resolves UUIDs to actual names.
    pub async fn warm_cache_for_session(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        location_id: Option<Uuid>,
        character_id: Option<Uuid>,
    ) -> Result<(), AppError> {
        
        // Resolve location name if provided
        let (current_location, current_location_name) = if let Some(loc_id) = location_id {
            let location_name = self.resolve_entity_name(loc_id, user_id).await
                .unwrap_or_else(|_| format!("Location-{}", loc_id.to_string().split('-').next().unwrap_or("unknown")));
            (loc_id, location_name)
        } else {
            let default_location = Uuid::new_v4();
            (default_location, "Unknown Location".to_string())
        };
        
        // Resolve character name if provided
        let active_character_name = if let Some(char_id) = character_id {
            Some(self.resolve_character_name(char_id, user_id).await
                .unwrap_or_else(|_| format!("Character-{}", char_id.to_string().split('-').next().unwrap_or("unknown"))))
        } else {
            None
        };
        
        let immediate_context = ImmediateContext {
            user_id,
            session_id,
            current_location,
            current_location_name,
            active_character: character_id,
            active_character_name,
            recent_messages: Vec::new(),
        };
        
        self.cache_service
            .set_immediate_context(session_id, immediate_context)
            .await?;
        
        info!("Cache warmed for session {} with resolved names", session_id);
        Ok(())
    }
}

/// Cache health status for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct CacheHealth {
    pub redis_healthy: bool,
    pub response_time_ms: u64,
    pub cache_service_healthy: bool,
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_lightning_agent_creation() {
        // Test will be implemented when we create the cache service
    }
}