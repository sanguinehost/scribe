use crate::errors::AppError;
use crate::services::progressive_cache::{
    ProgressiveCacheService, Context, ImmediateContext, EnhancedContext, FullContext,
};
use crate::auth::session_dek::SessionDek;
use crate::schema::characters;
use crate::services::ecs_entity_manager::EcsEntityManager;
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
    redis_client: Arc<redis::Client>,
    db_pool: PgPool,
    entity_manager: Arc<EcsEntityManager>,
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
        redis_client: Arc<redis::Client>,
        db_pool: PgPool,
        entity_manager: Arc<EcsEntityManager>,
    ) -> Self {
        Self {
            cache_service,
            redis_client,
            db_pool,
            entity_manager,
        }
    }

    /// Retrieve progressive context with strict timeout enforcement
    /// 
    /// This method attempts to retrieve the richest available context
    /// within a 500ms timeout window. It falls through cache layers
    /// from Full -> Enhanced -> Immediate -> Minimal.
    #[instrument(skip(self, _session_dek), fields(session_id = %session_id, user_id = %user_id))]
    pub async fn retrieve_progressive_context(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        _session_dek: &SessionDek,
    ) -> Result<ProgressiveContext, AppError> {
        let start = Instant::now();
        
        // Attempt cache retrieval with strict timeout
        let context_result = timeout(
            Duration::from_millis(500),
            self.cache_service.get_context(session_id)
        ).await;
        
        let (context, cache_layer) = match context_result {
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
                warn!("Cache retrieval timeout after 500ms");
                (Context::Minimal, CacheLayer::None)
            }
        };
        
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
        if retrieval_time_ms > 100 {
            warn!(
                "Lightning retrieval exceeded 100ms target: {}ms",
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
        
        // Try to ping Redis
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis connection failed: {}", e)))?;
        
        let ping_result: Result<String, _> = redis::cmd("PING")
            .query_async(&mut conn)
            .await;
        
        let redis_healthy = ping_result.is_ok();
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
    use super::*;

    #[tokio::test]
    async fn test_lightning_agent_creation() {
        // Test will be implemented when we create the cache service
    }
}