use crate::errors::AppError;
use redis::AsyncCommands;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument};
use uuid::Uuid;

/// Progressive cache service for the Lightning Agent
/// 
/// This service implements a three-layer cache architecture:
/// 1. Immediate Context - Core data for coherent response (<100ms)
/// 2. Enhanced Context - Rich context from async processing (100-500ms)
/// 3. Full Context - Complete analysis for next interaction (background)
pub struct ProgressiveCacheService {
    redis_client: Arc<redis::Client>,
    default_ttl_immediate: Duration,
    default_ttl_enhanced: Duration,
    default_ttl_full: Duration,
}

/// Combined context enum for all cache layers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Context {
    Full(FullContext),
    Enhanced(EnhancedContext),
    Immediate(ImmediateContext),
    Minimal,
}

/// Layer 1: Immediate Context (<100ms retrieval)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmediateContext {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub current_location: Uuid,
    pub current_location_name: String,
    pub active_character: Option<Uuid>,
    pub active_character_name: Option<String>,
    pub recent_messages: Vec<MessageSummary>,
}

/// Summary of a recent message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSummary {
    pub role: String,
    pub summary: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Layer 2: Enhanced Context (100-500ms retrieval)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedContext {
    pub immediate: ImmediateContext,
    pub visible_entities: Vec<EntitySummary>,
    pub location_details: Location,
    pub character_relationships: Vec<RelationshipSummary>,
    pub active_narrative_threads: Vec<NarrativeThread>,
}

/// Summary of an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_id: Uuid,
    pub name: String,
    pub description: String,
    pub entity_type: String,
}

/// Location details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub location_id: Uuid,
    pub name: String,
    pub description: String,
    pub scale: String,
}

/// Relationship summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSummary {
    pub target_id: Uuid,
    pub target_name: String,
    pub relationship_type: String,
    pub strength: f32,
}

/// Narrative thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeThread {
    pub thread_id: Uuid,
    pub description: String,
    pub priority: f32,
}

/// Layer 3: Full Context (background processing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullContext {
    pub enhanced: EnhancedContext,
    pub entity_salience_scores: std::collections::HashMap<Uuid, SalienceScore>,
    pub memory_associations: Vec<Memory>,
    pub complete_entity_details: Vec<Entity>,
    pub narrative_state: NarrativeState,
}

/// Salience score for an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalienceScore {
    pub entity_id: Uuid,
    pub score: f32,
    pub reason: String,
}

/// Memory association
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub memory_id: Uuid,
    pub memory_type: String,
    pub content: String,
    pub relevance: f32,
}

/// Complete entity details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub entity_id: Uuid,
    pub name: String,
    pub description: String,
    pub components: serde_json::Value,
}

/// Narrative state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeState {
    pub current_phase: String,
    pub active_goals: Vec<String>,
    pub tension_level: f32,
}

impl ProgressiveCacheService {
    /// Create a new progressive cache service
    pub fn new(redis_client: Arc<redis::Client>) -> Self {
        Self {
            redis_client,
            default_ttl_immediate: Duration::from_secs(3600), // 1 hour
            default_ttl_enhanced: Duration::from_secs(900),   // 15 minutes
            default_ttl_full: Duration::from_secs(300),       // 5 minutes
        }
    }

    /// Get context with progressive fallback
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_context(&self, session_id: Uuid) -> Result<Context, AppError> {
        // Try layers in order: Full → Enhanced → Immediate → Minimal
        if let Some(full) = self.get_full_context(session_id).await? {
            debug!("Cache hit: Full context");
            return Ok(Context::Full(full));
        }
        
        if let Some(enhanced) = self.get_enhanced_context(session_id).await? {
            debug!("Cache hit: Enhanced context");
            return Ok(Context::Enhanced(enhanced));
        }
        
        if let Some(immediate) = self.get_immediate_context(session_id).await? {
            debug!("Cache hit: Immediate context");
            return Ok(Context::Immediate(immediate));
        }
        
        debug!("Cache miss: Returning minimal context");
        Ok(Context::Minimal)
    }

    /// Get immediate context from cache
    pub async fn get_immediate_context(&self, session_id: Uuid) -> Result<Option<ImmediateContext>, AppError> {
        let key = format!("ctx:immediate:{}", session_id);
        self.get_from_cache(&key).await
    }

    /// Set immediate context in cache
    pub async fn set_immediate_context(
        &self,
        session_id: Uuid,
        context: ImmediateContext,
    ) -> Result<(), AppError> {
        let key = format!("ctx:immediate:{}", session_id);
        self.set_in_cache(&key, &context, self.default_ttl_immediate).await
    }

    /// Get enhanced context from cache
    pub async fn get_enhanced_context(&self, session_id: Uuid) -> Result<Option<EnhancedContext>, AppError> {
        let key = format!("ctx:enhanced:{}", session_id);
        self.get_from_cache(&key).await
    }

    /// Set enhanced context in cache
    pub async fn set_enhanced_context(
        &self,
        session_id: Uuid,
        context: EnhancedContext,
    ) -> Result<(), AppError> {
        let key = format!("ctx:enhanced:{}", session_id);
        self.set_in_cache(&key, &context, self.default_ttl_enhanced).await
    }

    /// Get full context from cache
    pub async fn get_full_context(&self, session_id: Uuid) -> Result<Option<FullContext>, AppError> {
        let key = format!("ctx:full:{}", session_id);
        self.get_from_cache(&key).await
    }

    /// Set full context in cache
    pub async fn set_full_context(
        &self,
        session_id: Uuid,
        context: FullContext,
    ) -> Result<(), AppError> {
        let key = format!("ctx:full:{}", session_id);
        self.set_in_cache(&key, &context, self.default_ttl_full).await
    }

    /// Update enhanced context progressively
    pub async fn update_enhanced_context(
        &self,
        session_id: Uuid,
        entities: Vec<EntitySummary>,
        location: Location,
    ) -> Result<(), AppError> {
        // Get or create immediate context first
        let immediate = self.get_immediate_context(session_id).await?
            .unwrap_or_else(|| ImmediateContext {
                user_id: Uuid::new_v4(),
                session_id,
                current_location: location.location_id,
                current_location_name: location.name.clone(),
                active_character: None,
                active_character_name: None,
                recent_messages: Vec::new(),
            });
        
        let enhanced = EnhancedContext {
            immediate,
            visible_entities: entities,
            location_details: location,
            character_relationships: Vec::new(), // Will be populated later
            active_narrative_threads: Vec::new(), // Will be populated later
        };
        
        self.set_enhanced_context(session_id, enhanced).await
    }

    /// Update full context with complete analysis
    pub async fn update_full_context(
        &self,
        session_id: Uuid,
        update: FullContextUpdate,
    ) -> Result<(), AppError> {
        // Get enhanced context as base
        let enhanced = self.get_enhanced_context(session_id).await?
            .ok_or_else(|| AppError::NotFound("Enhanced context not found".to_string()))?;
        
        let full = FullContext {
            enhanced,
            entity_salience_scores: update.salience_scores,
            memory_associations: update.memory_associations,
            complete_entity_details: Vec::new(), // Could be populated if needed
            narrative_state: update.narrative_state,
        };
        
        self.set_full_context(session_id, full).await
    }

    /// Invalidate cache for a session
    pub async fn invalidate_session_cache(&self, session_id: Uuid) -> Result<(), AppError> {
        let keys = vec![
            format!("ctx:immediate:{}", session_id),
            format!("ctx:enhanced:{}", session_id),
            format!("ctx:full:{}", session_id),
        ];
        
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis connection failed: {}", e)))?;
        
        for key in keys {
            let _: Result<(), _> = conn.del(&key).await;
        }
        
        info!("Invalidated cache for session {}", session_id);
        Ok(())
    }

    /// Generic get from cache
    async fn get_from_cache<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, AppError> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis connection failed: {}", e)))?;
        
        let data: Option<Vec<u8>> = conn.get(key).await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis get failed: {}", e)))?;
        
        match data {
            Some(bytes) => {
                let value = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::SerializationError(format!("Deserialization failed: {}", e)))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Generic set in cache
    async fn set_in_cache<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), AppError> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis connection failed: {}", e)))?;
        
        let data = serde_json::to_vec(value)
            .map_err(|e| AppError::SerializationError(format!("Serialization failed: {}", e)))?;
        
        let _: () = conn.set_ex(key, data, ttl.as_secs())
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis set failed: {}", e)))?;
        
        Ok(())
    }
}

/// Update structure for full context
#[derive(Debug, Clone)]
pub struct FullContextUpdate {
    pub salience_scores: std::collections::HashMap<Uuid, SalienceScore>,
    pub memory_associations: Vec<Memory>,
    pub narrative_state: NarrativeState,
}

#[cfg(test)]
mod tests {
    // Tests will be implemented in the unit test file
}