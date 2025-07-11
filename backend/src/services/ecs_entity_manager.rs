// backend/src/services/ecs_entity_manager.rs
//
// ECS Entity Manager with Redis Caching
//
// This service provides high-performance entity operations with component-level
// caching to achieve sub-100ms response times for ECS queries.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::{Value as JsonValue};
use tracing::{info, warn, debug, instrument};
use redis::{AsyncCommands, RedisResult};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        ecs_diesel::{EcsEntity, EcsComponent, NewEcsComponent, NewEcsEntity},
    },
    schema::{ecs_entities, ecs_components},
};

use diesel::prelude::*;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods};

/// Configuration for entity manager caching behavior
#[derive(Debug, Clone)]
pub struct EntityManagerConfig {
    /// Default TTL for entity cache entries (seconds)
    pub default_cache_ttl: u64,
    /// TTL for frequently accessed entities (seconds)
    pub hot_cache_ttl: u64,
    /// Batch size for bulk operations
    pub bulk_operation_batch_size: usize,
    /// Enable component-level granular caching
    pub enable_component_caching: bool,
}

impl Default for EntityManagerConfig {
    fn default() -> Self {
        Self {
            default_cache_ttl: 300,  // 5 minutes
            hot_cache_ttl: 1800,     // 30 minutes
            bulk_operation_batch_size: 100,
            enable_component_caching: true,
        }
    }
}

/// Result of entity queries with caching metadata
#[derive(Debug, Clone)]
pub struct EntityQueryResult {
    /// The entity data
    pub entity: EcsEntity,
    /// Components attached to this entity
    pub components: Vec<EcsComponent>,
    /// Whether this result came from cache
    pub cache_hit: bool,
    /// Cache key used for this entity
    pub cache_key: String,
}

/// Component update operation
#[derive(Debug, Clone)]
pub struct ComponentUpdate {
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
    pub operation: ComponentOperation,
}

/// Type of component operation
#[derive(Debug, Clone)]
pub enum ComponentOperation {
    Add,
    Update,
    Remove,
}

/// Cache warming statistics
#[derive(Debug, Clone)]
pub struct CacheWarmingStats {
    pub entities_requested: usize,
    pub entities_warmed: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub errors: usize,
}

/// Result of cache warming operations
#[derive(Debug, Clone)]
pub struct CacheWarmingResult {
    pub stats: CacheWarmingStats,
    pub duration_ms: u64,
    pub success_rate: f64, // Percentage
}

/// Cache warming recommendations based on usage patterns
#[derive(Debug, Clone)]
pub struct CacheWarmingRecommendations {
    pub high_priority_entities: Vec<Uuid>,
    pub recent_entities: Vec<Uuid>,
    pub recommended_queries: Vec<ComponentQuery>,
    pub estimated_warming_time_ms: u64,
}

/// High-performance Entity Manager with Redis caching
pub struct EcsEntityManager {
    db_pool: Arc<PgPool>,
    redis_client: Arc<redis::Client>,
    config: EntityManagerConfig,
}

impl EcsEntityManager {
    /// Create a new entity manager
    pub fn new(
        db_pool: Arc<PgPool>,
        redis_client: Arc<redis::Client>,
        config: Option<EntityManagerConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        info!("Initializing ECS Entity Manager with config: {:?}", config);
        
        Self {
            db_pool,
            redis_client,
            config,
        }
    }

    /// Get entity with all components (read-through caching)
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_entity(&self, user_id: Uuid, entity_id: Uuid) -> Result<Option<EntityQueryResult>, AppError> {
        let cache_key = self.entity_cache_key(user_id, entity_id);
        
        // Try cache first
        if let Ok(Some(cached_result)) = self.get_entity_from_cache(&cache_key).await {
            debug!("Cache hit for entity {}", entity_id);
            return Ok(Some(cached_result));
        }

        // Cache miss - fetch from database
        debug!("Cache miss for entity {} - fetching from database", entity_id);
        let db_result = self.get_entity_from_db(user_id, entity_id).await?;
        
        if let Some(mut result) = db_result {
            result.cache_hit = false;
            result.cache_key = cache_key.clone();
            
            // Store in cache
            if let Err(e) = self.store_entity_in_cache(&cache_key, &result).await {
                warn!("Failed to cache entity {}: {}", entity_id, e);
            }
            
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Get multiple entities efficiently with batch caching
    #[instrument(skip(self, entity_ids), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), count = entity_ids.len()))]
    pub async fn get_entities(&self, user_id: Uuid, entity_ids: &[Uuid]) -> Result<Vec<EntityQueryResult>, AppError> {
        let mut results = Vec::new();
        let mut cache_misses = Vec::new();
        
        // Try to get entities from cache first
        for entity_id in entity_ids {
            let cache_key = self.entity_cache_key(user_id, *entity_id);
            
            match self.get_entity_from_cache(&cache_key).await {
                Ok(Some(cached_result)) => {
                    results.push(cached_result);
                }
                _ => {
                    cache_misses.push(*entity_id);
                }
            }
        }
        
        // Fetch cache misses from database in batch
        if !cache_misses.is_empty() {
            let db_results = self.get_entities_from_db(user_id, &cache_misses).await?;
            
            for mut result in db_results {
                result.cache_hit = false;
                let cache_key = self.entity_cache_key(user_id, result.entity.id);
                result.cache_key = cache_key.clone();
                
                // Store in cache (fire and forget)
                if let Err(e) = self.store_entity_in_cache(&cache_key, &result).await {
                    warn!("Failed to cache entity {}: {}", result.entity.id, e);
                }
                
                results.push(result);
            }
        }
        
        info!("Retrieved {} entities: {} from cache, {} from database", 
              results.len(), results.len() - cache_misses.len(), cache_misses.len());
        
        Ok(results)
    }

    /// Create a new entity with optional components
    #[instrument(skip(self, components), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn create_entity(
        &self,
        user_id: Uuid,
        entity_id: Option<Uuid>,
        archetype_signature: String,
        components: Vec<(String, JsonValue)>,
    ) -> Result<EntityQueryResult, AppError> {
        let entity_id = entity_id.unwrap_or_else(Uuid::new_v4);
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // Create entity and components in transaction
        let entity_components = conn.interact({
            let entity_id = entity_id;
            let user_id = user_id;
            let archetype_signature = archetype_signature.clone();
            let components = components.clone();
            
            move |conn| -> Result<(EcsEntity, Vec<EcsComponent>), AppError> {
                conn.transaction(|conn| {
                    // Create entity
                    let new_entity = NewEcsEntity {
                        id: entity_id,
                        user_id,
                        archetype_signature,
                    };

                    let entity: EcsEntity = diesel::insert_into(ecs_entities::table)
                        .values(&new_entity)
                        .returning(EcsEntity::as_returning())
                        .get_result(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Create components
                    let mut created_components = Vec::new();
                    for (component_type, component_data) in components {
                        let new_component = NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id,
                            user_id,
                            component_type: component_type.clone(),
                            component_data: component_data.clone(),
                        };

                        let ecs_component: EcsComponent = diesel::insert_into(ecs_components::table)
                            .values(&new_component)
                            .returning(EcsComponent::as_returning())
                            .get_result(conn)
                            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                        
                        created_components.push(ecs_component);
                    }

                    Ok((entity, created_components))
                })
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)?;

        let result = EntityQueryResult {
            entity: entity_components.0,
            components: entity_components.1,
            cache_hit: false,
            cache_key: self.entity_cache_key(user_id, entity_id),
        };

        // Cache the new entity
        if let Err(e) = self.store_entity_in_cache(&result.cache_key, &result).await {
            warn!("Failed to cache newly created entity {}: {}", entity_id, e);
        }

        info!("Created entity {} with {} components", entity_id, result.components.len());
        Ok(result)
    }

    /// Update entity components atomically
    #[instrument(skip(self, updates), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), updates_count = updates.len()))]
    pub async fn update_components(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        updates: Vec<ComponentUpdate>,
    ) -> Result<Vec<EcsComponent>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let updated_components = conn.interact({
            let updates = updates.clone();
            let user_id = user_id;
            let entity_id = entity_id;
            
            move |conn| -> Result<Vec<EcsComponent>, AppError> {
                conn.transaction(|conn| {
                    let mut result_components = Vec::new();
                    
                    for update in updates {
                        match update.operation {
                            ComponentOperation::Add => {
                                let new_component = NewEcsComponent {
                                    id: Uuid::new_v4(),
                                    entity_id: update.entity_id,
                                    user_id,
                                    component_type: update.component_type.clone(),
                                    component_data: update.component_data.clone(),
                                };

                                // Use upsert to handle cases where component already exists
                                let ecs_component: EcsComponent = diesel::insert_into(ecs_components::table)
                                    .values(&new_component)
                                    .on_conflict((ecs_components::entity_id, ecs_components::component_type))
                                    .do_update()
                                    .set(ecs_components::component_data.eq(update.component_data.clone()))
                                    .returning(EcsComponent::as_returning())
                                    .get_result(conn)
                                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                                result_components.push(ecs_component);
                            }
                            ComponentOperation::Update => {
                                // Try to update existing component
                                match diesel::update(
                                    ecs_components::table
                                        .filter(ecs_components::entity_id.eq(update.entity_id))
                                        .filter(ecs_components::component_type.eq(update.component_type.clone()))
                                        .filter(ecs_components::user_id.eq(user_id))
                                )
                                .set(ecs_components::component_data.eq(update.component_data.clone()))
                                .returning(EcsComponent::as_returning())
                                .get_result(conn) {
                                    Ok(updated) => {
                                        result_components.push(updated);
                                    }
                                    Err(diesel::result::Error::NotFound) => {
                                        // Component doesn't exist, create it instead
                                        let new_component = NewEcsComponent {
                                            id: Uuid::new_v4(),
                                            entity_id: update.entity_id,
                                            user_id,
                                            component_type: update.component_type.clone(),
                                            component_data: update.component_data.clone(),
                                        };

                                        let created: EcsComponent = diesel::insert_into(ecs_components::table)
                                            .values(&new_component)
                                            .returning(EcsComponent::as_returning())
                                            .get_result(conn)
                                            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                                        result_components.push(created);
                                    }
                                    Err(e) => {
                                        return Err(AppError::DatabaseQueryError(e.to_string()));
                                    }
                                }
                            }
                            ComponentOperation::Remove => {
                                diesel::delete(
                                    ecs_components::table
                                        .filter(ecs_components::entity_id.eq(update.entity_id))
                                        .filter(ecs_components::component_type.eq(update.component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                )
                                .execute(conn)
                                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                            }
                        }
                    }

                    Ok(result_components)
                })
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)?;

        // Invalidate cache for this entity
        let cache_key = self.entity_cache_key(user_id, entity_id);
        if let Err(e) = self.invalidate_entity_cache(&cache_key).await {
            warn!("Failed to invalidate cache for entity {}: {}", entity_id, e);
        }

        info!("Updated {} components for entity {}", updated_components.len(), entity_id);
        Ok(updated_components)
    }

    /// Query entities by component criteria (with caching for common queries)
    #[instrument(skip(self, component_criteria), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn query_entities(
        &self,
        user_id: Uuid,
        component_criteria: Vec<ComponentQuery>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        let query_options = EntityQueryOptions {
            criteria: component_criteria,
            limit,
            offset,
            sort_by: None,
            min_components: None,
            max_components: None,
            cache_key: None,
            cache_ttl: None,
        };

        let result = self.query_entities_advanced(user_id, query_options).await?;
        Ok(result.entities)
    }

    /// Advanced entity queries with full query options and performance tracking
    #[instrument(skip(self, options), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), criteria_count = options.criteria.len()))]
    pub async fn query_entities_advanced(
        &self,
        user_id: Uuid,
        options: EntityQueryOptions,
    ) -> Result<AdvancedQueryResult, AppError> {
        let start_time = std::time::Instant::now();
        
        // Check for cached results first
        if let Some(cache_key) = &options.cache_key {
            if let Ok(Some(cached_result)) = self.get_query_from_cache(cache_key).await {
                debug!("Cache hit for advanced query with key: {}", cache_key);
                return Ok(cached_result);
            }
        }

        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let (entities, total_count, entities_scanned) = conn.interact({
            let options = options.clone();
            let user_id = user_id;
            
            move |conn| -> Result<(Vec<Uuid>, Option<usize>, usize), AppError> {
                let limit = options.limit.unwrap_or(100);
                let offset = options.offset.unwrap_or(0);

                // Build the base query
                let mut query = ecs_entities::table
                    .select(ecs_entities::id)
                    .filter(ecs_entities::user_id.eq(user_id))
                    .into_boxed();

                // Track entities scanned for statistics
                let mut entities_scanned = 0;

                // Apply component criteria filters
                for criteria in &options.criteria {
                    match criteria {
                        ComponentQuery::HasComponent(component_type) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                )
                            );
                        }
                        ComponentQuery::ComponentDataContains(component_type, _path, value) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            ecs_components::component_data
                                                .contains(serde_json::json!({ "contains": value }))
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataEquals(component_type, path, value) => {
                            // Use JSONB path operator for exact matching
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "component_data->'{}' = '{}'::jsonb",
                                                path, value
                                            ))
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataInRange(component_type, path, min_val, max_val) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "cast(component_data->>'{}' as float) BETWEEN {} AND {}",
                                                path, min_val, max_val
                                            ))
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataGreaterThan(component_type, path, value) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "cast(component_data->>'{}' as float) > {}",
                                                path, value
                                            ))
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataLessThan(component_type, path, value) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "cast(component_data->>'{}' as float) < {}",
                                                path, value
                                            ))
                                        )
                                )
                            );
                        }
                        ComponentQuery::WithinDistance(component_type, max_distance, center_x, center_y, center_z) => {
                            // Spatial query using PostgreSQL functions for 3D distance
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "sqrt(power(cast(component_data->>'x' as float) - {}, 2) + \
                                                      power(cast(component_data->>'y' as float) - {}, 2) + \
                                                      power(cast(component_data->>'z' as float) - {}, 2)) <= {}",
                                                center_x, center_y, center_z, max_distance
                                            ))
                                        )
                                )
                            );
                        }
                        ComponentQuery::HasAllComponents(component_types) => {
                            for component_type in component_types {
                                query = query.filter(
                                    ecs_entities::id.eq_any(
                                        ecs_components::table
                                            .select(ecs_components::entity_id)
                                            .filter(ecs_components::component_type.eq(component_type))
                                            .filter(ecs_components::user_id.eq(user_id))
                                    )
                                );
                            }
                        }
                        ComponentQuery::HasAnyComponents(component_types) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq_any(component_types))
                                        .filter(ecs_components::user_id.eq(user_id))
                                )
                            );
                        }
                        ComponentQuery::ComponentDataMatches(component_type, path, pattern) => {
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                                                "component_data->>'{}' ILIKE '%{}%'",
                                                path, pattern
                                            ))
                                        )
                                )
                            );
                        }
                    }
                }

                // Apply component count filters
                if let Some(min_components) = options.min_components {
                    query = query.filter(
                        ecs_entities::id.eq_any(
                            ecs_components::table
                                .select(ecs_components::entity_id)
                                .filter(ecs_components::user_id.eq(user_id))
                                .group_by(ecs_components::entity_id)
                                .having(diesel::dsl::count(ecs_components::id).ge(min_components as i64))
                        )
                    );
                }

                if let Some(max_components) = options.max_components {
                    query = query.filter(
                        ecs_entities::id.eq_any(
                            ecs_components::table
                                .select(ecs_components::entity_id)
                                .filter(ecs_components::user_id.eq(user_id))
                                .group_by(ecs_components::entity_id)
                                .having(diesel::dsl::count(ecs_components::id).le(max_components as i64))
                        )
                    );
                }

                // Get total count if needed (for pagination)
                let total_count = if offset > 0 || limit < 1000 {
                    // Create a separate count query based on the same filters
                    let mut count_query = ecs_entities::table
                        .filter(ecs_entities::user_id.eq(user_id))
                        .into_boxed();

                    // Apply the same component criteria filters for count
                    for criteria in &options.criteria {
                        match criteria {
                            ComponentQuery::HasComponent(component_type) => {
                                count_query = count_query.filter(
                                    ecs_entities::id.eq_any(
                                        ecs_components::table
                                            .select(ecs_components::entity_id)
                                            .filter(ecs_components::component_type.eq(component_type))
                                            .filter(ecs_components::user_id.eq(user_id))
                                    )
                                );
                            }
                            // Add other criteria as needed, simplified for now
                            _ => {}
                        }
                    }

                    Some(count_query.count().get_result::<i64>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))? as usize)
                } else {
                    None
                };

                // Apply sorting if specified
                let sorted_query = if let Some(sort_config) = &options.sort_by {
                    // For sorting by component data, we need to join with components
                    // This is a simplified implementation - could be optimized further
                    query
                } else {
                    query
                };

                // Execute final query
                let entity_ids = sorted_query
                    .limit(limit)
                    .offset(offset)
                    .load::<Uuid>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                // For now, set entities_scanned to a reasonable estimate
                entities_scanned = total_count.unwrap_or(entity_ids.len() * 2);

                Ok((entity_ids, total_count, entities_scanned))
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)?;

        // Get full entity data for found entities
        let query_results = self.get_entities(user_id, &entities).await?;

        let execution_time = start_time.elapsed().as_millis() as u64;

        let stats = QueryExecutionStats {
            execution_time_ms: execution_time,
            entities_scanned,
            entities_returned: query_results.len(),
            cache_hit: false,
            query_plan: None, // Could be populated with EXPLAIN data in the future
        };

        let result = AdvancedQueryResult {
            entities: query_results,
            stats,
            total_count,
        };

        // Cache the result if cache key is provided
        if let Some(cache_key) = &options.cache_key {
            let ttl = options.cache_ttl.unwrap_or(self.config.default_cache_ttl);
            if let Err(e) = self.store_query_in_cache(cache_key, &result, ttl).await {
                warn!("Failed to cache query result: {}", e);
            }
        }

        info!("Advanced query completed in {}ms, returned {} entities", execution_time, result.entities.len());
        Ok(result)
    }

    // Cache warming strategies for frequently accessed entities

    /// Warm cache for specific entities (proactive caching)
    #[instrument(skip(self, entity_ids), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), count = entity_ids.len()))]
    pub async fn warm_entity_cache(&self, user_id: Uuid, entity_ids: &[Uuid]) -> Result<CacheWarmingResult, AppError> {
        let start_time = std::time::Instant::now();
        let mut warming_stats = CacheWarmingStats {
            entities_requested: entity_ids.len(),
            entities_warmed: 0,
            cache_hits: 0,
            cache_misses: 0,
            errors: 0,
        };

        info!("Starting cache warming for {} entities", entity_ids.len());

        // Process entities in batches to avoid overwhelming the database
        let batch_size = self.config.bulk_operation_batch_size;
        for batch in entity_ids.chunks(batch_size) {
            match self.warm_entity_batch(user_id, batch, &mut warming_stats).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to warm entity batch: {}", e);
                    warming_stats.errors += batch.len();
                }
            }
        }

        let duration = start_time.elapsed();
        
        info!(
            "Cache warming completed: {}/{} entities warmed, {} hits, {} misses, {} errors in {:?}",
            warming_stats.entities_warmed,
            warming_stats.entities_requested,
            warming_stats.cache_hits,
            warming_stats.cache_misses,
            warming_stats.errors,
            duration
        );

        let success_rate = if warming_stats.entities_requested > 0 {
            (warming_stats.entities_warmed as f64 / warming_stats.entities_requested as f64) * 100.0
        } else {
            0.0
        };

        Ok(CacheWarmingResult {
            stats: warming_stats,
            duration_ms: duration.as_millis() as u64,
            success_rate,
        })
    }

    /// Warm cache for recently accessed entities (smart warming based on access patterns)
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn warm_recent_entities_cache(&self, user_id: Uuid, limit: usize) -> Result<CacheWarmingResult, AppError> {
        info!("Starting smart cache warming for {} most recent entities", limit);

        // Get recently accessed entities from database
        let recent_entities = self.get_recently_accessed_entities(user_id, limit).await?;
        let entity_ids: Vec<Uuid> = recent_entities.into_iter().map(|e| e.id).collect();

        if entity_ids.is_empty() {
            info!("No recent entities found for cache warming");
            return Ok(CacheWarmingResult {
                stats: CacheWarmingStats {
                    entities_requested: 0,
                    entities_warmed: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    errors: 0,
                },
                duration_ms: 0,
                success_rate: 100.0,
            });
        }

        self.warm_entity_cache(user_id, &entity_ids).await
    }

    /// Warm cache for entities matching common query patterns
    #[instrument(skip(self, queries), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), query_count = queries.len()))]
    pub async fn warm_query_pattern_cache(&self, user_id: Uuid, queries: &[ComponentQuery]) -> Result<CacheWarmingResult, AppError> {
        let start_time = std::time::Instant::now();
        let mut total_entities_warmed = 0;
        let mut total_errors = 0;

        info!("Starting cache warming for {} query patterns", queries.len());

        for (i, query) in queries.iter().enumerate() {
            let options = EntityQueryOptions {
                criteria: vec![query.clone()],
                limit: Some(100), // Limit warming to prevent excessive load
                offset: Some(0),
                sort_by: None,
                min_components: None,
                max_components: None,
                cache_key: None,
                cache_ttl: None,
            };

            match self.query_entities_advanced(user_id, options).await {
                Ok(result) => {
                    total_entities_warmed += result.entities.len();
                    debug!("Warmed {} entities for query pattern {}", result.entities.len(), i + 1);
                }
                Err(e) => {
                    warn!("Failed to warm cache for query pattern {}: {}", i + 1, e);
                    total_errors += 1;
                }
            }
        }

        let duration = start_time.elapsed();
        let success_rate = if queries.len() > 0 {
            ((queries.len() - total_errors) as f64 / queries.len() as f64) * 100.0
        } else {
            100.0
        };

        info!(
            "Query pattern cache warming completed: {} entities warmed, {} query errors in {:?}",
            total_entities_warmed, total_errors, duration
        );

        Ok(CacheWarmingResult {
            stats: CacheWarmingStats {
                entities_requested: total_entities_warmed,
                entities_warmed: total_entities_warmed,
                cache_hits: 0, // These are all new cache entries
                cache_misses: total_entities_warmed,
                errors: total_errors,
            },
            duration_ms: duration.as_millis() as u64,
            success_rate,
        })
    }

    /// Get cache warming statistics and recommendations
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_cache_warming_recommendations(&self, user_id: Uuid) -> Result<CacheWarmingRecommendations, AppError> {
        // Get entities that are frequently accessed but not cached
        let frequent_entities = self.get_frequently_accessed_entities(user_id, 50).await?;
        let recent_entities = self.get_recently_accessed_entities(user_id, 20).await?;

        // Common query patterns that should be pre-warmed
        let recommended_queries = vec![
            ComponentQuery::HasAllComponents(vec!["Health".to_string(), "Position".to_string()]),
            ComponentQuery::HasComponent("Relationships".to_string()),
            ComponentQuery::HasComponent("Inventory".to_string()),
        ];

        let recommendations = CacheWarmingRecommendations {
            high_priority_entities: frequent_entities.into_iter().map(|e| e.id).collect(),
            recent_entities: recent_entities.into_iter().map(|e| e.id).collect(),
            recommended_queries,
            estimated_warming_time_ms: self.estimate_warming_time(user_id).await?,
        };

        info!("Generated cache warming recommendations: {} high priority, {} recent entities", 
              recommendations.high_priority_entities.len(), recommendations.recent_entities.len());

        Ok(recommendations)
    }

    /// Schedule automatic cache warming based on usage patterns
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn schedule_automatic_warming(&self, user_id: Uuid) -> Result<(), AppError> {
        let recommendations = self.get_cache_warming_recommendations(user_id).await?;

        // Warm high priority entities first
        if !recommendations.high_priority_entities.is_empty() {
            let result = self.warm_entity_cache(user_id, &recommendations.high_priority_entities).await?;
            info!("Automatic warming completed for {} high priority entities with {:.1}% success rate", 
                  result.stats.entities_requested, result.success_rate);
        }

        // Warm common query patterns
        if !recommendations.recommended_queries.is_empty() {
            let query_result = self.warm_query_pattern_cache(user_id, &recommendations.recommended_queries).await?;
            info!("Automatic query pattern warming completed: {} entities warmed", 
                  query_result.stats.entities_warmed);
        }

        Ok(())
    }

    // Private helper methods for cache warming

    async fn warm_entity_batch(&self, user_id: Uuid, entity_ids: &[Uuid], stats: &mut CacheWarmingStats) -> Result<(), AppError> {
        for entity_id in entity_ids {
            let cache_key = self.entity_cache_key(user_id, *entity_id);
            
            // Check if already cached
            match self.get_entity_from_cache(&cache_key).await {
                Ok(Some(_)) => {
                    stats.cache_hits += 1;
                    continue; // Already cached, skip
                }
                Ok(None) => {
                    stats.cache_misses += 1;
                }
                Err(_) => {
                    stats.errors += 1;
                    continue;
                }
            }

            // Fetch from database and cache
            match self.get_entity_from_db(user_id, *entity_id).await? {
                Some(result) => {
                    // Store in cache with hot cache TTL for frequently accessed entities
                    let cache_result = self.store_entity_in_cache_with_ttl(&cache_key, &result, self.config.hot_cache_ttl).await;
                    match cache_result {
                        Ok(_) => {
                            stats.entities_warmed += 1;
                            debug!("Warmed entity {} in cache", entity_id);
                        }
                        Err(e) => {
                            warn!("Failed to store entity {} in cache: {}", entity_id, e);
                            stats.errors += 1;
                        }
                    }
                }
                None => {
                    debug!("Entity {} not found during warming", entity_id);
                }
            }
        }

        Ok(())
    }

    async fn get_recently_accessed_entities(&self, user_id: Uuid, limit: usize) -> Result<Vec<EcsEntity>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| -> Result<Vec<EcsEntity>, AppError> {
            let entities = ecs_entities::table
                .filter(ecs_entities::user_id.eq(user_id))
                .order(ecs_entities::updated_at.desc())
                .limit(limit as i64)
                .select(EcsEntity::as_select())
                .load::<EcsEntity>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            Ok(entities)
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
    }

    async fn get_frequently_accessed_entities(&self, user_id: Uuid, limit: usize) -> Result<Vec<EcsEntity>, AppError> {
        // For now, use recently updated as a proxy for frequently accessed
        // In a real system, this would query access log tables
        self.get_recently_accessed_entities(user_id, limit).await
    }

    async fn estimate_warming_time(&self, user_id: Uuid) -> Result<u64, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let entity_count = conn.interact(move |conn| -> Result<i64, AppError> {
            let count = ecs_entities::table
                .filter(ecs_entities::user_id.eq(user_id))
                .count()
                .get_result::<i64>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            Ok(count)
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?;

        // Estimate ~1ms per entity for warming
        Ok((entity_count? as u64).saturating_mul(1))
    }

    /// Get all ECS entities for a specific chronicle
    /// This provides a simple direct query for entity listing in the UI
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), chronicle_id = %chronicle_id))]
    pub async fn get_entities_by_chronicle(&self, user_id: Uuid, chronicle_id: Uuid, limit: Option<usize>) -> Result<Vec<EntityQueryResult>, AppError> {
        info!("Getting ECS entities for chronicle {} by user {}", chronicle_id, user_id);
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let entity_ids = conn.interact({
            let chronicle_id = chronicle_id;
            let user_id = user_id;
            move |conn| -> Result<Vec<Uuid>, AppError> {
                use crate::schema::{ecs_entities, ecs_components};
                use diesel::prelude::*;

                let mut query = ecs_entities::table
                    .inner_join(ecs_components::table.on(ecs_entities::id.eq(ecs_components::entity_id)))
                    .filter(ecs_entities::user_id.eq(user_id))
                    .filter(ecs_components::component_type.eq("ChronicleSource"))
                    .filter(
                        diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                            "cast(component_data->>'chronicle_id' as uuid) = '{}'", chronicle_id
                        ))
                    )
                    .select(ecs_entities::id)
                    .distinct()
                    .into_boxed();

                if let Some(limit) = limit {
                    query = query.limit(limit as i64);
                }

                query.load::<Uuid>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        if entity_ids.is_empty() {
            info!("No ECS entities found for chronicle {}", chronicle_id);
            return Ok(Vec::new());
        }

        info!("Found {} ECS entities for chronicle {}", entity_ids.len(), chronicle_id);
        
        // Get full entity data for found entities
        let entities = self.get_entities(user_id, &entity_ids).await?;
        Ok(entities)
    }

    /// Delete all ECS entities for a specific chronicle
    /// This should be called during re-chronicle to clean up old entities
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), chronicle_id = %chronicle_id))]
    pub async fn purge_entities_by_chronicle(&self, user_id: Uuid, chronicle_id: Uuid) -> Result<usize, AppError> {
        info!("Purging ECS entities for chronicle {} by user {}", chronicle_id, user_id);
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // First, find all entities that have ChronicleSource components pointing to this chronicle
        let entities_to_delete = conn.interact({
            let chronicle_id = chronicle_id;
            let user_id = user_id;
            move |conn| -> Result<Vec<Uuid>, AppError> {
                use crate::schema::{ecs_entities, ecs_components};
                
                let entity_ids = ecs_entities::table
                    .inner_join(ecs_components::table.on(ecs_entities::id.eq(ecs_components::entity_id)))
                    .filter(ecs_entities::user_id.eq(user_id))
                    .filter(ecs_components::component_type.eq("ChronicleSource"))
                    .filter(
                        diesel::dsl::sql::<diesel::sql_types::Bool>(&format!(
                            "cast(component_data->>'chronicle_id' as uuid) = '{}'", chronicle_id
                        ))
                    )
                    .select(ecs_entities::id)
                    .distinct()
                    .load::<Uuid>(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
                Ok(entity_ids)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        if entities_to_delete.is_empty() {
            info!("No ECS entities found for chronicle {}", chronicle_id);
            return Ok(0);
        }

        info!("Found {} ECS entities to delete for chronicle {}", entities_to_delete.len(), chronicle_id);

        // Delete components first (foreign key constraint)
        let components_deleted = conn.interact({
            let entities_to_delete = entities_to_delete.clone();
            let user_id = user_id;
            move |conn| -> Result<usize, AppError> {
                use crate::schema::ecs_components;
                
                let deleted_count = diesel::delete(
                    ecs_components::table
                        .filter(ecs_components::entity_id.eq_any(&entities_to_delete))
                        .filter(ecs_components::user_id.eq(user_id))
                ).execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
                Ok(deleted_count)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        // Delete entity relationships
        let relationships_deleted = conn.interact({
            let entities_to_delete = entities_to_delete.clone();
            let user_id = user_id;
            move |conn| -> Result<usize, AppError> {
                use crate::schema::ecs_entity_relationships;
                
                let deleted_count = diesel::delete(
                    ecs_entity_relationships::table
                        .filter(
                            ecs_entity_relationships::from_entity_id.eq_any(&entities_to_delete)
                                .or(ecs_entity_relationships::to_entity_id.eq_any(&entities_to_delete))
                        )
                        .filter(ecs_entity_relationships::user_id.eq(user_id))
                ).execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
                Ok(deleted_count)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        // Delete entities
        let entities_deleted = conn.interact({
            let entities_to_delete = entities_to_delete.clone();
            let user_id = user_id;
            move |conn| -> Result<usize, AppError> {
                use crate::schema::ecs_entities;
                
                let deleted_count = diesel::delete(
                    ecs_entities::table
                        .filter(ecs_entities::id.eq_any(&entities_to_delete))
                        .filter(ecs_entities::user_id.eq(user_id))
                ).execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                
                Ok(deleted_count)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        // Clear cache for deleted entities
        self.clear_entities_from_cache(user_id, &entities_to_delete).await?;

        info!(
            "Purged {} entities, {} components, {} relationships for chronicle {}",
            entities_deleted, components_deleted, relationships_deleted, chronicle_id
        );

        Ok(entities_deleted)
    }

    /// Clear multiple entities from cache
    async fn clear_entities_from_cache(&self, user_id: Uuid, entity_ids: &[Uuid]) -> Result<(), AppError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await
            .map_err(|e| AppError::DatabaseQueryError(format!("Redis connection failed: {}", e)))?;

        for entity_id in entity_ids {
            let cache_key = self.entity_cache_key(user_id, *entity_id);
            let _: redis::RedisResult<()> = conn.del(&cache_key).await;
        }

        Ok(())
    }

    async fn store_entity_in_cache_with_ttl(&self, cache_key: &str, result: &EntityQueryResult, ttl: u64) -> redis::RedisResult<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let serialized = serde_json::to_string(result)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        
        conn.set_ex(cache_key, serialized, ttl).await
    }

    // Private helper methods

    fn entity_cache_key(&self, user_id: Uuid, entity_id: Uuid) -> String {
        format!("ecs:entity:{}:{}", Self::hash_user_id(user_id), entity_id)
    }

    fn hash_user_id(user_id: Uuid) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        hasher.finish()
    }

    async fn get_entity_from_cache(&self, cache_key: &str) -> RedisResult<Option<EntityQueryResult>> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let cached_data: Option<String> = conn.get(cache_key).await?;
        
        if let Some(data) = cached_data {
            match serde_json::from_str::<EntityQueryResult>(&data) {
                Ok(mut result) => {
                    result.cache_hit = true;
                    Ok(Some(result))
                }
                Err(e) => {
                    warn!("Failed to deserialize cached entity data: {}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn store_entity_in_cache(&self, cache_key: &str, result: &EntityQueryResult) -> RedisResult<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let serialized = serde_json::to_string(result)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        
        conn.set_ex(cache_key, serialized, self.config.default_cache_ttl).await
    }

    async fn invalidate_entity_cache(&self, cache_key: &str) -> RedisResult<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        conn.del(cache_key).await
    }

    async fn get_query_from_cache(&self, cache_key: &str) -> RedisResult<Option<AdvancedQueryResult>> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let cached_data: Option<String> = conn.get(cache_key).await?;
        
        if let Some(data) = cached_data {
            match serde_json::from_str::<AdvancedQueryResult>(&data) {
                Ok(mut result) => {
                    result.stats.cache_hit = true;
                    Ok(Some(result))
                }
                Err(e) => {
                    warn!("Failed to deserialize cached query result: {}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn store_query_in_cache(&self, cache_key: &str, result: &AdvancedQueryResult, ttl: u64) -> RedisResult<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let serialized = serde_json::to_string(result)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        
        conn.set_ex(cache_key, serialized, ttl).await
    }

    async fn get_entity_from_db(&self, user_id: Uuid, entity_id: Uuid) -> Result<Option<EntityQueryResult>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact({
            move |conn| -> Result<Option<EntityQueryResult>, AppError> {
                // Get entity
                let entity_opt: Option<EcsEntity> = ecs_entities::table
                    .filter(ecs_entities::id.eq(entity_id))
                    .filter(ecs_entities::user_id.eq(user_id))
                    .select(EcsEntity::as_select())
                    .first(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                if let Some(entity) = entity_opt {
                    // Get components
                    let components: Vec<EcsComponent> = ecs_components::table
                        .filter(ecs_components::entity_id.eq(entity_id))
                        .filter(ecs_components::user_id.eq(user_id))
                        .select(EcsComponent::as_select())
                        .load(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    Ok(Some(EntityQueryResult {
                        entity,
                        components,
                        cache_hit: false,
                        cache_key: String::new(), // Will be set by caller
                    }))
                } else {
                    Ok(None)
                }
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    async fn get_entities_from_db(&self, user_id: Uuid, entity_ids: &[Uuid]) -> Result<Vec<EntityQueryResult>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact({
            let entity_ids = entity_ids.to_vec();
            move |conn| -> Result<Vec<EntityQueryResult>, AppError> {
                // Get entities
                let entities: Vec<EcsEntity> = ecs_entities::table
                    .filter(ecs_entities::id.eq_any(&entity_ids))
                    .filter(ecs_entities::user_id.eq(user_id))
                    .select(EcsEntity::as_select())
                    .load(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                // Get all components for these entities
                let components: Vec<EcsComponent> = ecs_components::table
                    .filter(ecs_components::entity_id.eq_any(&entity_ids))
                    .filter(ecs_components::user_id.eq(user_id))
                    .select(EcsComponent::as_select())
                    .load(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                // Group components by entity_id
                let mut entity_components: std::collections::HashMap<Uuid, Vec<EcsComponent>> = 
                    std::collections::HashMap::new();
                
                for component in components {
                    entity_components
                        .entry(component.entity_id)
                        .or_insert_with(Vec::new)
                        .push(component);
                }

                // Build results
                let mut results = Vec::new();
                for entity in entities {
                    let components = entity_components
                        .remove(&entity.id)
                        .unwrap_or_default();
                    
                    results.push(EntityQueryResult {
                        entity,
                        components,
                        cache_hit: false,
                        cache_key: String::new(), // Will be set by caller
                    });
                }

                Ok(results)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)
    }

    /// Get total count of entities for a user
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_user_entity_count(&self, user_id: Uuid) -> Result<i64, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| {
            use crate::schema::ecs_entities::dsl::*;
            ecs_entities
                .filter(user_id.eq(user_id))
                .count()
                .get_result::<i64>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
    }

    /// Get total count of components for a user
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_user_component_count(&self, user_id: Uuid) -> Result<i64, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| {
            use crate::schema::ecs_components::dsl::*;
            ecs_components
                .filter(user_id.eq(user_id))
                .count()
                .get_result::<i64>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
    }

    /// Get total count of relationships for a user
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_user_relationship_count(&self, user_id: Uuid) -> Result<i64, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| {
            use crate::schema::ecs_entity_relationships::dsl::*;
            ecs_entity_relationships
                .filter(user_id.eq(user_id))
                .count()
                .get_result::<i64>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
    }
}

/// Component query criteria for entity filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComponentQuery {
    /// Entity must have component of this type
    HasComponent(String),
    /// Component data must contain specific path/value
    ComponentDataContains(String, String, String),
    /// Component data JSONB path equals value
    ComponentDataEquals(String, String, JsonValue),
    /// Component data JSONB path in range (for numeric values)
    ComponentDataInRange(String, String, f64, f64),
    /// Component data JSONB path greater than value
    ComponentDataGreaterThan(String, String, f64),
    /// Component data JSONB path less than value
    ComponentDataLessThan(String, String, f64),
    /// Position-based proximity query (component_type, max_distance, center_x, center_y, center_z)
    WithinDistance(String, f64, f64, f64, f64),
    /// Entity must have ALL of these component types (AND operation)
    HasAllComponents(Vec<String>),
    /// Entity must have ANY of these component types (OR operation)
    HasAnyComponents(Vec<String>),
    /// Component data matches text pattern (case-insensitive)
    ComponentDataMatches(String, String, String),
}

/// Advanced query options for complex entity searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityQueryOptions {
    /// Component criteria to filter by
    pub criteria: Vec<ComponentQuery>,
    /// Limit number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
    /// Sort by specific component field
    pub sort_by: Option<ComponentSort>,
    /// Include entities with at least this many components
    pub min_components: Option<usize>,
    /// Include entities with at most this many components
    pub max_components: Option<usize>,
    /// Cache key for this query (if cacheable)
    pub cache_key: Option<String>,
    /// TTL for cached results (seconds)
    pub cache_ttl: Option<u64>,
}

/// Sorting configuration for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentSort {
    /// Component type to sort by
    pub component_type: String,
    /// JSONB path within component data
    pub field_path: String,
    /// Sort direction
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Statistics about query execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExecutionStats {
    /// Total execution time in milliseconds
    pub execution_time_ms: u64,
    /// Number of entities scanned
    pub entities_scanned: usize,
    /// Number of entities returned
    pub entities_returned: usize,
    /// Whether result came from cache
    pub cache_hit: bool,
    /// Database query plan explanation (if available)
    pub query_plan: Option<String>,
}

/// Result of entity queries with execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedQueryResult {
    /// The matching entities
    pub entities: Vec<EntityQueryResult>,
    /// Query execution statistics
    pub stats: QueryExecutionStats,
    /// Total count (if different from returned count due to pagination)
    pub total_count: Option<usize>,
}

// Implement Serialize/Deserialize for caching
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct CachedEntityData {
    entity: EcsEntity,
    components: Vec<EcsComponent>,
}

impl Serialize for EntityQueryResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let cached_data = CachedEntityData {
            entity: self.entity.clone(),
            components: self.components.clone(),
        };
        cached_data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EntityQueryResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cached_data = CachedEntityData::deserialize(deserializer)?;
        Ok(EntityQueryResult {
            entity: cached_data.entity,
            components: cached_data.components,
            cache_hit: false, // Will be set correctly by caller
            cache_key: String::new(), // Will be set correctly by caller
        })
    }
}