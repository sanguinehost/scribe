// backend/src/services/ecs_entity_manager.rs
//
// ECS Entity Manager with Redis Caching
//
// This service provides high-performance entity operations with component-level
// caching to achieve sub-100ms response times for ECS queries.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde_json::{json, Value as JsonValue};
use tracing::{info, warn, debug, instrument, error};
use redis::{AsyncCommands, RedisResult};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        ecs_diesel::{EcsEntity, EcsComponent, NewEcsComponent, NewEcsEntity},
        ecs::{ParentLinkComponent, InventoryItem, Relationship},
    },
    schema::{ecs_entities, ecs_components},
};

use diesel::prelude::*;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods};
use diesel::sql_types::{Text, Float, Bool};
use diesel::dsl::sql;

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

    /// Sanitize HTML content to prevent script injection
    /// Removes script tags, javascript URLs, and other potentially harmful content
    fn sanitize_html_content(input: &str) -> String {
        let mut sanitized = input.to_string();
        
        // Remove script tags (case insensitive)
        sanitized = regex::Regex::new(r"(?i)<script[^>]*>.*?</script>")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
        
        // Remove javascript: URLs (case insensitive) 
        sanitized = regex::Regex::new(r"(?i)javascript:")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
        
        // Remove HTML tags that could contain scripts
        sanitized = regex::Regex::new(r"(?i)<(iframe|object|embed|link|meta)[^>]*>")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
        
        // Remove event handlers (onclick, onload, etc.) - simple approach
        sanitized = regex::Regex::new(r"(?i)\bon\w+\s*=")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
        
        // Remove template injection patterns
        sanitized = regex::Regex::new(r"\$\{[^}]*\}")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
        
        sanitized = regex::Regex::new(r"\{\{[^}]*\}\}")
            .unwrap()
            .replace_all(&sanitized, "")
            .to_string();
            
        sanitized
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
            limit: limit.map(|l| l as i64),
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
                            // Use Diesel's JSONB contains operator - much safer than raw SQL
                            let json_query = json!({ path: value });
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(ecs_components::component_data.contains(json_query))
                                )
                            );
                        }
                        ComponentQuery::ComponentDataInRange(component_type, path, min_val, max_val) => {
                            use diesel::sql_types::Double;
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            sql::<Bool>("CAST(component_data->>")
                                                .bind::<Text, _>(path)
                                                .sql(" AS FLOAT) BETWEEN ")
                                                .bind::<Double, _>(min_val)
                                                .sql(" AND ")
                                                .bind::<Double, _>(max_val)
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataGreaterThan(component_type, path, value) => {
                            use diesel::sql_types::Double;
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            sql::<Bool>("CAST(component_data->>")
                                                .bind::<Text, _>(path)
                                                .sql(" AS FLOAT) > ")
                                                .bind::<Double, _>(value)
                                        )
                                )
                            );
                        }
                        ComponentQuery::ComponentDataLessThan(component_type, path, value) => {
                            use diesel::sql_types::Double;
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            sql::<Bool>("CAST(component_data->>")
                                                .bind::<Text, _>(path)
                                                .sql(" AS FLOAT) < ")
                                                .bind::<Double, _>(value)
                                        )
                                )
                            );
                        }
                        ComponentQuery::WithinDistance(component_type, max_distance, center_x, center_y, center_z) => {
                            use diesel::sql_types::Double;
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            sql::<Bool>("SQRT(POWER(CAST(component_data->>'x' AS FLOAT) - ")
                                                .bind::<Double, _>(center_x)
                                                .sql(", 2) + POWER(CAST(component_data->>'y' AS FLOAT) - ")
                                                .bind::<Double, _>(center_y)
                                                .sql(", 2) + POWER(CAST(component_data->>'z' AS FLOAT) - ")
                                                .bind::<Double, _>(center_z)
                                                .sql(", 2)) <= ")
                                                .bind::<Double, _>(max_distance)
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
                            // For text matching, we need to use ILIKE on the extracted JSON field
                            // This properly handles partial matches for name searches
                            let pattern_with_wildcards = format!("%{}%", pattern);
                            query = query.filter(
                                ecs_entities::id.eq_any(
                                    ecs_components::table
                                        .select(ecs_components::entity_id)
                                        .filter(ecs_components::component_type.eq(component_type))
                                        .filter(ecs_components::user_id.eq(user_id))
                                        .filter(
                                            sql::<Bool>("component_data->>")
                                                .bind::<Text, _>(path)
                                                .sql(" ILIKE ")
                                                .bind::<Text, _>(pattern_with_wildcards)
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
                        diesel::dsl::sql::<diesel::sql_types::Bool>(
                            "cast(component_data->>'chronicle_id' as uuid) = $1"
                        )
                        .bind::<diesel::sql_types::Uuid, _>(chronicle_id)
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
                        diesel::dsl::sql::<diesel::sql_types::Bool>(
                            "cast(component_data->>'chronicle_id' as uuid) = $1"
                        )
                        .bind::<diesel::sql_types::Uuid, _>(chronicle_id)
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

    /// Promote an entity to have a new parent, creating intermediate hierarchy levels as needed
    /// This is used when the scope of interaction expands (e.g., moving from planet to galaxy level)
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), entity_id = %entity_id))]
    pub async fn promote_entity_hierarchy(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        new_parent_name: String,
        new_parent_scale: crate::models::ecs::SpatialScale,
        new_parent_position: crate::models::ecs::PositionType,
        relationship_type: String,
    ) -> Result<Uuid, AppError> {
        use crate::models::ecs::{
            SpatialArchetypeComponent, EnhancedPositionComponent, NameComponent, 
            TemporalComponent, SpatialComponent, SpatialType, SpatialConstraints,
            ParentLinkComponent, Component
        };

        info!("Promoting entity {} hierarchy with new parent: {}", entity_id, new_parent_name);

        // 1. Get current entity to understand existing hierarchy
        let current_entity = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound(format!("Entity not found: {}", entity_id)))?;

        // 2. Determine hierarchical level for new parent
        let current_parent_link = current_entity.components.iter()
            .find(|c| c.component_type == "ParentLink");

        let new_parent_level = 0u32; // New parent becomes root
        let entity_new_level = 1u32;  // Original entity becomes child

        // 3. Create new parent entity
        let new_parent_id = Uuid::new_v4();

        // Create spatial archetype for new parent
        let level_name = new_parent_scale.level_name(new_parent_level)
            .ok_or_else(|| AppError::InternalServerErrorGeneric(
                format!("Invalid level {} for scale {:?}", new_parent_level, new_parent_scale)
            ))?;

        let spatial_archetype = SpatialArchetypeComponent::new(
            new_parent_scale,
            new_parent_level,
            level_name.to_string(),
        ).map_err(|e| AppError::InternalServerErrorGeneric(e))?;

        let enhanced_position = EnhancedPositionComponent {
            position_type: new_parent_position,
            movement_constraints: Vec::new(),
            last_updated: chrono::Utc::now(),
        };

        let name_component = NameComponent {
            name: new_parent_name.clone(),
            display_name: new_parent_name.clone(),
            aliases: Vec::new(),
        };

        let temporal_component = TemporalComponent::default();

        // Create spatial component as container
        let spatial_component = SpatialComponent {
            spatial_type: SpatialType::Container {
                capacity: None,
                allowed_types: vec!["Location".to_string(), "Actor".to_string()],
            },
            constraints: SpatialConstraints {
                allow_multiple_locations: false,
                movable: false,
                rules: Vec::new(),
            },
            metadata: std::collections::HashMap::new(),
        };

        // Prepare components for new parent
        let parent_components = vec![
            ("SpatialArchetype".to_string(), spatial_archetype.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("EnhancedPosition".to_string(), enhanced_position.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Name".to_string(), name_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Temporal".to_string(), temporal_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Spatial".to_string(), spatial_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
        ];

        // Create new parent entity
        let archetype_signature = "SpatialArchetype|EnhancedPosition|Name|Temporal|Spatial".to_string();
        self.create_entity(user_id, Some(new_parent_id), archetype_signature, parent_components).await?;

        // 4. Update original entity to become child of new parent
        let new_parent_link = ParentLinkComponent {
            parent_entity_id: new_parent_id,
            depth_from_root: entity_new_level,
            spatial_relationship: relationship_type,
        };

        let parent_link_update = ComponentUpdate {
            entity_id,
            component_type: "ParentLink".to_string(),
            component_data: new_parent_link.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?,
            operation: if current_parent_link.is_some() {
                ComponentOperation::Update
            } else {
                ComponentOperation::Add
            },
        };

        // 5. Recursively update depth for all descendants of the original entity
        self.update_descendant_depths(user_id, entity_id, entity_new_level).await?;

        // 6. Apply the parent link update
        self.update_components(user_id, entity_id, vec![parent_link_update]).await?;

        info!("Successfully promoted entity {} hierarchy. New parent: {}", entity_id, new_parent_id);
        Ok(new_parent_id)
    }

    /// Recursively update depth_from_root for all descendants of an entity
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), parent_id = %parent_id, new_depth = new_parent_depth))]
    fn update_descendant_depths(
        &self,
        user_id: Uuid,
        parent_id: Uuid,
        new_parent_depth: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async move {
            use crate::models::ecs::{ParentLinkComponent, Component};

            // Query for all children of this entity
            let children = self.query_entities(
                user_id,
                vec![ComponentQuery::HasComponent("ParentLink".to_string())],
                None,
                None,
            ).await?;

            // Filter for direct children and update their depths
            for child in children {
                if let Some(parent_link_component) = child.components.iter()
                    .find(|c| c.component_type == "ParentLink") {
                    
                    let parent_link: ParentLinkComponent = serde_json::from_value(parent_link_component.component_data.clone())
                        .map_err(|e| AppError::SerializationError(e.to_string()))?;
                    
                    // Only update direct children of this parent
                    if parent_link.parent_entity_id == parent_id {
                        let new_child_depth = new_parent_depth + 1;
                        
                        // Update this child's depth
                        let updated_parent_link = ParentLinkComponent {
                            parent_entity_id: parent_link.parent_entity_id,
                            depth_from_root: new_child_depth,
                            spatial_relationship: parent_link.spatial_relationship,
                        };

                        let depth_update = ComponentUpdate {
                            entity_id: child.entity.id,
                            component_type: "ParentLink".to_string(),
                            component_data: updated_parent_link.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?,
                            operation: ComponentOperation::Update,
                        };

                        self.update_components(user_id, child.entity.id, vec![depth_update]).await?;

                        // Recursively update this child's descendants
                        self.update_descendant_depths(user_id, child.entity.id, new_child_depth).await?;
                    }
                }
            }

            Ok(())
        })
    }

    /// Get the complete hierarchy path for an entity (from root to entity)
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), entity_id = %entity_id))]
    pub async fn get_entity_hierarchy_path(&self, user_id: Uuid, entity_id: Uuid) -> Result<Vec<EntityHierarchyInfo>, AppError> {
        use crate::models::ecs::{ParentLinkComponent, NameComponent, SpatialArchetypeComponent, Component};

        let mut path = Vec::new();
        let mut current_entity_id = entity_id;

        // Traverse up the hierarchy until we reach the root
        loop {
            let entity = self.get_entity(user_id, current_entity_id).await?
                .ok_or_else(|| AppError::NotFound(format!("Entity not found: {}", current_entity_id)))?;

            // Extract entity information
            let name_component = entity.components.iter()
                .find(|c| c.component_type == "Name")
                .and_then(|c| serde_json::from_value::<NameComponent>(c.component_data.clone()).ok());

            let spatial_archetype = entity.components.iter()
                .find(|c| c.component_type == "SpatialArchetype")
                .and_then(|c| serde_json::from_value::<SpatialArchetypeComponent>(c.component_data.clone()).ok());

            let parent_link = entity.components.iter()
                .find(|c| c.component_type == "ParentLink")
                .and_then(|c| serde_json::from_value::<ParentLinkComponent>(c.component_data.clone()).ok());

            let hierarchy_info = EntityHierarchyInfo {
                entity_id: current_entity_id,
                name: name_component.map(|n| n.name).unwrap_or_else(|| "Unknown".to_string()),
                scale: spatial_archetype.as_ref().map(|s| s.scale.clone()),
                hierarchical_level: spatial_archetype.as_ref().map(|s| s.hierarchical_level).unwrap_or(0),
                depth_from_root: parent_link.as_ref().map(|p| p.depth_from_root).unwrap_or(0),
                parent_id: parent_link.as_ref().map(|p| p.parent_entity_id),
                relationship: parent_link.as_ref().map(|p| p.spatial_relationship.clone()),
            };

            path.insert(0, hierarchy_info); // Insert at beginning to build path from root

            // If no parent, we've reached the root
            if let Some(parent_link) = parent_link {
                current_entity_id = parent_link.parent_entity_id;
            } else {
                break;
            }
        }

        Ok(path)
    }
    
    // ============================================================================
    // Spatial Hierarchy Query Methods (Task 2.3)
    // ============================================================================
    
    /// Get immediate children of an entity (direct descendants only)
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), parent_id = %parent_id))]
    pub async fn get_children_entities(
        &self,
        user_id: Uuid,
        parent_id: Uuid,
        limit: Option<usize>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        info!("Getting immediate children of entity {} for user {}", parent_id, user_id);
        
        // Query for entities with ParentLink pointing to this parent
        let queries = vec![ComponentQuery::ComponentDataEquals(
            "ParentLink".to_string(),
            "parent_entity_id".to_string(),
            json!(parent_id.to_string()),
        )];
        
        let results = self.query_entities(user_id, queries, limit.map(|l| l as i64), None).await?;
        
        info!("Found {} immediate children for entity {}", results.len(), parent_id);
        Ok(results)
    }
    
    /// Get all descendants of an entity with optional depth limit
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), parent_id = %parent_id))]
    pub async fn get_descendants_entities(
        &self,
        user_id: Uuid,
        parent_id: Uuid,
        max_depth: Option<u32>,
        limit: Option<usize>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        info!("Getting descendants of entity {} with max_depth {:?}", parent_id, max_depth);
        
        let mut all_descendants = Vec::new();
        let mut current_level = vec![parent_id];
        let mut depth = 0u32;
        
        // Breadth-first search through hierarchy
        while !current_level.is_empty() {
            if let Some(max) = max_depth {
                if depth >= max {
                    break;
                }
            }
            
            let mut next_level = Vec::new();
            
            for current_parent in current_level {
                // Get immediate children of current entity
                let children = self.get_children_entities(user_id, current_parent, None).await?;
                
                for child in children {
                    all_descendants.push(child.clone());
                    next_level.push(child.entity.id);
                    
                    // Check limit
                    if let Some(lim) = limit {
                        if all_descendants.len() >= lim {
                            info!("Reached limit of {} descendants", lim);
                            return Ok(all_descendants);
                        }
                    }
                }
            }
            
            current_level = next_level;
            depth += 1;
        }
        
        info!("Found {} total descendants for entity {}", all_descendants.len(), parent_id);
        Ok(all_descendants)
    }
    
    /// Get descendants filtered by spatial scale
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), parent_id = %parent_id))]
    pub async fn get_descendants_by_scale(
        &self,
        user_id: Uuid,
        parent_id: Uuid,
        target_scale: crate::models::ecs::SpatialScale,
        limit: Option<usize>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        info!("Getting descendants of scale {:?} for entity {}", target_scale, parent_id);
        
        // Get all descendants first
        let all_descendants = self.get_descendants_entities(user_id, parent_id, None, None).await?;
        
        // Filter by scale
        let mut scale_filtered = Vec::new();
        
        for descendant in all_descendants {
            // Check if entity has SpatialArchetype component with matching scale
            if let Some(spatial_comp) = descendant.components.iter()
                .find(|c| c.component_type == "SpatialArchetype") {
                
                if let Ok(scale_value) = spatial_comp.component_data.get("scale")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing scale field".to_string())) {
                    
                    if scale_value == format!("{:?}", target_scale) {
                        scale_filtered.push(descendant);
                        
                        // Check limit
                        if let Some(lim) = limit {
                            if scale_filtered.len() >= lim {
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        info!("Found {} descendants of scale {:?}", scale_filtered.len(), target_scale);
        Ok(scale_filtered)
    }
    
    /// Get descendants filtered by component type
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), parent_id = %parent_id))]
    pub async fn get_descendants_with_component(
        &self,
        user_id: Uuid,
        parent_id: Uuid,
        component_type: &str,
        limit: Option<usize>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        info!("Getting descendants with component {} for entity {}", component_type, parent_id);
        
        // Get all descendants first
        let all_descendants = self.get_descendants_entities(user_id, parent_id, None, None).await?;
        
        // Filter by component presence
        let mut component_filtered = Vec::new();
        
        for descendant in all_descendants {
            if descendant.components.iter().any(|c| c.component_type == component_type) {
                component_filtered.push(descendant);
                
                // Check limit
                if let Some(lim) = limit {
                    if component_filtered.len() >= lim {
                        break;
                    }
                }
            }
        }
        
        info!("Found {} descendants with component {}", component_filtered.len(), component_type);
        Ok(component_filtered)
    }
    
    /// Get the full containment tree structure for an entity
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), root_id = %root_id))]
    pub async fn get_entity_containment_tree(
        &self,
        user_id: Uuid,
        root_id: Uuid,
        max_depth: Option<u32>,
    ) -> Result<EntityContainmentTree, AppError> {
        info!("Building containment tree for entity {}", root_id);
        
        // Get root entity details
        let root_entity = self.get_entity(user_id, root_id).await?
            .ok_or_else(|| AppError::NotFound(format!("Root entity {} not found", root_id)))?;
        
        // Build tree recursively
        let tree = self.build_containment_subtree(user_id, root_entity, 0, max_depth).await?;
        
        Ok(tree)
    }
    
    /// Helper method to build containment tree recursively
    async fn build_containment_subtree(
        &self,
        user_id: Uuid,
        entity: EntityQueryResult,
        current_depth: u32,
        max_depth: Option<u32>,
    ) -> Result<EntityContainmentTree, AppError> {
        let mut node = EntityContainmentTree {
            entity_id: entity.entity.id,
            name: self.extract_entity_name(&entity),
            scale: self.extract_entity_scale(&entity),
            depth: current_depth,
            children: Vec::new(),
        };
        
        // Check if we've reached max depth
        if let Some(max) = max_depth {
            if current_depth >= max {
                return Ok(node);
            }
        }
        
        // Get children and build their subtrees
        let children = self.get_children_entities(user_id, entity.entity.id, None).await?;
        
        for child in children {
            let child_tree = Box::pin(
                self.build_containment_subtree(user_id, child, current_depth + 1, max_depth)
            ).await?;
            node.children.push(child_tree);
        }
        
        Ok(node)
    }
    
    /// Extract entity name from components
    fn extract_entity_name(&self, entity: &EntityQueryResult) -> String {
        entity.components.iter()
            .find(|c| c.component_type == "Name")
            .and_then(|c| c.component_data.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown")
            .to_string()
    }
    
    /// Extract entity scale from components
    fn extract_entity_scale(&self, entity: &EntityQueryResult) -> Option<crate::models::ecs::SpatialScale> {
        entity.components.iter()
            .find(|c| c.component_type == "SpatialArchetype")
            .and_then(|c| c.component_data.get("scale"))
            .and_then(|s| s.as_str())
            .and_then(|s| match s {
                "Cosmic" => Some(crate::models::ecs::SpatialScale::Cosmic),
                "Planetary" => Some(crate::models::ecs::SpatialScale::Planetary),
                "Intimate" => Some(crate::models::ecs::SpatialScale::Intimate),
                _ => None,
            })
    }
    
    // ============================================================================
    // Entity Movement Operations (Task 2.3.4)
    // ============================================================================
    
    /// Move an entity to a new parent location with validation and position updates
    #[instrument(skip(self), fields(user_hash = %Self::hash_user_id(user_id), entity_id = %entity_id, destination_id = %destination_id))]
    pub async fn move_entity(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        destination_id: Uuid,
        options: Option<MoveEntityOptions>,
    ) -> Result<MoveEntityResult, AppError> {
        info!("Moving entity {} to destination {} for user {}", entity_id, destination_id, user_id);
        
        let options = options.unwrap_or_default();
        let mut validations_performed = std::collections::HashMap::new();
        
        // Step 1: Validate entity exists and is owned by user
        let entity = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound(format!("Entity {} not found", entity_id)))?;
        
        // Step 2: Validate destination exists and is owned by user
        let destination = self.get_entity(user_id, destination_id).await?
            .ok_or_else(|| AppError::NotFound(format!("Destination entity {} not found", destination_id)))?;
        
        // Step 3: Prevent moving entity to itself
        if entity_id == destination_id {
            return Err(AppError::InvalidInput("Entity cannot be moved to itself".to_string()));
        }
        
        // Step 4: Scale compatibility validation
        if options.validate_scale_compatibility {
            self.validate_movement_scale_compatibility(&entity, &destination).await?;
            validations_performed.insert("scale_compatibility".to_string(), json!(true));
        }
        
        // Step 5: Prevent circular parent relationships
        if options.validate_movement_path {
            self.validate_no_circular_parent(&entity, &destination, user_id).await?;
            validations_performed.insert("circular_parent_check".to_string(), json!(true));
        }
        
        // Step 6: Validate destination capacity if requested
        if options.validate_destination_capacity {
            self.validate_destination_capacity(&destination, user_id).await?;
            validations_performed.insert("destination_capacity".to_string(), json!(true));
        }
        
        // Step 7: Update ParentLink component
        let parent_link_json = json!({
            "parent_entity_id": destination_id.to_string(),
            "spatial_relationship": options.spatial_relationship.unwrap_or("contained_within".to_string()),
            "depth_from_root": 0  // Will be calculated properly in a future enhancement
        });
        
        // Update ParentLink component using database interaction
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact({
            let entity_id = entity_id;
            let user_id = user_id;
            let parent_link_json = parent_link_json.clone();
            
            move |conn| -> Result<(), AppError> {
                conn.transaction(|conn| {
                    // Try to update existing ParentLink component
                    let updated_count = diesel::update(
                        ecs_components::table
                            .filter(ecs_components::entity_id.eq(&entity_id))
                            .filter(ecs_components::component_type.eq("ParentLink"))
                            .filter(ecs_components::user_id.eq(&user_id))
                    )
                    .set(ecs_components::component_data.eq(&parent_link_json))
                    .execute(conn)
                    .map_err(|e| {
                        error!("Failed to update ParentLink component: {}", e);
                        AppError::DatabaseQueryError(e.to_string())
                    })?;

                    // If no ParentLink component exists, insert one
                    if updated_count == 0 {
                        let new_component = NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id,
                            component_type: "ParentLink".to_string(),
                            component_data: parent_link_json,
                            user_id,
                        };

                        diesel::insert_into(ecs_components::table)
                            .values(&new_component)
                            .execute(conn)
                            .map_err(|e| {
                                error!("Failed to insert ParentLink component: {}", e);
                                AppError::DatabaseQueryError(e.to_string())
                            })?;
                    }
                    
                    Ok(())
                })
            }
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;
        
        // Step 8: Update Position component if requested
        let mut position_updated = false;
        if options.update_position {
            if let Some(new_position) = options.new_position {
                // Sanitize zone field to prevent script injection
                let sanitized_zone = Self::sanitize_html_content(&new_position.zone);
                
                let position_json = json!({
                    "x": new_position.x,
                    "y": new_position.y,
                    "z": new_position.z,
                    "zone": sanitized_zone
                });
                
                conn.interact({
                    let entity_id = entity_id;
                    let user_id = user_id;
                    let position_json = position_json.clone();
                    
                    move |conn| -> Result<(), AppError> {
                        conn.transaction(|conn| {
                            // Try to update existing Position component
                            let updated_count = diesel::update(
                                ecs_components::table
                                    .filter(ecs_components::entity_id.eq(&entity_id))
                                    .filter(ecs_components::component_type.eq("Position"))
                                    .filter(ecs_components::user_id.eq(&user_id))
                            )
                            .set(ecs_components::component_data.eq(&position_json))
                            .execute(conn)
                            .map_err(|e| {
                                error!("Failed to update Position component: {}", e);
                                AppError::DatabaseQueryError(e.to_string())
                            })?;

                            // If no Position component exists, insert one
                            if updated_count == 0 {
                                let new_component = NewEcsComponent {
                                    id: Uuid::new_v4(),
                                    entity_id,
                                    component_type: "Position".to_string(),
                                    component_data: position_json,
                                    user_id,
                                };

                                diesel::insert_into(ecs_components::table)
                                    .values(&new_component)
                                    .execute(conn)
                                    .map_err(|e| {
                                        error!("Failed to insert Position component: {}", e);
                                        AppError::DatabaseQueryError(e.to_string())
                                    })?;
                            }
                            
                            Ok(())
                        })
                    }
                }).await
                .map_err(|e| AppError::DbInteractError(e.to_string()))??;
                
                position_updated = true;
            }
        }
        
        // Step 9: Invalidate cache entries
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            // Invalidate specific entity cache key
            let entity_cache_key = self.entity_cache_key(user_id, entity_id);
            let _: () = redis::cmd("DEL")
                .arg(&entity_cache_key)
                .query_async(&mut conn)
                .await
                .unwrap_or_default();
            
            // Invalidate any component caches related to this entity
            let component_patterns = vec![
                format!("ecs:component:{}:{}:*", Self::hash_user_id(user_id), entity_id),
                format!("ecs:children:{}:*", Self::hash_user_id(user_id)),
                format!("ecs:descendants:{}:*", Self::hash_user_id(user_id)),
            ];
            
            for pattern in component_patterns {
                let keys: Vec<String> = redis::cmd("KEYS")
                    .arg(&pattern)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or_default();
                
                if !keys.is_empty() {
                    let _: () = redis::cmd("DEL")
                        .arg(&keys)
                        .query_async(&mut conn)
                        .await
                        .unwrap_or_default();
                }
            }
        }
        
        info!("Successfully moved entity {} to destination {}", entity_id, destination_id);
        
        Ok(MoveEntityResult {
            success: true,
            entity_id,
            old_parent_id: self.extract_current_parent_id(&entity),
            new_parent_id: destination_id,
            position_updated,
            movement_type: self.determine_movement_type(&entity, &destination).await,
            validations_performed,
            timestamp: chrono::Utc::now(),
        })
    }
    
    /// Validate that movement between entities is scale-compatible
    async fn validate_movement_scale_compatibility(
        &self,
        entity: &EntityQueryResult,
        destination: &EntityQueryResult,
    ) -> Result<(), AppError> {
        let entity_scale = self.extract_entity_scale(entity);
        let dest_scale = self.extract_entity_scale(destination);
        
        match (entity_scale, dest_scale) {
            (Some(entity_s), Some(dest_s)) => {
                use crate::models::ecs::SpatialScale;
                
                // Define scale compatibility rules
                let is_compatible = match (&entity_s, &dest_s) {
                    // Same scale movements are generally allowed
                    (SpatialScale::Cosmic, SpatialScale::Cosmic) => true,
                    (SpatialScale::Planetary, SpatialScale::Planetary) => true,
                    (SpatialScale::Intimate, SpatialScale::Intimate) => true,
                    
                    // Cross-scale movements with restrictions
                    (SpatialScale::Planetary, SpatialScale::Cosmic) => true,  // Planets can move in cosmic space
                    (SpatialScale::Intimate, SpatialScale::Planetary) => true, // Intimate objects can move on planets
                    (SpatialScale::Intimate, SpatialScale::Cosmic) => false,   // Direct intimate-to-cosmic blocked
                    
                    // Reverse movements (generally more restrictive)
                    (SpatialScale::Cosmic, SpatialScale::Planetary) => false, // Can't put cosmic objects on planets
                    (SpatialScale::Cosmic, SpatialScale::Intimate) => false,  // Can't put cosmic objects in intimate spaces
                    (SpatialScale::Planetary, SpatialScale::Intimate) => false, // Can't put planets in intimate spaces
                };
                
                if !is_compatible {
                    return Err(AppError::InvalidInput(
                        format!("Scale incompatible: cannot move {:?} scale entity to {:?} scale destination", 
                               entity_s, dest_s)
                    ));
                }
            },
            _ => {
                // If scale information is missing, log warning but allow movement
                warn!("Scale information missing for movement validation");
            }
        }
        
        Ok(())
    }
    
    /// Validate that movement doesn't create circular parent relationships
    async fn validate_no_circular_parent(
        &self,
        entity: &EntityQueryResult,
        destination: &EntityQueryResult,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        // Check if destination is a descendant of the entity being moved
        let descendants = self.get_descendants_entities(user_id, entity.entity.id, Some(10), Some(100)).await?;
        
        for descendant in descendants {
            if descendant.entity.id == destination.entity.id {
                return Err(AppError::InvalidInput(
                    "Cannot move entity to its own descendant - would create circular relationship".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validate destination has capacity for new entity
    async fn validate_destination_capacity(
        &self,
        destination: &EntityQueryResult,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        // Get current children count
        let children = self.get_children_entities(user_id, destination.entity.id, None).await?;
        
        // Basic capacity limits based on scale/type
        let max_capacity = self.extract_entity_scale(destination)
            .map(|scale| match scale {
                crate::models::ecs::SpatialScale::Cosmic => 1000,    // Systems can contain many objects
                crate::models::ecs::SpatialScale::Planetary => 500,  // Planets can contain many locations  
                crate::models::ecs::SpatialScale::Intimate => 50,    // Intimate spaces have lower capacity
            })
            .unwrap_or(100); // Default capacity
        
        if children.len() >= max_capacity {
            return Err(AppError::InvalidInput(
                format!("Destination at capacity: {}/{}", children.len(), max_capacity)
            ));
        }
        
        Ok(())
    }
    
    /// Extract current parent ID from entity's ParentLink component
    fn extract_current_parent_id(&self, entity: &EntityQueryResult) -> Option<Uuid> {
        entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .and_then(|c| c.component_data.get("parent_entity_id"))
            .and_then(|id| id.as_str())
            .and_then(|id_str| Uuid::parse_str(id_str).ok())
    }
    
    /// Determine the type of movement being performed
    async fn determine_movement_type(&self, entity: &EntityQueryResult, destination: &EntityQueryResult) -> String {
        let entity_scale = self.extract_entity_scale(entity);
        let dest_scale = self.extract_entity_scale(destination);
        
        match (entity_scale, dest_scale) {
            (Some(entity_s), Some(dest_s)) => {
                use crate::models::ecs::SpatialScale;
                match (entity_s, dest_s) {
                    (SpatialScale::Planetary, SpatialScale::Cosmic) => "interplanetary".to_string(),
                    (SpatialScale::Cosmic, SpatialScale::Cosmic) => "interstellar".to_string(),
                    (SpatialScale::Intimate, SpatialScale::Planetary) => "surface_movement".to_string(),
                    (SpatialScale::Intimate, SpatialScale::Intimate) => "local_movement".to_string(),
                    _ => "cross_scale_movement".to_string(),
                }
            },
            _ => "standard_movement".to_string(),
        }
    }
    
    // ============================================================================
    // Salience-Aware Entity Management (Task 0.2.2)
    // ============================================================================
    
    /// Create an entity with a specific salience tier
    /// This method determines the appropriate component set based on salience
    #[instrument(skip(self, base_components), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn create_entity_with_salience(
        &self,
        user_id: Uuid,
        entity_id: Option<Uuid>,
        archetype_signature: String,
        salience_tier: crate::models::ecs::SalienceTier,
        scale_context: Option<crate::models::ecs::SpatialScale>,
        base_components: Vec<(String, JsonValue)>,
    ) -> Result<EntityQueryResult, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        let entity_id = entity_id.unwrap_or_else(Uuid::new_v4);
        
        // Create salience component
        let salience_component = if let Some(scale) = scale_context {
            SalienceComponent::with_scale(salience_tier.clone(), scale)
        } else {
            SalienceComponent::new(salience_tier.clone())
        };
        
        // Convert salience component to JSON
        let salience_json = salience_component.to_json()
            .map_err(|e| AppError::SerializationError(format!("Failed to serialize salience component: {}", e)))?;
        
        // Build component list based on salience tier requirements
        let mut components = base_components;
        
        // Always add the salience component
        components.push(("Salience".to_string(), salience_json));
        
        // Add required components for this salience tier if not already present
        let required_components = salience_tier.minimum_components();
        for required_type in required_components {
            if required_type == "Salience" {
                continue; // Already added
            }
            
            // Check if component is already provided
            let already_provided = components.iter().any(|(comp_type, _)| comp_type == required_type);
            if !already_provided {
                // Add default component based on type
                let default_component = self.create_default_component(required_type)?;
                components.push((required_type.to_string(), default_component));
            }
        }
        
        // Filter components based on salience tier (remove complex components for simplified tiers)
        if salience_tier.has_simplified_components() {
            components = self.simplify_components_for_salience(components, &salience_tier);
        }
        
        // Create the entity with all components
        self.create_entity(user_id, Some(entity_id), archetype_signature, components).await
    }
    
    /// Update an entity's salience tier and adjust its components accordingly
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn update_entity_salience(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        new_tier: crate::models::ecs::SalienceTier,
        reason: String,
    ) -> Result<(), AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Get current entity
        let entity_result = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound("Entity not found".to_string()))?;
        
        // Find and update salience component
        let mut salience_component: Option<SalienceComponent> = None;
        let mut other_components = Vec::new();
        
        for comp in &entity_result.components {
            if comp.component_type == "Salience" {
                let mut current_salience = SalienceComponent::from_json(&comp.component_data)
                    .map_err(|e| AppError::SerializationError(format!("Failed to deserialize salience: {}", e)))?;
                
                // Update the salience tier
                match new_tier {
                    crate::models::ecs::SalienceTier::Core => {
                        current_salience.tier = crate::models::ecs::SalienceTier::Core;
                        current_salience.promotion_count += 1;
                    }
                    crate::models::ecs::SalienceTier::Secondary => {
                        if current_salience.tier == crate::models::ecs::SalienceTier::Core {
                            current_salience.tier = crate::models::ecs::SalienceTier::Secondary;
                            current_salience.demotion_count += 1;
                        } else {
                            current_salience.tier = crate::models::ecs::SalienceTier::Secondary;
                            current_salience.promotion_count += 1;
                        }
                    }
                    crate::models::ecs::SalienceTier::Flavor => {
                        current_salience.tier = crate::models::ecs::SalienceTier::Flavor;
                        current_salience.demotion_count += 1;
                    }
                }
                
                current_salience.assignment_reason = reason.clone();
                current_salience.last_interaction = chrono::Utc::now();
                salience_component = Some(current_salience);
            } else {
                other_components.push((comp.component_type.clone(), comp.component_data.clone()));
            }
        }
        
        let salience_component = salience_component.ok_or_else(|| 
            AppError::BadRequest("Entity does not have a Salience component".to_string())
        )?;
        
        // Convert updated salience to JSON
        let salience_json = salience_component.to_json()
            .map_err(|e| AppError::SerializationError(format!("Failed to serialize updated salience: {}", e)))?;
        
        // Add the updated salience component
        other_components.push(("Salience".to_string(), salience_json));
        
        // Adjust components based on new salience tier
        let adjusted_components = self.adjust_components_for_salience_change(
            other_components,
            &salience_component.tier,
        );
        
        // Update the entity with new components
        let component_updates: Vec<ComponentUpdate> = adjusted_components.into_iter()
            .map(|(component_type, component_data)| ComponentUpdate {
                entity_id,
                component_type,
                component_data,
                operation: ComponentOperation::Update,
            })
            .collect();
        
        self.update_components(user_id, entity_id, component_updates).await?;
        Ok(())
    }
    
    /// Promote an entity's salience tier based on interaction tracking
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn promote_entity_salience(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        reason: String,
    ) -> Result<Option<crate::models::ecs::SalienceTier>, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Get current entity
        let entity_result = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound("Entity not found".to_string()))?;
        
        // Find salience component
        let salience_comp = entity_result.components.iter()
            .find(|comp| comp.component_type == "Salience")
            .ok_or_else(|| AppError::BadRequest("Entity does not have a Salience component".to_string()))?;
        
        let mut salience_component = SalienceComponent::from_json(&salience_comp.component_data)
            .map_err(|e| AppError::SerializationError(format!("Failed to deserialize salience: {}", e)))?;
        
        // Check if promotion is appropriate
        if salience_component.should_consider_promotion() {
            match salience_component.promote(reason) {
                Ok(new_tier) => {
                    // Update the entity with new salience tier
                    self.update_entity_salience(user_id, entity_id, new_tier.clone(), 
                                               salience_component.assignment_reason.clone()).await?;
                    Ok(Some(new_tier))
                }
                Err(_) => Ok(None), // Promotion not possible or not allowed
            }
        } else {
            Ok(None) // Not ready for promotion
        }
    }
    
    /// Demote an entity's salience tier based on inactivity
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn demote_entity_salience(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        reason: String,
    ) -> Result<Option<crate::models::ecs::SalienceTier>, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Get current entity
        let entity_result = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound("Entity not found".to_string()))?;
        
        // Find salience component
        let salience_comp = entity_result.components.iter()
            .find(|comp| comp.component_type == "Salience")
            .ok_or_else(|| AppError::BadRequest("Entity does not have a Salience component".to_string()))?;
        
        let mut salience_component = SalienceComponent::from_json(&salience_comp.component_data)
            .map_err(|e| AppError::SerializationError(format!("Failed to deserialize salience: {}", e)))?;
        
        // Check if demotion is appropriate
        if salience_component.should_consider_demotion() {
            match salience_component.demote(reason) {
                Ok(new_tier) => {
                    // Update the entity with new salience tier
                    self.update_entity_salience(user_id, entity_id, new_tier.clone(), 
                                               salience_component.assignment_reason.clone()).await?;
                    Ok(Some(new_tier))
                }
                Err(_) => Ok(None), // Demotion not possible or not allowed
            }
        } else {
            Ok(None) // Not ready for demotion
        }
    }
    
    /// Find entities that can be garbage collected (Flavor tier entities that are inactive)
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn find_garbage_collectible_entities(
        &self,
        user_id: Uuid,
        scale_context: Option<crate::models::ecs::SpatialScale>,
        limit: Option<usize>,
    ) -> Result<Vec<Uuid>, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Query entities with Salience components
        let query_criteria = vec![ComponentQuery::HasComponent("Salience".to_string())];
        let options = EntityQueryOptions {
            criteria: query_criteria,
            limit: limit.map(|l| l as i64),
            offset: None,
            sort_by: None,
            min_components: None,
            max_components: None,
            cache_key: None,
            cache_ttl: None,
        };
        
        let entities = self.query_entities_advanced(user_id, options).await?;
        
        let mut garbage_collectible = Vec::new();
        
        for entity_result in entities.entities {
            if let Some(salience_comp) = entity_result.components.iter()
                .find(|comp| comp.component_type == "Salience") {
                
                if let Ok(salience_component) = SalienceComponent::from_json(&salience_comp.component_data) {
                    // Check if this entity can be garbage collected
                    if salience_component.can_be_garbage_collected() {
                        // If scale context is specified, check if it matches
                        if let Some(scale) = &scale_context {
                            if salience_component.is_appropriate_for_scale(scale) {
                                garbage_collectible.push(entity_result.entity.id);
                            }
                        } else {
                            garbage_collectible.push(entity_result.entity.id);
                        }
                    }
                }
            }
        }
        
        Ok(garbage_collectible)
    }
    
    /// Garbage collect entities that are eligible for removal
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn garbage_collect_entities(
        &self,
        user_id: Uuid,
        entity_ids: Vec<Uuid>,
    ) -> Result<usize, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        let mut collected_count = 0;
        
        for entity_id in entity_ids {
            // Double-check that the entity can be garbage collected
            if let Ok(Some(entity_result)) = self.get_entity(user_id, entity_id).await {
                if let Some(salience_comp) = entity_result.components.iter()
                    .find(|comp| comp.component_type == "Salience") {
                    
                    if let Ok(salience_component) = SalienceComponent::from_json(&salience_comp.component_data) {
                        if salience_component.can_be_garbage_collected() {
                            // Delete the entity by removing all its components first, then the entity itself
                            let delete_result = self.delete_entity_internal(user_id, entity_id).await;
                            match delete_result {
                                Ok(_) => {
                                    collected_count += 1;
                                    info!("Garbage collected entity {} (reason: {})", 
                                          entity_id, salience_component.assignment_reason);
                                }
                                Err(e) => {
                                    warn!("Failed to garbage collect entity {}: {}", entity_id, e);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(collected_count)
    }
    
    /// Record an interaction with an entity to update its salience tracking
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn record_entity_interaction(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
    ) -> Result<bool, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Get current entity
        let entity_result = match self.get_entity(user_id, entity_id).await {
            Ok(Some(result)) => result,
            Ok(None) | Err(_) => return Ok(false), // Entity doesn't exist, nothing to record
        };
        
        // Find and update salience component
        if let Some(salience_comp) = entity_result.components.iter()
            .find(|comp| comp.component_type == "Salience") {
            
            let mut salience_component = SalienceComponent::from_json(&salience_comp.component_data)
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize salience: {}", e)))?;
            
            // Record the interaction
            salience_component.record_interaction();
            
            // Update the component
            let salience_json = salience_component.to_json()
                .map_err(|e| AppError::SerializationError(format!("Failed to serialize salience: {}", e)))?;
            
            // Update only the salience component
            let component_update = ComponentUpdate {
                entity_id,
                component_type: "Salience".to_string(),
                component_data: salience_json,
                operation: ComponentOperation::Update,
            };
            
            self.update_components(user_id, entity_id, vec![component_update]).await?;
            
            Ok(true)
        } else {
            Ok(false) // No salience component to update
        }
    }
    
    /// Get entities filtered by salience tier
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_entities_by_salience(
        &self,
        user_id: Uuid,
        salience_tier: crate::models::ecs::SalienceTier,
        scale_context: Option<crate::models::ecs::SpatialScale>,
        limit: Option<usize>,
    ) -> Result<Vec<EntityQueryResult>, AppError> {
        use crate::models::ecs::{SalienceComponent, Component};
        
        // Query entities with Salience components
        let query_criteria = vec![ComponentQuery::HasComponent("Salience".to_string())];
        let options = EntityQueryOptions {
            criteria: query_criteria,
            limit: limit.map(|l| l as i64),
            offset: None,
            sort_by: None,
            min_components: None,
            max_components: None,
            cache_key: None,
            cache_ttl: None,
        };
        
        let entities = self.query_entities_advanced(user_id, options).await?;
        
        let mut filtered_entities = Vec::new();
        
        for entity_result in entities.entities {
            if let Some(salience_comp) = entity_result.components.iter()
                .find(|comp| comp.component_type == "Salience") {
                
                if let Ok(salience_component) = SalienceComponent::from_json(&salience_comp.component_data) {
                    // Check if salience tier matches
                    if salience_component.tier == salience_tier {
                        // If scale context is specified, check if it matches
                        if let Some(scale) = &scale_context {
                            if salience_component.is_appropriate_for_scale(scale) {
                                filtered_entities.push(entity_result);
                            }
                        } else {
                            filtered_entities.push(entity_result);
                        }
                    }
                }
            }
        }
        
        Ok(filtered_entities)
    }
    
    // ============================================================================
    // Inventory Management (Task 2.4)
    // ============================================================================
    
    /// Add an item to an entity's inventory
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn add_item_to_inventory(
        &self,
        user_id: Uuid,
        character_entity_id: Uuid,
        item_entity_id: Uuid,
        quantity: u32,
        slot: Option<usize>,
    ) -> Result<InventoryItem, AppError> {
        use crate::models::ecs::{InventoryComponent, InventoryItem, Component};
        use diesel::prelude::*;
        
        // Validate that both entities exist and belong to the user
        let character = self.get_entity(user_id, character_entity_id).await?
            .ok_or_else(|| AppError::NotFound("Character entity not found".to_string()))?;
        let _item = self.get_entity(user_id, item_entity_id).await?
            .ok_or_else(|| AppError::NotFound("Item entity not found".to_string()))?;
        
        // Find the inventory component
        let inventory_comp = character.components.iter()
            .find(|c| c.component_type == "Inventory")
            .ok_or_else(|| AppError::NotFound("Entity does not have an Inventory component".to_string()))?;
        
        let mut inventory: InventoryComponent = serde_json::from_value(inventory_comp.component_data.clone())
            .map_err(|e| AppError::SerializationError(format!("Failed to deserialize inventory: {}", e)))?;
        
        // Check if adding this item would exceed capacity
        let current_item_count = inventory.items.len();
        if current_item_count >= inventory.capacity {
            return Err(AppError::InvalidInput(
                format!("Inventory at capacity: {}/{}", current_item_count, inventory.capacity)
            ));
        }
        
        // Check if item already exists, if so, add to existing quantity
        if let Some(existing_item) = inventory.items.iter_mut().find(|item| item.entity_id == item_entity_id) {
            existing_item.quantity += quantity;
            if slot.is_some() {
                existing_item.slot = slot;
            }
        } else {
            // Add new item
            let new_item = InventoryItem {
                entity_id: item_entity_id,
                quantity,
                slot,
            };
            inventory.items.push(new_item.clone());
        }
        
        // Update the inventory component in the database
        let updated_inventory_json = serde_json::to_value(&inventory)
            .map_err(|e| AppError::SerializationError(format!("Failed to serialize updated inventory: {}", e)))?;
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact(move |conn| {
            conn.transaction(|conn| {
                diesel::update(crate::schema::ecs_components::table)
                    .filter(crate::schema::ecs_components::entity_id.eq(character_entity_id))
                    .filter(crate::schema::ecs_components::component_type.eq("Inventory"))
                    .set(crate::schema::ecs_components::component_data.eq(&updated_inventory_json))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to update inventory: {}", e)))
            })
        }).await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))??;
        
        // Invalidate cache
        let user_hash = Self::hash_user_id(user_id);
        let cache_key = format!("ecs:entity:{}:{}", user_hash, character_entity_id);
        if let Ok(mut redis_conn) = self.redis_client.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::Cmd::del(&cache_key).query_async(&mut redis_conn).await;
        }
        
        // Return the added item
        let added_item = inventory.items.iter()
            .find(|item| item.entity_id == item_entity_id)
            .cloned()
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Failed to find added item".to_string()))?;
        
        Ok(added_item)
    }
    
    /// Remove an item from an entity's inventory
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn remove_item_from_inventory(
        &self,
        user_id: Uuid,
        character_entity_id: Uuid,
        item_entity_id: Uuid,
        quantity: u32,
    ) -> Result<InventoryItem, AppError> {
        use crate::models::ecs::{InventoryComponent, InventoryItem, Component};
        use diesel::prelude::*;
        
        // Validate that character exists and belongs to the user
        let character = self.get_entity(user_id, character_entity_id).await?
            .ok_or_else(|| AppError::NotFound("Character entity not found".to_string()))?;
        
        // Find the inventory component
        let inventory_comp = character.components.iter()
            .find(|c| c.component_type == "Inventory")
            .ok_or_else(|| AppError::NotFound("Entity does not have an Inventory component".to_string()))?;
        
        let mut inventory: InventoryComponent = serde_json::from_value(inventory_comp.component_data.clone())
            .map_err(|e| AppError::SerializationError(format!("Failed to deserialize inventory: {}", e)))?;
        
        // Find the item to remove
        let item_index = inventory.items.iter().position(|item| item.entity_id == item_entity_id)
            .ok_or_else(|| AppError::NotFound("Item not found in inventory".to_string()))?;
        
        let current_item = &mut inventory.items[item_index];
        
        // Check if we have enough quantity to remove
        if current_item.quantity < quantity {
            return Err(AppError::InvalidInput(
                format!("Insufficient quantity: has {}, trying to remove {}", current_item.quantity, quantity)
            ));
        }
        
        let removed_item = InventoryItem {
            entity_id: item_entity_id,
            quantity,
            slot: current_item.slot,
        };
        
        // Update quantity or remove item completely
        if current_item.quantity == quantity {
            inventory.items.remove(item_index);
        } else {
            current_item.quantity -= quantity;
        }
        
        // Update the inventory component in the database
        let updated_inventory_json = serde_json::to_value(&inventory)
            .map_err(|e| AppError::SerializationError(format!("Failed to serialize updated inventory: {}", e)))?;
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact(move |conn| {
            conn.transaction(|conn| {
                diesel::update(crate::schema::ecs_components::table)
                    .filter(crate::schema::ecs_components::entity_id.eq(character_entity_id))
                    .filter(crate::schema::ecs_components::component_type.eq("Inventory"))
                    .set(crate::schema::ecs_components::component_data.eq(&updated_inventory_json))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to update inventory: {}", e)))
            })
        }).await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))??;
        
        // Invalidate cache
        let user_hash = Self::hash_user_id(user_id);
        let cache_key = format!("ecs:entity:{}:{}", user_hash, character_entity_id);
        if let Ok(mut redis_conn) = self.redis_client.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::Cmd::del(&cache_key).query_async(&mut redis_conn).await;
        }
        
        Ok(removed_item)
    }
    
    // ============================================================================
    // Relationship Management (Task 2.4)
    // ============================================================================
    
    /// Update or create a relationship between two entities
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn update_relationship(
        &self,
        user_id: Uuid,
        source_entity_id: Uuid,
        target_entity_id: Uuid,
        relationship_type: String,
        trust: f32,
        affection: f32,
        metadata: HashMap<String, JsonValue>,
    ) -> Result<Relationship, AppError> {
        use crate::models::ecs::{RelationshipsComponent, Relationship, Component};
        use diesel::prelude::*;
        use std::collections::HashMap;
        
        // Validate trust and affection bounds
        if trust < -1.0 || trust > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Trust value must be between -1.0 and 1.0, got: {}", trust)
            ));
        }
        if affection < -1.0 || affection > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Affection value must be between -1.0 and 1.0, got: {}", affection)
            ));
        }
        
        // Prevent self-relationships
        if source_entity_id == target_entity_id {
            return Err(AppError::InvalidInput("Entity cannot have a relationship with itself".to_string()));
        }
        
        // Validate that both entities exist and belong to the user
        let source_entity = self.get_entity(user_id, source_entity_id).await?
            .ok_or_else(|| AppError::NotFound("Source entity not found".to_string()))?;
        let _target_entity = self.get_entity(user_id, target_entity_id).await?
            .ok_or_else(|| AppError::NotFound("Target entity not found".to_string()))?;
        
        // Find the relationships component
        let relationships_comp = source_entity.components.iter()
            .find(|c| c.component_type == "Relationships")
            .ok_or_else(|| AppError::NotFound("Entity does not have a Relationships component".to_string()))?;
        
        let mut relationships: RelationshipsComponent = serde_json::from_value(relationships_comp.component_data.clone())
            .map_err(|e| AppError::SerializationError(format!("Failed to deserialize relationships: {}", e)))?;
        
        // Find existing relationship or create new one
        let new_relationship = Relationship {
            target_entity_id,
            relationship_type: relationship_type.clone(),
            trust,
            affection,
            metadata: metadata.clone(),
        };
        
        if let Some(existing_rel) = relationships.relationships.iter_mut()
            .find(|rel| rel.target_entity_id == target_entity_id) {
            // Update existing relationship
            *existing_rel = new_relationship.clone();
        } else {
            // Add new relationship
            relationships.relationships.push(new_relationship.clone());
        }
        
        // Update the relationships component in the database
        let updated_relationships_json = serde_json::to_value(&relationships)
            .map_err(|e| AppError::SerializationError(format!("Failed to serialize updated relationships: {}", e)))?;
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        conn.interact(move |conn| {
            conn.transaction(|conn| {
                diesel::update(crate::schema::ecs_components::table)
                    .filter(crate::schema::ecs_components::entity_id.eq(source_entity_id))
                    .filter(crate::schema::ecs_components::component_type.eq("Relationships"))
                    .set(crate::schema::ecs_components::component_data.eq(&updated_relationships_json))
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to update relationships: {}", e)))
            })
        }).await
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))??;
        
        // Invalidate cache
        let user_hash = Self::hash_user_id(user_id);
        let cache_key = format!("ecs:entity:{}:{}", user_hash, source_entity_id);
        if let Ok(mut redis_conn) = self.redis_client.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::Cmd::del(&cache_key).query_async(&mut redis_conn).await;
        }
        
        Ok(new_relationship)
    }
    
    /// Get all relationships for an entity
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn get_relationships(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
    ) -> Result<Vec<Relationship>, AppError> {
        use crate::models::ecs::{RelationshipsComponent, Component};
        
        // Get entity and validate ownership
        let entity = self.get_entity(user_id, entity_id).await?
            .ok_or_else(|| AppError::NotFound("Entity not found".to_string()))?;
        
        // Find the relationships component
        if let Some(relationships_comp) = entity.components.iter()
            .find(|c| c.component_type == "Relationships") {
            
            let relationships: RelationshipsComponent = serde_json::from_value(relationships_comp.component_data.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize relationships: {}", e)))?;
            
            Ok(relationships.relationships)
        } else {
            // Entity has no relationships component, return empty list
            Ok(Vec::new())
        }
    }

    // Helper methods for salience management
    
    /// Create a default component of the given type
    fn create_default_component(&self, component_type: &str) -> Result<JsonValue, AppError> {
        use crate::models::ecs::{NameComponent, TemporalComponent, Component};
        use serde_json::json;
        
        match component_type {
            "Name" => {
                let name_component = NameComponent {
                    name: "Generated Entity".to_string(),
                    display_name: "Generated Entity".to_string(),
                    aliases: Vec::new(),
                };
                name_component.to_json()
                    .map_err(|e| AppError::SerializationError(format!("Failed to serialize name component: {}", e)))
            }
            "Temporal" => {
                let temporal_component = TemporalComponent::default();
                temporal_component.to_json()
                    .map_err(|e| AppError::SerializationError(format!("Failed to serialize temporal component: {}", e)))
            }
            _ => {
                // Return empty JSON object for unknown component types
                Ok(json!({}))
            }
        }
    }
    
    /// Simplify components for entities with simplified salience tiers
    fn simplify_components_for_salience(
        &self,
        components: Vec<(String, JsonValue)>,
        salience_tier: &crate::models::ecs::SalienceTier,
    ) -> Vec<(String, JsonValue)> {
        use serde_json::json;
        
        if !salience_tier.has_simplified_components() {
            return components;
        }
        
        // For simplified entities, keep only essential components and simplify complex ones
        let mut simplified = Vec::new();
        
        for (component_type, component_data) in components {
            match component_type.as_str() {
                "Salience" | "Name" => {
                    // Always keep these components as-is
                    simplified.push((component_type, component_data));
                }
                "Temporal" => {
                    // Simplify temporal component for Secondary/Flavor entities
                    if *salience_tier == crate::models::ecs::SalienceTier::Flavor {
                        // Minimal temporal data for flavor entities
                        simplified.push((component_type, json!({
                            "created_at": chrono::Utc::now(),
                            "time_scale": 1.0
                        })));
                    } else {
                        // Keep full temporal for Secondary
                        simplified.push((component_type, component_data));
                    }
                }
                "Relationships" => {
                    // Simplify relationships for flavor entities
                    if *salience_tier == crate::models::ecs::SalienceTier::Flavor {
                        simplified.push((component_type, json!({
                            "relationships": []
                        })));
                    } else {
                        simplified.push((component_type, component_data));
                    }
                }
                "Inventory" => {
                    // Simplify inventory for non-core entities
                    if *salience_tier != crate::models::ecs::SalienceTier::Core {
                        simplified.push((component_type, json!({
                            "items": [],
                            "capacity": 5
                        })));
                    } else {
                        simplified.push((component_type, component_data));
                    }
                }
                _ => {
                    // Keep other components but mark them as simplified if needed
                    simplified.push((component_type, component_data));
                }
            }
        }
        
        simplified
    }
    
    /// Adjust components when salience tier changes
    fn adjust_components_for_salience_change(
        &self,
        components: Vec<(String, JsonValue)>,
        new_salience_tier: &crate::models::ecs::SalienceTier,
    ) -> Vec<(String, JsonValue)> {
        // For now, just apply simplification based on new tier
        self.simplify_components_for_salience(components, new_salience_tier)
    }
    
    /// Internal method to delete an entity and all its components
    async fn delete_entity_internal(&self, user_id: Uuid, entity_id: Uuid) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact({
            let user_id = user_id;
            let entity_id = entity_id;
            move |conn| -> Result<(), AppError> {
                conn.transaction(|conn| {
                    use crate::schema::{ecs_components, ecs_entities};
                    
                    // Delete components first (foreign key constraint)
                    diesel::delete(
                        ecs_components::table
                            .filter(ecs_components::entity_id.eq(entity_id))
                            .filter(ecs_components::user_id.eq(user_id))
                    )
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                    
                    // Delete the entity
                    diesel::delete(
                        ecs_entities::table
                            .filter(ecs_entities::id.eq(entity_id))
                            .filter(ecs_entities::user_id.eq(user_id))
                    )
                    .execute(conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                    
                    Ok(())
                })
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))??;

        // Clear cache entry for deleted entity
        let cache_key = format!("entity:{}:{}", user_id, entity_id);
        let _: Result<(), redis::RedisError> = async {
            let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
            conn.del(&cache_key).await
        }.await;

        Ok(())
    }
}

/// Information about an entity in a spatial hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityHierarchyInfo {
    pub entity_id: Uuid,
    pub name: String,
    pub scale: Option<crate::models::ecs::SpatialScale>,
    pub hierarchical_level: u32,
    pub depth_from_root: u32,
    pub parent_id: Option<Uuid>,
    pub relationship: Option<String>,
}

/// Options for entity movement operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveEntityOptions {
    /// Whether to validate scale compatibility between entity and destination
    pub validate_scale_compatibility: bool,
    /// Whether to validate that movement doesn't create circular relationships
    pub validate_movement_path: bool,
    /// Whether to validate that destination has capacity for new entity
    pub validate_destination_capacity: bool,
    /// Whether to update the entity's position component
    pub update_position: bool,
    /// New position data if update_position is true
    pub new_position: Option<PositionData>,
    /// Spatial relationship type (default: "contained_within")
    pub spatial_relationship: Option<String>,
    /// Movement type classification (e.g., "interplanetary", "local")
    pub movement_type: Option<String>,
}

impl Default for MoveEntityOptions {
    fn default() -> Self {
        Self {
            validate_scale_compatibility: true,
            validate_movement_path: true,
            validate_destination_capacity: false,
            update_position: false,
            new_position: None,
            spatial_relationship: None,
            movement_type: None,
        }
    }
}

/// Position data for entity movement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionData {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub zone: String,
}

/// Result of entity movement operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveEntityResult {
    /// Whether the movement was successful
    pub success: bool,
    /// ID of the entity that was moved
    pub entity_id: Uuid,
    /// Previous parent entity ID (if any)
    pub old_parent_id: Option<Uuid>,
    /// New parent entity ID
    pub new_parent_id: Uuid,
    /// Whether position was updated during movement
    pub position_updated: bool,
    /// Type of movement performed
    pub movement_type: String,
    /// Validations that were performed
    pub validations_performed: std::collections::HashMap<String, JsonValue>,
    /// Timestamp of the movement
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Tree structure representing entity containment hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityContainmentTree {
    pub entity_id: Uuid,
    pub name: String,
    pub scale: Option<crate::models::ecs::SpatialScale>,
    pub depth: u32,
    pub children: Vec<EntityContainmentTree>,
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