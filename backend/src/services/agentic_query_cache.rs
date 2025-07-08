use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use tracing::{info, debug, instrument};

use crate::errors::AppError;

/// Cache entry for agentic query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cached result data
    pub result: String,
    /// When this entry was created
    pub created_at: DateTime<Utc>,
    /// When this entry expires
    pub expires_at: DateTime<Utc>,
    /// How many times this cache entry has been accessed
    pub access_count: u64,
    /// Last time this entry was accessed
    pub last_accessed: DateTime<Utc>,
    /// Context that was used to generate this result
    pub context_hash: String,
}

/// Configuration for the agentic query cache
#[derive(Debug, Clone)]
pub struct AgenticCacheConfig {
    /// Default TTL for cache entries
    pub default_ttl: Duration,
    /// Maximum number of entries to keep in memory
    pub max_entries: usize,
    /// TTL for entity state queries (shorter since entity state changes frequently)
    pub entity_state_ttl: Duration,
    /// TTL for relationship queries (medium duration)
    pub relationship_ttl: Duration,
    /// TTL for chronicle/lorebook queries (longer since these change less frequently)
    pub content_ttl: Duration,
}

impl Default for AgenticCacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::minutes(30),
            max_entries: 1000,
            entity_state_ttl: Duration::minutes(5),  // Entity states change quickly
            relationship_ttl: Duration::minutes(15), // Relationships change moderately
            content_ttl: Duration::hours(2),         // Chronicles/lorebooks change slowly
        }
    }
}

/// Types of queries that can be cached
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QueryType {
    EntityState,
    EntityRelationships,
    ChronicleContent,
    LorebookContent,
    SpatialContext,
    CausalAnalysis,
    TemporalAnalysis,
}

/// A cache key that uniquely identifies a query
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Type of query
    pub query_type: QueryType,
    /// User ID for isolation
    pub user_id: Uuid,
    /// Hash of the query parameters
    pub parameter_hash: String,
    /// Optional chronicle context
    pub chronicle_id: Option<Uuid>,
}

impl CacheKey {
    /// Create a cache key from query parameters
    pub fn new(
        query_type: QueryType,
        user_id: Uuid,
        parameters: &str,
        chronicle_id: Option<Uuid>,
    ) -> Self {
        let parameter_hash = Self::hash_string(parameters);
        Self {
            query_type,
            user_id,
            parameter_hash,
            chronicle_id,
        }
    }

    /// Hash a string for use in cache keys
    fn hash_string(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string() // Take first 16 chars for brevity
    }

    /// Convert to a string key for storage
    pub fn to_string_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            serde_json::to_string(&self.query_type).unwrap_or_default(),
            self.user_id,
            self.parameter_hash,
            self.chronicle_id.map(|id| id.to_string()).unwrap_or_default()
        )
    }
}

/// Cache metrics for performance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub total_lookups: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub hit_rate: f64,
    pub miss_rate: f64,
    pub evictions: u64,
    pub stores: u64,
    pub invalidations: u64,
    pub current_size: usize,
    pub max_size: usize,
    pub utilization_percentage: f64,
}

/// In-memory cache for agentic query results with TTL and LRU eviction
pub struct AgenticQueryCache {
    /// Configuration
    config: AgenticCacheConfig,
    /// Cache storage - map from string key to cache entry
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Access order for LRU eviction - most recently accessed keys at the end
    access_order: Arc<RwLock<Vec<String>>>,
    /// Performance metrics (atomic counters for thread safety)
    metrics: CacheMetricsCounters,
}

/// Atomic counters for cache metrics
#[derive(Debug)]
struct CacheMetricsCounters {
    total_lookups: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    evictions: AtomicU64,
    stores: AtomicU64,
    invalidations: AtomicU64,
}

impl AgenticQueryCache {
    /// Create a new agentic query cache
    pub fn new(config: AgenticCacheConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(RwLock::new(Vec::new())),
            metrics: CacheMetricsCounters {
                total_lookups: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
                evictions: AtomicU64::new(0),
                stores: AtomicU64::new(0),
                invalidations: AtomicU64::new(0),
            },
        }
    }

    /// Get the TTL for a specific query type
    fn get_ttl_for_query_type(&self, query_type: &QueryType) -> Duration {
        match query_type {
            QueryType::EntityState => self.config.entity_state_ttl,
            QueryType::EntityRelationships => self.config.relationship_ttl,
            QueryType::ChronicleContent => self.config.content_ttl,
            QueryType::LorebookContent => self.config.content_ttl,
            QueryType::SpatialContext => self.config.relationship_ttl,
            QueryType::CausalAnalysis => self.config.default_ttl,
            QueryType::TemporalAnalysis => self.config.default_ttl,
        }
    }

    /// Store a result in the cache
    #[instrument(skip(self, result), fields(cache_key = %cache_key.to_string_key()))]
    pub async fn store(
        &self,
        cache_key: CacheKey,
        result: String,
        context: Option<&str>,
    ) -> Result<(), AppError> {
        let string_key = cache_key.to_string_key();
        let ttl = self.get_ttl_for_query_type(&cache_key.query_type);
        let now = Utc::now();
        
        let context_hash = context.map_or_else(
            || "no_context".to_string(),
            |ctx| CacheKey::hash_string(ctx)
        );

        let entry = CacheEntry {
            result,
            created_at: now,
            expires_at: now + ttl,
            access_count: 0,
            last_accessed: now,
            context_hash,
        };

        // Store the entry
        {
            let mut cache = self.cache.write().await;
            cache.insert(string_key.clone(), entry);
        }

        // Update access order (add to end as most recent)
        {
            let mut access_order = self.access_order.write().await;
            // Remove if already exists (to move to end)
            access_order.retain(|k| k != &string_key);
            access_order.push(string_key.clone());
        }

        // Check if we need to evict entries
        self.evict_if_needed().await?;

        // Update metrics
        self.metrics.stores.fetch_add(1, Ordering::Relaxed);

        debug!("Stored cache entry for key: {}", string_key);
        Ok(())
    }

    /// Retrieve a result from the cache
    #[instrument(skip(self), fields(cache_key = %cache_key.to_string_key()))]
    pub async fn get(
        &self,
        cache_key: &CacheKey,
        context: Option<&str>,
    ) -> Result<Option<String>, AppError> {
        let string_key = cache_key.to_string_key();
        let now = Utc::now();
        
        let context_hash = context.map_or_else(
            || "no_context".to_string(),
            |ctx| CacheKey::hash_string(ctx)
        );

        // Update lookup metrics
        self.metrics.total_lookups.fetch_add(1, Ordering::Relaxed);

        let mut cache = self.cache.write().await;
        
        if let Some(mut entry) = cache.get(&string_key).cloned() {
            // Check if entry has expired
            if entry.expires_at < now {
                debug!("Cache entry expired for key: {}", string_key);
                cache.remove(&string_key);
                self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }

            // Check if context matches (for context-sensitive queries)
            if !self.context_matches(&entry.context_hash, &context_hash, &cache_key.query_type) {
                debug!("Cache entry context mismatch for key: {}", string_key);
                self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }

            // Update access statistics
            entry.access_count += 1;
            entry.last_accessed = now;
            cache.insert(string_key.clone(), entry.clone());

            // Update access order (move to end as most recent)
            {
                let mut access_order = self.access_order.write().await;
                access_order.retain(|k| k != &string_key);
                access_order.push(string_key.clone());
            }

            debug!("Cache hit for key: {} (access count: {})", string_key, entry.access_count);
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            Ok(Some(entry.result))
        } else {
            debug!("Cache miss for key: {}", string_key);
            self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    /// Check if the context matches for cache validity
    fn context_matches(
        &self,
        stored_context_hash: &str,
        current_context_hash: &str,
        query_type: &QueryType,
    ) -> bool {
        match query_type {
            // Entity state queries are very context-sensitive
            QueryType::EntityState => stored_context_hash == current_context_hash,
            // Relationship queries are moderately context-sensitive
            QueryType::EntityRelationships => stored_context_hash == current_context_hash,
            // Content queries are less context-sensitive
            QueryType::ChronicleContent | QueryType::LorebookContent => {
                // Allow some context variation for content queries
                stored_context_hash == current_context_hash || stored_context_hash == "no_context"
            }
            // Analysis queries are context-sensitive
            QueryType::SpatialContext | QueryType::CausalAnalysis | QueryType::TemporalAnalysis => {
                stored_context_hash == current_context_hash
            }
        }
    }

    /// Invalidate cache entries for a specific entity (when entity state changes)
    #[instrument(skip(self))]
    pub async fn invalidate_entity(&self, user_id: Uuid, entity_id: Uuid) -> Result<(), AppError> {
        let user_id_str = user_id.to_string();
        let mut cache = self.cache.write().await;
        let mut access_order = self.access_order.write().await;
        
        // Create potential parameter patterns that might involve this entity
        let entity_patterns = vec![
            format!("entity_{}_current_state", entity_id),
            format!("entity_{}_relationships", entity_id),
            format!("entity_{}", entity_id),
            entity_id.to_string(),
        ];
        
        // Hash these patterns to match against stored parameter hashes
        let entity_pattern_hashes: Vec<String> = entity_patterns
            .iter()
            .map(|pattern| CacheKey::hash_string(pattern))
            .collect();
        
        // Find keys that involve this entity by checking user_id and query type patterns
        let keys_to_remove: Vec<String> = cache
            .keys()
            .filter(|key| {
                // Check if this key belongs to the user and is entity-related
                if !key.contains(&user_id_str) || 
                   !(key.contains("EntityState") || key.contains("EntityRelationships")) {
                    return false;
                }
                
                // Check if any of our entity pattern hashes match this key
                entity_pattern_hashes.iter().any(|hash| key.contains(hash))
            })
            .cloned()
            .collect();

        let removed_count = keys_to_remove.len();
        for key in &keys_to_remove {
            cache.remove(key);
            access_order.retain(|k| k != key);
        }

        if removed_count > 0 {
            info!("Invalidated {} cache entries for entity {}", removed_count, entity_id);
            self.metrics.invalidations.fetch_add(removed_count as u64, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Invalidate cache entries for a specific chronicle
    #[instrument(skip(self))]
    pub async fn invalidate_chronicle(&self, user_id: Uuid, chronicle_id: Uuid) -> Result<(), AppError> {
        let chronicle_id_str = chronicle_id.to_string();
        let mut cache = self.cache.write().await;
        let mut access_order = self.access_order.write().await;
        
        // Find keys that involve this chronicle
        let keys_to_remove: Vec<String> = cache
            .keys()
            .filter(|key| {
                key.contains(&user_id.to_string()) && 
                key.contains(&chronicle_id_str) &&
                key.contains("ChronicleContent")
            })
            .cloned()
            .collect();

        let removed_count = keys_to_remove.len();
        for key in &keys_to_remove {
            cache.remove(key);
            access_order.retain(|k| k != key);
        }

        if removed_count > 0 {
            info!("Invalidated {} cache entries for chronicle {}", removed_count, chronicle_id);
            self.metrics.invalidations.fetch_add(removed_count as u64, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Evict entries if we've exceeded the maximum cache size
    async fn evict_if_needed(&self) -> Result<(), AppError> {
        let cache_size = self.cache.read().await.len();
        
        if cache_size > self.config.max_entries {
            let entries_to_evict = cache_size - self.config.max_entries + 100; // Evict some extra to avoid frequent evictions
            
            let mut cache = self.cache.write().await;
            let mut access_order = self.access_order.write().await;
            
            // Evict least recently used entries
            let keys_to_evict: Vec<String> = access_order
                .iter()
                .take(entries_to_evict)
                .cloned()
                .collect();

            for key in &keys_to_evict {
                cache.remove(key);
            }
            
            access_order.drain(0..keys_to_evict.len());
            
            let evicted_count = keys_to_evict.len();
            self.metrics.evictions.fetch_add(evicted_count as u64, Ordering::Relaxed);
            info!("Evicted {} cache entries (LRU)", evicted_count);
        }

        Ok(())
    }

    /// Clean up expired entries
    #[instrument(skip(self))]
    pub async fn cleanup_expired(&self) -> Result<usize, AppError> {
        let now = Utc::now();
        let mut cache = self.cache.write().await;
        let mut access_order = self.access_order.write().await;
        
        // Find expired entries
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.expires_at < now)
            .map(|(key, _)| key.clone())
            .collect();

        let expired_count = expired_keys.len();
        
        // Remove expired entries
        for key in &expired_keys {
            cache.remove(key);
            access_order.retain(|k| k != key);
        }

        if expired_count > 0 {
            info!("Cleaned up {} expired cache entries", expired_count);
        }

        Ok(expired_count)
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let now = Utc::now();
        
        let (expired_entries, total_access_count) = cache
            .values()
            .fold((0, 0), |(expired, total_access), entry| {
                let expired_count = if entry.expires_at < now { expired + 1 } else { expired };
                (expired_count, total_access + entry.access_count)
            });

        CacheStats {
            total_entries,
            expired_entries,
            total_access_count,
            max_entries: self.config.max_entries,
        }
    }

    /// Get comprehensive cache performance metrics
    pub async fn get_metrics(&self) -> CacheMetrics {
        let cache = self.cache.read().await;
        let current_size = cache.len();
        let max_size = self.config.max_entries;
        
        let total_lookups = self.metrics.total_lookups.load(Ordering::Relaxed);
        let cache_hits = self.metrics.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.metrics.cache_misses.load(Ordering::Relaxed);
        let evictions = self.metrics.evictions.load(Ordering::Relaxed);
        let stores = self.metrics.stores.load(Ordering::Relaxed);
        let invalidations = self.metrics.invalidations.load(Ordering::Relaxed);
        
        let hit_rate = if total_lookups > 0 {
            (cache_hits as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };
        
        let miss_rate = 100.0 - hit_rate;
        
        let utilization_percentage = if max_size > 0 {
            (current_size as f64 / max_size as f64) * 100.0
        } else {
            0.0
        };
        
        CacheMetrics {
            total_lookups,
            cache_hits,
            cache_misses,
            hit_rate,
            miss_rate,
            evictions,
            stores,
            invalidations,
            current_size,
            max_size,
            utilization_percentage,
        }
    }

    /// Reset all metrics counters
    pub fn reset_metrics(&self) {
        self.metrics.total_lookups.store(0, Ordering::Relaxed);
        self.metrics.cache_hits.store(0, Ordering::Relaxed);
        self.metrics.cache_misses.store(0, Ordering::Relaxed);
        self.metrics.evictions.store(0, Ordering::Relaxed);
        self.metrics.stores.store(0, Ordering::Relaxed);
        self.metrics.invalidations.store(0, Ordering::Relaxed);
    }
}

/// Cache performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub total_access_count: u64,
    pub max_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_store_and_retrieve() {
        let config = AgenticCacheConfig::default();
        let cache = AgenticQueryCache::new(config);
        
        let cache_key = CacheKey::new(
            QueryType::EntityState,
            Uuid::new_v4(),
            "entity_123_current_state",
            None,
        );
        
        let result = "Entity is healthy and active".to_string();
        
        // Store result
        cache.store(cache_key.clone(), result.clone(), None).await.unwrap();
        
        // Retrieve result
        let retrieved = cache.get(&cache_key, None).await.unwrap();
        assert_eq!(retrieved, Some(result));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let mut config = AgenticCacheConfig::default();
        config.entity_state_ttl = Duration::milliseconds(10); // Very short TTL
        let cache = AgenticQueryCache::new(config);
        
        let cache_key = CacheKey::new(
            QueryType::EntityState,
            Uuid::new_v4(),
            "entity_123_current_state",
            None,
        );
        
        let result = "Entity is healthy".to_string();
        
        // Store result
        cache.store(cache_key.clone(), result.clone(), None).await.unwrap();
        
        // Should be retrievable immediately
        let retrieved = cache.get(&cache_key, None).await.unwrap();
        assert_eq!(retrieved, Some(result));
        
        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        
        // Should be expired now
        let expired = cache.get(&cache_key, None).await.unwrap();
        assert_eq!(expired, None);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let config = AgenticCacheConfig::default();
        let cache = AgenticQueryCache::new(config);
        
        let user_id = Uuid::new_v4();
        let entity_id = Uuid::new_v4();
        
        let cache_key = CacheKey::new(
            QueryType::EntityState,
            user_id,
            &format!("entity_{}_current_state", entity_id),
            None,
        );
        
        let result = "Entity is healthy".to_string();
        
        // Store result
        cache.store(cache_key.clone(), result.clone(), None).await.unwrap();
        
        // Should be retrievable
        let retrieved = cache.get(&cache_key, None).await.unwrap();
        assert_eq!(retrieved, Some(result));
        
        // Invalidate entity
        cache.invalidate_entity(user_id, entity_id).await.unwrap();
        
        // Should be gone now
        let invalidated = cache.get(&cache_key, None).await.unwrap();
        assert_eq!(invalidated, None);
    }

    #[tokio::test]
    async fn test_context_sensitivity() {
        let config = AgenticCacheConfig::default();
        let cache = AgenticQueryCache::new(config);
        
        let cache_key = CacheKey::new(
            QueryType::EntityState,
            Uuid::new_v4(),
            "entity_123_current_state",
            None,
        );
        
        let result = "Entity is healthy".to_string();
        let context1 = "in combat scenario";
        let context2 = "peaceful exploration";
        
        // Store with context1
        cache.store(cache_key.clone(), result.clone(), Some(context1)).await.unwrap();
        
        // Should retrieve with same context
        let retrieved1 = cache.get(&cache_key, Some(context1)).await.unwrap();
        assert_eq!(retrieved1, Some(result));
        
        // Should not retrieve with different context
        let retrieved2 = cache.get(&cache_key, Some(context2)).await.unwrap();
        assert_eq!(retrieved2, None);
    }
}