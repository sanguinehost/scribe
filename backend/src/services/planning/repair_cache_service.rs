// backend/src/services/planning/repair_cache_service.rs
//
// Repair Cache Service - Redis-based caching for repair analysis and plans
//
// This service provides high-performance caching for repair operations with:
// - User isolation for security
// - TTL management for cache invalidation
// - Content-addressed caching for efficiency
// - Separate caching for analysis and repair plans

use std::sync::Arc;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tracing::{info, debug, warn, instrument, error};
use redis::{AsyncCommands, RedisResult};

use crate::{
    errors::AppError,
    services::planning::types::*,
};

/// Configuration for repair caching behavior
#[derive(Debug, Clone)]
pub struct RepairCacheConfig {
    /// TTL for repair plans (seconds)
    pub repair_plan_ttl: u64,
    /// TTL for inconsistency analysis (seconds)
    pub analysis_ttl: u64,
    /// TTL for failed repairs (seconds) - shorter to allow retries
    pub failed_repair_ttl: u64,
    /// Maximum cache key length
    pub max_key_length: usize,
}

impl Default for RepairCacheConfig {
    fn default() -> Self {
        Self {
            repair_plan_ttl: 1800,      // 30 minutes for repair plans
            analysis_ttl: 3600,         // 60 minutes for analysis results
            failed_repair_ttl: 300,     // 5 minutes for failed repairs
            max_key_length: 200,        // Redis key length limit
        }
    }
}

/// Cached repair analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAnalysis {
    pub analysis: InconsistencyAnalysis,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub cache_key: String,
}

/// Cached repair plan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRepairPlan {
    pub plan: Plan,
    pub original_plan_hash: String,
    pub analysis_hash: String,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub cache_key: String,
}

/// Repair failure result for short-term negative caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRepairFailure {
    pub error_type: String,
    pub error_message: String,
    pub failed_at: chrono::DateTime<chrono::Utc>,
    pub retry_after: chrono::DateTime<chrono::Utc>,
}

/// Service for caching repair operations with Redis
pub struct RepairCacheService {
    redis_client: Arc<redis::Client>,
    config: RepairCacheConfig,
}

impl RepairCacheService {
    pub fn new(redis_client: Arc<redis::Client>) -> Self {
        Self {
            redis_client,
            config: RepairCacheConfig::default(),
        }
    }

    pub fn with_config(redis_client: Arc<redis::Client>, config: RepairCacheConfig) -> Self {
        Self {
            redis_client,
            config,
        }
    }

    /// Cache inconsistency analysis result
    #[instrument(skip(self, analysis))]
    pub async fn cache_analysis(
        &self,
        user_id: Uuid,
        failures: &[ValidationFailure],
        analysis: &InconsistencyAnalysis,
    ) -> Result<(), AppError> {
        let cache_key = self.build_analysis_cache_key(user_id, failures);
        
        let cached_analysis = CachedAnalysis {
            analysis: analysis.clone(),
            cached_at: chrono::Utc::now(),
            cache_key: cache_key.clone(),
        };

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let serialized = serde_json::to_string(&cached_analysis)
                    .map_err(|e| AppError::InternalServerErrorGeneric(
                        format!("Failed to serialize analysis for caching: {}", e)
                    ))?;

                let result: RedisResult<()> = conn.set_ex(
                    &cache_key,
                    serialized,
                    self.config.analysis_ttl
                ).await;

                match result {
                    Ok(_) => {
                        debug!("Cached analysis result with key: {}", cache_key);
                        Ok(())
                    },
                    Err(e) => {
                        warn!("Failed to cache analysis: {}", e);
                        // Don't fail the operation, just log the warning
                        Ok(())
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for analysis caching: {}", e);
                // Don't fail the operation, just log the warning
                Ok(())
            }
        }
    }

    /// Get cached inconsistency analysis result
    #[instrument(skip(self, failures))]
    pub async fn get_cached_analysis(
        &self,
        user_id: Uuid,
        failures: &[ValidationFailure],
    ) -> Result<Option<CachedAnalysis>, AppError> {
        let cache_key = self.build_analysis_cache_key(user_id, failures);

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let result: RedisResult<Option<String>> = conn.get(&cache_key).await;
                
                match result {
                    Ok(Some(cached_data)) => {
                        match serde_json::from_str::<CachedAnalysis>(&cached_data) {
                            Ok(cached_analysis) => {
                                debug!("Found cached analysis with key: {}", cache_key);
                                Ok(Some(cached_analysis))
                            },
                            Err(e) => {
                                warn!("Failed to deserialize cached analysis: {}", e);
                                // Delete corrupted cache entry
                                let _: RedisResult<()> = conn.del(&cache_key).await;
                                Ok(None)
                            }
                        }
                    },
                    Ok(None) => {
                        debug!("No cached analysis found for key: {}", cache_key);
                        Ok(None)
                    },
                    Err(e) => {
                        warn!("Redis error while fetching cached analysis: {}", e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for analysis retrieval: {}", e);
                Ok(None)
            }
        }
    }

    /// Cache repair plan result
    #[instrument(skip(self, repair_plan, original_plan, analysis))]
    pub async fn cache_repair_plan(
        &self,
        user_id: Uuid,
        repair_plan: &Plan,
        original_plan: &Plan,
        analysis: &InconsistencyAnalysis,
    ) -> Result<(), AppError> {
        let cache_key = self.build_repair_plan_cache_key(user_id, analysis, original_plan);
        
        let cached_repair = CachedRepairPlan {
            plan: repair_plan.clone(),
            original_plan_hash: self.hash_plan(original_plan),
            analysis_hash: self.hash_analysis(analysis),
            cached_at: chrono::Utc::now(),
            cache_key: cache_key.clone(),
        };

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let serialized = serde_json::to_string(&cached_repair)
                    .map_err(|e| AppError::InternalServerErrorGeneric(
                        format!("Failed to serialize repair plan for caching: {}", e)
                    ))?;

                let result: RedisResult<()> = conn.set_ex(
                    &cache_key,
                    serialized,
                    self.config.repair_plan_ttl
                ).await;

                match result {
                    Ok(_) => {
                        debug!("Cached repair plan with key: {}", cache_key);
                        Ok(())
                    },
                    Err(e) => {
                        warn!("Failed to cache repair plan: {}", e);
                        Ok(())
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for repair plan caching: {}", e);
                Ok(())
            }
        }
    }

    /// Get cached repair plan result
    #[instrument(skip(self, original_plan, analysis))]
    pub async fn get_cached_repair_plan(
        &self,
        user_id: Uuid,
        original_plan: &Plan,
        analysis: &InconsistencyAnalysis,
    ) -> Result<Option<CachedRepairPlan>, AppError> {
        let cache_key = self.build_repair_plan_cache_key(user_id, analysis, original_plan);

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let result: RedisResult<Option<String>> = conn.get(&cache_key).await;
                
                match result {
                    Ok(Some(cached_data)) => {
                        match serde_json::from_str::<CachedRepairPlan>(&cached_data) {
                            Ok(mut cached_repair) => {
                                // Verify cache validity by comparing hashes
                                let current_plan_hash = self.hash_plan(original_plan);
                                let current_analysis_hash = self.hash_analysis(analysis);
                                
                                if cached_repair.original_plan_hash == current_plan_hash &&
                                   cached_repair.analysis_hash == current_analysis_hash {
                                    debug!("Found valid cached repair plan with key: {}", cache_key);
                                    cached_repair.cache_key = cache_key;
                                    Ok(Some(cached_repair))
                                } else {
                                    debug!("Cached repair plan invalid due to hash mismatch, deleting");
                                    let _: RedisResult<()> = conn.del(&cache_key).await;
                                    Ok(None)
                                }
                            },
                            Err(e) => {
                                warn!("Failed to deserialize cached repair plan: {}", e);
                                let _: RedisResult<()> = conn.del(&cache_key).await;
                                Ok(None)
                            }
                        }
                    },
                    Ok(None) => {
                        debug!("No cached repair plan found for key: {}", cache_key);
                        Ok(None)
                    },
                    Err(e) => {
                        warn!("Redis error while fetching cached repair plan: {}", e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for repair plan retrieval: {}", e);
                Ok(None)
            }
        }
    }

    /// Cache repair failure for negative caching (avoid repeated failures)
    #[instrument(skip(self, error))]
    pub async fn cache_repair_failure(
        &self,
        user_id: Uuid,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        error: &AppError,
    ) -> Result<(), AppError> {
        let cache_key = format!("failure:{}", self.build_repair_plan_cache_key(user_id, analysis, original_plan));
        
        let cached_failure = CachedRepairFailure {
            error_type: "repair_generation_failed".to_string(),
            error_message: error.to_string(),
            failed_at: chrono::Utc::now(),
            retry_after: chrono::Utc::now() + chrono::Duration::seconds(self.config.failed_repair_ttl as i64),
        };

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let serialized = serde_json::to_string(&cached_failure)
                    .map_err(|e| AppError::InternalServerErrorGeneric(
                        format!("Failed to serialize repair failure for caching: {}", e)
                    ))?;

                let result: RedisResult<()> = conn.set_ex(
                    &cache_key,
                    serialized,
                    self.config.failed_repair_ttl
                ).await;

                match result {
                    Ok(_) => {
                        debug!("Cached repair failure with key: {}", cache_key);
                        Ok(())
                    },
                    Err(e) => {
                        warn!("Failed to cache repair failure: {}", e);
                        Ok(())
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for failure caching: {}", e);
                Ok(())
            }
        }
    }

    /// Check if repair recently failed (negative caching)
    #[instrument(skip(self, analysis, original_plan))]
    pub async fn is_repair_recently_failed(
        &self,
        user_id: Uuid,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
    ) -> Result<Option<CachedRepairFailure>, AppError> {
        let cache_key = format!("failure:{}", self.build_repair_plan_cache_key(user_id, analysis, original_plan));

        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let result: RedisResult<Option<String>> = conn.get(&cache_key).await;
                
                match result {
                    Ok(Some(cached_data)) => {
                        match serde_json::from_str::<CachedRepairFailure>(&cached_data) {
                            Ok(cached_failure) => {
                                if chrono::Utc::now() < cached_failure.retry_after {
                                    debug!("Found recent repair failure, avoiding retry until: {}", cached_failure.retry_after);
                                    Ok(Some(cached_failure))
                                } else {
                                    debug!("Repair failure cache expired, allowing retry");
                                    let _: RedisResult<()> = conn.del(&cache_key).await;
                                    Ok(None)
                                }
                            },
                            Err(e) => {
                                warn!("Failed to deserialize cached repair failure: {}", e);
                                let _: RedisResult<()> = conn.del(&cache_key).await;
                                Ok(None)
                            }
                        }
                    },
                    Ok(None) => Ok(None),
                    Err(e) => {
                        warn!("Redis error while checking repair failure cache: {}", e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                warn!("Failed to connect to Redis for failure check: {}", e);
                Ok(None)
            }
        }
    }

    /// Build cache key for inconsistency analysis results
    fn build_analysis_cache_key(&self, user_id: Uuid, failures: &[ValidationFailure]) -> String {
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        
        // Hash the failure details for content-addressed caching
        for failure in failures {
            failure.failure_type.hash(&mut hasher);
            failure.message.hash(&mut hasher);
        }
        
        let hash = hasher.finish();
        let key = format!("analysis:{}:{:x}", user_id, hash);
        
        // Truncate if too long
        if key.len() > self.config.max_key_length {
            key[..self.config.max_key_length].to_string()
        } else {
            key
        }
    }

    /// Build cache key for repair plan results
    fn build_repair_plan_cache_key(&self, user_id: Uuid, analysis: &InconsistencyAnalysis, original_plan: &Plan) -> String {
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        analysis.inconsistency_type.hash(&mut hasher);
        analysis.repair_reasoning.hash(&mut hasher);
        original_plan.goal.hash(&mut hasher);
        original_plan.actions.len().hash(&mut hasher);
        
        let hash = hasher.finish();
        let key = format!("repair:{}:{:x}", user_id, hash);
        
        // Truncate if too long
        if key.len() > self.config.max_key_length {
            key[..self.config.max_key_length].to_string()
        } else {
            key
        }
    }

    /// Generate hash for plan content
    fn hash_plan(&self, plan: &Plan) -> String {
        let mut hasher = DefaultHasher::new();
        plan.goal.hash(&mut hasher);
        plan.actions.len().hash(&mut hasher);
        // Hash action IDs and names for content verification
        for action in &plan.actions {
            action.id.hash(&mut hasher);
            action.name.hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }

    /// Generate hash for analysis content
    fn hash_analysis(&self, analysis: &InconsistencyAnalysis) -> String {
        let mut hasher = DefaultHasher::new();
        analysis.inconsistency_type.hash(&mut hasher);
        analysis.repair_reasoning.hash(&mut hasher);
        analysis.confidence_score.to_bits().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Clear all cached entries for a user (useful for testing or user data cleanup)
    #[instrument(skip(self))]
    pub async fn clear_user_cache(&self, user_id: Uuid) -> Result<(), AppError> {
        match self.redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                // Use pattern matching to find all keys for this user
                let patterns = [
                    format!("analysis:{}:*", user_id),
                    format!("repair:{}:*", user_id),
                    format!("failure:repair:{}:*", user_id),
                ];

                for pattern in &patterns {
                    let keys: RedisResult<Vec<String>> = conn.keys(pattern).await;
                    match keys {
                        Ok(keys_to_delete) => {
                            if !keys_to_delete.is_empty() {
                                let _: RedisResult<()> = conn.del(&keys_to_delete).await;
                                debug!("Deleted {} cached entries for pattern: {}", keys_to_delete.len(), pattern);
                            }
                        },
                        Err(e) => warn!("Failed to find keys for pattern {}: {}", pattern, e),
                    }
                }

                info!("Cleared repair cache for user: {}", user_id);
                Ok(())
            },
            Err(e) => {
                error!("Failed to connect to Redis for cache clearing: {}", e);
                Err(AppError::InternalServerErrorGeneric(
                    format!("Failed to clear user cache: {}", e)
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ecs_diesel::EcsEntity;
    use chrono::Utc;

    fn create_test_analysis() -> InconsistencyAnalysis {
        InconsistencyAnalysis {
            inconsistency_type: InconsistencyType::MissingMovement,
            narrative_evidence: vec!["Test evidence".to_string()],
            ecs_state_summary: "Test ECS state".to_string(),
            repair_reasoning: "Test entity needs to be moved".to_string(),
            confidence_score: 0.8,
            detection_timestamp: Utc::now(),
        }
    }

    fn create_test_plan() -> Plan {
        Plan {
            goal: "Test repair plan".to_string(),
            actions: vec![],
            metadata: PlanMetadata {
                estimated_duration: Some(30),
                confidence: 0.7,
                alternative_considered: None,
            },
        }
    }

    #[test]
    fn test_cache_key_generation() {
        let redis_client = Arc::new(redis::Client::open("redis://localhost").unwrap());
        let cache_service = RepairCacheService::new(redis_client);
        
        let user_id = Uuid::new_v4();
        let analysis = create_test_analysis();
        let plan = create_test_plan();

        let analysis_key = cache_service.build_analysis_cache_key(user_id, &[]);
        let repair_key = cache_service.build_repair_plan_cache_key(user_id, &analysis, &plan);

        assert!(analysis_key.starts_with(&format!("analysis:{}", user_id)));
        assert!(repair_key.starts_with(&format!("repair:{}", user_id)));
        assert!(analysis_key.len() <= cache_service.config.max_key_length);
        assert!(repair_key.len() <= cache_service.config.max_key_length);
    }

    #[test]
    fn test_plan_hash_consistency() {
        let redis_client = Arc::new(redis::Client::open("redis://localhost").unwrap());
        let cache_service = RepairCacheService::new(redis_client);
        
        let plan = create_test_plan();
        let hash1 = cache_service.hash_plan(&plan);
        let hash2 = cache_service.hash_plan(&plan);
        
        assert_eq!(hash1, hash2, "Plan hash should be consistent");
    }

    #[test]
    fn test_analysis_hash_consistency() {
        let redis_client = Arc::new(redis::Client::open("redis://localhost").unwrap());
        let cache_service = RepairCacheService::new(redis_client);
        
        let analysis = create_test_analysis();
        let hash1 = cache_service.hash_analysis(&analysis);
        let hash2 = cache_service.hash_analysis(&analysis);
        
        assert_eq!(hash1, hash2, "Analysis hash should be consistent");
    }
}