use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, debug, warn, instrument};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;

use crate::{
    errors::AppError,
    auth::session_dek::SessionDek,
    crypto,
};

/// Shared context mechanism for coordination between perception, tactical, and strategic agents.
/// This provides a centralized way for agents to share information, insights, and coordination data.
/// 
/// ## Security:
/// - All operations require SessionDek for encrypted data access
/// - User isolation enforced through user_id scoping
/// - TTL-based expiration prevents stale data accumulation
/// - Comprehensive logging for security auditing
#[derive(Clone)]
pub struct SharedAgentContext {
    redis_client: Arc<redis::Client>,
}

/// Types of context information that can be shared between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextType {
    /// Entities discovered/created by perception agent
    EntityDiscovery,
    /// Strategic insights from strategic agent analysis
    StrategicInsight,
    /// Tactical planning decisions and validation results
    TacticalPlanning,
    /// Cross-agent coordination signals
    Coordination,
    /// Performance metrics and timing data
    Performance,
}

/// A piece of shared context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntry {
    pub context_type: ContextType,
    pub source_agent: AgentType,
    pub timestamp: DateTime<Utc>,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub key: String,
    pub data: Value,
    pub ttl_seconds: Option<u64>,
    pub metadata: HashMap<String, Value>,
}

/// Encrypted context entry for storage (sensitive fields encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedContextEntry {
    pub context_type: ContextType,
    pub source_agent: AgentType,
    pub timestamp: DateTime<Utc>,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub key: String,
    pub encrypted_data: Vec<u8>,
    pub data_nonce: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub metadata_nonce: Vec<u8>,
    pub ttl_seconds: Option<u64>,
}

/// Agent types for source tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AgentType {
    Perception,
    Tactical,
    Strategic,
    Lightning,
    Orchestrator,
    HierarchicalPipeline,
    Chronicler,
}

/// Context query filters for retrieving specific context
#[derive(Debug, Clone)]
pub struct ContextQuery {
    pub context_types: Option<Vec<ContextType>>,
    pub source_agents: Option<Vec<AgentType>>,
    pub session_id: Option<Uuid>,
    pub since_timestamp: Option<DateTime<Utc>>,
    pub keys: Option<Vec<String>>,
    pub limit: Option<usize>,
}

impl SharedAgentContext {
    /// Create a new SharedAgentContext instance
    pub fn new(redis_client: Arc<redis::Client>) -> Self {
        Self {
            redis_client,
        }
    }

    /// Store context information that can be shared between agents
    /// All sensitive data is encrypted using the session DEK before storage
    #[instrument(
        name = "shared_context_store",
        skip(self, entry, session_dek),
        fields(
            context_type = ?entry.context_type,
            source_agent = ?entry.source_agent,
            user_id = %entry.user_id,
            session_id = %entry.session_id,
            key = %entry.key
        )
    )]
    pub async fn store_context(&self, entry: ContextEntry, session_dek: &SessionDek) -> Result<(), AppError> {
        let context_key = format!(
            "agent_context:{}:{}:{}:{}",
            entry.user_id,
            entry.session_id,
            serde_json::to_string(&entry.context_type).unwrap_or_default(),
            entry.key
        );
        
        // Encrypt the sensitive data field before storage
        let data_bytes = serde_json::to_vec(&entry.data)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to serialize context data: {}", e)
            ))?;
        
        let (encrypted_data, data_nonce) = crypto::encrypt_gcm(&data_bytes, &session_dek.0)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to encrypt context data: {}", e)
            ))?;
        
        // Encrypt metadata if it contains sensitive information
        let metadata_bytes = serde_json::to_vec(&entry.metadata)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to serialize context metadata: {}", e)
            ))?;
        
        let (encrypted_metadata, metadata_nonce) = crypto::encrypt_gcm(&metadata_bytes, &session_dek.0)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to encrypt context metadata: {}", e)
            ))?;
        
        // Create encrypted context entry (non-sensitive fields remain plaintext for querying)
        let encrypted_entry = EncryptedContextEntry {
            context_type: entry.context_type,
            source_agent: entry.source_agent,
            timestamp: entry.timestamp,
            session_id: entry.session_id,
            user_id: entry.user_id,
            key: entry.key,
            encrypted_data,
            data_nonce,
            encrypted_metadata,
            metadata_nonce,
            ttl_seconds: entry.ttl_seconds,
        };
        
        let serialized_entry = serde_json::to_string(&encrypted_entry)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to serialize encrypted context entry: {}", e)
            ))?;

        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            use redis::AsyncCommands;
            
            // Store the encrypted context entry
            let _: Result<(), _> = conn.set(&context_key, &serialized_entry).await;
            
            // Set TTL if specified, otherwise default to 24 hours
            let ttl = encrypted_entry.ttl_seconds.unwrap_or(86400);
            let _: Result<(), _> = conn.expire(&context_key, ttl as i64).await;
            
            // Add to agent's context index for efficient querying
            let agent_index_key = format!(
                "agent_index:{}:{}:{}",
                encrypted_entry.user_id,
                encrypted_entry.session_id,
                serde_json::to_string(&encrypted_entry.source_agent).unwrap_or_default()
            );
            let _: Result<(), _> = conn.sadd(&agent_index_key, &context_key).await;
            let _: Result<(), _> = conn.expire(&agent_index_key, ttl as i64).await;
            
            debug!(
                "Stored encrypted context entry: {} -> {} (TTL: {}s)",
                context_key, encrypted_entry.key, ttl
            );
        } else {
            warn!("Failed to get Redis connection for storing context");
            return Err(AppError::InternalServerErrorGeneric(
                "Failed to connect to Redis for context storage".to_string()
            ));
        }

        Ok(())
    }

    /// Retrieve context information based on query filters
    /// Decrypts sensitive data using the session DEK before returning
    #[instrument(
        name = "shared_context_query",
        skip(self, query, session_dek),
        fields(
            user_id = %user_id,
            session_id = ?query.session_id,
            limit = ?query.limit
        )
    )]
    pub async fn query_context(
        &self,
        user_id: Uuid,
        query: ContextQuery,
        session_dek: &SessionDek,
    ) -> Result<Vec<ContextEntry>, AppError> {
        let mut results = Vec::new();
        
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            use redis::AsyncCommands;
            
            // Build search pattern based on query
            let session_pattern = if let Some(session_id) = query.session_id {
                session_id.to_string()
            } else {
                "*".to_string()
            };
            
            let context_type_patterns = if let Some(types) = &query.context_types {
                types.iter()
                    .map(|t| serde_json::to_string(t).unwrap_or_default())
                    .collect::<Vec<_>>()
            } else {
                vec!["*".to_string()]
            };
            
            // Search for matching context keys
            for context_type_pattern in context_type_patterns {
                let pattern = format!(
                    "agent_context:{}:{}:{}:*",
                    user_id, session_pattern, context_type_pattern
                );
                
                if let Ok(keys) = conn.keys::<_, Vec<String>>(&pattern).await {
                    for key in keys {
                        if let Ok(Some(data)) = conn.get::<_, Option<String>>(&key).await {
                            match serde_json::from_str::<EncryptedContextEntry>(&data) {
                                Ok(encrypted_entry) => {
                                    // Decrypt the data and metadata
                                    let decrypted_data_secret = crypto::decrypt_gcm(
                                        &encrypted_entry.encrypted_data,
                                        &encrypted_entry.data_nonce,
                                        &session_dek.0
                                    ).map_err(|e| AppError::InternalServerErrorGeneric(
                                        format!("Failed to decrypt context data: {}", e)
                                    ))?;
                                    
                                    let data: Value = serde_json::from_slice(decrypted_data_secret.expose_secret())
                                        .map_err(|e| AppError::InternalServerErrorGeneric(
                                            format!("Failed to deserialize decrypted data: {}", e)
                                        ))?;
                                    
                                    let decrypted_metadata_secret = crypto::decrypt_gcm(
                                        &encrypted_entry.encrypted_metadata,
                                        &encrypted_entry.metadata_nonce,
                                        &session_dek.0
                                    ).map_err(|e| AppError::InternalServerErrorGeneric(
                                        format!("Failed to decrypt context metadata: {}", e)
                                    ))?;
                                    
                                    let metadata: HashMap<String, Value> = serde_json::from_slice(decrypted_metadata_secret.expose_secret())
                                        .map_err(|e| AppError::InternalServerErrorGeneric(
                                            format!("Failed to deserialize decrypted metadata: {}", e)
                                        ))?;
                                    
                                    // Reconstruct decrypted context entry
                                    let entry = ContextEntry {
                                        context_type: encrypted_entry.context_type,
                                        source_agent: encrypted_entry.source_agent,
                                        timestamp: encrypted_entry.timestamp,
                                        session_id: encrypted_entry.session_id,
                                        user_id: encrypted_entry.user_id,
                                        key: encrypted_entry.key,
                                        data,
                                        ttl_seconds: encrypted_entry.ttl_seconds,
                                        metadata,
                                    };
                                    
                                    // Apply additional filters
                                    if let Some(since) = query.since_timestamp {
                                        if entry.timestamp < since {
                                            continue;
                                        }
                                    }
                                    
                                    if let Some(agents) = &query.source_agents {
                                        if !agents.iter().any(|a| std::mem::discriminant(a) == std::mem::discriminant(&entry.source_agent)) {
                                            continue;
                                        }
                                    }
                                    
                                    if let Some(keys) = &query.keys {
                                        if !keys.contains(&entry.key) {
                                            continue;
                                        }
                                    }
                                    
                                    results.push(entry);
                                },
                                Err(e) => {
                                    warn!("Failed to deserialize encrypted context entry from key {}: {}", key, e);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            warn!("Failed to get Redis connection for querying context");
            return Err(AppError::InternalServerErrorGeneric(
                "Failed to connect to Redis for context query".to_string()
            ));
        }
        
        // Sort by timestamp (newest first) and apply limit
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        
        debug!("Context query returned {} entries", results.len());
        Ok(results)
    }

    /// Get recent entity discoveries from perception agent for a session
    pub async fn get_recent_entity_discoveries(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        limit: Option<usize>,
        session_dek: &SessionDek,
    ) -> Result<Vec<ContextEntry>, AppError> {
        let query = ContextQuery {
            context_types: Some(vec![ContextType::EntityDiscovery]),
            source_agents: Some(vec![AgentType::Perception]),
            session_id: Some(session_id),
            since_timestamp: None,
            keys: None,
            limit,
        };
        
        self.query_context(user_id, query, session_dek).await
    }

    /// Get strategic insights that tactical agent can use for planning
    pub async fn get_strategic_insights(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        limit: Option<usize>,
        session_dek: &SessionDek,
    ) -> Result<Vec<ContextEntry>, AppError> {
        let query = ContextQuery {
            context_types: Some(vec![ContextType::StrategicInsight]),
            source_agents: Some(vec![AgentType::Strategic]),
            session_id: Some(session_id),
            since_timestamp: None,
            keys: None,
            limit,
        };
        
        self.query_context(user_id, query, session_dek).await
    }

    /// Get tactical planning decisions that strategic agent can use for feedback
    pub async fn get_tactical_planning_history(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        limit: Option<usize>,
        session_dek: &SessionDek,
    ) -> Result<Vec<ContextEntry>, AppError> {
        let query = ContextQuery {
            context_types: Some(vec![ContextType::TacticalPlanning]),
            source_agents: Some(vec![AgentType::Tactical]),
            session_id: Some(session_id),
            since_timestamp: None,
            keys: None,
            limit,
        };
        
        self.query_context(user_id, query, session_dek).await
    }

    /// Store entity discovery information from perception agent
    pub async fn store_entity_discovery(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        entities: &[Value],
        context: Option<String>,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let entry = ContextEntry {
            context_type: ContextType::EntityDiscovery,
            source_agent: AgentType::Perception,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key: format!("entities_{}", Utc::now().timestamp()),
            data: json!({
                "entities": entities,
                "count": entities.len(),
                "context": context
            }),
            ttl_seconds: Some(86400), // 24 hours
            metadata: HashMap::new(),
        };
        
        self.store_context(entry, session_dek).await
    }

    /// Store strategic insight from strategic agent
    pub async fn store_strategic_insight(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        insight_key: String,
        insight_data: Value,
        metadata: Option<HashMap<String, Value>>,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let entry = ContextEntry {
            context_type: ContextType::StrategicInsight,
            source_agent: AgentType::Strategic,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key: insight_key,
            data: insight_data,
            ttl_seconds: Some(172800), // 48 hours for strategic insights
            metadata: metadata.unwrap_or_default(),
        };
        
        self.store_context(entry, session_dek).await
    }

    /// Store tactical planning decision
    pub async fn store_tactical_planning(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        planning_key: String,
        planning_data: Value,
        metadata: Option<HashMap<String, Value>>,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let entry = ContextEntry {
            context_type: ContextType::TacticalPlanning,
            source_agent: AgentType::Tactical,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key: planning_key,
            data: planning_data,
            ttl_seconds: Some(86400), // 24 hours
            metadata: metadata.unwrap_or_default(),
        };
        
        self.store_context(entry, session_dek).await
    }

    /// Store coordination signal between agents
    pub async fn store_coordination_signal(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        source_agent: AgentType,
        signal_key: String,
        signal_data: Value,
        ttl_seconds: Option<u64>,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let entry = ContextEntry {
            context_type: ContextType::Coordination,
            source_agent,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key: signal_key,
            data: signal_data,
            ttl_seconds: ttl_seconds.or(Some(3600)), // Default 1 hour for coordination
            metadata: HashMap::new(),
        };
        
        self.store_context(entry, session_dek).await
    }

    /// Store performance metrics for agent coordination optimization
    pub async fn store_performance_metrics(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        source_agent: AgentType,
        metrics: Value,
        session_dek: &SessionDek,
    ) -> Result<(), AppError> {
        let key = format!("metrics_{}_{:?}", Utc::now().timestamp(), source_agent);
        let entry = ContextEntry {
            context_type: ContextType::Performance,
            source_agent,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key,
            data: metrics,
            ttl_seconds: Some(604800), // 7 days for performance data
            metadata: HashMap::new(),
        };
        
        self.store_context(entry, session_dek).await
    }

    /// Clear old context data for a session (useful for cleanup)
    pub async fn cleanup_session_context(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        older_than_hours: u64,
    ) -> Result<usize, AppError> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(older_than_hours as i64);
        let mut deleted_count = 0;
        
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            use redis::AsyncCommands;
            
            // Find all context keys for this session
            let pattern = format!("agent_context:{}:{}:*", user_id, session_id);
            if let Ok(keys) = conn.keys::<_, Vec<String>>(&pattern).await {
                for key in keys {
                    if let Ok(Some(data)) = conn.get::<_, Option<String>>(&key).await {
                        if let Ok(encrypted_entry) = serde_json::from_str::<EncryptedContextEntry>(&data) {
                            if encrypted_entry.timestamp < cutoff_time {
                                let _: Result<(), _> = conn.del(&key).await;
                                deleted_count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        info!("Cleaned up {} old context entries for session {}", deleted_count, session_id);
        Ok(deleted_count)
    }
}

/// Helper trait to add shared context capabilities to agents
pub trait AgentWithSharedContext {
    fn get_shared_context(&self) -> &SharedAgentContext;
    
    /// Store discovery made by this agent
    async fn share_discovery(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        key: String,
        data: Value,
    ) -> Result<(), AppError>;
    
    /// Get discoveries from other agents
    async fn get_shared_discoveries(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        from_agents: Option<Vec<AgentType>>,
        limit: Option<usize>,
    ) -> Result<Vec<ContextEntry>, AppError>;
}