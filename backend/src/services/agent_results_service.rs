use chrono::{DateTime, Utc};
use diesel::prelude::*;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;
use serde_json;

use crate::{
    auth::session_dek::SessionDek,
    errors::AppError,
    models::{
        agent_results::{
            AgentResult, AgentResultQuery, AgentResultStatus, AgentType, 
            DecryptedAgentResult, NewAgentResult, OperationType,
        },
    },
    state::DbPool,
    services::EncryptionService,
};

// Re-export commonly used types for external access
// Note: These types are already imported above, no need to re-export
use std::sync::Arc;

/// Service for managing agent processing results with encryption
pub struct AgentResultsService {
    pool: DbPool,
    encryption_service: Arc<EncryptionService>,
}

impl AgentResultsService {
    pub fn new(pool: DbPool, encryption_service: Arc<EncryptionService>) -> Self {
        Self {
            pool,
            encryption_service,
        }
    }

    /// Store a new agent result with encryption
    #[instrument(
        name = "agent_results_service_store",
        skip(self, result_data, metadata, session_dek),
        fields(
            user_id = %user_id,
            session_id = %session_id,
            agent_type = agent_type.as_str(),
            operation_type = operation_type.as_str()
        )
    )]
    pub async fn store_agent_result(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        message_id: Option<Uuid>,
        agent_type: AgentType,
        operation_type: OperationType,
        result_data: serde_json::Value,
        metadata: Option<serde_json::Value>,
        processing_time_ms: i32,
        token_count: Option<i32>,
        confidence_score: Option<f32>,
        processing_phase: Option<String>,
        coordination_key: Option<String>,
        session_dek: &SessionDek,
    ) -> Result<Uuid, AppError> {
        debug!("Storing agent result for session: {}", session_id);

        // Serialize and encrypt the result data
        let result_json = serde_json::to_string(&result_data)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to serialize result: {}", e)))?;
        
        let (encrypted_result, result_nonce) = self.encryption_service
            .encrypt(&result_json, session_dek.expose_bytes())?;

        // Encrypt metadata if provided
        let (encrypted_metadata, metadata_nonce) = if let Some(meta) = metadata {
            let meta_json = serde_json::to_string(&meta)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to serialize metadata: {}", e)))?;
            let (enc_meta, nonce) = self.encryption_service
                .encrypt(&meta_json, session_dek.expose_bytes())?;
            (Some(enc_meta), Some(nonce))
        } else {
            (None, None)
        };

        let agent_type_str = agent_type.as_str().to_string();
        let operation_type_str = operation_type.as_str().to_string();

        let new_result = NewAgentResult {
            session_id,
            user_id,
            message_id,
            agent_type: agent_type.into(),
            operation_type: operation_type.into(),
            encrypted_result,
            result_nonce,
            encrypted_metadata,
            metadata_nonce,
            processing_time_ms,
            token_count,
            confidence_score,
            status: AgentResultStatus::Completed.into(),
            error_message: None,
            processing_phase,
            coordination_key,
        };

        let conn = self.pool.get().await?;
        let result: AgentResult = conn
            .interact(move |conn| {
                diesel::insert_into(crate::schema::agent_results::table)
                    .values(&new_result)
                    .get_result::<AgentResult>(conn)
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to interact with DB: {}", e)))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        info!(
            "Stored agent result {} for session {} (agent: {}, operation: {})",
            result.id, session_id, agent_type_str, operation_type_str
        );

        Ok(result.id)
    }

    /// Retrieve and decrypt agent results based on query parameters
    #[instrument(
        name = "agent_results_service_retrieve",
        skip(self, query, session_dek),
        fields(
            session_id = ?query.session_id,
            unretrieved_only = query.unretrieved_only
        )
    )]
    pub async fn retrieve_agent_results(
        &self,
        query: AgentResultQuery,
        session_dek: &SessionDek,
    ) -> Result<Vec<DecryptedAgentResult>, AppError> {
        use crate::schema::agent_results::dsl::*;
        
        let conn = self.pool.get().await?;
        
        let results: Vec<AgentResult> = conn
            .interact(move |conn| {
                // Build the query
                let mut db_query = agent_results.into_boxed();

                if let Some(sid) = query.session_id {
                    db_query = db_query.filter(session_id.eq(sid));
                }

                if let Some(uid) = query.user_id {
                    db_query = db_query.filter(user_id.eq(uid));
                }

                if let Some(types) = query.agent_types {
                    db_query = db_query.filter(agent_type.eq_any(types));
                }

                if let Some(ops) = query.operation_types {
                    db_query = db_query.filter(operation_type.eq_any(ops));
                }

                if query.unretrieved_only {
                    db_query = db_query.filter(retrieved_at.is_null());
                }

                if let Some(since) = query.since_timestamp {
                    db_query = db_query.filter(created_at.gt(since));
                }

                // Order by created_at descending
                db_query = db_query.order(created_at.desc());

                if let Some(limit_val) = query.limit {
                    db_query = db_query.limit(limit_val);
                }

                db_query.load(conn)
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to interact with DB: {}", e)))??;

        debug!("Retrieved {} agent results", results.len());

        // Decrypt results
        let mut decrypted_results = Vec::new();
        for result in results {
            match self.decrypt_agent_result(&result, session_dek) {
                Ok(decrypted) => decrypted_results.push(decrypted),
                Err(e) => {
                    error!("Failed to decrypt agent result {}: {}", result.id, e);
                    // Continue processing other results
                }
            }
        }

        Ok(decrypted_results)
    }

    /// Mark agent results as retrieved
    #[instrument(
        name = "agent_results_service_mark_retrieved",
        skip(self),
        fields(
            session_id = %session_id,
            user_id = %user_id
        )
    )]
    pub async fn mark_results_retrieved(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        cutoff_time: Option<DateTime<Utc>>,
    ) -> Result<usize, AppError> {
        use crate::schema::agent_results::dsl;

        let conn = self.pool.get().await?;
        let cutoff = cutoff_time.unwrap_or_else(Utc::now);

        let updated = conn
            .interact(move |conn| {
                diesel::update(
                    dsl::agent_results
                        .filter(dsl::session_id.eq(session_id))
                        .filter(dsl::user_id.eq(user_id))
                        .filter(dsl::retrieved_at.is_null())
                        .filter(dsl::created_at.le(cutoff))
                )
                .set(dsl::retrieved_at.eq(Utc::now()))
                .execute(conn)
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to interact with DB: {}", e)))??;

        debug!("Marked {} agent results as retrieved", updated);
        Ok(updated)
    }

    /// Query results specifically for Phase 3/4 coordination
    #[instrument(
        name = "agent_results_service_query_coordination",
        skip(self, session_dek),
        fields(
            session_id = %session_id,
            coordination_key_pattern = ?coordination_key_pattern
        )
    )]
    pub async fn query_coordination_results(
        &self,
        session_id: Uuid,
        coordination_key_pattern: Option<String>,
        session_dek: &SessionDek,
    ) -> Result<Vec<DecryptedAgentResult>, AppError> {
        use crate::schema::agent_results::dsl::*;

        let conn = self.pool.get().await?;
        
        let results: Vec<AgentResult> = conn
            .interact(move |conn| {
                let mut db_query = agent_results
                    .filter(session_id.eq(session_id))
                    .filter(coordination_key.is_not_null())
                    .into_boxed();

                if let Some(pattern) = coordination_key_pattern {
                    db_query = db_query.filter(coordination_key.like(format!("%{}%", pattern)));
                }

                db_query
                    .order(created_at.desc())
                    .load(conn)
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to interact with DB: {}", e)))??;

        let mut decrypted_results = Vec::new();
        for result in results {
            match self.decrypt_agent_result(&result, session_dek) {
                Ok(decrypted) => decrypted_results.push(decrypted),
                Err(e) => {
                    error!("Failed to decrypt coordination result {}: {}", result.id, e);
                }
            }
        }

        Ok(decrypted_results)
    }

    /// Decrypt a single agent result
    fn decrypt_agent_result(
        &self,
        result: &AgentResult,
        session_dek: &SessionDek,
    ) -> Result<DecryptedAgentResult, AppError> {
        // Decrypt result data
        let decrypted_result_bytes = self.encryption_service
            .decrypt(&result.encrypted_result, &result.result_nonce, session_dek.expose_bytes())?;
        let result_str = String::from_utf8(decrypted_result_bytes)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in result: {}", e)))?;
        let result_data: serde_json::Value = serde_json::from_str(&result_str)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid JSON in result: {}", e)))?;

        // Decrypt metadata if present
        let metadata = if let (Some(enc_meta), Some(nonce)) = (&result.encrypted_metadata, &result.metadata_nonce) {
            let decrypted_meta_bytes = self.encryption_service
                .decrypt(enc_meta, nonce, session_dek.expose_bytes())?;
            let meta_str = String::from_utf8(decrypted_meta_bytes)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in metadata: {}", e)))?;
            let meta_data: serde_json::Value = serde_json::from_str(&meta_str)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid JSON in metadata: {}", e)))?;
            Some(meta_data)
        } else {
            None
        };

        // Parse agent type
        let agent_type = match result.agent_type.as_str() {
            "perception" => AgentType::Perception,
            "tactical" => AgentType::Tactical,
            "strategic" => AgentType::Strategic,
            "orchestrator" => AgentType::Orchestrator,
            _ => return Err(AppError::InternalServerErrorGeneric(format!("Unknown agent type: {}", result.agent_type))),
        };

        // Parse operation type
        let operation_type = match result.operation_type.as_str() {
            "perception_analysis" => OperationType::PerceptionAnalysis,
            "entity_extraction" => OperationType::EntityExtraction,
            "spatial_analysis" => OperationType::SpatialAnalysis,
            "tactical_planning" => OperationType::TacticalPlanning,
            "action_execution" => OperationType::ActionExecution,
            "strategic_directive" => OperationType::StrategicDirective,
            "narrative_generation" => OperationType::NarrativeGeneration,
            "orchestrator_coordination" => OperationType::OrchestratorCoordination,
            other => OperationType::Other(other.to_string()),
        };

        Ok(DecryptedAgentResult {
            id: result.id,
            session_id: result.session_id,
            user_id: result.user_id,
            message_id: result.message_id,
            agent_type,
            operation_type,
            result: result_data,
            metadata,
            processing_time_ms: result.processing_time_ms,
            token_count: result.token_count,
            confidence_score: result.confidence_score,
            created_at: result.created_at,
            processing_phase: result.processing_phase.clone(),
        })
    }

    /// Clean up old agent results
    #[instrument(
        name = "agent_results_service_cleanup",
        skip(self),
        fields(
            older_than_days = older_than_days
        )
    )]
    pub async fn cleanup_old_results(
        &self,
        older_than_days: i64,
    ) -> Result<usize, AppError> {
        use crate::schema::agent_results::dsl::*;

        let cutoff_date = Utc::now() - chrono::Duration::days(older_than_days);
        let conn = self.pool.get().await?;

        let deleted = conn
            .interact(move |conn| {
                diesel::delete(
                    agent_results
                        .filter(created_at.lt(cutoff_date))
                        .filter(status.eq(AgentResultStatus::Completed.as_str()))
                )
                .execute(conn)
            })
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to interact with DB: {}", e)))??;

        info!("Cleaned up {} old agent results", deleted);
        Ok(deleted)
    }
}