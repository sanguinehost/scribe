use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::agent_results;

/// Database model for storing encrypted agent processing results
#[derive(Debug, Clone, Queryable, Insertable, Selectable)]
#[diesel(table_name = agent_results)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AgentResult {
    pub id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub message_id: Option<Uuid>,
    pub agent_type: String,
    pub operation_type: String,
    pub encrypted_result: Vec<u8>,
    pub result_nonce: Vec<u8>,
    pub encrypted_metadata: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub processing_time_ms: i32,
    pub token_count: Option<i32>,
    pub confidence_score: Option<f32>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub retrieved_at: Option<DateTime<Utc>>,
    pub processing_phase: Option<String>,
    pub coordination_key: Option<String>,
}

/// Insertable struct for creating new agent results
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = agent_results)]
pub struct NewAgentResult {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub message_id: Option<Uuid>,
    pub agent_type: String,
    pub operation_type: String,
    pub encrypted_result: Vec<u8>,
    pub result_nonce: Vec<u8>,
    pub encrypted_metadata: Option<Vec<u8>>,
    pub metadata_nonce: Option<Vec<u8>>,
    pub processing_time_ms: i32,
    pub token_count: Option<i32>,
    pub confidence_score: Option<f32>,
    pub status: String,
    pub error_message: Option<String>,
    pub processing_phase: Option<String>,
    pub coordination_key: Option<String>,
}

/// Agent types enum
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AgentType {
    Perception,
    Tactical,
    Strategic,
    Orchestrator,
}

impl AgentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentType::Perception => "perception",
            AgentType::Tactical => "tactical",
            AgentType::Strategic => "strategic",
            AgentType::Orchestrator => "orchestrator",
        }
    }
}

impl From<AgentType> for String {
    fn from(agent_type: AgentType) -> Self {
        agent_type.as_str().to_string()
    }
}

/// Operation types for different agent operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OperationType {
    PerceptionAnalysis,
    EntityExtraction,
    SpatialAnalysis,
    TacticalPlanning,
    ActionExecution,
    StrategicDirective,
    NarrativeGeneration,
    OrchestratorCoordination,
    Other(String),
}

impl OperationType {
    pub fn as_str(&self) -> &str {
        match self {
            OperationType::PerceptionAnalysis => "perception_analysis",
            OperationType::EntityExtraction => "entity_extraction",
            OperationType::SpatialAnalysis => "spatial_analysis",
            OperationType::TacticalPlanning => "tactical_planning",
            OperationType::ActionExecution => "action_execution",
            OperationType::StrategicDirective => "strategic_directive",
            OperationType::NarrativeGeneration => "narrative_generation",
            OperationType::OrchestratorCoordination => "orchestrator_coordination",
            OperationType::Other(s) => s,
        }
    }
}

impl From<OperationType> for String {
    fn from(op_type: OperationType) -> Self {
        op_type.as_str().to_string()
    }
}

/// Status of agent result processing
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AgentResultStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl AgentResultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentResultStatus::Pending => "pending",
            AgentResultStatus::Processing => "processing",
            AgentResultStatus::Completed => "completed",
            AgentResultStatus::Failed => "failed",
        }
    }
}

impl From<AgentResultStatus> for String {
    fn from(status: AgentResultStatus) -> Self {
        status.as_str().to_string()
    }
}

/// Decrypted agent result for application use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedAgentResult {
    pub id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub message_id: Option<Uuid>,
    pub agent_type: AgentType,
    pub operation_type: OperationType,
    pub result: serde_json::Value,
    pub metadata: Option<serde_json::Value>,
    pub processing_time_ms: i32,
    pub token_count: Option<i32>,
    pub confidence_score: Option<f32>,
    pub created_at: DateTime<Utc>,
    pub processing_phase: Option<String>,
}

/// Query parameters for retrieving agent results
#[derive(Debug, Clone, Default)]
pub struct AgentResultQuery {
    pub session_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub agent_types: Option<Vec<String>>,
    pub operation_types: Option<Vec<String>>,
    pub unretrieved_only: bool,
    pub since_timestamp: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}