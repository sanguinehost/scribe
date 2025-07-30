// backend/src/services/orchestrator/types.rs
//
// Orchestrator Type Definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid;
use crate::services::task_queue::EnrichmentTaskPayload;

/// Reasoning phases in the Orchestrator's decision loop
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasoningPhase {
    Perceive,
    Strategize,
    Plan,
    Execute,
    Reflect,
}

impl std::fmt::Display for ReasoningPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReasoningPhase::Perceive => write!(f, "Perceive"),
            ReasoningPhase::Strategize => write!(f, "Strategize"),
            ReasoningPhase::Plan => write!(f, "Plan"),
            ReasoningPhase::Execute => write!(f, "Execute"),
            ReasoningPhase::Reflect => write!(f, "Reflect"),
        }
    }
}

/// Context passed through reasoning phases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningContext {
    pub task_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub is_first_message: bool,
    pub cached_world_state: Option<JsonValue>,
    pub phase_history: Vec<ReasoningPhase>,
    pub metadata: HashMap<String, JsonValue>,
    pub chronicle_id: Option<Uuid>,
}

/// Result from Perceive phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionResult {
    pub entities_extracted: Vec<String>,
    pub locations_identified: Vec<String>,
    pub temporal_context: Option<String>,
    pub narrative_significance: f32,
    pub world_state_delta: Option<JsonValue>,
}

/// Result from Strategize phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyResult {
    pub primary_goals: Vec<String>,
    pub narrative_threads: Vec<String>,
    pub world_state_implications: JsonValue,
    pub alternative_paths: Option<Vec<String>>,
}

/// Result from Plan phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResult {
    pub action_steps: Vec<JsonValue>,
    pub dependency_graph: Option<JsonValue>,
    pub tool_selections: HashMap<String, String>,
    pub cache_optimization_hints: Option<Vec<String>>,
}

/// Result from Execute phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub executed_actions: Vec<JsonValue>,
    pub world_state_changes: JsonValue,
    pub cache_updates: Option<Vec<String>>,
    pub errors: Vec<String>,
}

/// Result from Reflect phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionResult {
    pub goals_completed: Vec<String>,
    pub goals_remaining: Vec<String>,
    pub replan_needed: bool,
    pub cache_layers_updated: Vec<String>,
    pub performance_metrics: PerformanceMetrics,
}

/// Performance metrics tracked during reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_duration_ms: u64,
    pub phase_durations: HashMap<ReasoningPhase, u64>,
    pub cache_hits: u32,
    pub cache_misses: u32,
    pub tool_calls: u32,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            total_duration_ms: 0,
            phase_durations: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
            tool_calls: 0,
        }
    }
}

/// Full reasoning loop result
#[derive(Debug, Serialize, Deserialize)]
pub struct ReasoningLoopResult {
    pub task_id: Uuid,
    pub phases_completed: Vec<ReasoningPhase>,
    pub world_enrichment_complete: bool,
    pub total_duration_ms: u64,
    pub replan_count: u32,
    pub alternative_paths_explored: Option<Vec<String>>,
    pub cache_layers_populated: Vec<String>,
    pub cache_hits: u32,
    pub processing_time_saved_ms: u64,
}

/// Task context for observers
#[derive(Debug, Clone)]
pub struct TaskContext {
    pub task_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub payload: EnrichmentTaskPayload,
    pub status: String,
    pub created_at: DateTime<Utc>,
}