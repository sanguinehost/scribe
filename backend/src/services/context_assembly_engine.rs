use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use tracing::{info, debug, instrument};

use crate::{
    errors::AppError,
    PgPool,
    services::{
        query_strategy_planner::{QueryExecutionPlan, PlannedQuery, PlannedQueryType, QueryStrategy},
        hybrid_query_service::HybridQueryService,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssembledContext {
    pub strategy_used: QueryStrategy,
    pub results: Vec<QueryExecutionResult>,
    pub total_tokens_used: u32,
    pub execution_time_ms: u64,
    pub success_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryExecutionResult {
    EntityEvents(EntityEventsResult),
    SpatialEntities(SpatialEntitiesResult),
    EntityRelationships(EntityRelationshipsResult),
    CausalChain(CausalChainResult),
    TimelineEvents(TimelineEventsResult),
    EntityCurrentState(EntityCurrentStateResult),
    EntityStates(EntityStatesResult),
    SharedEvents(SharedEventsResult),
    CausalFactors(CausalFactorsResult),
    StateTransitions(StateTransitionsResult),
    RecentEvents(RecentEventsResult),
    HistoricalParallels(HistoricalParallelsResult),
    ActiveEntities(ActiveEntitiesResult),
    NarrativeThreads(NarrativeThreadsResult),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEventsResult {
    pub entities: HashMap<String, Vec<EventSummary>>,
    pub time_scope: String,
    pub total_events: usize,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialEntitiesResult {
    pub location_name: String,
    pub entities: Vec<EntitySummary>,
    pub include_contained: bool,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationshipsResult {
    pub entity_names: Vec<String>,
    pub relationships: Vec<RelationshipSummary>,
    pub max_depth: u32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChainResult {
    pub from_entity: String,
    pub causality_type: String,
    pub causal_chain: Vec<CausalLink>,
    pub max_depth: u32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEventsResult {
    pub entity_names: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub event_categories: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCurrentStateResult {
    pub entity_names: Vec<String>,
    pub current_states: HashMap<String, EntityState>,
    pub state_aspects: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStatesResult {
    pub entities: Vec<EntityState>,
    pub scope: String,
    pub state_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedEventsResult {
    pub entity_names: Vec<String>,
    pub shared_events: Vec<SharedEventSummary>,
    pub event_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalFactorsResult {
    pub scenario: String,
    pub entity: String,
    pub factors: Vec<CausalFactor>,
    pub factor_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionsResult {
    pub entity: String,
    pub transitions: Vec<StateTransition>,
    pub transition_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEventsResult {
    pub time_scope: String,
    pub events: Vec<EventSummary>,
    pub event_types: Vec<String>,
    pub max_events: u32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalParallelsResult {
    pub scenario_type: String,
    pub parallels: Vec<HistoricalParallel>,
    pub outcome_focus: bool,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveEntitiesResult {
    pub entities: Vec<EntitySummary>,
    pub activity_threshold: f32,
    pub include_positions: bool,
    pub include_states: bool,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeThreadsResult {
    pub threads: Vec<NarrativeThread>,
    pub thread_types: Vec<String>,
    pub status: String,
    pub max_threads: u32,
    pub tokens_used: u32,
}

// Supporting types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub event_id: Uuid,
    pub summary: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_id: Uuid,
    pub name: String,
    pub entity_type: String,
    pub current_location: Option<String>,
    pub activity_level: f32,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSummary {
    pub from_entity: String,
    pub to_entity: String,
    pub relationship_type: String,
    pub strength: f32,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalLink {
    pub cause_event: String,
    pub effect_event: String,
    pub causal_strength: f32,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_summary: String,
    pub entities_involved: Vec<String>,
    pub category: String,
    pub impact_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    pub entity_name: String,
    pub state_data: HashMap<String, serde_json::Value>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedEventSummary {
    pub event_summary: String,
    pub entities_involved: Vec<String>,
    pub event_type: String,
    pub impact_level: f32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalFactor {
    pub factor_name: String,
    pub factor_type: String,
    pub influence_strength: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub transition_time: chrono::DateTime<chrono::Utc>,
    pub trigger_event: Option<String>,
    pub transition_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalParallel {
    pub scenario_description: String,
    pub outcome: String,
    pub similarity_score: f32,
    pub lessons_learned: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeThread {
    pub thread_id: String,
    pub thread_type: String,
    pub description: String,
    pub entities_involved: Vec<String>,
    pub current_status: String,
    pub intensity: f32,
}

pub struct ContextAssemblyEngine {
    hybrid_query_service: Arc<HybridQueryService>,
    db_pool: Arc<PgPool>,
}

impl ContextAssemblyEngine {
    pub fn new(
        hybrid_query_service: Arc<HybridQueryService>,
        db_pool: Arc<PgPool>,
    ) -> Self {
        Self {
            hybrid_query_service,
            db_pool,
        }
    }

    #[instrument(skip(self), fields(num_queries = plan.queries.len(), strategy = ?plan.primary_strategy))]
    pub async fn execute_plan(
        &self,
        plan: &QueryExecutionPlan,
        user_id: Uuid,
    ) -> Result<AssembledContext, AppError> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        let mut total_tokens = 0u32;
        let mut successful_queries = 0;

        info!("Executing query plan with {} queries", plan.queries.len());

        // Execute queries in dependency order
        for query_type_name in &plan.execution_order {
            if let Some(query) = plan.queries.iter().find(|q| {
                format!("{:?}", q.query_type) == *query_type_name
            }) {
                match self.execute_query(query, user_id).await {
                    Ok(result) => {
                        total_tokens += self.get_result_tokens(&result);
                        results.push(result);
                        successful_queries += 1;
                    }
                    Err(e) => {
                        debug!("Query {:?} failed: {}", query.query_type, e);
                        // Continue with other queries but track the failure
                    }
                }

                // Check if we're approaching token budget
                if total_tokens >= plan.context_budget {
                    info!("Approaching token budget, stopping execution");
                    break;
                }
            }
        }

        let execution_time = start_time.elapsed().as_millis() as u64;
        let success_rate = if plan.queries.is_empty() {
            0.0
        } else {
            successful_queries as f32 / plan.queries.len() as f32
        };

        Ok(AssembledContext {
            strategy_used: plan.primary_strategy.clone(),
            results,
            total_tokens_used: total_tokens,
            execution_time_ms: execution_time,
            success_rate,
        })
    }

    #[instrument(skip(self), fields(query_type = ?query.query_type, priority = query.priority))]
    pub async fn execute_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        debug!("Executing query: {:?}", query.query_type);

        match query.query_type {
            PlannedQueryType::EntityEvents => {
                self.execute_entity_events_query(query, user_id).await
            }
            PlannedQueryType::SpatialEntities => {
                self.execute_spatial_entities_query(query, user_id).await
            }
            PlannedQueryType::EntityRelationships => {
                self.execute_entity_relationships_query(query, user_id).await
            }
            PlannedQueryType::CausalChain => {
                self.execute_causal_chain_query(query, user_id).await
            }
            PlannedQueryType::TimelineEvents => {
                self.execute_timeline_events_query(query, user_id).await
            }
            PlannedQueryType::EntityCurrentState => {
                self.execute_entity_current_state_query(query, user_id).await
            }
            PlannedQueryType::EntityStates => {
                self.execute_entity_states_query(query, user_id).await
            }
            PlannedQueryType::SharedEvents => {
                self.execute_shared_events_query(query, user_id).await
            }
            PlannedQueryType::CausalFactors => {
                self.execute_causal_factors_query(query, user_id).await
            }
            PlannedQueryType::StateTransitions => {
                self.execute_state_transitions_query(query, user_id).await
            }
            PlannedQueryType::RecentEvents => {
                self.execute_recent_events_query(query, user_id).await
            }
            PlannedQueryType::HistoricalParallels => {
                self.execute_historical_parallels_query(query, user_id).await
            }
            PlannedQueryType::ActiveEntities => {
                self.execute_active_entities_query(query, user_id).await
            }
            PlannedQueryType::NarrativeThreads => {
                self.execute_narrative_threads_query(query, user_id).await
            }
        }
    }

    async fn execute_entity_events_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity_names = query.parameters.get("entity_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| AppError::SerializationError("Missing entity_names parameter".to_string()))?;

        let time_scope = query.parameters.get("time_scope")
            .and_then(|v| v.as_str())
            .unwrap_or("Recent")
            .to_string();

        let max_events = query.parameters.get("max_events")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        // For now, return a mock result structure
        // In real implementation, this would query the hybrid service
        let mut entities = HashMap::new();
        for entity_name in entity_names {
            entities.insert(entity_name, Vec::new()); // Empty events for now
        }

        Ok(QueryExecutionResult::EntityEvents(EntityEventsResult {
            entities,
            time_scope,
            total_events: 0,
            tokens_used: query.estimated_tokens.unwrap_or(500),
        }))
    }

    async fn execute_spatial_entities_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let location_name = query.parameters.get("location_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("Missing location_name parameter".to_string()))?
            .to_string();

        let include_contained = query.parameters.get("include_contained")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(QueryExecutionResult::SpatialEntities(SpatialEntitiesResult {
            location_name,
            entities: Vec::new(), // Empty for now
            include_contained,
            tokens_used: query.estimated_tokens.unwrap_or(400),
        }))
    }

    async fn execute_entity_relationships_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity_names = query.parameters.get("entity_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| AppError::SerializationError("Missing entity_names parameter".to_string()))?;

        let max_depth = query.parameters.get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(2) as u32;

        Ok(QueryExecutionResult::EntityRelationships(EntityRelationshipsResult {
            entity_names,
            relationships: Vec::new(), // Empty for now
            max_depth,
            tokens_used: query.estimated_tokens.unwrap_or(600),
        }))
    }

    async fn execute_causal_chain_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let from_entity = query.parameters.get("from_entity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("Missing from_entity parameter".to_string()))?
            .to_string();

        let causality_type = query.parameters.get("causality_type")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();

        let max_depth = query.parameters.get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as u32;

        Ok(QueryExecutionResult::CausalChain(CausalChainResult {
            from_entity,
            causality_type,
            causal_chain: Vec::new(), // Empty for now
            max_depth,
            tokens_used: query.estimated_tokens.unwrap_or(800),
        }))
    }

    async fn execute_timeline_events_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity_names = query.parameters.get("entity_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| AppError::SerializationError("Missing entity_names parameter".to_string()))?;

        let event_categories = query.parameters.get("event_categories")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::TimelineEvents(TimelineEventsResult {
            entity_names,
            timeline: Vec::new(), // Empty for now
            event_categories,
            tokens_used: query.estimated_tokens.unwrap_or(1000),
        }))
    }

    async fn execute_entity_current_state_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity_names = query.parameters.get("entity_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| AppError::SerializationError("Missing entity_names parameter".to_string()))?;

        let state_aspects = query.parameters.get("state_aspects")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::EntityCurrentState(EntityCurrentStateResult {
            entity_names,
            current_states: HashMap::new(), // Empty for now
            state_aspects,
            tokens_used: query.estimated_tokens.unwrap_or(500),
        }))
    }

    async fn execute_entity_states_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let scope = query.parameters.get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();

        let state_types = query.parameters.get("state_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::EntityStates(EntityStatesResult {
            entities: Vec::new(), // Empty for now
            scope,
            state_types,
            tokens_used: query.estimated_tokens.unwrap_or(400),
        }))
    }

    async fn execute_shared_events_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity_names = query.parameters.get("entities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let event_types = query.parameters.get("event_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::SharedEvents(SharedEventsResult {
            entity_names,
            shared_events: Vec::new(), // Empty for now
            event_types,
            tokens_used: query.estimated_tokens.unwrap_or(700),
        }))
    }

    async fn execute_causal_factors_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let scenario = query.parameters.get("scenario")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let entity = query.parameters.get("entity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let factor_types = query.parameters.get("factor_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::CausalFactors(CausalFactorsResult {
            scenario,
            entity,
            factors: Vec::new(), // Empty for now
            factor_types,
            tokens_used: query.estimated_tokens.unwrap_or(600),
        }))
    }

    async fn execute_state_transitions_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let entity = query.parameters.get("entity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let transition_types = query.parameters.get("transition_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(QueryExecutionResult::StateTransitions(StateTransitionsResult {
            entity,
            transitions: Vec::new(), // Empty for now
            transition_types,
            tokens_used: query.estimated_tokens.unwrap_or(500),
        }))
    }

    async fn execute_recent_events_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let time_scope = query.parameters.get("time_scope")
            .and_then(|v| v.as_str())
            .unwrap_or("last_24_hours")
            .to_string();

        let event_types = query.parameters.get("event_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let max_events = query.parameters.get("max_events")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;

        Ok(QueryExecutionResult::RecentEvents(RecentEventsResult {
            time_scope,
            events: Vec::new(), // Empty for now
            event_types,
            max_events,
            tokens_used: query.estimated_tokens.unwrap_or(800),
        }))
    }

    async fn execute_historical_parallels_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let scenario_type = query.parameters.get("scenario_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let outcome_focus = query.parameters.get("outcome_focus")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(QueryExecutionResult::HistoricalParallels(HistoricalParallelsResult {
            scenario_type,
            parallels: Vec::new(), // Empty for now
            outcome_focus,
            tokens_used: query.estimated_tokens.unwrap_or(600),
        }))
    }

    async fn execute_active_entities_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let activity_threshold = query.parameters.get("activity_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.1) as f32;

        let include_positions = query.parameters.get("include_positions")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let include_states = query.parameters.get("include_states")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(QueryExecutionResult::ActiveEntities(ActiveEntitiesResult {
            entities: Vec::new(), // Empty for now
            activity_threshold,
            include_positions,
            include_states,
            tokens_used: query.estimated_tokens.unwrap_or(500),
        }))
    }

    async fn execute_narrative_threads_query(
        &self,
        query: &PlannedQuery,
        _user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let thread_types = query.parameters.get("thread_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let status = query.parameters.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active")
            .to_string();

        let max_threads = query.parameters.get("max_threads")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32;

        Ok(QueryExecutionResult::NarrativeThreads(NarrativeThreadsResult {
            threads: Vec::new(), // Empty for now
            thread_types,
            status,
            max_threads,
            tokens_used: query.estimated_tokens.unwrap_or(400),
        }))
    }

    fn get_result_tokens(&self, result: &QueryExecutionResult) -> u32 {
        match result {
            QueryExecutionResult::EntityEvents(r) => r.tokens_used,
            QueryExecutionResult::SpatialEntities(r) => r.tokens_used,
            QueryExecutionResult::EntityRelationships(r) => r.tokens_used,
            QueryExecutionResult::CausalChain(r) => r.tokens_used,
            QueryExecutionResult::TimelineEvents(r) => r.tokens_used,
            QueryExecutionResult::EntityCurrentState(r) => r.tokens_used,
            QueryExecutionResult::EntityStates(r) => r.tokens_used,
            QueryExecutionResult::SharedEvents(r) => r.tokens_used,
            QueryExecutionResult::CausalFactors(r) => r.tokens_used,
            QueryExecutionResult::StateTransitions(r) => r.tokens_used,
            QueryExecutionResult::RecentEvents(r) => r.tokens_used,
            QueryExecutionResult::HistoricalParallels(r) => r.tokens_used,
            QueryExecutionResult::ActiveEntities(r) => r.tokens_used,
            QueryExecutionResult::NarrativeThreads(r) => r.tokens_used,
        }
    }
}