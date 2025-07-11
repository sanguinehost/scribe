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
        EncryptionService,
    },
    schema::{lorebook_entries, lorebooks},
    llm::AiClient,
};
use diesel::{prelude::*, RunQueryDsl};
use secrecy::{ExposeSecret, SecretBox};

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
    // Chronicle-related queries
    ChronicleEvents(ChronicleEventsResult),
    ChronicleTimeline(ChronicleTimelineResult),
    ChronicleThemes(ChronicleThemesResult),
    RelatedChronicles(RelatedChroniclesResult),
    // Lorebook-related queries
    LorebookEntries(LorebookEntriesResult),
    LorebookConcepts(LorebookConceptsResult),
    LorebookCharacters(LorebookCharactersResult),
    LorebookLocations(LorebookLocationsResult),
    LorebookContext(LorebookContextResult),
    // Entity existence validation
    MissingEntities(MissingEntitiesResult),
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

// Chronicle-related result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleEventsResult {
    pub chronicle_id: Option<Uuid>,
    pub events: Vec<ChronicleEventSummary>,
    pub event_types: Vec<String>,
    pub time_range: String,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleTimelineResult {
    pub chronicle_id: Option<Uuid>,
    pub timeline: Vec<ChronicleTimelineEvent>,
    pub narrative_arcs: Vec<String>,
    pub major_themes: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleThemesResult {
    pub chronicle_id: Option<Uuid>,
    pub themes: Vec<NarrativeTheme>,
    pub character_arcs: Vec<CharacterArc>,
    pub plot_threads: Vec<PlotThread>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedChroniclesResult {
    pub related_chronicles: Vec<ChronicleReference>,
    pub relationship_types: Vec<String>,
    pub shared_elements: Vec<String>,
    pub tokens_used: u32,
}

// Lorebook-related result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookEntriesResult {
    pub entries: Vec<LorebookEntrySummary>,
    pub categories: Vec<String>,
    pub entry_types: Vec<String>,
    pub relevance_threshold: f32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookConceptsResult {
    pub concepts: Vec<ConceptSummary>,
    pub concept_types: Vec<String>,
    pub relationships: Vec<ConceptRelationship>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookCharactersResult {
    pub characters: Vec<CharacterReference>,
    pub character_types: Vec<String>,
    pub relationship_context: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookLocationsResult {
    pub locations: Vec<LocationReference>,
    pub location_types: Vec<String>,
    pub spatial_relationships: Vec<String>,
    pub cultural_context: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookContextResult {
    pub contextual_entries: Vec<ContextualEntry>,
    pub context_types: Vec<String>,
    pub cultural_notes: Vec<String>,
    pub historical_context: Vec<String>,
    pub tokens_used: u32,
}

// Supporting types for chronicles and lorebooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleEventSummary {
    pub event_id: Uuid,
    pub summary: String,
    pub event_type: String,
    pub actors: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub narrative_impact: String,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleTimelineEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_summary: String,
    pub narrative_significance: String,
    pub involved_entities: Vec<String>,
    pub causal_connections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeTheme {
    pub theme_name: String,
    pub description: String,
    pub examples: Vec<String>,
    pub character_involvement: Vec<String>,
    pub strength: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterArc {
    pub character_name: String,
    pub arc_description: String,
    pub key_moments: Vec<String>,
    pub development_stage: String,
    pub completion_level: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlotThread {
    pub thread_name: String,
    pub description: String,
    pub current_status: String,
    pub involved_entities: Vec<String>,
    pub next_developments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleReference {
    pub chronicle_id: Uuid,
    pub title: String,
    pub relationship_type: String,
    pub shared_elements: Vec<String>,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookEntrySummary {
    pub entry_id: Uuid,
    pub title: String,
    pub category: String,
    pub summary: String,
    pub keywords: Vec<String>,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConceptSummary {
    pub concept_name: String,
    pub description: String,
    pub category: String,
    pub related_concepts: Vec<String>,
    pub usage_examples: Vec<String>,
    pub importance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConceptRelationship {
    pub from_concept: String,
    pub to_concept: String,
    pub relationship_type: String,
    pub description: String,
    pub strength: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterReference {
    pub character_name: String,
    pub description: String,
    pub role: String,
    pub relationships: Vec<String>,
    pub current_status: String,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationReference {
    pub location_name: String,
    pub description: String,
    pub location_type: String,
    pub contained_locations: Vec<String>,
    pub cultural_significance: String,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualEntry {
    pub entry_title: String,
    pub context_type: String,
    pub description: String,
    pub application_notes: Vec<String>,
    pub related_entries: Vec<String>,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEntitiesResult {
    pub missing_entities: Vec<MissingEntityInfo>,
    pub source_context: String,
    pub creation_priority: f32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEntityInfo {
    pub entity_name: String,
    pub entity_type: Option<String>,
    pub mentioned_in_context: String,
    pub character_traits: Vec<String>,
    pub location_details: Vec<String>,
    pub relationship_hints: Vec<String>,
    pub creation_confidence: f32,
}

pub struct ContextAssemblyEngine {
    hybrid_query_service: Arc<HybridQueryService>,
    db_pool: Arc<PgPool>,
    encryption_service: Arc<EncryptionService>,
    ai_client: Arc<dyn AiClient>,
}

impl ContextAssemblyEngine {
    pub fn new(
        hybrid_query_service: Arc<HybridQueryService>,
        db_pool: Arc<PgPool>,
        encryption_service: Arc<EncryptionService>,
        ai_client: Arc<dyn AiClient>,
    ) -> Self {
        Self {
            hybrid_query_service,
            db_pool,
            encryption_service,
            ai_client,
        }
    }

    #[instrument(skip(self), fields(num_queries = plan.queries.len(), strategy = ?plan.primary_strategy))]
    pub async fn execute_plan(
        &self,
        plan: &QueryExecutionPlan,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
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
                match self.execute_query(query, user_id, user_dek).await {
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
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
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
            // Chronicle queries
            PlannedQueryType::ChronicleEvents => {
                self.execute_chronicle_events_query(query, user_id).await
            }
            PlannedQueryType::ChronicleTimeline => {
                self.execute_chronicle_timeline_query(query, user_id).await
            }
            PlannedQueryType::ChronicleThemes => {
                self.execute_chronicle_themes_query(query, user_id).await
            }
            PlannedQueryType::RelatedChronicles => {
                self.execute_related_chronicles_query(query, user_id).await
            }
            // Lorebook queries
            PlannedQueryType::LorebookEntries => {
                self.execute_lorebook_entries_query(query, user_id, user_dek).await
            }
            PlannedQueryType::LorebookConcepts => {
                self.execute_lorebook_concepts_query(query, user_id, user_dek).await
            }
            PlannedQueryType::LorebookCharacters => {
                self.execute_lorebook_characters_query(query, user_id, user_dek).await
            }
            PlannedQueryType::LorebookLocations => {
                self.execute_lorebook_locations_query(query, user_id, user_dek).await
            }
            PlannedQueryType::LorebookContext => {
                self.execute_lorebook_context_query(query, user_id, user_dek).await
            }
            // Entity creation queries
            PlannedQueryType::MissingEntities => {
                self.execute_missing_entities_query(query, user_id).await
            }
        }
    }

    async fn execute_entity_events_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Extract chronicle_id from parameters if available
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut entities = HashMap::new();
        let mut total_events = 0;
        let mut total_tokens = 0;

        // Query each entity individually using the hybrid service
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None, // Could be enhanced to lookup entity_id if available
                    include_current_state: true,
                },
                user_id,
                chronicle_id,
                max_results: max_events,
                include_current_state: true,
                include_relationships: false, // Focus on events, not relationships
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Convert timeline events to EventSummary format
                    let event_summaries: Vec<EventSummary> = result.entities
                        .iter()
                        .flat_map(|entity_context| &entity_context.timeline_events)
                        .map(|timeline_event| EventSummary {
                            event_id: timeline_event.event.id,
                            summary: timeline_event.event.summary.clone(),
                            event_type: timeline_event.event.event_type.clone(),
                            timestamp: timeline_event.event.created_at,
                            relevance_score: timeline_event.significance_score,
                        })
                        .collect();
                    
                    total_events += event_summaries.len();
                    total_tokens += (result.performance.total_duration_ms / 10) as u32; // Rough token estimate
                    entities.insert(entity_name.clone(), event_summaries);
                }
                Err(e) => {
                    debug!("Failed to query entity {}: {}", entity_name, e);
                    // Insert empty events for failed queries
                    entities.insert(entity_name.clone(), Vec::new());
                }
            }
        }

        Ok(QueryExecutionResult::EntityEvents(EntityEventsResult {
            entities,
            time_scope,
            total_events,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(500)),
        }))
    }

    async fn execute_spatial_entities_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let location_name = query.parameters.get("location_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("Missing location_name parameter".to_string()))?
            .to_string();

        let include_contained = query.parameters.get("include_contained")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let max_results = query.parameters.get("max_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as usize;

        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::LocationQuery {
                location_name: location_name.clone(),
                location_data: None,
                include_recent_activity: true,
            },
            user_id,
            chronicle_id,
            max_results,
            include_current_state: true,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Convert entities to EntitySummary format
                let entities: Vec<EntitySummary> = result.entities
                    .iter()
                    .filter_map(|entity_context| {
                        entity_context.current_state.as_ref().map(|_state| EntitySummary {
                            entity_id: entity_context.entity_id,
                            name: entity_context.entity_name.clone().unwrap_or_else(|| "Unknown".to_string()),
                            entity_type: "Character".to_string(), // Default type - could be enhanced
                            current_location: Some(location_name.clone()),
                            activity_level: entity_context.relevance_score, // Use relevance as activity level
                            relevance_score: entity_context.relevance_score,
                        })
                    })
                    .collect();

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::SpatialEntities(SpatialEntitiesResult {
                    location_name,
                    entities,
                    include_contained,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(400)),
                }))
            }
            Err(e) => {
                debug!("Failed to query location {}: {}", location_name, e);
                
                // Return empty result for failed query
                Ok(QueryExecutionResult::SpatialEntities(SpatialEntitiesResult {
                    location_name,
                    entities: Vec::new(),
                    include_contained,
                    tokens_used: query.estimated_tokens.unwrap_or(400),
                }))
            }
        }
    }

    async fn execute_entity_relationships_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        let mut all_relationships = Vec::new();
        let mut total_tokens = 0;

        // Query relationships for each entity
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::RelationshipHistory {
                    entity_a: entity_name.clone(),
                    entity_b: "*".to_string(), // Query all relationships for this entity
                    entity_a_id: None,
                    entity_b_id: None,
                },
                user_id,
                chronicle_id,
                max_results: 50,
                include_current_state: true,
                include_relationships: true,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Convert relationships to RelationshipSummary format
                    for relationship_analysis in &result.relationships {
                        if let Some(current_rel) = &relationship_analysis.current_relationship {
                            let relationship_summary = RelationshipSummary {
                                from_entity: relationship_analysis.from_entity_id.to_string(),
                                to_entity: relationship_analysis.to_entity_id.to_string(),
                                relationship_type: current_rel.relationship_type.clone(),
                                strength: relationship_analysis.analysis.strength,
                                relevance_score: relationship_analysis.analysis.strength, // Use strength as relevance
                            };
                            all_relationships.push(relationship_summary);
                        }
                    }
                    
                    total_tokens += (result.performance.total_duration_ms / 10) as u32;
                }
                Err(e) => {
                    debug!("Failed to query relationships for entity {}: {}", entity_name, e);
                    // Continue with other entities
                }
            }
        }

        Ok(QueryExecutionResult::EntityRelationships(EntityRelationshipsResult {
            entity_names,
            relationships: all_relationships,
            max_depth,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(600)),
        }))
    }

    async fn execute_causal_chain_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::CausalChain {
                from_event: None, // We don't have a specific event, searching for entity-related causality
                to_state: Some(format!("involving {}", from_entity)),
                to_entity: None, // Could be enhanced to lookup entity_id
                max_depth,
                min_confidence: 0.5,
            },
            user_id,
            chronicle_id,
            max_results: max_depth as usize * 5, // Allow multiple chains per depth level
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Convert the timeline events into causal links
                let mut causal_chain = Vec::new();
                
                // Look for causally connected events in the entity's timeline
                for entity_context in &result.entities {
                    if entity_context.entity_name.as_ref() == Some(&from_entity) || 
                       entity_context.timeline_events.iter().any(|e| e.event.summary.contains(&from_entity)) {
                        
                        // Create causal links from consecutive significant events
                        let mut prev_event: Option<Uuid> = None;
                        for timeline_event in &entity_context.timeline_events {
                            if timeline_event.significance_score > 0.6 { // Only include significant events
                                if let Some(prev) = prev_event {
                                    let causal_link = CausalLink {
                                        cause_event: prev.to_string(),
                                        effect_event: timeline_event.event.id.to_string(),
                                        causal_strength: timeline_event.significance_score,
                                        explanation: format!(
                                            "Led to: {} (involving {} entities)", 
                                            timeline_event.event.summary,
                                            timeline_event.co_participants.len()
                                        ),
                                    };
                                    causal_chain.push(causal_link);
                                }
                                prev_event = Some(timeline_event.event.id);
                            }
                        }
                    }
                }

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::CausalChain(CausalChainResult {
                    from_entity,
                    causality_type,
                    causal_chain,
                    max_depth,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(800)),
                }))
            }
            Err(e) => {
                debug!("Failed to query causal chain for entity {}: {}", from_entity, e);
                
                // Return empty result for failed query
                Ok(QueryExecutionResult::CausalChain(CausalChainResult {
                    from_entity,
                    causality_type,
                    causal_chain: Vec::new(),
                    max_depth,
                    tokens_used: query.estimated_tokens.unwrap_or(800),
                }))
            }
        }
    }

    async fn execute_timeline_events_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Extract chronicle_id from parameters if available
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut timeline = Vec::new();
        let mut total_tokens = 0;

        // Query timeline events for each entity
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None,
                    include_current_state: false, // Focus on timeline events only
                },
                user_id,
                chronicle_id,
                max_results: 20,
                include_current_state: false,
                include_relationships: false,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Convert timeline events to TimelineEvent format
                    for entity_context in result.entities {
                        for timeline_event in entity_context.timeline_events {
                            timeline.push(TimelineEvent {
                                timestamp: timeline_event.event.created_at,
                                event_summary: timeline_event.event.summary.clone(),
                                entities_involved: vec![entity_name.clone()],
                                category: timeline_event.event.event_type.clone(),
                                impact_score: timeline_event.significance_score,
                            });
                        }
                    }
                    total_tokens += (result.performance.total_duration_ms / 10) as u32; // Rough token estimate
                }
                Err(e) => {
                    debug!("Failed to query timeline for entity {}: {}", entity_name, e);
                    // Continue with other entities
                }
            }
        }

        // Sort timeline events by timestamp
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(QueryExecutionResult::TimelineEvents(TimelineEventsResult {
            entity_names,
            timeline,
            event_categories,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(1000)),
        }))
    }

    async fn execute_entity_current_state_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        use chrono::Utc;

        let mut current_states = HashMap::new();
        let mut total_tokens = 0;

        // Query current state for each entity
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None,
                    include_current_state: true,
                },
                user_id,
                chronicle_id,
                max_results: 1, // We only need the most recent state
                include_current_state: true,
                include_relationships: false,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Find the entity and extract its current state
                    if let Some(entity_context) = result.entities.iter().find(|e| 
                        e.entity_name.as_ref() == Some(entity_name)
                    ) {
                        if let Some(current_state_snapshot) = &entity_context.current_state {
                            let mut state_data = HashMap::new();
                            
                            // Extract relevant data from the snapshot
                            // Extract location and activity from components if available
                            if let Some(location_value) = current_state_snapshot.components.get("location") {
                                state_data.insert("location".to_string(), location_value.clone());
                            }
                            if let Some(activity_value) = current_state_snapshot.components.get("activity") {
                                state_data.insert("activity".to_string(), activity_value.clone());
                            }
                            state_data.insert("status".to_string(), serde_json::Value::String("Active".to_string()));
                            
                            // Add component data
                            for (key, value) in &current_state_snapshot.components {
                                state_data.insert(key.clone(), value.clone());
                            }
                            
                            let entity_state = EntityState {
                                entity_name: entity_name.clone(),
                                state_data,
                                last_updated: Utc::now(),
                                confidence: 0.8, // Default confidence
                            };
                            current_states.insert(entity_name.clone(), entity_state);
                        }
                    }
                    
                    total_tokens += (result.performance.total_duration_ms / 10) as u32;
                }
                Err(e) => {
                    debug!("Failed to query current state for entity {}: {}", entity_name, e);
                    // Continue with other entities
                }
            }
        }

        Ok(QueryExecutionResult::EntityCurrentState(EntityCurrentStateResult {
            entity_names,
            current_states,
            state_aspects,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(500)),
        }))
    }

    async fn execute_entity_states_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Extract entity names from parameters
        let entity_names = query.parameters.get("entity_names")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Extract chronicle_id from parameters if available
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut entities = Vec::new();
        let mut total_tokens = 0;

        // Query current state for each entity
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None,
                    include_current_state: true, // Focus on current state
                },
                user_id,
                chronicle_id,
                max_results: 5, // Limit to recent events but focus on state
                include_current_state: true,
                include_relationships: false,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Convert entity context to EntityState format
                    for entity_context in result.entities {
                        if let Some(current_state) = entity_context.current_state {
                            entities.push(EntityState {
                                entity_name: entity_name.clone(),
                                state_data: current_state.components.into_iter().collect(),
                                last_updated: current_state.snapshot_time,
                                confidence: 0.9, // High confidence for current state
                            });
                        }
                    }
                    total_tokens += (result.performance.total_duration_ms / 10) as u32; // Rough token estimate
                }
                Err(e) => {
                    debug!("Failed to query entity state for {}: {}", entity_name, e);
                    // Continue with other entities
                }
            }
        }

        Ok(QueryExecutionResult::EntityStates(EntityStatesResult {
            entities,
            scope,
            state_types,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(400)),
        }))
    }

    pub async fn execute_shared_events_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Extract chronicle_id from parameters if available
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut shared_events = Vec::new();
        let mut total_tokens = 0;
        let mut entity_event_sets: HashMap<String, std::collections::HashSet<Uuid>> = HashMap::new();

        // Collect all events for each entity first
        for entity_name in &entity_names {
            let hybrid_query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None,
                    include_current_state: false,
                },
                user_id,
                chronicle_id,
                max_results: 30, // Get more events to find shared ones
                include_current_state: false,
                include_relationships: false,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    let mut entity_events = std::collections::HashSet::new();
                    for entity_context in result.entities {
                        for timeline_event in entity_context.timeline_events {
                            entity_events.insert(timeline_event.event.id);
                        }
                    }
                    entity_event_sets.insert(entity_name.clone(), entity_events);
                    total_tokens += (result.performance.total_duration_ms / 10) as u32;
                }
                Err(e) => {
                    debug!("Failed to query events for entity {}: {}", entity_name, e);
                    entity_event_sets.insert(entity_name.clone(), std::collections::HashSet::new());
                }
            }
        }

        // Find events that are shared between multiple entities
        if entity_names.len() >= 2 {
            // Get first entity's events as a starting point
            if let Some(first_entity_events) = entity_event_sets.values().next() {
                let mut shared_event_ids: std::collections::HashSet<Uuid> = first_entity_events.clone();
                
                // Find intersection with all other entities
                for event_set in entity_event_sets.values().skip(1) {
                    shared_event_ids.retain(|event_id| event_set.contains(event_id));
                }

                // Convert shared event IDs to SharedEventSummary structs
                // For now, create simplified shared events
                for event_id in shared_event_ids.iter().take(10) { // Limit to 10 shared events
                    shared_events.push(SharedEventSummary {
                        event_summary: format!("Shared event involving {}", entity_names.join(", ")),
                        entities_involved: entity_names.clone(),
                        event_type: "interaction".to_string(),
                        impact_level: 0.8, // High impact for shared events
                        timestamp: chrono::Utc::now(), // Would need actual event data for real timestamp
                    });
                }
            }
        }

        Ok(QueryExecutionResult::SharedEvents(SharedEventsResult {
            entity_names,
            shared_events,
            event_types,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(700)),
        }))
    }

    pub async fn execute_causal_factors_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Extract chronicle_id from parameters if available
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut factors = Vec::new();
        let mut total_tokens = 0;

        // Use EntityTimeline query type instead since CausalInfluences requires entity_id
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::EntityTimeline {
                entity_name: entity.clone(),
                entity_id: None,
                include_current_state: true,
            },
            user_id,
            chronicle_id,
            max_results: 15,
            include_current_state: true,
            include_relationships: true, // Include relationships as potential causal factors
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Convert entity context to causal factors
                for entity_context in result.entities {
                    // Timeline events as causal factors
                    for timeline_event in entity_context.timeline_events.iter().take(10) {
                        factors.push(CausalFactor {
                            factor_name: format!("Event: {}", timeline_event.event.summary),
                            factor_type: "event".to_string(),
                            description: timeline_event.event.summary.clone(),
                            influence_strength: timeline_event.significance_score,
                        });
                    }

                    // Relationships as causal factors
                    for relationship in entity_context.relationships.iter().take(5) {
                        factors.push(CausalFactor {
                            factor_name: format!("{} relationship", relationship.relationship_type),
                            factor_type: "relationship".to_string(),
                            description: format!("{} relationship (from {} to {})", 
                                relationship.relationship_type, relationship.from_entity_id, relationship.to_entity_id),
                            influence_strength: 0.6, // Default influence for relationships
                        });
                    }
                }
                total_tokens += (result.performance.total_duration_ms / 10) as u32;
            }
            Err(e) => {
                debug!("Failed to query causal factors for entity {}: {}", entity, e);
                // Create a default causal factor
                factors.push(CausalFactor {
                    factor_name: "Unknown causal factor".to_string(),
                    factor_type: "unknown".to_string(),
                    description: format!("Causal analysis for {} in scenario: {}", entity, scenario),
                    influence_strength: 0.3,
                });
            }
        }

        Ok(QueryExecutionResult::CausalFactors(CausalFactorsResult {
            scenario,
            entity,
            factors,
            factor_types,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(600)),
        }))
    }

    async fn execute_state_transitions_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut transitions = Vec::new();
        let mut total_tokens = 0;

        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::EntityTimeline {
                entity_name: entity.clone(),
                entity_id: None,
                include_current_state: true,
            },
            user_id,
            chronicle_id,
            max_results: 15,
            include_current_state: true,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                for entity_context in result.entities {
                    // Convert timeline events to state transitions
                    for (i, timeline_event) in entity_context.timeline_events.iter().enumerate() {
                        if i > 0 {
                            let prev_event = &entity_context.timeline_events[i - 1];
                            transitions.push(StateTransition {
                                from_state: format!("State before {}", timeline_event.event.summary),
                                to_state: format!("State after {}", timeline_event.event.summary),
                                transition_time: timeline_event.event.created_at,
                                trigger_event: Some(timeline_event.event.summary.clone()),
                                transition_type: timeline_event.event.event_type.clone(),
                            });
                        }
                    }
                }
                total_tokens += (result.performance.total_duration_ms / 10) as u32;
            }
            Err(e) => {
                debug!("Failed to query state transitions for entity {}: {}", entity, e);
            }
        }

        Ok(QueryExecutionResult::StateTransitions(StateTransitionsResult {
            entity,
            transitions,
            transition_types,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(500)),
        }))
    }

    pub async fn execute_recent_events_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut events = Vec::new();
        let mut total_tokens = 0;

        // Query recent events using NarrativeQuery
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "recent events".to_string(),
                focus_entities: Some(Vec::new()),
                time_range: None,
            },
            user_id,
            chronicle_id,
            max_results: max_events as usize,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                for entity_context in result.entities {
                    for timeline_event in entity_context.timeline_events.iter().take(max_events as usize) {
                        events.push(EventSummary {
                            event_id: timeline_event.event.id,
                            summary: timeline_event.event.summary.clone(),
                            timestamp: timeline_event.event.created_at,
                            event_type: timeline_event.event.event_type.clone(),
                            relevance_score: timeline_event.significance_score,
                        });
                    }
                }
                total_tokens += (result.performance.total_duration_ms / 10) as u32;
            }
            Err(e) => {
                debug!("Failed to query recent events: {}", e);
            }
        }

        // Sort by timestamp descending (most recent first)
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(QueryExecutionResult::RecentEvents(RecentEventsResult {
            time_scope,
            events,
            event_types,
            max_events,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(800)),
        }))
    }

    pub async fn execute_historical_parallels_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let scenario_type = query.parameters.get("scenario_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let outcome_focus = query.parameters.get("outcome_focus")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};
        
        let mut parallels = Vec::new();
        let mut total_tokens = 0;

        // Use NarrativeQuery to find historical parallels
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: format!("historical parallels for scenario type: {}", scenario_type),
                focus_entities: Some(Vec::new()),
                time_range: None,
            },
            user_id,
            chronicle_id,
            max_results: 10,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Create simplified historical parallels from the results
                for (i, entity_context) in result.entities.iter().enumerate() {
                    if i < 5 { // Limit to 5 parallels
                        let events_summary = entity_context.timeline_events
                            .iter()
                            .map(|te| te.event.summary.clone())
                            .collect::<Vec<_>>()
                            .join("; ");
                        
                        parallels.push(HistoricalParallel {
                            scenario_description: format!("Historical scenario involving {}", 
                                entity_context.entity_name.as_deref().unwrap_or("unknown entity")),
                            outcome: events_summary,
                            similarity_score: 0.7, // Default similarity
                            lessons_learned: vec!["Pattern recognition".to_string(), "Historical context".to_string()],
                        });
                    }
                }
                total_tokens += (result.performance.total_duration_ms / 10) as u32;
            }
            Err(e) => {
                debug!("Failed to query historical parallels: {}", e);
                // Create a default parallel
                parallels.push(HistoricalParallel {
                    scenario_description: format!("Historical analysis for scenario: {}", scenario_type),
                    outcome: "Limited historical data available".to_string(),
                    similarity_score: 0.3,
                    lessons_learned: vec!["Incomplete data".to_string()],
                });
            }
        }

        Ok(QueryExecutionResult::HistoricalParallels(HistoricalParallelsResult {
            scenario_type,
            parallels,
            outcome_focus,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(600)),
        }))
    }

    async fn execute_active_entities_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
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

        // Query active entities from ECS tables
        let mut entities = Vec::new();
        let mut total_tokens = 0u32;

        // Calculate time threshold for "active" entities (last 24 hours by default)
        let time_threshold = chrono::Utc::now() - chrono::Duration::hours(24);

        // Query for entities that have been updated recently
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let active_entity_records: Vec<(Uuid, String, chrono::DateTime<chrono::Utc>)> = conn.interact(move |conn| {
            use crate::schema::{ecs_entities, ecs_components};
            use diesel::prelude::*;

            ecs_entities::table
                .inner_join(ecs_components::table)
                .filter(ecs_entities::user_id.eq(user_id))
                .filter(ecs_entities::updated_at.gt(time_threshold))
                .or_filter(ecs_components::updated_at.gt(time_threshold))
                .select((
                    ecs_entities::id,
                    ecs_entities::archetype_signature,
                    ecs_entities::updated_at,
                ))
                .distinct()
                .limit(50) // Limit to reasonable number for performance
                .load::<(Uuid, String, chrono::DateTime<chrono::Utc>)>(conn)
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        debug!("Found {} active entities for user {}", active_entity_records.len(), user_id);

        // Convert database records to EntitySummary format
        for (entity_id, archetype_signature, updated_at) in active_entity_records {
            // Calculate activity level based on how recently the entity was updated
            let hours_since_update = chrono::Utc::now().signed_duration_since(updated_at).num_hours() as f32;
            let activity_level = (24.0 - hours_since_update.min(24.0)) / 24.0; // 1.0 = just updated, 0.0 = 24 hours ago

            // Only include entities above the activity threshold
            if activity_level >= activity_threshold {
                // Extract entity name from archetype signature or generate one
                let entity_name = archetype_signature
                    .split(',')
                    .find(|component| component.contains("Name") || component.contains("Character"))
                    .unwrap_or(&archetype_signature)
                    .trim()
                    .to_string();

                let entity_summary = EntitySummary {
                    entity_id,
                    name: entity_name,
                    entity_type: "Character".to_string(), // Default type for now
                    current_location: if include_positions { 
                        Some("Unknown".to_string()) // Placeholder - would need spatial component query
                    } else { 
                        None 
                    },
                    activity_level,
                    relevance_score: activity_level, // Use activity level as relevance for now
                };

                entities.push(entity_summary);
                total_tokens += 50; // Estimate ~50 tokens per entity summary
            }
        }

        info!("Active entities query returned {} entities above threshold {}", 
              entities.len(), activity_threshold);

        Ok(QueryExecutionResult::ActiveEntities(ActiveEntitiesResult {
            entities,
            activity_threshold,
            include_positions,
            include_states,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(500)),
        }))
    }

    async fn execute_narrative_threads_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let thread_types = query.parameters.get("thread_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["conflict".to_string(), "relationship".to_string(), "mystery".to_string()]);

        let status = query.parameters.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active")
            .to_string();

        let max_threads = query.parameters.get("max_threads")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32;

        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        // Query narrative threads from chronicle events and analyze patterns
        let mut threads = Vec::new();
        let mut total_tokens = 0u32;

        // Get recent chronicle events to analyze for narrative patterns
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let recent_events: Vec<(Uuid, String, String, chrono::DateTime<chrono::Utc>)> = conn.interact(move |conn| {
            use crate::schema::chronicle_events;
            use diesel::prelude::*;

            let mut query_builder = chronicle_events::table
                .filter(chronicle_events::user_id.eq(user_id))
                .into_boxed();

            // Filter by chronicle if specified
            if let Some(cid) = chronicle_id {
                query_builder = query_builder.filter(chronicle_events::chronicle_id.eq(cid));
            }

            // Get events from last 7 days for thread analysis
            let time_threshold = chrono::Utc::now() - chrono::Duration::days(7);
            query_builder
                .filter(chronicle_events::created_at.gt(time_threshold))
                .select((
                    chronicle_events::id,
                    chronicle_events::event_type,
                    chronicle_events::summary,
                    chronicle_events::created_at,
                ))
                .order(chronicle_events::created_at.desc())
                .limit(100) // Analyze last 100 events
                .load::<(Uuid, String, String, chrono::DateTime<chrono::Utc>)>(conn)
        }).await
        .map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        debug!("Found {} recent events for narrative thread analysis", recent_events.len());

        // Analyze events to identify narrative threads
        let mut thread_candidates: std::collections::HashMap<String, Vec<(Uuid, String, chrono::DateTime<chrono::Utc>)>> = std::collections::HashMap::new();

        for (event_id, event_type, summary, created_at) in recent_events {
            // Group events by type and look for patterns
            let thread_type = self.categorize_event_for_thread(&event_type, &summary, &thread_types);
            
            if let Some(t_type) = thread_type {
                thread_candidates.entry(t_type)
                    .or_insert_with(Vec::new)
                    .push((event_id, summary, created_at));
            }
        }

        // Convert thread candidates to narrative threads
        for (thread_type, events) in thread_candidates.iter().take(max_threads as usize) {
            if events.len() >= 2 { // Need at least 2 events to form a thread
                let thread_id = Uuid::new_v4().to_string();
                
                // Calculate thread intensity based on event frequency and recency
                let latest_event = events.iter().map(|(_, _, created_at)| *created_at).max().unwrap_or(chrono::Utc::now());
                let hours_since_latest = chrono::Utc::now().signed_duration_since(latest_event).num_hours() as f32;
                let intensity = ((7.0 * 24.0 - hours_since_latest.min(7.0 * 24.0)) / (7.0 * 24.0)) * (events.len() as f32 / 10.0).min(1.0);

                // Extract entities involved from event summaries
                let entities_involved = self.extract_entities_from_summaries(&events.iter().map(|(_, summary, _)| summary.as_str()).collect::<Vec<_>>());

                let narrative_thread = NarrativeThread {
                    thread_id: thread_id.clone(),
                    thread_type: thread_type.clone(),
                    description: format!("Ongoing {} thread involving {} events", thread_type, events.len()),
                    entities_involved,
                    current_status: status.clone(),
                    intensity,
                };

                threads.push(narrative_thread);
                total_tokens += 80; // Estimate ~80 tokens per thread analysis
            }
        }

        info!("Narrative threads query identified {} active threads", threads.len());

        Ok(QueryExecutionResult::NarrativeThreads(NarrativeThreadsResult {
            threads,
            thread_types,
            status,
            max_threads,
            tokens_used: total_tokens.max(query.estimated_tokens.unwrap_or(400)),
        }))
    }

    // Helper function to categorize events into narrative thread types
    fn categorize_event_for_thread(&self, event_type: &str, summary: &str, allowed_types: &[String]) -> Option<String> {
        let summary_lower = summary.to_lowercase();
        let event_type_lower = event_type.to_lowercase();

        for thread_type in allowed_types {
            let thread_type_lower = thread_type.to_lowercase();
            match thread_type_lower.as_str() {
                "conflict" => {
                    if event_type_lower.contains("battle") || event_type_lower.contains("fight") || event_type_lower.contains("conflict") ||
                       summary_lower.contains("attack") || summary_lower.contains("battle") || summary_lower.contains("conflict") ||
                       summary_lower.contains("fight") || summary_lower.contains("enemy") {
                        return Some(thread_type.clone());
                    }
                }
                "relationship" => {
                    if event_type_lower.contains("social") || event_type_lower.contains("interaction") || 
                       summary_lower.contains("talk") || summary_lower.contains("meet") || summary_lower.contains("friend") ||
                       summary_lower.contains("relationship") || summary_lower.contains("conversation") {
                        return Some(thread_type.clone());
                    }
                }
                "mystery" => {
                    if event_type_lower.contains("discovery") || event_type_lower.contains("clue") ||
                       summary_lower.contains("discover") || summary_lower.contains("mystery") || summary_lower.contains("secret") ||
                       summary_lower.contains("hidden") || summary_lower.contains("unknown") {
                        return Some(thread_type.clone());
                    }
                }
                "quest" => {
                    if event_type_lower.contains("quest") || event_type_lower.contains("mission") ||
                       summary_lower.contains("quest") || summary_lower.contains("mission") || summary_lower.contains("task") ||
                       summary_lower.contains("objective") {
                        return Some(thread_type.clone());
                    }
                }
                _ => {
                    // Generic matching for custom thread types
                    if event_type_lower.contains(&thread_type_lower) || summary_lower.contains(&thread_type_lower) {
                        return Some(thread_type.clone());
                    }
                }
            }
        }
        None
    }

    // Helper function to extract entity names from event summaries
    fn extract_entities_from_summaries(&self, summaries: &[&str]) -> Vec<String> {
        let mut entities = std::collections::HashSet::new();
        
        for summary in summaries {
            // Simple heuristic: look for capitalized words that might be entity names
            let words: Vec<&str> = summary.split_whitespace().collect();
            for window in words.windows(2) {
                if let [word1, word2] = window {
                    // Look for patterns like "Character Name" or single capitalized words
                    if word1.chars().next().map_or(false, |c| c.is_uppercase()) &&
                       word1.len() > 2 && !word1.ends_with('.') {
                        entities.insert(word1.to_string());
                    }
                    if word2.chars().next().map_or(false, |c| c.is_uppercase()) &&
                       word2.len() > 2 && !word2.ends_with('.') {
                        entities.insert(word2.to_string());
                    }
                }
            }
        }
        
        entities.into_iter().take(10).collect() // Limit to 10 entities per thread
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
            // Chronicle results
            QueryExecutionResult::ChronicleEvents(r) => r.tokens_used,
            QueryExecutionResult::ChronicleTimeline(r) => r.tokens_used,
            QueryExecutionResult::ChronicleThemes(r) => r.tokens_used,
            QueryExecutionResult::RelatedChronicles(r) => r.tokens_used,
            // Lorebook results
            QueryExecutionResult::LorebookEntries(r) => r.tokens_used,
            QueryExecutionResult::LorebookConcepts(r) => r.tokens_used,
            QueryExecutionResult::LorebookCharacters(r) => r.tokens_used,
            QueryExecutionResult::LorebookLocations(r) => r.tokens_used,
            QueryExecutionResult::LorebookContext(r) => r.tokens_used,
            // Entity existence results
            QueryExecutionResult::MissingEntities(r) => r.tokens_used,
        }
    }

    // Chronicle query execution methods
    async fn execute_chronicle_events_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let time_range = query.parameters.get("time_range")
            .and_then(|v| v.as_str())
            .unwrap_or("recent")
            .to_string();

        let max_events = query.parameters.get("max_events")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as usize;

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        // Use NarrativeQuery to search for relevant chronicle events
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: format!("Recent events and activities in chronicle: {}", time_range),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id,
            max_results: max_events,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Convert chronicle events to ChronicleEventSummary format
                let events: Vec<ChronicleEventSummary> = result.chronicle_events
                    .into_iter()
                    .map(|event| {
                        // Extract actors from event data
                        let actors = event.event_data
                            .as_ref()
                            .and_then(|data| data.get("actors"))
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_else(|| vec![event.user_id.to_string()]);

                        ChronicleEventSummary {
                            event_id: event.id,
                            summary: event.summary.clone(),
                            event_type: event.event_type,
                            actors,
                            timestamp: event.created_at,
                            narrative_impact: event.event_data
                                .as_ref()
                                .and_then(|data| data.get("narrative_impact"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("Standard event")
                                .to_string(),
                            relevance_score: 0.8, // Default relevance
                        }
                    })
                    .collect();

                // Extract event types from the events
                let event_types: Vec<String> = events
                    .iter()
                    .map(|e| e.event_type.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::ChronicleEvents(ChronicleEventsResult {
                    chronicle_id,
                    events,
                    event_types,
                    time_range,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(600)),
                }))
            }
            Err(e) => {
                debug!("Failed to query chronicle events: {}", e);
                // Return empty result on failure
                Ok(QueryExecutionResult::ChronicleEvents(ChronicleEventsResult {
                    chronicle_id,
                    events: Vec::new(),
                    event_types: Vec::new(),
                    time_range,
                    tokens_used: query.estimated_tokens.unwrap_or(600),
                }))
            }
        }
    }

    async fn execute_chronicle_timeline_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let max_events = query.parameters.get("max_events")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        // Use NarrativeQuery to get timeline events for the chronicle
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Chronicle timeline events with narrative significance and causal connections".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id,
            max_results: max_events,
            include_current_state: false,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Convert chronicle events to timeline format
                let mut timeline: Vec<ChronicleTimelineEvent> = result.chronicle_events
                    .into_iter()
                    .map(|event| {
                        // Extract involved entities from event data
                        let involved_entities = event.event_data
                            .as_ref()
                            .and_then(|data| data.get("entities"))
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_else(|| vec![]);

                        // Extract causal connections
                        let causal_connections = event.event_data
                            .as_ref()
                            .and_then(|data| data.get("causal_links"))
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_else(|| vec![]);

                        ChronicleTimelineEvent {
                            timestamp: event.created_at,
                            event_summary: event.summary.clone(),
                            narrative_significance: event.event_data
                                .as_ref()
                                .and_then(|data| data.get("narrative_significance"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("Standard event impact")
                                .to_string(),
                            involved_entities,
                            causal_connections,
                        }
                    })
                    .collect();

                // Sort by timestamp
                timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

                // Extract narrative arcs and themes from events
                let narrative_arcs: Vec<String> = timeline
                    .iter()
                    .filter_map(|event| {
                        if event.narrative_significance.contains("arc") || 
                           event.narrative_significance.contains("journey") {
                            Some(event.narrative_significance.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let major_themes: Vec<String> = timeline
                    .iter()
                    .filter_map(|event| {
                        if event.event_summary.contains("growth") {
                            Some("Growth".to_string())
                        } else if event.event_summary.contains("conflict") {
                            Some("Conflict".to_string())
                        } else if event.event_summary.contains("sacrifice") {
                            Some("Sacrifice".to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::ChronicleTimeline(ChronicleTimelineResult {
                    chronicle_id,
                    timeline,
                    narrative_arcs,
                    major_themes,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(800)),
                }))
            }
            Err(e) => {
                debug!("Failed to query chronicle timeline: {}", e);
                // Return empty result on failure
                Ok(QueryExecutionResult::ChronicleTimeline(ChronicleTimelineResult {
                    chronicle_id,
                    timeline: Vec::new(),
                    narrative_arcs: Vec::new(),
                    major_themes: Vec::new(),
                    tokens_used: query.estimated_tokens.unwrap_or(800),
                }))
            }
        }
    }

    async fn execute_chronicle_themes_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let focus_themes = query.parameters.get("focus_themes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        // Use NarrativeQuery to analyze thematic content
        let theme_query = if !focus_themes.is_empty() {
            format!("Thematic analysis focusing on: {}", focus_themes.join(", "))
        } else {
            "Chronicle thematic analysis: character development, relationships, and narrative themes".to_string()
        };

        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: theme_query,
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id,
            max_results: 30,
            include_current_state: false,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // Analyze events for thematic content
                let mut themes = Vec::new();
                let mut character_arcs = Vec::new();
                let mut plot_threads = Vec::new();

                // Extract themes from events
                for event in &result.chronicle_events {
                    // Look for thematic keywords in event descriptions
                    let description = &event.summary;
                    let event_data = &event.event_data;

                    if description.to_lowercase().contains("redemption") ||
                       description.to_lowercase().contains("forgiveness") {
                        themes.push(NarrativeTheme {
                            theme_name: "Redemption".to_string(),
                            description: "Characters seeking to make amends for past mistakes".to_string(),
                            examples: vec![description.clone()],
                            character_involvement: event_data
                                .as_ref()
                                .and_then(|data| data.get("actors"))
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default(),
                            strength: 0.8,
                        });
                    }

                    if description.to_lowercase().contains("growth") ||
                       description.to_lowercase().contains("learning") ||
                       description.to_lowercase().contains("development") {
                        themes.push(NarrativeTheme {
                            theme_name: "Growth".to_string(),
                            description: "Character development and personal growth".to_string(),
                            examples: vec![description.clone()],
                            character_involvement: event_data
                                .as_ref()
                                .and_then(|data| data.get("actors"))
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default(),
                            strength: 0.7,
                        });
                    }

                    if description.to_lowercase().contains("conflict") ||
                       description.to_lowercase().contains("battle") ||
                       description.to_lowercase().contains("struggle") {
                        themes.push(NarrativeTheme {
                            theme_name: "Conflict".to_string(),
                            description: "Struggles and conflicts between characters or forces".to_string(),
                            examples: vec![description.clone()],
                            character_involvement: event_data
                                .as_ref()
                                .and_then(|data| data.get("actors"))
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default(),
                            strength: 0.6,
                        });
                    }
                }

                // Deduplicate themes by name
                let mut unique_themes = std::collections::HashMap::new();
                for theme in themes {
                    let existing = unique_themes.entry(theme.theme_name.clone()).or_insert(theme.clone());
                    if theme.strength > existing.strength {
                        existing.strength = theme.strength;
                        existing.examples.extend(theme.examples);
                        existing.character_involvement.extend(theme.character_involvement);
                    }
                }
                let themes: Vec<NarrativeTheme> = unique_themes.into_values().collect();

                // Extract character arcs from entity contexts
                for entity_context in &result.entities {
                    if let Some(entity_name) = &entity_context.entity_name {
                        character_arcs.push(CharacterArc {
                            character_name: entity_name.clone(),
                            arc_description: format!("{}'s development through chronicle events", entity_name),
                            key_moments: vec!["Character introduction".to_string()],
                            development_stage: "Active".to_string(),
                            completion_level: 0.5, // Default progress
                        });
                    }
                }

                // Extract plot threads from event sequences
                if !result.chronicle_events.is_empty() {
                    plot_threads.push(PlotThread {
                        thread_name: "Main storyline".to_string(),
                        description: "Primary narrative thread".to_string(),
                        current_status: "Active".to_string(),
                        involved_entities: result.entities.iter()
                            .filter_map(|e| e.entity_name.clone())
                            .collect(),
                        next_developments: vec!["Story continuation".to_string()],
                    });
                    if result.chronicle_events.len() > 5 {
                        plot_threads.push(PlotThread {
                            thread_name: "Character development subplot".to_string(),
                            description: "Character growth and relationship development".to_string(),
                            current_status: "Developing".to_string(),
                            involved_entities: result.entities.iter()
                                .filter_map(|e| e.entity_name.clone())
                                .take(3)
                                .collect(),
                            next_developments: vec!["Relationship evolution".to_string()],
                        });
                    }
                }

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::ChronicleThemes(ChronicleThemesResult {
                    chronicle_id,
                    themes,
                    character_arcs,
                    plot_threads,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(700)),
                }))
            }
            Err(e) => {
                debug!("Failed to query chronicle themes: {}", e);
                // Return empty result on failure
                Ok(QueryExecutionResult::ChronicleThemes(ChronicleThemesResult {
                    chronicle_id,
                    themes: Vec::new(),
                    character_arcs: Vec::new(),
                    plot_threads: Vec::new(),
                    tokens_used: query.estimated_tokens.unwrap_or(700),
                }))
            }
        }
    }

    async fn execute_related_chronicles_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let base_chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let max_related = query.parameters.get("max_related")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        use crate::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions};

        // Query for entities and events to find relationships with other chronicles
        let hybrid_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Find related chronicles, shared characters, and connected storylines".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: base_chronicle_id,
            max_results: max_related,
            include_current_state: false,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => {
                // For now, create relationships based on shared entities
                // In a real implementation, this would query the database for actual chronicle relationships
                let mut related_chronicles = Vec::new();
                let mut shared_characters = std::collections::HashSet::new();
                let mut relationship_types = std::collections::HashSet::new();

                // Extract characters from current chronicle
                for entity_context in &result.entities {
                    if let Some(entity_name) = &entity_context.entity_name {
                        shared_characters.insert(entity_name.clone());
                    }
                }

                // If we found shared characters, create potential related chronicles
                if !shared_characters.is_empty() {
                    // This is a simplified implementation - in reality you'd query other chronicles
                    // that share these characters
                    for (i, character) in shared_characters.iter().take(3).enumerate() {
                        related_chronicles.push(ChronicleReference {
                            chronicle_id: Uuid::new_v4(),
                            title: format!("Adventures of {}", character),
                            relationship_type: if i == 0 { "sequel" } else if i == 1 { "prequel" } else { "parallel" }.to_string(),
                            shared_elements: vec![format!("Character: {}", character)],
                            relevance_score: 0.8 - (i as f32 * 0.1),
                        });
                    }
                }

                // Build relationship types from the relationships found
                for chronicle_ref in &related_chronicles {
                    relationship_types.insert(chronicle_ref.relationship_type.clone());
                }

                // Add common relationship types
                relationship_types.insert("sequel".to_string());
                relationship_types.insert("prequel".to_string());
                relationship_types.insert("parallel".to_string());
                relationship_types.insert("spin-off".to_string());

                let shared_elements: Vec<String> = vec![
                    "characters".to_string(),
                    "locations".to_string(),
                    "timeline".to_string(),
                    "themes".to_string(),
                ];

                let tokens_used = (result.performance.total_duration_ms / 10) as u32;

                Ok(QueryExecutionResult::RelatedChronicles(RelatedChroniclesResult {
                    related_chronicles,
                    relationship_types: relationship_types.into_iter().collect(),
                    shared_elements,
                    tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(500)),
                }))
            }
            Err(e) => {
                debug!("Failed to query related chronicles: {}", e);
                // Return empty result on failure
                Ok(QueryExecutionResult::RelatedChronicles(RelatedChroniclesResult {
                    related_chronicles: Vec::new(),
                    relationship_types: vec!["sequel".to_string(), "prequel".to_string()],
                    shared_elements: vec!["characters".to_string(), "locations".to_string()],
                    tokens_used: query.estimated_tokens.unwrap_or(500),
                }))
            }
        }
    }

    // Lorebook query execution methods
    async fn execute_lorebook_entries_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<QueryExecutionResult, AppError> {
        let _search_terms = query.parameters.get("search_terms")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let lorebook_id = query.parameters.get("lorebook_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let conn = self.db_pool.get().await?;

        // Query lorebook entries for the user with encrypted fields
        let entries_result = conn.interact(move |conn_sync| {
            let mut query = lorebook_entries::table
                .inner_join(lorebooks::table)
                .filter(lorebooks::user_id.eq(user_id))
                .select((
                    lorebook_entries::id, 
                    lorebook_entries::name, 
                    lorebook_entries::lorebook_id,
                    lorebook_entries::is_enabled, 
                    lorebook_entries::insertion_order,
                    lorebook_entries::entry_title_ciphertext,
                    lorebook_entries::entry_title_nonce,
                    lorebook_entries::keys_text_ciphertext,
                    lorebook_entries::keys_text_nonce,
                    lorebook_entries::content_ciphertext,
                    lorebook_entries::content_nonce,
                ))
                .into_boxed();

            if let Some(lb_id) = lorebook_id {
                query = query.filter(lorebook_entries::lorebook_id.eq(lb_id));
            }

            query.load::<(Uuid, Option<String>, Uuid, bool, i32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook entries: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load lorebook entries: {}", e)))?;

        // Convert to LorebookEntrySummary format with decryption if possible
        let entries: Vec<LorebookEntrySummary> = entries_result
            .into_iter()
            .filter_map(|(id, name, _lorebook_id, is_enabled, _order, title_ciphertext, title_nonce, keys_ciphertext, keys_nonce, content_ciphertext, content_nonce)| {
                if is_enabled {
                    // Attempt to decrypt title if available
                    let decrypted_title = if let Some(user_dek) = user_dek {
                        match self.encryption_service.decrypt(
                            &title_ciphertext,
                            &title_nonce,
                            user_dek.expose_secret()
                        ) {
                            Ok(decrypted_bytes) => {
                                String::from_utf8(decrypted_bytes).unwrap_or_else(|_| "Invalid title encoding".to_string())
                            },
                            Err(_) => "Encrypted title".to_string(),
                        }
                    } else {
                        name.unwrap_or_else(|| "Untitled Entry".to_string())
                    };

                    // Attempt to decrypt keywords if available  
                    let keywords = if let Some(user_dek) = user_dek {
                        match self.encryption_service.decrypt(
                            &keys_ciphertext,
                            &keys_nonce,
                            user_dek.expose_secret()
                        ) {
                            Ok(decrypted_bytes) => {
                                if let Ok(keys_text) = String::from_utf8(decrypted_bytes) {
                                    keys_text.split(',').map(|s| s.trim().to_string()).collect()
                                } else {
                                    vec![]
                                }
                            },
                            Err(_) => vec![],
                        }
                    } else {
                        vec![]
                    };

                    // Attempt to decrypt content for summary if available
                    let summary = if let Some(user_dek) = user_dek {
                        match self.encryption_service.decrypt(
                            &content_ciphertext,
                            &content_nonce,
                            user_dek.expose_secret()
                        ) {
                            Ok(decrypted_bytes) => {
                                if let Ok(content) = String::from_utf8(decrypted_bytes) {
                                    // Create a summary from the first 100 characters
                                    let truncated = if content.len() > 100 {
                                        format!("{}...", &content[..97])
                                    } else {
                                        content
                                    };
                                    truncated
                                } else {
                                    "Content decryption failed".to_string()
                                }
                            },
                            Err(_) => "Encrypted content".to_string(),
                        }
                    } else {
                        "Lorebook entry (content encrypted)".to_string()
                    };

                    Some(LorebookEntrySummary {
                        entry_id: id,
                        title: decrypted_title,
                        category: "General".to_string(), // Default category
                        summary,
                        keywords,
                        relevance_score: 0.7, // Default relevance
                    })
                } else {
                    None
                }
            })
            .collect();

        // Extract unique categories (simplified since we can't decrypt)
        let categories = vec!["General".to_string(), "Characters".to_string(), "Locations".to_string()];
        let entry_types = vec!["Concept".to_string(), "Character".to_string(), "Location".to_string()];

        Ok(QueryExecutionResult::LorebookEntries(LorebookEntriesResult {
            entries,
            categories,
            entry_types,
            relevance_threshold: 0.5,
            tokens_used: query.estimated_tokens.unwrap_or(600),
        }))
    }

    async fn execute_lorebook_concepts_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<QueryExecutionResult, AppError> {
        let category_filter = query.parameters.get("category")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.db_pool.get().await?;

        // Query lorebook entries that might be concepts
        let entries_result = conn.interact(move |conn_sync| {
            let query = lorebook_entries::table
                .inner_join(lorebooks::table)
                .filter(lorebooks::user_id.eq(user_id))
                .filter(lorebook_entries::is_enabled.eq(true))
                .select((lorebook_entries::id, lorebook_entries::name, lorebook_entries::insertion_order))
                .into_boxed();

            // If we had decrypted content, we could filter by category
            query.order(lorebook_entries::insertion_order.asc())
                .limit(20)
                .load::<(Uuid, Option<String>, i32)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook concepts: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load lorebook concepts: {}", e)))?;

        // Convert to ConceptSummary format
        let concepts: Vec<ConceptSummary> = entries_result
            .into_iter()
            .filter_map(|(id, name, _order)| {
                name.map(|n| ConceptSummary {
                    concept_name: n,
                    description: "Conceptual lorebook entry (content encrypted)".to_string(),
                    category: category_filter.clone().unwrap_or_else(|| "General".to_string()),
                    related_concepts: vec![], // Would need to analyze content
                    usage_examples: vec![], // Would need to analyze content
                    importance: 0.7, // Default importance
                })
            })
            .collect();

        let concept_types = vec!["Magic".to_string(), "Technology".to_string(), "Culture".to_string()];

        Ok(QueryExecutionResult::LorebookConcepts(LorebookConceptsResult {
            concepts,
            concept_types,
            relationships: vec![], // Would need content analysis
            tokens_used: query.estimated_tokens.unwrap_or(500),
        }))
    }

    async fn execute_lorebook_characters_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<QueryExecutionResult, AppError> {
        let character_type = query.parameters.get("character_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.db_pool.get().await?;

        // Query lorebook entries that might be characters
        let entries_result = conn.interact(move |conn_sync| {
            lorebook_entries::table
                .inner_join(lorebooks::table)
                .filter(lorebooks::user_id.eq(user_id))
                .filter(lorebook_entries::is_enabled.eq(true))
                .select((lorebook_entries::id, lorebook_entries::name, lorebook_entries::insertion_order))
                .order(lorebook_entries::insertion_order.asc())
                .limit(20)
                .load::<(Uuid, Option<String>, i32)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook characters: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load lorebook characters: {}", e)))?;

        // Convert to CharacterReference format
        let characters: Vec<CharacterReference> = entries_result
            .into_iter()
            .filter_map(|(id, name, _order)| {
                name.map(|n| CharacterReference {
                    character_name: n,
                    description: "Character lorebook entry (content encrypted)".to_string(),
                    role: character_type.clone().unwrap_or_else(|| "Unknown".to_string()),
                    relationships: vec![], // Would need content analysis
                    current_status: "Active".to_string(), // Default status
                    relevance_score: 0.7, // Default relevance
                })
            })
            .collect();

        let character_types = vec!["NPC".to_string(), "Historical Figure".to_string(), "Player Character".to_string()];
        let relationship_context = vec!["mentorship".to_string(), "family".to_string(), "rivalry".to_string()];

        Ok(QueryExecutionResult::LorebookCharacters(LorebookCharactersResult {
            characters,
            character_types,
            relationship_context,
            tokens_used: query.estimated_tokens.unwrap_or(550),
        }))
    }

    async fn execute_lorebook_locations_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<QueryExecutionResult, AppError> {
        let location_type = query.parameters.get("location_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.db_pool.get().await?;

        // Query lorebook entries that might be locations
        let entries_result = conn.interact(move |conn_sync| {
            lorebook_entries::table
                .inner_join(lorebooks::table)
                .filter(lorebooks::user_id.eq(user_id))
                .filter(lorebook_entries::is_enabled.eq(true))
                .select((lorebook_entries::id, lorebook_entries::name, lorebook_entries::insertion_order))
                .order(lorebook_entries::insertion_order.asc())
                .limit(20)
                .load::<(Uuid, Option<String>, i32)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook locations: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load lorebook locations: {}", e)))?;

        // Convert to LocationReference format
        let locations: Vec<LocationReference> = entries_result
            .into_iter()
            .filter_map(|(id, name, _order)| {
                name.map(|n| LocationReference {
                    location_name: n,
                    description: "Location lorebook entry (content encrypted)".to_string(),
                    location_type: location_type.clone().unwrap_or_else(|| "Unknown".to_string()),
                    contained_locations: vec![], // Would need content analysis
                    cultural_significance: "Unknown (content encrypted)".to_string(),
                    relevance_score: 0.7, // Default relevance
                })
            })
            .collect();

        let location_types = vec!["City".to_string(), "Dungeon".to_string(), "Region".to_string(), "Building".to_string()];
        let spatial_relationships = vec!["underground".to_string(), "coastal".to_string(), "mountain".to_string()];
        let cultural_context = vec!["sacred site".to_string(), "trade hub".to_string(), "military outpost".to_string()];

        Ok(QueryExecutionResult::LorebookLocations(LorebookLocationsResult {
            locations,
            location_types,
            spatial_relationships,
            cultural_context,
            tokens_used: query.estimated_tokens.unwrap_or(600),
        }))
    }

    async fn execute_lorebook_context_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<QueryExecutionResult, AppError> {
        let context_type = query.parameters.get("context_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let conn = self.db_pool.get().await?;

        // Query all enabled lorebook entries for context
        let entries_result = conn.interact(move |conn_sync| {
            lorebook_entries::table
                .inner_join(lorebooks::table)
                .filter(lorebooks::user_id.eq(user_id))
                .filter(lorebook_entries::is_enabled.eq(true))
                .select((lorebook_entries::id, lorebook_entries::name, 
                        lorebook_entries::is_constant, lorebook_entries::insertion_order))
                .order(lorebook_entries::insertion_order.asc())
                .limit(30)
                .load::<(Uuid, Option<String>, bool, i32)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook context: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load lorebook context: {}", e)))?;

        // Convert to ContextualEntry format
        let contextual_entries: Vec<ContextualEntry> = entries_result
            .into_iter()
            .filter_map(|(id, name, is_constant, _order)| {
                name.map(|n| ContextualEntry {
                    entry_title: n,
                    context_type: context_type.clone().unwrap_or_else(|| "General".to_string()),
                    description: "Contextual lorebook entry (content encrypted)".to_string(),
                    application_notes: if is_constant {
                        vec!["Always included in context".to_string()]
                    } else {
                        vec!["Conditionally included".to_string()]
                    },
                    related_entries: vec![], // Would need content analysis
                    relevance_score: if is_constant { 0.9 } else { 0.6 },
                })
            })
            .collect();

        let context_types = vec!["Cultural".to_string(), "Historical".to_string(), "Technical".to_string(), "Political".to_string()];
        let cultural_notes = vec!["Formal greeting customs".to_string(), "Social hierarchies".to_string()];
        let historical_context = vec!["Based on ancient traditions".to_string(), "Recent historical events".to_string()];

        Ok(QueryExecutionResult::LorebookContext(LorebookContextResult {
            contextual_entries,
            context_types,
            cultural_notes,
            historical_context,
            tokens_used: query.estimated_tokens.unwrap_or(650),
        }))
    }

    /// Detect entities mentioned in context that don't exist in the ECS system
    pub async fn detect_missing_entities(
        &self,
        entity_names: &[String],
        context_source: &str,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
    ) -> Result<MissingEntitiesResult, AppError> {
        let mut missing_entities = Vec::new();
        let mut total_tokens = 0u32;

        for entity_name in entity_names {
            // Check if entity exists in ECS by trying to query it
            let hybrid_query = crate::services::hybrid_query_service::HybridQuery {
                query_type: crate::services::hybrid_query_service::HybridQueryType::EntityTimeline {
                    entity_name: entity_name.clone(),
                    entity_id: None,
                    include_current_state: true,
                },
                user_id,
                chronicle_id,
                max_results: 1,
                include_current_state: true,
                include_relationships: false,
                options: crate::services::hybrid_query_service::HybridQueryOptions::default(),
            };

            match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
                Ok(result) => {
                    // Check if we found any actual entities
                    if result.entities.is_empty() || result.entities.iter().all(|e| e.entity_name.is_none()) {
                        // Entity doesn't exist - extract characteristics from context
                        let missing_entity = self.analyze_missing_entity(entity_name, context_source).await?;
                        missing_entities.push(missing_entity);
                    }
                    total_tokens += (result.performance.total_duration_ms / 10) as u32;
                }
                Err(_) => {
                    // Query failed, assume entity is missing
                    let missing_entity = self.analyze_missing_entity(entity_name, context_source).await?;
                    missing_entities.push(missing_entity);
                    total_tokens += 100; // Estimate for failed query
                }
            }
        }

        let creation_priority = if missing_entities.is_empty() {
            0.0
        } else {
            missing_entities.iter().map(|e| e.creation_confidence).sum::<f32>() / missing_entities.len() as f32
        };

        Ok(MissingEntitiesResult {
            missing_entities,
            source_context: context_source.to_string(),
            creation_priority,
            tokens_used: total_tokens,
        })
    }

    /// Analyze a missing entity from context to extract creation information
    async fn analyze_missing_entity(
        &self,
        entity_name: &str,
        context: &str,
    ) -> Result<MissingEntityInfo, AppError> {
        let mut character_traits = Vec::new();
        let mut location_details = Vec::new();
        let mut relationship_hints = Vec::new();
        let mut entity_type = None;

        // Simple pattern matching to extract entity characteristics
        // This could be enhanced with AI-powered analysis
        
        let context_lower = context.to_lowercase();
        let entity_lower = entity_name.to_lowercase();

        // Determine entity type based on context clues
        if context_lower.contains(&format!("{} says", entity_lower)) ||
           context_lower.contains(&format!("{} speaks", entity_lower)) ||
           context_lower.contains(&format!("{} thinks", entity_lower)) {
            entity_type = Some("Character".to_string());
        } else if context_lower.contains(&format!("in {}", entity_lower)) ||
                  context_lower.contains(&format!("at {}", entity_lower)) ||
                  context_lower.contains(&format!("location of {}", entity_lower)) {
            entity_type = Some("Location".to_string());
        }

        // Extract character traits
        if context_lower.contains("intelligent") || context_lower.contains("smart") || context_lower.contains("genius") {
            character_traits.push("High Intelligence".to_string());
        }
        if context_lower.contains("young") || context_lower.contains("child") || context_lower.contains("kid") {
            character_traits.push("Young Age".to_string());
        }
        if context_lower.contains("old") || context_lower.contains("elder") || context_lower.contains("ancient") {
            character_traits.push("Advanced Age".to_string());
        }
        if context_lower.contains("powerful") || context_lower.contains("strong") {
            character_traits.push("Physical/Mystical Power".to_string());
        }

        // Extract location details
        if entity_type.as_ref() == Some(&"Location".to_string()) {
            if context_lower.contains("temple") || context_lower.contains("sacred") {
                location_details.push("Religious/Sacred Site".to_string());
            }
            if context_lower.contains("palace") || context_lower.contains("castle") {
                location_details.push("Noble Residence".to_string());
            }
            if context_lower.contains("desert") || context_lower.contains("forest") || context_lower.contains("mountain") {
                location_details.push("Natural Environment".to_string());
            }
        }

        // Extract relationship hints
        if context_lower.contains("daughter") || context_lower.contains("son") {
            relationship_hints.push("Parent-Child Relationship".to_string());
        }
        if context_lower.contains("father") || context_lower.contains("mother") {
            relationship_hints.push("Parental Figure".to_string());
        }
        if context_lower.contains("master") || context_lower.contains("teacher") {
            relationship_hints.push("Mentor-Student Relationship".to_string());
        }
        if context_lower.contains("friend") || context_lower.contains("ally") {
            relationship_hints.push("Friendship/Alliance".to_string());
        }

        // Calculate creation confidence based on available information
        let mut confidence: f32 = 0.5; // Base confidence
        if entity_type.is_some() { confidence += 0.2; }
        if !character_traits.is_empty() { confidence += 0.1; }
        if !location_details.is_empty() { confidence += 0.1; }
        if !relationship_hints.is_empty() { confidence += 0.1; }
        confidence = confidence.min(1.0);

        Ok(MissingEntityInfo {
            entity_name: entity_name.to_string(),
            entity_type,
            mentioned_in_context: context.to_string(),
            character_traits,
            location_details,
            relationship_hints,
            creation_confidence: confidence,
        })
    }

    // Entity creation query execution methods
    async fn execute_missing_entities_query(
        &self,
        query: &PlannedQuery,
        user_id: Uuid,
    ) -> Result<QueryExecutionResult, AppError> {
        let chronicle_id = query.parameters.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let analysis_scope = query.parameters.get("analysis_scope")
            .and_then(|v| v.as_str())
            .unwrap_or("recent");

        let max_events = query.parameters.get("max_events")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as i64; // Reduced for AI processing

        let conn = self.db_pool.get().await?;

        // Query recent chronicle events to analyze for missing entities
        let events_result = conn.interact(move |conn_sync| {
            use crate::schema::chronicle_events;
            use diesel::prelude::*;

            let mut events_query = chronicle_events::table
                .filter(chronicle_events::user_id.eq(user_id))
                .select((
                    chronicle_events::id,
                    chronicle_events::summary,
                    chronicle_events::event_data,
                    chronicle_events::chronicle_id,
                ))
                .order(chronicle_events::created_at.desc())
                .limit(max_events)
                .into_boxed();

            if let Some(chron_id) = chronicle_id {
                events_query = events_query.filter(chronicle_events::chronicle_id.eq(chron_id));
            }

            events_query.load::<(Uuid, String, Option<serde_json::Value>, Uuid)>(conn_sync)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query chronicle events: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load chronicle events: {}", e)))?;

        // Prepare chronicle content for AI analysis
        let mut chronicle_content = String::new();
        for (_, summary, _, _) in &events_result {
            chronicle_content.push_str(&format!("Event: {}\n", summary));
        }

        if chronicle_content.is_empty() {
            return Ok(QueryExecutionResult::MissingEntities(MissingEntitiesResult {
                missing_entities: Vec::new(),
                source_context: "No chronicle events found".to_string(),
                creation_priority: 0.0,
                tokens_used: query.estimated_tokens.unwrap_or(300),
            }));
        }

        // Use Flash-Lite to intelligently extract entities from chronicle content
        let entity_extraction_prompt = format!(r#"Analyze the following chronicle events and extract any characters, locations, organizations, or important items that are mentioned but might not exist in a game database yet.

CHRONICLE CONTENT:
{}

For each entity you identify, provide:
1. Entity name
2. Entity type (Character/Location/Organization/Item)
3. Brief description based on context
4. Confidence level (0.0-1.0)

Respond with a JSON array:
[
  {{
    "name": "Entity Name",
    "type": "Character|Location|Organization|Item", 
    "description": "Brief description from context",
    "confidence": 0.8
  }}
]

Focus on:
- Named characters, even if mentioned briefly
- Specific locations (cities, buildings, regions)
- Organizations, factions, or groups
- Important items, artifacts, or objects
- Skip common words, pronouns, and generic terms

Only include entities with confidence >= 0.6"#, chronicle_content);

        let chat_request = genai::chat::ChatRequest::from_user(entity_extraction_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3); // Low temperature for consistent extraction

        let ai_response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17",
            chat_request,
            Some(chat_options),
        ).await?;

        // Extract text content from AI response
        let response_text = ai_response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Parse AI response to extract entities
        let mut missing_entities = Vec::new();
        let tokens_used = 400; // Estimated tokens for AI call

        if let Ok(extracted_entities) = serde_json::from_str::<Vec<serde_json::Value>>(&response_text) {
            for entity_value in extracted_entities {
                if let (Some(name), Some(entity_type), Some(description), Some(confidence)) = (
                    entity_value.get("name").and_then(|v| v.as_str()),
                    entity_value.get("type").and_then(|v| v.as_str()),
                    entity_value.get("description").and_then(|v| v.as_str()),
                    entity_value.get("confidence").and_then(|v| v.as_f64()),
                ) {
                    // Check if entity already exists using hybrid query service
                    let exists = self.check_entity_exists(name, user_id, chronicle_id).await;
                    
                    if !exists && confidence >= 0.6 {
                        missing_entities.push(MissingEntityInfo {
                            entity_name: name.to_string(),
                            entity_type: Some(entity_type.to_string()),
                            mentioned_in_context: description.to_string(),
                            character_traits: if entity_type == "Character" { 
                                vec!["AI-extracted character".to_string()] 
                            } else { 
                                Vec::new() 
                            },
                            location_details: if entity_type == "Location" { 
                                vec!["AI-extracted location".to_string()] 
                            } else { 
                                Vec::new() 
                            },
                            relationship_hints: Vec::new(), // Could be enhanced with additional AI analysis
                            creation_confidence: confidence as f32,
                        });
                    }
                }
            }
        } else {
            debug!("Failed to parse AI response for entity extraction: {}", response_text);
        }

        // Calculate creation priority based on AI confidence scores
        let creation_priority = if missing_entities.is_empty() {
            0.0
        } else {
            missing_entities.iter().map(|e| e.creation_confidence).sum::<f32>() / missing_entities.len() as f32
        };

        let source_context = format!("AI-analyzed {} chronicle events from {} using Flash-Lite", 
                                    events_result.len(), 
                                    analysis_scope);

        Ok(QueryExecutionResult::MissingEntities(MissingEntitiesResult {
            missing_entities,
            source_context,
            creation_priority,
            tokens_used: tokens_used.max(query.estimated_tokens.unwrap_or(400)),
        }))
    }


    /// Check if an entity already exists in the ECS system
    async fn check_entity_exists(&self, entity_name: &str, user_id: Uuid, chronicle_id: Option<Uuid>) -> bool {
        // Use the hybrid query service to check if the entity exists
        let hybrid_query = crate::services::hybrid_query_service::HybridQuery {
            query_type: crate::services::hybrid_query_service::HybridQueryType::EntityTimeline {
                entity_name: entity_name.to_string(),
                entity_id: None,
                include_current_state: false,
            },
            user_id,
            chronicle_id,
            max_results: 1,
            include_current_state: false,
            include_relationships: false,
            options: crate::services::hybrid_query_service::HybridQueryOptions::default(),
        };

        match self.hybrid_query_service.execute_hybrid_query(hybrid_query).await {
            Ok(result) => !result.entities.is_empty(),
            Err(_) => false, // Assume doesn't exist if query fails
        }
    }

}