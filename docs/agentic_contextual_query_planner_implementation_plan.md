# Agentic Contextual Query Planner Implementation Plan

## Overview

This document outlines the comprehensive implementation plan for the agentic contextual query planner that will enable intelligent, token-efficient context generation for our ECS-enhanced RAG pipeline. The system uses Gemini 2.5 Flash-Lite (gemini-2.5-flash-lite-preview-06-17) for all decision-making components, providing cost-effective and high-performance agentic loops.

## Architecture Overview

The agentic loop works as follows:
1. **Intent Detection** (gemini-2.5-flash-lite-preview-06-17) → Parse user query to understand what they want
2. **Query Strategy Planning** (gemini-2.5-flash-lite-preview-06-17) → Decide what ECS queries to execute  
3. **Context Assembly** → Execute queries and gather relevant entity data
4. **Context Optimization** (gemini-2.5-flash-lite-preview-06-17) → Filter and prioritize entities for token efficiency
5. **Final Prompt Generation** → Assemble optimized context for the main LLM

## Phase 1: Foundation - NLPQueryHandler with Flash-Lite Intent Detection

### Task 1.1: Create Intent Detection Service
**DoD**: Intent detection service correctly categorizes user queries with >90% accuracy on test cases

```rust
// backend/src/services/intent_detection_service.rs - New file

use std::sync::Arc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use tracing::{info, debug, instrument};

use crate::{
    llm::AiClient,
    errors::AppError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    pub intent_type: IntentType,
    pub focus_entities: Vec<EntityFocus>,
    pub time_scope: TimeScope,
    pub spatial_scope: Option<SpatialScope>,
    pub reasoning_depth: ReasoningDepth,
    pub context_priorities: Vec<ContextPriority>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentType {
    CausalAnalysis,      // "What caused X?"
    RelationshipQuery,   // "Who trusts Y?"
    StateInquiry,        // "Where is Z?"
    TemporalAnalysis,    // "What happened between T1 and T2?"
    SpatialAnalysis,     // "What's in location L?"
    PredictiveQuery,     // "What might happen if...?"
    NarrativeGeneration, // "Continue the story"
    ComparisonQuery,     // "How do X and Y differ?"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityFocus {
    pub entity_name: String,
    pub entity_type: Option<String>,
    pub priority: f32, // 0.0-1.0
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeScope {
    Current,
    Recent(Duration),
    Historical(DateTime<Utc>),
    Range(DateTime<Utc>, DateTime<Utc>),
    AllTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReasoningDepth {
    Surface,    // Just facts
    Analytical, // Include relationships
    Causal,     // Include causality
    Deep,       // Full reasoning chains
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextPriority {
    Entities,
    Relationships,
    RecentEvents,
    SpatialContext,
    CausalChains,
    TemporalState,
}

pub struct IntentDetectionService {
    ai_client: Arc<dyn AiClient>,
}

impl IntentDetectionService {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self), fields(query_len = query.len()))]
    pub async fn detect_intent(
        &self,
        user_query: &str,
        conversation_context: Option<&str>,
    ) -> Result<QueryIntent, AppError> {
        let prompt = self.build_intent_detection_prompt(user_query, conversation_context);
        
        info!("Detecting intent for query: {}", user_query);
        
        let response = self.ai_client.generate_text(
            &prompt,
            Some(1000), // Max tokens
            Some(0.1),  // Low temperature for consistent parsing
        ).await?;

        self.parse_intent_response(&response)
    }

    fn build_intent_detection_prompt(&self, query: &str, context: Option<&str>) -> String {
        let context_section = context.map_or(String::new(), |c| format!("Conversation Context:\n{}\n\n", c));
        
        format!(r#"You are an expert query intent analyzer for a narrative AI system. Analyze the user's query and determine their intent, focus entities, and context requirements.

{}User Query: "{}"

Analyze this query and respond with a JSON object containing:
1. intent_type: One of [CausalAnalysis, RelationshipQuery, StateInquiry, TemporalAnalysis, SpatialAnalysis, PredictiveQuery, NarrativeGeneration, ComparisonQuery]
2. focus_entities: Array of {{name: string, type?: string, priority: 0.0-1.0, required: boolean}}
3. time_scope: {{type: "Current"|"Recent"|"Historical"|"Range"|"AllTime", duration_hours?: number, start_time?: ISO8601, end_time?: ISO8601}}
4. spatial_scope?: {{location_name?: string, radius?: number, include_contained: boolean}}
5. reasoning_depth: "Surface"|"Analytical"|"Causal"|"Deep"
6. context_priorities: Array of [Entities, Relationships, RecentEvents, SpatialContext, CausalChains, TemporalState] in order of importance
7. confidence: 0.0-1.0

Examples:
- "What caused Luke to leave Tatooine?" → CausalAnalysis, focus_entities: [{{name: "Luke", priority: 1.0, required: true}}], reasoning_depth: "Causal"
- "Who is in the cantina right now?" → SpatialAnalysis + StateInquiry, spatial_scope: {{location_name: "cantina"}}, time_scope: "Current"
- "How do Vader and Obi-Wan feel about each other?" → RelationshipQuery, focus_entities: [{{name: "Vader", priority: 1.0}}, {{name: "Obi-Wan", priority: 1.0}}]

Respond with only the JSON object, no other text:"#, context_section, query)
    }

    fn parse_intent_response(&self, response: &str) -> Result<QueryIntent, AppError> {
        let cleaned = response.trim();
        serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse intent response: {}", e)))
    }
}
```

### Task 1.2: Create Intent Detection Tests
**DoD**: Comprehensive test suite with >20 test cases covering all intent types

```rust
// backend/tests/intent_detection_tests.rs - New file

use sanguine_scribe::services::intent_detection_service::*;
use sanguine_scribe::llm::MockAiClient;
use std::sync::Arc;

#[tokio::test]
async fn test_causal_analysis_intent() {
    let mut mock_client = MockAiClient::new();
    mock_client.expect_generate_text()
        .returning(|_, _, _| Ok(r#"{
            "intent_type": "CausalAnalysis",
            "focus_entities": [{"name": "Luke", "priority": 1.0, "required": true}],
            "time_scope": {"type": "Recent", "duration_hours": 24},
            "reasoning_depth": "Causal",
            "context_priorities": ["CausalChains", "Entities", "RecentEvents"],
            "confidence": 0.9
        }"#.to_string()));

    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("What caused Luke to leave?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::CausalAnalysis));
    assert_eq!(intent.focus_entities.len(), 1);
    assert_eq!(intent.focus_entities[0].name, "Luke");
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Causal));
}

#[tokio::test]
async fn test_spatial_analysis_intent() {
    // Test spatial queries...
}

#[tokio::test]
async fn test_relationship_query_intent() {
    // Test relationship queries...
}

// Add 15+ more test cases covering all IntentTypes
```

## Phase 2: Query Strategy Planning Service

### Task 2.1: Create Query Strategy Planner
**DoD**: Strategy planner generates optimized query plans for each intent type

```rust
// backend/src/services/query_strategy_planner.rs - New file

use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use tracing::{info, debug, instrument};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::intent_detection_service::QueryIntent,
    models::world_model::*,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStrategy {
    pub strategy_id: Uuid,
    pub intent: QueryIntent,
    pub query_plan: Vec<QueryStep>,
    pub estimated_entities: usize,
    pub context_budget: TokenBudget,
    pub execution_order: Vec<usize>, // Indexes into query_plan
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStep {
    pub step_id: Uuid,
    pub query_type: StrategyQueryType,
    pub parameters: serde_json::Value,
    pub priority: f32,
    pub estimated_results: usize,
    pub token_cost: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrategyQueryType {
    EntitySearch { names: Vec<String>, fuzzy: bool },
    RelationshipNetwork { entity_ids: Vec<Uuid>, depth: u32 },
    CausalChain { from_events: Vec<Uuid>, max_depth: u32 },
    SpatialContainment { location_id: Uuid, recursive: bool },
    TemporalEvents { time_range: (DateTime<Utc>, DateTime<Utc>) },
    StateAtTime { entity_ids: Vec<Uuid>, timestamp: DateTime<Utc> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudget {
    pub total_budget: usize,
    pub entity_budget: usize,
    pub relationship_budget: usize,
    pub event_budget: usize,
    pub reasoning_budget: usize,
}

pub struct QueryStrategyPlanner {
    ai_client: Arc<dyn AiClient>,
}

impl QueryStrategyPlanner {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self, intent))]
    pub async fn create_strategy(
        &self,
        intent: QueryIntent,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        context_budget: TokenBudget,
    ) -> Result<QueryStrategy, AppError> {
        info!("Creating query strategy for intent: {:?}", intent.intent_type);

        let strategy_prompt = self.build_strategy_planning_prompt(&intent, &context_budget);
        
        let response = self.ai_client.generate_text(
            &strategy_prompt,
            Some(2000),
            Some(0.1),
        ).await?;

        let query_plan = self.parse_strategy_response(&response)?;
        
        Ok(QueryStrategy {
            strategy_id: Uuid::new_v4(),
            intent,
            query_plan,
            estimated_entities: self.estimate_total_entities(&query_plan),
            context_budget,
            execution_order: self.optimize_execution_order(&query_plan),
        })
    }

    fn build_strategy_planning_prompt(&self, intent: &QueryIntent, budget: &TokenBudget) -> String {
        format!(r#"You are a query strategy planner for an ECS narrative system. Design an optimal query execution plan.

Intent Analysis:
- Type: {:?}
- Focus Entities: {:?}
- Time Scope: {:?}
- Reasoning Depth: {:?}
- Context Priorities: {:?}

Token Budget:
- Total: {} tokens
- Entities: {} tokens
- Relationships: {} tokens
- Events: {} tokens

Available Query Types:
1. EntitySearch - Find entities by name/type
2. RelationshipNetwork - Get entity relationships (specify depth)
3. CausalChain - Trace causality (specify max_depth)
4. SpatialContainment - Get entities in locations
5. TemporalEvents - Get events in time range
6. StateAtTime - Get entity state at specific time

Create a JSON query plan with steps ordered by dependency and priority:
{{
  "query_plan": [
    {{
      "query_type": "EntitySearch",
      "parameters": {{"names": ["entity1"], "fuzzy": true}},
      "priority": 1.0,
      "estimated_results": 5,
      "token_cost": 200
    }}
  ]
}}

Optimize for the intent type - focus queries on what the user actually needs to know."#,
            intent.intent_type,
            intent.focus_entities,
            intent.time_scope,
            intent.reasoning_depth,
            intent.context_priorities,
            budget.total_budget,
            budget.entity_budget,
            budget.relationship_budget,
            budget.event_budget,
        )
    }

    fn parse_strategy_response(&self, response: &str) -> Result<Vec<QueryStep>, AppError> {
        // Parse the AI response into QueryStep objects
        let parsed: serde_json::Value = serde_json::from_str(response.trim())?;
        let steps = parsed["query_plan"].as_array()
            .ok_or_else(|| AppError::SerializationError("Missing query_plan".to_string()))?;
        
        let mut query_steps = Vec::new();
        for step_value in steps {
            let step = QueryStep {
                step_id: Uuid::new_v4(),
                query_type: serde_json::from_value(step_value["query_type"].clone())?,
                parameters: step_value["parameters"].clone(),
                priority: step_value["priority"].as_f64().unwrap_or(0.5) as f32,
                estimated_results: step_value["estimated_results"].as_u64().unwrap_or(10) as usize,
                token_cost: step_value["token_cost"].as_u64().unwrap_or(100) as usize,
            };
            query_steps.push(step);
        }
        
        Ok(query_steps)
    }

    fn estimate_total_entities(&self, plan: &[QueryStep]) -> usize {
        plan.iter().map(|step| step.estimated_results).sum()
    }

    fn optimize_execution_order(&self, plan: &[QueryStep]) -> Vec<usize> {
        // Sort by priority (high to low), then by dependency
        let mut indexed_steps: Vec<(usize, &QueryStep)> = plan.iter().enumerate().collect();
        indexed_steps.sort_by(|a, b| b.1.priority.partial_cmp(&a.1.priority).unwrap());
        indexed_steps.into_iter().map(|(idx, _)| idx).collect()
    }
}
```

### Task 2.2: Create Query Strategy Tests
**DoD**: Strategy planner creates optimal plans for each intent type within token budgets

```rust
// backend/tests/query_strategy_tests.rs

#[tokio::test]
async fn test_causal_analysis_strategy() {
    // Test that causal analysis creates appropriate CausalChain queries
}

#[tokio::test]
async fn test_spatial_analysis_strategy() {
    // Test spatial queries use SpatialContainment appropriately
}

#[tokio::test]
async fn test_token_budget_compliance() {
    // Test that strategies respect token budgets
}
```

## Phase 3: Context Assembly Engine

### Task 3.1: Create Context Assembly Service
**DoD**: Context assembler executes query strategies and gathers relevant ECS data

```rust
// backend/src/services/context_assembly_service.rs - New file

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{info, debug, instrument, warn};

use crate::{
    errors::AppError,
    services::{
        query_strategy_planner::{QueryStrategy, QueryStep, StrategyQueryType},
        ecs_entity_manager::EcsEntityManager,
        hybrid_query_service::HybridQueryService,
        chronicle_service::ChronicleService,
    },
    models::world_model::*,
};

#[derive(Debug, Clone)]
pub struct AssembledContext {
    pub strategy_id: Uuid,
    pub entities: HashMap<Uuid, EntitySnapshot>,
    pub relationships: Vec<RelationshipSnapshot>,
    pub events: Vec<CausalEventSnapshot>,
    pub spatial_hierarchy: SpatialHierarchy,
    pub execution_metadata: ExecutionMetadata,
}

#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    pub steps_executed: usize,
    pub total_entities_found: usize,
    pub execution_time_ms: u64,
    pub token_usage: TokenUsage,
}

#[derive(Debug, Clone)]
pub struct TokenUsage {
    pub estimated_tokens: usize,
    pub entity_tokens: usize,
    pub relationship_tokens: usize,
    pub event_tokens: usize,
}

pub struct ContextAssemblyService {
    entity_manager: Arc<EcsEntityManager>,
    query_service: Arc<HybridQueryService>,
    chronicle_service: Arc<ChronicleService>,
}

impl ContextAssemblyService {
    pub fn new(
        entity_manager: Arc<EcsEntityManager>,
        query_service: Arc<HybridQueryService>,
        chronicle_service: Arc<ChronicleService>,
    ) -> Self {
        Self {
            entity_manager,
            query_service,
            chronicle_service,
        }
    }

    #[instrument(skip(self, strategy), fields(strategy_id = %strategy.strategy_id))]
    pub async fn assemble_context(
        &self,
        strategy: QueryStrategy,
        user_id: Uuid,
    ) -> Result<AssembledContext, AppError> {
        let start_time = std::time::Instant::now();
        info!("Assembling context for strategy: {}", strategy.strategy_id);

        let mut assembled = AssembledContext {
            strategy_id: strategy.strategy_id,
            entities: HashMap::new(),
            relationships: Vec::new(),
            events: Vec::new(),
            spatial_hierarchy: SpatialHierarchy::default(),
            execution_metadata: ExecutionMetadata {
                steps_executed: 0,
                total_entities_found: 0,
                execution_time_ms: 0,
                token_usage: TokenUsage {
                    estimated_tokens: 0,
                    entity_tokens: 0,
                    relationship_tokens: 0,
                    event_tokens: 0,
                },
            },
        };

        // Execute query steps in optimized order
        for step_idx in &strategy.execution_order {
            let step = &strategy.query_plan[*step_idx];
            match self.execute_query_step(step, user_id, &mut assembled).await {
                Ok(_) => {
                    assembled.execution_metadata.steps_executed += 1;
                    debug!("Completed query step: {:?}", step.query_type);
                }
                Err(e) => {
                    warn!("Query step failed: {:?}, error: {}", step.query_type, e);
                    // Continue with other steps
                }
            }
        }

        assembled.execution_metadata.execution_time_ms = start_time.elapsed().as_millis() as u64;
        assembled.execution_metadata.total_entities_found = assembled.entities.len();
        
        Ok(assembled)
    }

    async fn execute_query_step(
        &self,
        step: &QueryStep,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        match &step.query_type {
            StrategyQueryType::EntitySearch { names, fuzzy } => {
                self.execute_entity_search(names, *fuzzy, user_id, context).await
            }
            StrategyQueryType::RelationshipNetwork { entity_ids, depth } => {
                self.execute_relationship_network(entity_ids, *depth, user_id, context).await
            }
            StrategyQueryType::CausalChain { from_events, max_depth } => {
                self.execute_causal_chain(from_events, *max_depth, user_id, context).await
            }
            StrategyQueryType::SpatialContainment { location_id, recursive } => {
                self.execute_spatial_containment(*location_id, *recursive, user_id, context).await
            }
            StrategyQueryType::TemporalEvents { time_range } => {
                self.execute_temporal_events(time_range, user_id, context).await
            }
            StrategyQueryType::StateAtTime { entity_ids, timestamp } => {
                self.execute_state_at_time(entity_ids, *timestamp, user_id, context).await
            }
        }
    }

    async fn execute_entity_search(
        &self,
        names: &[String],
        fuzzy: bool,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for entity search
        for name in names {
            // Use entity manager to find entities by name
            if let Ok(entities) = self.entity_manager.search_entities_by_name(name, user_id, fuzzy).await {
                for entity in entities {
                    let snapshot = EntitySnapshot {
                        entity_id: entity.id,
                        archetype: entity.archetype_signature,
                        name: Some(name.clone()),
                        components: entity.components,
                        last_modified: entity.updated_at,
                        causal_influences: Vec::new(), // Will be filled by causal queries
                    };
                    context.entities.insert(entity.id, snapshot);
                }
            }
        }
        Ok(())
    }

    async fn execute_relationship_network(
        &self,
        entity_ids: &[Uuid],
        depth: u32,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for relationship network queries
        for entity_id in entity_ids {
            if let Ok(relationships) = self.entity_manager.get_entity_relationships(*entity_id, user_id, Some(depth)).await {
                for rel in relationships {
                    let snapshot = RelationshipSnapshot {
                        from_entity: rel.from_entity_id,
                        to_entity: rel.to_entity_id,
                        relationship_type: rel.relationship_type,
                        category: rel.relationship_data.get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown").to_string(),
                        strength: rel.relationship_data.get("strength")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.5) as f32,
                        metadata: rel.relationship_data,
                    };
                    context.relationships.push(snapshot);
                }
            }
        }
        Ok(())
    }

    async fn execute_causal_chain(
        &self,
        from_events: &[Uuid],
        max_depth: u32,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for causal chain tracing
        // This would use the enhanced causality tracking from chronicle events
        Ok(())
    }

    async fn execute_spatial_containment(
        &self,
        location_id: Uuid,
        recursive: bool,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for spatial containment queries
        Ok(())
    }

    async fn execute_temporal_events(
        &self,
        time_range: &(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for temporal event queries
        Ok(())
    }

    async fn execute_state_at_time(
        &self,
        entity_ids: &[Uuid],
        timestamp: chrono::DateTime<chrono::Utc>,
        user_id: Uuid,
        context: &mut AssembledContext,
    ) -> Result<(), AppError> {
        // Implementation for historical state reconstruction
        Ok(())
    }
}
```

## Phase 4: Context Optimization with Flash-Lite

### Task 4.1: Create Context Optimizer
**DoD**: Context optimizer reduces token usage by 40-60% while maintaining relevance

```rust
// backend/src/services/context_optimizer.rs - New file

use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tracing::{info, debug, instrument};
use uuid::Uuid;

use crate::{
    llm::AiClient,
    errors::AppError,
    services::{
        context_assembly_service::AssembledContext,
        intent_detection_service::QueryIntent,
    },
    models::world_model::*,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedContext {
    pub original_context: AssembledContext,
    pub optimized_entities: Vec<EntitySnapshot>,
    pub optimized_relationships: Vec<RelationshipSnapshot>,
    pub optimized_events: Vec<CausalEventSnapshot>,
    pub optimization_metadata: OptimizationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationMetadata {
    pub original_entity_count: usize,
    pub optimized_entity_count: usize,
    pub token_reduction_percent: f32,
    pub relevance_scores: HashMap<Uuid, f32>,
    pub optimization_reasoning: String,
}

pub struct ContextOptimizer {
    ai_client: Arc<dyn AiClient>,
}

impl ContextOptimizer {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self, context, intent))]
    pub async fn optimize_context(
        &self,
        context: AssembledContext,
        intent: &QueryIntent,
        target_token_budget: usize,
    ) -> Result<OptimizedContext, AppError> {
        info!("Optimizing context for intent: {:?}, target tokens: {}", intent.intent_type, target_token_budget);

        let optimization_prompt = self.build_optimization_prompt(&context, intent, target_token_budget);
        
        let response = self.ai_client.generate_text(
            &optimization_prompt,
            Some(3000),
            Some(0.1),
        ).await?;

        self.parse_optimization_response(context, &response).await
    }

    fn build_optimization_prompt(
        &self,
        context: &AssembledContext,
        intent: &QueryIntent,
        target_tokens: usize,
    ) -> String {
        let entity_summaries: Vec<String> = context.entities.iter()
            .map(|(id, entity)| format!("- {}: {} ({})", 
                entity.name.as_ref().unwrap_or(&id.to_string()),
                entity.archetype,
                entity.components.len()
            ))
            .collect();

        format!(r#"You are a context optimization expert. Reduce this narrative context to fit within {} tokens while maintaining maximum relevance for the user's query.

User Intent: {:?}
Focus Entities: {:?}
Reasoning Depth: {:?}

Current Context:
Entities ({} total):
{}

Relationships: {} total
Recent Events: {} total

Your task:
1. Identify the most relevant entities for answering the user's query
2. Score each entity's relevance (0.0-1.0)
3. Select entities that fit within the token budget
4. Prioritize based on the user's intent type and focus entities

Respond with JSON:
{{
  "selected_entities": [
    {{"entity_id": "uuid", "relevance_score": 0.95, "reasoning": "directly mentioned in query"}},
    {{"entity_id": "uuid", "relevance_score": 0.8, "reasoning": "key relationship to focus entity"}}
  ],
  "selected_relationships": ["uuid1", "uuid2"],
  "selected_events": ["uuid1", "uuid2"],
  "optimization_reasoning": "Focused on causal chain from X to Y, excluded distant entities",
  "estimated_tokens": 850
}}

Be aggressive in pruning - only include what's truly necessary to answer the user's question."#,
            target_tokens,
            intent.intent_type,
            intent.focus_entities,
            intent.reasoning_depth,
            context.entities.len(),
            entity_summaries.join("\n"),
            context.relationships.len(),
            context.events.len(),
        )
    }

    async fn parse_optimization_response(
        &self,
        original_context: AssembledContext,
        response: &str,
    ) -> Result<OptimizedContext, AppError> {
        let optimization: serde_json::Value = serde_json::from_str(response.trim())?;
        
        // Extract selected entities
        let selected_entities: Vec<EntitySnapshot> = optimization["selected_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| {
                let entity_id_str = item["entity_id"].as_str()?;
                let entity_id = Uuid::parse_str(entity_id_str).ok()?;
                original_context.entities.get(&entity_id).cloned()
            })
            .collect();

        // Calculate optimization metadata
        let token_reduction = if original_context.entities.len() > 0 {
            (1.0 - (selected_entities.len() as f32 / original_context.entities.len() as f32)) * 100.0
        } else {
            0.0
        };

        let relevance_scores: HashMap<Uuid, f32> = optimization["selected_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| {
                let entity_id = Uuid::parse_str(item["entity_id"].as_str()?).ok()?;
                let score = item["relevance_score"].as_f64()? as f32;
                Some((entity_id, score))
            })
            .collect();

        Ok(OptimizedContext {
            original_context,
            optimized_entities: selected_entities,
            optimized_relationships: Vec::new(), // TODO: Implement relationship filtering
            optimized_events: Vec::new(),        // TODO: Implement event filtering
            optimization_metadata: OptimizationMetadata {
                original_entity_count: original_context.entities.len(),
                optimized_entity_count: selected_entities.len(),
                token_reduction_percent: token_reduction,
                relevance_scores,
                optimization_reasoning: optimization["optimization_reasoning"]
                    .as_str()
                    .unwrap_or("No reasoning provided")
                    .to_string(),
            },
        })
    }
}
```

## Phase 5: Agentic Orchestrator

### Task 5.1: Create Main Agentic Service
**DoD**: Full agentic loop reduces context size by 50%+ while maintaining >95% relevance for queries

```rust
// backend/src/services/agentic_context_service.rs - New file

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Duration;
use tracing::{info, debug, instrument};

use crate::{
    errors::AppError,
    services::{
        intent_detection_service::{IntentDetectionService, QueryIntent},
        query_strategy_planner::{QueryStrategyPlanner, QueryStrategy, TokenBudget},
        context_assembly_service::{ContextAssemblyService, AssembledContext},
        context_optimizer::{ContextOptimizer, OptimizedContext},
    },
    models::world_model::*,
};

#[derive(Debug, Clone)]
pub struct AgenticContextRequest {
    pub user_query: String,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>,
    pub conversation_history: Option<String>,
    pub token_budget: TokenBudget,
    pub optimization_aggressive: bool,
}

#[derive(Debug, Clone)]
pub struct AgenticContextResponse {
    pub detected_intent: QueryIntent,
    pub query_strategy: QueryStrategy,
    pub optimized_context: OptimizedContext,
    pub llm_formatted_context: LLMWorldContext,
    pub processing_metadata: ProcessingMetadata,
}

#[derive(Debug, Clone)]
pub struct ProcessingMetadata {
    pub total_processing_time_ms: u64,
    pub intent_detection_time_ms: u64,
    pub strategy_planning_time_ms: u64,
    pub context_assembly_time_ms: u64,
    pub optimization_time_ms: u64,
    pub context_reduction_percent: f32,
}

pub struct AgenticContextService {
    intent_detection: Arc<IntentDetectionService>,
    strategy_planner: Arc<QueryStrategyPlanner>,
    context_assembly: Arc<ContextAssemblyService>,
    context_optimizer: Arc<ContextOptimizer>,
}

impl AgenticContextService {
    pub fn new(
        intent_detection: Arc<IntentDetectionService>,
        strategy_planner: Arc<QueryStrategyPlanner>,
        context_assembly: Arc<ContextAssemblyService>,
        context_optimizer: Arc<ContextOptimizer>,
    ) -> Self {
        Self {
            intent_detection,
            strategy_planner,
            context_assembly,
            context_optimizer,
        }
    }

    #[instrument(skip(self, request), fields(user_id = %request.user_id, query_len = request.user_query.len()))]
    pub async fn generate_contextual_response(
        &self,
        request: AgenticContextRequest,
    ) -> Result<AgenticContextResponse, AppError> {
        let total_start = std::time::Instant::now();
        info!("Starting agentic context generation for query: {}", request.user_query);

        // Step 1: Intent Detection
        let intent_start = std::time::Instant::now();
        let detected_intent = self.intent_detection.detect_intent(
            &request.user_query,
            request.conversation_history.as_deref(),
        ).await?;
        let intent_time = intent_start.elapsed().as_millis() as u64;
        debug!("Intent detected: {:?}", detected_intent.intent_type);

        // Step 2: Query Strategy Planning
        let strategy_start = std::time::Instant::now();
        let query_strategy = self.strategy_planner.create_strategy(
            detected_intent.clone(),
            request.user_id,
            request.chronicle_id,
            request.token_budget.clone(),
        ).await?;
        let strategy_time = strategy_start.elapsed().as_millis() as u64;
        debug!("Query strategy created with {} steps", query_strategy.query_plan.len());

        // Step 3: Context Assembly
        let assembly_start = std::time::Instant::now();
        let assembled_context = self.context_assembly.assemble_context(
            query_strategy.clone(),
            request.user_id,
        ).await?;
        let assembly_time = assembly_start.elapsed().as_millis() as u64;
        debug!("Context assembled: {} entities, {} relationships", 
               assembled_context.entities.len(), 
               assembled_context.relationships.len());

        // Step 4: Context Optimization
        let optimization_start = std::time::Instant::now();
        let target_tokens = if request.optimization_aggressive {
            request.token_budget.total_budget / 2 // Aggressive: use only 50% of budget
        } else {
            (request.token_budget.total_budget as f32 * 0.8) as usize // Conservative: 80%
        };

        let optimized_context = self.context_optimizer.optimize_context(
            assembled_context,
            &detected_intent,
            target_tokens,
        ).await?;
        let optimization_time = optimization_start.elapsed().as_millis() as u64;

        // Step 5: Format for LLM
        let llm_context = self.format_for_llm(&optimized_context, &detected_intent)?;

        let total_time = total_start.elapsed().as_millis() as u64;

        Ok(AgenticContextResponse {
            detected_intent,
            query_strategy,
            optimized_context: optimized_context.clone(),
            llm_formatted_context: llm_context,
            processing_metadata: ProcessingMetadata {
                total_processing_time_ms: total_time,
                intent_detection_time_ms: intent_time,
                strategy_planning_time_ms: strategy_time,
                context_assembly_time_ms: assembly_time,
                optimization_time_ms: optimization_time,
                context_reduction_percent: optimized_context.optimization_metadata.token_reduction_percent,
            },
        })
    }

    fn format_for_llm(
        &self,
        optimized_context: &OptimizedContext,
        intent: &QueryIntent,
    ) -> Result<LLMWorldContext, AppError> {
        // Convert optimized context to LLM-friendly format
        let entity_summaries: Vec<EntitySummary> = optimized_context.optimized_entities
            .iter()
            .map(|entity| EntitySummary {
                entity_id: entity.entity_id,
                name: entity.name.clone().unwrap_or_else(|| entity.entity_id.to_string()),
                entity_type: entity.archetype.clone(),
                current_state: "Active".to_string(), // TODO: Derive from components
                key_attributes: HashMap::new(),      // TODO: Extract from components
                recent_actions: Vec::new(),          // TODO: Extract from events
            })
            .collect();

        // TODO: Build relationship graph, causal chains, spatial context, etc.

        Ok(LLMWorldContext {
            entity_summaries,
            relationship_graph: RelationshipGraph {
                nodes: Vec::new(),
                edges: Vec::new(),
                clusters: Vec::new(),
            },
            causal_chains: Vec::new(),
            spatial_context: SpatialContext::default(),
            recent_changes: Vec::new(),
            reasoning_hints: self.generate_reasoning_hints(intent),
        })
    }

    fn generate_reasoning_hints(&self, intent: &QueryIntent) -> Vec<String> {
        match intent.intent_type {
            IntentType::CausalAnalysis => vec![
                "Look for cause-and-effect relationships between events".to_string(),
                "Consider both direct and indirect causation".to_string(),
                "Trace the timeline of events to understand causality".to_string(),
            ],
            IntentType::RelationshipQuery => vec![
                "Focus on the emotional and social connections between entities".to_string(),
                "Consider how relationships have changed over time".to_string(),
            ],
            IntentType::SpatialAnalysis => vec![
                "Pay attention to spatial relationships and locations".to_string(),
                "Consider who or what is present in the same space".to_string(),
            ],
            _ => vec!["Analyze the context carefully to provide an accurate response".to_string()],
        }
    }
}
```

## Phase 6: Integration & Testing

### Task 6.1: Integration with Existing RAG Pipeline
**DoD**: Agentic context service integrates seamlessly with existing prompt_builder.rs

```rust
// Modify backend/src/prompt_builder.rs to use agentic context

impl PromptBuilder {
    pub async fn build_prompt_with_agentic_context(
        &self,
        user_query: &str,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        agentic_service: &AgenticContextService,
    ) -> Result<String, AppError> {
        let agentic_request = AgenticContextRequest {
            user_query: user_query.to_string(),
            user_id,
            chronicle_id,
            conversation_history: None, // TODO: Extract from context
            token_budget: TokenBudget {
                total_budget: 4000,      // Adjust based on model
                entity_budget: 1500,
                relationship_budget: 1000,
                event_budget: 1000,
                reasoning_budget: 500,
            },
            optimization_aggressive: true,
        };

        let agentic_response = agentic_service.generate_contextual_response(agentic_request).await?;
        
        // Format the LLM context into the prompt
        let context_section = self.format_llm_context(&agentic_response.llm_formatted_context)?;
        
        Ok(format!("{}\n\n{}\n\nUser Query: {}", 
                  self.system_prompt, 
                  context_section, 
                  user_query))
    }
}
```

### Task 6.2: Comprehensive Test Suite
**DoD**: >90% test coverage with performance benchmarks

```rust
// backend/tests/agentic_integration_tests.rs

#[tokio::test]
async fn test_full_agentic_pipeline_causal_query() {
    // Test the complete flow from intent detection to optimized context
}

#[tokio::test]
async fn test_agentic_context_reduces_tokens_significantly() {
    // Verify token reduction meets targets (40-60% reduction)
}

#[tokio::test]
async fn test_agentic_maintains_query_relevance() {
    // Verify that optimization doesn't lose critical information
}

#[tokio::test]
async fn test_agentic_performance_benchmarks() {
    // Verify total processing time < 2000ms for complex queries
}
```

## Implementation Timeline

| Week | Phase | Key Deliverables | Success Criteria |
|------|-------|------------------|------------------|
| 1 | Intent Detection | Flash-Lite intent detection service | >90% accuracy on test cases |
| 2 | Query Strategy | Strategy planner with Flash-Lite | Optimal plans within token budgets |
| 3 | Context Assembly | Query execution engine | Assembles relevant ECS context |
| 4 | Context Optimization | Flash-Lite context pruning | 40-60% token reduction maintained |
| 5 | Agentic Orchestrator | Full pipeline integration | <2s end-to-end response time |
| 6 | Testing & Integration | RAG pipeline integration | >90% test coverage, production ready |

## Benefits of This Approach

1. **Cost-Effective**: Uses Flash-Lite for all agentic decisions (~$0.001 per query)
2. **Performance**: Complete pipeline under 2 seconds
3. **Token Efficiency**: 50%+ reduction in context size while maintaining relevance
4. **Scalable**: Each component can be optimized and scaled independently
5. **Flexible**: Easy to add new intent types and query strategies
6. **Testable**: Each phase has clear success criteria and comprehensive tests

This plan leverages Flash-Lite's speed and cost-effectiveness for all the agentic decision-making while building a sophisticated contextual query system that dramatically improves ECS context relevance and efficiency.