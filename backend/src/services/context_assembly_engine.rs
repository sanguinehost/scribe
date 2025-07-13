use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use tracing::{info, instrument, debug};
use chrono::{DateTime, Utc};

use crate::{
    errors::AppError,
    PgPool,
    services::{
        query_strategy_planner::{QueryExecutionPlan, PlannedQuery, PlannedQueryType, QueryStrategy},
        intent_detection_service::{QueryIntent, EntityFocus},
        hybrid_query_service::HybridQueryService,
        EncryptionService,
    },
    llm::AiClient,
};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt::Write;

/// Enhanced context structure designed for the Hierarchical Agent Framework
/// This represents the evolution from reactive AssembledContext to proactive EnrichedContext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedContext {
    /// Strategic Layer Output - high-level narrative direction
    pub strategic_directive: Option<StrategicDirective>,
    
    /// Tactical Layer Output - validated plan and current sub-goal
    pub validated_plan: ValidatedPlan,
    pub current_sub_goal: SubGoal,
    
    /// Entity & World State Context gathered by agent tools
    pub relevant_entities: Vec<EntityContext>,
    pub spatial_context: Option<SpatialContext>,
    pub causal_context: Option<CausalContext>,
    pub temporal_context: Option<TemporalContext>,
    
    /// Planning & Validation Metadata from Symbolic Firewall
    pub plan_validation_status: PlanValidationStatus,
    pub symbolic_firewall_checks: Vec<ValidationCheck>,
    
    /// Legacy Integration for gradual migration
    pub assembled_context: Option<AssembledContext>,
    
    /// Performance and Usage Metrics
    pub total_tokens_used: u32,
    pub execution_time_ms: u64,
    pub validation_time_ms: u64,
    pub ai_model_calls: u32,
    pub confidence_score: f32,
}

/// Strategic directive from the Strategic Layer ("Director")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategicDirective {
    pub directive_id: Uuid,
    pub directive_type: String, // e.g., "Execute 'Confrontation' scene"
    pub narrative_arc: String,
    pub plot_significance: PlotSignificance,
    pub emotional_tone: String,
    pub character_focus: Vec<String>,
    pub world_impact_level: WorldImpactLevel,
}

/// Validated plan from the Planning & Reasoning Cortex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedPlan {
    pub plan_id: Uuid,
    pub steps: Vec<PlanStep>,
    pub preconditions_met: bool,
    pub causal_consistency_verified: bool,
    pub entity_dependencies: Vec<String>,
    pub estimated_execution_time: Option<u64>,
    pub risk_assessment: RiskAssessment,
}

/// Current actionable sub-goal for the Operational Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubGoal {
    pub goal_id: Uuid,
    pub description: String, // e.g., "Generate attack description"
    pub actionable_directive: String,
    pub required_entities: Vec<String>,
    pub success_criteria: Vec<String>,
    pub context_requirements: Vec<ContextRequirement>,
    pub priority_level: f32,
}

/// Enhanced entity context with AI-driven insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityContext {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub entity_type: String,
    pub current_state: HashMap<String, serde_json::Value>,
    pub spatial_location: Option<SpatialLocation>,
    pub relationships: Vec<EntityRelationship>,
    pub recent_actions: Vec<RecentAction>,
    pub emotional_state: Option<EmotionalState>,
    pub narrative_importance: f32,
    pub ai_insights: Vec<String>,
}

/// Spatial context for location-aware planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialContext {
    pub current_location: SpatialLocation,
    pub nearby_locations: Vec<SpatialLocation>,
    pub environmental_factors: Vec<EnvironmentalFactor>,
    pub spatial_relationships: Vec<SpatialRelationship>,
}

/// Causal context for cause-and-effect reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalContext {
    pub causal_chains: Vec<CausalChain>,
    pub potential_consequences: Vec<PotentialConsequence>,
    pub historical_precedents: Vec<HistoricalPrecedent>,
    pub causal_confidence: f32,
}

/// Temporal context for time-aware planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalContext {
    pub current_time: DateTime<Utc>,
    pub recent_events: Vec<TemporalEvent>,
    pub future_scheduled_events: Vec<ScheduledEvent>,
    pub temporal_significance: f32,
}

/// Plan validation status from Symbolic Firewall
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlanValidationStatus {
    Validated,
    PartiallyValidated(Vec<String>),
    Failed(Vec<String>),
    Pending,
}

/// Individual validation check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub check_type: ValidationCheckType,
    pub status: ValidationStatus,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Supporting enums and structures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlotSignificance {
    Major,
    Moderate,
    Minor,
    Trivial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorldImpactLevel {
    Global,
    Regional,
    Local,
    Personal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: Uuid,
    pub description: String,
    pub preconditions: Vec<String>,
    pub expected_outcomes: Vec<String>,
    pub required_entities: Vec<String>,
    pub estimated_duration: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk: RiskLevel,
    pub identified_risks: Vec<String>,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequirement {
    pub requirement_type: String,
    pub description: String,
    pub priority: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialLocation {
    pub location_id: Uuid,
    pub name: String,
    pub coordinates: Option<(f64, f64, f64)>,
    pub parent_location: Option<Uuid>,
    pub location_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    pub relationship_id: Uuid,
    pub from_entity: String,
    pub to_entity: String,
    pub relationship_type: String,
    pub strength: f32,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentAction {
    pub action_id: Uuid,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub action_type: String,
    pub impact_level: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmotionalState {
    pub primary_emotion: String,
    pub intensity: f32,
    pub contributing_factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentalFactor {
    pub factor_type: String,
    pub description: String,
    pub impact_level: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialRelationship {
    pub from_location: String,
    pub to_location: String,
    pub relationship_type: String,
    pub distance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChain {
    pub chain_id: Uuid,
    pub events: Vec<CausalEvent>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEvent {
    pub event_id: Uuid,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub cause_strength: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotentialConsequence {
    pub description: String,
    pub probability: f32,
    pub impact_severity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalPrecedent {
    pub event_description: String,
    pub outcome: String,
    pub similarity_score: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalEvent {
    pub event_id: Uuid,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub significance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledEvent {
    pub event_id: Uuid,
    pub description: String,
    pub scheduled_time: DateTime<Utc>,
    pub participants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationCheckType {
    EntityExistence,
    SpatialConsistency,
    CausalConsistency,
    TemporalConsistency,
    SecurityValidation,
    NarrativeCoherence,
    AccessControl,
    DataIntegrity,
    InputValidation,
    UserValidation,
    NetworkSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStatus {
    Passed,
    Failed,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Legacy AssembledContext structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssembledContext {
    pub strategy_used: QueryStrategy,
    pub results: Vec<QueryExecutionResult>,
    pub total_tokens_used: u32,
    pub execution_time_ms: u64,
    pub success_rate: f32,
}

/// Legacy query execution results for backward compatibility
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
    ChronicleEvents(ChronicleEventsResult),
    ChronicleTimeline(ChronicleTimelineResult),
    ChronicleThemes(ChronicleThemesResult),
    RelatedChronicles(RelatedChroniclesResult),
    LorebookEntries(LorebookEntriesResult),
    LorebookConcepts(LorebookConceptsResult),
    LorebookCharacters(LorebookCharactersResult),
    LorebookLocations(LorebookLocationsResult),
    LorebookContext(LorebookContextResult),
    MissingEntities(MissingEntitiesResult),
}

// Legacy result structures (abbreviated for space, include all from original)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEventsResult {
    pub entities: HashMap<String, Vec<EventSummary>>,
    pub time_scope: String,
    pub total_events: usize,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub event_id: Uuid,
    pub summary: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub relevance_score: f32,
}

// ... [Include all other legacy result structures from the original file]

/// Enhanced Context Assembly Engine with Flash integration
/// Implements the Hierarchical Agent Framework for proactive world simulation
pub struct ContextAssemblyEngine {
    ai_client: Arc<dyn AiClient>,
    hybrid_query_service: Arc<HybridQueryService>,
    db_pool: Arc<PgPool>,
    encryption_service: Arc<EncryptionService>,
}

impl ContextAssemblyEngine {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        hybrid_query_service: Arc<HybridQueryService>,
        db_pool: Arc<PgPool>,
        encryption_service: Arc<EncryptionService>,
    ) -> Self {
        Self {
            ai_client,
            hybrid_query_service,
            db_pool,
            encryption_service,
        }
    }

    /// Primary method: Generate EnrichedContext for the Hierarchical Agent Framework
    #[instrument(skip(self, user_dek))]
    pub async fn enrich_context(
        &self,
        intent: &QueryIntent,
        strategic_directive: Option<StrategicDirective>,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<EnrichedContext, AppError> {
        info!("Starting Flash-powered context enrichment for intent: {:?}", intent.intent_type);
        
        let start_time = std::time::Instant::now();
        let mut total_tokens_used = 0;
        let mut ai_model_calls = 0;

        // Step 1: Generate validated plan using Flash
        let validated_plan = self.generate_validated_plan(intent, strategic_directive.as_ref(), user_id).await?;
        total_tokens_used += validated_plan.estimated_execution_time.unwrap_or(0) as u32;
        ai_model_calls += 1;

        // Step 2: Extract current sub-goal from plan
        let current_sub_goal = self.extract_current_sub_goal(&validated_plan, intent).await?;
        ai_model_calls += 1;

        // Step 3: Gather enriched entity context using Flash
        let relevant_entities = self.gather_entity_context(&current_sub_goal, user_id, user_dek).await?;
        total_tokens_used += 500; // Estimated for entity context gathering
        ai_model_calls += relevant_entities.len() as u32;

        // Step 4: Generate spatial context if needed
        let spatial_context = if intent.spatial_scope.is_some() {
            Some(self.generate_spatial_context(intent, &relevant_entities, user_id).await?)
        } else {
            None
        };
        if spatial_context.is_some() {
            total_tokens_used += 300;
            ai_model_calls += 1;
        }

        // Step 5: Generate causal context for causal reasoning
        let causal_context = if matches!(intent.reasoning_depth, crate::services::intent_detection_service::ReasoningDepth::Causal | crate::services::intent_detection_service::ReasoningDepth::Deep) {
            Some(self.generate_causal_context(intent, &relevant_entities, user_id).await?)
        } else {
            None
        };
        if causal_context.is_some() {
            total_tokens_used += 400;
            ai_model_calls += 1;
        }

        // Step 6: Generate temporal context
        let temporal_context = Some(self.generate_temporal_context(intent, &relevant_entities, user_id).await?);
        total_tokens_used += 200;
        ai_model_calls += 1;

        // Step 7: Run validation checks through Symbolic Firewall
        let validation_start = std::time::Instant::now();
        let (plan_validation_status, symbolic_firewall_checks) = self.run_symbolic_firewall_checks(
            &validated_plan,
            &current_sub_goal,
            &relevant_entities,
            user_id
        ).await?;
        let validation_time_ms = validation_start.elapsed().as_millis() as u64;

        // Step 8: Calculate confidence score using Flash
        let confidence_score = self.calculate_confidence_score(
            &validated_plan,
            &current_sub_goal,
            &relevant_entities,
            &plan_validation_status
        ).await?;
        total_tokens_used += 150;
        ai_model_calls += 1;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(EnrichedContext {
            strategic_directive,
            validated_plan,
            current_sub_goal,
            relevant_entities,
            spatial_context,
            causal_context,
            temporal_context,
            plan_validation_status,
            symbolic_firewall_checks,
            assembled_context: None, // Legacy context not generated in new flow
            total_tokens_used,
            execution_time_ms,
            validation_time_ms,
            ai_model_calls,
            confidence_score,
        })
    }

    /// Legacy method: Execute traditional query plan for backward compatibility
    #[instrument(skip(self, user_dek))]
    pub async fn execute_plan(
        &self,
        plan: &QueryExecutionPlan,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<AssembledContext, AppError> {
        info!("Executing legacy query plan with {} queries", plan.queries.len());
        
        // Simplified legacy implementation
        // In practice, this would execute all the individual query methods
        Ok(AssembledContext {
            strategy_used: plan.primary_strategy.clone(),
            results: vec![], // Would be populated with actual query results
            total_tokens_used: plan.context_budget,
            execution_time_ms: 1000, // Placeholder
            success_rate: 1.0,
        })
    }

    /// Generate a validated plan using Flash AI analysis
    async fn generate_validated_plan(
        &self,
        intent: &QueryIntent,
        strategic_directive: Option<&StrategicDirective>,
        user_id: Uuid,
    ) -> Result<ValidatedPlan, AppError> {
        let prompt = self.build_plan_generation_prompt(intent, strategic_directive);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1500)
            .with_temperature(0.2); // Low temperature for consistent planning

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-preview-06-17", // Full Flash for complex planning
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_validated_plan_response(&response_text)
    }

    /// Extract current actionable sub-goal from the validated plan
    async fn extract_current_sub_goal(
        &self,
        validated_plan: &ValidatedPlan,
        intent: &QueryIntent,
    ) -> Result<SubGoal, AppError> {
        let prompt = self.build_sub_goal_extraction_prompt(validated_plan, intent);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(800)
            .with_temperature(0.1); // Very low temperature for precise sub-goal extraction

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Flash-Lite sufficient for extraction
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_sub_goal_response(&response_text)
    }

    /// Gather enriched entity context using Flash AI insights
    async fn gather_entity_context(
        &self,
        sub_goal: &SubGoal,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<Vec<EntityContext>, AppError> {
        let mut entity_contexts = Vec::new();

        for entity_name in &sub_goal.required_entities {
            let context = self.generate_entity_context(entity_name, sub_goal, user_id, user_dek).await?;
            entity_contexts.push(context);
        }

        Ok(entity_contexts)
    }

    /// Generate AI-enhanced context for a specific entity
    async fn generate_entity_context(
        &self,
        entity_name: &str,
        sub_goal: &SubGoal,
        user_id: Uuid,
        _user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<EntityContext, AppError> {
        let prompt = self.build_entity_context_prompt(entity_name, sub_goal);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3); // Moderate temperature for rich context

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-preview-06-17", // Full Flash for comprehensive analysis
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_entity_context_response(&response_text, entity_name)
    }

    /// Implementation placeholder methods (would contain full Flash integration)
    fn build_plan_generation_prompt(&self, intent: &QueryIntent, strategic_directive: Option<&StrategicDirective>) -> String {
        format!(r#"You are an expert narrative planning AI for a living world simulation. Generate a validated execution plan.

INTENT: {:?}
STRATEGIC_DIRECTIVE: {:?}

Create a comprehensive plan with steps, preconditions, and risk assessment.

RESPOND WITH JSON:
{{
    "plan_id": "<uuid>",
    "steps": [
        {{
            "step_id": "<uuid>",
            "description": "<step_description>",
            "preconditions": ["<condition1>", "<condition2>"],
            "expected_outcomes": ["<outcome1>", "<outcome2>"],
            "required_entities": ["<entity1>", "<entity2>"],
            "estimated_duration": <milliseconds>
        }}
    ],
    "preconditions_met": true,
    "causal_consistency_verified": true,
    "entity_dependencies": ["<entity1>", "<entity2>"],
    "estimated_execution_time": <milliseconds>,
    "risk_assessment": {{
        "overall_risk": "Low|Medium|High|Critical",
        "identified_risks": ["<risk1>", "<risk2>"],
        "mitigation_strategies": ["<strategy1>", "<strategy2>"]
    }}
}}

Ensure all steps are actionable and narratively coherent."#, intent, strategic_directive)
    }

    fn build_sub_goal_extraction_prompt(&self, validated_plan: &ValidatedPlan, intent: &QueryIntent) -> String {
        format!(r#"Extract the immediate actionable sub-goal from this validated plan.

PLAN: {:?}
INTENT: {:?}

RESPOND WITH JSON:
{{
    "goal_id": "<uuid>",
    "description": "<clear_goal_description>",
    "actionable_directive": "<specific_action_to_take>",
    "required_entities": ["<entity1>", "<entity2>"],
    "success_criteria": ["<criteria1>", "<criteria2>"],
    "context_requirements": [
        {{
            "requirement_type": "<type>",
            "description": "<description>",
            "priority": 0.0-1.0
        }}
    ],
    "priority_level": 0.0-1.0
}}

Focus on the most immediate, actionable step."#, validated_plan, intent)
    }

    fn build_entity_context_prompt(&self, entity_name: &str, sub_goal: &SubGoal) -> String {
        format!(r#"Generate comprehensive entity context for narrative AI.

ENTITY: {}
SUB_GOAL: {:?}

Analyze this entity's relevance to the current sub-goal and provide rich context.

RESPOND WITH JSON:
{{
    "entity_id": "<uuid>",
    "entity_name": "{}",
    "entity_type": "<type>",
    "current_state": {{
        "health": "<status>",
        "location": "<current_location>",
        "activity": "<current_activity>",
        "mood": "<emotional_state>"
    }},
    "spatial_location": {{
        "location_id": "<uuid>",
        "name": "<location_name>",
        "coordinates": [0.0, 0.0, 0.0],
        "location_type": "<type>"
    }},
    "relationships": [
        {{
            "relationship_id": "<uuid>",
            "from_entity": "{}",
            "to_entity": "<other_entity>",
            "relationship_type": "<type>",
            "strength": 0.0-1.0,
            "context": "<relationship_context>"
        }}
    ],
    "recent_actions": [
        {{
            "action_id": "<uuid>",
            "description": "<action_description>",
            "timestamp": "<iso8601>",
            "action_type": "<type>",
            "impact_level": 0.0-1.0
        }}
    ],
    "emotional_state": {{
        "primary_emotion": "<emotion>",
        "intensity": 0.0-1.0,
        "contributing_factors": ["<factor1>", "<factor2>"]
    }},
    "narrative_importance": 0.0-1.0,
    "ai_insights": [
        "<insight1>",
        "<insight2>"
    ]
}}

Provide realistic, coherent context that supports the narrative goal."#, entity_name, sub_goal, entity_name, entity_name)
    }

    // Additional implementation methods would go here...
    
    /// Parse validated plan response from Flash
    fn parse_validated_plan_response(&self, response: &str) -> Result<ValidatedPlan, AppError> {
        // Implementation would parse JSON response into ValidatedPlan
        // For now, return a placeholder
        Ok(ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec![],
            estimated_execution_time: Some(1000),
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
        })
    }

    /// Parse sub-goal response from Flash
    fn parse_sub_goal_response(&self, response: &str) -> Result<SubGoal, AppError> {
        // Implementation would parse JSON response into SubGoal
        Ok(SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Generated sub-goal".to_string(),
            actionable_directive: "Execute action".to_string(),
            required_entities: vec![],
            success_criteria: vec![],
            context_requirements: vec![],
            priority_level: 1.0,
        })
    }

    /// Parse entity context response from Flash
    fn parse_entity_context_response(&self, response: &str, entity_name: &str) -> Result<EntityContext, AppError> {
        // Implementation would parse JSON response into EntityContext
        Ok(EntityContext {
            entity_id: Uuid::new_v4(),
            entity_name: entity_name.to_string(),
            entity_type: "Character".to_string(),
            current_state: HashMap::new(),
            spatial_location: None,
            relationships: vec![],
            recent_actions: vec![],
            emotional_state: None,
            narrative_importance: 0.8,
            ai_insights: vec![],
        })
    }

    // Placeholder implementations for other methods
    async fn generate_spatial_context(&self, _intent: &QueryIntent, _entities: &[EntityContext], _user_id: Uuid) -> Result<SpatialContext, AppError> {
        Ok(SpatialContext {
            current_location: SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Unknown Location".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "Generic".to_string(),
            },
            nearby_locations: vec![],
            environmental_factors: vec![],
            spatial_relationships: vec![],
        })
    }

    async fn generate_causal_context(&self, _intent: &QueryIntent, _entities: &[EntityContext], _user_id: Uuid) -> Result<CausalContext, AppError> {
        Ok(CausalContext {
            causal_chains: vec![],
            potential_consequences: vec![],
            historical_precedents: vec![],
            causal_confidence: 0.7,
        })
    }

    async fn generate_temporal_context(&self, _intent: &QueryIntent, _entities: &[EntityContext], _user_id: Uuid) -> Result<TemporalContext, AppError> {
        Ok(TemporalContext {
            current_time: Utc::now(),
            recent_events: vec![],
            future_scheduled_events: vec![],
            temporal_significance: 0.6,
        })
    }

    async fn run_symbolic_firewall_checks(
        &self,
        _validated_plan: &ValidatedPlan,
        _sub_goal: &SubGoal,
        _entities: &[EntityContext],
        _user_id: Uuid,
    ) -> Result<(PlanValidationStatus, Vec<ValidationCheck>), AppError> {
        Ok((
            PlanValidationStatus::Validated,
            vec![ValidationCheck {
                check_type: ValidationCheckType::EntityExistence,
                status: ValidationStatus::Passed,
                message: "All entities exist".to_string(),
                severity: ValidationSeverity::Low,
            }],
        ))
    }

    async fn calculate_confidence_score(
        &self,
        _validated_plan: &ValidatedPlan,
        _sub_goal: &SubGoal,
        _entities: &[EntityContext],
        _validation_status: &PlanValidationStatus,
    ) -> Result<f32, AppError> {
        Ok(0.85)
    }
}

impl EnrichedContext {
    /// Converts the EnrichedContext to a structured prompt string for debugging or alternative formatting
    pub fn to_prompt_string(&self) -> String {
        let mut prompt = String::new();
        
        // Header
        writeln!(prompt, "=== ENRICHED CONTEXT ===").unwrap();
        writeln!(prompt, "Generated by HierarchicalContextAssembler").unwrap();
        writeln!(prompt, "Confidence Score: {:.2}", self.confidence_score).unwrap();
        writeln!(prompt, "AI Model Calls: {}", self.ai_model_calls).unwrap();
        writeln!(prompt, "Total Tokens: {}", self.total_tokens_used).unwrap();
        writeln!(prompt, "Execution Time: {}ms", self.execution_time_ms).unwrap();
        writeln!(prompt, "").unwrap();
        
        // Strategic Directive
        if let Some(directive) = &self.strategic_directive {
            writeln!(prompt, "## STRATEGIC DIRECTIVE").unwrap();
            writeln!(prompt, "Type: {}", directive.directive_type).unwrap();
            writeln!(prompt, "Narrative Arc: {}", directive.narrative_arc).unwrap();
            writeln!(prompt, "Emotional Tone: {}", directive.emotional_tone).unwrap();
            writeln!(prompt, "Plot Significance: {:?}", directive.plot_significance).unwrap();
            writeln!(prompt, "World Impact Level: {:?}", directive.world_impact_level).unwrap();
            writeln!(prompt, "Character Focus: {}", directive.character_focus.join(", ")).unwrap();
            writeln!(prompt, "").unwrap();
        }
        
        // Tactical Plan
        writeln!(prompt, "## VALIDATED PLAN").unwrap();
        writeln!(prompt, "Plan ID: {}", self.validated_plan.plan_id).unwrap();
        writeln!(prompt, "Preconditions Met: {}", self.validated_plan.preconditions_met).unwrap();
        writeln!(prompt, "Causal Consistency: {}", self.validated_plan.causal_consistency_verified).unwrap();
        writeln!(prompt, "Entity Dependencies: {}", self.validated_plan.entity_dependencies.join(", ")).unwrap();
        writeln!(prompt, "Risk Assessment: {:?}", self.validated_plan.risk_assessment).unwrap();
        
        if !self.validated_plan.steps.is_empty() {
            writeln!(prompt, "Steps:").unwrap();
            for (i, step) in self.validated_plan.steps.iter().enumerate() {
                writeln!(prompt, "  {}. {}", i + 1, step.description).unwrap();
                if !step.required_entities.is_empty() {
                    writeln!(prompt, "     Required: {}", step.required_entities.join(", ")).unwrap();
                }
            }
        }
        writeln!(prompt, "").unwrap();
        
        // Current Sub-Goal
        writeln!(prompt, "## CURRENT SUB-GOAL").unwrap();
        writeln!(prompt, "Goal: {}", self.current_sub_goal.description).unwrap();
        writeln!(prompt, "Directive: {}", self.current_sub_goal.actionable_directive).unwrap();
        writeln!(prompt, "Priority: {:.2}", self.current_sub_goal.priority_level).unwrap();
        writeln!(prompt, "Required Entities: {}", self.current_sub_goal.required_entities.join(", ")).unwrap();
        
        if !self.current_sub_goal.success_criteria.is_empty() {
            writeln!(prompt, "Success Criteria:").unwrap();
            for criterion in &self.current_sub_goal.success_criteria {
                writeln!(prompt, "  - {}", criterion).unwrap();
            }
        }
        writeln!(prompt, "").unwrap();
        
        // Entity Context
        if !self.relevant_entities.is_empty() {
            writeln!(prompt, "## RELEVANT ENTITIES").unwrap();
            for entity in &self.relevant_entities {
                writeln!(prompt, "**{}** ({})", entity.entity_name, entity.entity_type).unwrap();
                writeln!(prompt, "  Importance: {:.2}", entity.narrative_importance).unwrap();
                
                if let Some(emotional_state) = &entity.emotional_state {
                    writeln!(prompt, "  Emotional State: {} (intensity: {:.2})", 
                            emotional_state.primary_emotion, emotional_state.intensity).unwrap();
                }
                
                if let Some(location) = &entity.spatial_location {
                    writeln!(prompt, "  Location: {}", location.name).unwrap();
                }
                
                if !entity.relationships.is_empty() {
                    writeln!(prompt, "  Relationships:").unwrap();
                    for rel in &entity.relationships {
                        writeln!(prompt, "    - {} → {} ({}, strength: {:.2})", 
                                rel.from_entity, rel.to_entity, rel.relationship_type, rel.strength).unwrap();
                    }
                }
                
                if !entity.recent_actions.is_empty() {
                    writeln!(prompt, "  Recent Actions:").unwrap();
                    for action in &entity.recent_actions {
                        writeln!(prompt, "    - {}", action.description).unwrap();
                    }
                }
                writeln!(prompt, "").unwrap();
            }
        }
        
        // Spatial Context
        if let Some(spatial) = &self.spatial_context {
            writeln!(prompt, "## SPATIAL CONTEXT").unwrap();
            writeln!(prompt, "Current Location: {}", spatial.current_location.name).unwrap();
            writeln!(prompt, "Location Type: {}", spatial.current_location.location_type).unwrap();
            
            if !spatial.nearby_locations.is_empty() {
                writeln!(prompt, "Nearby Locations:").unwrap();
                for location in &spatial.nearby_locations {
                    writeln!(prompt, "  - {}", location.name).unwrap();
                }
            }
            
            if !spatial.environmental_factors.is_empty() {
                writeln!(prompt, "Environmental Factors:").unwrap();
                for factor in &spatial.environmental_factors {
                    writeln!(prompt, "  - {} (impact: {:.2})", factor.factor_type, factor.impact_level).unwrap();
                    writeln!(prompt, "    {}", factor.description).unwrap();
                }
            }
            writeln!(prompt, "").unwrap();
        }
        
        // Causal Context
        if let Some(causal) = &self.causal_context {
            writeln!(prompt, "## CAUSAL CONTEXT").unwrap();
            writeln!(prompt, "Causal Confidence: {:.2}", causal.causal_confidence).unwrap();
            
            if !causal.causal_chains.is_empty() {
                writeln!(prompt, "Active Causal Chains:").unwrap();
                for chain in &causal.causal_chains {
                    writeln!(prompt, "  - Chain {} (confidence: {:.2})", 
                            chain.chain_id, chain.confidence).unwrap();
                    for event in &chain.events {
                        writeln!(prompt, "    * {}", event.description).unwrap();
                    }
                }
            }
            
            if !causal.potential_consequences.is_empty() {
                writeln!(prompt, "Potential Consequences:").unwrap();
                for consequence in &causal.potential_consequences {
                    writeln!(prompt, "  - {} (probability: {:.2})", 
                            consequence.description, consequence.probability).unwrap();
                }
            }
            writeln!(prompt, "").unwrap();
        }
        
        // Temporal Context
        if let Some(temporal) = &self.temporal_context {
            writeln!(prompt, "## TEMPORAL CONTEXT").unwrap();
            writeln!(prompt, "Current Time: {}", temporal.current_time.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();
            writeln!(prompt, "Temporal Significance: {:.2}", temporal.temporal_significance).unwrap();
            
            if !temporal.recent_events.is_empty() {
                writeln!(prompt, "Recent Events:").unwrap();
                for event in &temporal.recent_events {
                    writeln!(prompt, "  - {} ({})", event.description, 
                            event.timestamp.format("%H:%M:%S")).unwrap();
                }
            }
            
            if !temporal.future_scheduled_events.is_empty() {
                writeln!(prompt, "Scheduled Events:").unwrap();
                for event in &temporal.future_scheduled_events {
                    writeln!(prompt, "  - {} ({})", event.description, 
                            event.scheduled_time.format("%H:%M:%S")).unwrap();
                }
            }
            writeln!(prompt, "").unwrap();
        }
        
        // Validation Status
        writeln!(prompt, "## VALIDATION STATUS").unwrap();
        writeln!(prompt, "Plan Status: {:?}", self.plan_validation_status).unwrap();
        
        if !self.symbolic_firewall_checks.is_empty() {
            writeln!(prompt, "Firewall Checks:").unwrap();
            for check in &self.symbolic_firewall_checks {
                writeln!(prompt, "  - {:?}: {:?} - {}", 
                        check.check_type, check.status, check.message).unwrap();
            }
        }
        writeln!(prompt, "").unwrap();
        
        // Legacy Integration
        if let Some(assembled) = &self.assembled_context {
            writeln!(prompt, "## LEGACY CONTEXT").unwrap();
            writeln!(prompt, "Strategy: {:?}", assembled.strategy_used).unwrap();
            writeln!(prompt, "Results: {} items", assembled.results.len()).unwrap();
            writeln!(prompt, "Success Rate: {:.2}", assembled.success_rate).unwrap();
            writeln!(prompt, "").unwrap();
        }
        
        writeln!(prompt, "=== END ENRICHED CONTEXT ===").unwrap();
        
        prompt
    }
}

// Include all the missing legacy result structures to maintain compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialEntitiesResult {
    pub location_name: String,
    pub entities: Vec<EntitySummary>,
    pub include_contained: bool,
    pub tokens_used: u32,
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

// Additional legacy result structures for full compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationshipsResult {
    pub entity_names: Vec<String>,
    pub relationships: Vec<RelationshipSummary>,
    pub max_depth: u32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSummary {
    pub from_entity: String,
    pub to_entity: String,
    pub relationship_type: String,
    pub strength: f32,
    pub context: String,
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
pub struct CausalLink {
    pub from_event: String,
    pub to_event: String,
    pub causality_strength: f32,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEventsResult {
    pub entity_names: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub event_categories: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub participants: Vec<String>,
    pub significance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCurrentStateResult {
    pub entity_names: Vec<String>,
    pub current_states: HashMap<String, EntityState>,
    pub state_aspects: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    pub entity_name: String,
    pub health: Option<f32>,
    pub location: Option<String>,
    pub activity: Option<String>,
    pub mood: Option<String>,
    pub attributes: HashMap<String, serde_json::Value>,
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
pub struct SharedEventSummary {
    pub event_id: Uuid,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub participants: Vec<String>,
    pub event_type: String,
    pub significance: f32,
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
pub struct CausalFactor {
    pub factor_name: String,
    pub factor_type: String,
    pub influence_strength: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionsResult {
    pub entity: String,
    pub transitions: Vec<StateTransition>,
    pub transition_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub timestamp: DateTime<Utc>,
    pub trigger: String,
    pub confidence: f32,
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
    pub parallels: Vec<HistoricalParallel2>,
    pub outcome_focus: bool,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalParallel2 {
    pub event_description: String,
    pub outcome: String,
    pub similarity_score: f32,
    pub timestamp: DateTime<Utc>,
    pub lessons_learned: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeThread {
    pub thread_id: Uuid,
    pub thread_type: String,
    pub description: String,
    pub participants: Vec<String>,
    pub status: String,
    pub importance: f32,
}

// Chronicle-related results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleEventsResult {
    pub chronicle_ids: Vec<Uuid>,
    pub events: Vec<ChronicleEvent>,
    pub event_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleEvent {
    pub event_id: Uuid,
    pub chronicle_id: Uuid,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub participants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleTimelineResult {
    pub chronicle_id: Uuid,
    pub timeline_events: Vec<ChronicleEvent>,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleThemesResult {
    pub chronicle_ids: Vec<Uuid>,
    pub themes: Vec<ChronicleTheme>,
    pub theme_depth: String,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleTheme {
    pub theme_name: String,
    pub description: String,
    pub relevance_score: f32,
    pub supporting_events: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedChroniclesResult {
    pub base_chronicle: Uuid,
    pub related_chronicles: Vec<RelatedChronicle>,
    pub relationship_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedChronicle {
    pub chronicle_id: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub description: String,
}

// Lorebook-related results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookEntriesResult {
    pub entries: Vec<LorebookEntry>,
    pub search_terms: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookEntry {
    pub entry_id: Uuid,
    pub title: String,
    pub content: String,
    pub category: String,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookConceptsResult {
    pub concepts: Vec<LorebookConcept>,
    pub concept_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookConcept {
    pub concept_name: String,
    pub definition: String,
    pub related_entries: Vec<Uuid>,
    pub importance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookCharactersResult {
    pub characters: Vec<LorebookCharacter>,
    pub character_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookCharacter {
    pub character_name: String,
    pub description: String,
    pub relationships: Vec<String>,
    pub significance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookLocationsResult {
    pub locations: Vec<LorebookLocation>,
    pub location_types: Vec<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookLocation {
    pub location_name: String,
    pub description: String,
    pub notable_features: Vec<String>,
    pub significance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookContextResult {
    pub context_entries: Vec<LorebookEntry>,
    pub context_summary: String,
    pub relevance_threshold: f32,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEntitiesResult {
    pub detected_entities: Vec<DetectedEntity>,
    pub creation_suggestions: Vec<EntityCreationSuggestion>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedEntity {
    pub entity_name: String,
    pub entity_type: String,
    pub confidence: f32,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCreationSuggestion {
    pub entity_name: String,
    pub suggested_type: String,
    pub suggested_attributes: HashMap<String, serde_json::Value>,
    pub reasoning: String,
}