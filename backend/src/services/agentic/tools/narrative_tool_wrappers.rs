//! Self-Registering Narrative Tool Wrappers
//!
//! This module provides wrapper implementations that make the AI-driven narrative
//! tools compatible with the unified tool registry system by implementing the
//! SelfRegisteringTool trait.

use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};

use crate::{
    errors::AppError,
    auth::session_dek::SessionDek,
    services::{ChronicleService, LorebookService},
    state::AppState,
    services::agentic::{
        tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        unified_tool_registry::{
            SelfRegisteringTool, UnifiedToolRegistry, ToolMetadata, ToolCategory, 
            ToolCapability, ToolExample, ToolSecurityPolicy, AgentType, 
            DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime,
        },
        narrative_tools::{
            AnalyzeTextSignificanceTool, CreateChronicleEventTool, CreateLorebookEntryTool,
            ExtractTemporalEventsTool, ExtractWorldConceptsTool, SearchKnowledgeBaseTool,
            UpdateLorebookEntryTool,
        },
    },
};

/// Self-registering wrapper for AnalyzeTextSignificanceTool
pub struct AnalyzeTextSignificanceToolWrapper {
    inner: AnalyzeTextSignificanceTool,
}

impl AnalyzeTextSignificanceToolWrapper {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            inner: AnalyzeTextSignificanceTool::new(app_state),
        }
    }
}

#[async_trait]
impl ScribeTool for AnalyzeTextSignificanceToolWrapper {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn input_schema(&self) -> JsonValue {
        self.inner.input_schema()
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        self.inner.execute(params, session_dek).await
    }
}

#[async_trait]
impl SelfRegisteringTool for AnalyzeTextSignificanceToolWrapper {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "analyze".to_string(),
                target: "narrative text".to_string(),
                context: Some("for significance and event detection".to_string()),
            },
            ToolCapability {
                action: "assess".to_string(),
                target: "content".to_string(),
                context: Some("narrative importance".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to determine if narrative content contains significant events, character development, or world changes worth recording in the chronicle. Essential for narrative triage and filtering.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for already processed content, non-narrative text, or when you need to extract specific events (use extract_temporal_events instead).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Analyzing a conversation for chronicle-worthy events".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "The dragon appeared suddenly, breathing fire across the village square. Sir Gareth raised his shield and charged forward, striking the beast with his enchanted sword."
                }),
                expected_output: "Returns significance analysis with high confidence score and event type classification".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
                AgentType::Perception,
            ],
            required_capabilities: vec!["narrative_analysis".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["narratives".to_string(), "analysis".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 50,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash-Lite API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "is_significant": {"type": "boolean"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "event_type": {"type": "string"},
                "summary": {"type": "string"},
                "reasoning": {"type": "string"},
                "extracted_entities": {"type": "array", "items": {"type": "string"}},
                "analysis_method": {"type": "string"}
            },
            "required": ["is_significant", "confidence", "analysis_method"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash-lite".to_string(),
            "narrative".to_string(),
            "significance".to_string(),
            "triage".to_string(),
        ]
    }
}

/// Self-registering wrapper for CreateChronicleEventTool
pub struct CreateChronicleEventToolWrapper {
    inner: CreateChronicleEventTool,
}

impl CreateChronicleEventToolWrapper {
    pub fn new(chronicle_service: Arc<ChronicleService>, app_state: Arc<AppState>) -> Self {
        Self {
            inner: CreateChronicleEventTool::new(chronicle_service, app_state),
        }
    }
}

#[async_trait]
impl ScribeTool for CreateChronicleEventToolWrapper {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn input_schema(&self) -> JsonValue {
        self.inner.input_schema()
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        self.inner.execute(params, session_dek).await
    }
}

#[async_trait]
impl SelfRegisteringTool for CreateChronicleEventToolWrapper {
    fn category(&self) -> ToolCategory {
        ToolCategory::Creation
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "create".to_string(),
                target: "chronicle event".to_string(),
                context: Some("with structured temporal data".to_string()),
            },
            ToolCapability {
                action: "record".to_string(),
                target: "temporal events".to_string(),
                context: Some("in chronicle timeline".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool to create discrete chronicle events that represent specific moments in the game timeline. Each event should have clear actors, actions, and temporal context.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for ongoing states, general world information (use lorebook instead), or multiple events at once (create them individually).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Recording a combat event in the chronicle".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "chronicle_id": "456e7890-e89b-12d3-a456-426614174001",
                    "event_type": "COMBAT.ENCOUNTER.DRAGON_BATTLE",
                    "action": "defeated",
                    "actors": [{"name": "Sir Gareth", "role": "AGENT"}, {"name": "Ancient Red Dragon", "role": "PATIENT"}],
                    "summary": "Sir Gareth defeated the Ancient Red Dragon in the village square using his enchanted sword."
                }),
                expected_output: "Returns success confirmation with event ID and sequence number".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["chronicle_write".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["chronicles".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 20,
            execution_time: ExecutionTime::Fast,
            external_calls: false,
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "event_id": {"type": "string"},
                "event_type": {"type": "string"},
                "sequence_number": {"type": "integer"},
                "actors": {"type": "array"},
                "action": {"type": "string"}
            },
            "required": ["status", "event_id"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "chronicle".to_string(),
            "creation".to_string(),
            "temporal".to_string(),
            "events".to_string(),
        ]
    }
}

/// Self-registering wrapper for ExtractTemporalEventsTool
pub struct ExtractTemporalEventsToolWrapper {
    inner: ExtractTemporalEventsTool,
}

impl ExtractTemporalEventsToolWrapper {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            inner: ExtractTemporalEventsTool::new(app_state),
        }
    }
}

#[async_trait]
impl ScribeTool for ExtractTemporalEventsToolWrapper {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn input_schema(&self) -> JsonValue {
        self.inner.input_schema()
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        self.inner.execute(params, session_dek).await
    }
}

#[async_trait]
impl SelfRegisteringTool for ExtractTemporalEventsToolWrapper {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "extract".to_string(),
                target: "temporal events".to_string(),
                context: Some("from narrative content".to_string()),
            },
            ToolCapability {
                action: "identify".to_string(),
                target: "discrete events".to_string(),
                context: Some("with chronological ordering".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool to extract multiple discrete temporal events from complex narrative content. It identifies individual events with their actors, causality, and temporal relationships.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for simple single-event content or when you just need significance analysis (use analyze_text_significance first).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Extracting events from a complex battle sequence".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "First, the dragon landed on the tower. Then Sir Gareth charged across the courtyard. The dragon breathed fire, but Gareth dodged behind his shield. Finally, he struck the killing blow with his enchanted sword."
                }),
                expected_output: "Returns structured array of 4 temporal events with causality chains and actor roles".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["narrative_analysis".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["narratives".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 75,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "event_type": {"type": "string"},
                            "summary": {"type": "string"},
                            "actors": {"type": "array"},
                            "temporal_context": {"type": "object"},
                            "spatial_context": {"type": "object"},
                            "causality": {"type": "object"}
                        }
                    }
                }
            }
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash".to_string(),
            "extraction".to_string(),
            "temporal".to_string(),
            "events".to_string(),
            "narrative".to_string(),
        ]
    }
}

/// Self-registering wrapper for ExtractWorldConceptsTool
pub struct ExtractWorldConceptsToolWrapper {
    inner: ExtractWorldConceptsTool,
}

impl ExtractWorldConceptsToolWrapper {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            inner: ExtractWorldConceptsTool::new(app_state),
        }
    }
}

#[async_trait]
impl ScribeTool for ExtractWorldConceptsToolWrapper {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn input_schema(&self) -> JsonValue {
        self.inner.input_schema()
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        self.inner.execute(params, session_dek).await
    }
}

#[async_trait]
impl SelfRegisteringTool for ExtractWorldConceptsToolWrapper {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "extract".to_string(),
                target: "world concepts".to_string(),
                context: Some("for lorebook creation".to_string()),
            },
            ToolCapability {
                action: "identify".to_string(),
                target: "persistent elements".to_string(),
                context: Some("locations, factions, items, lore".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool to extract world-building concepts from narrative content that should be recorded in the lorebook. Focuses on persistent elements that define the game world.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for temporary events (use extract_temporal_events), character actions, or content that's not world-building related.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Extracting world concepts from location description".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "The Crystal Caverns of Aethermoor are home to the ancient Draconic Order, a sect of dragon-riding knights who guard the Shard of Eternal Flame. Their enchanted weapons are forged from starfall metal."
                }),
                expected_output: "Returns structured concepts: Crystal Caverns (location), Draconic Order (faction), Shard of Eternal Flame (artifact), starfall metal (material)".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["narrative_analysis".to_string(), "lorebook_access".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["narratives".to_string(), "lorebook".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 100,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Advanced model API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "concepts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "category": {"type": "string"},
                            "description": {"type": "string"},
                            "relationships": {"type": "array"},
                            "lorebook_entry": {"type": "object"}
                        }
                    }
                }
            }
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "world-building".to_string(),
            "lorebook".to_string(),
            "concepts".to_string(),
            "extraction".to_string(),
        ]
    }
}

/// Self-registering wrapper for SearchKnowledgeBaseTool
pub struct SearchKnowledgeBaseToolWrapper {
    inner: SearchKnowledgeBaseTool,
}

impl SearchKnowledgeBaseToolWrapper {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            inner: SearchKnowledgeBaseTool::new(app_state),
        }
    }
}

#[async_trait]
impl ScribeTool for SearchKnowledgeBaseToolWrapper {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn input_schema(&self) -> JsonValue {
        self.inner.input_schema()
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        self.inner.execute(params, session_dek).await
    }
}

#[async_trait]
impl SelfRegisteringTool for SearchKnowledgeBaseToolWrapper {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "search".to_string(),
                target: "knowledge base".to_string(),
                context: Some("with AI-enhanced queries".to_string()),
            },
            ToolCapability {
                action: "retrieve".to_string(),
                target: "relevant information".to_string(),
                context: Some("from chronicles and lorebook".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool to search for existing information across chronicles, lorebook entries, and entities. Uses AI to enhance queries and rank results by relevance.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use when you need to create new content or when you already know specific entity/entry IDs (use direct retrieval tools instead).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Searching for information about a character's past".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": "Sir Gareth dragon encounters previous battles"
                }),
                expected_output: "Returns ranked search results from chronicles and lorebook with relevance scores".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
                AgentType::Perception,
            ],
            required_capabilities: vec!["search".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["chronicles".to_string(), "lorebook".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 75,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Multiple AI model calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "query_analysis": {"type": "object"},
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "relevance_score": {"type": "number"},
                            "source_type": {"type": "string"},
                            "metadata": {"type": "object"}
                        }
                    }
                },
                "search_suggestions": {"type": "array"}
            }
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "search".to_string(),
            "knowledge-base".to_string(),
            "semantic".to_string(),
            "discovery".to_string(),
        ]
    }
}

/// Registration function for all narrative tools
pub fn register_narrative_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    // Register AnalyzeTextSignificanceTool
    let analyze_tool = Arc::new(AnalyzeTextSignificanceToolWrapper::new(app_state.clone())) 
        as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(analyze_tool)?;

    // Register CreateChronicleEventTool
    let create_chronicle_tool = Arc::new(CreateChronicleEventToolWrapper::new(
        app_state.chronicle_service.clone(),
        app_state.clone(),
    )) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(create_chronicle_tool)?;

    // Register ExtractTemporalEventsTool
    let extract_events_tool = Arc::new(ExtractTemporalEventsToolWrapper::new(app_state.clone()))
        as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(extract_events_tool)?;

    // Register ExtractWorldConceptsTool
    let extract_concepts_tool = Arc::new(ExtractWorldConceptsToolWrapper::new(app_state.clone()))
        as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(extract_concepts_tool)?;

    // Register SearchKnowledgeBaseTool
    let search_tool = Arc::new(SearchKnowledgeBaseToolWrapper::new(app_state.clone()))
        as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(search_tool)?;

    Ok(())
}