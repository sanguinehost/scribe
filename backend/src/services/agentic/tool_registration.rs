//! Tool Registration Module
//! 
//! This module handles the registration of all AI agent tools with their metadata.
//! It provides comprehensive information about each tool to help AI agents understand
//! when and how to use them effectively.

use std::sync::Arc;
use serde_json::json;
use tracing::{info, debug, warn};

use crate::{
    errors::AppError,
    state::AppState,
    services::{ChronicleService, LorebookService, EcsEntityManager},
};

use super::{
    narrative_tools::*,
    entity_resolution_tool::EntityResolutionTool,
    tools::{
        ScribeTool,
        hierarchy_tools::*,
        ai_powered_tools::*,
        world_interaction_tools::*,
    },
    tool_registry::{
        ToolRegistry, ToolMetadataBuilder, ToolCategory, 
        ExecutionTime
    },
    tool_access_config::get_default_tool_policies,
};

/// Register all core AI agent tools with their metadata
pub fn register_all_tools(
    app_state: Arc<AppState>,
    chronicle_service: Arc<ChronicleService>,
    lorebook_service: Arc<LorebookService>,
) -> Result<(), AppError> {
    info!("Starting tool registration process");
    
    // Register narrative analysis tools
    register_narrative_analysis_tools(app_state.clone())?;
    
    // Register knowledge creation tools
    register_knowledge_creation_tools(
        app_state.clone(),
        chronicle_service,
        lorebook_service.clone(),
    )?;
    
    // Register knowledge management tools
    register_knowledge_management_tools(app_state.clone(), lorebook_service)?;
    
    // Register entity management tools
    register_entity_management_tools(app_state.clone())?;
    
    // Register hierarchy tools
    register_hierarchy_tools(app_state.clone())?;
    
    // Register AI-powered tools
    register_ai_powered_tools(app_state.clone())?;
    
    // Register world interaction tools
    register_world_interaction_tools(app_state.ecs_entity_manager.clone())?;
    
    // Apply access policies to registered tools
    apply_tool_access_policies()?;
    
    let tool_count = ToolRegistry::list_tool_names().len();
    info!("Successfully registered {} tools with access policies", tool_count);
    
    Ok(())
}

/// Register narrative analysis tools
fn register_narrative_analysis_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    // AnalyzeTextSignificanceTool
    let significance_tool = AnalyzeTextSignificanceTool::new(app_state.clone());
    let significance_metadata = ToolMetadataBuilder::new(
        significance_tool.name(),
        significance_tool.description()
    )
    .category(ToolCategory::AIAnalysis)
    .when_to_use("When you need to determine if narrative text contains significant events, world-building elements, or character development worthy of recording")
    .when_not_to_use("For simple chat messages or queries that don't contain narrative content")
    .execution_time(ExecutionTime::Fast)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["triage".to_string(), "analysis".to_string(), "narrative".to_string()])
    .input_schema(significance_tool.input_schema())
    .output_format("JSON object with significance score (0.0-1.0), is_significant boolean, category (character/event/world/meta), reasoning, and key_elements array")
    .example(
        "User describes a dramatic battle between two factions",
        json!({
            "text": "The Northern Fleet launched a surprise attack on the Crystal Spire at dawn, shattering the century-old peace treaty.",
            "context": "Military conflict in a fantasy world"
        }),
        "Returns high significance (0.9) with category 'event', identifying key elements like conflict, location, and historical impact"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(significance_tool), significance_metadata)?;
    
    // ExtractTemporalEventsTool
    let extract_events_tool = ExtractTemporalEventsTool::new(app_state.clone());
    let extract_events_metadata = ToolMetadataBuilder::new(
        extract_events_tool.name(),
        extract_events_tool.description()
    )
    .category(ToolCategory::Extraction)
    .when_to_use("After determining text is significant, to extract specific temporal events with participants, actions, and outcomes")
    .when_not_to_use("For text that doesn't describe events or actions")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["extraction".to_string(), "events".to_string(), "temporal".to_string()])
    .input_schema(extract_events_tool.input_schema())
    .output_format("JSON object with array of extracted events, each containing title, description, participants, temporal markers, location, and outcomes")
    .depends_on(vec!["analyze_text_significance".to_string()])
    .example(
        "Extract events from battle narrative",
        json!({
            "text": "Alice led the charge against the goblin fortress. After hours of fierce fighting, they breached the walls and captured the enemy commander.",
            "context": "Fantasy battle sequence",
            "metadata": {
                "location": "Goblin Fortress",
                "time_period": "Current era"
            }
        }),
        "Extracts two events: 'Charge against goblin fortress' and 'Capture of enemy commander' with full participant and outcome details"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(extract_events_tool), extract_events_metadata)?;
    
    // ExtractWorldConceptsTool
    let extract_concepts_tool = ExtractWorldConceptsTool::new(app_state.clone());
    let extract_concepts_metadata = ToolMetadataBuilder::new(
        extract_concepts_tool.name(),
        extract_concepts_tool.description()
    )
    .category(ToolCategory::Extraction)
    .when_to_use("To identify and extract world-building concepts like locations, organizations, magic systems, or cultural elements from narrative text")
    .when_not_to_use("For purely action-focused text without world-building elements")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["extraction".to_string(), "world-building".to_string(), "concepts".to_string()])
    .input_schema(extract_concepts_tool.input_schema())
    .output_format("JSON object with arrays of concepts by type (locations, organizations, systems, cultures), each with name, description, and significance")
    .depends_on(vec!["analyze_text_significance".to_string()])
    .example(
        "Extract concepts from world description",
        json!({
            "text": "The Mage's Guild controls all magical education in the Seven Kingdoms through their network of Crystal Towers.",
            "existing_concepts": ["Seven Kingdoms"]
        }),
        "Extracts organization 'Mage's Guild', system 'magical education network', and location type 'Crystal Towers'"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(extract_concepts_tool), extract_concepts_metadata)?;
    
    Ok(())
}

/// Register knowledge creation tools
fn register_knowledge_creation_tools(
    app_state: Arc<AppState>,
    chronicle_service: Arc<ChronicleService>,
    lorebook_service: Arc<LorebookService>,
) -> Result<(), AppError> {
    // CreateChronicleEventTool
    let create_event_tool = CreateChronicleEventTool::new(
        chronicle_service,
        app_state.clone(),
    );
    let create_event_metadata = ToolMetadataBuilder::new(
        create_event_tool.name(),
        create_event_tool.description()
    )
    .category(ToolCategory::Creation)
    .when_to_use("To permanently record significant events in the chronicle after extraction")
    .when_not_to_use("For minor or transient events that don't impact the world state")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["chronicle".to_string(), "events".to_string(), "persistence".to_string()])
    .input_schema(create_event_tool.input_schema())
    .output_format("JSON object with created event details including ID, timestamp, and confirmation")
    .depends_on(vec!["extract_temporal_events".to_string()])
    .example(
        "Record a major battle event",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "title": "Battle of Crystal Spire",
            "content": "Northern Fleet attacks Crystal Spire, breaking century-old peace treaty",
            "event_type": "military_conflict",
            "metadata": {
                "participants": ["Northern Fleet", "Crystal Spire defenders"],
                "location": "Crystal Spire",
                "outcome": "Treaty broken, war begun"
            }
        }),
        "Creates chronicle entry with unique ID and timestamp, returns confirmation"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(create_event_tool), create_event_metadata)?;
    
    // CreateLorebookEntryTool
    let create_lorebook_tool = CreateLorebookEntryTool::new(
        lorebook_service,
        app_state.clone(),
    );
    let create_lorebook_metadata = ToolMetadataBuilder::new(
        create_lorebook_tool.name(),
        create_lorebook_tool.description()
    )
    .category(ToolCategory::Creation)
    .when_to_use("To create permanent lorebook entries for world concepts, organizations, locations, or systems")
    .when_not_to_use("For temporary or character-specific information")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["lorebook".to_string(), "world-building".to_string(), "persistence".to_string()])
    .input_schema(create_lorebook_tool.input_schema())
    .output_format("JSON object with created entry ID and confirmation")
    .depends_on(vec!["extract_world_concepts".to_string()])
    .example(
        "Create entry for magical organization",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Mage's Guild",
            "entry_type": "organization",
            "content": "Controls magical education across Seven Kingdoms through Crystal Tower network",
            "tags": ["magic", "education", "government"],
            "visibility": "public"
        }),
        "Creates lorebook entry with searchable tags and returns entry ID"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(create_lorebook_tool), create_lorebook_metadata)?;
    
    Ok(())
}

/// Register knowledge management tools
fn register_knowledge_management_tools(
    app_state: Arc<AppState>,
    lorebook_service: Arc<LorebookService>,
) -> Result<(), AppError> {
    // SearchKnowledgeBaseTool
    let search_tool = SearchKnowledgeBaseTool::new(app_state.clone());
    let search_metadata = ToolMetadataBuilder::new(
        search_tool.name(),
        search_tool.description()
    )
    .category(ToolCategory::Search)
    .when_to_use("To find relevant context from chronicles and lorebooks using semantic search")
    .when_not_to_use("For exact ID-based lookups or when you already have the specific entry")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["search".to_string(), "knowledge".to_string(), "context".to_string()])
    .input_schema(search_tool.input_schema())
    .output_format("JSON object with arrays of matching chronicle events and lorebook entries, sorted by relevance")
    .example(
        "Search for information about dragons",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "query": "dragon attacks on mountain villages",
            "collections": ["chronicles", "lorebooks"],
            "limit": 5,
            "min_score": 0.7
        }),
        "Returns relevant chronicle events about dragon attacks and lorebook entries about dragons, mountains, or defensive strategies"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(search_tool), search_metadata)?;
    
    // UpdateLorebookEntryTool
    let update_lorebook_tool = UpdateLorebookEntryTool::new(
        lorebook_service,
        app_state.clone(),
    );
    let update_lorebook_metadata = ToolMetadataBuilder::new(
        update_lorebook_tool.name(),
        update_lorebook_tool.description()
    )
    .category(ToolCategory::Creation)
    .when_to_use("To update existing lorebook entries with new information or corrections")
    .when_not_to_use("To create new entries (use create_lorebook_entry instead)")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["lorebook".to_string(), "update".to_string(), "management".to_string()])
    .input_schema(update_lorebook_tool.input_schema())
    .output_format("JSON object with update confirmation and modified fields")
    .example(
        "Update organization details",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "updates": {
                "content": "Controls magical education across Seven Kingdoms. Recently established new Crystal Tower in the Northern Wastes.",
                "tags": ["magic", "education", "government", "expansion"]
            }
        }),
        "Updates the specified lorebook entry with new content and tags"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(update_lorebook_tool), update_lorebook_metadata)?;
    
    Ok(())
}

/// Register entity management tools
fn register_entity_management_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    // EntityResolutionTool
    let entity_resolution_tool = EntityResolutionTool::new(app_state.clone());
    let entity_resolution_metadata = ToolMetadataBuilder::new(
        entity_resolution_tool.name(),
        entity_resolution_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To identify, disambiguate, and resolve entity references in text to canonical entities")
    .when_not_to_use("For creating new entities (use world interaction tools instead)")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["entities".to_string(), "resolution".to_string(), "disambiguation".to_string()])
    .input_schema(entity_resolution_tool.input_schema())
    .output_format("JSON object with resolved entities array, each containing the matched text, canonical entity details, confidence score, and resolution method")
    .example(
        "Resolve entity references in narrative",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "text": "Alice met with the General at the Crystal Tower to discuss the northern threat.",
            "processing_mode": "comprehensive",
            "context": {
                "recent_entities": ["Alice", "General Marcus", "Crystal Tower of Wisdom"],
                "location": "Capital City"
            }
        }),
        "Resolves 'Alice' to character entity, 'the General' to 'General Marcus', and 'Crystal Tower' to specific location entity"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(entity_resolution_tool), entity_resolution_metadata)?;
    
    Ok(())
}

/// Register hierarchy management tools
fn register_hierarchy_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    let ecs_manager = app_state.ecs_entity_manager.clone();
    
    // GetEntityHierarchyTool
    let get_hierarchy_tool = GetEntityHierarchyTool::new(ecs_manager.clone());
    let get_hierarchy_metadata = ToolMetadataBuilder::new(
        get_hierarchy_tool.name(),
        get_hierarchy_tool.description()
    )
    .category(ToolCategory::Hierarchy)
    .when_to_use("To retrieve the complete hierarchical structure of an entity, including parents and children")
    .when_not_to_use("For simple entity lookups without hierarchy information")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(false)
    .tags(vec!["hierarchy".to_string(), "query".to_string(), "structure".to_string()])
    .input_schema(get_hierarchy_tool.input_schema())
    .output_format("JSON object with entity details, parent chain up to root, immediate children, and hierarchy metadata")
    .example(
        "Get hierarchy for a planet",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "planet-uuid-here",
            "include_siblings": true
        }),
        "Returns planet details, parent solar system and galaxy, child continents/cities, and sibling planets"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(get_hierarchy_tool), get_hierarchy_metadata)?;
    
    // PromoteEntityHierarchyTool
    let promote_tool = PromoteEntityHierarchyTool::new(ecs_manager.clone());
    let promote_metadata = ToolMetadataBuilder::new(
        promote_tool.name(),
        promote_tool.description()
    )
    .category(ToolCategory::Hierarchy)
    .when_to_use("To elevate an entity to a higher spatial scale when it gains narrative importance")
    .when_not_to_use("For routine entity updates or position changes")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["hierarchy".to_string(), "promotion".to_string(), "scale".to_string()])
    .input_schema(promote_tool.input_schema())
    .output_format("JSON object with previous scale, new scale, and confirmation")
    .depends_on(vec!["suggest_hierarchy_promotion".to_string()])
    .example(
        "Promote a city to planetary importance",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "city-uuid-here",
            "new_scale": "Planetary",
            "reason": "Became capital of united world government"
        }),
        "Promotes city from Intimate to Planetary scale, updates hierarchy accordingly"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(promote_tool), promote_metadata)?;
    
    Ok(())
}

/// Register AI-powered analysis tools
fn register_ai_powered_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    // AnalyzeHierarchyRequestTool
    let analyze_hierarchy_tool = AnalyzeHierarchyRequestTool::new(app_state.clone());
    let analyze_hierarchy_metadata = ToolMetadataBuilder::new(
        analyze_hierarchy_tool.name(),
        analyze_hierarchy_tool.description()
    )
    .category(ToolCategory::AIAnalysis)
    .when_to_use("To interpret natural language requests about entity hierarchies and translate them to structured queries")
    .when_not_to_use("When you already have specific entity IDs and know exactly what hierarchy operation to perform")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["ai".to_string(), "hierarchy".to_string(), "interpretation".to_string()])
    .input_schema(analyze_hierarchy_tool.input_schema())
    .output_format("JSON object with interpreted query type, target entities, and suggested hierarchy operation")
    .example(
        "Interpret hierarchy question",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "natural_language_request": "Show me what star system this planet belongs to",
            "available_entities": "Current scene includes Planet Xerion"
        }),
        "Interprets as hierarchy_path query for Planet Xerion, suggests get_entity_hierarchy operation"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(analyze_hierarchy_tool), analyze_hierarchy_metadata)?;
    
    // SuggestHierarchyPromotionTool
    let suggest_promotion_tool = SuggestHierarchyPromotionTool::new(app_state.clone());
    let suggest_promotion_metadata = ToolMetadataBuilder::new(
        suggest_promotion_tool.name(),
        suggest_promotion_tool.description()
    )
    .category(ToolCategory::AIAnalysis)
    .when_to_use("To analyze narrative text and identify entities that may deserve hierarchy promotion based on increased importance")
    .when_not_to_use("For predetermined promotion decisions")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(false)
    .tags(vec!["ai".to_string(), "hierarchy".to_string(), "analysis".to_string()])
    .input_schema(suggest_promotion_tool.input_schema())
    .output_format("JSON object with promotion suggestions array, each containing entity name, current scale, suggested scale, confidence, and reasoning")
    .example(
        "Analyze text for promotion candidates",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "narrative_text": "The small mining outpost of Redrock has become the center of the galactic conflict after discovering ancient technology."
        }),
        "Suggests promoting 'Redrock' from Intimate to Planetary or Cosmic scale due to galactic importance"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(suggest_promotion_tool), suggest_promotion_metadata)?;
    
    // UpdateSalienceTool
    let update_salience_tool = UpdateSalienceTool::new(app_state.clone());
    let update_salience_metadata = ToolMetadataBuilder::new(
        update_salience_tool.name(),
        update_salience_tool.description()
    )
    .category(ToolCategory::AIAnalysis)
    .when_to_use("To analyze narrative importance and update entity salience tiers dynamically")
    .when_not_to_use("For entities with fixed importance levels")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(true)
    .modifies_state(true)
    .tags(vec!["ai".to_string(), "salience".to_string(), "narrative".to_string()])
    .input_schema(update_salience_tool.input_schema())
    .output_format("JSON object with salience updates including previous tier, new tier, confidence, and detailed reasoning")
    .example(
        "Update character salience after major event",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "narrative_context": "Alice defeated the Dark Lord and saved the kingdom, becoming a legendary hero.",
            "recent_events": ["Defeated Dark Lord", "Crowned as Hero of the Realm"]
        }),
        "Updates Alice's salience from Background to Prominent tier based on narrative importance"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(update_salience_tool), update_salience_metadata)?;
    
    Ok(())
}

/// Register world interaction tools
fn register_world_interaction_tools(ecs_manager: Arc<EcsEntityManager>) -> Result<(), AppError> {
    // FindEntityTool
    let find_entity_tool = FindEntityTool::new(ecs_manager.clone());
    let find_entity_metadata = ToolMetadataBuilder::new(
        find_entity_tool.name(),
        find_entity_tool.description()
    )
    .category(ToolCategory::WorldState)
    .when_to_use("To search for entities by name, scale, parent, or component type")
    .when_not_to_use("When you already have the entity ID")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(false)
    .tags(vec!["search".to_string(), "entities".to_string(), "query".to_string()])
    .input_schema(find_entity_tool.input_schema())
    .output_format("JSON object with array of matching entities, each containing ID, name, scale, position, and component types")
    .example(
        "Find all cosmic-scale entities",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "criteria": {
                "type": "ByScale",
                "scale": "Cosmic"
            },
            "limit": 10
        }),
        "Returns list of galaxies, nebulae, and other cosmic-scale entities"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(find_entity_tool), find_entity_metadata)?;
    
    // GetEntityDetailsTool
    let get_details_tool = GetEntityDetailsTool::new(ecs_manager.clone());
    let get_details_metadata = ToolMetadataBuilder::new(
        get_details_tool.name(),
        get_details_tool.description()
    )
    .category(ToolCategory::WorldState)
    .when_to_use("To retrieve complete details about a specific entity including all components")
    .when_not_to_use("For bulk entity queries or searches")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(false)
    .tags(vec!["entities".to_string(), "details".to_string(), "components".to_string()])
    .input_schema(get_details_tool.input_schema())
    .output_format("JSON object with entity ID, name, all component data organized by type")
    .example(
        "Get character details",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid-here"
        }),
        "Returns complete character data including position, inventory, relationships, and all other components"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(get_details_tool), get_details_metadata)?;
    
    // CreateEntityTool
    let create_entity_tool = CreateEntityTool::new(ecs_manager.clone());
    let create_entity_metadata = ToolMetadataBuilder::new(
        create_entity_tool.name(),
        create_entity_tool.description()
    )
    .category(ToolCategory::Creation)
    .when_to_use("To create new entities in the world with specified components")
    .when_not_to_use("To update existing entities (use update_entity instead)")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["creation".to_string(), "entities".to_string(), "world-building".to_string()])
    .input_schema(create_entity_tool.input_schema())
    .output_format("JSON object with created entity ID and initialization details")
    .example(
        "Create a new character",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_name": "Marcus the Brave",
            "components": {
                "identity": {
                    "display_name": "Marcus the Brave",
                    "description": "A veteran warrior seeking redemption"
                },
                "position": {
                    "x": 100.0,
                    "y": 0.0,
                    "z": 50.0,
                    "position_type": "Absolute"
                }
            }
        }),
        "Creates new character entity with identity and position components"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(create_entity_tool), create_entity_metadata)?;
    
    // UpdateEntityTool
    let update_entity_tool = UpdateEntityTool::new(ecs_manager.clone());
    let update_entity_metadata = ToolMetadataBuilder::new(
        update_entity_tool.name(),
        update_entity_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To modify existing entity components or add new components")
    .when_not_to_use("To create new entities or change hierarchical relationships")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["update".to_string(), "entities".to_string(), "components".to_string()])
    .input_schema(update_entity_tool.input_schema())
    .output_format("JSON object with update confirmation and modified components")
    .example(
        "Update character health",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "updates": [
                {
                    "component_type": "health",
                    "operation": "Set",
                    "data": {
                        "current": 75,
                        "maximum": 100
                    }
                }
            ]
        }),
        "Updates character's health component to 75/100"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(update_entity_tool), update_entity_metadata)?;
    
    // GetContainedEntitiesTool
    let contained_entities_tool = GetContainedEntitiesTool::new(ecs_manager.clone());
    let contained_entities_metadata = ToolMetadataBuilder::new(
        contained_entities_tool.name(),
        contained_entities_tool.description()
    )
    .category(ToolCategory::WorldState)
    .when_to_use("To find all entities contained within a specific location or container")
    .when_not_to_use("For general entity searches not based on containment")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(false)
    .tags(vec!["spatial".to_string(), "containment".to_string(), "query".to_string()])
    .input_schema(contained_entities_tool.input_schema())
    .output_format("JSON object with array of contained entities, organized by direct children and recursive descendants")
    .example(
        "Get all entities in a building",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "container_id": "building-uuid",
            "recursive": true,
            "include_scale": ["Intimate"]
        }),
        "Returns all characters, objects, and rooms within the building"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(contained_entities_tool), contained_entities_metadata)?;
    
    // GetSpatialContextTool
    let spatial_context_tool = GetSpatialContextTool::new(ecs_manager.clone());
    let spatial_context_metadata = ToolMetadataBuilder::new(
        spatial_context_tool.name(),
        spatial_context_tool.description()
    )
    .category(ToolCategory::WorldState)
    .when_to_use("To understand the complete spatial context around an entity, including nearby entities and hierarchical location")
    .when_not_to_use("For simple position queries or containment checks")
    .execution_time(ExecutionTime::Moderate)
    .external_calls(false)
    .modifies_state(false)
    .tags(vec!["spatial".to_string(), "context".to_string(), "proximity".to_string()])
    .input_schema(spatial_context_tool.input_schema())
    .output_format("JSON object with entity position, containing hierarchy, nearby entities sorted by distance, and spatial analysis")
    .example(
        "Get spatial context for a character",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "radius": 100.0,
            "include_scale": ["Intimate"],
            "max_nearby": 10
        }),
        "Returns character's location hierarchy (building->district->city) and nearest 10 entities within 100 units"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(spatial_context_tool), spatial_context_metadata)?;
    
    // MoveEntityTool
    let move_entity_tool = MoveEntityTool::new(ecs_manager.clone());
    let move_entity_metadata = ToolMetadataBuilder::new(
        move_entity_tool.name(),
        move_entity_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To change an entity's position or move it to a different container")
    .when_not_to_use("For hierarchy promotions or scale changes")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["movement".to_string(), "spatial".to_string(), "position".to_string()])
    .input_schema(move_entity_tool.input_schema())
    .output_format("JSON object with previous position, new position, and movement confirmation")
    .example(
        "Move character to new location",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "destination": {
                "type": "Container",
                "container_id": "tavern-uuid"
            }
        }),
        "Moves character from current location to inside the tavern"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(move_entity_tool), move_entity_metadata)?;
    
    // AddItemToInventoryTool
    let add_item_tool = AddItemToInventoryTool::new(ecs_manager.clone());
    let add_item_metadata = ToolMetadataBuilder::new(
        add_item_tool.name(),
        add_item_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To add items to an entity's inventory")
    .when_not_to_use("For removing items or transferring between inventories")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["inventory".to_string(), "items".to_string(), "management".to_string()])
    .input_schema(add_item_tool.input_schema())
    .output_format("JSON object with updated inventory summary")
    .example(
        "Add sword to character inventory",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "item_name": "Iron Sword",
            "quantity": 1,
            "item_data": {
                "damage": 10,
                "durability": 100
            }
        }),
        "Adds Iron Sword to character's inventory with specified properties"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(add_item_tool), add_item_metadata)?;
    
    // RemoveItemFromInventoryTool
    let remove_item_tool = RemoveItemFromInventoryTool::new(ecs_manager.clone());
    let remove_item_metadata = ToolMetadataBuilder::new(
        remove_item_tool.name(),
        remove_item_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To remove items from an entity's inventory")
    .when_not_to_use("For adding items or transferring between inventories")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["inventory".to_string(), "items".to_string(), "management".to_string()])
    .input_schema(remove_item_tool.input_schema())
    .output_format("JSON object with removed item details and updated inventory")
    .example(
        "Remove potion from inventory",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "entity_id": "character-uuid",
            "item_name": "Health Potion",
            "quantity": 2
        }),
        "Removes 2 Health Potions from character's inventory"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(remove_item_tool), remove_item_metadata)?;
    
    // UpdateRelationshipTool
    let update_relationship_tool = UpdateRelationshipTool::new(ecs_manager.clone());
    let update_relationship_metadata = ToolMetadataBuilder::new(
        update_relationship_tool.name(),
        update_relationship_tool.description()
    )
    .category(ToolCategory::EntityManagement)
    .when_to_use("To create or update relationships between entities")
    .when_not_to_use("For removing relationships entirely")
    .execution_time(ExecutionTime::Fast)
    .external_calls(false)
    .modifies_state(true)
    .tags(vec!["relationships".to_string(), "social".to_string(), "connections".to_string()])
    .input_schema(update_relationship_tool.input_schema())
    .output_format("JSON object with relationship details")
    .example(
        "Create friendship between characters",
        json!({
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "source_entity_id": "alice-uuid",
            "target_entity_id": "bob-uuid",
            "relationship_type": "friend",
            "strength": 0.8
        }),
        "Creates or updates friendship relationship between Alice and Bob with high strength"
    )
    .build();
    
    ToolRegistry::register_tool(Arc::new(update_relationship_tool), update_relationship_metadata)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: Since tool registration requires many dependencies like ChronicleService,
    // LorebookService, etc., full integration testing would be done at a higher level.
    // Here we can test the basic structure.
    
    #[test]
    fn test_tool_metadata_builder() {
        let metadata = ToolMetadataBuilder::new("test_tool", "A test tool")
            .category(ToolCategory::Utility)
            .when_to_use("When testing")
            .execution_time(ExecutionTime::Fast)
            .tags(vec!["test".to_string()])
            .input_schema(json!({"type": "object"}))
            .build();
        
        assert_eq!(metadata.name, "test_tool");
        assert_eq!(metadata.category, ToolCategory::Utility);
        assert_eq!(metadata.execution_time, ExecutionTime::Fast);
    }
}

/// Apply access policies to registered tools
fn apply_tool_access_policies() -> Result<(), AppError> {
    
    
    info!("Applying tool access policies");
    
    // Get the default policies
    let policies = get_default_tool_policies();
    
    // Apply each policy to the corresponding tool
    for (tool_name, policy) in policies {
        // Get the current metadata
        if let Some(mut metadata) = ToolRegistry::get_metadata(tool_name) {
            // Apply the access policy
            metadata.access_policy = Some(policy.clone());
            
            // Update the registry with the modified metadata
            match ToolRegistry::update_metadata(tool_name, metadata) {
                Ok(()) => {
                    info!(
                        "Applied access policy to tool '{}': allowed agents: {:?}, priority: {}, required: {}",
                        tool_name,
                        policy.allowed_agents,
                        policy.priority,
                        policy.required
                    );
                }
                Err(e) => {
                    warn!("Failed to update metadata for tool '{}': {}", tool_name, e);
                }
            }
        } else {
            // Tool not found - this is okay, not all tools need policies
            debug!("Tool '{}' not found in registry, skipping policy application", tool_name);
        }
    }
    
    info!("Access policies applied successfully");
    Ok(())
}