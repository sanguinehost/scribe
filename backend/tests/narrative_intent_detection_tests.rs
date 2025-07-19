use scribe_backend::services::intent_detection_service::*;
use scribe_backend::test_helpers::MockAiClient;
use std::sync::Arc;

#[tokio::test]
async fn test_narrative_intent_roleplay_scene_transition() {
    // Test the new open-ended narrative analysis with a roleplay scenario
    let mock_response = r#"{
        "narrative_analysis": "User is transitioning from a tense confrontation scene to an intimate family moment. They want to shift focus from conflict to domestic tranquility, exploring Lumiya's relationship with her children and showing her maternal side after the political tension.",
        "context_needs": [
            "Lumiya's current emotional state and recent interactions",
            "Her children's current activities and wellbeing", 
            "The domestic setting and family dynamics",
            "Recent family-related events or conversations",
            "Lumiya's maternal personality traits and parenting style"
        ],
        "scene_context": {
            "current_scene_type": "family_domestic",
            "narrative_goal": "character_development_maternal_side",
            "emotional_tone": "shift_from_tension_to_warmth",
            "relationship_focus": "parent_child_bonds"
        },
        "focus_entities": [
            {
                "name": "Lumiya",
                "priority": 1.0,
                "required": true,
                "context_role": "primary_character_maternal_focus"
            },
            {
                "name": "Lumiya's children",
                "priority": 0.9,
                "required": true,
                "context_role": "relationship_targets"
            }
        ],
        "time_scope": {
            "type": "Current",
            "narrative_timeframe": "immediate_scene_transition"
        },
        "spatial_scope": {
            "location_name": "family_quarters",
            "include_contained": true,
            "spatial_narrative": "intimate_domestic_space"
        },
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities", "Relationships", "RecentEvents", "SpatialContext"],
        "query_strategies": [
            "get_entity_emotional_state",
            "find_recent_family_interactions", 
            "get_children_current_activities",
            "understand_domestic_setting_details"
        ],
        "confidence": 0.92
    }"#;

    let mock_client = MockAiClient::new_with_response(mock_response.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let user_query = "Lumiya sighs softly and goes to check on her children, needing the comfort of family after the difficult political meeting.";
    let conversation_context = Some("Previous messages showed tense political confrontation with Republic senators about trade agreements. Lumiya was frustrated and defensive about her people's needs.");
    
    let intent = service.detect_narrative_intent(user_query, conversation_context).await.unwrap();
    
    // Verify the narrative analysis captures the scene transition
    assert!(intent.narrative_analysis.contains("family moment"));
    assert!(intent.narrative_analysis.contains("maternal side"));
    
    // Check context needs are appropriate for roleplay
    assert!(intent.context_needs.contains(&"Lumiya's current emotional state and recent interactions".to_string()));
    assert!(intent.context_needs.contains(&"Her children's current activities and wellbeing".to_string()));
    
    // Verify scene context understanding
    assert_eq!(intent.scene_context.get("current_scene_type").unwrap().as_str().unwrap(), "family_domestic");
    assert_eq!(intent.scene_context.get("narrative_goal").unwrap().as_str().unwrap(), "character_development_maternal_side");
    
    // Check focus entities
    assert_eq!(intent.focus_entities.len(), 2);
    assert_eq!(intent.focus_entities[0].name, "Lumiya");
    assert_eq!(intent.focus_entities[0].priority, 1.0);
    assert!(intent.focus_entities[0].required);
    
    // Verify query strategies are dynamic and narrative-appropriate
    assert!(intent.query_strategies.contains(&"get_entity_emotional_state".to_string()));
    assert!(intent.query_strategies.contains(&"find_recent_family_interactions".to_string()));
    
    assert!(intent.confidence > 0.9);
}

#[tokio::test]
async fn test_narrative_intent_action_scene() {
    // Test analysis of an action-oriented scene
    let mock_response = r#"{
        "narrative_analysis": "User is initiating a combat encounter with multiple adversaries. The scene requires tactical positioning, weapon states, and environmental hazards. This is high-stakes action requiring immediate threat assessment.",
        "context_needs": [
            "Combat readiness and weapon states of all characters",
            "Environmental layout and tactical advantages",
            "Recent injuries or status effects affecting performance",
            "Relationships between combatants that might affect strategy",
            "Available cover and escape routes"
        ],
        "scene_context": {
            "current_scene_type": "combat_encounter", 
            "narrative_goal": "tactical_action_resolution",
            "emotional_tone": "high_tension_immediate_danger",
            "relationship_focus": "adversarial_tactical"
        },
        "focus_entities": [
            {
                "name": "Kael",
                "priority": 1.0,
                "required": true,
                "context_role": "primary_combatant"
            },
            {
                "name": "mercenary squad",
                "priority": 0.8, 
                "required": true,
                "context_role": "immediate_threats"
            }
        ],
        "time_scope": {
            "type": "Current",
            "narrative_timeframe": "immediate_action_resolution"
        },
        "spatial_scope": {
            "location_name": "spaceport_landing_bay",
            "include_contained": true,
            "spatial_narrative": "tactical_combat_environment"
        },
        "reasoning_depth": "Analytical",
        "context_priorities": ["Entities", "SpatialContext", "RecentEvents", "Relationships"],
        "query_strategies": [
            "get_combat_readiness_states",
            "analyze_environmental_tactical_features",
            "check_weapon_and_equipment_status", 
            "assess_numerical_advantage_factors"
        ],
        "confidence": 0.88
    }"#;

    let mock_client = MockAiClient::new_with_response(mock_response.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let user_query = "Kael draws his blaster as the mercenary squad surrounds him in the landing bay, looking for cover behind the cargo containers.";
    
    let intent = service.detect_narrative_intent(user_query, None).await.unwrap();
    
    // Verify combat scene analysis
    assert!(intent.narrative_analysis.contains("combat encounter"));
    assert!(intent.narrative_analysis.contains("tactical"));
    
    // Check action-appropriate context needs
    assert!(intent.context_needs.contains(&"Combat readiness and weapon states of all characters".to_string()));
    assert!(intent.context_needs.contains(&"Environmental layout and tactical advantages".to_string()));
    
    // Verify scene context
    assert_eq!(intent.scene_context.get("current_scene_type").unwrap().as_str().unwrap(), "combat_encounter");
    assert_eq!(intent.scene_context.get("emotional_tone").unwrap().as_str().unwrap(), "high_tension_immediate_danger");
    
    // Check spatial focus for tactical scenes
    assert!(intent.spatial_scope.is_some());
    let spatial = intent.spatial_scope.as_ref().unwrap();
    assert_eq!(spatial.location_name.as_ref().unwrap(), "spaceport_landing_bay");
    
    // Verify query strategies are combat-focused
    assert!(intent.query_strategies.contains(&"get_combat_readiness_states".to_string()));
    assert!(intent.query_strategies.contains(&"analyze_environmental_tactical_features".to_string()));
}

#[tokio::test] 
async fn test_narrative_intent_exploration_discovery() {
    // Test analysis of exploration/discovery scene
    let mock_response = r#"{
        "narrative_analysis": "User is exploring unknown territory with focus on discovery and wonder. The character is investigating mysterious ancient ruins, requiring atmospheric details and historical context to build immersion and reveal secrets gradually.",
        "context_needs": [
            "Historical significance and past events at this location",
            "Environmental atmosphere and mysterious elements",
            "Character's archaeological knowledge and past experiences",
            "Any previous mentions of similar ruins or artifacts",
            "Local legends or stories about this place"
        ],
        "scene_context": {
            "current_scene_type": "exploration_discovery",
            "narrative_goal": "world_building_mystery_revelation", 
            "emotional_tone": "wonder_apprehension_curiosity",
            "relationship_focus": "character_environment_interaction"
        },
        "focus_entities": [
            {
                "name": "Zara",
                "priority": 1.0,
                "required": true,
                "context_role": "explorer_protagonist"
            },
            {
                "name": "ancient ruins",
                "priority": 0.9,
                "required": true,
                "context_role": "mysterious_location"
            }
        ],
        "time_scope": {
            "type": "Historical",
            "narrative_timeframe": "connecting_past_to_present"
        },
        "spatial_scope": {
            "location_name": "Keth_ancient_ruins",
            "include_contained": true,
            "spatial_narrative": "mysterious_archaeological_site"
        },
        "reasoning_depth": "Deep",
        "context_priorities": ["SpatialContext", "TemporalState", "Entities", "CausalChains"],
        "query_strategies": [
            "retrieve_historical_location_significance",
            "get_atmospheric_environmental_details",
            "find_related_archaeological_discoveries",
            "check_character_relevant_knowledge_skills"
        ],
        "confidence": 0.85
    }"#;

    let mock_client = MockAiClient::new_with_response(mock_response.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let user_query = "Zara carefully approaches the weathered stone archway, her archaeologist training telling her these symbols are far older than anything she's seen before.";
    
    let intent = service.detect_narrative_intent(user_query, None).await.unwrap();
    
    // Verify exploration scene analysis
    assert!(intent.narrative_analysis.contains("exploring"));
    assert!(intent.narrative_analysis.contains("discovery"));
    assert!(intent.narrative_analysis.contains("mysterious"));
    
    // Check exploration-appropriate context needs
    assert!(intent.context_needs.contains(&"Historical significance and past events at this location".to_string()));
    assert!(intent.context_needs.contains(&"Environmental atmosphere and mysterious elements".to_string()));
    
    // Verify scene context captures exploration nature
    assert_eq!(intent.scene_context.get("current_scene_type").unwrap().as_str().unwrap(), "exploration_discovery");
    assert_eq!(intent.scene_context.get("narrative_goal").unwrap().as_str().unwrap(), "world_building_mystery_revelation");
    
    // Check historical time scope for archaeological context
    assert!(matches!(intent.time_scope, TimeScope::Historical(_)));
    
    // Verify query strategies focus on discovery and history
    assert!(intent.query_strategies.contains(&"retrieve_historical_location_significance".to_string()));
    assert!(intent.query_strategies.contains(&"get_atmospheric_environmental_details".to_string()));
}