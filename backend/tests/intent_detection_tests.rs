use scribe_backend::{
    services::intent_detection_service::{
        IntentDetectionService, IntentType, 
        ReasoningDepth, ContextPriority, TimeScope
    },
    test_helpers::MockAiClient,
};
use std::sync::Arc;

#[tokio::test]
async fn test_detect_intent_causal_analysis() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
        "intent_type": "CausalAnalysis",
        "focus_entities": [
            {
                "name": "Luke",
                "entity_type": "CHARACTER",
                "priority": 1.0,
                "required": true
            }
        ],
        "time_scope": {
            "type": "AllTime"
        },
        "spatial_scope": null,
        "reasoning_depth": "Deep",
        "context_priorities": ["CausalChains", "Entities", "TemporalState"],
        "confidence": 0.95
    }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "What caused Luke to leave Tatooine?",
        None
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::CausalAnalysis);
    assert_eq!(result.reasoning_depth, ReasoningDepth::Deep);
    assert_eq!(result.focus_entities.len(), 1);
    assert_eq!(result.focus_entities[0].name, "Luke");
    assert_eq!(result.focus_entities[0].priority, 1.0);
    assert!(result.focus_entities[0].required);
    assert_eq!(result.confidence, 0.95);
    assert_eq!(result.context_priorities[0], ContextPriority::CausalChains);
}

#[tokio::test]
async fn test_detect_intent_spatial_analysis() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
        "intent_type": "SpatialAnalysis",
        "focus_entities": [],
        "time_scope": {
            "type": "Current"
        },
        "spatial_scope": {
            "location_name": "cantina",
            "radius": null,
            "include_contained": true
        },
        "reasoning_depth": "Analytical",
        "context_priorities": ["SpatialContext", "Entities", "RecentEvents"],
        "confidence": 0.88
    }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "Who is in the cantina right now?",
        None
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::SpatialAnalysis);
    assert_eq!(result.reasoning_depth, ReasoningDepth::Analytical);
    assert!(matches!(result.time_scope, TimeScope::Current));
    assert!(result.spatial_scope.is_some());
    
    let spatial = result.spatial_scope.unwrap();
    assert_eq!(spatial.location_name, Some("cantina".to_string()));
    assert!(spatial.include_contained);
}

#[tokio::test]
async fn test_detect_intent_relationship_query() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
        "intent_type": "RelationshipQuery",
        "focus_entities": [
            {
                "name": "Vader",
                "entity_type": "CHARACTER",
                "priority": 1.0,
                "required": true
            },
            {
                "name": "Obi-Wan",
                "entity_type": "CHARACTER", 
                "priority": 1.0,
                "required": true
            }
        ],
        "time_scope": {
            "type": "AllTime"
        },
        "spatial_scope": null,
        "reasoning_depth": "Analytical",
        "context_priorities": ["Relationships", "Entities", "TemporalState"],
        "confidence": 0.92
    }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "How do Vader and Obi-Wan feel about each other?",
        Some("They have a complex history")
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::RelationshipQuery);
    assert_eq!(result.focus_entities.len(), 2);
    assert_eq!(result.focus_entities[0].name, "Vader");
    assert_eq!(result.focus_entities[1].name, "Obi-Wan");
    assert_eq!(result.context_priorities[0], ContextPriority::Relationships);
}

#[tokio::test]
async fn test_detect_narrative_intent_combat_scene() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
        "narrative_analysis": "The user is initiating a combat scene where the protagonist is drawing their weapon in response to a threat. This is a high-tension action sequence that requires immediate tactical context and character readiness information.",
        "context_needs": [
            "Character's combat abilities and equipment status",
            "Environmental hazards and tactical advantages",
            "Enemy threat assessment and positions"
        ],
        "scene_context": {
            "current_scene_type": "combat_encounter",
            "narrative_goal": "tension_building",
            "emotional_tone": "high_action_excitement",
            "relationship_focus": "protagonist_vs_antagonists"
        },
        "focus_entities": [
            {
                "name": "protagonist",
                "priority": 1.0,
                "required": true,
                "context_role": "primary_combatant"
            },
            {
                "name": "beast",
                "priority": 0.9,
                "required": true,
                "context_role": "primary_threat"
            }
        ],
        "time_scope": {
            "type": "Current",
            "narrative_timeframe": "immediate_action"
        },
        "spatial_scope": {
            "location_name": "combat_arena",
            "include_contained": true,
            "spatial_narrative": "tactical_combat_environment"
        },
        "reasoning_depth": "Analytical",
        "context_priorities": ["Entities", "SpatialContext", "RecentEvents"],
        "query_strategies": [
            "analyze_combat_readiness_status",
            "get_entity_equipment_status",
            "retrieve_location_tactical_details"
        ],
        "confidence": 0.94
    }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_narrative_intent(
        "I draw my sword and face the beast",
        None
    ).await.unwrap();
    
    assert!(result.narrative_analysis.contains("combat scene"));
    assert_eq!(result.context_needs.len(), 3);
    assert_eq!(result.scene_context.get("current_scene_type").unwrap(), "combat_encounter");
    assert_eq!(result.focus_entities.len(), 2);
    assert_eq!(result.focus_entities[0].name, "protagonist");
    assert_eq!(result.focus_entities[0].entity_type, Some("primary_combatant".to_string()));
    assert_eq!(result.query_strategies.len(), 3);
    assert!(result.query_strategies.contains(&"analyze_combat_readiness_status".to_string()));
}

#[tokio::test]
async fn test_detect_narrative_intent_emotional_scene() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "narrative_analysis": "The user is transitioning to a domestic family scene with emotional undertones. The sigh indicates weariness or concern, suggesting this is a character development moment focused on family relationships and emotional state.",
            "context_needs": [
                "Character's current emotional state",
                "Children's activities and wellbeing",
                "Recent family dynamics and events",
                "Domestic setting atmosphere"
            ],
            "scene_context": {
                "current_scene_type": "family_domestic",
                "narrative_goal": "character_development",
                "emotional_tone": "warm_intimate",
                "relationship_focus": "parent_child_dynamics"
            },
            "focus_entities": [
                {
                    "name": "Lumiya",
                    "priority": 1.0,
                    "required": true,
                    "context_role": "caring_parent"
                },
                {
                    "name": "children",
                    "priority": 0.8,
                    "required": true,
                    "context_role": "family_members"
                }
            ],
            "time_scope": {
                "type": "Recent",
                "narrative_timeframe": "immediate_scene_transition",
                "duration_hours": 4
            },
            "spatial_scope": {
                "location_name": "home",
                "include_contained": true,
                "spatial_narrative": "intimate_private_space"
            },
            "reasoning_depth": "Deep",
            "context_priorities": ["Entities", "Relationships", "RecentEvents", "SpatialContext"],
            "query_strategies": [
                "get_entity_emotional_state",
                "find_recent_relationship_interactions",
                "retrieve_domestic_setting_details"
            ],
            "confidence": 0.91
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_narrative_intent(
        "Lumiya sighs and goes to check on her children",
        Some("Earlier there was a tense family discussion")
    ).await.unwrap();
    
    assert!(result.narrative_analysis.contains("domestic family scene"));
    assert_eq!(result.scene_context.get("current_scene_type").unwrap(), "family_domestic");
    assert_eq!(result.scene_context.get("emotional_tone").unwrap(), "warm_intimate");
    assert_eq!(result.focus_entities[0].entity_type, Some("caring_parent".to_string()));
    assert_eq!(result.reasoning_depth, ReasoningDepth::Deep);
}

#[tokio::test]
async fn test_detect_intent_temporal_analysis() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "intent_type": "TemporalAnalysis",
            "focus_entities": [
                {
                    "name": "Empire",
                    "entity_type": "ORGANIZATION",
                    "priority": 0.9,
                    "required": false
                }
            ],
            "time_scope": {
                "type": "Range",
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2024-06-30T23:59:59Z"
            },
            "spatial_scope": null,
            "reasoning_depth": "Analytical",
            "context_priorities": ["TemporalState", "RecentEvents", "Entities"],
            "confidence": 0.87
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "What major events happened in the first half of 2024?",
        None
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::TemporalAnalysis);
    if let TimeScope::Range(start, end) = result.time_scope {
        assert_eq!(start.format("%Y-%m-%d").to_string(), "2024-01-01");
        assert_eq!(end.format("%Y-%m-%d").to_string(), "2024-06-30");
    } else {
        panic!("Expected Range time scope");
    }
}

#[tokio::test]
async fn test_detect_intent_predictive_query() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "intent_type": "PredictiveQuery",
            "focus_entities": [
                {
                    "name": "rebellion",
                    "entity_type": "ORGANIZATION",
                    "priority": 1.0,
                    "required": true
                },
                {
                    "name": "Death Star",
                    "entity_type": "WEAPON",
                    "priority": 0.95,
                    "required": true
                }
            ],
            "time_scope": {
                "type": "Current"
            },
            "spatial_scope": null,
            "reasoning_depth": "Causal",
            "context_priorities": ["CausalChains", "Entities", "TemporalState"],
            "confidence": 0.82
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "What might happen if the rebellion discovers the Death Star plans?",
        None
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::PredictiveQuery);
    assert_eq!(result.reasoning_depth, ReasoningDepth::Causal);
    assert_eq!(result.context_priorities[0], ContextPriority::CausalChains);
    assert_eq!(result.focus_entities.len(), 2);
}

#[tokio::test]
async fn test_detect_intent_with_conversation_context() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [
                {
                    "name": "Sol",
                    "entity_type": "CHARACTER",
                    "priority": 1.0,
                    "required": true
                }
            ],
            "time_scope": {
                "type": "Current"
            },
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities", "SpatialContext", "TemporalState"],
            "confidence": 0.96
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "Where is he now?",
        Some("We were just talking about Sol and his journey")
    ).await.unwrap();
    
    assert_eq!(result.intent_type, IntentType::StateInquiry);
    assert_eq!(result.focus_entities[0].name, "Sol");
    assert_eq!(result.reasoning_depth, ReasoningDepth::Surface);
}

#[tokio::test]
async fn test_detect_intent_recent_time_scope() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "intent_type": "TemporalAnalysis",
            "focus_entities": [],
            "time_scope": {
                "type": "Recent",
                "duration_hours": 48
            },
            "spatial_scope": null,
            "reasoning_depth": "Analytical",
            "context_priorities": ["RecentEvents", "TemporalState"],
            "confidence": 0.85
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "What happened in the last two days?",
        None
    ).await.unwrap();
    
    if let TimeScope::Recent(duration) = result.time_scope {
        assert_eq!(duration.num_hours(), 48);
    } else {
        panic!("Expected Recent time scope");
    }
}

#[tokio::test]
async fn test_ai_response_parsing_error() {
    let mock_ai_client = MockAiClient::new_with_response("This is not valid JSON".to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_intent(
        "What caused the error?",
        None
    ).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Failed to parse Flash intent response"));
}

#[tokio::test]
async fn test_narrative_intent_missing_required_fields() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "context_needs": ["Some context"],
            "confidence": 0.5
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_narrative_intent(
        "Test narrative",
        None
    ).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("AI didn't provide narrative_analysis"));
}

#[tokio::test]
async fn test_narrative_intent_exploration_scene() {
    let mock_ai_client = MockAiClient::new_with_response(r#"{
            "narrative_analysis": "The user is examining ancient symbols, indicating an exploration/discovery scene. This requires historical context and archaeological details to create an engaging moment of revelation.",
            "context_needs": [
                "Historical significance of the location",
                "Character's archaeological knowledge",
                "Previous discoveries in this area"
            ],
            "scene_context": {
                "current_scene_type": "exploration_discovery",
                "narrative_goal": "world_building",
                "emotional_tone": "mysterious_foreboding",
                "relationship_focus": "character_vs_environment"
            },
            "focus_entities": [
                {
                    "name": "archaeologist",
                    "priority": 1.0,
                    "required": true,
                    "context_role": "primary_investigator"
                },
                {
                    "name": "ancient_temple",
                    "priority": 0.85,
                    "required": true,
                    "context_role": "mysterious_location"
                }
            ],
            "time_scope": {
                "type": "Current",
                "narrative_timeframe": "discovery_moment"
            },
            "spatial_scope": {
                "location_name": "ancient_temple",
                "include_contained": true,
                "spatial_narrative": "mysterious_archaeological_site"
            },
            "reasoning_depth": "Deep",
            "context_priorities": ["SpatialContext", "TemporalState", "Entities"],
            "query_strategies": [
                "get_historical_location_significance",
                "check_character_skills_equipment",
                "retrieve_location_atmospheric_details"
            ],
            "confidence": 0.89
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client), "gemini-2.5-flash-lite-preview-06-17".to_string());
    
    let result = service.detect_narrative_intent(
        "She examines the ancient symbols carved into the stone",
        None
    ).await.unwrap();
    
    assert_eq!(result.scene_context.get("current_scene_type").unwrap(), "exploration_discovery");
    assert_eq!(result.scene_context.get("narrative_goal").unwrap(), "world_building");
    assert!(result.query_strategies.contains(&"get_historical_location_significance".to_string()));
}