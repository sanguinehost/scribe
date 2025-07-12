// Integration tests for AI-powered foundational tools
// Tests the AI-driven hierarchy and salience management tools using centralized test infrastructure

use scribe_backend::{
    services::agentic::tools::{
        ai_powered_tools::{AnalyzeHierarchyRequestTool, SuggestHierarchyPromotionTool, UpdateSalienceTool},
        ScribeTool,
    },
    test_helpers::ai_tool_testing::{
        setup_tool_test, configure_mock_ai_response, configure_mock_ai_error,
        create_tool_with_app_state, execute_tool_test, create_test_user_id,
        verify_tool_schema, verify_tool_output, test_tool_error_handling,
        ToolTestConfig,
    },
};
use serde_json::json;

#[tokio::test]
async fn test_analyze_hierarchy_request_basic() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock AI response
    let mock_response = json!({
        "interpretation": "User wants to see the command structure of the Crimson Fleet",
        "query_type": "command_structure",
        "target_entities": ["Crimson Fleet"],
        "scope": "Cosmic",
        "reasoning": "The request mentions 'chain of command' which indicates organizational hierarchy",
        "suggested_query": {
            "action": "get_entity_hierarchy",
            "parameters": {}
        }
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    // Create tool using centralized helper
    let tool: AnalyzeHierarchyRequestTool = create_tool_with_app_state(setup.app.app_state.clone());

    // Test schema validation
    let schema = tool.input_schema();
    verify_tool_schema(&schema, &["user_id", "natural_language_request"])
        .expect("Schema validation failed");

    // Test tool execution
    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "natural_language_request": "Show me the chain of command for the Crimson Fleet",
        "available_entities": "Crimson Fleet Admiral, Crimson Fleet Captain, Crimson Fleet Destroyer"
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    
    // The output has the interpretation nested inside an "interpretation" field
    verify_tool_output(&output, &["interpretation", "status", "reason"])
        .expect("Output validation failed");
    
    let interpretation = &output["interpretation"];
    verify_tool_output(interpretation, &["interpretation", "query_type", "target_entities", "scope", "reasoning"])
        .expect("Interpretation structure validation failed");
}

#[tokio::test]
async fn test_analyze_hierarchy_request_spatial_query() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for spatial containment query
    let mock_response = json!({
        "interpretation": "User wants to know what galaxy contains this planet",
        "query_type": "hierarchy_path",
        "target_entities": ["Tatooine"],
        "scope": "Cosmic",
        "reasoning": "Question asks about galactic containment hierarchy",
        "suggested_query": {
            "action": "get_entity_hierarchy",
            "parameters": {}
        }
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: AnalyzeHierarchyRequestTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "natural_language_request": "What galaxy is Tatooine in?",
        "available_entities": "Tatooine, Outer Rim, Unknown Galaxy"
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    let interpretation = &output["interpretation"];
    assert_eq!(interpretation["query_type"], "hierarchy_path");
    assert_eq!(interpretation["scope"], "Cosmic");
    assert!(interpretation["target_entities"].as_array().unwrap().contains(&json!("Tatooine")));
}

#[tokio::test]
async fn test_suggest_hierarchy_promotion_basic() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for promotion suggestions
    let mock_response = json!({
        "analysis": "The Crimson Fleet has been mentioned frequently and is central to ongoing conflicts",
        "promotion_suggestions": [
            {
                "entity_name": "Crimson Fleet",
                "current_perceived_tier": "Flavor",
                "suggested_new_tier": "Core",
                "reasoning": "Referenced 5 times as major antagonist organization",
                "evidence": [
                    "The Crimson Fleet attacked the settlement",
                    "Captain mentioned Crimson Fleet orders"
                ],
                "suggested_hierarchy": {
                    "new_parent_name": "Outer Rim Criminal Organizations",
                    "scale": "Cosmic",
                    "relationship_type": "organizational"
                }
            }
        ],
        "confidence": 0.9
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: SuggestHierarchyPromotionTool = create_tool_with_app_state(setup.app.app_state.clone());

    // Test schema validation
    let schema = tool.input_schema();
    verify_tool_schema(&schema, &["user_id", "narrative_text"])
        .expect("Schema validation failed");

    // Test execution
    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "narrative_text": "The Crimson Fleet ships appeared on the horizon. Captain Sarah contacted the Crimson Fleet admiral. The Crimson Fleet has been terrorizing this sector for months.",
        "current_entities": ["Captain Sarah", "Unknown Ships"]
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    verify_tool_output(&output, &["analysis", "promotion_suggestions", "confidence"])
        .expect("Output validation failed");

    let suggestions = output["promotion_suggestions"].as_array().unwrap();
    assert!(!suggestions.is_empty());

    let first_suggestion = &suggestions[0];
    verify_tool_output(first_suggestion, &["entity_name", "suggested_new_tier", "reasoning", "evidence"])
        .expect("Suggestion structure validation failed");
}

#[tokio::test]
async fn test_suggest_hierarchy_promotion_no_promotions() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for no promotions needed
    let mock_response = json!({
        "analysis": "Narrative contains only existing Core entities and minimal background details",
        "promotion_suggestions": [],
        "confidence": 0.7
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: SuggestHierarchyPromotionTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "narrative_text": "Luke walked to the store and bought some milk. The weather was nice.",
        "current_entities": ["Luke Skywalker"]
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    let suggestions = output["promotion_suggestions"].as_array().unwrap();
    assert!(suggestions.is_empty());
}

#[tokio::test]
async fn test_update_salience_core_entity() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for Core salience assignment
    let mock_response = json!({
        "analysis": "Luke Skywalker is the main protagonist and central to all narrative events",
        "recommended_tier": "Core",
        "reasoning": "Character drives the plot and is present in all major scenes",
        "confidence": 0.95,
        "scale_context": "Intimate",
        "interaction_indicators": [
            "Luke performs actions",
            "Luke makes decisions",
            "Luke drives plot forward"
        ],
        "persistence_reasoning": "Main character should always persist across sessions",
        "change_from_current": "maintain"
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());

    // Test schema validation
    let schema = tool.input_schema();
    verify_tool_schema(&schema, &["user_id", "entity_name", "narrative_context"])
        .expect("Schema validation failed");

    // Test execution
    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "entity_name": "Luke Skywalker",
        "narrative_context": "Luke ignited his lightsaber and faced Darth Vader. The fate of the galaxy hung in the balance as Luke made his choice.",
        "current_tier": "Core"
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    verify_tool_output(&output, &["analysis"])
        .expect("Output validation failed");

    let analysis = &output["analysis"];
    assert_eq!(analysis["recommended_tier"], "Core");
    assert!(analysis["confidence"].as_f64().unwrap() > 0.8);
    assert_eq!(analysis["scale_context"], "Intimate");
}

#[tokio::test]
async fn test_update_salience_flavor_to_secondary() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for promotion from Flavor to Secondary
    let mock_response = json!({
        "analysis": "The bartender has become a key information source and quest giver",
        "recommended_tier": "Secondary",
        "reasoning": "Initially background NPC but now provides important quests and information",
        "confidence": 0.8,
        "scale_context": "Intimate",
        "interaction_indicators": [
            "Bartender gives quests",
            "Provides important information",
            "Characters return to speak with bartender"
        ],
        "persistence_reasoning": "Should persist when players are in this area",
        "change_from_current": "upgrade"
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "entity_name": "Tavern Bartender",
        "narrative_context": "The bartender leaned in conspiratorially. 'I have information about the stolen plans,' he whispered. Luke knew this bartender had become a valuable ally.",
        "current_tier": "Flavor"
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    let analysis = &output["analysis"];
    assert_eq!(analysis["recommended_tier"], "Secondary");
    assert_eq!(analysis["change_from_current"], "upgrade");
}

#[tokio::test]
async fn test_update_salience_flavor_scenery() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for maintaining Flavor tier
    let mock_response = json!({
        "analysis": "Random background NPC with no narrative significance",
        "recommended_tier": "Flavor",
        "reasoning": "Mentioned only once as background atmosphere, no interactions or plot relevance",
        "confidence": 0.9,
        "scale_context": "Intimate",
        "interaction_indicators": [],
        "persistence_reasoning": "Pure atmosphere, can be garbage collected when out of scope",
        "change_from_current": "maintain"
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "entity_name": "Random Patron #3",
        "narrative_context": "The cantina was busy. A few patrons sat at the bar drinking."
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    let analysis = &output["analysis"];
    assert_eq!(analysis["recommended_tier"], "Flavor");
    assert_eq!(analysis["change_from_current"], "maintain");
}

#[tokio::test]
async fn test_update_salience_cosmic_scale() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Configure mock for Cosmic scale entity
    let mock_response = json!({
        "analysis": "Death Star is a cosmic-scale superweapon central to galactic conflict",
        "recommended_tier": "Core",
        "reasoning": "Major plot device affecting entire galaxy, central to rebellion storyline",
        "confidence": 0.98,
        "scale_context": "Cosmic",
        "interaction_indicators": [
            "Central to galactic war",
            "Target of major operation",
            "Affects entire star systems"
        ],
        "persistence_reasoning": "Cosmic-scale threats should always be tracked",
        "change_from_current": "initial_assignment"
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, mock_response.clone());
    }

    let tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "entity_name": "Death Star",
        "narrative_context": "The Death Star appeared in the system, its massive presence blocking out the stars. The superweapon capable of destroying entire planets had arrived."
    });

    let result = execute_tool_test(&tool, params).await;
    assert!(result.is_ok(), "Tool execution failed: {:?}", result);

    let output = result.unwrap();
    let analysis = &output["analysis"];
    assert_eq!(analysis["recommended_tier"], "Core");
    assert_eq!(analysis["scale_context"], "Cosmic");
    assert!(analysis["confidence"].as_f64().unwrap() > 0.9);
}

#[tokio::test]
async fn test_analyze_hierarchy_invalid_user_id() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    let tool: AnalyzeHierarchyRequestTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": "invalid-uuid",
        "natural_language_request": "Show me something"
    });

    // Test error handling using centralized helper
    test_tool_error_handling(&tool, params, "Invalid user_id").await
        .expect("Error handling test failed");
}

#[tokio::test]
async fn test_tools_integration_with_error_handling() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Test AI error handling using centralized error configuration
    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_error(mock_ai_client, "AI service unavailable");
    }

    let tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());

    let params = json!({
        "user_id": create_test_user_id().to_string(),
        "entity_name": "Test Entity",
        "narrative_context": "Some context"
    });

    // Test that error propagates correctly
    test_tool_error_handling(&tool, params, "AI service unavailable").await
        .expect("AI error handling test failed");
}

#[tokio::test]
async fn test_comprehensive_tool_workflow() {
    let setup = setup_tool_test(ToolTestConfig::default()).await;
    let _guard = setup.guard;

    // Test a complete workflow using multiple tools
    let user_id = create_test_user_id();

    // Step 1: Analyze a hierarchy request
    let hierarchy_response = json!({
        "interpretation": "User wants to understand fleet command structure",
        "query_type": "command_structure",
        "target_entities": ["Imperial Fleet"],
        "scope": "Cosmic",
        "reasoning": "Request about military hierarchy",
        "suggested_query": {
            "action": "get_entity_hierarchy",
            "parameters": {}
        }
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, hierarchy_response.clone());
    }

    let hierarchy_tool: AnalyzeHierarchyRequestTool = create_tool_with_app_state(setup.app.app_state.clone());
    
    let hierarchy_params = json!({
        "user_id": user_id.to_string(),
        "natural_language_request": "Show me the Imperial Fleet command structure"
    });

    let hierarchy_result = execute_tool_test(&hierarchy_tool, hierarchy_params).await;
    assert!(hierarchy_result.is_ok(), "Hierarchy analysis failed");

    // Step 2: Suggest promotions based on narrative
    let promotion_response = json!({
        "analysis": "Admiral Thrawn emerges as key strategic leader",
        "promotion_suggestions": [
            {
                "entity_name": "Admiral Thrawn",
                "current_perceived_tier": "Secondary",
                "suggested_new_tier": "Core",
                "reasoning": "Central to Imperial strategy and fleet operations",
                "evidence": ["Commands multiple Star Destroyers", "Makes strategic decisions"],
                "suggested_hierarchy": {
                    "new_parent_name": "Imperial High Command",
                    "scale": "Cosmic",
                    "relationship_type": "command_structure"
                }
            }
        ],
        "confidence": 0.95
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, promotion_response.clone());
    }

    let promotion_tool: SuggestHierarchyPromotionTool = create_tool_with_app_state(setup.app.app_state.clone());
    
    let promotion_params = json!({
        "user_id": user_id.to_string(),
        "narrative_text": "Admiral Thrawn studied the tactical display, coordinating the movements of dozens of Star Destroyers across multiple sectors."
    });

    let promotion_result = execute_tool_test(&promotion_tool, promotion_params).await;
    assert!(promotion_result.is_ok(), "Promotion suggestion failed");

    // Step 3: Update salience based on the promotion
    let salience_response = json!({
        "analysis": "Admiral Thrawn has demonstrated strategic importance",
        "recommended_tier": "Core",
        "reasoning": "Key military leader with fleet-wide impact",
        "confidence": 0.95,
        "scale_context": "Cosmic",
        "interaction_indicators": ["Commands fleets", "Makes strategic decisions"],
        "persistence_reasoning": "Critical military leader should always be tracked",
        "change_from_current": "upgrade"
    });

    if let Some(ref mock_ai_client) = setup.mock_ai_client {
        configure_mock_ai_response(mock_ai_client, salience_response.clone());
    }

    let salience_tool: UpdateSalienceTool = create_tool_with_app_state(setup.app.app_state.clone());
    
    let salience_params = json!({
        "user_id": user_id.to_string(),
        "entity_name": "Admiral Thrawn",
        "narrative_context": "Admiral Thrawn's strategic brilliance becomes apparent as he orchestrates complex fleet maneuvers.",
        "current_tier": "Secondary"
    });

    let salience_result = execute_tool_test(&salience_tool, salience_params).await;
    assert!(salience_result.is_ok(), "Salience update failed");

    // Verify the workflow results are consistent
    let hierarchy_output = hierarchy_result.unwrap();
    let promotion_output = promotion_result.unwrap();
    let salience_output = salience_result.unwrap();

    // The hierarchy output has the interpretation nested inside an "interpretation" field
    assert_eq!(hierarchy_output["interpretation"]["scope"], "Cosmic");
    assert!(!promotion_output["promotion_suggestions"].as_array().unwrap().is_empty());
    assert_eq!(salience_output["analysis"]["recommended_tier"], "Core");
}