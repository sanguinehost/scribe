use scribe_backend::services::agentic::{
    AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
    ScribeTool,
};
use scribe_backend::test_helpers::MockAiClient;
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_analyze_text_significance_basic() {
    // Configure mock AI client to return valid JSON response
    let mock_response = json!({
        "is_significant": true,
        "confidence": 0.8,
        "reason": "Test conversation contains greeting",
        "suggested_categories": ["lorebook_entries"]
    });
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
    let tool = AnalyzeTextSignificanceTool::new(mock_ai_client);
    
    // Test schema
    let schema = tool.input_schema();
    assert!(schema["properties"]["messages"].is_object());
    assert_eq!(schema["required"], json!(["messages"]));
    
    // Test execution
    let params = json!({
        "messages": [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"}
        ]
    });
    
    let result = tool.execute(&params).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["is_significant"].is_boolean());
    assert!(output["confidence"].is_number());
}

#[tokio::test]
async fn test_extract_temporal_events_basic() {
    // Configure mock AI client to return valid JSON response
    let mock_response = json!({
        "events": [
            {
                "event_type": "COMBAT",
                "summary": "Dragon battle",
                "participants": ["Player", "Dragon"],
                "location": "Unknown",
                "timestamp": "now"
            }
        ]
    });
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
    let tool = ExtractTemporalEventsTool::new(mock_ai_client);
    
    let params = json!({
        "messages": [
            {"role": "user", "content": "We fought the dragon"},
            {"role": "assistant", "content": "The dragon was defeated"}
        ]
    });
    
    let result = tool.execute(&params).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["events"].is_array());
}

#[tokio::test]
async fn test_extract_world_concepts_basic() {
    // Configure mock AI client to return valid JSON response
    let mock_response = json!({
        "concepts": [
            {
                "name": "Gandalf",
                "type": "character",
                "description": "A wise wizard",
                "tags": ["wizard", "wise"]
            }
        ]
    });
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
    let tool = ExtractWorldConceptsTool::new(mock_ai_client);
    
    let params = json!({
        "messages": [
            {"role": "user", "content": "Tell me about the wizard"},
            {"role": "assistant", "content": "The wizard Gandalf is wise"}
        ]
    });
    
    let result = tool.execute(&params).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["concepts"].is_array());
}

#[tokio::test]
async fn test_tool_error_handling() {
    // Configure mock AI client to return valid JSON response
    let mock_response = json!({
        "is_significant": false,
        "confidence": 0.1,
        "reason": "Test error handling",
        "suggested_categories": []
    });
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
    let tool = AnalyzeTextSignificanceTool::new(mock_ai_client);
    
    // Missing required field should return error
    let invalid_params = json!({});
    let result = tool.execute(&invalid_params).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("messages array is required"));
    
    // Wrong type for messages should return error
    let wrong_type_params = json!({
        "messages": "not an array"
    });
    let result = tool.execute(&wrong_type_params).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("messages array is required"));
    
    // Empty messages array should work (returns not significant)
    let empty_messages_params = json!({
        "messages": []
    });
    let result = tool.execute(&empty_messages_params).await;
    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output["is_significant"], false);
    assert!(output["reason"].as_str().unwrap().contains("No content to analyze"));
}

#[tokio::test]
async fn test_workflow_simulation() {
    // Simulate the 4-step workflow with our atomic tools
    
    // Step 1: Triage
    let triage_response = json!({
        "is_significant": true,
        "confidence": 0.9,
        "reason": "Temple exploration with artifact discovery is significant",
        "suggested_categories": ["chronicle_events", "lorebook_entries"]
    });
    
    let mock_ai_client_triage = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));
    let triage_tool = AnalyzeTextSignificanceTool::new(mock_ai_client_triage);
    let messages = json!({
        "messages": [
            {"role": "user", "content": "The party entered the ancient temple"},
            {"role": "assistant", "content": "Inside, they found mystical artifacts"}
        ]
    });
    
    let triage_result = triage_tool.execute(&messages).await.unwrap();
    let is_significant = triage_result["is_significant"].as_bool().unwrap();
    
    assert!(is_significant);
    
    // Step 2: Knowledge search would happen here
    // (SearchKnowledgeBaseTool has placeholder implementation)
    
    // Step 3: Extract information
    if is_significant {
        let events_response = json!({
            "events": [
                {
                    "event_type": "EXPLORATION",
                    "summary": "Temple exploration",
                    "participants": ["Party"],
                    "location": "Ancient Temple",
                    "timestamp": "now"
                }
            ]
        });
        
        let concepts_response = json!({
            "concepts": [
                {
                    "name": "Ancient Temple",
                    "type": "location",
                    "description": "A temple with mystical artifacts",
                    "tags": ["temple", "ancient", "mystical"]
                }
            ]
        });
        
        let mock_ai_client_events = Arc::new(MockAiClient::new_with_response(events_response.to_string()));
        let mock_ai_client_concepts = Arc::new(MockAiClient::new_with_response(concepts_response.to_string()));
        let events_tool = ExtractTemporalEventsTool::new(mock_ai_client_events);
        let concepts_tool = ExtractWorldConceptsTool::new(mock_ai_client_concepts);
        
        let events_result = events_tool.execute(&messages).await.unwrap();
        let concepts_result = concepts_tool.execute(&messages).await.unwrap();
        
        let events = events_result["events"].as_array().unwrap();
        let concepts = concepts_result["concepts"].as_array().unwrap();
        
        // In a real workflow, the agent would analyze these results
        // and decide which create_* tools to call
        assert!(!events.is_empty() || !concepts.is_empty());
    }
    
    // Step 4: Atomic creation would happen here
    // (CreateChronicleEventTool and CreateLorebookEntryTool require DB)
}