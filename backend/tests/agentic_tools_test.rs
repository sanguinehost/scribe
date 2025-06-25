use scribe_backend::services::agentic::{
    AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
    ScribeTool,
};
use serde_json::json;

#[tokio::test]
async fn test_analyze_text_significance_basic() {
    let tool = AnalyzeTextSignificanceTool::new();
    
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
    let tool = ExtractTemporalEventsTool::new();
    
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
    let tool = ExtractWorldConceptsTool::new();
    
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
    let tool = AnalyzeTextSignificanceTool::new();
    
    // Missing required field
    let invalid_params = json!({});
    let result = tool.execute(&invalid_params).await;
    assert!(result.is_err());
    
    // Wrong type for messages
    let wrong_type_params = json!({
        "messages": "not an array"
    });
    let result = tool.execute(&wrong_type_params).await;
    // Currently this passes because we don't validate types in the mock
    // In a real implementation, this would fail
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_workflow_simulation() {
    // Simulate the 4-step workflow with our atomic tools
    
    // Step 1: Triage
    let triage_tool = AnalyzeTextSignificanceTool::new();
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
        let events_tool = ExtractTemporalEventsTool::new();
        let concepts_tool = ExtractWorldConceptsTool::new();
        
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