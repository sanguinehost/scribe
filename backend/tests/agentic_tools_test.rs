use scribe_backend::services::agentic::{
    AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
    ScribeTool,
};
use scribe_backend::test_helpers::TestDataGuard;
use serde_json::json;

#[tokio::test]
async fn test_analyze_text_significance_basic() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = AnalyzeTextSignificanceTool::new(test_app.app_state.clone());
    
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
    
    let session_dek = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&params, &session_dek).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["is_significant"].is_boolean());
    assert!(output["confidence"].is_number());
}

#[tokio::test]
async fn test_extract_temporal_events_basic() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = ExtractTemporalEventsTool::new(test_app.app_state.clone());
    
    let params = json!({
        "messages": [
            {"role": "user", "content": "We fought the dragon"},
            {"role": "assistant", "content": "The dragon was defeated"}
        ]
    });
    
    let session_dek = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&params, &session_dek).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["events"].is_array());
}

#[tokio::test]
async fn test_extract_world_concepts_basic() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = ExtractWorldConceptsTool::new(test_app.app_state.clone());
    
    let params = json!({
        "messages": [
            {"role": "user", "content": "Tell me about the wizard"},
            {"role": "assistant", "content": "The wizard Gandalf is wise"}
        ]
    });
    
    let session_dek = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&params, &session_dek).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output["concepts"].is_array());
}

#[tokio::test]
async fn test_tool_error_handling() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = AnalyzeTextSignificanceTool::new(test_app.app_state.clone());
    
    // Missing required field should return error
    let invalid_params = json!({});
    let session_dek = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&invalid_params, &session_dek).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("messages array is required"));
    
    // Wrong type for messages should return error
    let wrong_type_params = json!({
        "messages": "not an array"
    });
    let session_dek2 = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&wrong_type_params, &session_dek2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("messages array is required"));
    
    // Empty messages array should work (returns not significant)
    let empty_messages_params = json!({
        "messages": []
    });
    let session_dek3 = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let result = tool.execute(&empty_messages_params, &session_dek3).await;
    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output["is_significant"], false);
    assert!(output["reason"].as_str().unwrap().contains("No content to analyze"));
}

#[tokio::test]
async fn test_workflow_simulation() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Simulate the 4-step workflow with our atomic tools
    let triage_tool = AnalyzeTextSignificanceTool::new(test_app.app_state.clone());
    let messages = json!({
        "messages": [
            {"role": "user", "content": "The party entered the ancient temple"},
            {"role": "assistant", "content": "Inside, they found mystical artifacts"}
        ]
    });
    
    let session_dek = scribe_backend::auth::session_dek::SessionDek::generate_new();
    let triage_result = triage_tool.execute(&messages, &session_dek).await.unwrap();
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
        
        let events_tool = ExtractTemporalEventsTool::new(test_app.app_state.clone());
        let concepts_tool = ExtractWorldConceptsTool::new(test_app.app_state.clone());
        
        let events_result = events_tool.execute(&messages, &session_dek).await.unwrap();
        let concepts_result = concepts_tool.execute(&messages, &session_dek).await.unwrap();
        
        let events = events_result["events"].as_array().unwrap();
        let concepts = concepts_result["concepts"].as_array().unwrap();
        
        // In a real workflow, the agent would analyze these results
        // and decide which create_* tools to call
        assert!(!events.is_empty() || !concepts.is_empty());
    }
    
    // Step 4: Atomic creation would happen here
    // (CreateChronicleEventTool and CreateLorebookEntryTool require DB)
}