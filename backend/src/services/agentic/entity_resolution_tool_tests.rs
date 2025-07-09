// Tests for the EntityResolutionTool - Flash-powered entity resolution system
//
// This test suite validates the key functionality of the entity resolution system:
// - Entity creation and updates
// - Duplicate detection and prevention
// - Component extraction from narrative context
// - Processing mode handling (batch vs incremental)
// - Lifecycle management and validation

use super::{EntityResolutionTool, ProcessingMode};
use crate::services::agentic::tools::{ScribeTool, ToolError};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_entity_resolution_tool_creation() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create AppState using the same pattern as working tests
    let services = crate::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
    };
    
    let app_state = Arc::new(crate::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let tool = EntityResolutionTool::new(app_state);
    
    assert_eq!(tool.name(), "resolve_entities");
    assert_eq!(
        tool.description(),
        "Resolves entity names from narrative text to existing entities or creates new ones with rich component data extracted from context."
    );
    
    // Validate input schema has required fields
    let schema = tool.input_schema();
    let properties = schema.get("properties").unwrap();
    assert!(properties.get("user_id").is_some());
    assert!(properties.get("narrative_text").is_some());
    assert!(properties.get("entity_names").is_some());
}

#[tokio::test]
async fn test_processing_mode_enum() {
    let incremental = ProcessingMode::Incremental;
    let batch = ProcessingMode::Batch;
    
    assert_eq!(incremental.to_string(), "incremental");
    assert_eq!(batch.to_string(), "batch");
}

#[tokio::test]
async fn test_narrative_context_creation() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create AppState using the same pattern as working tests
    let services = crate::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
    };
    
    let app_state = Arc::new(crate::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let tool = EntityResolutionTool::new(app_state);
    
    let actors = vec![
        json!({
            "entity_name": "Elara",
            "role": "AGENT",
            "context": "brave warrior wielding a sword"
        }),
        json!({
            "entity_name": "ancient dragon",
            "role": "OPPONENT",
            "context": "breathing fire"
        })
    ];
    
    let narrative_context = tool.create_narrative_context_from_actors(&actors);
    
    assert!(narrative_context.contains("Elara"));
    assert!(narrative_context.contains("ancient dragon"));
    assert!(narrative_context.contains("AGENT"));
    assert!(narrative_context.contains("OPPONENT"));
    assert!(narrative_context.contains("brave warrior"));
    assert!(narrative_context.contains("breathing fire"));
}

#[tokio::test]
async fn test_error_handling() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create AppState using the same pattern as working tests
    let services = crate::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
    };
    
    let app_state = Arc::new(crate::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let tool = EntityResolutionTool::new(app_state);
    
    // Test with invalid parameters
    let invalid_params = json!({
        "invalid_field": "invalid_value"
    });
    
    let result = tool.execute(&invalid_params).await;
    assert!(result.is_err());
    
    if let Err(error) = result {
        match error {
            ToolError::InvalidParams(_) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidParams error"),
        }
    }
}
#[tokio::test]
async fn test_truncated_ai_response_handling() {
    let test_app = crate::test_helpers::spawn_app(true, false, false).await;
    let user_id = uuid::Uuid::new_v4();

    // Simulate a truncated AI response
    let truncated_response = r#"```json
{
  "resolved_entities": [
    {
      "input_name": "vargo_id",
      "entity_id": "e2f3g4h5-i6j7-8901-2345-67890abcdef0",
      "is_new": true,
      "confidence": 1.0,
      "components": {
        "Name": {
          "name": "vargo_id",
          "display_name": "Vargo"
        }
"#; // Note the missing closing braces and backticks

    test_app.ai_client.set_next_chat_response(truncated_response.to_string());

    let tool = EntityResolutionTool::new(test_app.app_state.clone());

    let params = json!({
        "user_id": user_id.to_string(),
        "narrative_text": "An urgent message from Vargo.",
        "entity_names": ["vargo_id"]
    });

    let result = tool.execute(&params).await;

    // Assert that the tool returns a parsing error, not a panic
    assert!(result.is_err());
    if let Err(ToolError::ExecutionFailed(msg)) = result {
        assert!(msg.contains("Failed to parse AI response"));
    } else {
        panic!("Expected ExecutionFailed error due to parsing failure, but got a different result.");
    }
}
