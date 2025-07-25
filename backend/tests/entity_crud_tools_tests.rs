//! Functional Tests for Entity CRUD Tools
//!
//! This test suite validates the AI-driven entity CRUD tools including the new QuerySpatialTypesTool

use scribe_backend::{
    services::agentic::tools::{
        ScribeTool,
        entity_crud_tools::{QuerySpatialTypesTool, FindEntityTool},
    },
    test_helpers::*,
    auth::session_dek::SessionDek,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_all_types() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "all_types"
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    // Verify the result contains all expected spatial type categories
    assert!(result.get("cosmic_types").is_some());
    assert!(result.get("vehicle_types").is_some());
    assert!(result.get("geographic_types").is_some());
    assert!(result.get("political_types").is_some());
    assert!(result.get("structural_types").is_some());
    assert!(result.get("intimate_types").is_some());
    assert!(result.get("custom_types").is_some());
    
    // Verify specific cosmic types are present
    let cosmic_types = result.get("cosmic_types").unwrap().as_array().unwrap();
    assert!(cosmic_types.iter().any(|v| v.as_str() == Some("Galaxy")));
    assert!(cosmic_types.iter().any(|v| v.as_str() == Some("Planet")));
    assert!(cosmic_types.iter().any(|v| v.as_str() == Some("SpaceStation")));
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_cosmic_types() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "cosmic_types"
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    // Verify structure
    assert!(result.get("types").is_some());
    assert!(result.get("description").is_some());
    
    let types = result.get("types").unwrap().as_array().unwrap();
    assert!(types.len() > 10); // Should have many cosmic types
    assert!(types.iter().any(|v| v.as_str() == Some("Universe")));
    assert!(types.iter().any(|v| v.as_str() == Some("Galaxy")));
    assert!(types.iter().any(|v| v.as_str() == Some("StarSystem")));
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_containment_rules() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "containment_rules"
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    // Verify structure
    assert!(result.get("examples").is_some());
    assert!(result.get("note").is_some());
    
    let examples = result.get("examples").unwrap().as_object().unwrap();
    assert!(examples.contains_key("Universe"));
    assert!(examples.contains_key("Galaxy"));
    assert!(examples.contains_key("Planet"));
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_invalid_query_type() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "invalid_type"
    });
    
    let result = tool.execute(&params, &session_dek).await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore] // Requires database and Redis setup  
async fn test_query_spatial_types_missing_query_type() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({});
    
    let result = tool.execute(&params, &session_dek).await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_find_entity_tool_fixed_json_schema() {
    let app = spawn_app(false, false, false).await;
    
    let tool = FindEntityTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // This test verifies that the JSON schema fix allows the tool to execute
    // without the "properties should be non-empty for OBJECT type" error
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "search_request": "find magical items",
        "context": "Testing the fixed JSON schema"
    });
    
    // The tool should not fail with JSON schema validation errors
    // Note: It might still fail with other errors (like AI API calls) but not schema validation
    let result = tool.execute(&params, &session_dek).await;
    
    // We primarily care that it doesn't fail with schema validation errors
    // The actual result might vary based on AI responses
    match result {
        Ok(_) => {
            // Success - schema validation worked
        },
        Err(err) => {
            // Make sure it's not a schema validation error
            let error_msg = format!("{:?}", err);
            assert!(!error_msg.contains("properties: should be non-empty for OBJECT type"));
            assert!(!error_msg.contains("relationship_constraints"));
        }
    }
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_planetary_types() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "planetary_types"
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    let types = result.get("types").unwrap().as_array().unwrap();
    assert!(types.iter().any(|v| v.as_str() == Some("Continent")));
    assert!(types.iter().any(|v| v.as_str() == Some("City")));
    assert!(types.iter().any(|v| v.as_str() == Some("Forest")));
    assert!(types.iter().any(|v| v.as_str() == Some("Kingdom")));
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_intimate_types() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "intimate_types" 
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    let types = result.get("types").unwrap().as_array().unwrap();
    assert!(types.iter().any(|v| v.as_str() == Some("Building")));
    assert!(types.iter().any(|v| v.as_str() == Some("Room")));
    assert!(types.iter().any(|v| v.as_str() == Some("Furniture")));
    assert!(types.iter().any(|v| v.as_str() == Some("Container")));
}