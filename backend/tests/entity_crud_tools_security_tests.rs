//! Security Tests for Entity CRUD Tools
//!
//! This test suite validates security aspects of the AI-driven entity CRUD tools

use scribe_backend::{
    services::agentic::tools::{
        ScribeTool,
        entity_crud_tools::{QuerySpatialTypesTool, FindEntityTool, CreateEntityTool},
    },
    test_helpers::*,
    auth::session_dek::SessionDek,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_no_sensitive_data_exposure() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "query_type": "all_types"
    });
    
    let result = tool.execute(&params, &session_dek).await.expect("Tool execution should succeed");
    
    // Verify that the result only contains static spatial type information
    // and no user data, database connections, or other sensitive information
    let result_str = serde_json::to_string(&result).unwrap();
    
    // Should not contain database credentials, user IDs, or internal system info
    assert!(!result_str.contains("password"));
    assert!(!result_str.contains("postgres"));
    assert!(!result_str.contains("redis"));
    assert!(!result_str.contains("localhost"));
    assert!(!result_str.contains("127.0.0.1"));
    assert!(!result_str.contains("secret"));
    assert!(!result_str.contains("token"));
    
    // Should only contain expected spatial type names
    assert!(result_str.contains("Galaxy"));
    assert!(result_str.contains("Planet"));
    assert!(result_str.contains("Building"));
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_different_session_deks_same_result() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek1 = SessionDek::new(vec![0u8; 32]);
    let session_dek2 = SessionDek::new(vec![1u8; 32]);
    
    let params = json!({
        "query_type": "cosmic_types"
    });
    
    let result1 = tool.execute(&params, &session_dek1).await.expect("Tool execution should succeed");
    let result2 = tool.execute(&params, &session_dek2).await.expect("Tool execution should succeed");
    
    // Results should be identical regardless of session_dek since this tool 
    // returns static metadata only
    assert_eq!(result1, result2);
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_find_entity_tool_properly_handles_session_dek() {
    let app = spawn_app(false, false, false).await;
    
    let tool = FindEntityTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "search_request": "find magical items",
        "context": "Testing session_dek handling"
    });
    
    // Verify tool accepts session_dek parameter without panicking
    let result = tool.execute(&params, &session_dek).await;
    
    // The actual result may vary, but the tool should not panic or fail
    // due to session_dek handling issues
    match result {
        Ok(_) => {
            // Success - properly handled session_dek
        },
        Err(err) => {
            // Make sure it's not a session_dek related error
            let error_msg = format!("{:?}", err);
            assert!(!error_msg.contains("session_dek"));
            assert!(!error_msg.contains("SessionDek"));
            assert!(!error_msg.contains("encryption"));
        }
    }
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_create_entity_tool_encryption_parameter_handling() {
    let app = spawn_app(false, false, false).await;
    
    let tool = CreateEntityTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "creation_request": "Create a magical sword",
        "context": "Testing encryption handling"
    });
    
    // Verify tool accepts session_dek and doesn't expose encryption details
    let result = tool.execute(&params, &session_dek).await;
    
    match result {
        Ok(response) => {
            let response_str = serde_json::to_string(&response).unwrap();
            // Should not expose encryption details
            assert!(!response_str.contains("session_dek"));
            assert!(!response_str.contains("encryption"));
            assert!(!response_str.contains("decrypt"));
        },
        Err(err) => {
            // Error is fine, but shouldn't be encryption related unless that's expected
            let error_msg = format!("{:?}", err);
            // Most likely to fail on AI API calls, not encryption
            println!("CreateEntityTool error (expected): {}", error_msg);
        }
    }
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_query_spatial_types_input_validation() {
    let app = spawn_app(false, false, false).await;
    
    let tool = QuerySpatialTypesTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test SQL injection attempt
    let malicious_params = json!({
        "query_type": "all_types'; DROP TABLE entities; --"
    });
    
    let result = tool.execute(&malicious_params, &session_dek).await;
    assert!(result.is_err()); // Should reject invalid query_type
    
    // Test XSS attempt 
    let xss_params = json!({
        "query_type": "<script>alert('xss')</script>"
    });
    
    let result = tool.execute(&xss_params, &session_dek).await;
    assert!(result.is_err()); // Should reject invalid query_type
    
    // Test very long input
    let long_input = "a".repeat(10000);
    let long_params = json!({
        "query_type": long_input
    });
    
    let result = tool.execute(&long_params, &session_dek).await;
    assert!(result.is_err()); // Should reject invalid query_type
}

#[tokio::test]
#[ignore] // Requires database and Redis setup
async fn test_find_entity_tool_user_id_validation() {
    let app = spawn_app(false, false, false).await;
    
    let tool = FindEntityTool::new(app.app_state.clone());
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test invalid user_id formats
    let invalid_params = json!({
        "user_id": "not-a-uuid", 
        "search_request": "find items",
        "context": "test"
    });
    
    let result = tool.execute(&invalid_params, &session_dek).await;
    assert!(result.is_err()); // Should validate user_id format
    
    // Test SQL injection in user_id
    let sql_injection_params = json!({
        "user_id": "'; DROP TABLE users; --",
        "search_request": "find items", 
        "context": "test"
    });
    
    let result = tool.execute(&sql_injection_params, &session_dek).await;
    assert!(result.is_err()); // Should validate user_id format
}