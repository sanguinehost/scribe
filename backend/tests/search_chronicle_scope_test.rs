// Test chronicle-scoped search functionality
use scribe_backend::services::agentic::narrative_tools::SearchKnowledgeBaseTool;
use scribe_backend::services::agentic::tools::ScribeTool;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_chronicle_scoped_search_compiles() {
    // This test verifies the chronicle-scoped search functionality compiles
    let app = spawn_app(false, false, false).await; // Use mock services
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    println!("Setting up test for chronicle-scoped search...");
    
    // Create dummy UUIDs for testing
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    println!("Test user: {}", user_id);
    println!("Test chronicle: {}", chronicle_id);
    println!("Test session: {}", session_id);
    
    // Create the app state
    let app_state = app.create_app_state().await;
    
    // Create the search tool
    let search_tool = SearchKnowledgeBaseTool::new(
        app.qdrant_service.clone(),
        app.mock_embedding_client.clone(),
        app_state,
    );
    
    // Test 1: Chronicle-scoped search (should compile and execute without crashing)
    let search_params = json!({
        "query": "dragon",
        "search_type": "lorebooks",
        "limit": 10,
        "user_id": user_id.to_string(),
        "chronicle_id": chronicle_id.to_string()
    });
    
    println!("\nTesting chronicle-scoped search with chronicle_id: {}", chronicle_id);
    
    let result = search_tool.execute(&search_params).await;
    
    match result {
        Ok(tool_result) => {
            println!("✅ Chronicle-scoped search executed successfully");
            
            // Verify the result structure
            assert!(tool_result.is_object(), "Result should be a JSON object");
            assert!(tool_result["results"].is_array(), "Should have a results array");
            
            let results = tool_result["results"].as_array().unwrap();
            println!("Found {} results (expected 0 with mocks)", results.len());
        }
        Err(e) => {
            println!("Search failed with error: {:?}", e);
            panic!("Chronicle-scoped search should not fail with valid parameters");
        }
    }
    
    // Test 2: Session-scoped search (should also work)
    let search_params_session = json!({
        "query": "dragon",
        "search_type": "lorebooks",
        "limit": 10,
        "user_id": user_id.to_string(),
        "session_id": session_id.to_string()
    });
    
    println!("\nTesting session-scoped search with session_id: {}", session_id);
    
    let result_session = search_tool.execute(&search_params_session).await;
    
    match result_session {
        Ok(tool_result) => {
            println!("✅ Session-scoped search executed successfully");
            
            // Verify the result structure
            assert!(tool_result.is_object(), "Result should be a JSON object");
            assert!(tool_result["results"].is_array(), "Should have a results array");
            
            let results = tool_result["results"].as_array().unwrap();
            println!("Found {} results (expected 0 with mocks)", results.len());
        }
        Err(e) => {
            println!("Search failed with error: {:?}", e);
            panic!("Session-scoped search should not fail with valid parameters");
        }
    }
    
    // Test 3: User-scoped search (no chronicle or session)
    let search_params_user = json!({
        "query": "dragon",
        "search_type": "lorebooks",
        "limit": 10,
        "user_id": user_id.to_string()
    });
    
    println!("\nTesting user-scoped search (no chronicle or session)");
    
    let result_user = search_tool.execute(&search_params_user).await;
    
    match result_user {
        Ok(tool_result) => {
            println!("✅ User-scoped search executed successfully");
            
            // Verify the result structure
            assert!(tool_result.is_object(), "Result should be a JSON object");
            assert!(tool_result["results"].is_array(), "Should have a results array");
            
            let results = tool_result["results"].as_array().unwrap();
            println!("Found {} results (expected 0 with mocks)", results.len());
        }
        Err(e) => {
            println!("Search failed with error: {:?}", e);
            panic!("User-scoped search should not fail with valid parameters");
        }
    }
    
    println!("\n✅ All chronicle-scoped search tests passed!");
    println!("The chronicle-scoped search functionality compiles and executes correctly.");
    println!("\nTo see debug logging, run with:");
    println!("RUST_LOG=info cargo test --test search_chronicle_scope_test -- --nocapture");
}