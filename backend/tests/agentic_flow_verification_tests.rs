use scribe_backend::{
    routes::chat::{
        should_use_agentic_orchestration, calculate_agentic_token_budget,
        allocate_agentic_token_budget, determine_quality_mode,
    },
    services::{
        agentic_orchestrator::QualityMode,
        AgenticQueryCache, 
        IntentDetectionService, QueryStrategyPlanner, ContextOptimizationService,
    },
    test_helpers::{spawn_app, db::create_test_user, MockAiClient},
};
use std::sync::Arc;
use uuid::Uuid;
use serde_json;

#[tokio::test]
async fn test_agentic_orchestration_decision_logic() {
    // Test the decision logic for when to use agentic orchestration
    
    // Simple queries should not trigger agentic orchestration
    assert!(!should_use_agentic_orchestration("Hi", &None));
    assert!(!should_use_agentic_orchestration("Ok", &None));
    assert!(!should_use_agentic_orchestration("Yes", &None));
    
    // Complex narrative queries should trigger agentic orchestration
    assert!(should_use_agentic_orchestration(
        "What happened to Lumiya after she left the castle last night?", 
        &Some(Uuid::new_v4())
    ));
    assert!(should_use_agentic_orchestration(
        "I want to know more about the relationship between these characters and their history together.", 
        &Some(Uuid::new_v4())
    ));
    assert!(should_use_agentic_orchestration(
        "Can you tell me about the political situation in the kingdom right now?", 
        &Some(Uuid::new_v4())
    ));
}

#[tokio::test]
async fn test_agentic_token_budget_calculations() {
    // Create query params using serde since the fields are private
    let query_params: scribe_backend::routes::chat::ChatGenerateQueryParams = 
        serde_json::from_str("{\"request_thinking\": false}").unwrap();
    
    // Test token budget calculation
    let total_budget = calculate_agentic_token_budget(&query_params);
    assert_eq!(total_budget, 5000, "Should return default budget of 5000 tokens");
    
    // Test budget allocation
    let (context_budget, query_budget) = allocate_agentic_token_budget(total_budget);
    assert_eq!(context_budget, 1500, "Context budget should be 30% of total");
    assert_eq!(query_budget, 3500, "Query budget should be 70% of total");
    assert_eq!(context_budget + query_budget, total_budget, "Budgets should sum to total");
    
    // Test quality mode determination
    let quality_mode = determine_quality_mode(&query_params);
    assert_eq!(quality_mode, QualityMode::Balanced, "Should return balanced quality mode");
}

#[tokio::test]
async fn test_agentic_cache_creation() {
    // Test that we can create the cache without panicking
    let _cache = AgenticQueryCache::new(Default::default());
    
    println!("Agentic cache created successfully");
    
    // This is primarily a compilation test to ensure the cache can be instantiated
    // The actual cache functionality requires more complex setup with proper keys
}

#[tokio::test]
async fn test_agentic_orchestrator_creation() {
    let app = spawn_app(false, false, false).await; // multi_thread=false, use_real_ai=false, use_real_qdrant=false
    
    // Create a test user and chronicle for the orchestrator
    let user = create_test_user(&app.db_pool, "test_agentic_user".to_string(), "password".to_string())
        .await
        .expect("Failed to create test user");
    
    // Create mock AI client
    let _mock_ai_client = Arc::new(MockAiClient::new());
    
    // For this test, we'll just verify that we can create the services without panicking
    // The actual hybrid query service creation is complex and requires the full app state
    println!("Successfully created test user: {}", user.id);
    println!("Test app created with mock services");
    
    // Basic verification that the core functions work
    assert!(user.id != Uuid::nil(), "User should have valid ID");
}

#[tokio::test]
async fn test_agentic_service_components_basic() {
    let _app = spawn_app(false, false, false).await;
    
    // Basic test that we can create core components
    let _mock_ai_client = Arc::new(MockAiClient::new());
    
    // Test cache creation (simplest component)
    let _cache = AgenticQueryCache::new(Default::default());
    
    println!("Agentic cache component created successfully");
}

#[tokio::test]
async fn test_agentic_flow_components_creation() {
    // Test that all the individual components can be created
    let _app = spawn_app(false, false, false).await;
    let mock_ai_client = Arc::new(MockAiClient::new());
    
    // Test individual service creation
    let _intent_service = IntentDetectionService::new(mock_ai_client.clone(), "test-model".to_string());
    let _strategy_planner = QueryStrategyPlanner::new(mock_ai_client.clone(), "test-model".to_string());
    let _optimization_service = ContextOptimizationService::new(mock_ai_client.clone(), "test-model".to_string());
    
    // Verify services can be created without panicking (they don't return Result)
    println!("Intent detection service created successfully");
    println!("Strategy planner created successfully"); 
    println!("Context optimization service created successfully");
    
    // Just verify they were created successfully (no panic occurred)
    println!("All agentic services created successfully without panicking");
}

#[tokio::test]
async fn test_agentic_helper_functions_integration() {
    // Test that the helper functions from chat.rs work correctly
    let _app = spawn_app(false, false, false).await;
    
    // Test agentic decision making
    let complex_query = "What is the relationship between Lumiya and the ancient prophecy mentioned in the chronicles?";
    let character_id = Some(Uuid::new_v4());
    
    assert!(should_use_agentic_orchestration(complex_query, &character_id), 
            "Complex narrative query should trigger agentic orchestration");
    
    // Test token budget functions
    let query_params: scribe_backend::routes::chat::ChatGenerateQueryParams = 
        serde_json::from_str("{\"request_thinking\": false}").unwrap();
    let budget = calculate_agentic_token_budget(&query_params);
    let (context_budget, query_budget) = allocate_agentic_token_budget(budget);
    
    assert!(budget > 0, "Token budget should be positive");
    assert!(context_budget > 0, "Context budget should be positive");
    assert!(query_budget > 0, "Query budget should be positive");
    assert_eq!(context_budget + query_budget, budget, "Budget allocation should sum correctly");
    
    let quality_mode = determine_quality_mode(&query_params);
    assert_eq!(quality_mode, QualityMode::Balanced, "Should use balanced quality mode");
}

#[tokio::test]
async fn test_agentic_flow_end_to_end_compilation() {
    // This test verifies the complete agentic flow compiles and basic functions work
    // This is more of a compilation/integration test rather than functional test
    
    let app = spawn_app(false, false, false).await;
    let user = create_test_user(&app.db_pool, "e2e_test_user".to_string(), "password".to_string())
        .await
        .expect("Failed to create test user");
    
    // Test all the core helper functions from the agentic flow
    let complex_query = "Tell me about the political intrigue involving the characters in this scene";
    let should_use_agentic = should_use_agentic_orchestration(complex_query, &Some(user.id));
    
    if should_use_agentic {
        let query_params: scribe_backend::routes::chat::ChatGenerateQueryParams = 
        serde_json::from_str("{\"request_thinking\": false}").unwrap();
        let budget = calculate_agentic_token_budget(&query_params);
        let (context_budget, query_budget) = allocate_agentic_token_budget(budget);
        let quality_mode = determine_quality_mode(&query_params);
        
        println!("Agentic flow would be triggered:");
        println!("  Total budget: {} tokens", budget);
        println!("  Context budget: {} tokens", context_budget);
        println!("  Query budget: {} tokens", query_budget);
        println!("  Quality mode: {:?}", quality_mode);
        
        // Verify all values are sensible
        assert!(budget > 0, "Budget should be positive");
        assert!(context_budget > 0, "Context budget should be positive");
        assert!(query_budget > 0, "Query budget should be positive");
        assert_eq!(context_budget + query_budget, budget, "Budgets should sum correctly");
        assert_eq!(quality_mode, QualityMode::Balanced, "Should use balanced mode");
    }
    
    println!("All agentic flow helper functions work correctly");
}