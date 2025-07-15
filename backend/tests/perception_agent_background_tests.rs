use scribe_backend::services::agentic::perception_agent::{PerceptionAgent, PerceptionResult};
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, SpatialContext, TemporalContext, SpatialLocation,
    RiskAssessment, RiskLevel
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::Utc;
use tokio::time::{sleep, Duration, timeout};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, debug};

// Shared state for testing background operations
struct TestState {
    processed_count: Arc<Mutex<usize>>,
    results: Arc<Mutex<Vec<PerceptionResult>>>,
    errors: Arc<Mutex<Vec<String>>>,
}

impl TestState {
    fn new() -> Self {
        Self {
            processed_count: Arc::new(Mutex::new(0)),
            results: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[tokio::test]
async fn test_perception_agent_background_spawn() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    // Create channel for completion notification
    let (tx, mut rx) = mpsc::channel::<PerceptionResult>(1);
    
    // Spawn background task
    let agent_clone = perception_agent.clone();
    let response = "Sol entered the cantina.";
    let context = create_test_context();
    
    tokio::spawn(async move {
        let result = agent_clone.process_ai_response(
            response,
            &context,
            user_id,
            &user_dek,
        ).await;
        
        if let Ok(perception_result) = result {
            let _ = tx.send(perception_result).await;
        }
    });
    
    // Wait for background processing with timeout
    let result = timeout(Duration::from_secs(5), rx.recv()).await;
    
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_perception_agent_concurrent_background_tasks() {
    let app = spawn_app(false, false, false).await;
    let test_state = TestState::new();
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    // Spawn multiple background tasks
    let num_tasks = 5;
    let mut handles = vec![];
    
    for i in 0..num_tasks {
        let agent_clone = perception_agent.clone();
        let state_clone = test_state.processed_count.clone();
        let results_clone = test_state.results.clone();
        let user_id = Uuid::new_v4();
        let user_dek = SessionDek::new(vec![i as u8; 32]);
        
        let handle = tokio::spawn(async move {
            let response = format!("User {} performed action {}", i, i);
            let context = create_test_context();
            
            let result = agent_clone.process_ai_response(
                &response,
                &context,
                user_id,
                &user_dek,
            ).await;
            
            if let Ok(perception_result) = result {
                let mut count = state_clone.lock().unwrap();
                *count += 1;
                
                let mut results = results_clone.lock().unwrap();
                results.push(perception_result);
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    // Verify all tasks completed
    let final_count = *test_state.processed_count.lock().unwrap();
    assert_eq!(final_count, num_tasks);
    
    let results = test_state.results.lock().unwrap();
    assert_eq!(results.len(), num_tasks);
}

#[tokio::test]
async fn test_perception_agent_background_cancellation() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    // Create a long-running response
    let response = "Sol performed a very complex series of actions...".repeat(100);
    let context = create_test_context();
    
    let agent_clone = perception_agent.clone();
    let handle = tokio::spawn(async move {
        agent_clone.process_ai_response(
            &response,
            &context,
            user_id,
            &user_dek,
        ).await
    });
    
    // Cancel after short delay
    sleep(Duration::from_millis(10)).await;
    handle.abort();
    
    // Verify cancellation
    assert!(handle.is_finished());
}

#[tokio::test]
async fn test_perception_agent_background_error_isolation() {
    let app = spawn_app(false, false, false).await;
    let test_state = TestState::new();
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    let mut handles = vec![];
    
    // Task 1: Valid processing
    let agent_clone = perception_agent.clone();
    let results_clone = test_state.results.clone();
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let handle1 = tokio::spawn(async move {
        let response = "Valid response";
        let context = create_test_context();
        
        let result = agent_clone.process_ai_response(
            response,
            &context,
            user_id,
            &user_dek,
        ).await;
        
        if let Ok(perception_result) = result {
            let mut results = results_clone.lock().unwrap();
            results.push(perception_result);
        }
    });
    handles.push(handle1);
    
    // Task 2: Invalid processing (should not affect Task 1)
    let agent_clone = perception_agent.clone();
    let errors_clone = test_state.errors.clone();
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![1u8; 32]);
    
    let handle2 = tokio::spawn(async move {
        let response = "{ invalid json that will cause errors";
        let context = create_test_context();
        
        let result = agent_clone.process_ai_response(
            response,
            &context,
            user_id,
            &user_dek,
        ).await;
        
        if result.is_err() {
            let mut errors = errors_clone.lock().unwrap();
            errors.push("Error processing".to_string());
        }
    });
    handles.push(handle2);
    
    // Wait for both tasks
    for handle in handles {
        let _ = handle.await;
    }
    
    // Verify isolation - valid task should succeed despite error in other task
    let results = test_state.results.lock().unwrap();
    assert!(!results.is_empty());
    
    let errors = test_state.errors.lock().unwrap();
    assert!(!errors.is_empty() || results.len() == 2); // Either error or both succeeded
}

#[tokio::test]
async fn test_perception_agent_background_with_timeout() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    let response = "Quick response";
    let context = create_test_context();
    
    let agent_clone = perception_agent.clone();
    
    // Process with timeout
    let result = timeout(Duration::from_secs(2), async move {
        agent_clone.process_ai_response(
            response,
            &context,
            user_id,
            &user_dek,
        ).await
    }).await;
    
    // Should complete within timeout
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn test_perception_agent_background_queue_simulation() {
    let app = spawn_app(false, false, false).await;
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    // Create a queue for perception tasks
    let (tx, mut rx) = mpsc::channel::<(String, EnrichedContext, Uuid, SessionDek)>(10);
    
    // Producer: Queue multiple tasks
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        for i in 0..5 {
            let response = format!("Response {}", i);
            let context = create_test_context();
            let user_id = Uuid::new_v4();
            let user_dek = SessionDek::new(vec![i as u8; 32]);
            
            tx_clone.send((response, context, user_id, user_dek)).await.unwrap();
            sleep(Duration::from_millis(10)).await;
        }
    });
    
    // Consumer: Process from queue
    let agent_clone = perception_agent.clone();
    let consumer_handle = tokio::spawn(async move {
        let mut processed = 0;
        
        while let Some((response, context, user_id, user_dek)) = rx.recv().await {
            let result = agent_clone.process_ai_response(
                &response,
                &context,
                user_id,
                &user_dek,
            ).await;
            
            if result.is_ok() {
                processed += 1;
            }
            
            if processed >= 5 {
                break;
            }
        }
        
        processed
    });
    
    // Wait for consumer to process all
    let processed_count = consumer_handle.await.unwrap();
    assert_eq!(processed_count, 5);
}

#[tokio::test]
async fn test_perception_agent_background_with_callbacks() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let perception_agent = Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));
    
    // Create oneshot channel for callback
    let (tx, rx) = oneshot::channel::<PerceptionResult>();
    
    let response = "Sol found a hidden treasure.";
    let context = create_test_context();
    
    let agent_clone = perception_agent.clone();
    
    // Spawn with callback
    tokio::spawn(async move {
        let result = agent_clone.process_ai_response(
            response,
            &context,
            user_id,
            &user_dek,
        ).await;
        
        if let Ok(perception_result) = result {
            let _ = tx.send(perception_result);
        }
    });
    
    // Wait for callback
    let result = timeout(Duration::from_secs(5), rx).await;
    
    assert!(result.is_ok());
    let perception_result = result.unwrap().unwrap();
    assert!(!perception_result.extracted_entities.is_empty());
}

#[tokio::test]
async fn test_perception_agent_background_resource_cleanup() {
    let app = spawn_app(false, false, false).await;
    
    // Track resource usage
    let initial_handle_count = tokio::runtime::Handle::current().metrics().num_alive_tasks();
    
    {
        let planning_service = Arc::new(PlanningService::new(
            app.app_state.ai_client.clone(),
            app.app_state.ecs_entity_manager.clone(),
            app.app_state.redis_client.clone(),
            Arc::new(app.app_state.pool.clone()),
        ));
        
        let plan_validator = Arc::new(PlanValidatorService::new(
            app.app_state.ecs_entity_manager.clone(),
            app.app_state.redis_client.clone(),
        ));
        
        let perception_agent = Arc::new(PerceptionAgent::new(
            app.app_state.ai_client.clone(),
            app.app_state.ecs_entity_manager.clone(),
            planning_service,
            plan_validator,
            app.app_state.redis_client.clone(),
        ));
        
        // Spawn and complete multiple tasks
        let mut handles = vec![];
        
        for i in 0..3 {
            let agent_clone = perception_agent.clone();
            let user_id = Uuid::new_v4();
            let user_dek = SessionDek::new(vec![i as u8; 32]);
            
            let handle = tokio::spawn(async move {
                let response = format!("Task {}", i);
                let context = create_test_context();
                
                agent_clone.process_ai_response(
                    &response,
                    &context,
                    user_id,
                    &user_dek,
                ).await
            });
            
            handles.push(handle);
        }
        
        // Wait for all to complete
        for handle in handles {
            let _ = handle.await;
        }
    }
    
    // Give time for cleanup
    sleep(Duration::from_millis(100)).await;
    
    // Check that resources are cleaned up
    let final_handle_count = tokio::runtime::Handle::current().metrics().num_alive_tasks();
    
    // Should return to approximately initial state (allowing some variance)
    assert!(final_handle_count <= initial_handle_count + 2);
}

// Helper function
fn create_test_context() -> EnrichedContext {
    EnrichedContext {
        strategic_directives: vec![],
        validated_plans: vec![],
        sub_goals: vec![],
        entity_context: HashMap::new(),
        spatial_context: SpatialContext {
            primary_location: SpatialLocation {
                entity_id: Uuid::new_v4(),
                name: "Test Location".to_string(),
                scale: "room".to_string(),
                coordinates: None,
                parent_id: None,
            },
            nearby_locations: vec![],
            scale_context: "intimate".to_string(),
        },
        temporal_context: TemporalContext {
            current_time: Utc::now(),
            time_period: "day".to_string(),
            recent_events: vec![],
            time_constraints: vec![],
        },
        risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            identified_risks: vec![],
            mitigation_strategies: vec![],
        },
        performance_metrics: HashMap::new(),
        context_cache: None,
    }
}