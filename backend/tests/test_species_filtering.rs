use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::models::lorebook_dtos::{CreateLorebookPayload, CreateLorebookEntryPayload};
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, ValidatedPlan, RiskAssessment, RiskLevel,
    PlanStep, SubGoal, PlanValidationStatus
};
use uuid::Uuid;
use tracing::info;
use secrecy::SecretString;

#[tokio::test]
#[ignore = "Requires running services"]
async fn test_species_filtering_with_lorebook() {
    // Setup test environment with lorebook embeddings enabled
    let app = spawn_app_with_rate_limiting_options(false, false, false, true, 100, 50).await;
    
    // Create test user and session
    let pool = app.db_pool.clone();
    let test_user = scribe_backend::test_helpers::create_test_user(
        &pool,
        "test_user".to_string(),
        "test_password".to_string(),
    ).await.unwrap();
    let user_id = test_user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Get user DEK for lorebook operations
    let password = SecretString::from("test_password".to_string());
    let user_dek = test_user.get_data_encryption_key(&password).unwrap();
    
    // Create a lorebook with species and item entries
    let lorebook_id = {
        let lorebook_service = &app.app_state.lorebook_service;
        let lorebook = lorebook_service.create_lorebook_for_test(
            user_id,
            CreateLorebookPayload {
                name: "Test Species Lorebook".to_string(),
                description: Some("Test lorebook with species and items".to_string()),
            }
        ).await.unwrap();
        
        // Create lorebook entries for species
        let species_entries = vec![
            ("Ren", "The Ren are a species of sentient beings known for their telepathic abilities. This race of creatures inhabits the northern regions."),
            ("Shanyuan", "Shanyuan is a species of winged humanoids. These beings are a race of aerial dwellers with hollow bones."),
            ("Waterskin", "A waterskin is a portable water container made from animal hide. This item is commonly used by travelers."),
            ("Torn Map Fragment", "A torn map fragment is a piece of parchment showing partial geographic information. This item might reveal important locations."),
        ];
        
        for (title, content) in species_entries {
            lorebook_service.create_lorebook_entry_for_test(
                user_id,
                lorebook.id,
                CreateLorebookEntryPayload {
                    entry_title: title.to_string(),
                    keys_text: Some(title.to_string()),
                    content: content.to_string(),
                    comment: None,
                    is_enabled: Some(true),
                    is_constant: Some(false),
                    insertion_order: Some(100),
                    placement_hint: Some("after_prompt".to_string()),
                },
                &user_dek,
            ).await.unwrap();
        }
        
        lorebook.id
    };
    
    // Wait for embeddings to be indexed
    info!("Waiting for lorebook embeddings to be indexed...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    
    // Create perception agent
    let perception_agent = scribe_backend::services::agentic::factory::AgenticNarrativeFactory::create_perception_agent(&app.app_state);
    
    // Test AI response that mentions both species and items
    let ai_response = r#"
        The traveler encountered a group of Ren traders in the marketplace. They were selling various items including a waterskin and a torn map fragment. 
        A Shanyuan messenger flew overhead, delivering news to the town.
    "#;
    
    // Create enriched context
    let context = EnrichedContext {
        strategic_directive: None,
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                description: "Test step".to_string(),
                preconditions: vec![],
                expected_outcomes: vec![],
                required_entities: vec![],
                estimated_duration: None,
            }],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec![],
            estimated_execution_time: None,
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Test sub-goal".to_string(),
            actionable_directive: "Test directive".to_string(),
            required_entities: vec![],
            success_criteria: vec![],
            context_requirements: vec![],
            priority_level: 1.0,
        },
        relevant_entities: vec![],
        spatial_context: None,
        causal_context: None,
        temporal_context: None,
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![],
        assembled_context: None,
        perception_analysis: None,
        total_tokens_used: 0,
        execution_time_ms: 0,
        validation_time_ms: 0,
        ai_model_calls: 0,
        confidence_score: 1.0,
    };
    
    // Process the AI response through perception agent
    let session_id = Uuid::new_v4();
    
    let perception_result = perception_agent.process_ai_response(
        ai_response,
        &context,
        user_id,
        session_id,
        &session_dek,
    ).await.unwrap();
    
    // Check results
    info!("Extracted entities after species filtering:");
    for entity in &perception_result.extracted_entities {
        info!("  - {} (type: {})", entity.name, entity.entity_type);
    }
    
    // Verify that species were filtered out and items remained
    let entity_names: Vec<String> = perception_result.extracted_entities.iter().map(|e| e.name.clone()).collect();
    
    // Species should be filtered out
    assert!(!entity_names.contains(&"Ren".to_string()), "Ren (species) should be filtered out");
    assert!(!entity_names.contains(&"Shanyuan".to_string()), "Shanyuan (species) should be filtered out");
    
    // Items should remain - be flexible with case
    let has_waterskin = entity_names.iter().any(|name| name.to_lowercase() == "waterskin");
    let has_map_fragment = entity_names.iter().any(|name| name.to_lowercase().contains("torn map fragment"));
    
    assert!(has_waterskin, "Waterskin (item) should NOT be filtered out");
    assert!(has_map_fragment, "Torn Map Fragment (item) should NOT be filtered out");
    
    info!("Species filtering test completed successfully!");
}