use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use scribe_backend::models::chronicle_event::ChronicleEvent;
use scribe_backend::models::narrative_ontology::EventActor;
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};
use scribe_backend::errors::AppError;

// Helper function to create test ChronicleEvent objects
fn create_test_chronicle_event(
    chronicle_id: Uuid,
    user_id: Uuid,
    event_type: &str,
    event_data: serde_json::Value,
) -> ChronicleEvent {
    let now = Utc::now();
    ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id,
        event_type: event_type.to_string(),
        summary: "Test event".to_string(),
        source: "USER_ADDED".to_string(),
        event_data: Some(event_data),
        created_at: now,
        updated_at: now,
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: now,
        actors: None,
        action: None,
        context_data: None,
        causality: None,
        valence: None,
        modality: None,
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    }
}

#[tokio::test]
async fn test_entity_context_extraction_from_event_content() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with rich context in content field
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Character Development",
        json!({
            "content": "Elena Martinez, the renowned archaeologist, discovered ancient ruins beneath the city. She wore her signature leather jacket and carried her grandfather's compass. Her expertise in Mayan hieroglyphs proved invaluable.",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Elena Martinez"
            }],
            "attributes": {
                "profession": "archaeologist",
                "clothing": "leather jacket",
                "items": ["grandfather's compass"],
                "expertise": ["Mayan hieroglyphs"]
            }
        })
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Elena Martinez".to_string(),
            entity_id: Some(entity_id),
            include_current_state: true,
        },
        max_results: 10,
        include_current_state: true,
        include_relationships: true,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify entity context was extracted
    assert_eq!(result.entities.len(), 1);
    let entity_context = &result.entities[0];
    assert_eq!(entity_context.entity_id, entity_id);
    
    // TODO: Verify rich context extraction once implemented
    // assert!(entity_context.extracted_attributes.contains("profession"));
    // assert_eq!(entity_context.extracted_attributes["profession"], "archaeologist");
    
    Ok(())
}

#[tokio::test]
async fn test_entity_context_extraction_from_dialogue() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with dialogue revealing character traits
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Dialogue",
        json!({
            "content": "\"I've spent twenty years studying these symbols,\" Elena said, adjusting her reading glasses. \"My doctoral thesis at Oxford focused on pre-Columbian scripts.\"",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Elena Martinez"
            }],
            "dialogue_metadata": {
                "speaker": "Elena Martinez",
                "tone": "confident",
                "reveals": {
                    "experience": "twenty years",
                    "education": "doctoral thesis at Oxford",
                    "specialization": "pre-Columbian scripts"
                }
            }
        })
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Elena Martinez".to_string(),
            entity_id: None,
            include_current_state: true,
        },
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify dialogue context extraction
    assert_eq!(result.entities.len(), 1);
    
    // TODO: Verify dialogue-based context once implemented
    // assert!(entity_context.dialogue_reveals.contains_key("education"));
    
    Ok(())
}

#[tokio::test]
async fn test_entity_context_aggregation_across_events() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create multiple events building entity context
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Introduction",
        json!({
            "content": "Captain Sarah Chen commands the starship Endeavor.",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Sarah Chen"
            }],
            "attributes": {
                "rank": "Captain",
                "command": "starship Endeavor"
            }
        })
    );
    
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Character Development",
        json!({
            "content": "Chen's tactical brilliance comes from her years at the Academy and combat experience in the Outer Rim conflicts.",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Sarah Chen"
            }],
            "attributes": {
                "skills": ["tactical brilliance"],
                "background": ["Academy training", "Outer Rim combat"]
            }
        })
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Sarah Chen".to_string(),
            entity_id: Some(entity_id),
            include_current_state: true,
        },
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify aggregated context
    assert_eq!(result.entities.len(), 1);
    let entity_context = &result.entities[0];
    assert_eq!(entity_context.timeline_events.len(), 2);
    
    // TODO: Verify aggregated attributes once implemented
    // assert!(entity_context.aggregated_attributes.contains_key("rank"));
    // assert!(entity_context.aggregated_attributes.contains_key("skills"));
    
    Ok(())
}

#[tokio::test]
async fn test_entity_context_extraction_with_nested_json() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with deeply nested context
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Complex Scene",
        json!({
            "content": "The meeting in the war room was tense.",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "General Marcus"
            }],
            "scene_details": {
                "location": "war room",
                "participants": {
                    "general_marcus": {
                        "mood": "determined",
                        "equipment": {
                            "uniform": "dress blues",
                            "medals": ["Purple Heart", "Silver Star"],
                            "sidearm": "ceremonial pistol"
                        },
                        "recent_actions": {
                            "strategic_planning": {
                                "operation": "Northern Shield",
                                "status": "approved"
                            }
                        }
                    }
                }
            }
        })
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "General Marcus".to_string(),
            entity_id: Some(entity_id),
            include_current_state: true,
        },
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify nested context extraction
    assert_eq!(result.entities.len(), 1);
    
    // TODO: Verify nested JSON extraction once implemented
    // assert!(entity_context.extracted_equipment.contains("ceremonial pistol"));
    // assert!(entity_context.extracted_medals.contains(&"Purple Heart".to_string()));
    
    Ok(())
}

#[tokio::test]
async fn test_entity_context_extraction_handles_invalid_json() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with malformed nested data
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Scene",
        json!({
            "content": "Dr. Smith examined the artifact.",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Dr. Smith"
            }],
            "invalid_nested": "not_an_object",
            "partial_data": {
                "some_field": null
            }
        })
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Dr. Smith".to_string(),
            entity_id: None,
            include_current_state: true,
        },
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should handle gracefully without errors
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}