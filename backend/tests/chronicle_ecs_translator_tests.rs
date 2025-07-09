// backend/tests/chronicle_ecs_translator_tests.rs

use chrono::Utc;
use scribe_backend::{
    models::{
        chronicle_event::ChronicleEvent,
        ecs::{HealthComponent, NameComponent, PositionComponent},
        ecs_diesel::{EcsComponent, EcsEntityRelationship},
    },
    services::{
        agentic::entity_resolution_tool::{
            NarrativeAction, NarrativeContext, NarrativeEntity, SocialContext, SocialRelationship,
            SpatialContext, SpatialRelationship, TemporalContext,
        },
        chronicle_ecs_translator::ChronicleEcsTranslator,
    },
    test_helpers::{db::create_test_user, spawn_app, TestDataGuard},
    PgPool,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_full_narrative_to_ecs_translation() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let test_user = create_test_user(&app.db_pool, "testuser".to_string(), "password123".to_string())
        .await
        .expect("Failed to create test user");
    tdg.add_user(test_user.id);
    let user_id = test_user.id;

    // 1. Setup: Create a mock NarrativeContext with an action
    let narrative_context = NarrativeContext {
        entities: vec![
            NarrativeEntity {
                name: "Sol".to_string(),
                description: "A stoic warrior".to_string(),
                entity_type: "CHARACTER".to_string(),
                properties: vec!["healthy".to_string(), "brave".to_string()],
            },
            NarrativeEntity {
                name: "Borga".to_string(),
                description: "A cunning rogue".to_string(),
                entity_type: "CHARACTER".to_string(),
                properties: vec!["injured".to_string(), "deceptive".to_string()],
            },
        ],
        spatial_context: SpatialContext {
            primary_location: Some("The Shadowy Alley".to_string()),
            secondary_locations: vec!["near the tavern".to_string()],
            spatial_relationships: vec![SpatialRelationship {
                entity1: "Sol".to_string(),
                entity2: "Borga".to_string(),
                relationship: "standing near".to_string(),
            }],
        },
        social_context: SocialContext {
            relationships: vec![SocialRelationship {
                entity1: "Sol".to_string(),
                entity2: "Borga".to_string(),
                relationship: "allies".to_string(),
            }],
            social_dynamics: vec![],
            emotional_tone: "tense".to_string(),
        },
        temporal_context: TemporalContext {
            time_indicators: vec![],
            sequence_markers: vec![],
            duration_hints: vec![],
        },
        actions_and_events: vec![NarrativeAction {
            action: "attacked".to_string(),
            agent: Some("Sol".to_string()),
            target: Some("Borga".to_string()),
            context: Some("with a rusty sword".to_string()),
        }],
    };

    // 2. Create a ChronicleEvent with this context
    let sol_id = Uuid::new_v4();
    let borga_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let summary = "Sol and Borga met in a shadowy alley.".to_string();

    let event = ChronicleEvent {
        id: event_id,
        user_id,
        chronicle_id: Uuid::new_v4(),
        event_type: "narrative".to_string(),
        summary: summary.clone(),
        source: "AI_EXTRACTED".to_string(),
        event_data: Some(json!({
            "actors": [
                {"entity_id": sol_id.to_string(), "entity_name": "Sol", "entity_type": "CHARACTER", "role": "Agent"},
                {"entity_id": borga_id.to_string(), "entity_name": "Borga", "entity_type": "CHARACTER", "role": "Patient"}
            ],
            "action": "Met",
            "summary": summary,
        })),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": sol_id.to_string(), "entity_name": "Sol", "role": "Agent"},
            {"entity_id": borga_id.to_string(), "entity_name": "Borga", "role": "Patient"}
        ])),
        action: Some("Met".to_string()),
        context_data: Some(serde_json::to_value(&narrative_context).unwrap()),
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };

    // 3. Run the translator
    let translator = ChronicleEcsTranslator::new(app.db_pool.clone().into());
    let result = translator.translate_event(&event, user_id).await.unwrap();

    // 4. Assertions
    assert_eq!(result.entities_created.len(), 2);
    assert!(result.entities_created.contains(&sol_id));
    assert!(result.entities_created.contains(&borga_id));

    // Verify Sol's components
    let sol_components = get_entity_components(&app.db_pool, sol_id).await;

    let sol_name: NameComponent = get_component_data(&sol_components, "Name").unwrap();
    assert_eq!(sol_name.name, "Sol");

    let sol_health: HealthComponent = get_component_data(&sol_components, "Health").unwrap();
    assert_eq!(sol_health.current, 100);

    let sol_pos: PositionComponent = get_component_data(&sol_components, "Position").unwrap();
    assert_eq!(sol_pos.zone, "The Shadowy Alley");

    // Verify Personality and Skills for Sol
    let sol_personality: serde_json::Value = get_component_data(&sol_components, "Personality").unwrap();
    let sol_traits = sol_personality["traits"].as_array().unwrap();
    assert!(sol_traits.iter().any(|v| v.as_str().unwrap() == "brave"));
    assert!(sol_traits.iter().any(|v| v.as_str().unwrap() == "tense"));

    let sol_skills: serde_json::Value = get_component_data(&sol_components, "Skills").unwrap();
    let sol_skill_list = sol_skills["skills"].as_array().unwrap();
    assert!(sol_skill_list.iter().any(|v| v.as_str().unwrap() == "combat"));

    // Verify Borga's components
    let borga_components = get_entity_components(&app.db_pool, borga_id).await;

    let borga_name: NameComponent = get_component_data(&borga_components, "Name").unwrap();
    assert_eq!(borga_name.name, "Borga");

    let borga_health: HealthComponent = get_component_data(&borga_components, "Health").unwrap();
    assert_eq!(borga_health.current, 50);

    let borga_pos: PositionComponent = get_component_data(&borga_components, "Position").unwrap();
    assert_eq!(borga_pos.zone, "The Shadowy Alley");

    // Verify relationships
    let sol_relationships = get_entity_relationships(&app.db_pool, sol_id).await;
    assert_eq!(sol_relationships.len(), 1);
    assert_eq!(sol_relationships[0].to_entity_id, borga_id);
    assert_eq!(sol_relationships[0].relationship_type, "allies");

    let borga_relationships = get_entity_relationships(&app.db_pool, borga_id).await;
    assert_eq!(borga_relationships.len(), 1);
    assert_eq!(borga_relationships[0].to_entity_id, sol_id);
    assert_eq!(borga_relationships[0].relationship_type, "allies");
}

// Helper functions to query DB for verification
async fn get_entity_components(pool: &PgPool, entity_id_val: Uuid) -> Vec<EcsComponent> {
    use diesel::prelude::*;
    use scribe_backend::schema::ecs_components::dsl::*;
    let conn = pool.get().await.unwrap();
    conn.interact(move |conn| {
        ecs_components
            .filter(entity_id.eq(entity_id_val))
            .load::<EcsComponent>(conn)
    })
    .await
    .unwrap()
    .unwrap()
}

async fn get_entity_relationships(
    pool: &PgPool,
    entity_id_val: Uuid,
) -> Vec<EcsEntityRelationship> {
    use diesel::prelude::*;
    use scribe_backend::schema::ecs_entity_relationships::dsl::*;
    let conn = pool.get().await.unwrap();
    conn.interact(move |conn| {
        ecs_entity_relationships
            .filter(from_entity_id.eq(entity_id_val))
            .load::<EcsEntityRelationship>(conn)
    })
    .await
    .unwrap()
    .unwrap()
}

fn get_component_data<'a, T: serde::de::DeserializeOwned>(
    components: &'a [EcsComponent],
    component_type: &str,
) -> Option<T> {
    components
        .iter()
        .find(|c| c.component_type == component_type)
        .and_then(|c| serde_json::from_value(c.component_data.clone()).ok())
}