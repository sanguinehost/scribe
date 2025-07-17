use scribe_backend::{
    services::{
        hybrid_query_service::{HybridQueryService, HybridQueryConfig},
        chronicle_service::ChronicleService,
    },
    models::{
        chronicle::CreateChronicleRequest,
        chronicle::PlayerChronicle,
        ecs::RelationshipsComponent,
    },
    test_helpers::{TestApp, db::create_test_user},
};
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde_json::json;
use anyhow::Result;

/// Test context containing all necessary services and data
pub struct HybridQueryTestContext {
    pub app: TestApp,
    pub service: Arc<HybridQueryService>,
    pub user_id: Uuid,
    pub chronicle: Option<PlayerChronicle>,
}

impl HybridQueryTestContext {
    /// Create a new test context with user and optional chronicle
    pub async fn new(with_chronicle: bool) -> Result<Self> {
        let app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        
        // Create test user
        let user = create_test_user(
            &app.db_pool,
            format!("hybrid_test_user_{}", Uuid::new_v4()),
            "password123".to_string()
        ).await?;
        
        // Create chronicle if requested
        let chronicle = if with_chronicle {
            let chronicle_service = ChronicleService::new(app.db_pool.clone());
            Some(chronicle_service.create_chronicle(
                user.id,
                CreateChronicleRequest {
                    name: "Test Chronicle".to_string(),
                    description: Some("Test chronicle for hybrid queries".to_string()),
                },
            ).await?)
        } else {
            None
        };
        
        // Create hybrid query service
        let service = Arc::new(HybridQueryService::new(
            Arc::new(app.app_state.pool.clone()),
            HybridQueryConfig::default(),
            app.app_state.feature_flags.clone(),
            app.app_state.ecs_entity_manager.clone(),
            app.app_state.ecs_enhanced_rag_service.clone(),
            app.app_state.ecs_graceful_degradation.clone(),
        ));
        
        Ok(Self {
            app,
            service,
            user_id: user.id,
            chronicle,
        })
    }
    
    /// Create a character entity with all necessary components
    pub async fn create_character(
        &self,
        name: &str,
        health: (i32, i32), // (current, max)
        with_relationships: bool,
    ) -> Result<scribe_backend::services::ecs_entity_manager::EntityQueryResult> {
        let mut components = vec![
            ("name".to_string(), json!({"value": name})),
            ("health".to_string(), json!({"current": health.0, "max": health.1})),
        ];
        
        // Add chronicle metadata if we have a chronicle
        if let Some(chronicle) = &self.chronicle {
            components.push((
                "chronicle_metadata".to_string(), 
                json!({
                    "chronicle_id": chronicle.id,
                    "chronicle_name": chronicle.name
                })
            ));
        }
        
        // Add empty relationships component if requested
        if with_relationships {
            let relationships_component = RelationshipsComponent {
                relationships: vec![],
            };
            components.push((
                "relationships".to_string(),
                serde_json::to_value(relationships_component)?
            ));
        }
        
        self.app.app_state.ecs_entity_manager.create_entity(
            self.user_id,
            None,
            "character".to_string(),
            components,
        ).await.map_err(|e| anyhow::anyhow!("Failed to create character: {}", e))
    }
    
    /// Create a location entity
    pub async fn create_location(
        &self,
        name: &str,
        location_type: &str,
        description: Option<&str>,
    ) -> Result<scribe_backend::services::ecs_entity_manager::EntityQueryResult> {
        let mut components = vec![
            ("name".to_string(), json!({"value": name})),
            ("location_type".to_string(), json!({"type": location_type})),
        ];
        
        if let Some(desc) = description {
            components.push(("description".to_string(), json!({"text": desc})));
        }
        
        // Add chronicle metadata if we have a chronicle
        if let Some(chronicle) = &self.chronicle {
            components.push((
                "chronicle_metadata".to_string(), 
                json!({
                    "chronicle_id": chronicle.id,
                    "chronicle_name": chronicle.name
                })
            ));
        }
        
        self.app.app_state.ecs_entity_manager.create_entity(
            self.user_id,
            None,
            "location".to_string(),
            components,
        ).await.map_err(|e| anyhow::anyhow!("Failed to create location: {}", e))
    }
    
    /// Create a relationship between two entities
    pub async fn create_relationship(
        &self,
        source_entity_id: Uuid,
        target_entity_id: Uuid,
        relationship_type: &str,
        trust: f32,
        affection: f32,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        // First ensure both entities have relationships components
        self.ensure_relationships_component(source_entity_id).await?;
        self.ensure_relationships_component(target_entity_id).await?;
        
        // Now update the relationship
        self.app.app_state.ecs_entity_manager.update_relationship(
            self.user_id,
            source_entity_id,
            target_entity_id,
            relationship_type.to_string(),
            trust,
            affection,
            metadata,
        ).await.map_err(|e| anyhow::anyhow!("Failed to create relationship: {}", e))?;
        
        Ok(())
    }
    
    /// Ensure an entity has a relationships component
    async fn ensure_relationships_component(&self, entity_id: Uuid) -> Result<()> {
        // Check if entity already has relationships component
        let entity = self.app.app_state.ecs_entity_manager
            .get_entity(self.user_id, entity_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get entity: {}", e))?
            .ok_or_else(|| anyhow::anyhow!("Entity not found"))?;
        
        let has_relationships = entity.components.iter()
            .any(|c| c.component_type == "relationships");
        
        if !has_relationships {
            // Can't add component after creation, so we'll just return an error
            // In real usage, entities should be created with relationships component from the start
            return Err(anyhow::anyhow!(
                "Entity {} doesn't have relationships component. Please create entities with relationships component from the start.",
                entity_id
            ));
        }
        
        Ok(())
    }
    
    /// Create a chronicle event
    pub async fn create_chronicle_event(
        &self,
        event_type: &str,
        summary: &str,
        actors: Vec<(Uuid, &str, &str)>, // (entity_id, role, context)
    ) -> Result<()> {
        use scribe_backend::models::chronicle_event::{NewChronicleEvent, EventSource};
        
        let chronicle = self.chronicle.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No chronicle available"))?;
        
        let actors_json = actors.into_iter()
            .map(|(id, role, context)| json!({
                "entity_id": id,
                "role": role,
                "context": context
            }))
            .collect::<Vec<_>>();
        
        let new_event = NewChronicleEvent {
            chronicle_id: chronicle.id,
            user_id: self.user_id,
            event_type: event_type.to_string(),
            summary: summary.to_string(),
            summary_encrypted: None,
            summary_nonce: None,
            source: EventSource::AiExtracted.to_string(),
            timestamp_iso8601: chrono::Utc::now(),
            event_data: Some(json!({"test": true})),
            actors: Some(json!(actors_json)),
            action: Some("TEST_ACTION".to_string()),
            context_data: None,
            causality: None,
            valence: None,
            modality: Some("ACTUAL".to_string()),
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 1,
        };
        
        let conn = self.app.db_pool.get().await
            .map_err(|e| anyhow::anyhow!("Failed to get connection: {}", e))?;
        
        conn.interact(move |conn| {
            use diesel::prelude::*;
            use scribe_backend::schema::chronicle_events;
            
            diesel::insert_into(chronicle_events::table)
                .values(&new_event)
                .execute(conn)
        }).await
            .map_err(|e| anyhow::anyhow!("Failed to insert event: {}", e))?
            .map_err(|e| anyhow::anyhow!("Failed to insert event: {}", e))?;
        
        Ok(())
    }
}

/// Create a complete test scenario with entities and relationships
pub async fn create_test_scenario() -> Result<(HybridQueryTestContext, TestScenarioData)> {
    let ctx = HybridQueryTestContext::new(true).await?;
    
    // Create characters
    let alice = ctx.create_character("Alice", (100, 100), true).await?;
    let bob = ctx.create_character("Bob", (90, 100), true).await?;
    let merchant = ctx.create_character("Merchant", (100, 100), true).await?;
    
    // Create locations
    let tavern = ctx.create_location(
        "The Rusty Anchor Tavern",
        "tavern",
        Some("A cozy tavern by the docks")
    ).await?;
    
    let market = ctx.create_location(
        "Central Market",
        "market",
        Some("Bustling marketplace in the city center")
    ).await?;
    
    // Skip relationships for now - would need to update entities with relationships component
    // ctx.create_relationship(
    //     alice.entity.id,
    //     bob.entity.id,
    //     "friendship",
    //     0.8,
    //     0.7,
    //     HashMap::from([
    //         ("duration".to_string(), json!("3 months")),
    //         ("origin".to_string(), json!("met at tavern")),
    //     ]),
    // ).await?;
    
    // ctx.create_relationship(
    //     alice.entity.id,
    //     merchant.entity.id,
    //     "customer",
    //     0.6,
    //     0.5,
    //     HashMap::from([
    //         ("frequency".to_string(), json!("weekly")),
    //         ("preferred_goods".to_string(), json!(["potions", "maps"])),
    //     ]),
    // ).await?;
    
    // Create some chronicle events
    ctx.create_chronicle_event(
        "SOCIAL_INTERACTION",
        "Alice and Bob meet at the tavern",
        vec![
            (alice.entity.id, "AGENT", "initiator"),
            (bob.entity.id, "PATIENT", "participant"),
        ],
    ).await?;
    
    ctx.create_chronicle_event(
        "TRADE",
        "Alice purchases supplies from the merchant",
        vec![
            (alice.entity.id, "AGENT", "buyer"),
            (merchant.entity.id, "PATIENT", "seller"),
        ],
    ).await?;
    
    Ok((ctx, TestScenarioData {
        alice,
        bob,
        merchant,
        tavern,
        market,
    }))
}

pub struct TestScenarioData {
    pub alice: scribe_backend::services::ecs_entity_manager::EntityQueryResult,
    pub bob: scribe_backend::services::ecs_entity_manager::EntityQueryResult,
    pub merchant: scribe_backend::services::ecs_entity_manager::EntityQueryResult,
    pub tavern: scribe_backend::services::ecs_entity_manager::EntityQueryResult,
    pub market: scribe_backend::services::ecs_entity_manager::EntityQueryResult,
}