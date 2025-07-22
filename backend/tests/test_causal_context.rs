use scribe_backend::{
    services::{
        hierarchical_context_assembler::HierarchicalContextAssembler,
        intent_detection_service::IntentDetectionService,
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
        context_assembly_engine::{
            CausalContext, CausalChain, CausalEvent, PotentialConsequence, HistoricalPrecedent,
        },
    },
    models::{
        characters::CharacterMetadata,
    },
    test_helpers::{MockAiClient, spawn_app_with_options, db::create_test_user},
    crypto::{generate_dek, encrypt_gcm},
};
use std::sync::Arc;
use uuid::Uuid;
use genai::chat::{ChatMessage as GenAiChatMessage};
use chrono::Utc;

/// Helper to create a properly encrypted test character
async fn create_encrypted_test_character(user_dek: &Arc<secrecy::SecretBox<Vec<u8>>>) -> CharacterMetadata {
    let (description_ct, description_nonce) = encrypt_gcm(
        b"A brave knight with a mysterious past, haunted by the loss of his mentor",
        user_dek
    ).unwrap();
    
    let (personality_ct, personality_nonce) = encrypt_gcm(
        b"Noble, courageous, but prone to impulsive decisions when his honor is questioned",
        user_dek
    ).unwrap();
    
    let (scenario_ct, scenario_nonce) = encrypt_gcm(
        b"The kingdom is under threat from an ancient dragon that has awakened from centuries of slumber",
        user_dek
    ).unwrap();
    
    let (example_ct, example_nonce) = encrypt_gcm(
        b"Knight: 'I shall avenge my fallen mentor and protect the innocent, no matter the cost to myself.'",
        user_dek
    ).unwrap();
    
    CharacterMetadata {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "Sir Galahad".to_string(),
        description: Some(description_ct),
        description_nonce: Some(description_nonce),
        personality: Some(personality_ct),
        personality_nonce: Some(personality_nonce),
        scenario: Some(scenario_ct),
        scenario_nonce: Some(scenario_nonce),
        mes_example: Some(example_ct),
        mes_example_nonce: Some(example_nonce),
        creator_comment: None,
        creator_comment_nonce: None,
        first_mes: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a functional HierarchicalContextAssembler with comprehensive mock responses
async fn create_functional_assembler_for_causal_test(test_app: &scribe_backend::test_helpers::TestApp) -> HierarchicalContextAssembler {
    // Create comprehensive mock responses that replicate production behavior
    let mock_responses = vec![
        // Intent detection - captures causal reasoning depth
        r#"{
            "intent_type": "NarrativeGeneration",
            "focus_entities": [{"name": "dragon", "priority": 0.9, "required": true}],
            "time_scope": {"type": "Current"},
            "spatial_scope": {"location_name": "dragon_lair", "include_contained": true},
            "reasoning_depth": "Causal",
            "context_priorities": ["CausalChains", "Entities", "TemporalState"],
            "confidence": 0.92
        }"#.to_string(),
        
        // Strategic directive - high-level narrative direction
        r#"{
            "directive_type": "Combat Escalation",
            "narrative_arc": "Hero's Journey - Ordeal",
            "plot_significance": "Major",
            "emotional_tone": "Desperate Determination",
            "character_focus": ["Sir Galahad", "Ancient Dragon"],
            "world_impact_level": "Regional"
        }"#.to_string(),
        
        // Tactical plan - detailed combat sequence
        r#"{
            "steps": [
                {
                    "description": "Execute precision strike at dragon's vulnerable neck",
                    "preconditions": ["Character wielding sword", "Dragon within striking distance", "Character has clear line of attack"],
                    "expected_outcomes": ["Significant damage to dragon", "Dragon retaliation likely", "Combat intensity escalates"],
                    "required_entities": ["Sir Galahad", "Ancient Dragon", "Enchanted Sword"],
                    "estimated_duration": 3000
                },
                {
                    "description": "Anticipate and counter dragon's retaliatory fire breath",
                    "preconditions": ["Dragon is wounded", "Character positioned for evasive maneuver"],
                    "expected_outcomes": ["Character avoids major damage", "Opens opportunity for follow-up attack"],
                    "required_entities": ["Sir Galahad", "Ancient Dragon"],
                    "estimated_duration": 2000
                }
            ],
            "overall_risk": "Critical",
            "mitigation_strategies": [
                "Ensure character has protective enchantments active",
                "Position near structural cover for emergency retreat",
                "Monitor dragon's energy levels for fatigue opportunities"
            ]
        }"#.to_string(),
        
        // Character spatial location extraction
        r#"{
            "primary_location": "Dragon's Lair - Inner Sanctum",
            "confidence": 0.95,
            "environmental_factors": ["Ancient stone pillars", "Treasure hoard", "Volcanic heat", "Limited escape routes"]
        }"#.to_string(),
        
        // Character relationship extraction
        r#"[
            {
                "entity1": "Sir Galahad",
                "relationship_type": "sworn_enemy",
                "entity2": "Ancient Dragon",
                "strength": 0.9,
                "context": "Dragon killed his mentor years ago"
            },
            {
                "entity1": "Sir Galahad", 
                "relationship_type": "spiritual_connection",
                "entity2": "Fallen Mentor",
                "strength": 0.8,
                "context": "Mentor's spirit guides him in battle"
            }
        ]"#.to_string(),
        
        // Character recent actions
        r#"[
            {
                "action": "entered_dragon_lair",
                "timestamp": "2024-01-15T10:00:00Z",
                "context": "Stealthily infiltrated through ancient entrance",
                "significance": 0.8
            },
            {
                "action": "awakened_dragon",
                "timestamp": "2024-01-15T10:05:00Z", 
                "context": "Accidentally triggered magical alarm",
                "significance": 0.9
            },
            {
                "action": "drew_enchanted_sword",
                "timestamp": "2024-01-15T10:08:00Z",
                "context": "Prepared for inevitable confrontation",
                "significance": 0.7
            }
        ]"#.to_string(),
        
        // Character emotional state
        r#"{
            "primary_emotion": "Grim Determination",
            "intensity": 0.85,
            "contributing_factors": [
                "Memory of mentor's death",
                "Awareness of kingdom's peril",
                "Fear of personal failure",
                "Adrenaline from immediate danger"
            ],
            "stability": 0.6,
            "confidence": 0.8
        }"#.to_string(),
        
        // Entity resolution - extract entity names
        r#"["Sir Galahad", "Ancient Dragon", "Fallen Mentor", "Enchanted Sword", "Dragon's Lair"]"#.to_string(),
        
        // Entity resolution - comprehensive narrative context
        r#"{
            "entities": [
                {
                    "name": "Sir Galahad",
                    "entity_type": "Character",
                    "description": "A noble knight driven by vengeance and duty",
                    "properties": ["armed", "experienced_warrior", "magically_protected", "emotionally_driven"]
                },
                {
                    "name": "Ancient Dragon",
                    "entity_type": "Creature",
                    "description": "A massive, ancient beast of immense power and cunning",
                    "properties": ["fire_breathing", "armored_scales", "centuries_old", "intelligent", "territorial"]
                },
                {
                    "name": "Fallen Mentor",
                    "entity_type": "Spirit",
                    "description": "The ghost of Sir Galahad's former teacher",
                    "properties": ["deceased", "spiritual_guide", "wise", "protective"]
                },
                {
                    "name": "Enchanted Sword",
                    "entity_type": "Weapon",
                    "description": "A blessed blade capable of harming ancient creatures",
                    "properties": ["magical", "sharp", "blessed", "dragon_slaying"]
                }
            ],
            "spatial_context": {
                "primary_location": "Dragon's Lair",
                "secondary_locations": ["Inner Sanctum", "Treasure Chamber", "Ancient Passages"],
                "spatial_relationships": [
                    {
                        "entity1": "Sir Galahad",
                        "relationship": "confronts",
                        "entity2": "Ancient Dragon"
                    },
                    {
                        "entity1": "Ancient Dragon",
                        "relationship": "guards",
                        "entity2": "Treasure Chamber"
                    }
                ]
            },
            "temporal_context": {
                "time_indicators": ["now", "during final confrontation", "after years of preparation"],
                "sequence_markers": ["after entering the lair", "following the awakening", "before the strike"],
                "duration_hints": ["lengthy battle ahead", "climactic moment", "decisive action required"]
            },
            "social_context": {
                "relationships": [
                    {
                        "entity1": "Sir Galahad",
                        "relationship": "seeks_vengeance_against",
                        "entity2": "Ancient Dragon"
                    },
                    {
                        "entity1": "Fallen Mentor",
                        "relationship": "spiritually_guides",
                        "entity2": "Sir Galahad"
                    }
                ],
                "social_dynamics": ["mortal_combat", "ancient_grudge", "spiritual_guidance"],
                "emotional_tone": "desperate_resolve"
            },
            "actions_and_events": [
                {
                    "action": "prepares_to_strike",
                    "agent": "Sir Galahad",
                    "target": "Ancient Dragon",
                    "context": "final_confrontation"
                },
                {
                    "action": "awakens_from_slumber",
                    "agent": "Ancient Dragon",
                    "target": null,
                    "context": "disturbance_in_lair"
                }
            ]
        }"#.to_string(),
        
        // Entity semantic matching (multiple entities)
        r#"{"match_found": false, "similarity": 0.1, "reasoning": "No existing entity matches Sir Galahad"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.2, "reasoning": "No existing entity matches Ancient Dragon"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.0, "reasoning": "No existing entity matches Fallen Mentor"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.1, "reasoning": "No existing entity matches Enchanted Sword"}"#.to_string(),
        
        // AI component suggestions (multiple entities)
        r#"{
            "suggested_components": [
                {
                    "component_type": "Combat",
                    "initial_values": {"health": 85, "attack_power": 30, "defense": 25, "stamina": 70},
                    "reasoning": "Knight in active combat with high-stakes battle experience"
                },
                {
                    "component_type": "Emotion",
                    "initial_values": {"primary_emotion": "determined", "intensity": 0.85, "stability": 0.6},
                    "reasoning": "Character driven by vengeance and duty in climactic moment"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Combat", 
                    "initial_values": {"health": 95, "attack_power": 50, "defense": 40, "magical_resistance": 30},
                    "reasoning": "Ancient dragon with centuries of battle experience"
                },
                {
                    "component_type": "Territorial",
                    "initial_values": {"territory_size": 100, "intrusion_sensitivity": 0.9},
                    "reasoning": "Dragon defending its lair from intruder"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Spirit",
                    "initial_values": {"manifestation_strength": 0.3, "guidance_ability": 0.8},
                    "reasoning": "Deceased mentor providing spiritual guidance"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Weapon",
                    "initial_values": {"damage": 35, "magical_enhancement": 0.7, "dragon_effectiveness": 0.9},
                    "reasoning": "Enchanted blade specifically effective against ancient creatures"
                }
            ]
        }"#.to_string(),
        
        // Temporal event extraction - recent events
        r#"[
            {
                "description": "Sir Galahad infiltrated the dragon's lair through an ancient passage",
                "timestamp": "2024-01-15T10:00:00Z",
                "significance": 0.8,
                "participants": ["Sir Galahad"],
                "event_type": "infiltration"
            },
            {
                "description": "Ancient magical wards detected the intruder's presence",
                "timestamp": "2024-01-15T10:03:00Z",
                "significance": 0.7,
                "participants": ["Sir Galahad", "Ancient Dragon"],
                "event_type": "detection"
            },
            {
                "description": "The Ancient Dragon awakened from centuries of slumber",
                "timestamp": "2024-01-15T10:05:00Z",
                "significance": 0.9,
                "participants": ["Ancient Dragon"],
                "event_type": "awakening"
            },
            {
                "description": "Sir Galahad drew his enchanted sword in preparation",
                "timestamp": "2024-01-15T10:08:00Z",
                "significance": 0.7,
                "participants": ["Sir Galahad", "Enchanted Sword"],
                "event_type": "preparation"
            }
        ]"#.to_string(),
        
        // Temporal event extraction - future events
        r#"[
            {
                "description": "The dragon will retaliate with devastating fire breath",
                "time_until": "immediately",
                "participants": ["Ancient Dragon", "Sir Galahad"],
                "urgency": 0.95
            },
            {
                "description": "Sir Galahad must find cover or face severe burns",
                "time_until": "within seconds",
                "participants": ["Sir Galahad"],
                "urgency": 0.9
            },
            {
                "description": "The battle will determine the fate of the kingdom",
                "time_until": "within the hour",
                "participants": ["Sir Galahad", "Ancient Dragon"],
                "urgency": 0.8
            }
        ]"#.to_string(),
        
        // CAUSAL CONTEXT EXTRACTION - The main focus of this test
        r#"{
            "causal_chains": [
                {
                    "events": [
                        {
                            "description": "Sir Galahad's mentor was killed by the Ancient Dragon decades ago",
                            "timestamp": "1995-03-15T14:30:00Z"
                        },
                        {
                            "description": "Sir Galahad swore a blood oath to avenge his mentor's death",
                            "timestamp": "1995-03-20T09:00:00Z"
                        },
                        {
                            "description": "Years of training and preparation led to this moment",
                            "timestamp": "2024-01-10T12:00:00Z"
                        },
                        {
                            "description": "Sir Galahad infiltrated the dragon's lair seeking confrontation",
                            "timestamp": "2024-01-15T10:00:00Z"
                        },
                        {
                            "description": "The dragon awakened, sensing the intruder's hostile intent",
                            "timestamp": "2024-01-15T10:05:00Z"
                        }
                    ],
                    "confidence": 0.92
                },
                {
                    "events": [
                        {
                            "description": "The kingdom's desperate situation forced Sir Galahad to act",
                            "timestamp": "2024-01-01T00:00:00Z"
                        },
                        {
                            "description": "Reports of the dragon's awakening reached the capital",
                            "timestamp": "2024-01-14T16:00:00Z"
                        },
                        {
                            "description": "Sir Galahad volunteered for the suicidal mission",
                            "timestamp": "2024-01-14T18:00:00Z"
                        }
                    ],
                    "confidence": 0.85
                }
            ],
            "potential_consequences": [
                {
                    "description": "Sir Galahad could be killed by the dragon's retaliation",
                    "probability": 0.45,
                    "impact_severity": 0.95
                },
                {
                    "description": "The dragon could be mortally wounded, ending its threat",
                    "probability": 0.35,
                    "impact_severity": 0.90
                },
                {
                    "description": "The battle could cause the lair to collapse, trapping both combatants",
                    "probability": 0.25,
                    "impact_severity": 0.80
                },
                {
                    "description": "Sir Galahad's attack could enrage the dragon further",
                    "probability": 0.70,
                    "impact_severity": 0.60
                },
                {
                    "description": "The kingdom's fate depends on the outcome of this confrontation",
                    "probability": 0.85,
                    "impact_severity": 0.95
                }
            ],
            "historical_precedents": [
                {
                    "event_description": "Sir Galahad's mentor attempted to slay the same dragon",
                    "outcome": "Mentor was killed despite his skill and preparation",
                    "similarity_score": 0.85,
                    "timestamp": "1995-03-15T14:30:00Z"
                },
                {
                    "event_description": "Ancient legends speak of other dragon slayers who failed",
                    "outcome": "All previous attempts resulted in the heroes' deaths",
                    "similarity_score": 0.70,
                    "timestamp": "1200-01-01T00:00:00Z"
                },
                {
                    "event_description": "Sir Galahad previously defeated a lesser dragon",
                    "outcome": "Victory achieved through cunning and magical sword",
                    "similarity_score": 0.60,
                    "timestamp": "2020-06-20T12:00:00Z"
                }
            ],
            "causal_confidence": 0.88
        }"#.to_string(),
    ];
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(mock_responses));
    
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone(), "gemini-2.5-flash-lite-preview-06-17".to_string()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone(), "gemini-2.5-flash".to_string()));
    let entity_tool = Arc::new(EntityResolutionTool::new(test_app.app_state.clone()));
    let encryption_service = Arc::new(EncryptionService);
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    HierarchicalContextAssembler::new(
        mock_ai_client,
        intent_service,
        query_planner,
        entity_tool,
        encryption_service,
        db_pool,
        "gemini-2.5-flash".to_string(),
    )
}

#[tokio::test]
async fn test_comprehensive_causal_context_extraction() {
    // Setup test environment
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_functional_assembler_for_causal_test(&test_app).await;
    
    // Create test data with proper encryption
    let user = create_test_user(&test_app.db_pool, "galahad@kingdom.com".to_string(), "Sir Galahad".to_string()).await.unwrap();
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_encrypted_test_character(&user_dek).await;
    
    // Create realistic chat history that establishes causal narrative
    let chat_history = vec![
        GenAiChatMessage::user("Years ago, my mentor was slain by the Ancient Dragon while defending the kingdom. I swore an oath to avenge him."),
        GenAiChatMessage::assistant("The memory of that dark day still haunts Sir Galahad. His mentor's final words echo in his mind: 'The dragon must be stopped, whatever the cost.'"),
        GenAiChatMessage::user("Recent reports indicate the dragon has awakened. The kingdom is in peril. I must act now."),
        GenAiChatMessage::assistant("Sir Galahad steels himself for the confrontation he has prepared for his entire life. The enchanted sword feels heavy in his hands."),
        GenAiChatMessage::user("I have infiltrated the dragon's lair. The ancient beast stirs, sensing my presence."),
        GenAiChatMessage::assistant("The massive dragon's eyes snap open, glowing with fury. It recognizes the scent of its old enemy's student."),
        GenAiChatMessage::user("The time for subtlety has passed. I draw my blade and prepare to strike at the dragon's neck!"),
    ];
    
    // Execute the causal context extraction
    let user_input = "I swing my enchanted sword at the dragon's vulnerable neck with all my might!";
    let enriched_context = assembler.assemble_enriched_context(
        user_input,
        &chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    // Verify the operation succeeded
    match &enriched_context {
        Ok(context) => {
            println!("✅ Causal context extraction succeeded");
            println!("   - Causal context present: {}", context.causal_context.is_some());
            if let Some(ref causal_context) = context.causal_context {
                println!("   - Causal chains: {}", causal_context.causal_chains.len());
                println!("   - Potential consequences: {}", causal_context.potential_consequences.len());
                println!("   - Historical precedents: {}", causal_context.historical_precedents.len());
                println!("   - Causal confidence: {}", causal_context.causal_confidence);
            }
        }
        Err(e) => {
            println!("❌ Causal context extraction failed: {:?}", e);
            panic!("Causal context extraction should succeed: {}", e);
        }
    }
    let context = enriched_context.unwrap();
    
    // === COMPREHENSIVE CAUSAL CONTEXT VERIFICATION ===
    
    // Verify causal context was extracted
    assert!(context.causal_context.is_some(), "Causal context should be extracted for complex narrative");
    let causal_context = context.causal_context.unwrap();
    
    // Verify causal chains capture the long-term narrative arc
    assert_eq!(causal_context.causal_chains.len(), 2, "Should have extracted both personal and kingdom-related causal chains");
    
    // Verify primary causal chain (personal revenge narrative)
    let primary_chain = &causal_context.causal_chains[0];
    assert_eq!(primary_chain.events.len(), 5, "Primary causal chain should have 5 events");
    assert_eq!(primary_chain.confidence, 0.92, "Primary chain should have high confidence");
    
    // Verify chain events are chronologically ordered and meaningful
    assert!(primary_chain.events[0].description.contains("mentor was killed"), "First event should establish mentor's death");
    assert!(primary_chain.events[1].description.contains("swore a blood oath"), "Second event should show oath of vengeance");
    assert!(primary_chain.events[2].description.contains("training and preparation"), "Third event should show preparation period");
    assert!(primary_chain.events[3].description.contains("infiltrated"), "Fourth event should show infiltration");
    assert!(primary_chain.events[4].description.contains("awakened"), "Fifth event should show dragon awakening");
    
    // Verify secondary causal chain (kingdom's plight)
    let secondary_chain = &causal_context.causal_chains[1];
    assert_eq!(secondary_chain.events.len(), 3, "Secondary causal chain should have 3 events");
    assert_eq!(secondary_chain.confidence, 0.85, "Secondary chain should have good confidence");
    
    // Verify potential consequences are realistic and comprehensive
    assert_eq!(causal_context.potential_consequences.len(), 5, "Should have 5 potential consequences");
    
    // Test specific consequences
    let death_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("killed by the dragon"))
        .expect("Should have death consequence");
    assert_eq!(death_consequence.probability, 0.45, "Death probability should be realistic");
    assert_eq!(death_consequence.impact_severity, 0.95, "Death impact should be severe");
    
    let victory_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("mortally wounded"))
        .expect("Should have victory consequence");
    assert_eq!(victory_consequence.probability, 0.35, "Victory probability should be lower than death");
    assert_eq!(victory_consequence.impact_severity, 0.90, "Victory impact should be high");
    
    let collapse_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("lair to collapse"))
        .expect("Should have collapse consequence");
    assert_eq!(collapse_consequence.probability, 0.25, "Collapse should be less likely");
    assert_eq!(collapse_consequence.impact_severity, 0.80, "Collapse impact should be significant");
    
    // Verify historical precedents provide context
    assert_eq!(causal_context.historical_precedents.len(), 3, "Should have 3 historical precedents");
    
    let mentor_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("mentor attempted"))
        .expect("Should have mentor precedent");
    assert_eq!(mentor_precedent.similarity_score, 0.85, "Mentor precedent should be highly similar");
    assert!(mentor_precedent.outcome.contains("killed"), "Mentor precedent should show failure");
    
    let legend_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("Ancient legends"))
        .expect("Should have legend precedent");
    assert_eq!(legend_precedent.similarity_score, 0.70, "Legend precedent should be moderately similar");
    
    let success_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("defeated a lesser dragon"))
        .expect("Should have success precedent");
    assert_eq!(success_precedent.similarity_score, 0.60, "Success precedent should be somewhat similar");
    assert!(success_precedent.outcome.contains("Victory"), "Success precedent should show victory");
    
    // Verify overall causal confidence
    assert_eq!(causal_context.causal_confidence, 0.88, "Should have high causal confidence");
    
    // === INTEGRATION VERIFICATION ===
    
    // Verify causal context integrates with other context types
    assert!(context.temporal_context.is_some(), "Temporal context should also be present");
    assert!(context.spatial_context.is_some(), "Spatial context should also be present");
    assert!(!context.relevant_entities.is_empty(), "Should have relevant entities");
    
    // Verify the character entity has rich context
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    assert!(character_entity.emotional_state.is_some(), "Character should have emotional state");
    assert!(!character_entity.relationships.is_empty(), "Character should have relationships");
    
    // Verify strategic directive aligns with causal narrative
    assert!(context.strategic_directive.is_some(), "Strategic directive should be present");
    let directive = context.strategic_directive.unwrap();
    assert_eq!(directive.directive_type, "Combat Escalation", "Strategic directive should match causal escalation");
    assert_eq!(directive.narrative_arc, "Hero's Journey - Ordeal", "Should recognize climactic moment");
    
    // Verify tactical plan considers causal implications
    assert!(!context.validated_plan.steps.is_empty(), "Should have tactical steps");
    let first_step = &context.validated_plan.steps[0];
    assert!(first_step.description.contains("precision strike"), "First step should be precise attack");
    assert!(first_step.required_entities.contains(&"Enchanted Sword".to_string()), "Should require enchanted weapon");
    
    // === PERFORMANCE VERIFICATION ===
    
    // Verify reasonable performance metrics
    assert!(context.execution_time_ms < 5000, "Should execute within reasonable time");
    assert!(context.ai_model_calls >= 15, "Should make expected number of AI calls");
    assert!(context.total_tokens_used > 0, "Should track token usage");
    
    println!("✅ Comprehensive causal context extraction test passed!");
    println!("   - Extracted {} causal chains with {} total events", 
        causal_context.causal_chains.len(),
        causal_context.causal_chains.iter().map(|c| c.events.len()).sum::<usize>());
    println!("   - Identified {} potential consequences", causal_context.potential_consequences.len());
    println!("   - Found {} historical precedents", causal_context.historical_precedents.len());
    println!("   - Overall causal confidence: {:.2}", causal_context.causal_confidence);
    println!("   - Integration: {} entities, temporal: {}, spatial: {}", 
        context.relevant_entities.len(),
        context.temporal_context.is_some(),
        context.spatial_context.is_some());
}