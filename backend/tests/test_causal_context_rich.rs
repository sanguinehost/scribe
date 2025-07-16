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
    models::characters::CharacterMetadata,
    test_helpers::{MockAiClient, spawn_app_with_options, db::create_test_user},
    crypto::{generate_dek, encrypt_gcm},
};
use std::sync::Arc;
use uuid::Uuid;
use genai::chat::ChatMessage as GenAiChatMessage;
use chrono::Utc;

/// Helper to create a test character with rich background
async fn create_rich_test_character(user_dek: &Arc<secrecy::SecretBox<Vec<u8>>>) -> CharacterMetadata {
    let (description_ct, description_nonce) = encrypt_gcm(
        b"Sir Galahad the Bold, last surviving knight of the Round Table, haunted by his failure to save his mentor Sir Lancelot from the ancient dragon Vermithrax. Driven by guilt and a sacred oath of vengeance.",
        user_dek
    ).unwrap();
    
    let (personality_ct, personality_nonce) = encrypt_gcm(
        b"Tormented by past failures, desperately seeking redemption. Prone to reckless decisions when his honor is questioned. Highly skilled in combat but emotionally unstable.",
        user_dek
    ).unwrap();
    
    let (scenario_ct, scenario_nonce) = encrypt_gcm(
        b"The ancient dragon Vermithrax has awakened after decades of slumber, threatening the kingdom. Sir Galahad must face the same beast that killed his mentor, knowing he may suffer the same fate.",
        user_dek
    ).unwrap();
    
    let (example_ct, example_nonce) = encrypt_gcm(
        b"Sir Galahad: 'I will not fail again! Lancelot's death will be avenged, even if it costs me my life!'",
        user_dek
    ).unwrap();
    
    CharacterMetadata {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "Sir Galahad the Bold".to_string(),
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

/// Create an assembler with rich causal context mock responses
async fn create_rich_causal_assembler(test_app: &scribe_backend::test_helpers::TestApp) -> HierarchicalContextAssembler {
    let rich_mock_responses = vec![
        // Intent detection - indicates causal reasoning is needed
        r#"{
            "intent_type": "NarrativeGeneration",
            "focus_entities": [
                {"name": "Sir Galahad", "priority": 1.0, "required": true},
                {"name": "Vermithrax", "priority": 0.9, "required": true}
            ],
            "time_scope": {"type": "Current"},
            "spatial_scope": {"location_name": "dragon_lair", "include_contained": true},
            "reasoning_depth": "Causal",
            "context_priorities": ["CausalChains", "Entities", "TemporalState"],
            "confidence": 0.95
        }"#.to_string(),
        
        // Strategic directive - climactic confrontation
        r#"{
            "directive_type": "Climactic Confrontation",
            "narrative_arc": "Hero's Journey - Ordeal",
            "plot_significance": "Major",
            "emotional_tone": "Desperate Resolve",
            "character_focus": ["Sir Galahad", "Vermithrax"],
            "world_impact_level": "Kingdom"
        }"#.to_string(),
        
        // Tactical plan - detailed combat approach
        r#"{
            "steps": [
                {
                    "description": "Channel grief and rage into focused attack on dragon's weak point",
                    "preconditions": ["Character emotionally prepared", "Dragon within striking distance"],
                    "expected_outcomes": ["Significant damage potential", "High risk of retaliation"],
                    "required_entities": ["Sir Galahad", "Vermithrax", "Enchanted Blade"],
                    "estimated_duration": 4000
                },
                {
                    "description": "Use mentor's final teaching to exploit dragon's blind spot",
                    "preconditions": ["Initial strike successful", "Dragon momentarily stunned"],
                    "expected_outcomes": ["Tactical advantage", "Emotional catharsis"],
                    "required_entities": ["Sir Galahad", "Vermithrax"],
                    "estimated_duration": 3000
                }
            ],
            "overall_risk": "Critical",
            "mitigation_strategies": [
                "Draw upon mentor's training for tactical awareness",
                "Channel emotional pain into combat focus",
                "Prepare for potential death with honor"
            ]
        }"#.to_string(),
        
        // Spatial location - dragon's lair
        r#"{
            "primary_location": "Dragon's Lair - Chamber of Bones",
            "confidence": 0.92,
            "environmental_factors": ["Scattered knight remains", "Scorched walls", "Treasure hoard", "Ancient runes"]
        }"#.to_string(),
        
        // Character relationships - complex emotional connections
        r#"[
            {
                "entity1": "Sir Galahad",
                "relationship_type": "seeks_vengeance_against",
                "entity2": "Vermithrax",
                "strength": 0.95,
                "context": "Dragon killed his beloved mentor Sir Lancelot"
            },
            {
                "entity1": "Sir Galahad",
                "relationship_type": "haunted_by_memory_of",
                "entity2": "Sir Lancelot",
                "strength": 0.9,
                "context": "Mentor's death drives his quest for redemption"
            },
            {
                "entity1": "Vermithrax",
                "relationship_type": "ancient_enemy_of",
                "entity2": "Knights of the Round Table",
                "strength": 0.8,
                "context": "Has killed multiple knights over centuries"
            }
        ]"#.to_string(),
        
        // Recent actions - building to climax
        r#"[
            {
                "action": "recalled_mentors_final_words",
                "timestamp": "2024-01-15T10:00:00Z",
                "context": "Remembered Lancelot's dying advice about dragon's weakness",
                "significance": 0.9
            },
            {
                "action": "entered_chamber_of_bones",
                "timestamp": "2024-01-15T10:05:00Z",
                "context": "Discovered remains of fallen knights including mentor",
                "significance": 0.85
            },
            {
                "action": "challenged_dragon_directly",
                "timestamp": "2024-01-15T10:10:00Z",
                "context": "Shouted oath of vengeance to awaken Vermithrax",
                "significance": 0.95
            }
        ]"#.to_string(),
        
        // Emotional state - complex trauma and determination
        r#"{
            "primary_emotion": "Vengeful Determination",
            "intensity": 0.95,
            "contributing_factors": [
                "Guilt over mentor's death",
                "Rage at dragon's cruelty",
                "Fear of own mortality",
                "Desperate need for redemption"
            ],
            "stability": 0.4,
            "confidence": 0.85
        }"#.to_string(),
        
        // Entity names extraction
        r#"["Sir Galahad", "Vermithrax", "Sir Lancelot", "Enchanted Blade", "Chamber of Bones"]"#.to_string(),
        
        // Comprehensive entity context
        r#"{
            "entities": [
                {
                    "name": "Sir Galahad",
                    "entity_type": "Character",
                    "description": "Last knight of the Round Table, seeking vengeance for his mentor",
                    "properties": ["traumatized", "skilled_warrior", "emotionally_unstable", "honor_bound"]
                },
                {
                    "name": "Vermithrax",
                    "entity_type": "Dragon",
                    "description": "Ancient dragon responsible for killing multiple knights",
                    "properties": ["ancient", "powerful", "intelligent", "ruthless", "knight_killer"]
                },
                {
                    "name": "Sir Lancelot",
                    "entity_type": "Deceased_Knight",
                    "description": "Galahad's mentor, killed by Vermithrax years ago",
                    "properties": ["deceased", "mentor", "skilled", "beloved", "tragic_end"]
                },
                {
                    "name": "Enchanted Blade",
                    "entity_type": "Weapon",
                    "description": "Lancelot's sword, now wielded by Galahad",
                    "properties": ["magical", "legacy_weapon", "dragon_effective", "emotionally_significant"]
                }
            ],
            "spatial_context": {
                "primary_location": "Chamber of Bones",
                "secondary_locations": ["Dragon's Hoard", "Ancient Passages", "Bone Scattered Floor"],
                "spatial_relationships": [
                    {
                        "entity1": "Sir Galahad",
                        "relationship": "confronts",
                        "entity2": "Vermithrax"
                    },
                    {
                        "entity1": "Sir Lancelot",
                        "relationship": "remains_scattered_in",
                        "entity2": "Chamber of Bones"
                    }
                ]
            },
            "temporal_context": {
                "time_indicators": ["now", "after years of preparation", "moment of truth"],
                "sequence_markers": ["upon entering", "after discovery", "during confrontation"],
                "duration_hints": ["climactic battle", "life-or-death moment", "final confrontation"]
            },
            "social_context": {
                "relationships": [
                    {
                        "entity1": "Sir Galahad",
                        "relationship": "seeks_to_avenge",
                        "entity2": "Sir Lancelot"
                    },
                    {
                        "entity1": "Vermithrax",
                        "relationship": "killed",
                        "entity2": "Sir Lancelot"
                    }
                ],
                "social_dynamics": ["vengeance_quest", "mentor_student_bond", "dragon_knight_enmity"],
                "emotional_tone": "tragic_determination"
            },
            "actions_and_events": [
                {
                    "action": "prepares_final_strike",
                    "agent": "Sir Galahad",
                    "target": "Vermithrax",
                    "context": "channeling_mentors_memory"
                },
                {
                    "action": "awakens_to_challenge",
                    "agent": "Vermithrax",
                    "target": null,
                    "context": "recognizes_another_knight"
                }
            ]
        }"#.to_string(),
        
        // Entity semantic matching (multiple entities)
        r#"{"match_found": false, "similarity": 0.1, "reasoning": "Sir Galahad is a new character"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.0, "reasoning": "Vermithrax is a unique dragon"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.0, "reasoning": "Sir Lancelot is a deceased mentor"}"#.to_string(),
        r#"{"match_found": false, "similarity": 0.0, "reasoning": "Enchanted Blade is a legacy weapon"}"#.to_string(),
        
        // AI component suggestions (multiple entities)
        r#"{
            "suggested_components": [
                {
                    "component_type": "Trauma",
                    "initial_values": {"trauma_level": 0.9, "trigger": "mentor_death", "stability": 0.3},
                    "reasoning": "Character deeply traumatized by mentor's death"
                },
                {
                    "component_type": "Combat",
                    "initial_values": {"health": 80, "attack_power": 35, "defense": 20, "rage_bonus": 15},
                    "reasoning": "Skilled knight with emotional combat bonus"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Ancient_Dragon",
                    "initial_values": {"age": 800, "power_level": 95, "knight_kills": 12, "intelligence": 85},
                    "reasoning": "Ancient dragon with extensive history of killing knights"
                },
                {
                    "component_type": "Territorial",
                    "initial_values": {"territory_size": 200, "intrusion_sensitivity": 0.95},
                    "reasoning": "Dragon defending its ancient lair"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Ghost",
                    "initial_values": {"manifestation_strength": 0.7, "guidance_ability": 0.9},
                    "reasoning": "Mentor's spirit may guide his student"
                }
            ]
        }"#.to_string(),
        r#"{
            "suggested_components": [
                {
                    "component_type": "Legacy_Weapon",
                    "initial_values": {"damage": 40, "magical_enhancement": 0.8, "emotional_resonance": 0.9},
                    "reasoning": "Mentor's weapon with emotional significance"
                }
            ]
        }"#.to_string(),
        
        // Temporal events - past events building to this moment
        r#"[
            {
                "description": "Sir Lancelot trained young Galahad in advanced swordplay",
                "timestamp": "2020-03-15T14:30:00Z",
                "significance": 0.8,
                "participants": ["Sir Lancelot", "Sir Galahad"],
                "event_type": "training"
            },
            {
                "description": "Vermithrax killed Sir Lancelot in single combat",
                "timestamp": "2023-06-20T16:45:00Z",
                "significance": 0.95,
                "participants": ["Sir Lancelot", "Vermithrax"],
                "event_type": "tragic_death"
            },
            {
                "description": "Galahad swore a blood oath to avenge his mentor",
                "timestamp": "2023-06-21T09:00:00Z",
                "significance": 0.9,
                "participants": ["Sir Galahad"],
                "event_type": "oath_taking"
            },
            {
                "description": "Galahad spent months preparing for this confrontation",
                "timestamp": "2024-01-01T00:00:00Z",
                "significance": 0.85,
                "participants": ["Sir Galahad"],
                "event_type": "preparation"
            }
        ]"#.to_string(),
        
        // Temporal events - future implications
        r#"[
            {
                "description": "The kingdom's fate depends on this battle's outcome",
                "time_until": "within the hour",
                "participants": ["Sir Galahad", "Vermithrax"],
                "urgency": 0.95
            },
            {
                "description": "Galahad may join his mentor in death",
                "time_until": "within minutes",
                "participants": ["Sir Galahad"],
                "urgency": 0.9
            },
            {
                "description": "The dragon's reign of terror could end",
                "time_until": "if the knight succeeds",
                "participants": ["Vermithrax"],
                "urgency": 0.85
            }
        ]"#.to_string(),
        
        // RICH CAUSAL CONTEXT EXTRACTION - The key response
        r#"{
            "causal_chains": [
                {
                    "events": [
                        {
                            "description": "Sir Lancelot discovered the dragon's weakness during their fatal encounter",
                            "timestamp": "2023-06-20T16:30:00Z",
                            "cause_strength": 0.9
                        },
                        {
                            "description": "Lancelot shared this knowledge with Galahad before dying",
                            "timestamp": "2023-06-20T16:44:00Z",
                            "cause_strength": 0.95
                        },
                        {
                            "description": "Galahad spent months training to exploit this weakness",
                            "timestamp": "2024-01-01T00:00:00Z",
                            "cause_strength": 0.85
                        },
                        {
                            "description": "The knight's grief transformed into cold determination",
                            "timestamp": "2024-01-15T09:00:00Z",
                            "cause_strength": 0.8
                        },
                        {
                            "description": "Galahad now strikes at the exact spot Lancelot identified",
                            "timestamp": "2024-01-15T10:15:00Z",
                            "cause_strength": 0.9
                        }
                    ],
                    "confidence": 0.92
                },
                {
                    "events": [
                        {
                            "description": "The dragon's cruelty in killing knights has made it overconfident",
                            "timestamp": "2023-06-20T16:45:00Z",
                            "cause_strength": 0.8
                        },
                        {
                            "description": "Vermithrax expects this knight to fall like all the others",
                            "timestamp": "2024-01-15T10:10:00Z",
                            "cause_strength": 0.85
                        },
                        {
                            "description": "The dragon's arrogance may lead to a fatal mistake",
                            "timestamp": "2024-01-15T10:15:00Z",
                            "cause_strength": 0.75
                        }
                    ],
                    "confidence": 0.88
                }
            ],
            "potential_consequences": [
                {
                    "description": "Galahad's strike could fatally wound the dragon, ending its reign of terror",
                    "probability": 0.4,
                    "impact_severity": 0.95
                },
                {
                    "description": "The dragon could kill Galahad, continuing its cycle of knight-slaying",
                    "probability": 0.5,
                    "impact_severity": 0.9
                },
                {
                    "description": "Both combatants could die in a mutual destruction scenario",
                    "probability": 0.25,
                    "impact_severity": 0.85
                },
                {
                    "description": "Galahad's emotional state could cause him to make a tactical error",
                    "probability": 0.6,
                    "impact_severity": 0.8
                },
                {
                    "description": "The knight's knowledge of the dragon's weakness could give him a decisive advantage",
                    "probability": 0.45,
                    "impact_severity": 0.9
                }
            ],
            "historical_precedents": [
                {
                    "event_description": "Sir Lancelot's failed attempt to slay the same dragon",
                    "outcome": "Lancelot died but discovered the dragon's weakness",
                    "similarity_score": 0.95,
                    "timestamp": "2023-06-20T16:45:00Z"
                },
                {
                    "event_description": "Sir Percival's earlier encounter with Vermithrax",
                    "outcome": "Percival fled but lived to warn others",
                    "similarity_score": 0.7,
                    "timestamp": "2022-09-15T14:20:00Z"
                },
                {
                    "event_description": "The legendary dragonslayer Saint George's victory",
                    "outcome": "George defeated his dragon through faith and tactical knowledge",
                    "similarity_score": 0.65,
                    "timestamp": "1200-04-23T12:00:00Z"
                }
            ],
            "causal_confidence": 0.91
        }"#.to_string(),
    ];
    
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(rich_mock_responses));
    let intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone()));
    let query_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone()));
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
    )
}

#[tokio::test]
async fn test_rich_causal_context_extraction() {
    // Setup test environment
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let assembler = create_rich_causal_assembler(&test_app).await;
    
    // Create test data with rich background
    let user = create_test_user(&test_app.db_pool, "galahad@roundtable.com".to_string(), "Sir Galahad".to_string()).await.unwrap();
    let user_dek = Arc::new(generate_dek().unwrap());
    let character = create_rich_test_character(&user_dek).await;
    
    // Create rich chat history with complex causal relationships
    let rich_chat_history = vec![
        GenAiChatMessage::user("I remember the day my mentor Sir Lancelot was killed by the dragon Vermithrax. He died protecting the kingdom, but not before discovering the beast's weakness."),
        GenAiChatMessage::assistant("The memory of that tragic day still haunts Sir Galahad. Lancelot's final words echo in his mind: 'The dragon's scales are weakest just below the left shoulder blade. Remember this, young knight.'"),
        GenAiChatMessage::user("I swore an oath that day to avenge my mentor's death. I have spent months preparing for this confrontation, training specifically to exploit the weakness Lancelot discovered."),
        GenAiChatMessage::assistant("Sir Galahad's grief has transformed into cold determination. Every strike of his blade in training has been aimed at that precise spot Lancelot identified with his dying breath."),
        GenAiChatMessage::user("Now I stand in the Chamber of Bones, surrounded by the remains of fallen knights. I can see Lancelot's armor among the scattered bones. The dragon awakens, sensing my presence."),
        GenAiChatMessage::assistant("Vermithrax's ancient eyes open, glowing with malevolent intelligence. The dragon recognizes another knight come to challenge it, expecting this one to fall like all the others."),
        GenAiChatMessage::user("I raise Lancelot's enchanted blade and shout my oath of vengeance. The dragon roars in response, flames beginning to gather in its throat."),
        GenAiChatMessage::assistant("The chamber fills with the dragon's roar as Vermithrax rises to its full terrifying height. This is the moment of truth - will Galahad succeed where his mentor failed?"),
        GenAiChatMessage::user("I remember Lancelot's training, feel his spirit guiding my blade. Now I strike at the dragon's weakness with all my might!"),
    ];
    
    // Execute the rich causal context extraction
    let user_input = "I channel my mentor's memory and strike at the dragon's vulnerable spot below the left shoulder blade!";
    let enriched_context = assembler.assemble_enriched_context(
        user_input,
        &rich_chat_history,
        Some(&character),
        user.id,
        Some(&user_dek),
    ).await;
    
    // Verify the operation succeeded
    match &enriched_context {
        Ok(context) => {
            println!("✅ Rich causal context extraction succeeded");
            println!("   - Causal context present: {}", context.causal_context.is_some());
            if let Some(ref causal_context) = context.causal_context {
                println!("   - Causal chains: {}", causal_context.causal_chains.len());
                println!("   - Potential consequences: {}", causal_context.potential_consequences.len());
                println!("   - Historical precedents: {}", causal_context.historical_precedents.len());
                println!("   - Causal confidence: {:.2}", causal_context.causal_confidence);
            }
        }
        Err(e) => {
            println!("❌ Rich causal context extraction failed: {:?}", e);
            panic!("Rich causal context extraction should succeed: {}", e);
        }
    }
    let context = enriched_context.unwrap();
    
    // === RICH CAUSAL CONTEXT VERIFICATION ===
    
    // Verify causal context was extracted with rich data
    assert!(context.causal_context.is_some(), "Rich causal context should be extracted");
    let causal_context = context.causal_context.unwrap();
    
    // Verify rich causal chains
    assert_eq!(causal_context.causal_chains.len(), 2, "Should have 2 rich causal chains");
    
    // Verify first causal chain (mentor's knowledge passing to student)
    let mentor_chain = &causal_context.causal_chains[0];
    assert_eq!(mentor_chain.events.len(), 5, "Mentor chain should have 5 events");
    assert_eq!(mentor_chain.confidence, 0.92, "Mentor chain should have high confidence");
    
    // Verify specific causal events
    assert!(mentor_chain.events[0].description.contains("discovered the dragon's weakness"), "First event should be about discovering weakness");
    assert!(mentor_chain.events[1].description.contains("shared this knowledge"), "Second event should be about sharing knowledge");
    assert!(mentor_chain.events[2].description.contains("training to exploit"), "Third event should be about training");
    assert!(mentor_chain.events[4].description.contains("strikes at the exact spot"), "Final event should be about striking");
    
    // Verify second causal chain (dragon's overconfidence)
    let dragon_chain = &causal_context.causal_chains[1];
    assert_eq!(dragon_chain.events.len(), 3, "Dragon chain should have 3 events");
    assert_eq!(dragon_chain.confidence, 0.88, "Dragon chain should have good confidence");
    
    // Verify rich potential consequences
    assert_eq!(causal_context.potential_consequences.len(), 5, "Should have 5 potential consequences");
    
    // Test specific consequences
    let fatal_wound_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("fatally wound the dragon"))
        .expect("Should have fatal wound consequence");
    assert_eq!(fatal_wound_consequence.probability, 0.4, "Fatal wound probability should be 0.4");
    assert_eq!(fatal_wound_consequence.impact_severity, 0.95, "Fatal wound impact should be severe");
    
    let knight_death_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("kill Galahad"))
        .expect("Should have knight death consequence");
    assert_eq!(knight_death_consequence.probability, 0.5, "Knight death probability should be 0.5");
    
    let tactical_advantage_consequence = causal_context.potential_consequences.iter()
        .find(|c| c.description.contains("knowledge of the dragon's weakness"))
        .expect("Should have tactical advantage consequence");
    assert_eq!(tactical_advantage_consequence.probability, 0.45, "Tactical advantage probability should be 0.45");
    
    // Verify rich historical precedents
    assert_eq!(causal_context.historical_precedents.len(), 3, "Should have 3 historical precedents");
    
    let lancelot_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("Sir Lancelot's failed attempt"))
        .expect("Should have Lancelot precedent");
    assert_eq!(lancelot_precedent.similarity_score, 0.95, "Lancelot precedent should be highly similar");
    assert!(lancelot_precedent.outcome.contains("discovered the dragon's weakness"), "Lancelot precedent should mention weakness discovery");
    
    let percival_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("Sir Percival's earlier encounter"))
        .expect("Should have Percival precedent");
    assert_eq!(percival_precedent.similarity_score, 0.7, "Percival precedent should be moderately similar");
    
    let george_precedent = causal_context.historical_precedents.iter()
        .find(|p| p.event_description.contains("Saint George's victory"))
        .expect("Should have Saint George precedent");
    assert_eq!(george_precedent.similarity_score, 0.65, "Saint George precedent should be somewhat similar");
    assert!(george_precedent.outcome.contains("through faith and tactical knowledge"), "Saint George precedent should mention tactical knowledge");
    
    // Verify high overall causal confidence
    assert_eq!(causal_context.causal_confidence, 0.91, "Should have high causal confidence");
    
    // === INTEGRATION VERIFICATION ===
    
    // Verify causal context integrates with other rich context
    assert!(context.temporal_context.is_some(), "Temporal context should be present");
    assert!(context.spatial_context.is_some(), "Spatial context should be present");
    assert!(!context.relevant_entities.is_empty(), "Should have relevant entities");
    
    // Verify character entity has rich context
    let character_entity = context.relevant_entities.iter()
        .find(|e| e.entity_name == "Sir Galahad")
        .expect("Character entity should be present");
    assert!(character_entity.emotional_state.is_some(), "Character should have emotional state");
    assert!(!character_entity.relationships.is_empty(), "Character should have relationships");
    
    // Verify strategic directive matches rich narrative
    assert!(context.strategic_directive.is_some(), "Strategic directive should be present");
    let directive = context.strategic_directive.unwrap();
    assert_eq!(directive.directive_type, "Climactic Confrontation", "Should be climactic confrontation");
    assert_eq!(directive.narrative_arc, "Hero's Journey - Ordeal", "Should be hero's journey ordeal");
    
    // === PERFORMANCE VERIFICATION ===
    
    // Verify reasonable performance with rich context
    assert!(context.execution_time_ms < 10000, "Should execute within reasonable time even with rich context");
    assert!(context.ai_model_calls >= 15, "Should make expected number of AI calls for rich context");
    assert!(context.total_tokens_used > 0, "Should track token usage");
    
    println!("✅ Rich causal context extraction test passed completely!");
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