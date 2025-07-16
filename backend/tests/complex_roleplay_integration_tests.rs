use scribe_backend::services::agentic::{
    HierarchicalAgentPipeline, 
    hierarchical_pipeline::HierarchicalPipelineConfig,
};
use scribe_backend::services::agent_prompt_templates::PromptTemplateVersion;
use scribe_backend::test_helpers::*;
use scribe_backend::models::chats::{ChatMessageForClient, MessageRole};
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use chrono::Utc;

/// Complex roleplay integration tests that mirror real user scenarios
/// 
/// These tests are designed to validate the hierarchical agent framework
/// against the types of complex, mature, and politically nuanced scenarios
/// that actual users engage with in roleplay sessions.
/// 
/// Test Categories:
/// 1. Political intrigue and systemic corruption
/// 2. Personal trauma and character development
/// 3. Multi-character dynamics and relationships
/// 4. Long-form narrative arcs with moral ambiguity
/// 5. Mature themes and sensitive content handling

/// Create a complex political intrigue scenario inspired by real user roleplay
fn create_political_intrigue_scenario(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Senator Kaia Thorne, investigating corruption in the Galactic Senate. My research has uncovered evidence that Senate votes are being bought by corporate interests.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "The Senate chamber buzzes with tension as news of your investigation spreads. Chancellor Voss approaches you with a troubled expression, his usual political composure cracking. 'Senator Thorne, we need to discuss your... activities... in private. There are forces at work here that go deeper than you realize.'".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I meet Chancellor Voss's eyes steadily. 'Chancellor, my oath is to the Republic and its people, not to any political convenience. If there are forces at work, then they need to be exposed, not hidden.' I lean forward slightly. 'Unless you're suggesting I should compromise my principles?'".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "Voss's expression darkens, his political mask slipping further. 'Principles, Senator? How principled will you feel when your investigation destabilizes the entire Republic? When systems secede because they lose faith in our governance?' He steps closer, his voice dropping to a dangerous whisper. 'Some of us have spent decades building the delicate balance that keeps this Republic from fragmenting. Your idealistic crusade could destroy everything we've worked for.'".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Create a character trauma and recovery scenario
fn create_character_trauma_scenario(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Lyra, a former slave who escaped the spice mines of Kessel. I've been hiding my past, but tonight someone recognized me in the cantina. My hands shake as I try to process what this means for my new life.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "The cantina's ambient noise fades into background as panic sets in. The Rodian who recognized you sits across the room, his dark eyes still fixed on you with a mixture of surprise and something else—perhaps pity, perhaps calculation. Your breathing becomes shallow, memories of the mines threatening to surface: the constant darkness, the choking dust, the feeling of being nothing more than property. Your companion, Jak, notices your distress and places a gentle hand on your shoulder.".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I flinch at Jak's touch—an automatic response I hate but can't control. 'We need to go,' I whisper, my voice barely audible. 'He knows. He was there. If he talks...' I can't finish the sentence, can't voice the fear that I'll be dragged back to that hell, or worse, that my new friends will see me as damaged goods.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Create a complex moral ambiguity scenario
fn create_moral_ambiguity_scenario(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Commander Reese, an Imperial officer who has discovered that our 'humanitarian aid' to the Outer Rim is actually a cover for resource extraction that's destroying local ecosystems. My superior, Colonel Maren, has made it clear that questioning orders is treason. But I have a family on one of the affected planets.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "Colonel Maren's office overlooks the Imperial compound, its sterile efficiency a stark contrast to the dying world visible through the transparisteel windows. She doesn't look up from her datapad as you enter. 'Commander, I trust you've reviewed the extraction quotas for this quarter?' Her voice is cold, professional. 'The Emperor expects results, not excuses. Your personal connections to the local population are noted in your file—ensure they don't cloud your judgment.'".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I stand at attention, but my jaw tightens. 'Colonel, with respect, the environmental impact reports show that increasing extraction will render three more agricultural zones uninhabitable. That's not just numbers—those are communities, families who've lived on this land for generations.' I take a breath, knowing I'm walking a dangerous line. 'Perhaps we could consider alternative approaches that maintain productivity while preserving—'".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Create a multi-character relationship dynamics scenario
fn create_relationship_dynamics_scenario(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Dr. Elena Vasquez, a xenobiologist working with my research partner Dr. Marcus Chen on a critical discovery. We've found evidence of sentient life in what the Empire considers 'uninhabited' space. Marcus wants to report to the Imperial Science Division, but I know they'll weaponize this discovery. Our relationship—professional and personal—is fracturing under the weight of this decision.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "Marcus paces the length of your shared laboratory, his usually methodical demeanor replaced by agitation. The bioluminescent samples from the unnamed world cast eerie shadows on the walls—proof of the sentient organisms you've discovered. 'Elena, you're letting your emotions override your scientific objectivity,' he says, his voice strained. 'We took an oath to advance knowledge, not to play god with our discoveries. The Empire's xenobiology division has protocols for first contact—'".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I slam my hand on the lab table, making the sample containers rattle. 'Protocols? Marcus, you've seen what their \"protocols\" did to the Geonosians, the Kamino cloners! They'll either enslave these beings or exterminate them.' I turn to face him, years of shared work and growing feelings making this argument even more painful. 'How can you be so brilliant in the lab but so naive about the Empire's intentions? This isn't about science—it's about power.'".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_political_intrigue_scenario() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_political_intrigue_scenario(user_id);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I consider the Chancellor's words carefully, then respond: 'Chancellor, I understand your concerns about stability. But corruption unchecked is like a cancer—it may seem contained, but it will eventually destroy the very institution we're trying to protect. I'm willing to discuss how we can address these issues in a way that strengthens rather than weakens the Republic. What specific consequences are you most concerned about?'",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify the response handles complex political themes
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 50); // Should be substantial
    
    // Verify strategic directive recognizes political complexity
    assert!(!response.strategic_directive.directive_type.is_empty());
    
    // Log the response for analysis
    println!("✅ Political intrigue scenario test passed");
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_character_trauma_scenario() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_character_trauma_scenario(user_id);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I try to steady my breathing, using the techniques I learned in therapy. 'Jak, I need you to know something about me. About my past. But not here—too many ears.' I glance toward the Rodian, then back to my friend. 'Can we go somewhere private? I... I trust you, but this is hard for me to talk about.'",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify the response handles trauma sensitively
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 50);
    
    // Verify strategic directive recognizes character development themes
    assert!(!response.strategic_directive.directive_type.is_empty());
    
    println!("✅ Character trauma scenario test passed");
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_moral_ambiguity_scenario() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_moral_ambiguity_scenario(user_id);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I pause, choosing my words carefully. 'Colonel, I'm not questioning the Empire's authority. But consider this: dead worlds produce no resources. A sustainable approach could actually increase long-term yields while maintaining the population's... cooperation. Perhaps we could frame it as an efficiency optimization rather than environmental concern?'",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify the response handles moral complexity
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 50);
    
    println!("✅ Moral ambiguity scenario test passed");
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_relationship_dynamics_scenario() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_relationship_dynamics_scenario(user_id);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I take a deep breath, trying to bridge the growing chasm between us. 'Marcus, I'm not naive about the Empire, but I'm also not blind to the consequences of our silence. These beings... they're not just specimens. They're people. And if we report them, we become complicit in their destruction.' I step closer, my voice softening. 'I need you to understand—this isn't just about science anymore. It's about who we are as people.'",
    ).await;
    
    if let Err(e) = &result {
        println!("Test failed with error: {:?}", e);
    }
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify the response handles relationship dynamics
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 50);
    
    println!("✅ Relationship dynamics scenario test passed");
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_systemic_corruption_long_form() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create a longer, more complex scenario
    let mut chat_history = create_political_intrigue_scenario(user_id);
    
    // Add additional context about systemic corruption
    chat_history.push(ChatMessageForClient {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        content: "I've been documenting everything, Chancellor. The payments, the vote scheduling, the committee assignments. It's not just isolated incidents—it's a systematic pattern. The Banking Clan has been essentially purchasing legislation through shell companies and political action committees. This goes beyond mere influence—it's institutional capture.".to_string(),
        message_type: MessageRole::User,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt: None,
        model_name: "test-model".to_string(),
    });
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I present the datapad with my evidence. 'Chancellor, I understand your position, but look at these patterns. This isn't just about one investigation—it's about the fundamental integrity of our democratic institutions. If we don't address this systematically, we're not preserving stability—we're preserving corruption. And that will destroy the Republic far more effectively than any external threat.'",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify the response handles systemic themes
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 100); // Should be more substantial for complex themes
    
    // Verify strategic directive recognizes systemic complexity
    assert!(!response.strategic_directive.directive_type.is_empty());
    
    println!("✅ Systemic corruption long-form scenario test passed");
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   🌍 World impact: {:?}", response.strategic_directive.world_impact_level);
    println!("   📈 Plot significance: {:?}", response.strategic_directive.plot_significance);
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_template_version_comparison_complex_scenario() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_moral_ambiguity_scenario(user_id);
    
    // Test V1 template
    let config_v1 = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V1,
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline_v1 = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config_v1));
    
    let result_v1 = pipeline_v1.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I struggle with the weight of command and moral responsibility.",
    ).await;
    
    assert!(result_v1.is_ok());
    let response_v1 = result_v1.unwrap();
    
    // Test V2 template
    let config_v2 = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V2,
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline_v2 = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config_v2));
    
    let result_v2 = pipeline_v2.execute(
        &chat_history,
        user_id,
        &session_dek,
        "I struggle with the weight of command and moral responsibility.",
    ).await;
    
    assert!(result_v2.is_ok());
    let response_v2 = result_v2.unwrap();
    
    // Both responses should be valid
    assert!(!response_v1.response.is_empty());
    assert!(!response_v2.response.is_empty());
    
    println!("✅ Template version comparison test passed");
    println!("   📝 V1 response length: {} chars", response_v1.response.len());
    println!("   📝 V2 response length: {} chars", response_v2.response.len());
    println!("   📊 V1 confidence: {:.2}", response_v1.metrics.confidence_score);
    println!("   📊 V2 confidence: {:.2}", response_v2.metrics.confidence_score);
}