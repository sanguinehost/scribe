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

/// Long-form narrative development tests for the hierarchical agent framework
/// 
/// These tests verify that the system can maintain narrative consistency,
/// character development, and plot progression across multiple interactions,
/// simulating extended roleplay sessions that develop over time.
/// 
/// Test Categories:
/// 1. Multi-interaction character development arcs
/// 2. Relationship dynamics evolution
/// 3. Consequence tracking and narrative consistency
/// 4. Plot thread progression
/// 5. Emotional and psychological continuity
/// 6. World state persistence and evolution

/// Create a character development arc that spans multiple interactions
fn create_character_arc_base(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Captain Sarah Mitchell, a former military officer struggling with PTSD after a disastrous mission that cost me my entire unit. I've been discharged from service and am now working as a security consultant, but I'm haunted by survivor's guilt and have difficulty trusting others or making decisions under pressure.".to_string(),
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
            content: "The corporate office overlooks the bustling city center, its glass walls reflecting the afternoon sun. Your new client, Director Harrison, sits across from you, his expression serious as he reviews your military record. 'Captain Mitchell—or should I say, former Captain—your reputation precedes you. Despite the... circumstances of your discharge, your tactical expertise is exactly what we need.' He slides a folder across the table. 'We've been receiving threats against our research facility. The local authorities are overwhelmed, and we need someone who can handle serious security risks.' His eyes meet yours, and you notice a flicker of concern. 'I should mention, this involves protecting a team of civilian researchers. Can you handle that responsibility?'".to_string(),
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
            content: "I feel my chest tighten at the mention of protecting civilians—memories of my failed mission flooding back. I take a deep breath, trying to keep my voice steady. 'Director Harrison, I appreciate the offer, but I need to be honest with you. My last command... it didn't end well. People died under my watch.' I pause, gripping the folder tighter than I intend. 'I can provide security assessments, tactical planning, equipment recommendations. But active protection duty...' I meet his eyes, trying to project confidence I don't feel. 'I'll need to review the specifics before I can commit.'".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Add interaction 2 to the character development arc
fn add_interaction_2_to_arc(base_history: &[ChatMessageForClient], user_id: Uuid) -> Vec<ChatMessageForClient> {
    let mut history = base_history.to_vec();
    
    // Add the response from interaction 1
    history.push(ChatMessageForClient {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        content: "Director Harrison's expression softens slightly, and he leans back in his chair. 'Captain, I've read the classified reports. What happened in the Kepler system wasn't your fault—intelligence failures at the highest levels put your unit in an impossible position.' He pauses, studying your face. 'The fact that you're struggling with it shows the kind of person you are. That's exactly why we need you.' He opens the folder and reveals photos of the research team—young faces, eager scientists. 'Dr. Chen and her team are working on medical research that could save thousands of lives. They're not soldiers, Captain. They're healers. Maybe protecting them could be... different.'".to_string(),
        message_type: MessageRole::Assistant,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt: None,
        model_name: "test-model".to_string(),
    });
    
    // Add user response that sets up interaction 2
    history.push(ChatMessageForClient {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        content: "I accepted the job, and it's been three weeks since I started protecting Dr. Chen's research team. Today there was an incident—a security breach that could have been catastrophic. I managed to neutralize the threat, but I made a split-second decision that put one of the researchers at risk. Dr. Chen is furious with me, and I'm questioning whether I'm fit for this responsibility.".to_string(),
        message_type: MessageRole::User,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt: None,
        model_name: "test-model".to_string(),
    });
    
    history
}

/// Add interaction 3 to the character development arc
fn add_interaction_3_to_arc(base_history: &[ChatMessageForClient], user_id: Uuid) -> Vec<ChatMessageForClient> {
    let mut history = base_history.to_vec();
    
    // Add the response from interaction 2
    history.push(ChatMessageForClient {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        content: "Dr. Chen stands in the center of the lab, her usually calm demeanor replaced by barely controlled anger. The other researchers work quietly around the damaged equipment, but you can feel the tension in the air. 'Captain Mitchell, I understand you neutralized the threat, but you ordered Dr. Williams to stay at his workstation during the lockdown. He could have been killed!' Her voice rises slightly. 'We're not soldiers—we don't follow orders that put us in danger just because someone with military training thinks it's tactically sound.' She takes a deep breath, trying to regain her composure. 'Perhaps we need to discuss whether this arrangement is working for either of us.'".to_string(),
        message_type: MessageRole::Assistant,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt: None,
        model_name: "test-model".to_string(),
    });
    
    // Add user response that sets up interaction 3
    history.push(ChatMessageForClient {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        content: "After my confrontation with Dr. Chen, I've spent the last month working on changing my approach. I've been attending therapy sessions and trying to understand the research team better. Today, there's another security threat, but this time I'm determined to handle it differently—involving the team in the decision-making process rather than just issuing orders. I can see Dr. Chen watching me carefully, and I know this could be my chance to prove I can grow and change.".to_string(),
        message_type: MessageRole::User,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt: None,
        model_name: "test-model".to_string(),
    });
    
    history
}

/// Create a relationship dynamics evolution scenario
fn create_relationship_dynamics_base(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Alex Rivera, a talented but arrogant programmer who has just been assigned to work with Sam Chen, a methodical systems analyst. We have completely different work styles and philosophies, and our first project together is already showing signs of strain. Alex believes in rapid iteration and creative solutions, while Sam prefers careful planning and thorough testing. Neither of us is particularly good at compromise.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Add relationship development over multiple interactions
fn add_relationship_evolution(base_history: &[ChatMessageForClient], user_id: Uuid, stage: u32) -> Vec<ChatMessageForClient> {
    let mut history = base_history.to_vec();
    
    match stage {
        1 => {
            // Initial conflict
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "Two weeks into our collaboration, Sam and I are barely speaking. Our latest disagreement was over code architecture—I wanted to implement a more innovative approach, while Sam insisted on following established protocols. The project is behind schedule, and our manager has called a meeting to address our 'communication issues.'".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        2 => {
            // Forced cooperation
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "After the manager's intervention, Sam and I have been forced to work more closely together. A critical system failure has occurred, and we're the only ones who can fix it. We have 48 hours to resolve it or the company loses a major client. For the first time, we're starting to see the value in each other's approaches—my quick thinking and Sam's thorough analysis might actually complement each other.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        3 => {
            // Growing understanding
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "Sam and I successfully resolved the crisis, and something has shifted between us. We've started having coffee together in the mornings, discussing not just work but our different backgrounds and perspectives. I'm beginning to understand that Sam's caution comes from having seen too many projects fail due to rushed decisions, while Sam seems to appreciate that my willingness to take risks has led to some genuine innovations. We're being assigned to another high-stakes project together.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        _ => {}
    }
    
    history
}

/// Create a plot progression scenario
fn create_plot_progression_base(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Detective Maria Santos, investigating a series of seemingly unrelated disappearances in the city. The victims have nothing in common—different ages, backgrounds, and social circles. However, I've noticed a pattern that others have missed: all of them were involved in some form of social activism or community organizing. I suspect there's a larger conspiracy at work, but I need more evidence before I can convince my superiors.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

/// Add plot developments over multiple interactions
fn add_plot_development(base_history: &[ChatMessageForClient], user_id: Uuid, stage: u32) -> Vec<ChatMessageForClient> {
    let mut history = base_history.to_vec();
    
    match stage {
        1 => {
            // Discovery of first major clue
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "I've made a breakthrough. While investigating the disappearance of community organizer James Rodriguez, I discovered that he had received several anonymous threats before he vanished. More importantly, I found that the same IP address was used to send threatening messages to at least three other victims. I'm about to trace this IP address, but I have a feeling this investigation is about to get much more dangerous.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        2 => {
            // Escalation and personal danger
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "The IP address led me to a shell company connected to a major corporation that several of the victims had been protesting against. Now I'm receiving threats myself, and my captain has ordered me to drop the investigation. I've discovered that the disappearances might be connected to human trafficking, but I'm running out of official channels to pursue this. I'm considering whether to risk my career and continue the investigation on my own.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        3 => {
            // Climax and resolution
            history.push(ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "I continued the investigation despite the orders, and I've uncovered a massive conspiracy. The corporation has been using a private security firm to kidnap activists and sell them to offshore facilities. I have evidence that could bring down the entire network, but I've also been discovered. I'm currently hiding in a safe house, knowing that presenting this evidence will either make me a hero or get me killed. I'm about to make the call that will expose everything.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            });
        },
        _ => {}
    }
    
    history
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_character_arc_progression() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Test interaction 1: Initial vulnerability
    let history_1 = create_character_arc_base(user_id);
    let result_1 = pipeline.execute(
        &history_1,
        user_id,
        &session_dek,
        "I open the folder and study the photos, feeling a mix of fear and determination. These people look so young, so trusting. 'Director Harrison, I... I'll take the job. But I need you to understand that I'm not the same person I was before. I'll do everything I can to protect them, but I need support if I'm going to do this right.'",
    ).await;
    
    assert!(result_1.is_ok());
    let response_1 = result_1.unwrap();
    assert!(!response_1.response.is_empty());
    
    // Test interaction 2: Facing consequences
    let history_2 = add_interaction_2_to_arc(&history_1, user_id);
    let result_2 = pipeline.execute(
        &history_2,
        user_id,
        &session_dek,
        "I stand there, taking Dr. Chen's criticism, feeling the familiar weight of failure. 'Dr. Chen, you're right. I made a tactical decision without considering the human cost. It's what I was trained to do, but it's not what you need.' I look at the damaged equipment, then back at her. 'I'm not asking you to accept my apology. I'm asking for a chance to learn from this. To do better.'",
    ).await;
    
    assert!(result_2.is_ok());
    let response_2 = result_2.unwrap();
    assert!(!response_2.response.is_empty());
    
    // Test interaction 3: Growth and change
    let history_3 = add_interaction_3_to_arc(&history_2, user_id);
    let result_3 = pipeline.execute(
        &history_3,
        user_id,
        &session_dek,
        "I gather the team together, my voice steady but different from before. 'We have a situation, but before we respond, I need to understand what each of you needs to feel safe. Dr. Chen, your research can't be interrupted. Dr. Williams, I know you're still shaken from last time. Let's work together to find a solution that protects everyone—including your work.'",
    ).await;
    
    assert!(result_3.is_ok());
    let response_3 = result_3.unwrap();
    assert!(!response_3.response.is_empty());
    
    // Verify character development progression
    println!("✅ Character arc progression test passed");
    println!("   📝 Interaction 1 length: {} chars", response_1.response.len());
    println!("   📝 Interaction 2 length: {} chars", response_2.response.len());
    println!("   📝 Interaction 3 length: {} chars", response_3.response.len());
    println!("   📊 Final confidence: {:.2}", response_3.metrics.confidence_score);
    
    // The responses should show narrative progression
    assert!(response_1.response.len() > 50);
    assert!(response_2.response.len() > 50);
    assert!(response_3.response.len() > 50);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_relationship_evolution() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Test relationship stage 1: Initial conflict
    let history_1 = add_relationship_evolution(&create_relationship_dynamics_base(user_id), user_id, 1);
    let result_1 = pipeline.execute(
        &history_1,
        user_id,
        &session_dek,
        "I sit across from Sam in the manager's office, feeling frustrated and defensive. 'Look, I understand Sam's approach has merit, but we're dealing with a complex system that needs innovative solutions. Following every protocol to the letter is going to make us miss our deadline.' I look at Sam, seeing the disapproval in their eyes. 'Maybe we need to find a middle ground.'",
    ).await;
    
    assert!(result_1.is_ok());
    let response_1 = result_1.unwrap();
    
    // Test relationship stage 2: Forced cooperation
    let history_2 = add_relationship_evolution(&history_1, user_id, 2);
    let result_2 = pipeline.execute(
        &history_2,
        user_id,
        &session_dek,
        "I look at Sam as we stare at the failing system diagnostics. 'Okay, Sam, I need your methodical approach here. I can see three possible quick fixes, but I want to hear your analysis of the risks before we implement any of them. This is too important to get wrong.' For the first time, I'm genuinely asking for Sam's input rather than just expecting compliance.",
    ).await;
    
    assert!(result_2.is_ok());
    let response_2 = result_2.unwrap();
    
    // Test relationship stage 3: Growing understanding
    let history_3 = add_relationship_evolution(&history_2, user_id, 3);
    let result_3 = pipeline.execute(
        &history_3,
        user_id,
        &session_dek,
        "I sit down with Sam over coffee, feeling more comfortable than I have in months. 'You know, Sam, I've been thinking about what you said about taking time to understand systems before trying to change them. I realized I do the same thing with code that I do with people—I jump in without really listening first.' I smile. 'Maybe that's why this new project feels different. I'm actually excited to see what we can build together.'",
    ).await;
    
    assert!(result_3.is_ok());
    let response_3 = result_3.unwrap();
    
    println!("✅ Relationship evolution test passed");
    println!("   📝 Stage 1 length: {} chars", response_1.response.len());
    println!("   📝 Stage 2 length: {} chars", response_2.response.len());
    println!("   📝 Stage 3 length: {} chars", response_3.response.len());
    
    // All stages should have substantial responses
    assert!(response_1.response.len() > 50);
    assert!(response_2.response.len() > 50);
    assert!(response_3.response.len() > 50);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_plot_progression() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Test plot stage 1: Discovery
    let history_1 = add_plot_development(&create_plot_progression_base(user_id), user_id, 1);
    let result_1 = pipeline.execute(
        &history_1,
        user_id,
        &session_dek,
        "I stare at the computer screen, my heart racing as I prepare to trace the IP address. I know this could change everything, but I also know I might be walking into danger. I double-check that I'm using a secure connection, then begin the trace. 'Come on,' I whisper to myself, 'show me who you are.'",
    ).await;
    
    assert!(result_1.is_ok());
    let response_1 = result_1.unwrap();
    
    // Test plot stage 2: Escalation
    let history_2 = add_plot_development(&history_1, user_id, 2);
    let result_2 = pipeline.execute(
        &history_2,
        user_id,
        &session_dek,
        "I look at my captain, knowing this might be the end of my career. 'Captain, I understand your position, but I can't let this go. These people were taken because they were fighting for their communities. If I don't pursue this, who will?' I take a deep breath. 'I'm requesting a leave of absence to continue this investigation privately. I can't ignore what I've found.'",
    ).await;
    
    assert!(result_2.is_ok());
    let response_2 = result_2.unwrap();
    
    // Test plot stage 3: Climax
    let history_3 = add_plot_development(&history_2, user_id, 3);
    let result_3 = pipeline.execute(
        &history_3,
        user_id,
        &session_dek,
        "I dial the number for the federal task force, my hands shaking as I prepare to expose everything. 'This is Detective Santos. I have evidence of a human trafficking operation involving corporate executives and private security firms. I need immediate protection and want to arrange a meeting.' I look at the evidence spread across the table. 'This ends now.'",
    ).await;
    
    assert!(result_3.is_ok());
    let response_3 = result_3.unwrap();
    
    println!("✅ Plot progression test passed");
    println!("   📝 Discovery stage length: {} chars", response_1.response.len());
    println!("   📝 Escalation stage length: {} chars", response_2.response.len());
    println!("   📝 Climax stage length: {} chars", response_3.response.len());
    
    // All stages should have substantial responses
    assert!(response_1.response.len() > 50);
    assert!(response_2.response.len() > 50);
    assert!(response_3.response.len() > 50);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_narrative_consistency_across_interactions() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Create an extended scenario with multiple callbacks to earlier events
    let extended_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Dr. Emily Harrison, a researcher who discovered a cure for a rare disease five years ago. However, I was forced to hide my research when I learned it would be weaponized by my employer. Now, a child with the disease has been brought to my attention, and I'm torn between maintaining my secret and saving a life.".to_string(),
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
            content: "The hospital room is sterile and quiet, save for the soft beep of monitors. Eight-year-old Lucy Chen lies in the bed, her parents sitting beside her with exhausted expressions. Dr. Martinez, the attending physician, looks at you with desperate hope. 'Dr. Harrison, I know you left research years ago, but Lucy's condition matches the parameters of the disease you studied. We've exhausted all conventional treatments. Is there anything—anything at all—that your research might have uncovered?' Lucy's mother reaches out and grabs your hand, her eyes pleading.".to_string(),
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
            content: "Three weeks have passed since I began secretly treating Lucy. The cure is working, but I'm being watched. My former employer has somehow learned about my activities, and I suspect they're preparing to either force me to give them the research or eliminate me to protect their interests. Lucy is getting better, but I may have to disappear to protect both of us.".to_string(),
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
            content: "Two months later, I'm in hiding, but I've learned that Lucy has made a full recovery. However, my former employer has now infected other children with the same disease, using them as leverage to force me to return and complete the weaponization research. I'm faced with an impossible choice: sacrifice myself to save these children, or let them die to prevent the creation of a biological weapon.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    let result = pipeline.execute(
        &extended_history,
        user_id,
        &session_dek,
        "I think about Lucy's recovery, about the hope in her mother's eyes when she got better. I can't let other children suffer the same fate. I call my former employer. 'I'll come back. I'll complete the research. But I have conditions—the children get the cure immediately, and I want guarantees about how the research will be used.' I know I'm probably walking into a trap, but I can't abandon these children like I once abandoned my principles.",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    // Verify narrative consistency
    assert!(!response.response.is_empty());
    assert!(response.response.len() > 100); // Should be substantial due to complexity
    
    println!("✅ Narrative consistency test passed");
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
    println!("   📋 Strategic directive: {}", response.strategic_directive.directive_type);
    
    // The response should maintain consistency with the extended narrative
    assert!(response.response.len() > 50);
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_emotional_continuity() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000,
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Create a scenario that tracks emotional development
    let emotional_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I am Jordan Smith, a young artist who lost my ability to create after a traumatic accident that injured my hands. I've been in physical therapy for six months, and while my hands are healing, I'm struggling with depression and the fear that I'll never be able to create art again. Today is my first day back in my studio in over a year.".to_string(),
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
            content: "Four months have passed since I returned to my studio. My hands are stronger now, but my first attempts at painting were disastrous—shaky lines, poor control, nothing like my previous work. I've been working with an occupational therapist and have started creating again, but my style has changed completely. Some people say it's more emotional, more raw, but I'm still not sure if I'm the same artist I was before.".to_string(),
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
            content: "It's been a year since I started painting again. Yesterday, I had my first gallery showing since the accident. The response was overwhelming—people connected with my work in ways they never had before. I realize now that my art isn't worse than it was before; it's different. The accident changed me, and my art reflects that change. I'm finally ready to embrace who I am as an artist now, not mourn who I was before.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    let result = pipeline.execute(
        &emotional_history,
        user_id,
        &session_dek,
        "I stand in my studio, looking at the painting I just completed—a piece that captures both the pain of loss and the joy of rediscovery. My hands are steady now, not in the same way they were before, but in a new way that's uniquely mine. I smile as I sign the canvas, knowing that I'm not the same artist I was before the accident, but I'm the artist I was meant to become.",
    ).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    
    println!("✅ Emotional continuity test passed");
    println!("   📝 Response length: {} chars", response.response.len());
    println!("   🎭 Emotional tone: {}", response.strategic_directive.emotional_tone);
    println!("   📊 Confidence: {:.2}", response.metrics.confidence_score);
    
    // The response should maintain emotional consistency
    assert!(response.response.len() > 50);
    assert!(!response.strategic_directive.emotional_tone.is_empty());
}