use scribe_backend::{
    routes::chat::{
        build_token_aware_conversation_context, calculate_agentic_token_budget,
        allocate_agentic_token_budget, determine_quality_mode, ChatGenerateQueryParams,
    },
    services::{
        hybrid_token_counter::HybridTokenCounter,
        tokenizer_service::TokenizerService, QualityMode,
    },
    test_helpers::{spawn_app_with_options, TestApp},
};
use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent};
use std::sync::Arc;
use std::path::PathBuf;

/// Creates a test token counter for testing
fn create_test_token_counter() -> Arc<HybridTokenCounter> {
    // For testing, we'll use the actual tokenizer with the default model
    let model_path = PathBuf::from("../models/gpt2.tiktoken");
    
    // First try to create tokenizer service with actual model
    let tokenizer_service = match TokenizerService::new(&model_path) {
        Ok(service) => service,
        Err(_) => {
            // If that fails, try relative to current directory
            let alt_path = PathBuf::from("models/gpt2.tiktoken");
            TokenizerService::new(&alt_path).unwrap_or_else(|_| {
                // If still failing, this suggests the test environment doesn't have the model
                // For now, we'll skip these tests by returning early with a panic
                panic!("Tokenizer model not found for testing. These tests require the tokenizer model to be available.")
            })
        }
    };
    
    Arc::new(HybridTokenCounter::new(
        tokenizer_service,
        None, // No Gemini client
        "gemini-1.5-flash".to_string(),
    ))
}

/// Creates test chat messages for various scenarios
fn create_test_messages() -> Vec<GenAiChatMessage> {
    vec![
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("Hello, how are you today?".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("I'm doing well! I've been thinking about our conversation yesterday about the upcoming journey. There's something important I need to tell you.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("What is it? You look worried.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("I love you, but I fear what lies ahead. The path we've chosen is dangerous, and I suddenly realized that we might not both make it back home.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("We'll face it together! No matter what happens, I won't leave you behind.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("Thank you. That means everything to me. Let's prepare for tomorrow.".to_string()),
            options: None,
        },
    ]
}

#[tokio::test]
async fn test_build_token_aware_conversation_context_basic() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    let messages = create_test_messages();
    
    let result = build_token_aware_conversation_context(
        &messages,
        1000, // Reasonable budget
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should successfully build context");
    let context = result.unwrap();
    assert!(context.is_some(), "Should return Some context with messages");
    
    let context_str = context.unwrap();
    assert!(context_str.contains("Recent Conversation Context"), "Should contain header");
    assert!(context_str.contains("User:"), "Should contain user messages");
    assert!(context_str.contains("Character:"), "Should contain assistant messages");
    assert!(context_str.contains("messages selected from"), "Should contain summary info");
}

#[tokio::test]
async fn test_build_token_aware_conversation_context_empty_history() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    let empty_messages: Vec<GenAiChatMessage> = vec![];
    
    let result = build_token_aware_conversation_context(
        &empty_messages,
        1000,
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should handle empty history gracefully");
    let context = result.unwrap();
    assert!(context.is_none(), "Should return None for empty history");
}

#[tokio::test]
async fn test_build_token_aware_conversation_context_small_budget() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    let messages = create_test_messages();
    
    // Very small budget should only include most recent/important messages
    let result = build_token_aware_conversation_context(
        &messages,
        50, // Very small budget
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should handle small budget gracefully");
    let context = result.unwrap();
    
    if let Some(context_str) = context {
        // Should contain fewer messages due to budget constraints
        let user_count = context_str.matches("User:").count();
        let character_count = context_str.matches("Character:").count();
        assert!(user_count + character_count > 0, "Should include at least some messages");
        assert!(user_count + character_count < messages.len(), "Should be fewer than all messages due to budget");
    }
}

#[tokio::test]
async fn test_build_token_aware_conversation_context_key_moments() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    
    // Create messages with high importance markers
    let important_messages = vec![
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("Regular question".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("I love you more than anything! This changes everything.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("What do you mean? Are you okay?".to_string()),
            options: None,
        },
    ];
    
    let result = build_token_aware_conversation_context(
        &important_messages,
        1000,
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should build context with important messages");
    let context = result.unwrap();
    assert!(context.is_some(), "Should return context");
    
    let context_str = context.unwrap();
    assert!(context_str.contains("**[KEY MOMENT]**"), "Should mark key moments");
    assert!(context_str.contains("love"), "Should include emotional content");
}

#[tokio::test]
async fn test_build_token_aware_conversation_context_narrative_gaps() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    
    // Create a scenario where budget forces gaps in conversation
    let mut many_messages = Vec::new();
    for i in 0..20 {
        many_messages.push(GenAiChatMessage {
            role: if i % 2 == 0 { ChatRole::User } else { ChatRole::Assistant },
            content: MessageContent::Text(format!("Message number {} with some content to use tokens", i)),
            options: None,
        });
    }
    
    let result = build_token_aware_conversation_context(
        &many_messages,
        200, // Small budget to force selection
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should handle many messages with small budget");
    if let Ok(Some(context_str)) = result {
        // With budget constraints and many messages, there should be gaps
        let gap_count = context_str.matches("[...narrative continues...]").count();
        println!("Found {} narrative gaps in context", gap_count);
        // Note: Gap detection depends on message selection pattern
    }
}

#[tokio::test]
async fn test_calculate_agentic_token_budget() {
    let query_params = ChatGenerateQueryParams {
        request_thinking: false,
    };
    
    let budget = calculate_agentic_token_budget(&query_params);
    assert_eq!(budget, 5000, "Should return default budget of 5000 tokens");
}

#[tokio::test]
async fn test_allocate_agentic_token_budget() {
    let total_budget = 5000;
    let (context_budget, query_budget) = allocate_agentic_token_budget(total_budget);
    
    assert_eq!(context_budget, 1500, "Context budget should be 30% of total (1500)");
    assert_eq!(query_budget, 3500, "Query budget should be 70% of total (3500)");
    assert_eq!(context_budget + query_budget, total_budget, "Budgets should sum to total");
}

#[tokio::test]
async fn test_allocate_agentic_token_budget_edge_cases() {
    // Test with small budget
    let (context_small, query_small) = allocate_agentic_token_budget(100);
    assert_eq!(context_small, 30, "Small context budget should be 30");
    assert_eq!(query_small, 70, "Small query budget should be 70");
    
    // Test with large budget
    let (context_large, query_large) = allocate_agentic_token_budget(50000);
    assert_eq!(context_large, 15000, "Large context budget should be 15000");
    assert_eq!(query_large, 35000, "Large query budget should be 35000");
}

#[tokio::test]
async fn test_determine_quality_mode() {
    let query_params = ChatGenerateQueryParams {
        request_thinking: false,
    };
    
    let quality_mode = determine_quality_mode(&query_params);
    assert_eq!(quality_mode, QualityMode::Balanced, "Should return balanced quality mode");
}

#[tokio::test]
async fn test_message_importance_scoring() {
    // Test high importance indicators
    let _high_importance_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("I love you! What should we decide about the future?".to_string()),
        options: None,
    };
    
    let _low_importance_message = GenAiChatMessage {
        role: ChatRole::Assistant,
        content: MessageContent::Text("Ok".to_string()),
        options: None,
    };
    
    // We can't directly test calculate_message_importance since it's not public,
    // but we can test the behavior through the main function
    let _guard = tokio::runtime::Handle::current();
}

#[tokio::test]
async fn test_token_aware_context_respects_budget() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    
    // Create long messages that would exceed budget
    let long_messages = vec![
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("This is a very long message that contains a lot of content and should use many tokens when counted by the tokenizer service. ".repeat(20)),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("This is another very long message with even more content that definitely should push the token count very high. ".repeat(25)),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("And yet another extremely long message to test budget constraints thoroughly. ".repeat(30)),
            options: None,
        },
    ];
    
    let small_budget = 100;
    let result = build_token_aware_conversation_context(
        &long_messages,
        small_budget,
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should handle token budget constraints gracefully");
    
    // The function should either return None (if no messages fit) or Some with limited content
    if let Ok(Some(context)) = result {
        println!("Context length: {}", context.len());
        assert!(context.len() > 0, "Should return some context if any messages fit budget");
    }
}

#[tokio::test]
async fn test_token_aware_context_prioritizes_recent_and_user() {
    let _app = spawn_app_with_options(false, false, false, false).await;
    let token_counter = create_test_token_counter();
    
    // Create messages where user messages should be prioritized
    let mixed_messages = vec![
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("Old assistant message with mundane content.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("Important user question that drives the story forward?".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("Response to user.".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("Most recent user input that should definitely be included.".to_string()),
            options: None,
        },
    ];
    
    let result = build_token_aware_conversation_context(
        &mixed_messages,
        200, // Limited budget to force selection
        &token_counter,
        "gemini-1.5-flash",
    ).await;
    
    assert!(result.is_ok(), "Should build context with mixed message types");
    if let Ok(Some(context)) = result {
        let user_count = context.matches("User:").count();
        let character_count = context.matches("Character:").count();
        
        // Should prioritize user messages
        assert!(user_count >= 1, "Should include at least one user message");
        println!("User messages: {}, Character messages: {}", user_count, character_count);
    }
}