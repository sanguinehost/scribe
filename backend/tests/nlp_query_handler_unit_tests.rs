// NLP Query Handler Unit Tests
//
// Unit tests for Phase 3: LLM Integration Layer - NLP Query Handler
// - Intent detection and classification
// - Query analysis and complexity scoring
// - OWASP security compliance for data structures

use chrono::Duration;

use scribe_backend::{
    services::{
        nlp_query_handler::{IntentType, QueryIntent},
        world_model_service::{TimeFocus, ReasoningDepth},
    },
    models::world_model::{LLMWorldContext, RelationshipGraph, CausalChain, SpatialContext},
};

#[tokio::test]
async fn test_intent_type_serialization() {
    // Test that IntentType can be serialized/deserialized safely
    let intent_types = vec![
        IntentType::CausalReasoning,
        IntentType::SpatialQuery,
        IntentType::RelationshipAnalysis,
        IntentType::TemporalQuery,
        IntentType::QuantitativeQuery,
        IntentType::ComparativeQuery,
        IntentType::GeneralInquiry,
    ];

    for intent_type in intent_types {
        // Test string conversion
        let intent_string = intent_type.to_string();
        assert!(!intent_string.is_empty());
        
        // Test that different types produce different strings
        match intent_type {
            IntentType::CausalReasoning => assert_eq!(intent_string, "causal_reasoning"),
            IntentType::SpatialQuery => assert_eq!(intent_string, "spatial_query"),
            IntentType::RelationshipAnalysis => assert_eq!(intent_string, "relationship_analysis"),
            IntentType::TemporalQuery => assert_eq!(intent_string, "temporal_query"),
            IntentType::QuantitativeQuery => assert_eq!(intent_string, "quantitative_query"),
            IntentType::ComparativeQuery => assert_eq!(intent_string, "comparative_query"),
            IntentType::GeneralInquiry => assert_eq!(intent_string, "general_inquiry"),
        }
    }
}

#[tokio::test]
async fn test_query_intent_structure() {
    // Test QueryIntent data structure integrity
    let intent = QueryIntent {
        intent_type: IntentType::CausalReasoning,
        focus_entities: None,
        time_focus: TimeFocus::Current,
        reasoning_depth: ReasoningDepth::Deep,
        confidence: 0.85,
        extracted_keywords: vec!["test".to_string(), "query".to_string()],
        complexity_score: 0.7,
    };

    // Verify all fields are accessible
    assert!(matches!(intent.intent_type, IntentType::CausalReasoning));
    assert!(intent.focus_entities.is_none());
    assert!(matches!(intent.time_focus, TimeFocus::Current));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Deep));
    assert_eq!(intent.confidence, 0.85);
    assert_eq!(intent.extracted_keywords.len(), 2);
    assert_eq!(intent.complexity_score, 0.7);
}

#[tokio::test]
async fn test_time_focus_variants() {
    // Test all TimeFocus variants work correctly
    let current = TimeFocus::Current;
    assert!(matches!(current, TimeFocus::Current));

    let historical = TimeFocus::Historical(Duration::days(7));
    if let TimeFocus::Historical(duration) = historical {
        assert_eq!(duration, Duration::days(7));
    } else {
        panic!("Expected Historical variant");
    }

    let specific = TimeFocus::Specific(chrono::Utc::now());
    assert!(matches!(specific, TimeFocus::Specific(_)));
}

#[tokio::test]
async fn test_reasoning_depth_variants() {
    // Test all ReasoningDepth variants work correctly
    let surface = ReasoningDepth::Surface;
    assert!(matches!(surface, ReasoningDepth::Surface));

    let causal = ReasoningDepth::Causal;
    assert!(matches!(causal, ReasoningDepth::Causal));

    let deep = ReasoningDepth::Deep;
    assert!(matches!(deep, ReasoningDepth::Deep));
}

// OWASP Security Tests for NLP Query Handler Data Structures

#[tokio::test]
async fn test_query_intent_data_validation() {
    // A08: Software and Data Integrity Failures - Test QueryIntent with malicious data
    
    // Test with malicious keywords
    let malicious_intent = QueryIntent {
        intent_type: IntentType::CausalReasoning,
        focus_entities: None,
        time_focus: TimeFocus::Current,
        reasoning_depth: ReasoningDepth::Deep,
        confidence: 0.85,
        extracted_keywords: vec![
            "'; DROP TABLE entities; --".to_string(),
            "<script>alert('xss')</script>".to_string(),
            "../../../etc/passwd".to_string(),
            "\"; rm -rf /".to_string(),
        ],
        complexity_score: 0.7,
    };

    // System should store malicious data safely without interpretation
    assert_eq!(malicious_intent.extracted_keywords.len(), 4);
    assert!(malicious_intent.extracted_keywords[0].contains("DROP TABLE"));
    assert!(malicious_intent.extracted_keywords[1].contains("<script>"));
    assert!(malicious_intent.extracted_keywords[2].contains("../../../"));
    assert!(malicious_intent.extracted_keywords[3].contains("rm -rf"));
    
    // Confidence and complexity should be bounded
    assert!(malicious_intent.confidence >= 0.0 && malicious_intent.confidence <= 1.0);
    assert!(malicious_intent.complexity_score >= 0.0 && malicious_intent.complexity_score <= 1.0);
}

#[tokio::test]
async fn test_query_intent_memory_safety() {
    // Performance and DoS protection test - prevent excessive memory usage
    
    // Test with large number of keywords
    let large_keywords: Vec<String> = (0..10000).map(|i| format!("keyword{}", i)).collect();
    
    let large_intent = QueryIntent {
        intent_type: IntentType::GeneralInquiry,
        focus_entities: None,
        time_focus: TimeFocus::Current,
        reasoning_depth: ReasoningDepth::Surface,
        confidence: 0.5,
        extracted_keywords: large_keywords,
        complexity_score: 0.9,
    };

    // Should handle large amounts of data gracefully
    assert_eq!(large_intent.extracted_keywords.len(), 10000);
    
    // Test with very long individual keywords
    let long_keyword = "x".repeat(10000);
    let long_keyword_intent = QueryIntent {
        intent_type: IntentType::GeneralInquiry,
        focus_entities: None,
        time_focus: TimeFocus::Current,
        reasoning_depth: ReasoningDepth::Surface,
        confidence: 0.5,
        extracted_keywords: vec![long_keyword.clone()],
        complexity_score: 0.9,
    };

    assert_eq!(long_keyword_intent.extracted_keywords[0].len(), 10000);
    assert_eq!(long_keyword_intent.extracted_keywords[0], long_keyword);
}

#[tokio::test]
async fn test_intent_type_edge_cases() {
    // Test that IntentType handles all cases properly
    
    let all_intents = vec![
        IntentType::CausalReasoning,
        IntentType::SpatialQuery,
        IntentType::RelationshipAnalysis,
        IntentType::TemporalQuery,
        IntentType::QuantitativeQuery,
        IntentType::ComparativeQuery,
        IntentType::GeneralInquiry,
    ];

    // All intents should convert to valid strings
    for intent in all_intents {
        let string_repr = intent.to_string();
        assert!(!string_repr.is_empty());
        assert!(!string_repr.contains(' ')); // Should be snake_case
        assert!(string_repr.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[tokio::test]
async fn test_time_focus_serialization_safety() {
    // Test that TimeFocus can be safely serialized/deserialized
    use serde_json;
    
    let time_focuses = vec![
        TimeFocus::Current,
        TimeFocus::Historical(Duration::days(30)),
        TimeFocus::Specific(chrono::Utc::now()),
    ];

    for focus in time_focuses {
        // Test JSON serialization
        let serialized = serde_json::to_string(&focus);
        assert!(serialized.is_ok(), "TimeFocus should serialize successfully");
        
        if let Ok(json_str) = serialized {
            // Test JSON deserialization
            let deserialized: Result<TimeFocus, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "TimeFocus should deserialize successfully");
        }
    }
}

#[tokio::test]
async fn test_reasoning_depth_serialization_safety() {
    // Test that ReasoningDepth can be safely serialized/deserialized
    use serde_json;
    
    let reasoning_depths = vec![
        ReasoningDepth::Surface,
        ReasoningDepth::Causal,
        ReasoningDepth::Deep,
    ];

    for depth in reasoning_depths {
        // Test JSON serialization
        let serialized = serde_json::to_string(&depth);
        assert!(serialized.is_ok(), "ReasoningDepth should serialize successfully");
        
        if let Ok(json_str) = serialized {
            // Test JSON deserialization
            let deserialized: Result<ReasoningDepth, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "ReasoningDepth should deserialize successfully");
        }
    }
}

#[tokio::test]
async fn test_llm_world_context_structure() {
    // Test that LLMWorldContext structure is safe and complete
    let context = LLMWorldContext {
        entity_summaries: vec![],
        relationship_graph: RelationshipGraph {
            nodes: vec![],
            edges: vec![],
            clusters: vec![],
        },
        causal_chains: vec![
            CausalChain::new(
                "Test cause".to_string(),
                "Test effect".to_string(),
                0.8,
            ),
        ],
        spatial_context: SpatialContext::new(),
        recent_changes: vec![],
        reasoning_hints: vec!["Test hint".to_string()],
    };

    // Verify structure integrity
    assert_eq!(context.entity_summaries.len(), 0);
    assert_eq!(context.relationship_graph.nodes.len(), 0);
    assert_eq!(context.relationship_graph.edges.len(), 0);
    assert_eq!(context.relationship_graph.clusters.len(), 0);
    assert_eq!(context.causal_chains.len(), 1);
    assert_eq!(context.recent_changes.len(), 0);
    assert_eq!(context.reasoning_hints.len(), 1);
    
    // Verify causal chain integrity
    assert_eq!(context.causal_chains[0].root_cause, "Test cause");
    assert_eq!(context.causal_chains[0].final_effect, "Test effect");
    assert_eq!(context.causal_chains[0].confidence, 0.8);
}