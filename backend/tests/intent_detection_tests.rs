use scribe_backend::services::intent_detection_service::*;
use scribe_backend::test_helpers::MockAiClient;
use scribe_backend::errors::AppError;
use std::sync::Arc;

#[tokio::test]
async fn test_causal_analysis_intent() {
    let response_json = r#"{
        "intent_type": "CausalAnalysis",
        "focus_entities": [{"name": "Luke", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Recent", "duration_hours": 24},
        "reasoning_depth": "Causal",
        "context_priorities": ["CausalChains", "Entities", "RecentEvents"],
        "confidence": 0.9
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("What caused Luke to leave?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::CausalAnalysis));
    assert_eq!(intent.focus_entities.len(), 1);
    assert_eq!(intent.focus_entities[0].name, "Luke");
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Causal));
    assert!(intent.confidence > 0.8);
}

#[tokio::test]
async fn test_spatial_analysis_intent() {
    let response_json = r#"{
        "intent_type": "SpatialAnalysis",
        "focus_entities": [],
        "time_scope": {"type": "Current"},
        "spatial_scope": {"location_name": "cantina", "include_contained": true},
        "reasoning_depth": "Surface",
        "context_priorities": ["SpatialContext", "Entities"],
        "confidence": 0.85
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("Who is in the cantina right now?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::SpatialAnalysis));
    assert!(intent.spatial_scope.is_some());
    assert!(matches!(intent.time_scope, TimeScope::Current));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Surface));
}

#[tokio::test]
async fn test_relationship_query_intent() {
    let response_json = r#"{
        "intent_type": "RelationshipQuery",
        "focus_entities": [
            {"name": "Vader", "priority": 1.0, "required": true},
            {"name": "Obi-Wan", "priority": 1.0, "required": true}
        ],
        "time_scope": {"type": "AllTime"},
        "reasoning_depth": "Analytical",
        "context_priorities": ["Relationships", "Entities", "RecentEvents"],
        "confidence": 0.92
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("How do Vader and Obi-Wan feel about each other?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::RelationshipQuery));
    assert_eq!(intent.focus_entities.len(), 2);
    assert!(intent.focus_entities.iter().any(|e| e.name == "Vader"));
    assert!(intent.focus_entities.iter().any(|e| e.name == "Obi-Wan"));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Analytical));
}

#[tokio::test]
async fn test_temporal_analysis_intent() {
    let response_json = r#"{
        "intent_type": "TemporalAnalysis",
        "focus_entities": [{"name": "Empire", "priority": 0.8, "required": false}],
        "time_scope": {"type": "Range", "start_time": "2023-01-01T00:00:00Z", "end_time": "2023-12-31T23:59:59Z"},
        "reasoning_depth": "Deep",
        "context_priorities": ["TemporalState", "RecentEvents", "Entities"],
        "confidence": 0.88
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("What happened to the Empire between January and December 2023?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::TemporalAnalysis));
    assert!(matches!(intent.time_scope, TimeScope::Range(_, _)));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Deep));
}

#[tokio::test]
async fn test_predictive_query_intent() {
    let response_json = r#"{
        "intent_type": "PredictiveQuery",
        "focus_entities": [{"name": "Rebellion", "priority": 0.9, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Deep",
        "context_priorities": ["CausalChains", "Relationships", "Entities"],
        "confidence": 0.75
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("What might happen if the Rebellion attacks the Death Star?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::PredictiveQuery));
    assert!(intent.focus_entities.iter().any(|e| e.name == "Rebellion"));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Deep));
}

#[tokio::test]
async fn test_narrative_generation_intent() {
    let response_json = r#"{
        "intent_type": "NarrativeGeneration",
        "focus_entities": [],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Analytical",
        "context_priorities": ["Entities", "Relationships", "RecentEvents"],
        "confidence": 0.95
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("Continue the story from where we left off.", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::NarrativeGeneration));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Analytical));
}

#[tokio::test]
async fn test_comparison_query_intent() {
    let response_json = r#"{
        "intent_type": "ComparisonQuery",
        "focus_entities": [
            {"name": "Jedi", "priority": 1.0, "required": true},
            {"name": "Sith", "priority": 1.0, "required": true}
        ],
        "time_scope": {"type": "AllTime"},
        "reasoning_depth": "Analytical",
        "context_priorities": ["Entities", "Relationships", "RecentEvents"],
        "confidence": 0.87
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("How do the Jedi and Sith differ in their philosophy?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::ComparisonQuery));
    assert_eq!(intent.focus_entities.len(), 2);
    assert!(intent.focus_entities.iter().any(|e| e.name == "Jedi"));
    assert!(intent.focus_entities.iter().any(|e| e.name == "Sith"));
}

#[tokio::test]
async fn test_state_inquiry_intent() {
    let response_json = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "Princess Leia", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities", "SpatialContext"],
        "confidence": 0.93
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("Where is Princess Leia right now?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::StateInquiry));
    assert_eq!(intent.focus_entities.len(), 1);
    assert_eq!(intent.focus_entities[0].name, "Princess Leia");
    assert!(matches!(intent.time_scope, TimeScope::Current));
}

#[tokio::test]
async fn test_intent_with_conversation_context() {
    let response_json = r#"{
        "intent_type": "CausalAnalysis",
        "focus_entities": [{"name": "Luke", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Recent", "duration_hours": 48},
        "reasoning_depth": "Causal",
        "context_priorities": ["CausalChains", "Entities"],
        "confidence": 0.91
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let conversation_context = "We were discussing Luke's journey from Tatooine to becoming a Jedi.";
    let intent = service.detect_intent("What made him take that path?", Some(conversation_context)).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::CausalAnalysis));
    assert!(intent.confidence > 0.9);
}

#[tokio::test]
async fn test_invalid_json_response_handling() {
    let mock_client = MockAiClient::new_with_response("This is not valid JSON".to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let result = service.detect_intent("What caused Luke to leave?", None).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to parse intent response"));
}

#[tokio::test]
async fn test_complex_multi_entity_query() {
    let response_json = r#"{
        "intent_type": "RelationshipQuery",
        "focus_entities": [
            {"name": "Luke", "priority": 1.0, "required": true},
            {"name": "Vader", "priority": 0.9, "required": true},
            {"name": "Emperor", "priority": 0.7, "required": false}
        ],
        "time_scope": {"type": "Recent", "duration_hours": 72},
        "reasoning_depth": "Deep",
        "context_priorities": ["Relationships", "CausalChains", "Entities", "RecentEvents"],
        "confidence": 0.86
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = IntentDetectionService::new(Arc::new(mock_client));
    let intent = service.detect_intent("How did Luke's confrontation with Vader affect his relationship with the Emperor?", None).await.unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::RelationshipQuery));
    assert_eq!(intent.focus_entities.len(), 3);
    assert!(intent.focus_entities.iter().any(|e| e.name == "Luke" && e.required));
    assert!(intent.focus_entities.iter().any(|e| e.name == "Vader" && e.required));
    assert!(intent.focus_entities.iter().any(|e| e.name == "Emperor" && !e.required));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Deep));
}