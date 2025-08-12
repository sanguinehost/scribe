#![cfg(test)]

use scribe_backend::models::agent_context_analysis::{NewAgentContextAnalysis, AnalysisType};
use uuid::Uuid;
use secrecy::SecretBox;

#[test]
fn test_new_agent_context_analysis_with_message_id() {
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32]));

    // Test creating a new analysis with message_id
    let analysis = NewAgentContextAnalysis::new_encrypted(
        session_id,
        user_id,
        AnalysisType::PreProcessing,
        "test reasoning",
        &serde_json::json!([]),
        &serde_json::json!({"steps": []}),
        "test context",
        "test summary",
        100,
        50,
        "gemini-2.5-flash-lite",
        &session_dek,
        message_id,
    ).expect("Should create analysis");

    assert_eq!(analysis.chat_session_id, session_id);
    assert_eq!(analysis.user_id, user_id);
    assert_eq!(analysis.analysis_type, "pre_processing");
    assert_eq!(analysis.message_id, message_id);
    assert!(analysis.agent_reasoning.is_some());
    assert!(analysis.agent_reasoning_nonce.is_some());
    assert!(analysis.execution_log.is_some());
    assert!(analysis.execution_log_nonce.is_some());
}

#[test]
fn test_new_agent_context_analysis_with_required_message_id() {
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32]));

    // Test creating a new analysis with required message_id
    let analysis = NewAgentContextAnalysis::new_encrypted(
        session_id,
        user_id,
        AnalysisType::PostProcessing,
        "test reasoning",
        &serde_json::json!([]),
        &serde_json::json!({"steps": []}),
        "test context",
        "test summary",
        100,
        50,
        "gemini-2.5-flash-lite",
        &session_dek,
        message_id, // Required message_id
    ).expect("Should create analysis");

    assert_eq!(analysis.chat_session_id, session_id);
    assert_eq!(analysis.user_id, user_id);
    assert_eq!(analysis.analysis_type, "post_processing");
    assert_eq!(analysis.message_id, message_id);
    assert!(analysis.agent_reasoning.is_some());
    assert!(analysis.agent_reasoning_nonce.is_some());
}

#[test]
fn test_analysis_type_conversion() {
    // Test conversion from AnalysisType enum to string
    let pre_processing = AnalysisType::PreProcessing;
    let post_processing = AnalysisType::PostProcessing;

    assert_eq!(pre_processing.to_string(), "pre_processing");
    assert_eq!(post_processing.to_string(), "post_processing");
}

#[test]
fn test_message_id_field_is_required() {
    // This test verifies that the message_id field is required
    // and each analysis is linked to a specific message
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32]));

    // Create multiple analyses with different message_id values
    let analyses = vec![
        NewAgentContextAnalysis::new_encrypted(
            session_id,
            user_id,
            AnalysisType::PreProcessing,
            "reasoning 1",
            &serde_json::json!([]),
            &serde_json::json!({}),
            "context 1",
            "summary 1",
            10,
            5,
            "model",
            &session_dek,
            Uuid::new_v4(),
        ).expect("Should create analysis 1"),
        NewAgentContextAnalysis::new_encrypted(
            session_id,
            user_id,
            AnalysisType::PostProcessing,
            "reasoning 2",
            &serde_json::json!([]),
            &serde_json::json!({}),
            "context 2",
            "summary 2",
            20,
            10,
            "model",
            &session_dek,
            Uuid::new_v4(),
        ).expect("Should create analysis 2"),
        NewAgentContextAnalysis::new_encrypted(
            session_id,
            user_id,
            AnalysisType::PreProcessing,
            "reasoning 3",
            &serde_json::json!([]),
            &serde_json::json!({}),
            "context 3",
            "summary 3",
            30,
            15,
            "model",
            &session_dek,
            Uuid::new_v4(),
        ).expect("Should create analysis 3"),
    ];

    // Verify each analysis has a message_id (all are required now)
    // Each analysis has a unique message_id
    assert_ne!(analyses[0].message_id, analyses[1].message_id);
    assert_ne!(analyses[1].message_id, analyses[2].message_id);
    assert_ne!(analyses[0].message_id, analyses[2].message_id);

    // Verify all analyses belong to the same session
    for analysis in &analyses {
        assert_eq!(analysis.chat_session_id, session_id);
        assert_eq!(analysis.user_id, user_id);
    }
}