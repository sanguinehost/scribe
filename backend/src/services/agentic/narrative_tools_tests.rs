#[cfg(test)]
mod tests {
    use super::super::narrative_tools::*;
    use super::super::tools::{ScribeTool, ToolParams};
    use serde_json::json;
    use uuid::Uuid;
    use std::sync::Arc;
    use crate::test_helpers::MockAiClient;

    #[tokio::test]
    async fn test_analyze_text_significance_tool() {
        // Arrange
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(json!({
            "is_significant": true,
            "confidence": 0.9,
            "reason": "Dragon attack is a significant combat event",
            "suggested_categories": ["chronicle_events"]
        }).to_string()));
        let tool = AnalyzeTextSignificanceTool::new(mock_ai_client);
        
        let params = json!({
            "messages": [
                {"role": "user", "content": "The dragon attacked the village"},
                {"role": "assistant", "content": "The villagers fled in terror as the ancient red dragon descended"}
            ]
        });

        // Act
        let result = tool.execute(&params).await;

        // Assert
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output["is_significant"], true);
        assert!(output["confidence"].as_f64().unwrap() > 0.5);
        assert!(output["suggested_categories"].as_array().unwrap().len() > 0);
    }

    // NOTE: test_extract_temporal_events_tool removed - tool was deleted as it only returned mock data

    // NOTE: test_extract_world_concepts_tool removed - tool was deleted as it only returned mock data

    #[tokio::test] 
    async fn test_tool_composability() {
        // This test demonstrates how tools can be composed in the workflow
        
        // Step 1: Analyze significance
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(json!({
            "is_significant": true,
            "confidence": 0.85,
            "reason": "Discovery of ancient artifact is narratively significant",
            "suggested_categories": ["chronicle_events", "lorebook_entries"],
            "events": [
                {
                    "event_type": "DISCOVERY",
                    "summary": "Ancient artifact discovered",
                    "details": "The party found an ancient orb"
                }
            ],
            "concepts": [
                {
                    "name": "Orb of Eternal Night",
                    "category": "magical_item",
                    "content": "Ancient magical artifact with dark powers",
                    "keywords": "orb, artifact, dark magic"
                }
            ]
        }).to_string()));
        let significance_tool = AnalyzeTextSignificanceTool::new(mock_ai_client.clone());
        let messages = json!({
            "messages": [
                {"role": "user", "content": "The party discovered an ancient artifact"},
                {"role": "assistant", "content": "The Orb of Eternal Night pulses with dark energy"}
            ]
        });
        
        let significance_result = significance_tool.execute(&messages).await.unwrap();
        assert_eq!(significance_result["is_significant"], true);
        
        // Step 2: Extract based on significance
        if significance_result["is_significant"].as_bool().unwrap() {
            let categories = significance_result["suggested_categories"].as_array().unwrap();
            
            // NOTE: Step 2 extraction tools removed - were only returning mock data
            // In the real single-agent system, context_enrichment_agent handles this directly
        }
    }

    #[tokio::test]
    async fn test_tool_input_validation() {
        // Test that tools properly validate input parameters
        let mock_ai_client = Arc::new(MockAiClient::new());
        let tool = AnalyzeTextSignificanceTool::new(mock_ai_client);
        
        // Missing required field
        let invalid_params = json!({
            // Missing messages field
        });
        
        let result = tool.execute(&invalid_params).await;
        assert!(result.is_err());
        
        // Test with valid params
        let valid_params = json!({
            "messages": []
        });
        
        let result = tool.execute(&valid_params).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_atomic_workflow() {
        // This test demonstrates the full atomic workflow
        let messages = [
            json!({"role": "user", "content": "We entered the dungeon"}),
            json!({"role": "assistant", "content": "The ancient dungeon of Mor'dun awaits, filled with traps and treasures"}),
        ];
        
        // Step 1: Triage
        let mock_ai_client = Arc::new(MockAiClient::new());
        let triage_tool = AnalyzeTextSignificanceTool::new(mock_ai_client.clone());
        let triage_result = triage_tool.execute(&json!({"messages": messages})).await.unwrap();
        
        if !triage_result["is_significant"].as_bool().unwrap() {
            return; // Not significant, stop processing
        }
        
        // Step 2: Knowledge retrieval would happen here with SearchKnowledgeBaseTool
        // (currently has placeholder implementation)
        
        // Step 3: NOTE - Extraction tools removed as they only returned mock data
        // In the real system, context_enrichment_agent handles extraction directly
        
        // Step 4: The agent would call CreateChronicleEventTool or CreateLorebookEntryTool
        // based on its reasoning about the conversation content
    }
}