#[cfg(test)]
mod tests {
    use super::super::narrative_tools::*;
    use super::super::tools::{ScribeTool, ToolParams};
    use serde_json::json;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_analyze_text_significance_tool() {
        // Arrange
        let tool = AnalyzeTextSignificanceTool::new();
        
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

    #[tokio::test]
    async fn test_extract_temporal_events_tool() {
        // Arrange
        let tool = ExtractTemporalEventsTool::new();
        
        let params = json!({
            "messages": [
                {"role": "user", "content": "We defeated the goblin horde"},
                {"role": "assistant", "content": "The battle was won, but at great cost"}
            ]
        });

        // Act
        let result = tool.execute(&params).await;

        // Assert
        assert!(result.is_ok());
        let output = result.unwrap();
        let events = output["events"].as_array().unwrap();
        assert!(!events.is_empty());
        
        // Check first event structure
        let first_event = &events[0];
        assert!(first_event["event_type"].is_string());
        assert!(first_event["summary"].is_string());
    }

    #[tokio::test]
    async fn test_extract_world_concepts_tool() {
        // Arrange
        let tool = ExtractWorldConceptsTool::new();
        
        let params = json!({
            "messages": [
                {"role": "user", "content": "Tell me about the Archmage Zephyr"},
                {"role": "assistant", "content": "Archmage Zephyr is the head of the Crystal Tower, master of elemental magic"}
            ]
        });

        // Act
        let result = tool.execute(&params).await;

        // Assert
        assert!(result.is_ok());
        let output = result.unwrap();
        let concepts = output["concepts"].as_array().unwrap();
        assert!(!concepts.is_empty());
        
        // Check first concept structure
        let first_concept = &concepts[0];
        assert!(first_concept["name"].is_string());
        assert!(first_concept["category"].is_string());
        assert!(first_concept["content"].is_string());
        assert!(first_concept["keywords"].is_string());
    }

    #[tokio::test] 
    async fn test_tool_composability() {
        // This test demonstrates how tools can be composed in the workflow
        
        // Step 1: Analyze significance
        let significance_tool = AnalyzeTextSignificanceTool::new();
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
            
            if categories.iter().any(|c| c.as_str() == Some("chronicle_events")) {
                let events_tool = ExtractTemporalEventsTool::new();
                let events_result = events_tool.execute(&messages).await.unwrap();
                assert!(!events_result["events"].as_array().unwrap().is_empty());
            }
            
            if categories.iter().any(|c| c.as_str() == Some("lorebook_entries")) {
                let concepts_tool = ExtractWorldConceptsTool::new();
                let concepts_result = concepts_tool.execute(&messages).await.unwrap();
                assert!(!concepts_result["concepts"].as_array().unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_tool_input_validation() {
        // Test that tools properly validate input parameters
        let tool = AnalyzeTextSignificanceTool::new();
        
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
        let triage_tool = AnalyzeTextSignificanceTool::new();
        let triage_result = triage_tool.execute(&json!({"messages": messages})).await.unwrap();
        
        if !triage_result["is_significant"].as_bool().unwrap() {
            return; // Not significant, stop processing
        }
        
        // Step 2: Knowledge retrieval would happen here with SearchKnowledgeBaseTool
        // (currently has placeholder implementation)
        
        // Step 3: Extract information (no DB operations)
        let extract_events_tool = ExtractTemporalEventsTool::new();
        let extract_concepts_tool = ExtractWorldConceptsTool::new();
        
        let events = extract_events_tool.execute(&json!({"messages": messages})).await.unwrap();
        let concepts = extract_concepts_tool.execute(&json!({"messages": messages})).await.unwrap();
        
        // Step 4: Agent would decide what to create based on extracted data
        // This demonstrates the atomic nature - extraction is separate from creation
        assert!(!events["events"].as_array().unwrap().is_empty());
        assert!(!concepts["concepts"].as_array().unwrap().is_empty());
        
        // The agent would then call CreateChronicleEventTool or CreateLorebookEntryTool
        // based on its reasoning about the extracted data
    }
}