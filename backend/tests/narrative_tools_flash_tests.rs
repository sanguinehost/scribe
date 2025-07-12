//! Comprehensive test suite for Flash-powered Narrative Tools
//!
//! Tests all 7 narrative tools with Flash/Flash-Lite integration:
//! - AnalyzeTextSignificanceTool (Flash-Lite)
//! - CreateChronicleEventTool 
//! - CreateLorebookEntryTool
//! - ExtractTemporalEventsTool (Flash)
//! - ExtractWorldConceptsTool (Flash)
//! - SearchKnowledgeBaseTool (Flash-Lite + Flash)
//! - UpdateLorebookEntryTool (Flash)

use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    services::{
        agentic::{
            narrative_tools::*,
            tools::{ScribeTool, ToolError},
        },
        ChronicleService, LorebookService,
    },
    test_helpers::{spawn_app, TestDataGuard},
};

/// Test Flash-Lite powered significance analysis tool
#[tokio::test]
async fn test_analyze_text_significance_flash_lite() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = AnalyzeTextSignificanceTool::new(app.app_state.clone());

    // Test with significant narrative content
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "content": "The ancient dragon Valexar emerged from the Shadowmount, his crimson scales gleaming as he unleashed a torrent of flame upon the kingdom of Eldoria. Heroes fell before his might, and the very stones of the castle began to melt."
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Flash-Lite significance analysis should succeed");

    let response = result.unwrap();
    
    // Verify Flash-Lite returns structured JSON response
    assert!(response.get("is_significant").is_some(), "Response should include significance flag");
    assert!(response.get("confidence").is_some(), "Response should include confidence score");
    assert!(response.get("event_type").is_some(), "Response should include event type classification");
    assert!(response.get("summary").is_some(), "Response should include summary");
    assert!(response.get("reasoning").is_some(), "Response should include reasoning");
    assert!(response.get("extracted_entities").is_some(), "Response should include extracted entities");
    
    // Check that it's using Flash-Lite method
    let analysis_method = response.get("analysis_method")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(analysis_method, "Flash-Lite AI analysis", "Should use Flash-Lite analysis method");

    println!("Flash-Lite Analysis Result: {}", serde_json::to_string_pretty(&response).unwrap());
}

/// Test significance analysis with mundane content
#[tokio::test]
async fn test_analyze_text_significance_mundane_content() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = AnalyzeTextSignificanceTool::new(app.app_state.clone());

    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "content": "I checked my backpack. The rope was still there."
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Analysis should succeed even for mundane content");

    let response = result.unwrap();
    
    // Even mundane content should get structured analysis
    assert!(response.get("is_significant").is_some(), "Response should include significance assessment");
    assert!(response.get("confidence").is_some(), "Response should include confidence even for mundane content");
}

/// Test significance analysis with invalid parameters
#[tokio::test]
async fn test_analyze_text_significance_invalid_params() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = AnalyzeTextSignificanceTool::new(app.app_state.clone());

    // Test missing user_id
    let params_missing_user = json!({
        "content": "Some content"
    });

    let result = tool.execute(&params_missing_user).await;
    assert!(result.is_err(), "Should fail with missing user_id");
    
    if let Err(ToolError::InvalidParams(msg)) = result {
        assert!(msg.contains("user_id"), "Error should mention missing user_id");
    } else {
        panic!("Expected InvalidParams error");
    }

    // Test missing content
    let params_missing_content = json!({
        "user_id": Uuid::new_v4().to_string()
    });

    let result = tool.execute(&params_missing_content).await;
    assert!(result.is_err(), "Should fail with missing content");

    // Test invalid user_id format
    let params_invalid_uuid = json!({
        "user_id": "not-a-uuid",
        "content": "Some content"
    });

    let result = tool.execute(&params_invalid_uuid).await;
    assert!(result.is_err(), "Should fail with invalid UUID format");
}

/// Test Flash-powered temporal event extraction
#[tokio::test]
async fn test_extract_temporal_events_flash() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = ExtractTemporalEventsTool::new(app.app_state.clone());

    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "content": "At dawn, Sir Gareth mounted his horse and rode to the old tower. Upon arrival, he discovered the ancient tome hidden beneath the altar. As the sun set, he returned to the village with the precious artifact."
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Flash temporal event extraction should succeed");

    let response = result.unwrap();
    
    // Verify Flash returns structured event data
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include status message");
    assert!(response.get("events").is_some(), "Should include events array");
    
    if let Some(events) = response.get("events").and_then(|v| v.as_array()) {
        println!("Extracted {} temporal events", events.len());
        
        // If events were extracted, verify structure
        for event in events {
            assert!(event.get("event_type").is_some(), "Event should have type");
            assert!(event.get("summary").is_some(), "Event should have summary");
            assert!(event.get("actors").is_some(), "Event should have actors");
            assert!(event.get("temporal_context").is_some(), "Event should have temporal context");
        }
    }

    println!("Flash Temporal Events: {}", serde_json::to_string_pretty(&response).unwrap());
}

/// Test Flash-powered world concept extraction
#[tokio::test]
async fn test_extract_world_concepts_flash() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = ExtractWorldConceptsTool::new(app.app_state.clone());

    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "content": "The Crystal Citadel of Aethermoor stands as the last bastion of the Skyborne Empire. Its floating spires are powered by captured storm essence, and the Order of the Silver Wind guards its ancient secrets. The citadel houses the Great Library, where knowledge from across the realm is preserved in crystalline matrices."
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Flash world concept extraction should succeed");

    let response = result.unwrap();
    
    // Verify Flash returns structured concept data
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include status message");
    assert!(response.get("concepts").is_some(), "Should include concepts array");
    
    if let Some(concepts) = response.get("concepts").and_then(|v| v.as_array()) {
        println!("Extracted {} world concepts", concepts.len());
        
        // If concepts were extracted, verify structure
        for concept in concepts {
            assert!(concept.get("name").is_some(), "Concept should have name");
            assert!(concept.get("category").is_some(), "Concept should have category");
            assert!(concept.get("description").is_some(), "Concept should have description");
            assert!(concept.get("lorebook_entry").is_some(), "Concept should have lorebook entry data");
        }
    }

    println!("Flash World Concepts: {}", serde_json::to_string_pretty(&response).unwrap());
}

/// Test Flash-enhanced knowledge base search
#[tokio::test]
async fn test_search_knowledge_base_flash_enhanced() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let tool = SearchKnowledgeBaseTool::new(app.app_state.clone());

    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "query": "ancient dragons of the northern mountains"
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Flash-enhanced search should succeed");

    let response = result.unwrap();
    
    // Verify Flash-enhanced search returns structured results
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include status message");
    assert!(response.get("query_analysis").is_some(), "Should include query analysis");
    assert!(response.get("results").is_some(), "Should include search results");
    assert!(response.get("search_suggestions").is_some(), "Should include search suggestions");
    
    // Verify query analysis structure
    if let Some(analysis) = response.get("query_analysis") {
        assert!(analysis.get("intent").is_some(), "Analysis should include intent");
        assert!(analysis.get("entity_types").is_some(), "Analysis should include entity types");
        assert!(analysis.get("complexity").is_some(), "Analysis should include complexity");
    }

    // Verify results structure
    if let Some(results) = response.get("results").and_then(|v| v.as_array()) {
        println!("Found {} search results", results.len());
        
        for result in results {
            assert!(result.get("title").is_some(), "Result should have title");
            assert!(result.get("content").is_some(), "Result should have content");
            assert!(result.get("relevance_score").is_some(), "Result should have relevance score");
            assert!(result.get("source_type").is_some(), "Result should have source type");
        }
    }

    println!("Flash Search Results: {}", serde_json::to_string_pretty(&response).unwrap());
}

/// Test Flash-powered lorebook entry updating with semantic merging
#[tokio::test]
async fn test_update_lorebook_entry_flash_semantic_merge() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let lorebook_service = Arc::new(LorebookService::new(
        app.db_pool.clone(),
        app.app_state.encryption_service.clone(),
        app.app_state.qdrant_service.clone(),
    ));
    let tool = UpdateLorebookEntryTool::new(lorebook_service, app.app_state.clone());

    let entry_id = Uuid::new_v4();
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "entry_id": entry_id.to_string(),
        "new_information": "Recent expeditions have discovered that the Crystal Citadel can actually move through dimensions, not just float in the sky. This ability is activated during lunar eclipses when the storm essence reaches peak resonance."
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Flash semantic merge should succeed");

    let response = result.unwrap();
    
    // Verify Flash semantic merging returns structured update data
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include status message");
    assert!(response.get("merge_analysis").is_some(), "Should include merge analysis");
    assert!(response.get("updated_entry").is_some(), "Should include updated entry");
    assert!(response.get("merge_confidence").is_some(), "Should include merge confidence");
    
    // Verify merge analysis structure
    if let Some(analysis) = response.get("merge_analysis") {
        assert!(analysis.get("conflicts_found").is_some(), "Should track conflicts found");
        assert!(analysis.get("new_facts_added").is_some(), "Should track new facts added");
        assert!(analysis.get("contradictions_resolved").is_some(), "Should track resolved contradictions");
    }

    // Verify updated entry structure
    if let Some(entry) = response.get("updated_entry") {
        assert!(entry.get("title").is_some(), "Updated entry should have title");
        assert!(entry.get("content").is_some(), "Updated entry should have content");
        assert!(entry.get("summary").is_some(), "Updated entry should have summary");
        assert!(entry.get("version_notes").is_some(), "Updated entry should have version notes");
    }

    println!("Flash Semantic Merge: {}", serde_json::to_string_pretty(&response).unwrap());
}

/// Test create chronicle event tool with proper service integration
#[tokio::test]
async fn test_create_chronicle_event_tool() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let chronicle_service = Arc::new(ChronicleService::new(app.db_pool.clone()));
    let tool = CreateChronicleEventTool::new(chronicle_service, app.app_state.clone());

    let chronicle_id = Uuid::new_v4();
    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "chronicle_id": chronicle_id.to_string(),
        "event_type": "CHARACTER.STATE_CHANGE.INJURY",
        "action": "Wounded",
        "actors": [
            {
                "id": "Sir Gareth",
                "role": "PATIENT",
                "context": "Hero wounded in dragon battle"
            },
            {
                "id": "Valexar the Red",
                "role": "AGENT", 
                "context": "Ancient dragon opponent"
            }
        ],
        "summary": "Sir Gareth was severely wounded during his battle with the red dragon Valexar"
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Chronicle event creation should succeed");

    let response = result.unwrap();
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include success message");
}

/// Test create lorebook entry tool
#[tokio::test]
async fn test_create_lorebook_entry_tool() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let lorebook_service = Arc::new(LorebookService::new(
        app.db_pool.clone(),
        app.app_state.encryption_service.clone(),
        app.app_state.qdrant_service.clone(),
    ));
    let tool = CreateLorebookEntryTool::new(lorebook_service, app.app_state.clone());

    let params = json!({
        "user_id": Uuid::new_v4().to_string(),
        "name": "Crystal Citadel of Aethermoor",
        "description": "A magnificent floating fortress that serves as the capital of the Skyborne Empire, powered by captured storm essence and guarded by the Order of the Silver Wind.",
        "category": "LOCATION"
    });

    let result = tool.execute(&params).await;
    assert!(result.is_ok(), "Lorebook entry creation should succeed");

    let response = result.unwrap();
    assert_eq!(response.get("status").and_then(|v| v.as_str()).unwrap_or(""), "success");
    assert!(response.get("message").is_some(), "Should include success message");
}

/// Test tool input schema validation
#[tokio::test]
async fn test_tool_input_schemas() {
    let app = spawn_app(false, false, false).await;
    let app_state_mock = app.app_state.clone();
    
    // Test all tools have proper schemas
    let significance_tool = AnalyzeTextSignificanceTool::new(app_state_mock.clone());
    let extract_events_tool = ExtractTemporalEventsTool::new(app_state_mock.clone());
    let extract_concepts_tool = ExtractWorldConceptsTool::new(app_state_mock.clone());
    let search_tool = SearchKnowledgeBaseTool::new(app_state_mock.clone());
    
    // All tools should have proper schemas
    let significance_schema = significance_tool.input_schema();
    assert!(significance_schema.get("type").is_some(), "Significance tool should have schema type");
    assert!(significance_schema.get("properties").is_some(), "Significance tool should have properties");
    assert!(significance_schema.get("required").is_some(), "Significance tool should have required fields");
    
    let events_schema = extract_events_tool.input_schema();
    assert!(events_schema.get("type").is_some(), "Events tool should have schema type");
    
    let concepts_schema = extract_concepts_tool.input_schema();
    assert!(concepts_schema.get("type").is_some(), "Concepts tool should have schema type");
    
    let search_schema = search_tool.input_schema();
    assert!(search_schema.get("type").is_some(), "Search tool should have schema type");
}

/// Test tool names and descriptions
#[tokio::test]
async fn test_tool_metadata() {
    let app = spawn_app(false, false, false).await;
    let app_state_mock = app.app_state.clone();
    
    let significance_tool = AnalyzeTextSignificanceTool::new(app_state_mock.clone());
    assert_eq!(significance_tool.name(), "analyze_text_significance");
    assert!(significance_tool.description().contains("Flash-Lite"), "Description should mention Flash-Lite");
    
    let extract_events_tool = ExtractTemporalEventsTool::new(app_state_mock.clone());
    assert_eq!(extract_events_tool.name(), "extract_temporal_events");
    assert!(extract_events_tool.description().contains("Flash"), "Description should mention Flash");
    
    let extract_concepts_tool = ExtractWorldConceptsTool::new(app_state_mock.clone());
    assert_eq!(extract_concepts_tool.name(), "extract_world_concepts");
    assert!(extract_concepts_tool.description().contains("Flash"), "Description should mention Flash");
    
    let search_tool = SearchKnowledgeBaseTool::new(app_state_mock.clone());
    assert_eq!(search_tool.name(), "search_knowledge_base");
    assert!(search_tool.description().contains("Flash"), "Description should mention Flash");
}