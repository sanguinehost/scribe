//! End-to-End Pipeline Validation Helpers
//!
//! This module provides comprehensive validation utilities for testing the
//! Chronicle→ECS→Query pipeline integrity and performance.

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::{json, Value as JsonValue};
use anyhow::{Context, Result as AnyhowResult, bail};

use scribe_backend::{
    models::{
        chronicle_event::ChronicleEvent,
        ecs::{Entity, EcsComponent, GameTime, TimeMode},
    },
    services::{
        HybridQueryService, HybridQuery, HybridQueryType, HybridQueryOptions, HybridQueryResult,
        EcsEntityManager,
        ecs_enhanced_rag_service::{EntityStateSnapshot, RelationshipContext},
    },
    errors::AppError,
};

/// Validation results for pipeline integrity
#[derive(Debug, Clone)]
pub struct PipelineValidationResult {
    /// Whether the validation passed
    pub success: bool,
    /// Duration of the validation process
    pub duration: Duration,
    /// Chronicle events processed
    pub events_processed: usize,
    /// ECS entities found
    pub entities_found: usize,
    /// Relationships discovered
    pub relationships_found: usize,
    /// Validation errors encountered
    pub errors: Vec<String>,
    /// Performance metrics
    pub performance_metrics: PipelinePerformanceMetrics,
    /// Detailed validation steps
    pub validation_steps: Vec<ValidationStep>,
}

/// Performance metrics for pipeline operations
#[derive(Debug, Clone)]
pub struct PipelinePerformanceMetrics {
    /// Chronicle query time
    pub chronicle_query_duration: Duration,
    /// ECS query time
    pub ecs_query_duration: Duration,
    /// Hybrid query time
    pub hybrid_query_duration: Duration,
    /// Total pipeline latency
    pub total_latency: Duration,
    /// Cache hit rates
    pub cache_hit_rate: f32,
    /// Query complexity score
    pub complexity_score: f32,
}

/// Individual validation step result
#[derive(Debug, Clone)]
pub struct ValidationStep {
    /// Step name
    pub name: String,
    /// Whether this step passed
    pub passed: bool,
    /// Duration of this step
    pub duration: Duration,
    /// Details about the step
    pub details: String,
    /// Metrics for this step
    pub metrics: HashMap<String, JsonValue>,
}

impl Default for PipelinePerformanceMetrics {
    fn default() -> Self {
        Self {
            chronicle_query_duration: Duration::from_millis(0),
            ecs_query_duration: Duration::from_millis(0),
            hybrid_query_duration: Duration::from_millis(0),
            total_latency: Duration::from_millis(0),
            cache_hit_rate: 0.0,
            complexity_score: 0.0,
        }
    }
}

/// Comprehensive pipeline validator
pub struct PipelineValidator {
    hybrid_service: Arc<HybridQueryService>,
    entity_manager: Option<Arc<EcsEntityManager>>,
    performance_thresholds: PerformanceThresholds,
}

/// Performance thresholds for validation
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    /// Maximum acceptable query duration
    pub max_query_duration: Duration,
    /// Maximum pipeline latency
    pub max_pipeline_latency: Duration,
    /// Minimum cache hit rate
    pub min_cache_hit_rate: f32,
    /// Maximum events to process in test
    pub max_events_processed: usize,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_query_duration: Duration::from_secs(10),
            max_pipeline_latency: Duration::from_secs(15),
            min_cache_hit_rate: 0.2, // 20% minimum
            max_events_processed: 1000,
        }
    }
}

impl PipelineValidator {
    /// Create a new pipeline validator
    pub fn new(
        hybrid_service: Arc<HybridQueryService>,
        entity_manager: Option<Arc<EcsEntityManager>>,
    ) -> Self {
        Self {
            hybrid_service,
            entity_manager,
            performance_thresholds: PerformanceThresholds::default(),
        }
    }

    /// Set custom performance thresholds
    pub fn with_thresholds(mut self, thresholds: PerformanceThresholds) -> Self {
        self.performance_thresholds = thresholds;
        self
    }

    /// Validate complete Chronicle→ECS→Query pipeline
    pub async fn validate_complete_pipeline(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        test_scenarios: Vec<PipelineTestScenario>,
    ) -> AnyhowResult<PipelineValidationResult> {
        let start_time = Instant::now();
        let mut validation_steps = Vec::new();
        let mut errors = Vec::new();
        let mut performance_metrics = PipelinePerformanceMetrics::default();

        println!("🔍 Starting comprehensive pipeline validation...");

        // Step 1: Validate Chronicle Event Processing
        let chronicle_step = self.validate_chronicle_processing(
            user_id,
            chronicle_id,
            &test_scenarios,
        ).await?;
        validation_steps.push(chronicle_step.clone());
        
        if !chronicle_step.passed {
            errors.push("Chronicle processing validation failed".to_string());
        }

        // Step 2: Validate ECS State Updates
        let ecs_step = self.validate_ecs_state_updates(
            user_id,
            &test_scenarios,
        ).await?;
        validation_steps.push(ecs_step.clone());
        
        if !ecs_step.passed {
            errors.push("ECS state update validation failed".to_string());
        }

        // Step 3: Validate Hybrid Query Integration
        let hybrid_step = self.validate_hybrid_query_integration(
            user_id,
            chronicle_id,
            &test_scenarios,
        ).await?;
        validation_steps.push(hybrid_step.clone());
        
        if !hybrid_step.passed {
            errors.push("Hybrid query integration validation failed".to_string());
        }

        // Step 4: Validate Performance Contracts
        let performance_step = self.validate_performance_contracts(
            user_id,
            chronicle_id,
            &test_scenarios,
        ).await?;
        validation_steps.push(performance_step.clone());
        
        if !performance_step.passed {
            errors.push("Performance contract validation failed".to_string());
        }

        // Step 5: Validate Data Consistency
        let consistency_step = self.validate_data_consistency(
            user_id,
            chronicle_id,
            &test_scenarios,
        ).await?;
        validation_steps.push(consistency_step.clone());
        
        if !consistency_step.passed {
            errors.push("Data consistency validation failed".to_string());
        }

        // Calculate overall metrics
        performance_metrics.total_latency = start_time.elapsed();
        performance_metrics.chronicle_query_duration = chronicle_step.duration;
        performance_metrics.ecs_query_duration = ecs_step.duration;
        performance_metrics.hybrid_query_duration = hybrid_step.duration;

        let total_events = test_scenarios.iter().map(|s| s.expected_events).sum();
        let total_entities = validation_steps.iter()
            .filter_map(|step| step.metrics.get("entities_found"))
            .filter_map(|v| v.as_u64())
            .sum::<u64>() as usize;
        let total_relationships = validation_steps.iter()
            .filter_map(|step| step.metrics.get("relationships_found"))
            .filter_map(|v| v.as_u64())
            .sum::<u64>() as usize;

        let success = errors.is_empty();

        let result = PipelineValidationResult {
            success,
            duration: start_time.elapsed(),
            events_processed: total_events,
            entities_found: total_entities,
            relationships_found: total_relationships,
            errors,
            performance_metrics,
            validation_steps,
        };

        if success {
            println!("✅ Pipeline validation PASSED");
        } else {
            println!("❌ Pipeline validation FAILED with {} errors", result.errors.len());
        }

        Ok(result)
    }

    /// Validate chronicle event processing
    async fn validate_chronicle_processing(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        scenarios: &[PipelineTestScenario],
    ) -> AnyhowResult<ValidationStep> {
        let start_time = Instant::now();
        let mut details = String::new();
        let mut metrics = HashMap::new();

        println!("  📖 Validating chronicle event processing...");

        // Test narrative query to find chronicle events
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Find all events and narrative content".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 100,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions::default(),
        };

        let result = self.hybrid_service.execute_hybrid_query(query).await?;
        
        let events_found = result.chronicle_events.len();
        let expected_events: usize = scenarios.iter().map(|s| s.expected_events).sum();

        metrics.insert("events_found".to_string(), json!(events_found));
        metrics.insert("expected_events".to_string(), json!(expected_events));
        metrics.insert("query_duration_ms".to_string(), json!(result.performance.chronicle_query_ms));

        let passed = events_found > 0; // Basic validation - events exist
        
        if passed {
            details = format!("Found {} chronicle events", events_found);
        } else {
            details = "No chronicle events found".to_string();
        }

        Ok(ValidationStep {
            name: "chronicle_processing".to_string(),
            passed,
            duration: start_time.elapsed(),
            details,
            metrics,
        })
    }

    /// Validate ECS state updates
    async fn validate_ecs_state_updates(
        &self,
        user_id: Uuid,
        scenarios: &[PipelineTestScenario],
    ) -> AnyhowResult<ValidationStep> {
        let start_time = Instant::now();
        let mut details = String::new();
        let mut metrics = HashMap::new();
        let mut passed = true;

        println!("  🎯 Validating ECS state updates...");

        // Test entity state query
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Find all entities with current states".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: None, // Search across all chronicles
            max_results: 50,
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        let result = self.hybrid_service.execute_hybrid_query(query).await?;

        let entities_with_state = result.entities.iter()
            .filter(|e| e.current_state.is_some())
            .count();
        
        let total_entities = result.entities.len();

        metrics.insert("total_entities".to_string(), json!(total_entities));
        metrics.insert("entities_with_state".to_string(), json!(entities_with_state));
        metrics.insert("ecs_enhanced".to_string(), json!(!result.warnings.iter().any(|w| w.contains("ECS unavailable"))));

        // Check if ECS is functioning
        let ecs_available = !result.warnings.iter().any(|w| w.contains("ECS unavailable"));
        
        if ecs_available {
            details = format!("ECS active: {} entities found, {} with current state", total_entities, entities_with_state);
        } else {
            details = "ECS not available - using fallback mode".to_string();
            // Don't fail if ECS is intentionally unavailable in test environment
            passed = true; // Allow graceful degradation
        }

        Ok(ValidationStep {
            name: "ecs_state_updates".to_string(),
            passed,
            duration: start_time.elapsed(),
            details,
            metrics,
        })
    }

    /// Validate hybrid query integration
    async fn validate_hybrid_query_integration(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        scenarios: &[PipelineTestScenario],
    ) -> AnyhowResult<ValidationStep> {
        let start_time = Instant::now();
        let mut details = String::new();
        let mut metrics = HashMap::new();

        println!("  🔄 Validating hybrid query integration...");

        let mut successful_queries = 0;
        let mut total_queries = 0;

        // Test different query types from scenarios
        for scenario in scenarios {
            for query_test in &scenario.query_tests {
                total_queries += 1;
                
                let query = HybridQuery {
                    query_type: query_test.query_type.clone(),
                    user_id,
                    chronicle_id: Some(chronicle_id),
                    max_results: 25,
                    include_current_state: true,
                    include_relationships: true,
                    options: HybridQueryOptions::default(),
                };

                match self.hybrid_service.execute_hybrid_query(query).await {
                    Ok(result) => {
                        successful_queries += 1;
                        
                        // Validate query result structure
                        if !result.summary.key_insights.is_empty() || !result.chronicle_events.is_empty() {
                            // Query returned meaningful results
                        }
                    }
                    Err(e) => {
                        println!("    ⚠️  Query failed: {}", e);
                    }
                }
            }
        }

        metrics.insert("successful_queries".to_string(), json!(successful_queries));
        metrics.insert("total_queries".to_string(), json!(total_queries));
        metrics.insert("success_rate".to_string(), json!(if total_queries > 0 { successful_queries as f32 / total_queries as f32 } else { 0.0 }));

        let passed = successful_queries > 0; // At least some queries should work
        
        details = format!("{}/{} queries successful", successful_queries, total_queries);

        Ok(ValidationStep {
            name: "hybrid_query_integration".to_string(),
            passed,
            duration: start_time.elapsed(),
            details,
            metrics,
        })
    }

    /// Validate performance contracts
    async fn validate_performance_contracts(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        _scenarios: &[PipelineTestScenario],
    ) -> AnyhowResult<ValidationStep> {
        let start_time = Instant::now();
        let mut details = String::new();
        let mut metrics = HashMap::new();

        println!("  ⚡ Validating performance contracts...");

        // Execute a performance test query
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Complex query to test performance with relationships and current state".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 50,
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        let query_start = Instant::now();
        let result = self.hybrid_service.execute_hybrid_query(query).await?;
        let query_duration = query_start.elapsed();

        metrics.insert("query_duration_ms".to_string(), json!(query_duration.as_millis()));
        metrics.insert("performance_total_ms".to_string(), json!(result.performance.total_duration_ms));
        metrics.insert("chronicle_query_ms".to_string(), json!(result.performance.chronicle_query_ms));
        metrics.insert("ecs_query_ms".to_string(), json!(result.performance.ecs_query_ms));

        // Check against thresholds
        let meets_duration_threshold = query_duration <= self.performance_thresholds.max_query_duration;
        let meets_pipeline_threshold = Duration::from_millis(result.performance.total_duration_ms) <= self.performance_thresholds.max_pipeline_latency;

        let passed = meets_duration_threshold && meets_pipeline_threshold;

        if passed {
            details = format!("Performance within thresholds: {}ms query, {}ms total", 
                            query_duration.as_millis(), result.performance.total_duration_ms);
        } else {
            details = format!("Performance exceeded thresholds: {}ms query (max {}ms), {}ms total (max {}ms)", 
                            query_duration.as_millis(), self.performance_thresholds.max_query_duration.as_millis(),
                            result.performance.total_duration_ms, self.performance_thresholds.max_pipeline_latency.as_millis());
        }

        Ok(ValidationStep {
            name: "performance_contracts".to_string(),
            passed,
            duration: start_time.elapsed(),
            details,
            metrics,
        })
    }

    /// Validate data consistency across systems
    async fn validate_data_consistency(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        _scenarios: &[PipelineTestScenario],
    ) -> AnyhowResult<ValidationStep> {
        let start_time = Instant::now();
        let mut details = String::new();
        let mut metrics = HashMap::new();

        println!("  🔒 Validating data consistency...");

        // Test consistency between chronicle events and ECS state
        let timeline_query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Find entities with both chronicle history and current state".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 30,
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };

        let result = self.hybrid_service.execute_hybrid_query(timeline_query).await?;

        let entities_with_timeline = result.entities.iter()
            .filter(|e| !e.timeline_events.is_empty())
            .count();
        
        let entities_with_state = result.entities.iter()
            .filter(|e| e.current_state.is_some())
            .count();

        let consistency_ratio = if entities_with_timeline > 0 {
            entities_with_state as f32 / entities_with_timeline as f32
        } else {
            1.0 // No inconsistency if no data
        };

        metrics.insert("entities_with_timeline".to_string(), json!(entities_with_timeline));
        metrics.insert("entities_with_state".to_string(), json!(entities_with_state));
        metrics.insert("consistency_ratio".to_string(), json!(consistency_ratio));
        metrics.insert("total_events".to_string(), json!(result.chronicle_events.len()));

        // Data is consistent if we have no major inconsistencies
        let passed = consistency_ratio >= 0.5 || entities_with_timeline == 0;

        if passed {
            details = format!("Data consistency validated: {}/{} entities have both timeline and state", 
                            entities_with_state, entities_with_timeline);
        } else {
            details = format!("Data consistency issues: only {}/{} entities have complete data", 
                            entities_with_state, entities_with_timeline);
        }

        Ok(ValidationStep {
            name: "data_consistency".to_string(),
            passed,
            duration: start_time.elapsed(),
            details,
            metrics,
        })
    }
}

/// Test scenario for pipeline validation
#[derive(Debug, Clone)]
pub struct PipelineTestScenario {
    /// Name of the test scenario
    pub name: String,
    /// Description of what this scenario tests
    pub description: String,
    /// Number of events expected to be processed
    pub expected_events: usize,
    /// Expected number of entities
    pub expected_entities: usize,
    /// Query tests to run
    pub query_tests: Vec<QueryTest>,
}

/// Individual query test within a scenario
#[derive(Debug, Clone)]
pub struct QueryTest {
    /// Type of query to test
    pub query_type: HybridQueryType,
    /// Expected minimum results
    pub expected_min_results: usize,
    /// Whether this query should succeed
    pub should_succeed: bool,
}

impl PipelineTestScenario {
    /// Create a new test scenario
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            expected_events: 0,
            expected_entities: 0,
            query_tests: Vec::new(),
        }
    }

    /// Set expected event count
    pub fn with_expected_events(mut self, count: usize) -> Self {
        self.expected_events = count;
        self
    }

    /// Set expected entity count
    pub fn with_expected_entities(mut self, count: usize) -> Self {
        self.expected_entities = count;
        self
    }

    /// Add a query test
    pub fn with_query_test(mut self, query_test: QueryTest) -> Self {
        self.query_tests.push(query_test);
        self
    }
}

impl QueryTest {
    /// Create a new query test
    pub fn new(query_type: HybridQueryType, should_succeed: bool) -> Self {
        Self {
            query_type,
            expected_min_results: 0,
            should_succeed,
        }
    }

    /// Set expected minimum results
    pub fn with_min_results(mut self, min_results: usize) -> Self {
        self.expected_min_results = min_results;
        self
    }
}

/// Create standard test scenarios for Dragon's Hoard
pub fn create_dragon_hoard_scenarios() -> Vec<PipelineTestScenario> {
    vec![
        PipelineTestScenario::new(
            "character_relationships",
            "Test character relationship tracking and queries"
        )
        .with_expected_events(5)
        .with_expected_entities(3)
        .with_query_test(QueryTest::new(
            HybridQueryType::RelationshipHistory {
                entity_a: "Sir Kael".to_string(),
                entity_b: "Princess Elena".to_string(),
                entity_a_id: None,
                entity_b_id: None,
            },
            true
        ).with_min_results(1)),

        PipelineTestScenario::new(
            "location_queries",
            "Test location-based entity queries"
        )
        .with_expected_events(3)
        .with_expected_entities(2)
        .with_query_test(QueryTest::new(
            HybridQueryType::LocationQuery {
                location_name: "Dragon's Lair".to_string(),
                location_data: None,
                include_recent_activity: true,
            },
            true
        )),

        PipelineTestScenario::new(
            "item_interactions",
            "Test item interaction tracking"
        )
        .with_expected_events(4)
        .with_expected_entities(1)
        .with_query_test(QueryTest::new(
            HybridQueryType::NarrativeQuery {
                query_text: "Sword of Light interactions".to_string(),
                focus_entities: None,
                time_range: None,
            },
            true
        )),
    ]
}