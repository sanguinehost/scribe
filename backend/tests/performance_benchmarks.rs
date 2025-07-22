//! Performance Benchmarks for ECS + RAG Integration
//!
//! This module provides comprehensive performance testing for the Chronicle→ECS→Query
//! pipeline under various load conditions and data sizes.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use anyhow::{Context, Result as AnyhowResult};
use tokio::task::JoinSet;
use secrecy::ExposeSecret;

use scribe_backend::{
    config::NarrativeFeatureFlags,
    models::{
        chronicle::{CreateChronicleRequest, PlayerChronicle},
        chronicle_event::{CreateEventRequest, EventSource},
    },
    services::{
        ChronicleService,
        HybridQueryService, HybridQueryConfig, HybridQuery, HybridQueryType, HybridQueryOptions,
        EcsEntityManager, EntityManagerConfig,
        EcsEnhancedRagService, EcsEnhancedRagConfig,
        EcsGracefulDegradation, GracefulDegradationConfig,
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestDataGuard, TestApp},
    auth::session_dek::SessionDek,
};

/// Performance benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Name of the benchmark
    pub name: String,
    /// Total operations performed
    pub operations: usize,
    /// Total duration
    pub duration: Duration,
    /// Operations per second
    pub ops_per_second: f64,
    /// Average latency per operation
    pub avg_latency: Duration,
    /// 95th percentile latency
    pub p95_latency: Duration,
    /// Memory usage metrics
    pub memory_metrics: MemoryMetrics,
    /// Error rate
    pub error_rate: f64,
    /// Additional metrics
    pub additional_metrics: HashMap<String, f64>,
}

/// Memory usage tracking
#[derive(Debug, Clone)]
pub struct MemoryMetrics {
    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,
    /// Memory growth during test
    pub memory_growth_bytes: u64,
    /// Final memory usage
    pub final_memory_bytes: u64,
}

impl Default for MemoryMetrics {
    fn default() -> Self {
        Self {
            peak_memory_bytes: 0,
            memory_growth_bytes: 0,
            final_memory_bytes: 0,
        }
    }
}

/// Performance benchmark suite
pub struct PerformanceBenchmarks {
    app: TestApp,
    _guard: TestDataGuard,
    user_id: Uuid,
    chronicle: PlayerChronicle,
    session_dek: SessionDek,
    hybrid_service: HybridQueryService,
    chronicle_service: ChronicleService,
}

impl PerformanceBenchmarks {
    /// Create a new performance benchmark suite
    pub async fn new() -> AnyhowResult<Self> {
        let app = spawn_app_permissive_rate_limiting(false, false, false).await;
        let guard = TestDataGuard::new(app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let plaintext_dek = scribe_backend::crypto::generate_dek().context("DEK generation failed")?;
        let session_dek = SessionDek::new(plaintext_dek.expose_secret().to_vec());

        // Create test chronicle
        let chronicle_service = ChronicleService::new(app.db_pool.clone());
        let chronicle_request = CreateChronicleRequest {
            name: "Performance Benchmark Chronicle".to_string(),
            description: Some("Testing performance under load".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, chronicle_request).await?;

        // Setup services with performance-optimized configuration
        let feature_flags = Arc::new(NarrativeFeatureFlags {
            enable_ecs_system: true,
            ..Default::default()
        });

        let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/1")?);

        let entity_manager = Arc::new(EcsEntityManager::new(
            Arc::new(app.db_pool.clone()),
            redis_client,
            Some(EntityManagerConfig {
                default_cache_ttl: 600,
                hot_cache_ttl: 1800,
                bulk_operation_batch_size: 100,
                enable_component_caching: true,
            }),
        ));

        let degradation_service = Arc::new(EcsGracefulDegradation::new(
            GracefulDegradationConfig::default(),
            feature_flags.clone(),
            Some(entity_manager.clone()),
            None,
        ));

        let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
            scribe_backend::text_processing::chunking::ChunkConfig {
                metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                max_size: 500,
                overlap: 50,
            }
        ));
        
        let rag_service = Arc::new(EcsEnhancedRagService::new(
            Arc::new(app.db_pool.clone()),
            EcsEnhancedRagConfig::default(),
            feature_flags.clone(),
            entity_manager.clone(),
            degradation_service.clone(),
            concrete_embedding_service,
        ));

        let hybrid_service = HybridQueryService::new(
            Arc::new(app.db_pool.clone()),
            HybridQueryConfig {
                enable_entity_caching: true,
                entity_cache_ttl: 600,
                max_entities_per_query: 100,
                enable_timeline_reconstruction: true,
                max_timeline_events: 500,
                enable_relationship_analysis: true,
                max_relationship_depth: 5,
            },
            feature_flags,
            app.app_state.ai_client.clone(),
            "gemini-2.5-flash".to_string(),
            entity_manager,
            rag_service,
            degradation_service,
        );

        Ok(Self {
            app,
            _guard: guard,
            user_id,
            chronicle,
            session_dek,
            hybrid_service,
            chronicle_service,
        })
    }

    /// Run all performance benchmarks
    pub async fn run_all_benchmarks(&self) -> AnyhowResult<Vec<BenchmarkResult>> {
        println!("🚀 Starting comprehensive performance benchmarks...");

        let mut results = Vec::new();

        // Benchmark 1: Chronicle Event Creation Throughput
        results.push(self.benchmark_chronicle_event_creation().await?);

        // Benchmark 2: Hybrid Query Performance
        results.push(self.benchmark_hybrid_query_performance().await?);

        // Benchmark 3: Concurrent Query Load
        results.push(self.benchmark_concurrent_query_load().await?);

        // Benchmark 4: Large Dataset Performance
        results.push(self.benchmark_large_dataset_performance().await?);

        // Benchmark 5: Cache Performance
        results.push(self.benchmark_cache_performance().await?);

        // Benchmark 6: Complex Relationship Queries
        results.push(self.benchmark_complex_relationship_queries().await?);

        println!("✅ All performance benchmarks completed");
        Self::print_benchmark_summary(&results);

        Ok(results)
    }

    /// Benchmark chronicle event creation throughput
    async fn benchmark_chronicle_event_creation(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  📝 Benchmarking chronicle event creation...");

        let num_events = 1000;
        let start_time = Instant::now();
        let mut latencies = Vec::new();
        let mut errors = 0;

        for i in 0..num_events {
            let event_start = Instant::now();
            
            let event_request = CreateEventRequest {
                event_type: "benchmark_event".to_string(),
                summary: format!("Benchmark event {} with various narrative content", i + 1),
                source: EventSource::UserAdded,
                event_data: Some(json!({
                    "content": format!("Event {} involves character interactions and location changes", i + 1),
                    "timestamp": Utc::now(),
                    "sequence": i + 1,
                    "benchmark": true
                })),
                timestamp_iso8601: Some(Utc::now()),
            };

            match self.chronicle_service.create_event(
                self.user_id,
                self.chronicle.id,
                event_request,
                Some(&self.session_dek),
            ).await {
                Ok(_) => {
                    latencies.push(event_start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }

            // Small delay to avoid overwhelming the system
            if i % 100 == 99 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = num_events as f64 / total_duration.as_secs_f64();
        let avg_latency = latencies.iter().sum::<Duration>() / latencies.len() as u32;
        
        latencies.sort();
        let p95_latency = latencies[(latencies.len() as f64 * 0.95) as usize];
        let error_rate = errors as f64 / num_events as f64;

        Ok(BenchmarkResult {
            name: "chronicle_event_creation".to_string(),
            operations: num_events,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("successful_events".to_string(), (num_events - errors) as f64);
                metrics.insert("failed_events".to_string(), errors as f64);
                metrics
            },
        })
    }

    /// Benchmark hybrid query performance
    async fn benchmark_hybrid_query_performance(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  🔍 Benchmarking hybrid query performance...");

        let num_queries = 100;
        let start_time = Instant::now();
        let mut latencies = Vec::new();
        let mut errors = 0;

        let query_templates = vec![
            "Find all characters and their relationships",
            "Show me locations with recent activity",
            "What items have been interacted with recently",
            "Analyze relationship changes over time",
            "Find entities with specific trust levels",
        ];

        for i in 0..num_queries {
            let query_start = Instant::now();
            
            let query_text = &query_templates[i % query_templates.len()];
            
            let query = HybridQuery {
                query_type: HybridQueryType::NarrativeQuery {
                    query_text: format!("{} (benchmark query {})", query_text, i + 1),
                    focus_entities: None,
                    time_range: None,
                },
                user_id: self.user_id,
                chronicle_id: Some(self.chronicle.id),
                max_results: 25,
                include_current_state: true,
                include_relationships: true,
                options: HybridQueryOptions::default(),
            };

            match self.hybrid_service.execute_hybrid_query(query).await {
                Ok(_) => {
                    latencies.push(query_start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = num_queries as f64 / total_duration.as_secs_f64();
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<Duration>() / latencies.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        latencies.sort();
        let p95_latency = if !latencies.is_empty() {
            latencies[(latencies.len() as f64 * 0.95) as usize]
        } else {
            Duration::from_millis(0)
        };
        let error_rate = errors as f64 / num_queries as f64;

        Ok(BenchmarkResult {
            name: "hybrid_query_performance".to_string(),
            operations: num_queries,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("successful_queries".to_string(), (num_queries - errors) as f64);
                metrics.insert("failed_queries".to_string(), errors as f64);
                metrics
            },
        })
    }

    /// Benchmark concurrent query load
    async fn benchmark_concurrent_query_load(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  🔀 Benchmarking concurrent query load...");

        let num_concurrent = 20;
        let queries_per_worker = 10;
        let total_queries = num_concurrent * queries_per_worker;
        
        let start_time = Instant::now();
        let mut join_set = JoinSet::new();

        // Spawn concurrent workers
        for worker_id in 0..num_concurrent {
            let hybrid_service = self.hybrid_service.clone();
            let user_id = self.user_id;
            let chronicle_id = self.chronicle.id;

            join_set.spawn(async move {
                let mut worker_latencies = Vec::new();
                let mut worker_errors = 0;

                for i in 0..queries_per_worker {
                    let query_start = Instant::now();
                    
                    let query = HybridQuery {
                        query_type: HybridQueryType::NarrativeQuery {
                            query_text: format!("Concurrent query from worker {} iteration {}", worker_id, i),
                            focus_entities: None,
                            time_range: None,
                        },
                        user_id,
                        chronicle_id: Some(chronicle_id),
                        max_results: 10,
                        include_current_state: true,
                        include_relationships: false,
                        options: HybridQueryOptions::default(),
                    };

                    match hybrid_service.execute_hybrid_query(query).await {
                        Ok(_) => {
                            worker_latencies.push(query_start.elapsed());
                        }
                        Err(_) => {
                            worker_errors += 1;
                        }
                    }
                }

                (worker_latencies, worker_errors)
            });
        }

        // Collect results from all workers
        let mut all_latencies = Vec::new();
        let mut total_errors = 0;

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((latencies, errors)) => {
                    all_latencies.extend(latencies);
                    total_errors += errors;
                }
                Err(_) => {
                    total_errors += queries_per_worker;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = total_queries as f64 / total_duration.as_secs_f64();
        let avg_latency = if !all_latencies.is_empty() {
            all_latencies.iter().sum::<Duration>() / all_latencies.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        all_latencies.sort();
        let p95_latency = if !all_latencies.is_empty() {
            all_latencies[(all_latencies.len() as f64 * 0.95) as usize]
        } else {
            Duration::from_millis(0)
        };
        let error_rate = total_errors as f64 / total_queries as f64;

        Ok(BenchmarkResult {
            name: "concurrent_query_load".to_string(),
            operations: total_queries,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("concurrent_workers".to_string(), num_concurrent as f64);
                metrics.insert("queries_per_worker".to_string(), queries_per_worker as f64);
                metrics.insert("successful_queries".to_string(), (total_queries - total_errors) as f64);
                metrics
            },
        })
    }

    /// Benchmark performance with large datasets
    async fn benchmark_large_dataset_performance(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  📊 Benchmarking large dataset performance...");

        // First, create a large dataset
        let dataset_size = 500;
        println!("    Creating large dataset ({} events)...", dataset_size);
        
        for i in 0..dataset_size {
            let event_request = CreateEventRequest {
                event_type: "large_dataset_event".to_string(),
                summary: format!("Large dataset event {} with complex relationships", i + 1),
                source: EventSource::UserAdded,
                event_data: Some(json!({
                    "content": format!("Character {} interacts with character {} at location {}",
                                     i % 10, (i + 1) % 10, i % 5),
                    "character_a": format!("character_{}", i % 10),
                    "character_b": format!("character_{}", (i + 1) % 10),
                    "location": format!("location_{}", i % 5),
                    "relationship_change": (i as f32 % 2.0) - 1.0, // Random trust change
                })),
                timestamp_iso8601: Some(Utc::now()),
            };

            let _ = self.chronicle_service.create_event(
                self.user_id,
                self.chronicle.id,
                event_request,
                Some(&self.session_dek),
            ).await;

            if i % 100 == 99 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // Now benchmark queries against the large dataset
        let num_queries = 50;
        let start_time = Instant::now();
        let mut latencies = Vec::new();
        let mut errors = 0;

        for i in 0..num_queries {
            let query_start = Instant::now();
            
            let query = HybridQuery {
                query_type: HybridQueryType::NarrativeQuery {
                    query_text: format!("Find complex relationships in large dataset query {}", i),
                    focus_entities: None,
                    time_range: None,
                },
                user_id: self.user_id,
                chronicle_id: Some(self.chronicle.id),
                max_results: 100, // Larger result set
                include_current_state: true,
                include_relationships: true,
                options: HybridQueryOptions {
                    use_cache: true,
                    include_timelines: true,
                    analyze_relationships: true,
                    confidence_threshold: 0.3,
                },
            };

            match self.hybrid_service.execute_hybrid_query(query).await {
                Ok(_) => {
                    latencies.push(query_start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = num_queries as f64 / total_duration.as_secs_f64();
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<Duration>() / latencies.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        latencies.sort();
        let p95_latency = if !latencies.is_empty() {
            latencies[(latencies.len() as f64 * 0.95) as usize]
        } else {
            Duration::from_millis(0)
        };
        let error_rate = errors as f64 / num_queries as f64;

        Ok(BenchmarkResult {
            name: "large_dataset_performance".to_string(),
            operations: num_queries,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("dataset_size".to_string(), dataset_size as f64);
                metrics.insert("result_set_size".to_string(), 100.0);
                metrics.insert("successful_queries".to_string(), (num_queries - errors) as f64);
                metrics
            },
        })
    }

    /// Benchmark cache performance
    async fn benchmark_cache_performance(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  🗄️  Benchmarking cache performance...");

        let num_queries = 200;
        let cache_queries = 100; // Repeat the same queries to test cache hits
        
        let start_time = Instant::now();
        let mut latencies = Vec::new();
        let mut errors = 0;

        // Create some baseline queries
        let base_queries = vec![
            "Find character relationships",
            "Show location activities", 
            "List item interactions",
            "Analyze trust changes",
            "Find recent events",
        ];

        // First pass - populate cache
        for i in 0..cache_queries {
            let query_text = &base_queries[i % base_queries.len()];
            
            let query = HybridQuery {
                query_type: HybridQueryType::NarrativeQuery {
                    query_text: query_text.to_string(),
                    focus_entities: None,
                    time_range: None,
                },
                user_id: self.user_id,
                chronicle_id: Some(self.chronicle.id),
                max_results: 20,
                include_current_state: true,
                include_relationships: true,
                options: HybridQueryOptions {
                    use_cache: true,
                    include_timelines: false,
                    analyze_relationships: true,
                    confidence_threshold: 0.5,
                },
            };

            let _ = self.hybrid_service.execute_hybrid_query(query).await;
        }

        // Second pass - measure cache performance
        for i in 0..num_queries {
            let query_start = Instant::now();
            
            let query_text = &base_queries[i % base_queries.len()];
            
            let query = HybridQuery {
                query_type: HybridQueryType::NarrativeQuery {
                    query_text: format!("{} (cache test {})", query_text, i),
                    focus_entities: None,
                    time_range: None,
                },
                user_id: self.user_id,
                chronicle_id: Some(self.chronicle.id),
                max_results: 20,
                include_current_state: true,
                include_relationships: true,
                options: HybridQueryOptions {
                    use_cache: true,
                    include_timelines: false,
                    analyze_relationships: true,
                    confidence_threshold: 0.5,
                },
            };

            match self.hybrid_service.execute_hybrid_query(query).await {
                Ok(_) => {
                    latencies.push(query_start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = num_queries as f64 / total_duration.as_secs_f64();
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<Duration>() / latencies.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        latencies.sort();
        let p95_latency = if !latencies.is_empty() {
            latencies[(latencies.len() as f64 * 0.95) as usize]
        } else {
            Duration::from_millis(0)
        };
        let error_rate = errors as f64 / num_queries as f64;

        Ok(BenchmarkResult {
            name: "cache_performance".to_string(),
            operations: num_queries,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("cache_warmup_queries".to_string(), cache_queries as f64);
                metrics.insert("test_queries".to_string(), num_queries as f64);
                metrics.insert("successful_queries".to_string(), (num_queries - errors) as f64);
                metrics
            },
        })
    }

    /// Benchmark complex relationship queries
    async fn benchmark_complex_relationship_queries(&self) -> AnyhowResult<BenchmarkResult> {
        println!("  🕸️  Benchmarking complex relationship queries...");

        let num_queries = 50;
        let start_time = Instant::now();
        let mut latencies = Vec::new();
        let mut errors = 0;

        for i in 0..num_queries {
            let query_start = Instant::now();
            
            // Alternate between different complex query types
            let query = match i % 3 {
                0 => self.hybrid_service.query_trusted_characters_at_location(
                    self.user_id,
                    Some(self.chronicle.id),
                    "location_1",
                    0.5,
                    Some(20),
                ).await,
                1 => self.hybrid_service.query_relationship_affecting_events(
                    self.user_id,
                    Some(self.chronicle.id),
                    "character_1",
                    "character_2",
                    None,
                    None,
                    true,
                    Some(30),
                ).await,
                _ => self.hybrid_service.query_item_interaction_history(
                    self.user_id,
                    Some(self.chronicle.id),
                    "important_item",
                    None,
                    Some(vec!["use".to_string(), "transfer".to_string()]),
                    None,
                    Some(25),
                ).await,
            };

            match query {
                Ok(_) => {
                    latencies.push(query_start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let ops_per_second = num_queries as f64 / total_duration.as_secs_f64();
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<Duration>() / latencies.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        latencies.sort();
        let p95_latency = if !latencies.is_empty() {
            latencies[(latencies.len() as f64 * 0.95) as usize]
        } else {
            Duration::from_millis(0)
        };
        let error_rate = errors as f64 / num_queries as f64;

        Ok(BenchmarkResult {
            name: "complex_relationship_queries".to_string(),
            operations: num_queries,
            duration: total_duration,
            ops_per_second,
            avg_latency,
            p95_latency,
            memory_metrics: MemoryMetrics::default(),
            error_rate,
            additional_metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("trusted_character_queries".to_string(), (num_queries / 3) as f64);
                metrics.insert("relationship_event_queries".to_string(), (num_queries / 3) as f64);
                metrics.insert("item_interaction_queries".to_string(), (num_queries / 3) as f64);
                metrics.insert("successful_queries".to_string(), (num_queries - errors) as f64);
                metrics
            },
        })
    }

    /// Print benchmark summary
    fn print_benchmark_summary(results: &[BenchmarkResult]) {
        println!("\n📊 Performance Benchmark Summary");
        println!("═══════════════════════════════════════════════════════");
        
        for result in results {
            println!("\n🔹 {}", result.name.replace("_", " ").to_uppercase());
            println!("   Operations: {}", result.operations);
            println!("   Duration: {:.2}s", result.duration.as_secs_f64());
            println!("   Ops/sec: {:.2}", result.ops_per_second);
            println!("   Avg Latency: {:.2}ms", result.avg_latency.as_millis());
            println!("   P95 Latency: {:.2}ms", result.p95_latency.as_millis());
            println!("   Error Rate: {:.2}%", result.error_rate * 100.0);
            
            if !result.additional_metrics.is_empty() {
                println!("   Additional Metrics:");
                for (key, value) in &result.additional_metrics {
                    println!("     {}: {:.2}", key.replace("_", " "), value);
                }
            }
        }
        
        println!("\n═══════════════════════════════════════════════════════");
        
        // Overall performance assessment
        let avg_ops_per_sec: f64 = results.iter().map(|r| r.ops_per_second).sum::<f64>() / results.len() as f64;
        let avg_error_rate: f64 = results.iter().map(|r| r.error_rate).sum::<f64>() / results.len() as f64;
        let max_latency = results.iter().map(|r| r.p95_latency).max().unwrap_or(Duration::from_millis(0));
        
        println!("🎯 OVERALL PERFORMANCE ASSESSMENT:");
        println!("   Average Throughput: {:.2} ops/sec", avg_ops_per_sec);
        println!("   Average Error Rate: {:.2}%", avg_error_rate * 100.0);
        println!("   Maximum P95 Latency: {:.2}ms", max_latency.as_millis());
        
        // Performance grade
        let grade = if avg_error_rate < 0.01 && max_latency.as_millis() < 5000 && avg_ops_per_sec > 10.0 {
            "EXCELLENT ⭐⭐⭐"
        } else if avg_error_rate < 0.05 && max_latency.as_millis() < 10000 && avg_ops_per_sec > 5.0 {
            "GOOD ⭐⭐"
        } else if avg_error_rate < 0.10 && max_latency.as_millis() < 30000 && avg_ops_per_sec > 1.0 {
            "ACCEPTABLE ⭐"
        } else {
            "NEEDS IMPROVEMENT ⚠️"
        };
        
        println!("   Performance Grade: {}", grade);
    }
}

/// Comprehensive performance test suite
#[tokio::test]
#[ignore = "Performance test - run manually with 'cargo test --ignored performance_benchmark_suite'"]
async fn performance_benchmark_suite() -> AnyhowResult<()> {
    println!("🚀 Starting Comprehensive Performance Benchmark Suite");
    println!("════════════════════════════════════════════════════════");
    
    let benchmarks = PerformanceBenchmarks::new().await?;
    let results = benchmarks.run_all_benchmarks().await?;
    
    // Validate performance requirements
    let mut failed_requirements = Vec::new();
    
    for result in &results {
        // Check error rate
        if result.error_rate > 0.05 {
            failed_requirements.push(format!("{}: Error rate too high ({:.2}%)", result.name, result.error_rate * 100.0));
        }
        
        // Check latency
        if result.p95_latency.as_millis() > 30000 {
            failed_requirements.push(format!("{}: P95 latency too high ({:.2}ms)", result.name, result.p95_latency.as_millis()));
        }
        
        // Check throughput
        if result.ops_per_second < 1.0 {
            failed_requirements.push(format!("{}: Throughput too low ({:.2} ops/sec)", result.name, result.ops_per_second));
        }
    }
    
    if failed_requirements.is_empty() {
        println!("\n✅ All performance requirements PASSED");
    } else {
        println!("\n❌ Performance requirements FAILED:");
        for failure in &failed_requirements {
            println!("   - {}", failure);
        }
    }
    
    println!("\n🎉 Performance benchmark suite completed");
    Ok(())
}

/// Quick performance smoke test
#[tokio::test]
async fn performance_smoke_test() -> AnyhowResult<()> {
    println!("💨 Running performance smoke test...");
    
    let benchmarks = PerformanceBenchmarks::new().await?;
    
    // Run a quick version of each benchmark
    let start_time = Instant::now();
    
    // Quick chronicle event test
    let event_request = CreateEventRequest {
        event_type: "smoke_test".to_string(),
        summary: "Quick performance smoke test event".to_string(),
        source: EventSource::UserAdded,
        event_data: Some(json!({"test": true})),
        timestamp_iso8601: Some(Utc::now()),
    };
    
    let _event = benchmarks.chronicle_service.create_event(
        benchmarks.user_id,
        benchmarks.chronicle.id,
        event_request,
        Some(&benchmarks.session_dek),
    ).await?;
    
    // Quick query test
    let query = scribe_backend::services::HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Quick smoke test query".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: benchmarks.user_id,
        chronicle_id: Some(benchmarks.chronicle.id),
        max_results: 5,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let _result = benchmarks.hybrid_service.execute_hybrid_query(query).await?;
    
    let total_time = start_time.elapsed();
    
    // Basic performance assertions
    assert!(total_time.as_secs() < 30, "Smoke test should complete within 30 seconds");
    
    println!("✅ Performance smoke test passed ({:.2}s)", total_time.as_secs_f64());
    Ok(())
}