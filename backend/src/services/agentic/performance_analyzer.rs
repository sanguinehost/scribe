//! Performance Analysis Tools for Living World Hierarchical Pipeline
//! 
//! This module provides utilities for analyzing performance bottlenecks and 
//! visualizing timing data from the hierarchical agent pipeline execution.

use std::collections::HashMap;
use tracing::debug;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::services::agentic::hierarchical_pipeline::{
    PipelineMetrics, PerceptionTimingBreakdown, StrategicTimingBreakdown,
    TacticalTimingBreakdown, OperationalTimingBreakdown,
};

/// Performance bottleneck identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBottleneck {
    /// Name of the bottleneck
    pub name: String,
    /// Layer where bottleneck occurs
    pub layer: AgentLayer,
    /// Time spent in milliseconds
    pub duration_ms: u64,
    /// Percentage of total pipeline time
    pub percentage_of_total: f32,
    /// Severity level
    pub severity: BottleneckSeverity,
    /// Recommended optimization
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentLayer {
    Perception,
    Strategic,
    Tactical,
    Operational,
    Pipeline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BottleneckSeverity {
    Critical, // >40% of total time
    High,     // 25-40% of total time
    Medium,   // 15-25% of total time
    Low,      // <15% of total time
}

/// Performance analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnalysisReport {
    /// Analysis timestamp
    pub timestamp: DateTime<Utc>,
    /// Total pipeline execution time
    pub total_time_ms: u64,
    /// Identified bottlenecks
    pub bottlenecks: Vec<PerformanceBottleneck>,
    /// Layer-by-layer breakdown
    pub layer_breakdown: HashMap<String, LayerPerformance>,
    /// Optimization opportunities
    pub optimization_opportunities: Vec<OptimizationOpportunity>,
    /// Performance score (0-100)
    pub performance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerPerformance {
    pub layer: AgentLayer,
    pub total_time_ms: u64,
    pub ai_call_time_ms: u64,
    pub processing_time_ms: u64,
    pub percentage_of_total: f32,
    pub ai_call_percentage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationOpportunity {
    pub title: String,
    pub description: String,
    pub potential_time_savings_ms: u64,
    pub implementation_complexity: ComplexityLevel,
    pub priority: OptimizationPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplexityLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Performance analyzer for hierarchical pipeline
pub struct PerformanceAnalyzer;

impl PerformanceAnalyzer {
    /// Analyze pipeline metrics and generate performance report
    pub fn analyze_pipeline_metrics(metrics: &PipelineMetrics) -> PerformanceAnalysisReport {
        debug!("Analyzing pipeline performance metrics");
        
        let mut bottlenecks = Vec::new();
        let mut layer_breakdown = HashMap::new();
        let mut optimization_opportunities = Vec::new();
        
        // Analyze perception layer
        if let Some(ref perception) = metrics.perception_breakdown {
            let layer_perf = Self::analyze_perception_layer(
                perception,
                metrics.perception_time_ms,
                metrics.total_execution_time_ms,
            );
            
            if layer_perf.percentage_of_total > 40.0 {
                bottlenecks.push(PerformanceBottleneck {
                    name: "Perception Layer Processing".to_string(),
                    layer: AgentLayer::Perception,
                    duration_ms: metrics.perception_time_ms,
                    percentage_of_total: layer_perf.percentage_of_total,
                    severity: BottleneckSeverity::Critical,
                    recommendation: "Consider caching entity extraction results or using lighter models".to_string(),
                });
            }
            
            layer_breakdown.insert("perception".to_string(), layer_perf);
        }
        
        // Analyze strategic layer
        if let Some(ref strategic) = metrics.strategic_breakdown {
            let layer_perf = Self::analyze_strategic_layer(
                strategic,
                metrics.strategic_time_ms,
                metrics.total_execution_time_ms,
            );
            
            if layer_perf.percentage_of_total > 40.0 {
                bottlenecks.push(PerformanceBottleneck {
                    name: "Strategic Layer Analysis".to_string(),
                    layer: AgentLayer::Strategic,
                    duration_ms: metrics.strategic_time_ms,
                    percentage_of_total: layer_perf.percentage_of_total,
                    severity: BottleneckSeverity::Critical,
                    recommendation: "Optimize context preparation or use session-based caching".to_string(),
                });
            }
            
            layer_breakdown.insert("strategic".to_string(), layer_perf);
        }
        
        // Analyze tactical layer
        if let Some(ref tactical) = metrics.tactical_breakdown {
            let layer_perf = Self::analyze_tactical_layer(
                tactical,
                metrics.tactical_time_ms,
                metrics.total_execution_time_ms,
            );
            
            if layer_perf.percentage_of_total > 40.0 {
                bottlenecks.push(PerformanceBottleneck {
                    name: "Tactical Layer Planning".to_string(),
                    layer: AgentLayer::Tactical,
                    duration_ms: metrics.tactical_time_ms,
                    percentage_of_total: layer_perf.percentage_of_total,
                    severity: BottleneckSeverity::Critical,
                    recommendation: "Parallelize tool execution or reduce context assembly overhead".to_string(),
                });
            }
            
            layer_breakdown.insert("tactical".to_string(), layer_perf);
        }
        
        // Analyze operational layer
        if let Some(ref operational) = metrics.operational_breakdown {
            let layer_perf = Self::analyze_operational_layer(
                operational,
                metrics.operational_time_ms,
                metrics.total_execution_time_ms,
            );
            
            if operational.retry_attempts > 0 {
                bottlenecks.push(PerformanceBottleneck {
                    name: format!("Response Generation Retries ({})", operational.retry_attempts),
                    layer: AgentLayer::Operational,
                    duration_ms: operational.retry_time_ms,
                    percentage_of_total: (operational.retry_time_ms as f32 / metrics.total_execution_time_ms as f32) * 100.0,
                    severity: BottleneckSeverity::High,
                    recommendation: "Improve prompt engineering to reduce safety filter triggers".to_string(),
                });
            }
            
            layer_breakdown.insert("operational".to_string(), layer_perf);
        }
        
        // Identify optimization opportunities
        optimization_opportunities.extend(Self::identify_optimization_opportunities(metrics, &layer_breakdown));
        
        // Calculate performance score
        let performance_score = Self::calculate_performance_score(metrics);
        
        // Sort bottlenecks by severity
        bottlenecks.sort_by(|a, b| b.percentage_of_total.partial_cmp(&a.percentage_of_total).unwrap());
        
        PerformanceAnalysisReport {
            timestamp: Utc::now(),
            total_time_ms: metrics.total_execution_time_ms,
            bottlenecks,
            layer_breakdown,
            optimization_opportunities,
            performance_score,
        }
    }
    
    fn analyze_perception_layer(
        breakdown: &PerceptionTimingBreakdown,
        total_layer_time: u64,
        total_pipeline_time: u64,
    ) -> LayerPerformance {
        LayerPerformance {
            layer: AgentLayer::Perception,
            total_time_ms: total_layer_time,
            ai_call_time_ms: breakdown.ai_call_ms,
            processing_time_ms: breakdown.response_processing_ms + breakdown.entity_creation_ms,
            percentage_of_total: (total_layer_time as f32 / total_pipeline_time as f32) * 100.0,
            ai_call_percentage: (breakdown.ai_call_ms as f32 / total_layer_time as f32) * 100.0,
        }
    }
    
    fn analyze_strategic_layer(
        breakdown: &StrategicTimingBreakdown,
        total_layer_time: u64,
        total_pipeline_time: u64,
    ) -> LayerPerformance {
        LayerPerformance {
            layer: AgentLayer::Strategic,
            total_time_ms: total_layer_time,
            ai_call_time_ms: breakdown.ai_call_ms,
            processing_time_ms: breakdown.context_preparation_ms + breakdown.response_parsing_ms + breakdown.validation_ms,
            percentage_of_total: (total_layer_time as f32 / total_pipeline_time as f32) * 100.0,
            ai_call_percentage: (breakdown.ai_call_ms as f32 / total_layer_time as f32) * 100.0,
        }
    }
    
    fn analyze_tactical_layer(
        breakdown: &TacticalTimingBreakdown,
        total_layer_time: u64,
        total_pipeline_time: u64,
    ) -> LayerPerformance {
        LayerPerformance {
            layer: AgentLayer::Tactical,
            total_time_ms: total_layer_time,
            ai_call_time_ms: breakdown.ai_call_ms,
            processing_time_ms: breakdown.context_assembly_ms + breakdown.plan_parsing_ms + 
                                breakdown.plan_validation_ms + breakdown.tool_execution_ms,
            percentage_of_total: (total_layer_time as f32 / total_pipeline_time as f32) * 100.0,
            ai_call_percentage: (breakdown.ai_call_ms as f32 / total_layer_time as f32) * 100.0,
        }
    }
    
    fn analyze_operational_layer(
        breakdown: &OperationalTimingBreakdown,
        total_layer_time: u64,
        total_pipeline_time: u64,
    ) -> LayerPerformance {
        LayerPerformance {
            layer: AgentLayer::Operational,
            total_time_ms: total_layer_time,
            ai_call_time_ms: breakdown.ai_call_ms,
            processing_time_ms: breakdown.template_building_ms + breakdown.retry_time_ms,
            percentage_of_total: (total_layer_time as f32 / total_pipeline_time as f32) * 100.0,
            ai_call_percentage: (breakdown.ai_call_ms as f32 / total_layer_time as f32) * 100.0,
        }
    }
    
    fn identify_optimization_opportunities(
        metrics: &PipelineMetrics,
        layer_breakdown: &HashMap<String, LayerPerformance>,
    ) -> Vec<OptimizationOpportunity> {
        let mut opportunities = Vec::new();
        
        // Check for parallel execution opportunity
        let sequential_time = metrics.perception_time_ms + metrics.strategic_time_ms;
        if sequential_time > metrics.total_execution_time_ms * 40 / 100 {
            opportunities.push(OptimizationOpportunity {
                title: "Parallel Agent Execution".to_string(),
                description: "Execute Perception and Strategic agents in parallel using tokio::join!".to_string(),
                potential_time_savings_ms: metrics.perception_time_ms.min(metrics.strategic_time_ms),
                implementation_complexity: ComplexityLevel::Medium,
                priority: OptimizationPriority::High,
            });
        }
        
        // Check for streaming opportunity
        if let Some(operational) = layer_breakdown.get("operational") {
            if operational.ai_call_time_ms > 2000 {
                opportunities.push(OptimizationOpportunity {
                    title: "Response Streaming".to_string(),
                    description: "Implement SSE streaming to reduce perceived latency".to_string(),
                    potential_time_savings_ms: operational.ai_call_time_ms / 2, // Perceived time savings
                    implementation_complexity: ComplexityLevel::High,
                    priority: OptimizationPriority::High,
                });
            }
        }
        
        // Check for caching opportunity
        if metrics.total_tokens_used > 5000 {
            opportunities.push(OptimizationOpportunity {
                title: "Context Caching".to_string(),
                description: "Cache frequently used context data across agent layers".to_string(),
                potential_time_savings_ms: metrics.total_execution_time_ms * 15 / 100, // Estimate 15% savings
                implementation_complexity: ComplexityLevel::Medium,
                priority: OptimizationPriority::Medium,
            });
        }
        
        // Check for model optimization
        if metrics.total_execution_time_ms > 30000 {
            opportunities.push(OptimizationOpportunity {
                title: "Conditional Agent Activation".to_string(),
                description: "Skip non-essential agents based on context analysis".to_string(),
                potential_time_savings_ms: metrics.total_execution_time_ms * 25 / 100, // Estimate 25% savings
                implementation_complexity: ComplexityLevel::High,
                priority: OptimizationPriority::Critical,
            });
        }
        
        opportunities
    }
    
    fn calculate_performance_score(metrics: &PipelineMetrics) -> f32 {
        // Base score starts at 100
        let mut score = 100.0;
        
        // Deduct points for total execution time
        if metrics.total_execution_time_ms > 10000 {
            score -= ((metrics.total_execution_time_ms - 10000) as f32 / 1000.0) * 2.0; // -2 points per second over 10s
        }
        
        // Deduct points for retries
        if let Some(ref operational) = metrics.operational_breakdown {
            score -= operational.retry_attempts as f32 * 5.0; // -5 points per retry
        }
        
        // Deduct points for low confidence
        if metrics.confidence_score < 0.8 {
            score -= (0.8 - metrics.confidence_score) * 20.0; // Up to -20 points for low confidence
        }
        
        // Ensure score is between 0 and 100
        score.max(0.0).min(100.0)
    }
    
    /// Generate a text-based performance report
    pub fn generate_text_report(report: &PerformanceAnalysisReport) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("=== Performance Analysis Report ===\n"));
        output.push_str(&format!("Timestamp: {}\n", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("Total Pipeline Time: {}ms\n", report.total_time_ms));
        output.push_str(&format!("Performance Score: {:.1}/100\n\n", report.performance_score));
        
        output.push_str("Layer Breakdown:\n");
        for (name, perf) in &report.layer_breakdown {
            output.push_str(&format!(
                "  {:12} {:6}ms ({:5.1}%) - AI Calls: {:5.1}%\n",
                name,
                perf.total_time_ms,
                perf.percentage_of_total,
                perf.ai_call_percentage,
            ));
        }
        
        if !report.bottlenecks.is_empty() {
            output.push_str("\nIdentified Bottlenecks:\n");
            for bottleneck in &report.bottlenecks {
                output.push_str(&format!(
                    "  [{:?}] {} - {}ms ({:.1}%)\n    Recommendation: {}\n",
                    bottleneck.severity,
                    bottleneck.name,
                    bottleneck.duration_ms,
                    bottleneck.percentage_of_total,
                    bottleneck.recommendation,
                ));
            }
        }
        
        if !report.optimization_opportunities.is_empty() {
            output.push_str("\nOptimization Opportunities:\n");
            for opp in &report.optimization_opportunities {
                output.push_str(&format!(
                    "  [{:?}] {} (Complexity: {:?})\n    {}\n    Potential Savings: {}ms\n",
                    opp.priority,
                    opp.title,
                    opp.implementation_complexity,
                    opp.description,
                    opp.potential_time_savings_ms,
                ));
            }
        }
        
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_performance_analyzer() {
        let metrics = PipelineMetrics {
            total_execution_time_ms: 40000,
            perception_time_ms: 8000,
            strategic_time_ms: 10000,
            tactical_time_ms: 12000,
            operational_time_ms: 10000,
            total_tokens_used: 6000,
            total_ai_calls: 4,
            confidence_score: 0.85,
            perception_breakdown: Some(PerceptionTimingBreakdown {
                ai_call_ms: 6000,
                response_processing_ms: 1500,
                entity_creation_ms: 500,
                hierarchy_analysis_ms: 0,
                salience_evaluation_ms: 0,
                entities_processed: 5,
            }),
            strategic_breakdown: Some(StrategicTimingBreakdown {
                context_preparation_ms: 1000,
                ai_call_ms: 8000,
                response_parsing_ms: 800,
                validation_ms: 200,
                messages_analyzed: 10,
            }),
            tactical_breakdown: Some(TacticalTimingBreakdown {
                context_assembly_ms: 2000,
                ai_call_ms: 8000,
                plan_parsing_ms: 1000,
                plan_validation_ms: 500,
                tool_execution_ms: 500,
                tools_planned: 3,
                tools_executed: 3,
            }),
            operational_breakdown: Some(OperationalTimingBreakdown {
                template_building_ms: 500,
                ai_call_ms: 8500,
                retry_time_ms: 1000,
                retry_attempts: 1,
                time_to_first_token_ms: None,
            }),
        };
        
        let report = PerformanceAnalyzer::analyze_pipeline_metrics(&metrics);
        
        // Verify bottlenecks are identified
        assert!(!report.bottlenecks.is_empty());
        
        // Verify optimization opportunities
        assert!(!report.optimization_opportunities.is_empty());
        
        // Check for parallel execution opportunity
        let has_parallel_opt = report.optimization_opportunities
            .iter()
            .any(|o| o.title.contains("Parallel"));
        assert!(has_parallel_opt);
        
        // Verify performance score calculation
        assert!(report.performance_score < 100.0); // Should be penalized for 40s execution
        assert!(report.performance_score > 0.0);
        
        // Test text report generation
        let text_report = PerformanceAnalyzer::generate_text_report(&report);
        assert!(text_report.contains("Performance Analysis Report"));
        assert!(text_report.contains("Layer Breakdown"));
        assert!(text_report.contains("Optimization Opportunities"));
    }
}