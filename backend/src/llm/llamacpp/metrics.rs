// backend/src/llm/llamacpp/metrics.rs
// Performance metrics collection and monitoring for LlamaCpp

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Performance metrics for a single inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub tokens_per_second: f32,
    pub time_to_first_token_ms: u64,
    pub total_inference_time_ms: u64,
    pub queue_depth: usize,
    pub memory_usage_mb: f32,
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub model_name: String,
    pub timestamp: std::time::SystemTime,
}

impl PerformanceMetrics {
    pub fn new(
        model_name: String,
        prompt_tokens: usize,
        completion_tokens: usize,
        start_time: Instant,
        first_token_time: Option<Instant>,
        memory_usage_mb: f32,
        queue_depth: usize,
    ) -> Self {
        let total_time = start_time.elapsed();
        let total_inference_time_ms = total_time.as_millis() as u64;
        
        let time_to_first_token_ms = first_token_time
            .map(|ft| ft.duration_since(start_time).as_millis() as u64)
            .unwrap_or(total_inference_time_ms);
            
        let tokens_per_second = if total_time.as_secs_f32() > 0.0 {
            completion_tokens as f32 / total_time.as_secs_f32()
        } else {
            0.0
        };

        Self {
            tokens_per_second,
            time_to_first_token_ms,
            total_inference_time_ms,
            queue_depth,
            memory_usage_mb,
            prompt_tokens,
            completion_tokens,
            model_name,
            timestamp: std::time::SystemTime::now(),
        }
    }
}

/// Trait for collecting and reporting metrics
pub trait MetricsCollector: Send + Sync {
    fn record_inference(&mut self, metrics: PerformanceMetrics);
    fn get_p95_latency(&self) -> Duration;
    fn get_throughput(&self) -> f32;
    fn get_average_queue_depth(&self) -> f32;
    fn get_memory_usage(&self) -> f32;
    fn get_total_requests(&self) -> u64;
    fn get_error_rate(&self) -> f32;
    fn record_error(&mut self, error_type: String);
}

/// In-memory metrics collector with rolling window
pub struct InMemoryMetricsCollector {
    metrics: VecDeque<PerformanceMetrics>,
    errors: VecDeque<(std::time::SystemTime, String)>,
    max_history: usize,
    total_requests: u64,
    total_errors: u64,
}

impl InMemoryMetricsCollector {
    pub fn new(max_history: usize) -> Self {
        Self {
            metrics: VecDeque::with_capacity(max_history),
            errors: VecDeque::new(),
            max_history,
            total_requests: 0,
            total_errors: 0,
        }
    }

    fn cleanup_old_entries(&mut self) {
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(3600); // Keep 1 hour
        
        // Clean old metrics
        while let Some(front) = self.metrics.front() {
            if front.timestamp < cutoff {
                self.metrics.pop_front();
            } else {
                break;
            }
        }
        
        // Clean old errors
        while let Some((timestamp, _)) = self.errors.front() {
            if *timestamp < cutoff {
                self.errors.pop_front();
            } else {
                break;
            }
        }
    }
}

impl MetricsCollector for InMemoryMetricsCollector {
    fn record_inference(&mut self, metrics: PerformanceMetrics) {
        debug!(
            "Recording inference metrics: {:.2} tokens/sec, {}ms total, {}ms to first token",
            metrics.tokens_per_second,
            metrics.total_inference_time_ms,
            metrics.time_to_first_token_ms
        );
        
        self.total_requests += 1;
        
        if self.metrics.len() >= self.max_history {
            self.metrics.pop_front();
        }
        
        self.metrics.push_back(metrics);
        self.cleanup_old_entries();
    }

    fn get_p95_latency(&self) -> Duration {
        if self.metrics.is_empty() {
            return Duration::from_millis(0);
        }

        let mut latencies: Vec<u64> = self.metrics
            .iter()
            .map(|m| m.total_inference_time_ms)
            .collect();
        
        latencies.sort_unstable();
        let index = (latencies.len() as f64 * 0.95) as usize;
        let p95_ms = latencies.get(index.saturating_sub(1)).copied().unwrap_or(0);
        
        Duration::from_millis(p95_ms)
    }

    fn get_throughput(&self) -> f32 {
        if self.metrics.is_empty() {
            return 0.0;
        }

        let total_tokens: f32 = self.metrics
            .iter()
            .map(|m| m.tokens_per_second)
            .sum();
            
        total_tokens / self.metrics.len() as f32
    }

    fn get_average_queue_depth(&self) -> f32 {
        if self.metrics.is_empty() {
            return 0.0;
        }

        let total_depth: usize = self.metrics
            .iter()
            .map(|m| m.queue_depth)
            .sum();
            
        total_depth as f32 / self.metrics.len() as f32
    }

    fn get_memory_usage(&self) -> f32 {
        self.metrics
            .back()
            .map(|m| m.memory_usage_mb)
            .unwrap_or(0.0)
    }

    fn get_total_requests(&self) -> u64 {
        self.total_requests
    }

    fn get_error_rate(&self) -> f32 {
        if self.total_requests == 0 {
            return 0.0;
        }
        
        self.total_errors as f32 / self.total_requests as f32
    }

    fn record_error(&mut self, error_type: String) {
        self.total_errors += 1;
        self.errors.push_back((std::time::SystemTime::now(), error_type));
        
        if self.errors.len() > self.max_history {
            self.errors.pop_front();
        }
    }
}

/// Thread-safe metrics collector wrapper
pub struct LlamaCppMetrics {
    collector: Arc<Mutex<dyn MetricsCollector>>,
}

impl LlamaCppMetrics {
    pub fn new() -> Self {
        Self {
            collector: Arc::new(Mutex::new(InMemoryMetricsCollector::new(1000))),
        }
    }

    pub fn with_collector(collector: Arc<Mutex<dyn MetricsCollector>>) -> Self {
        Self { collector }
    }

    pub fn record_inference(&self, metrics: PerformanceMetrics) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_inference(metrics);
        }
    }

    pub fn record_error(&self, error_type: String) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_error(error_type);
        }
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        if let Ok(collector) = self.collector.lock() {
            MetricsSnapshot {
                p95_latency_ms: collector.get_p95_latency().as_millis() as u64,
                average_throughput: collector.get_throughput(),
                average_queue_depth: collector.get_average_queue_depth(),
                current_memory_mb: collector.get_memory_usage(),
                total_requests: collector.get_total_requests(),
                error_rate: collector.get_error_rate(),
            }
        } else {
            MetricsSnapshot::default()
        }
    }

    pub fn log_stats(&self) {
        let stats = self.get_stats();
        info!(
            "LlamaCpp metrics - Requests: {}, P95 latency: {}ms, Throughput: {:.2} tok/s, Error rate: {:.2}%",
            stats.total_requests,
            stats.p95_latency_ms,
            stats.average_throughput,
            stats.error_rate * 100.0
        );
    }
}

impl Clone for LlamaCppMetrics {
    fn clone(&self) -> Self {
        Self {
            collector: Arc::clone(&self.collector),
        }
    }
}

impl Default for LlamaCppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of current metrics state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub p95_latency_ms: u64,
    pub average_throughput: f32,
    pub average_queue_depth: f32,
    pub current_memory_mb: f32,
    pub total_requests: u64,
    pub error_rate: f32,
}

impl Default for MetricsSnapshot {
    fn default() -> Self {
        Self {
            p95_latency_ms: 0,
            average_throughput: 0.0,
            average_queue_depth: 0.0,
            current_memory_mb: 0.0,
            total_requests: 0,
            error_rate: 0.0,
        }
    }
}

/// Helper function to get current memory usage (platform-specific)
pub fn get_current_memory_usage_mb() -> f32 {
    #[cfg(feature = "local-llm")]
    {
        use sysinfo::{System, Pid};
        
        let mut system = System::new();
        if let Ok(current_pid) = sysinfo::get_current_pid() {
            system.refresh_process(current_pid);
            
            if let Some(process) = system.process(current_pid) {
                return process.memory() as f32 / (1024.0 * 1024.0); // Convert bytes to MB
            }
        }
    }
    
    0.0 // Fallback if sysinfo is not available
}

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub metrics_history_size: usize,
    pub log_interval_seconds: u64,
    pub export_prometheus: bool,
    pub export_file_path: Option<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_history_size: 1000,
            log_interval_seconds: 60,
            export_prometheus: false,
            export_file_path: None,
        }
    }
}

/// Background task for periodic metrics logging
pub struct MetricsLogger {
    metrics: LlamaCppMetrics,
    config: MonitoringConfig,
}

impl MetricsLogger {
    pub fn new(metrics: LlamaCppMetrics, config: MonitoringConfig) -> Self {
        Self { metrics, config }
    }

    pub async fn start_logging_task(&self) {
        if !self.config.enable_metrics {
            return;
        }

        let metrics = self.metrics.clone();
        let interval = Duration::from_secs(self.config.log_interval_seconds);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            
            loop {
                interval.tick().await;
                metrics.log_stats();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_metrics_creation() {
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(100));
        let first_token = Some(Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        
        let metrics = PerformanceMetrics::new(
            "test-model".to_string(),
            100,
            50,
            start,
            first_token,
            512.0,
            2,
        );

        assert_eq!(metrics.model_name, "test-model");
        assert_eq!(metrics.prompt_tokens, 100);
        assert_eq!(metrics.completion_tokens, 50);
        assert!(metrics.total_inference_time_ms >= 150);
        assert!(metrics.time_to_first_token_ms >= 100);
        assert!(metrics.tokens_per_second > 0.0);
    }

    #[test]
    fn test_metrics_collector() {
        let mut collector = InMemoryMetricsCollector::new(10);
        
        let metrics = PerformanceMetrics::new(
            "test".to_string(),
            50,
            25,
            Instant::now(),
            None,
            256.0,
            1,
        );
        
        collector.record_inference(metrics.clone());
        
        assert_eq!(collector.get_total_requests(), 1);
        assert!(collector.get_throughput() >= 0.0);
        assert_eq!(collector.get_memory_usage(), 256.0);
    }

    #[test]
    fn test_p95_latency_calculation() {
        let mut collector = InMemoryMetricsCollector::new(100);
        
        // Add metrics with known latencies
        for i in 0..100 {
            let start = Instant::now() - Duration::from_millis(i);
            let metrics = PerformanceMetrics::new(
                "test".to_string(),
                10,
                10,
                start,
                None,
                100.0,
                1,
            );
            collector.record_inference(metrics);
        }
        
        let p95 = collector.get_p95_latency();
        assert!(p95.as_millis() > 0);
    }

    #[test]
    fn test_error_rate_tracking() {
        let mut collector = InMemoryMetricsCollector::new(10);
        
        // Record some successful requests
        for _ in 0..8 {
            let metrics = PerformanceMetrics::new(
                "test".to_string(),
                10,
                10,
                Instant::now(),
                None,
                100.0,
                1,
            );
            collector.record_inference(metrics);
        }
        
        // Record some errors
        for _ in 0..2 {
            collector.record_error("timeout".to_string());
        }
        
        let error_rate = collector.get_error_rate();
        assert!((error_rate - 0.2).abs() < 0.01); // 2 errors out of 10 total = 20%
    }

    #[test]
    fn test_thread_safe_metrics() {
        let metrics = LlamaCppMetrics::new();
        
        let perf_metrics = PerformanceMetrics::new(
            "test".to_string(),
            20,
            15,
            Instant::now(),
            None,
            128.0,
            3,
        );
        
        metrics.record_inference(perf_metrics);
        metrics.record_error("test_error".to_string());
        
        let stats = metrics.get_stats();
        assert_eq!(stats.total_requests, 1);
        assert!(stats.error_rate > 0.0);
    }

    #[test]
    fn test_metrics_snapshot_serialization() {
        let snapshot = MetricsSnapshot {
            p95_latency_ms: 500,
            average_throughput: 10.5,
            average_queue_depth: 2.3,
            current_memory_mb: 1024.0,
            total_requests: 100,
            error_rate: 0.05,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.p95_latency_ms, 500);
        assert!((deserialized.average_throughput - 10.5).abs() < 0.01);
    }
}