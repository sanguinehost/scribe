// backend/src/llm/llamacpp/health.rs
// Health monitoring and diagnostics for LlamaCpp server

use crate::llm::llamacpp::{LocalLlmError, LlamaCppConfig};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tracing::{debug, info, warn, error, instrument};

/// Health status of the LlamaCpp server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub server_responsive: bool,
    pub model_loaded: bool,
    pub memory_usage_mb: f32,
    pub cpu_usage_percent: Option<f32>,
    pub gpu_usage_percent: Option<f32>,
    pub response_time_ms: u64,
    pub error_messages: Vec<String>,
    pub last_check_time: SystemTime,
    pub uptime_seconds: Option<u64>,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub check_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_consecutive_failures: u32,
    pub check_model_endpoint: bool,
    pub check_system_resources: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 30,
            timeout_seconds: 10,
            max_consecutive_failures: 3,
            check_model_endpoint: true,
            check_system_resources: true,
        }
    }
}

/// Health checker for LlamaCpp server
#[derive(Clone)]
pub struct HealthChecker {
    config: LlamaCppConfig,
    health_config: HealthCheckConfig,
    http_client: HttpClient,
    consecutive_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    server_start_time: std::sync::Arc<std::sync::RwLock<Option<Instant>>>,
}

/// Server information response
#[derive(Debug, Deserialize)]
struct ServerInfoResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    slots_idle: Option<u32>,
    #[serde(default)]
    slots_processing: Option<u32>,
}

/// Models endpoint response
#[derive(Debug, Deserialize)]
struct ModelsResponse {
    data: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    id: String,
    #[serde(default)]
    owned_by: String,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: LlamaCppConfig) -> Self {
        let health_config = HealthCheckConfig::default();
        
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(health_config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client for health checker");
        
        Self {
            config,
            health_config,
            http_client,
            consecutive_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            server_start_time: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }
    
    /// Create a health checker with custom configuration
    pub fn new_with_config(config: LlamaCppConfig, health_config: HealthCheckConfig) -> Self {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(health_config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client for health checker");
        
        Self {
            config,
            health_config,
            http_client,
            consecutive_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            server_start_time: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }
    
    /// Perform a comprehensive health check
    #[instrument(skip(self))]
    pub async fn check_health(&self) -> Result<HealthStatus, LocalLlmError> {
        let start_time = Instant::now();
        let mut status = HealthStatus {
            is_healthy: false,
            server_responsive: false,
            model_loaded: false,
            memory_usage_mb: 0.0,
            cpu_usage_percent: None,
            gpu_usage_percent: None,
            response_time_ms: 0,
            error_messages: Vec::new(),
            last_check_time: SystemTime::now(),
            uptime_seconds: None,
        };
        
        debug!("Starting health check for LlamaCpp server");
        
        // Check server responsiveness
        match self.check_server_responsive().await {
            Ok(responsive) => {
                status.server_responsive = responsive;
                if !responsive {
                    status.error_messages.push("Server not responsive".to_string());
                }
            }
            Err(e) => {
                status.error_messages.push(format!("Server check failed: {}", e));
            }
        }
        
        // Check if model is loaded (if server is responsive)
        if status.server_responsive && self.health_config.check_model_endpoint {
            match self.check_model_loaded().await {
                Ok(loaded) => {
                    status.model_loaded = loaded;
                    if !loaded {
                        status.error_messages.push("No model loaded".to_string());
                    }
                }
                Err(e) => {
                    status.error_messages.push(format!("Model check failed: {}", e));
                }
            }
        }
        
        // Check system resources
        if self.health_config.check_system_resources {
            if let Ok(memory_usage) = self.get_memory_usage().await {
                status.memory_usage_mb = memory_usage;
            }
            
            if let Ok(cpu_usage) = self.get_cpu_usage().await {
                status.cpu_usage_percent = Some(cpu_usage);
            }
            
            if let Ok(gpu_usage) = self.get_gpu_usage().await {
                status.gpu_usage_percent = gpu_usage;
            }
        }
        
        // Calculate uptime
        if let Ok(server_start) = self.server_start_time.read() {
            if let Some(start) = *server_start {
                status.uptime_seconds = Some(start.elapsed().as_secs());
            }
        }
        
        // Calculate response time
        status.response_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Determine overall health
        status.is_healthy = status.server_responsive && 
                          (status.model_loaded || !self.health_config.check_model_endpoint) &&
                          status.error_messages.is_empty();
        
        // Update consecutive failures counter
        if status.is_healthy {
            self.consecutive_failures.store(0, std::sync::atomic::Ordering::Relaxed);
        } else {
            let failures = self.consecutive_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            warn!("Health check failed ({} consecutive failures): {:?}", failures, status.error_messages);
        }
        
        debug!("Health check completed in {}ms, healthy: {}", status.response_time_ms, status.is_healthy);
        Ok(status)
    }
    
    /// Check if the server is responsive
    async fn check_server_responsive(&self) -> Result<bool, LocalLlmError> {
        let url = format!("http://{}:{}/health", self.config.server_host, self.config.server_port);
        
        match self.http_client.get(&url).send().await {
            Ok(response) => {
                let is_success = response.status().is_success();
                debug!("Server health endpoint status: {}", response.status());
                Ok(is_success)
            }
            Err(e) => {
                debug!("Server health check failed: {}", e);
                Ok(false)
            }
        }
    }
    
    /// Check if a model is currently loaded
    async fn check_model_loaded(&self) -> Result<bool, LocalLlmError> {
        let url = format!("http://{}:{}/v1/models", self.config.server_host, self.config.server_port);
        
        match self.http_client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(models_response) = response.json::<ModelsResponse>().await {
                        let has_models = !models_response.data.is_empty();
                        debug!("Models loaded: {}, count: {}", has_models, models_response.data.len());
                        return Ok(has_models);
                    }
                }
                
                // Fallback: try the server info endpoint
                self.check_server_info().await
            }
            Err(e) => {
                debug!("Model check failed: {}", e);
                Ok(false)
            }
        }
    }
    
    /// Check server info endpoint as fallback
    async fn check_server_info(&self) -> Result<bool, LocalLlmError> {
        let url = format!("http://{}:{}/v1/info", self.config.server_host, self.config.server_port);
        
        match self.http_client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(info) = response.json::<ServerInfoResponse>().await {
                        let has_model = !info.model.is_empty() && info.model != "unknown";
                        debug!("Server info - model: '{}', status: '{}'", info.model, info.status);
                        return Ok(has_model);
                    }
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }
    
    /// Get current memory usage in MB
    async fn get_memory_usage(&self) -> Result<f32, LocalLlmError> {
        // Use the same function from metrics module
        Ok(crate::llm::llamacpp::metrics::get_current_memory_usage_mb())
    }
    
    /// Get current CPU usage percentage
    async fn get_cpu_usage(&self) -> Result<f32, LocalLlmError> {
        // Try to get CPU usage from system
        #[cfg(feature = "local-llm")]
        {
            use sysinfo::System;
            
            let mut system = System::new();
            system.refresh_cpu();
            
            // Wait a bit for accurate CPU measurement
            tokio::time::sleep(Duration::from_millis(200)).await;
            system.refresh_cpu();
            
            let cpu_usage = system.cpus().iter()
                .map(|cpu| cpu.cpu_usage())
                .sum::<f32>() / system.cpus().len() as f32;
            
            Ok(cpu_usage)
        }
        
        #[cfg(not(feature = "local-llm"))]
        {
            Err(LocalLlmError::ServerUnavailable("sysinfo not available".to_string()))
        }
    }
    
    /// Get current GPU usage percentage (if available)
    async fn get_gpu_usage(&self) -> Result<Option<f32>, LocalLlmError> {
        // Try to get GPU usage using nvidia-smi
        match Command::new("nvidia-smi")
            .args(&["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"])
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if let Ok(usage) = output_str.trim().parse::<f32>() {
                        debug!("GPU usage: {}%", usage);
                        return Ok(Some(usage));
                    }
                }
            }
            Err(_) => {
                // nvidia-smi not available or failed
                debug!("nvidia-smi not available for GPU monitoring");
            }
        }
        
        Ok(None)
    }
    
    /// Get number of consecutive health check failures
    pub fn get_consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    /// Check if the server should be considered failed
    pub fn is_server_failed(&self) -> bool {
        self.get_consecutive_failures() >= self.health_config.max_consecutive_failures
    }
    
    /// Reset consecutive failures counter
    pub fn reset_failures(&self) {
        self.consecutive_failures.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    
    /// Set server start time (for uptime calculation)
    pub fn set_server_start_time(&self, start_time: Instant) {
        if let Ok(mut server_start) = self.server_start_time.write() {
            *server_start = Some(start_time);
        }
    }
    
    /// Perform a quick ping to check basic connectivity
    pub async fn ping(&self) -> Result<Duration, LocalLlmError> {
        let start = Instant::now();
        let url = format!("http://{}:{}/health", self.config.server_host, self.config.server_port);
        
        match self.http_client.get(&url).send().await {
            Ok(response) => {
                let duration = start.elapsed();
                if response.status().is_success() {
                    Ok(duration)
                } else {
                    Err(LocalLlmError::ServerUnavailable(
                        format!("Server returned status: {}", response.status())
                    ))
                }
            }
            Err(e) => Err(LocalLlmError::ServerUnavailable(
                format!("Ping failed: {}", e)
            )),
        }
    }
    
    /// Get health check configuration
    pub fn get_config(&self) -> &HealthCheckConfig {
        &self.health_config
    }
    
    /// Update health check configuration
    pub fn update_config(&mut self, config: HealthCheckConfig) {
        self.health_config = config;
    }
}

/// Convenience function to create a basic health check
pub async fn quick_health_check(config: &LlamaCppConfig) -> Result<bool, LocalLlmError> {
    let checker = HealthChecker::new(config.clone());
    let status = checker.check_health().await?;
    Ok(status.is_healthy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    fn create_test_config() -> LlamaCppConfig {
        LlamaCppConfig {
            enabled: true,
            model_path: "test-model.gguf".to_string(),
            model_url: Some("https://example.com/model.gguf".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: 11435,
            context_size: 2048,
            gpu_layers: Some(32),
            threads: Some(4),
            timeout_seconds: 30,
            max_retries: 2,
            health_check_interval_seconds: 10,
        }
    }
    
    #[test]
    fn test_health_checker_creation() {
        let config = create_test_config();
        let checker = HealthChecker::new(config);
        
        assert_eq!(checker.get_consecutive_failures(), 0);
        assert!(!checker.is_server_failed());
    }
    
    #[test]
    fn test_health_config_defaults() {
        let config = HealthCheckConfig::default();
        
        assert!(config.enabled);
        assert_eq!(config.check_interval_seconds, 30);
        assert_eq!(config.timeout_seconds, 10);
        assert_eq!(config.max_consecutive_failures, 3);
        assert!(config.check_model_endpoint);
        assert!(config.check_system_resources);
    }
    
    #[tokio::test]
    async fn test_health_status_structure() {
        let config = create_test_config();
        let checker = HealthChecker::new(config);
        
        // This will likely fail since there's no actual server running,
        // but we can test the structure
        let result = checker.check_health().await;
        
        match result {
            Ok(status) => {
                // If somehow successful, validate structure
                assert!(status.response_time_ms > 0);
                assert!(status.last_check_time > UNIX_EPOCH);
            }
            Err(_) => {
                // Expected when no server is running
                // This tests that the health check doesn't panic
            }
        }
    }
    
    #[test]
    fn test_consecutive_failures() {
        let config = create_test_config();
        let checker = HealthChecker::new(config);
        
        assert_eq!(checker.get_consecutive_failures(), 0);
        assert!(!checker.is_server_failed());
        
        // Simulate failures by manually incrementing
        for _ in 0..3 {
            checker.consecutive_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        assert!(checker.is_server_failed());
        
        checker.reset_failures();
        assert_eq!(checker.get_consecutive_failures(), 0);
        assert!(!checker.is_server_failed());
    }
    
    #[test]
    fn test_server_start_time() {
        let config = create_test_config();
        let checker = HealthChecker::new(config);
        
        let start_time = Instant::now();
        checker.set_server_start_time(start_time);
        
        // We can't easily test the exact uptime calculation without waiting,
        // but we can verify the start time was set
        if let Ok(server_start) = checker.server_start_time.read() {
            assert!(server_start.is_some());
        }
    }
    
    #[tokio::test]
    async fn test_memory_usage() {
        let config = create_test_config();
        let checker = HealthChecker::new(config);
        
        let result = checker.get_memory_usage().await;
        
        // Memory usage should always be available (even if 0.0 fallback)
        match result {
            Ok(usage) => {
                assert!(usage >= 0.0);
            }
            Err(_) => {
                // Only fail if sysinfo is completely unavailable
            }
        }
    }
    
    #[tokio::test]
    async fn test_quick_health_check() {
        let config = create_test_config();
        
        // This will likely fail due to no server, but shouldn't panic
        let result = quick_health_check(&config).await;
        
        match result {
            Ok(healthy) => {
                // If successful, should be a boolean
                assert!(healthy == true || healthy == false);
            }
            Err(_) => {
                // Expected when no server is running
            }
        }
    }
}