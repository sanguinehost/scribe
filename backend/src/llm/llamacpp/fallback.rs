// backend/src/llm/llamacpp/fallback.rs
// Resilience patterns: circuit breaker, retry logic, and fallback strategies

use crate::llm::llamacpp::{LocalLlmError, LlamaCppConfig};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    /// Circuit is closed - requests flow normally
    Closed,
    /// Circuit is open - requests are blocked
    Open,
    /// Circuit is half-open - testing if service has recovered
    HalfOpen,
}

/// Fallback strategies when local LLM is unavailable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FallbackStrategy {
    /// Fail immediately without fallback
    Fail,
    /// Fallback to remote API (Gemini)
    RemoteApi,
    /// Queue request for later retry
    Queue,
    /// Return cached response if available
    Cache,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub success_threshold: u32,
    pub request_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 3,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f32,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Circuit breaker metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerMetrics {
    pub state: CircuitBreakerState,
    pub failure_count: u32,
    pub success_count: u32,
    #[serde(skip)]
    pub last_failure_time: Option<Instant>,
    #[serde(skip)]
    #[serde(default = "Instant::now")]
    pub last_state_change: Instant,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub blocked_requests: u64,
}

impl Default for CircuitBreakerMetrics {
    fn default() -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            blocked_requests: 0,
        }
    }
}

/// Circuit breaker implementation
#[derive(Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    metrics: Arc<RwLock<CircuitBreakerMetrics>>,
}

/// LlamaCpp resilience wrapper with circuit breaker and retry logic
#[derive(Clone)]
pub struct LlamaCppResilience {
    config: LlamaCppConfig,
    circuit_breaker: CircuitBreaker,
    retry_config: RetryConfig,
    fallback_strategy: FallbackStrategy,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let metrics = CircuitBreakerMetrics {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            blocked_requests: 0,
        };
        
        Self {
            config,
            metrics: Arc::new(RwLock::new(metrics)),
        }
    }
    
    /// Execute a request through the circuit breaker
    #[instrument(skip(self, request))]
    pub async fn execute<F, Fut, T>(&self, request: F) -> Result<T, LocalLlmError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, LocalLlmError>>,
    {
        if !self.config.enabled {
            return request().await;
        }
        
        // Check if circuit breaker allows request
        if !self.can_execute().await {
            let mut metrics = self.metrics.write().await;
            metrics.total_requests += 1;
            metrics.blocked_requests += 1;
            drop(metrics);
            
            return Err(LocalLlmError::FallbackTriggered {
                reason: "Circuit breaker is open".to_string(),
            });
        }
        
        // Execute request with timeout
        let start_time = Instant::now();
        let result = tokio::time::timeout(self.config.request_timeout, request()).await;
        
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;
        
        match result {
            Ok(Ok(response)) => {
                // Success
                metrics.successful_requests += 1;
                self.on_success(&mut metrics).await;
                debug!("Circuit breaker: request succeeded in {:?}", start_time.elapsed());
                Ok(response)
            }
            Ok(Err(error)) => {
                // Request failed
                metrics.failed_requests += 1;
                self.on_failure(&mut metrics).await;
                warn!("Circuit breaker: request failed: {}", error);
                Err(error)
            }
            Err(_) => {
                // Timeout
                metrics.failed_requests += 1;
                self.on_failure(&mut metrics).await;
                warn!("Circuit breaker: request timed out after {:?}", self.config.request_timeout);
                Err(LocalLlmError::ServerUnavailable("Request timeout".to_string()))
            }
        }
    }
    
    /// Check if the circuit breaker allows execution
    async fn can_execute(&self) -> bool {
        let mut metrics = self.metrics.write().await;
        
        match metrics.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if recovery timeout has passed
                if metrics.last_state_change.elapsed() >= self.config.recovery_timeout {
                    debug!("Circuit breaker: transitioning to half-open");
                    metrics.state = CircuitBreakerState::HalfOpen;
                    metrics.last_state_change = Instant::now();
                    true
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }
    
    /// Handle successful request
    async fn on_success(&self, metrics: &mut CircuitBreakerMetrics) {
        match metrics.state {
            CircuitBreakerState::Closed => {
                metrics.failure_count = 0;
            }
            CircuitBreakerState::HalfOpen => {
                metrics.success_count += 1;
                if metrics.success_count >= self.config.success_threshold {
                    debug!("Circuit breaker: transitioning to closed (recovered)");
                    metrics.state = CircuitBreakerState::Closed;
                    metrics.failure_count = 0;
                    metrics.success_count = 0;
                    metrics.last_state_change = Instant::now();
                }
            }
            CircuitBreakerState::Open => {
                // Should not happen, but reset if it does
                warn!("Circuit breaker: unexpected success in open state");
                metrics.state = CircuitBreakerState::Closed;
                metrics.failure_count = 0;
                metrics.success_count = 0;
                metrics.last_state_change = Instant::now();
            }
        }
    }
    
    /// Handle failed request
    async fn on_failure(&self, metrics: &mut CircuitBreakerMetrics) {
        metrics.last_failure_time = Some(Instant::now());
        
        match metrics.state {
            CircuitBreakerState::Closed => {
                metrics.failure_count += 1;
                if metrics.failure_count >= self.config.failure_threshold {
                    warn!("Circuit breaker: transitioning to open (threshold reached)");
                    metrics.state = CircuitBreakerState::Open;
                    metrics.last_state_change = Instant::now();
                }
            }
            CircuitBreakerState::HalfOpen => {
                warn!("Circuit breaker: transitioning to open (half-open failed)");
                metrics.state = CircuitBreakerState::Open;
                metrics.failure_count += 1;
                metrics.success_count = 0;
                metrics.last_state_change = Instant::now();
            }
            CircuitBreakerState::Open => {
                metrics.failure_count += 1;
            }
        }
    }
    
    /// Get current circuit breaker metrics
    pub async fn get_metrics(&self) -> CircuitBreakerMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Force circuit breaker to open state
    pub async fn force_open(&self) {
        let mut metrics = self.metrics.write().await;
        info!("Circuit breaker: forced to open state");
        metrics.state = CircuitBreakerState::Open;
        metrics.last_state_change = Instant::now();
    }
    
    /// Force circuit breaker to closed state
    pub async fn force_closed(&self) {
        let mut metrics = self.metrics.write().await;
        info!("Circuit breaker: forced to closed state");
        metrics.state = CircuitBreakerState::Closed;
        metrics.failure_count = 0;
        metrics.success_count = 0;
        metrics.last_state_change = Instant::now();
    }
    
    /// Reset circuit breaker statistics
    pub async fn reset(&self) {
        let mut metrics = self.metrics.write().await;
        info!("Circuit breaker: resetting statistics");
        metrics.failure_count = 0;
        metrics.success_count = 0;
        metrics.total_requests = 0;
        metrics.successful_requests = 0;
        metrics.failed_requests = 0;
        metrics.blocked_requests = 0;
        metrics.last_failure_time = None;
    }
}

impl LlamaCppResilience {
    /// Create a new resilience wrapper
    pub fn new(config: LlamaCppConfig) -> Self {
        let circuit_breaker_config = CircuitBreakerConfig::default();
        let circuit_breaker = CircuitBreaker::new(circuit_breaker_config);
        
        Self {
            config,
            circuit_breaker,
            retry_config: RetryConfig::default(),
            fallback_strategy: FallbackStrategy::RemoteApi,
        }
    }
    
    /// Create with custom configuration
    pub fn new_with_config(
        config: LlamaCppConfig,
        circuit_breaker_config: CircuitBreakerConfig,
        retry_config: RetryConfig,
        fallback_strategy: FallbackStrategy,
    ) -> Self {
        let circuit_breaker = CircuitBreaker::new(circuit_breaker_config);
        
        Self {
            config,
            circuit_breaker,
            retry_config,
            fallback_strategy,
        }
    }
    
    /// Execute request with retry logic and circuit breaker
    #[instrument(skip(self, operation))]
    pub async fn execute_with_retry<F, T>(&self, mut operation: impl FnMut() -> F) -> Result<T, LocalLlmError>
    where
        F: std::future::Future<Output = Result<T, LocalLlmError>>,
    {
        if !self.retry_config.enabled {
            return operation().await;
        }
        
        let mut last_error = None;
        let mut delay = self.retry_config.initial_delay;
        
        for attempt in 1..=self.retry_config.max_attempts {
            debug!("Resilience: attempt {} of {}", attempt, self.retry_config.max_attempts);
            
            let result = operation().await;
            
            match result {
                Ok(response) => {
                    if attempt > 1 {
                        info!("Resilience: request succeeded after {} attempts", attempt);
                    }
                    return Ok(response);
                }
                Err(error) => {
                    last_error = Some(error.clone());
                    
                    // Don't retry circuit breaker blocks or certain error types
                    if matches!(error, LocalLlmError::FallbackTriggered { .. }) ||
                       matches!(error, LocalLlmError::SecurityViolation(_)) {
                        debug!("Resilience: not retrying error type: {}", error);
                        return Err(error);
                    }
                    
                    // Don't sleep after last attempt
                    if attempt < self.retry_config.max_attempts {
                        let sleep_duration = self.calculate_delay(delay, attempt);
                        warn!("Resilience: attempt {} failed, retrying in {:?}: {}", attempt, sleep_duration, error);
                        tokio::time::sleep(sleep_duration).await;
                        
                        delay = std::cmp::min(
                            Duration::from_secs_f32(delay.as_secs_f32() * self.retry_config.backoff_multiplier),
                            self.retry_config.max_delay
                        );
                    }
                }
            }
        }
        
        let final_error = last_error.unwrap_or_else(|| {
            LocalLlmError::ServerUnavailable("All retry attempts failed".to_string())
        });
        
        error!("Resilience: all {} attempts failed, applying fallback strategy: {:?}", 
               self.retry_config.max_attempts, self.fallback_strategy);
        
        // Apply fallback strategy
        match self.fallback_strategy {
            FallbackStrategy::Fail => Err(final_error),
            FallbackStrategy::RemoteApi => {
                Err(LocalLlmError::FallbackTriggered {
                    reason: format!("Local LLM failed after {} attempts, should fallback to remote API", self.retry_config.max_attempts),
                })
            }
            FallbackStrategy::Queue => {
                Err(LocalLlmError::FallbackTriggered {
                    reason: "Request queued for later retry".to_string(),
                })
            }
            FallbackStrategy::Cache => {
                Err(LocalLlmError::FallbackTriggered {
                    reason: "Should return cached response if available".to_string(),
                })
            }
        }
    }
    
    /// Calculate delay with optional jitter
    fn calculate_delay(&self, base_delay: Duration, attempt: u32) -> Duration {
        if !self.retry_config.jitter {
            return base_delay;
        }
        
        // Add up to 25% jitter to prevent thundering herd
        use rand::Rng;
        let jitter_factor = rand::rng().random_range(0.75..=1.25);
        let jittered_delay = Duration::from_secs_f32(base_delay.as_secs_f32() * jitter_factor);
        
        std::cmp::min(jittered_delay, self.retry_config.max_delay)
    }
    
    /// Get circuit breaker metrics
    pub async fn get_circuit_breaker_metrics(&self) -> CircuitBreakerMetrics {
        self.circuit_breaker.get_metrics().await
    }
    
    /// Force circuit breaker open
    pub async fn force_circuit_breaker_open(&self) {
        self.circuit_breaker.force_open().await;
    }
    
    /// Force circuit breaker closed
    pub async fn force_circuit_breaker_closed(&self) {
        self.circuit_breaker.force_closed().await;
    }
    
    /// Reset circuit breaker
    pub async fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset().await;
    }
    
    /// Update fallback strategy
    pub fn set_fallback_strategy(&mut self, strategy: FallbackStrategy) {
        self.fallback_strategy = strategy;
    }
    
    /// Get current fallback strategy
    pub fn get_fallback_strategy(&self) -> &FallbackStrategy {
        &self.fallback_strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    
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
            enable_tool_calling: false,
            parallel_requests: Some(1),
            chat_template: None,
        }
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_creation() {
        let config = CircuitBreakerConfig::default();
        let circuit_breaker = CircuitBreaker::new(config);
        
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Closed);
        assert_eq!(metrics.failure_count, 0);
        assert_eq!(metrics.total_requests, 0);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_success() {
        let config = CircuitBreakerConfig::default();
        let circuit_breaker = CircuitBreaker::new(config);
        
        // Execute successful request
        let result = circuit_breaker.execute(|| async {
            Ok::<String, LocalLlmError>("success".to_string())
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Closed);
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.total_requests, 1);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_failure() {
        let mut config = CircuitBreakerConfig::default();
        config.failure_threshold = 2; // Lower threshold for testing
        let circuit_breaker = CircuitBreaker::new(config);
        
        // Execute failing request
        let result = circuit_breaker.execute(|| async {
            Err::<String, LocalLlmError>(LocalLlmError::ServerUnavailable("test error".to_string()))
        }).await;
        
        assert!(result.is_err());
        
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Closed);
        assert_eq!(metrics.failed_requests, 1);
        assert_eq!(metrics.failure_count, 1);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_opens() {
        let mut config = CircuitBreakerConfig::default();
        config.failure_threshold = 2;
        let circuit_breaker = CircuitBreaker::new(config);
        
        // Execute enough failing requests to open circuit
        for _ in 0..2 {
            let _ = circuit_breaker.execute(|| async {
                Err::<String, LocalLlmError>(LocalLlmError::ServerUnavailable("test error".to_string()))
            }).await;
        }
        
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Open);
        
        // Next request should be blocked
        let result = circuit_breaker.execute(|| async {
            Ok::<String, LocalLlmError>("should be blocked".to_string())
        }).await;
        
        assert!(result.is_err());
        if let Err(LocalLlmError::FallbackTriggered { reason }) = result {
            assert!(reason.contains("Circuit breaker is open"));
        }
    }
    
    #[tokio::test]
    async fn test_resilience_retry() {
        let config = create_test_config();
        let mut retry_config = RetryConfig::default();
        retry_config.max_attempts = 3;
        retry_config.initial_delay = Duration::from_millis(1); // Fast for testing
        
        let resilience = LlamaCppResilience::new_with_config(
            config,
            CircuitBreakerConfig::default(),
            retry_config,
            FallbackStrategy::Fail,
        );
        
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = Arc::clone(&attempt_count);
        
        let result = resilience.execute_with_retry(|| {
            let count = attempt_count_clone.clone();
            async move {
                let current = count.fetch_add(1, Ordering::Relaxed) + 1;
                if current < 3 {
                    Err(LocalLlmError::ServerUnavailable("not ready yet".to_string()))
                } else {
                    Ok("success after retries".to_string())
                }
            }
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success after retries");
        assert_eq!(attempt_count.load(Ordering::Relaxed), 3);
    }
    
    #[tokio::test]
    async fn test_fallback_strategies() {
        let config = create_test_config();
        
        // Test RemoteApi fallback
        let mut resilience = LlamaCppResilience::new(config.clone());
        resilience.set_fallback_strategy(FallbackStrategy::RemoteApi);
        
        let result = resilience.execute_with_retry(|| async {
            Err::<String, LocalLlmError>(LocalLlmError::ServerUnavailable("always fails".to_string()))
        }).await;
        
        assert!(result.is_err());
        if let Err(LocalLlmError::FallbackTriggered { reason }) = result {
            assert!(reason.contains("remote API"));
        }
        
        // Test Fail fallback
        resilience.set_fallback_strategy(FallbackStrategy::Fail);
        let result = resilience.execute_with_retry(|| async {
            Err::<String, LocalLlmError>(LocalLlmError::ServerUnavailable("always fails".to_string()))
        }).await;
        
        assert!(result.is_err());
        assert!(matches!(result, Err(LocalLlmError::ServerUnavailable(_))));
    }
    
    #[test]
    fn test_configuration_defaults() {
        let cb_config = CircuitBreakerConfig::default();
        assert!(cb_config.enabled);
        assert_eq!(cb_config.failure_threshold, 5);
        assert_eq!(cb_config.success_threshold, 3);
        
        let retry_config = RetryConfig::default();
        assert!(retry_config.enabled);
        assert_eq!(retry_config.max_attempts, 3);
        assert!(retry_config.jitter);
    }
    
    #[tokio::test]
    async fn test_force_circuit_states() {
        let config = CircuitBreakerConfig::default();
        let circuit_breaker = CircuitBreaker::new(config);
        
        // Force open
        circuit_breaker.force_open().await;
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Open);
        
        // Force closed
        circuit_breaker.force_closed().await;
        let metrics = circuit_breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitBreakerState::Closed);
    }
}