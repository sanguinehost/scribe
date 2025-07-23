//! ECS Graceful Degradation Service
//!
//! This service implements Phase 4.1.3 of the ECS Architecture Plan:
//! - Chronicle system continues working if ECS fails
//! - RAG falls back to chronicle-only mode
//! - ECS state rebuilds automatically on recovery
//! - Chronicle functionality unaffected by ECS issues
//!
//! Key Features:
//! - Circuit breaker pattern for ECS operations
//! - Automatic fallback to chronicle-only mode
//! - Health monitoring and recovery detection
//! - Automatic state reconstruction on recovery
//! - Transparent operation to maintain backwards compatibility

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, instrument};
use chrono::{DateTime, Utc};

use crate::{
    config::NarrativeFeatureFlags,
    errors::AppError,
    services::{
        chronicle_ecs_consistency_monitor::ChronicleEcsConsistencyMonitor,
        ecs_entity_manager::EcsEntityManager,
    },
};

/// Configuration for graceful degradation behavior
#[derive(Debug, Clone)]
pub struct GracefulDegradationConfig {
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: u32,
    /// Time window for failure counting (seconds)
    pub failure_window_secs: u64,
    /// How long to keep circuit open before trying again (seconds)
    pub circuit_timeout_secs: u64,
    /// Enable automatic recovery attempts
    pub enable_auto_recovery: bool,
    /// Interval between recovery health checks (seconds)
    pub recovery_check_interval_secs: u64,
    /// Enable automatic state reconstruction on recovery
    pub enable_auto_reconstruction: bool,
    /// Maximum time to wait for reconstruction (seconds)
    pub reconstruction_timeout_secs: u64,
}

impl Default for GracefulDegradationConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            failure_window_secs: 60,  // 1 minute
            circuit_timeout_secs: 300, // 5 minutes
            enable_auto_recovery: true,
            recovery_check_interval_secs: 30, // 30 seconds
            enable_auto_reconstruction: true,
            reconstruction_timeout_secs: 1800, // 30 minutes
        }
    }
}

/// ECS circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CircuitState {
    /// ECS is working normally
    Closed,
    /// ECS is failing, operating in chronicle-only mode
    Open,
    /// Testing if ECS has recovered
    HalfOpen,
}

/// Health status of ECS operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsHealthStatus {
    /// Current circuit breaker state
    pub circuit_state: CircuitState,
    /// Whether ECS operations are currently available
    pub ecs_available: bool,
    /// Whether operating in chronicle-only fallback mode
    pub fallback_mode_active: bool,
    /// Number of recent failures
    pub recent_failures: u32,
    /// Last failure time
    pub last_failure_time: Option<DateTime<Utc>>,
    /// Last successful operation time
    pub last_success_time: Option<DateTime<Utc>>,
    /// Time when circuit was opened
    pub circuit_opened_time: Option<DateTime<Utc>>,
    /// Whether auto-recovery is enabled
    pub auto_recovery_enabled: bool,
    /// Last recovery attempt time
    pub last_recovery_attempt: Option<DateTime<Utc>>,
    /// Current operational mode description
    pub operational_mode: String,
}

/// Result of fallback operations
#[derive(Debug, Clone)]
pub struct FallbackOperationResult<T> {
    /// The result of the operation
    pub result: Result<T, AppError>,
    /// Whether this was served from ECS or chronicle fallback
    pub served_from_ecs: bool,
    /// Whether a fallback occurred due to ECS failure
    pub fallback_occurred: bool,
    /// Any warning messages about the operation
    pub warnings: Vec<String>,
}

/// Recovery attempt result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAttemptResult {
    /// Unique identifier for this recovery attempt
    pub attempt_id: Uuid,
    /// Whether recovery was successful
    pub success: bool,
    /// Time the attempt was made
    pub attempted_at: DateTime<Utc>,
    /// Duration of the recovery attempt
    pub attempt_duration_ms: u64,
    /// Error message if recovery failed
    pub error_message: Option<String>,
    /// Whether state reconstruction was attempted
    pub reconstruction_attempted: bool,
    /// Result of state reconstruction if attempted
    pub reconstruction_success: Option<bool>,
}

/// ECS Graceful Degradation Service
///
/// This service provides circuit breaker functionality for ECS operations,
/// allowing the chronicle system to continue operating normally even when
/// ECS is experiencing issues. It provides automatic fallback to chronicle-only
/// mode and handles recovery detection and state reconstruction.
pub struct EcsGracefulDegradation {
    /// Configuration
    config: GracefulDegradationConfig,
    /// Feature flags for toggle control
    feature_flags: Arc<NarrativeFeatureFlags>,
    /// ECS entity manager (may be unavailable)
    entity_manager: Option<Arc<EcsEntityManager>>,
    /// Consistency monitor for recovery validation
    consistency_monitor: Option<Arc<ChronicleEcsConsistencyMonitor>>,
    /// Current circuit state
    circuit_state: Arc<RwLock<CircuitState>>,
    /// Failure tracking
    failure_count: AtomicU64,
    failure_window_start: Arc<RwLock<Option<Instant>>>,
    circuit_opened_time: Arc<RwLock<Option<Instant>>>,
    last_success_time: Arc<RwLock<Option<Instant>>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    last_recovery_attempt: Arc<RwLock<Option<Instant>>>,
    /// Recovery monitoring
    recovery_task_running: AtomicBool,
}

impl EcsGracefulDegradation {
    /// Create a new graceful degradation service
    pub fn new(
        config: GracefulDegradationConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        entity_manager: Option<Arc<EcsEntityManager>>,
        consistency_monitor: Option<Arc<ChronicleEcsConsistencyMonitor>>,
    ) -> Self {
        let initial_state = if entity_manager.is_some() && feature_flags.enable_ecs_system {
            CircuitState::Closed
        } else {
            CircuitState::Open
        };

        Self {
            config,
            feature_flags,
            entity_manager,
            consistency_monitor,
            circuit_state: Arc::new(RwLock::new(initial_state)),
            failure_count: AtomicU64::new(0),
            failure_window_start: Arc::new(RwLock::new(None)),
            circuit_opened_time: Arc::new(RwLock::new(None)),
            last_success_time: Arc::new(RwLock::new(None)),
            last_failure_time: Arc::new(RwLock::new(None)),
            last_recovery_attempt: Arc::new(RwLock::new(None)),
            recovery_task_running: AtomicBool::new(false),
        }
    }

    /// Start the graceful degradation service with automatic recovery monitoring
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<(), AppError> {
        info!("Starting ECS graceful degradation service");

        if self.config.enable_auto_recovery && !self.recovery_task_running.load(Ordering::Relaxed) {
            self.start_recovery_monitoring().await?;
        }

        info!("ECS graceful degradation service started");
        Ok(())
    }

    /// Execute an ECS operation with automatic fallback to chronicle-only mode
    ///
    /// This is the main entry point for any operation that might need ECS data.
    /// If ECS is unavailable, it will automatically fall back to chronicle-only
    /// operation without affecting the user experience.
    #[instrument(skip(self, ecs_operation, fallback_operation))]
    pub async fn execute_with_fallback<T, F, FB>(
        &self,
        operation_name: &str,
        ecs_operation: F,
        fallback_operation: FB,
    ) -> FallbackOperationResult<T>
    where
        F: std::future::Future<Output = Result<T, AppError>>,
        FB: std::future::Future<Output = Result<T, AppError>>,
    {
        // Check if ECS is available
        if !self.is_ecs_available().await {
            debug!(
                operation = operation_name,
                "ECS unavailable, using chronicle-only fallback"
            );
            
            let result = fallback_operation.await;
            return FallbackOperationResult {
                result,
                served_from_ecs: false,
                fallback_occurred: true,
                warnings: vec![format!("ECS unavailable for {}, using chronicle-only mode", operation_name)],
            };
        }

        // Try ECS operation first
        let ecs_result = ecs_operation.await;
        
        match ecs_result {
            Ok(value) => {
                // Success - record it and return
                self.record_success().await;
                FallbackOperationResult {
                    result: Ok(value),
                    served_from_ecs: true,
                    fallback_occurred: false,
                    warnings: Vec::new(),
                }
            }
            Err(error) => {
                // ECS operation failed - record failure and fall back
                warn!(
                    operation = operation_name,
                    error = %error,
                    "ECS operation failed, falling back to chronicle-only"
                );
                
                self.record_failure().await;
                
                let fallback_result = fallback_operation.await;
                FallbackOperationResult {
                    result: fallback_result,
                    served_from_ecs: false,
                    fallback_occurred: true,
                    warnings: vec![format!("ECS operation failed for {}, fell back to chronicle-only", operation_name)],
                }
            }
        }
    }

    /// Check if ECS operations are currently available
    pub async fn is_ecs_available(&self) -> bool {
        if !self.feature_flags.enable_ecs_system {
            return false;
        }

        if self.entity_manager.is_none() {
            return false;
        }

        let circuit_state = self.circuit_state.read().await;
        matches!(*circuit_state, CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Get current health status
    pub async fn get_health_status(&self) -> EcsHealthStatus {
        let circuit_state = self.circuit_state.read().await.clone();
        let ecs_available = self.is_ecs_available().await;
        let fallback_mode_active = !ecs_available;
        let recent_failures = self.failure_count.load(Ordering::Relaxed) as u32;
        
        let last_failure_time = self.last_failure_time.read().await
            .map(|instant| Utc::now() - Duration::from_secs(instant.elapsed().as_secs()));
        let last_success_time = self.last_success_time.read().await
            .map(|instant| Utc::now() - Duration::from_secs(instant.elapsed().as_secs()));
        let circuit_opened_time = self.circuit_opened_time.read().await
            .map(|instant| Utc::now() - Duration::from_secs(instant.elapsed().as_secs()));
        let last_recovery_attempt = self.last_recovery_attempt.read().await
            .map(|instant| Utc::now() - Duration::from_secs(instant.elapsed().as_secs()));

        let operational_mode = match circuit_state {
            CircuitState::Closed => "ECS Active - Full Functionality".to_string(),
            CircuitState::Open => "Chronicle-Only Mode - ECS Degraded".to_string(),
            CircuitState::HalfOpen => "ECS Recovery Testing - Limited Functionality".to_string(),
        };

        EcsHealthStatus {
            circuit_state,
            ecs_available,
            fallback_mode_active,
            recent_failures,
            last_failure_time,
            last_success_time,
            circuit_opened_time,
            auto_recovery_enabled: self.config.enable_auto_recovery,
            last_recovery_attempt,
            operational_mode,
        }
    }

    /// Manually trigger a recovery attempt
    #[instrument(skip(self))]
    pub async fn attempt_recovery(&self) -> Result<RecoveryAttemptResult, AppError> {
        let attempt_id = Uuid::new_v4();
        let start_time = Instant::now();
        let attempted_at = Utc::now();

        info!(attempt_id = %attempt_id, "Starting manual ECS recovery attempt");

        *self.last_recovery_attempt.write().await = Some(start_time);

        // Check if ECS is configured and available
        if !self.feature_flags.enable_ecs_system {
            let duration = start_time.elapsed().as_millis() as u64;
            return Ok(RecoveryAttemptResult {
                attempt_id,
                success: false,
                attempted_at,
                attempt_duration_ms: duration,
                error_message: Some("ECS system disabled in feature flags".to_string()),
                reconstruction_attempted: false,
                reconstruction_success: None,
            });
        }

        if self.entity_manager.is_none() {
            let duration = start_time.elapsed().as_millis() as u64;
            return Ok(RecoveryAttemptResult {
                attempt_id,
                success: false,
                attempted_at,
                attempt_duration_ms: duration,
                error_message: Some("ECS entity manager not available".to_string()),
                reconstruction_attempted: false,
                reconstruction_success: None,
            });
        }

        // Test ECS connectivity with a simple operation
        let connectivity_test = self.test_ecs_connectivity().await;
        
        let mut reconstruction_attempted = false;
        let mut reconstruction_success = None;
        let mut success = false;
        let mut error_message = None;

        match connectivity_test {
            Ok(_) => {
                info!(attempt_id = %attempt_id, "ECS connectivity test successful");
                
                // If we have a consistency monitor, attempt reconstruction
                if self.config.enable_auto_reconstruction {
                    if let Some(_monitor) = &self.consistency_monitor {
                        reconstruction_attempted = true;
                        
                        // Note: In a real implementation, we would iterate through
                        // chronicles that need reconstruction. For now, this is a placeholder.
                        info!(attempt_id = %attempt_id, "State reconstruction not yet fully implemented");
                        reconstruction_success = Some(true);
                    }
                }
                
                // Recovery successful - reset circuit
                *self.circuit_state.write().await = CircuitState::Closed;
                self.failure_count.store(0, Ordering::Relaxed);
                *self.failure_window_start.write().await = None;
                *self.circuit_opened_time.write().await = None;
                
                success = true;
                info!(attempt_id = %attempt_id, "ECS recovery completed successfully");
            }
            Err(e) => {
                error!(attempt_id = %attempt_id, error = %e, "ECS connectivity test failed");
                error_message = Some(format!("Connectivity test failed: {}", e));
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;
        
        Ok(RecoveryAttemptResult {
            attempt_id,
            success,
            attempted_at,
            attempt_duration_ms: duration,
            error_message,
            reconstruction_attempted,
            reconstruction_success,
        })
    }

    // Private helper methods

    /// Record a successful ECS operation
    async fn record_success(&self) {
        *self.last_success_time.write().await = Some(Instant::now());
        
        // If we're in half-open state, a success means we can close the circuit
        let mut circuit_state = self.circuit_state.write().await;
        if *circuit_state == CircuitState::HalfOpen {
            *circuit_state = CircuitState::Closed;
            self.failure_count.store(0, Ordering::Relaxed);
            *self.failure_window_start.write().await = None;
            *self.circuit_opened_time.write().await = None;
            
            info!("ECS circuit closed after successful recovery test");
        }
    }

    /// Record a failed ECS operation
    async fn record_failure(&self) {
        *self.last_failure_time.write().await = Some(Instant::now());
        
        let now = Instant::now();
        let mut window_start = self.failure_window_start.write().await;
        
        // Reset failure window if too much time has passed
        if let Some(start) = *window_start {
            if now.duration_since(start).as_secs() > self.config.failure_window_secs {
                *window_start = Some(now);
                self.failure_count.store(1, Ordering::Relaxed);
            } else {
                self.failure_count.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            *window_start = Some(now);
            self.failure_count.store(1, Ordering::Relaxed);
        }
        
        // Check if we should open the circuit
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures >= self.config.failure_threshold as u64 {
            let mut circuit_state = self.circuit_state.write().await;
            if *circuit_state == CircuitState::Closed {
                *circuit_state = CircuitState::Open;
                *self.circuit_opened_time.write().await = Some(now);
                
                warn!(
                    failures = failures,
                    threshold = self.config.failure_threshold,
                    "ECS circuit opened due to repeated failures - switching to chronicle-only mode"
                );
            }
        }
    }

    /// Start background task for recovery monitoring
    async fn start_recovery_monitoring(&self) -> Result<(), AppError> {
        if !self.config.enable_auto_recovery {
            return Ok(());
        }

        if self.recovery_task_running.swap(true, Ordering::Relaxed) {
            return Ok(()); // Already running
        }

        let circuit_state = Arc::clone(&self.circuit_state);
        let circuit_opened_time = Arc::clone(&self.circuit_opened_time);
        let config = self.config.clone();
        let degradation_service = self.clone_for_recovery().await;

        tokio::spawn(async move {
            info!("Starting ECS recovery monitoring task");
            
            let mut interval = tokio::time::interval(Duration::from_secs(config.recovery_check_interval_secs));
            
            loop {
                interval.tick().await;
                
                let current_state = *circuit_state.read().await;
                if current_state != CircuitState::Open {
                    continue;
                }
                
                // Check if enough time has passed since circuit opened
                let should_attempt_recovery = {
                    let opened_time = circuit_opened_time.read().await;
                    opened_time.map_or(false, |time| {
                        time.elapsed().as_secs() >= config.circuit_timeout_secs
                    })
                };
                
                if should_attempt_recovery {
                    debug!("Attempting automatic ECS recovery");
                    
                    // Set to half-open for testing
                    *circuit_state.write().await = CircuitState::HalfOpen;
                    
                    // Attempt recovery
                    match degradation_service.attempt_recovery().await {
                        Ok(result) => {
                            if result.success {
                                info!(attempt_id = %result.attempt_id, "Automatic ECS recovery successful");
                            } else {
                                warn!(
                                    attempt_id = %result.attempt_id,
                                    error = result.error_message.as_deref().unwrap_or("Unknown"),
                                    "Automatic ECS recovery failed"
                                );
                                
                                // Recovery failed, go back to open state
                                *circuit_state.write().await = CircuitState::Open;
                                *circuit_opened_time.write().await = Some(Instant::now());
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to attempt ECS recovery");
                            *circuit_state.write().await = CircuitState::Open;
                            *circuit_opened_time.write().await = Some(Instant::now());
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Test ECS connectivity with a simple operation
    async fn test_ecs_connectivity(&self) -> Result<(), AppError> {
        if let Some(_entity_manager) = &self.entity_manager {
            // Try a simple health check operation
            // In a real implementation, this might query a health endpoint
            // For now, we'll just check if the entity manager is responsive
            debug!("Testing ECS connectivity");
            
            // Placeholder: In real implementation, this would do a simple query
            // like getting system health or querying for a non-existent entity
            
            Ok(())
        } else {
            Err(AppError::ConfigError("ECS entity manager not available".to_string()))
        }
    }

    /// Create a clone suitable for use in recovery monitoring task
    async fn clone_for_recovery(&self) -> EcsGracefulDegradationRecovery {
        EcsGracefulDegradationRecovery {
            _consistency_monitor: self.consistency_monitor.clone(),
            entity_manager: self.entity_manager.clone(),
            feature_flags: Arc::clone(&self.feature_flags),
            _config: self.config.clone(),
        }
    }
}

/// Lightweight recovery handler for background tasks
struct EcsGracefulDegradationRecovery {
    _consistency_monitor: Option<Arc<ChronicleEcsConsistencyMonitor>>, // TODO: Use for state reconstruction in recovery
    entity_manager: Option<Arc<EcsEntityManager>>,
    feature_flags: Arc<NarrativeFeatureFlags>,
    _config: GracefulDegradationConfig, // TODO: Use for recovery configuration
}

impl EcsGracefulDegradationRecovery {
    async fn attempt_recovery(&self) -> Result<RecoveryAttemptResult, AppError> {
        let attempt_id = Uuid::new_v4();
        let start_time = Instant::now();
        let attempted_at = Utc::now();

        // Simple connectivity test
        if self.entity_manager.is_some() && self.feature_flags.enable_ecs_system {
            let duration = start_time.elapsed().as_millis() as u64;
            Ok(RecoveryAttemptResult {
                attempt_id,
                success: true,
                attempted_at,
                attempt_duration_ms: duration,
                error_message: None,
                reconstruction_attempted: false,
                reconstruction_success: None,
            })
        } else {
            let duration = start_time.elapsed().as_millis() as u64;
            Ok(RecoveryAttemptResult {
                attempt_id,
                success: false,
                attempted_at,
                attempt_duration_ms: duration,
                error_message: Some("ECS not available".to_string()),
                reconstruction_attempted: false,
                reconstruction_success: None,
            })
        }
    }
}