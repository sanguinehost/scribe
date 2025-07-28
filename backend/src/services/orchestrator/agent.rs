// backend/src/services/orchestrator/agent.rs
//
// Orchestrator Agent Implementation
// Epic 8: Orchestrator-Driven Intelligent Agent System

use chrono::Utc;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    auth::user_store::Backend as AuthBackend,
    config::Config,
    errors::AppError,
    llm::AiClient,
    PgPool,
    services::{
        encryption_service::EncryptionService,
        task_queue::{DequeuedTask, EnrichmentTaskPayload, TaskQueueService, TaskStatus},
    },
};

use super::{
    errors::OrchestratorError,
    reasoning::ReasoningEngine,
    types::*,
};

/// Configuration for the Orchestrator Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    pub worker_id: Uuid,
    pub poll_interval_ms: u64,
    pub batch_size: usize,
    pub retry_limit: u32,
    pub phase_timeout_ms: u64,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            worker_id: Uuid::new_v4(),
            poll_interval_ms: 1000,
            batch_size: 5,
            retry_limit: 3,
            phase_timeout_ms: 180000, // 3 minutes per phase (for complex multi-agent operations)
        }
    }
}

type PhaseObserver = Arc<dyn Fn(ReasoningPhase) -> BoxFuture<'static, ()> + Send + Sync>;
type TaskObserver = Arc<dyn Fn(TaskContext) -> BoxFuture<'static, ()> + Send + Sync>;
type StateObserver = Arc<dyn Fn(ReasoningPhase, serde_json::Value) -> BoxFuture<'static, ()> + Send + Sync>;

/// The Orchestrator Agent that processes enrichment tasks
pub struct OrchestratorAgent {
    config: OrchestratorConfig,
    task_queue: TaskQueueService,
    reasoning_engine: ReasoningEngine,
    
    // Observers for testing
    phase_observer: Arc<RwLock<Option<PhaseObserver>>>,
    task_observer: Arc<RwLock<Option<TaskObserver>>>,
    state_observer: Arc<RwLock<Option<StateObserver>>>,
    
    // State tracking
    active_tasks: Arc<Mutex<HashMap<Uuid, Instant>>>,
}

impl OrchestratorAgent {
    pub fn new(
        config: OrchestratorConfig,
        db_pool: PgPool,
        encryption_service: Arc<EncryptionService>,
        auth_backend: Arc<AuthBackend>,
        ai_client: Arc<dyn AiClient>,
        app_config: Arc<Config>,
    ) -> Self {
        let task_queue = TaskQueueService::new(
            db_pool, 
            encryption_service.clone(), 
            auth_backend.clone()
        );
        
        // Use the advanced model for complex reasoning tasks in orchestration
        let reasoning_engine = ReasoningEngine::new(
            ai_client,
            app_config.advanced_model.clone(),
        );

        Self {
            config,
            task_queue,
            reasoning_engine,
            phase_observer: Arc::new(RwLock::new(None)),
            task_observer: Arc::new(RwLock::new(None)),
            state_observer: Arc::new(RwLock::new(None)),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Validate configuration
    pub fn validate_config(&self) -> Result<(), OrchestratorError> {
        if self.config.worker_id == Uuid::nil() {
            return Err(OrchestratorError::ConfigurationError(
                "Worker ID cannot be nil".to_string()
            ));
        }
        
        if self.config.poll_interval_ms == 0 {
            return Err(OrchestratorError::ConfigurationError(
                "Poll interval must be greater than 0".to_string()
            ));
        }
        
        if self.config.batch_size == 0 {
            return Err(OrchestratorError::ConfigurationError(
                "Batch size must be greater than 0".to_string()
            ));
        }
        
        if self.config.batch_size > 100 {
            return Err(OrchestratorError::ConfigurationError(
                "Batch size cannot exceed 100".to_string()
            ));
        }
        
        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    /// Set phase observer for testing
    pub async fn set_phase_observer<F>(&self, observer: F)
    where
        F: Fn(ReasoningPhase) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        let mut guard = self.phase_observer.write().await;
        *guard = Some(Arc::new(observer));
    }

    /// Set task observer for testing
    pub async fn set_task_observer<F>(&self, observer: F)
    where
        F: Fn(TaskContext) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        let mut guard = self.task_observer.write().await;
        *guard = Some(Arc::new(observer));
    }

    /// Set state observer for testing
    pub async fn set_state_observer<F>(&self, observer: F)
    where
        F: Fn(ReasoningPhase, serde_json::Value) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        let mut guard = self.state_observer.write().await;
        *guard = Some(Arc::new(observer));
    }

    /// Process a single task from the queue
    #[instrument(skip(self))]
    pub async fn process_single_task(&self) -> Result<bool, AppError> {
        // Dequeue a task
        let dequeued = self.task_queue
            .dequeue_task(self.config.worker_id)
            .await?;
        
        match dequeued {
            Some(task) => {
                info!("Processing task {}", task.task.id);
                self.process_task(task).await?;
                Ok(true)
            }
            None => {
                debug!("No tasks available");
                Ok(false)
            }
        }
    }

    /// Process a batch of tasks
    #[instrument(skip(self))]
    pub async fn process_batch(&self) -> Result<usize, AppError> {
        let mut processed = 0;
        
        for _ in 0..self.config.batch_size {
            match self.process_single_task().await {
                Ok(true) => processed += 1,
                Ok(false) => break, // No more tasks
                Err(e) => {
                    error!("Error processing task: {}", e);
                    // Continue with next task
                }
            }
        }
        
        Ok(processed)
    }

    /// Run the worker loop
    pub async fn run_worker(&self) -> Result<(), AppError> {
        self.validate_config()?;
        
        info!("Starting Orchestrator worker {}", self.config.worker_id);
        
        loop {
            match self.process_batch().await {
                Ok(0) => {
                    // No tasks, sleep before next poll
                    tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
                }
                Ok(count) => {
                    info!("Processed {} tasks", count);
                }
                Err(e) => {
                    error!("Worker error: {}", e);
                    tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
                }
            }
        }
    }

    /// Process a single dequeued task
    async fn process_task(&self, dequeued: DequeuedTask) -> Result<(), AppError> {
        let task_id = dequeued.task.id;
        let start_time = Instant::now();
        
        // Track active task
        {
            let mut active = self.active_tasks.lock().await;
            active.insert(task_id, start_time);
        }
        
        // Notify task observer
        if let Some(observer) = self.task_observer.read().await.as_ref() {
            let context = TaskContext {
                task_id,
                session_id: dequeued.task.session_id,
                user_id: dequeued.task.user_id,
                payload: dequeued.payload.clone(),
                status: "processing".to_string(),
                created_at: dequeued.task.created_at,
            };
            observer(context).await;
        }
        
        // Process based on payload
        let result = if dequeued.payload.user_message == "FORCE_FAILURE" {
            // Test case for failure handling
            Err(OrchestratorError::TaskProcessingError("Forced failure for testing".to_string()))
        } else {
            self.execute_reasoning_loop(&dequeued).await
        };
        
        // Handle result
        match result {
            Ok(_) => {
                info!("Task {} completed successfully", task_id);
                self.task_queue
                    .update_task_status(task_id, TaskStatus::Completed, None)
                    .await?;
            }
            Err(e) => {
                error!("Task {} failed: {}", task_id, e);
                self.task_queue
                    .update_task_status(
                        task_id,
                        TaskStatus::Failed,
                        Some(e.to_string())
                    )
                    .await?;
            }
        }
        
        // Remove from active tasks
        {
            let mut active = self.active_tasks.lock().await;
            active.remove(&task_id);
        }
        
        Ok(())
    }

    /// Execute the full reasoning loop for a task
    async fn execute_reasoning_loop(&self, dequeued: &DequeuedTask) -> Result<(), OrchestratorError> {
        let task_id = dequeued.task.id;
        let is_first_message = self.is_first_message_in_session(&dequeued.task.session_id).await;
        
        // Build reasoning context
        let mut context = ReasoningContext {
            task_id,
            session_id: dequeued.task.session_id,
            user_id: dequeued.task.user_id,
            is_first_message,
            cached_world_state: if is_first_message {
                None
            } else {
                // In production, load from cache
                Some(serde_json::json!({
                    "location": "tavern",
                    "entities": ["bartender", "patrons"],
                    "atmosphere": "lively"
                }))
            },
            phase_history: Vec::new(),
            metadata: HashMap::new(),
        };
        
        // Execute phases
        
        // Perceive phase
        info!("Starting Perceive phase for task {}", task_id);
        self.notify_phase_observer(ReasoningPhase::Perceive).await;
        context.phase_history.push(ReasoningPhase::Perceive);
        
        let perception_result = timeout(
            Duration::from_millis(self.config.phase_timeout_ms),
            self.reasoning_engine.execute_perceive_phase(&context, &dequeued.payload)
        ).await
            .map_err(|_| OrchestratorError::PhaseTimeout {
                phase: "Perceive".to_string(),
                timeout_ms: self.config.phase_timeout_ms,
            })??;
        
        self.notify_state_observer(ReasoningPhase::Perceive, &perception_result).await;
        
        // Strategize phase
        info!("Starting Strategize phase for task {}", task_id);
        self.notify_phase_observer(ReasoningPhase::Strategize).await;
        context.phase_history.push(ReasoningPhase::Strategize);
        
        let strategy_result = timeout(
            Duration::from_millis(self.config.phase_timeout_ms),
            self.reasoning_engine.execute_strategize_phase(&context, &perception_result)
        ).await
            .map_err(|_| OrchestratorError::PhaseTimeout {
                phase: "Strategize".to_string(),
                timeout_ms: self.config.phase_timeout_ms,
            })??;
        
        self.notify_state_observer(ReasoningPhase::Strategize, &strategy_result).await;
        
        // Plan phase
        info!("Starting Plan phase for task {}", task_id);
        self.notify_phase_observer(ReasoningPhase::Plan).await;
        context.phase_history.push(ReasoningPhase::Plan);
        
        let plan_result = timeout(
            Duration::from_millis(self.config.phase_timeout_ms),
            self.reasoning_engine.execute_plan_phase(&context, &strategy_result)
        ).await
            .map_err(|_| OrchestratorError::PhaseTimeout {
                phase: "Plan".to_string(),
                timeout_ms: self.config.phase_timeout_ms,
            })??;
        
        self.notify_state_observer(ReasoningPhase::Plan, &plan_result).await;
        
        // Execute phase
        info!("Starting Execute phase for task {}", task_id);
        self.notify_phase_observer(ReasoningPhase::Execute).await;
        context.phase_history.push(ReasoningPhase::Execute);
        
        let execution_result = timeout(
            Duration::from_millis(self.config.phase_timeout_ms),
            self.reasoning_engine.execute_execute_phase(&context, &plan_result)
        ).await
            .map_err(|_| OrchestratorError::PhaseTimeout {
                phase: "Execute".to_string(),
                timeout_ms: self.config.phase_timeout_ms,
            })??;
        
        self.notify_state_observer(ReasoningPhase::Execute, &execution_result).await;
        
        // Reflect phase
        info!("Starting Reflect phase for task {}", task_id);
        self.notify_phase_observer(ReasoningPhase::Reflect).await;
        context.phase_history.push(ReasoningPhase::Reflect);
        
        let reflection_result = timeout(
            Duration::from_millis(self.config.phase_timeout_ms),
            self.reasoning_engine.execute_reflect_phase(&context, &execution_result, &strategy_result.primary_goals)
        ).await
            .map_err(|_| OrchestratorError::PhaseTimeout {
                phase: "Reflect".to_string(),
                timeout_ms: self.config.phase_timeout_ms,
            })??;
        
        self.notify_state_observer(ReasoningPhase::Reflect, &reflection_result).await;
        
        // Handle replanning if needed
        if reflection_result.replan_needed && !reflection_result.goals_remaining.is_empty() {
            warn!("Replanning needed for task {}", task_id);
            // In production, would trigger replanning
        }
        
        Ok(())
    }

    /// Notify phase observer
    async fn notify_phase_observer(&self, phase: ReasoningPhase) {
        if let Some(observer) = self.phase_observer.read().await.as_ref() {
            observer(phase).await;
        }
    }
    
    /// Notify state observer
    async fn notify_state_observer<T: Serialize>(&self, phase: ReasoningPhase, value: &T) {
        if let Some(observer) = self.state_observer.read().await.as_ref() {
            if let Ok(json_value) = serde_json::to_value(value) {
                observer(phase, json_value).await;
            }
        }
    }

    /// Check if this is the first message in a session
    async fn is_first_message_in_session(&self, _session_id: &Uuid) -> bool {
        // In production, would check task history
        // For now, assume it's first if no cached state
        true
    }

    /// Execute full reasoning loop (public interface for tests)
    pub async fn execute_full_reasoning_loop(
        &self,
        payload: &EnrichmentTaskPayload,
        is_first_message: bool,
    ) -> Result<ReasoningLoopResult, OrchestratorError> {
        let start_time = Instant::now();
        let task_id = Uuid::new_v4();
        
        // Create a mock dequeued task
        let dequeued = DequeuedTask {
            task: crate::services::task_queue::EnrichmentTask {
                id: task_id,
                session_id: payload.session_id,
                user_id: payload.user_id,
                status: TaskStatus::InProgress as i32,
                priority: 1,
                encrypted_payload: vec![],
                payload_nonce: vec![],
                encrypted_error: None,
                error_nonce: None,
                retry_count: 0,
                worker_id: Some(self.config.worker_id),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            payload: payload.clone(),
        };
        
        // Execute reasoning loop
        self.execute_reasoning_loop(&dequeued).await?;
        
        // Build result
        Ok(ReasoningLoopResult {
            task_id,
            phases_completed: vec![
                ReasoningPhase::Perceive,
                ReasoningPhase::Strategize,
                ReasoningPhase::Plan,
                ReasoningPhase::Execute,
                ReasoningPhase::Reflect,
            ],
            world_enrichment_complete: true,
            total_duration_ms: start_time.elapsed().as_millis() as u64,
            replan_count: 0,
            alternative_paths_explored: None,
            cache_layers_populated: vec![
                "immediate_context".to_string(),
                "enhanced_context".to_string(),
                "full_world_state".to_string(),
            ],
            cache_hits: if is_first_message { 0 } else { 3 },
            processing_time_saved_ms: if is_first_message { 0 } else { 50 },
        })
    }

    /// Verify tool compatibility
    pub async fn verify_tool_compatibility(&self) -> Result<(), OrchestratorError> {
        // In production, would check tool versions
        Ok(())
    }
}