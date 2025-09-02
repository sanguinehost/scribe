// backend/src/llm/llamacpp/server.rs
// LlamaCpp server lifecycle management and process control

use crate::llm::llamacpp::hardware::{
    ContextSizeConfig, ModelSelection, calculate_optimal_context_size, detect_hardware,
};
use crate::llm::llamacpp::{HealthChecker, LlamaCppConfig, LocalLlmError, ModelManager};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, instrument, warn};

/// Server lifecycle states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerState {
    /// Server is not running
    Stopped,
    /// Server is starting up
    Starting,
    /// Server is running and healthy
    Running,
    /// Server is stopping
    Stopping,
    /// Server encountered an error
    Error(String),
}

/// Server configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub executable_path: Option<PathBuf>,
    pub host: String,
    pub port: u16,
    pub context_size: usize,
    pub gpu_layers: Option<i32>,
    pub threads: Option<usize>,
    pub batch_size: Option<usize>,
    pub model_path: PathBuf,
    pub additional_args: Vec<String>,
    pub enable_tool_calling: bool,
    pub parallel_requests: Option<usize>,
    pub chat_template: Option<String>,
    pub adaptive_context: Option<ContextSizeConfig>, // Adaptive context configuration
}

/// Server process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub state: ServerState,
    pub pid: Option<u32>,
    #[serde(skip)]
    pub start_time: Option<Instant>,
    pub uptime: Option<Duration>,
    pub model_loaded: Option<String>,
    pub memory_usage_mb: Option<f32>,
    #[serde(skip)]
    pub last_health_check: Option<Instant>,
}

/// LlamaCpp server manager
pub struct LlamaCppServerManager {
    config: LlamaCppConfig,
    server_config: ServerConfig,
    process: Arc<Mutex<Option<Child>>>,
    state: Arc<RwLock<ServerState>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    health_checker: Arc<HealthChecker>,
    model_manager: Arc<ModelManager>,
}

impl ServerConfig {
    /// Create server config from LlamaCpp config
    pub fn from_llamacpp_config(config: &LlamaCppConfig) -> Self {
        Self {
            executable_path: None, // Will be auto-detected
            host: config.server_host.clone(),
            port: config.server_port,
            context_size: config.context_size,
            gpu_layers: config.gpu_layers,
            threads: config.threads,
            batch_size: None, // Use default
            model_path: PathBuf::from(&config.model_path),
            additional_args: Vec::new(),
            enable_tool_calling: config.enable_tool_calling,
            parallel_requests: config.parallel_requests,
            chat_template: config.chat_template.clone(),
            adaptive_context: None, // Will be calculated when needed
        }
    }

    /// Create server config with adaptive context sizing
    pub fn from_llamacpp_config_with_model(
        config: &LlamaCppConfig,
        model: &ModelSelection,
    ) -> Result<Self, LocalLlmError> {
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        let adaptive_context = calculate_optimal_context_size(model, &hardware);

        let mut server_config = Self::from_llamacpp_config(config);
        server_config.context_size = adaptive_context.optimal_context_size;
        server_config.gpu_layers = adaptive_context.optimal_gpu_layers;
        server_config.adaptive_context = Some(adaptive_context);

        Ok(server_config)
    }

    /// Update configuration for retry attempt
    pub fn with_retry_config(&self, context_size: usize, gpu_layers: Option<i32>) -> Self {
        let mut retry_config = self.clone();
        retry_config.context_size = context_size;
        retry_config.gpu_layers = gpu_layers;
        retry_config
    }

    /// Build command line arguments for server
    pub fn build_args(&self) -> Vec<String> {
        self.build_args_with_model(true)
    }

    /// Build command line arguments for server, optionally with model
    pub fn build_args_with_model(&self, include_model: bool) -> Vec<String> {
        let model_path = if include_model {
            Some(self.model_path.as_path())
        } else {
            None
        };
        self.build_args_with_model_path(model_path)
    }

    /// Build command line arguments for server with specific model path
    pub fn build_args_with_model_path(&self, model_path: Option<&std::path::Path>) -> Vec<String> {
        let mut args = Vec::new();

        // Model path (only if provided)
        if let Some(path) = model_path {
            args.push("--model".to_string());
            args.push(path.to_string_lossy().to_string());
            info!("Using model path: {}", path.display());
        } else {
            info!("Starting server without model (model will need to be loaded via API)");
        }

        // Network settings
        args.push("--host".to_string());
        args.push(self.host.clone());
        args.push("--port".to_string());
        args.push(self.port.to_string());

        // Context size
        args.push("--ctx-size".to_string());
        args.push(self.context_size.to_string());

        // GPU layers
        if let Some(gpu_layers) = self.gpu_layers {
            args.push("--n-gpu-layers".to_string());
            args.push(gpu_layers.to_string());
        }

        // Threads
        if let Some(threads) = self.threads {
            args.push("--threads".to_string());
            args.push(threads.to_string());
        }

        // Batch size
        if let Some(batch_size) = self.batch_size {
            args.push("--batch-size".to_string());
            args.push(batch_size.to_string());
        }

        // API key for authentication (removed --server flag as llama-server doesn't need it)
        args.push("--api-key".to_string());
        args.push("sk-no-key-required".to_string()); // Basic API key for local use

        // Tool calling support
        if self.enable_tool_calling {
            args.push("--jinja".to_string()); // Enable Jinja template support for tool calling
        }

        // Parallel requests for better tool calling performance
        if let Some(parallel) = self.parallel_requests {
            args.push("--parallel".to_string());
            args.push(parallel.to_string());
        }

        // Chat template for proper tool calling format
        if let Some(ref template) = self.chat_template {
            args.push("--chat-template".to_string());
            args.push(template.clone());
        }

        // Additional args
        args.extend(self.additional_args.clone());

        args
    }
}

/// Startup failure reasons
#[derive(Debug, Clone)]
pub enum StartupFailureReason {
    OutOfMemory,
    ModelTooLarge,
    ContextTooLarge,
    InsufficientVRAM,
    Other(String),
}

impl LlamaCppServerManager {
    /// Create a new server manager
    pub async fn new(
        config: LlamaCppConfig,
        model_manager: Arc<ModelManager>,
    ) -> Result<Self, LocalLlmError> {
        info!("Initializing LlamaCpp server manager");

        let server_config = ServerConfig::from_llamacpp_config(&config);
        let health_checker = Arc::new(HealthChecker::new(config.clone()));

        let manager = Self {
            config,
            server_config,
            process: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            health_checker,
            model_manager,
        };

        Ok(manager)
    }

    /// Kill any existing llama-server processes to prevent conflicts
    async fn kill_existing_servers(&self) {
        use tokio::process::Command;

        info!("Checking for existing llama-server processes...");

        // Kill any existing llama-server processes
        let _ = Command::new("pkill")
            .arg("-f")
            .arg("llama-server")
            .output()
            .await;

        // Also kill processes listening on our port
        let port = self.server_config.port;
        let _ = Command::new("bash")
            .arg("-c")
            .arg(format!("lsof -ti:{} | xargs -r kill -9", port))
            .output()
            .await;

        // Give processes time to clean up
        tokio::time::sleep(Duration::from_millis(100)).await;

        debug!("Existing server cleanup completed");
    }

    /// Start the LlamaCpp server with optional model
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<(), LocalLlmError> {
        self.start_with_model(None).await
    }

    /// Start the LlamaCpp server with a specific model
    #[instrument(skip(self))]
    pub async fn start_with_model(&self, model_name: Option<&str>) -> Result<(), LocalLlmError> {
        // Kill any existing llama-server processes to prevent port conflicts
        self.kill_existing_servers().await;

        let mut state = self.state.write().await;
        if *state != ServerState::Stopped {
            return Err(LocalLlmError::ServerUnavailable(format!(
                "Server is already in state: {:?}",
                *state
            )));
        }

        *state = ServerState::Starting;
        drop(state);

        // If a model is specified, activate it first
        if let Some(model_name) = model_name {
            info!("Activating model before server start: {}", model_name);
            self.model_manager.activate_model(model_name).await?;
        }

        info!(
            "Starting LlamaCpp server with adaptive configuration on {}:{}",
            self.server_config.host, self.server_config.port
        );

        // Try to start server with adaptive retry logic
        let result = self.start_with_adaptive_retry().await;

        match result {
            Ok(_) => {
                info!("LlamaCpp server is ready and healthy");
                Ok(())
            }
            Err(e) => {
                // Update state to error on failure
                let mut state = self.state.write().await;
                *state = ServerState::Error(format!("Startup failed: {}", e));
                Err(e)
            }
        }
    }

    /// Start server with adaptive retry logic for out-of-memory scenarios
    async fn start_with_adaptive_retry(&self) -> Result<(), LocalLlmError> {
        let mut current_config = self.server_config.clone();
        let max_retries = 5;

        // If we have adaptive context configuration, use its fallback sizes
        let fallback_configs = if let Some(adaptive_context) = &current_config.adaptive_context {
            let mut configs = vec![(current_config.context_size, current_config.gpu_layers)];

            // Add fallback context sizes with the same GPU layers
            for &fallback_size in &adaptive_context.fallback_sizes {
                configs.push((fallback_size, current_config.gpu_layers));
            }

            // If we have hybrid/offloading options, add those too
            if adaptive_context.requires_cpu_offloading {
                if let Some(optimal_layers) = adaptive_context.optimal_gpu_layers {
                    // Try with reduced GPU layers
                    let reduced_layers = optimal_layers / 2;
                    configs.push((adaptive_context.optimal_context_size, Some(reduced_layers)));
                    configs.push((
                        adaptive_context.optimal_context_size / 2,
                        Some(reduced_layers),
                    ));
                }
            }

            configs
        } else {
            // Default fallback strategy without adaptive context
            vec![
                (32768, current_config.gpu_layers),
                (16384, current_config.gpu_layers),
                (8192, current_config.gpu_layers),
                (4096, current_config.gpu_layers),
                (2048, Some(0)), // CPU-only fallback
            ]
        };

        let mut last_error = None;

        for (attempt, (context_size, gpu_layers)) in fallback_configs.iter().enumerate() {
            if attempt >= max_retries {
                break;
            }

            info!(
                "Attempt {} - Using context size: {}, GPU layers: {:?}",
                attempt + 1,
                context_size,
                gpu_layers
            );

            current_config = self
                .server_config
                .with_retry_config(*context_size, *gpu_layers);

            match self.try_start_with_config(&current_config).await {
                Ok(_) => {
                    info!(
                        "Server started successfully with context size: {}, GPU layers: {:?}",
                        context_size, gpu_layers
                    );

                    // Update our internal config to reflect the successful configuration
                    let mut server_config = self.server_config.clone();
                    server_config.context_size = *context_size;
                    server_config.gpu_layers = *gpu_layers;

                    return Ok(());
                }
                Err(e) => {
                    warn!("Attempt {} failed: {}", attempt + 1, e);
                    last_error = Some(e);

                    // Wait a moment before retry
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        // All attempts failed
        Err(last_error.unwrap_or_else(|| LocalLlmError::ServerStartupTimeout))
    }

    /// Try to start server with a specific configuration
    async fn try_start_with_config(&self, config: &ServerConfig) -> Result<(), LocalLlmError> {
        // Find llamacpp executable
        let executable = self.find_llamacpp_executable().await?;

        // Build command arguments WITH the active model path
        let active_model_path = if let Some(active_model) = self.model_manager.get_active_model() {
            // Get the full path to the active model
            match self.model_manager.get_model_path(Some(&active_model)).await {
                Ok(path) => Some(path),
                Err(e) => {
                    error!(
                        "Failed to get path for active model {}: {}",
                        active_model, e
                    );
                    return Err(LocalLlmError::ModelNotFound(format!(
                        "Active model path not found: {}",
                        e
                    )));
                }
            }
        } else {
            None
        };

        let args = config.build_args_with_model_path(active_model_path.as_deref());
        debug!(
            "Server command: {} {}",
            executable.display(),
            args.join(" ")
        );

        // Start server process
        let mut command = Command::new(&executable);
        command.args(&args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            LocalLlmError::ServerUnavailable(format!("Failed to start server process: {}", e))
        })?;

        let pid = child.id();
        debug!("LlamaCpp server started with PID: {:?}", pid);

        // Monitor stderr for startup errors in a separate task
        let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);

        if let Some(stderr) = child.stderr.take() {
            let error_tx_clone = error_tx.clone();
            tokio::spawn(async move {
                let mut stderr_reader = BufReader::new(stderr);
                let mut line = String::new();

                loop {
                    line.clear();
                    match stderr_reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let line = line.trim();

                            // Check for specific error patterns
                            if let Some(failure_reason) = detect_startup_failure(line) {
                                let _ = error_tx_clone.send(failure_reason).await;
                                break;
                            }

                            // Log stderr output for debugging
                            if line.contains("error")
                                || line.contains("Error")
                                || line.contains("failed")
                                || line.contains("Failed")
                            {
                                error!("LlamaCpp server stderr: {}", line);
                            } else {
                                debug!("LlamaCpp server stderr: {}", line);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // Store process temporarily
        let mut process = self.process.lock().await;
        *process = Some(child);
        drop(process);

        // Update state and start time
        let mut state = self.state.write().await;
        *state = ServerState::Running;
        drop(state);

        let current_time = Instant::now();
        {
            let mut start_time = self.start_time.write().await;
            *start_time = Some(current_time);
        }

        // Set health checker start time
        self.health_checker.set_server_start_time(current_time);

        // Wait for server to be ready or fail
        let ready_result = tokio::select! {
            result = self.wait_for_ready() => result,
            failure = error_rx.recv() => {
                match failure {
                    Some(reason) => {
                        error!("Server startup failed: {:?}", reason);
                        Err(LocalLlmError::ServerUnavailable(format!("Startup failed: {:?}", reason)))
                    }
                    None => Ok(()), // Channel closed without error
                }
            }
        };

        // If startup failed, clean up the process
        if ready_result.is_err() {
            self.cleanup_failed_startup().await;
        }

        ready_result
    }

    /// Clean up after a failed startup attempt
    async fn cleanup_failed_startup(&self) {
        let mut process = self.process.lock().await;
        if let Some(mut child) = process.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        let mut state = self.state.write().await;
        *state = ServerState::Stopped;
    }

    /// Stop the LlamaCpp server
    #[instrument(skip(self))]
    pub async fn stop(&self) -> Result<(), LocalLlmError> {
        let mut state = self.state.write().await;
        if *state == ServerState::Stopped {
            return Ok(());
        }

        *state = ServerState::Stopping;
        drop(state);

        info!("Stopping LlamaCpp server");

        let mut process = self.process.lock().await;
        if let Some(mut child) = process.take() {
            // Try graceful shutdown first
            if let Some(pid) = child.id() {
                debug!("Attempting graceful shutdown of PID: {}", pid);

                #[cfg(unix)]
                {
                    // Send SIGTERM on Unix systems
                    use nix::sys::signal::{self, Signal};
                    use nix::unistd::Pid;

                    let nix_pid = Pid::from_raw(pid as i32);
                    let _ = signal::kill(nix_pid, Signal::SIGTERM);
                }

                #[cfg(windows)]
                {
                    // On Windows, just kill the process
                    let _ = child.kill().await;
                }

                // Wait for graceful shutdown with timeout
                let shutdown_timeout = Duration::from_secs(10);
                match tokio::time::timeout(shutdown_timeout, child.wait()).await {
                    Ok(Ok(exit_status)) => {
                        info!("Server shutdown gracefully with status: {}", exit_status);
                    }
                    Ok(Err(e)) => {
                        warn!("Error waiting for server shutdown: {}", e);
                    }
                    Err(_) => {
                        // Timeout - force kill
                        warn!("Server shutdown timeout, force killing");
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                    }
                }
            }
        }
        drop(process);

        // Update state
        let mut state = self.state.write().await;
        *state = ServerState::Stopped;
        drop(state);

        // Clear start time
        let mut start_time = self.start_time.write().await;
        *start_time = None;

        info!("LlamaCpp server stopped");
        Ok(())
    }

    /// Restart the server
    pub async fn restart(&self) -> Result<(), LocalLlmError> {
        info!("Restarting LlamaCpp server");
        self.stop().await?;

        // Wait a moment for cleanup
        tokio::time::sleep(Duration::from_secs(2)).await;

        self.start().await?;
        Ok(())
    }

    /// Get current server information
    pub async fn get_server_info(&self) -> ServerInfo {
        let state = self.state.read().await.clone();
        let start_time = self.start_time.read().await.clone();

        let pid = {
            let process = self.process.lock().await;
            process.as_ref().and_then(|child| child.id())
        };

        let uptime = start_time.map(|start| start.elapsed());
        let model_loaded = self.model_manager.get_active_model();

        // Get memory usage if server is running
        let memory_usage_mb = if matches!(state, ServerState::Running) {
            Some(crate::llm::llamacpp::metrics::get_current_memory_usage_mb())
        } else {
            None
        };

        ServerInfo {
            state,
            pid,
            start_time,
            uptime,
            model_loaded,
            memory_usage_mb,
            last_health_check: None, // Could be implemented with health checker integration
        }
    }

    /// Check if server is running
    pub async fn is_running(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, ServerState::Running)
    }

    /// Wait for server to be ready (health check passes)
    async fn wait_for_ready(&self) -> Result<(), LocalLlmError> {
        let timeout = Duration::from_secs(self.config.timeout_seconds);
        let check_interval = Duration::from_secs(2);
        let start_time = Instant::now();

        info!(
            "Waiting for server to become ready (timeout: {:?})",
            timeout
        );

        while start_time.elapsed() < timeout {
            match self.health_checker.check_health().await {
                Ok(status) if status.is_healthy => {
                    info!("Server is ready after {:?}", start_time.elapsed());
                    return Ok(());
                }
                Ok(status) => {
                    debug!("Server not yet ready: {:?}", status.error_messages);
                }
                Err(e) => {
                    debug!("Health check error: {}", e);
                }
            }

            tokio::time::sleep(check_interval).await;
        }

        // Update state to error
        let mut state = self.state.write().await;
        *state = ServerState::Error("Server startup timeout".to_string());

        Err(LocalLlmError::ServerStartupTimeout)
    }

    /// Find llamacpp executable
    async fn find_llamacpp_executable(&self) -> Result<PathBuf, LocalLlmError> {
        // If explicitly configured, use that
        if let Some(ref path) = self.server_config.executable_path {
            if path.exists() {
                return Ok(path.clone());
            } else {
                return Err(LocalLlmError::ServerUnavailable(format!(
                    "Configured executable not found: {}",
                    path.display()
                )));
            }
        }

        // Try the compile-time path set by build.rs first
        let build_path = env!("LLAMA_SERVER_PATH");
        let path = PathBuf::from(build_path);
        if path.exists() {
            info!("Using llama-server from build path: {}", path.display());
            return Ok(path);
        }

        // Try common names and locations
        let candidates = vec![
            "llama-server",
            "llama-cpp-server",
            "llamacpp-server",
            "./llama-server",
            "./bin/llama-server",
            "/usr/local/bin/llama-server",
            "/opt/llamacpp/bin/llama-server",
        ];

        for candidate in candidates {
            let path = PathBuf::from(candidate);

            // Check if executable exists and is executable
            if path.exists() {
                // Try to run with --help to verify it's the right executable
                match Command::new(&path)
                    .arg("--help")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(mut child) => {
                        if let Ok(exit_status) = child.wait().await {
                            if exit_status.success() {
                                info!("Found llamacpp executable: {}", path.display());
                                return Ok(path);
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Try to find in PATH
        match which::which("llama-server") {
            Ok(path) => {
                info!("Found llamacpp executable in PATH: {}", path.display());
                Ok(path)
            }
            Err(_) => Err(LocalLlmError::ServerUnavailable(
                "LlamaCpp server executable not found. Please ensure llama-server is installed and in PATH, or set executable_path in configuration.".to_string()
            )),
        }
    }

    /// Monitor server process in background
    pub async fn start_monitoring(&self) {
        let process = Arc::clone(&self.process);
        let state = Arc::clone(&self.state);
        let health_checker = Arc::clone(&self.health_checker);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Check if process is still alive
                {
                    let mut process_guard = process.lock().await;
                    if let Some(ref mut child) = process_guard.as_mut() {
                        match child.try_wait() {
                            Ok(Some(exit_status)) => {
                                // Process has exited
                                error!(
                                    "LlamaCpp server process exited with status: {}",
                                    exit_status
                                );
                                let mut state_guard = state.write().await;
                                *state_guard = ServerState::Error(format!(
                                    "Process exited with status: {}",
                                    exit_status
                                ));
                                *process_guard = None;
                                break;
                            }
                            Ok(None) => {
                                // Process is still running
                            }
                            Err(e) => {
                                error!("Error checking process status: {}", e);
                            }
                        }
                    }
                }

                // Perform health check
                match health_checker.check_health().await {
                    Ok(health_status) => {
                        if !health_status.is_healthy {
                            warn!(
                                "Server health check failed: {:?}",
                                health_status.error_messages
                            );
                        }
                    }
                    Err(e) => {
                        error!("Health check error: {}", e);
                    }
                }
            }
        });
    }
}

/// Detect startup failure reasons from stderr output
fn detect_startup_failure(line: &str) -> Option<StartupFailureReason> {
    let line_lower = line.to_lowercase();

    // CUDA out of memory errors
    if line_lower.contains("cudamalloc failed: out of memory")
        || line_lower.contains("failed to allocate cuda0 buffer")
        || line_lower.contains("ggml_backend_cuda_buffer_type_alloc_buffer")
    {
        return Some(StartupFailureReason::InsufficientVRAM);
    }

    // Context size too large errors
    if line_lower.contains("failed to allocate buffer for kv cache")
        || line_lower.contains("alloc_tensor_range: failed to allocate")
    {
        return Some(StartupFailureReason::ContextTooLarge);
    }

    // Model loading failures
    if line_lower.contains("failed to load model")
        || line_lower.contains("srv    load_model: failed to load model")
    {
        return Some(StartupFailureReason::ModelTooLarge);
    }

    // General out of memory
    if line_lower.contains("out of memory")
        || line_lower.contains("memory allocation failed")
        || line_lower.contains("insufficient memory")
    {
        return Some(StartupFailureReason::OutOfMemory);
    }

    // Context initialization failures
    if line_lower.contains("failed to initialize the context")
        || line_lower.contains("llama_init_from_model: failed to initialize")
    {
        return Some(StartupFailureReason::ContextTooLarge);
    }

    // Exit due to model loading error
    if line_lower.contains("exiting due to model loading error") {
        return Some(StartupFailureReason::ModelTooLarge);
    }

    None
}

impl Drop for LlamaCppServerManager {
    fn drop(&mut self) {
        // Note: async drop is not stable yet, so we can't properly await stop()
        // The process should be killed when Child drops due to kill_on_drop(true)
        warn!("LlamaCppServerManager dropped - server process will be terminated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

    async fn create_test_manager() -> (LlamaCppServerManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = create_test_config();
        config.model_path = temp_dir
            .path()
            .join("test-model.gguf")
            .to_string_lossy()
            .to_string();

        // Create dummy model file
        tokio::fs::write(&config.model_path, b"dummy model")
            .await
            .unwrap();

        let model_manager = Arc::new(ModelManager::new_mock());
        let manager = LlamaCppServerManager::new(config, model_manager)
            .await
            .unwrap();

        (manager, temp_dir)
    }

    #[test]
    fn test_server_config_creation() {
        let config = create_test_config();
        let server_config = ServerConfig::from_llamacpp_config(&config);

        assert_eq!(server_config.host, "127.0.0.1");
        assert_eq!(server_config.port, 11435);
        assert_eq!(server_config.context_size, 2048);
        assert_eq!(server_config.gpu_layers, Some(32));
        assert_eq!(server_config.threads, Some(4));
    }

    #[test]
    fn test_server_args_building() {
        let config = create_test_config();
        let server_config = ServerConfig::from_llamacpp_config(&config);
        let args = server_config.build_args();

        assert!(args.contains(&"--model".to_string()));
        assert!(args.contains(&"--host".to_string()));
        assert!(args.contains(&"127.0.0.1".to_string()));
        assert!(args.contains(&"--port".to_string()));
        assert!(args.contains(&"11435".to_string()));
        assert!(args.contains(&"--ctx-size".to_string()));
        assert!(args.contains(&"2048".to_string()));
        assert!(args.contains(&"--n-gpu-layers".to_string()));
        assert!(args.contains(&"32".to_string()));
        assert!(args.contains(&"--api-key".to_string()));
    }

    #[tokio::test]
    async fn test_server_manager_creation() {
        let (manager, _temp_dir) = create_test_manager().await;

        assert!(!manager.is_running().await);

        let info = manager.get_server_info().await;
        assert_eq!(info.state, ServerState::Stopped);
        assert!(info.pid.is_none());
        assert!(info.uptime.is_none());
    }

    #[tokio::test]
    async fn test_server_state_transitions() {
        let (manager, _temp_dir) = create_test_manager().await;

        // Initial state should be stopped
        let info = manager.get_server_info().await;
        assert_eq!(info.state, ServerState::Stopped);

        // We can't easily test actual server starting without the executable,
        // but we can test the state management structure
        assert!(!manager.is_running().await);
    }

    #[test]
    fn test_server_state_serialization() {
        let state = ServerState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ServerState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);

        let error_state = ServerState::Error("test error".to_string());
        let json = serde_json::to_string(&error_state).unwrap();
        let deserialized: ServerState = serde_json::from_str(&json).unwrap();
        assert_eq!(error_state, deserialized);
    }

    #[tokio::test]
    async fn test_executable_finding() {
        let (manager, _temp_dir) = create_test_manager().await;

        // This will likely fail unless llama-server is actually installed,
        // but it shouldn't panic
        let result = manager.find_llamacpp_executable().await;

        match result {
            Ok(path) => {
                // If found, should be a valid path
                assert!(path.is_absolute() || path.starts_with("./"));
            }
            Err(LocalLlmError::ServerUnavailable(msg)) => {
                // Expected when executable is not available
                assert!(msg.contains("not found"));
            }
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            }
        }
    }
}
