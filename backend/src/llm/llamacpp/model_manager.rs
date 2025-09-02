// backend/src/llm/llamacpp/model_manager.rs
// Model downloading, caching, and lifecycle management

use crate::llm::llamacpp::hardware::{
    ContextSizeConfig, HardwareCapabilities, ModelSelection, calculate_optimal_context_size,
    detect_hardware, select_model_variant,
};
use crate::llm::llamacpp::{LlamaCppConfig, LocalLlmError};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

/// Model download progress callback
pub type ProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Model manager for downloading and caching models
#[derive(Clone)]
pub struct ModelManager {
    config: LlamaCppConfig,
    http_client: HttpClient,
    models_dir: PathBuf,
    active_model: Arc<RwLock<Option<String>>>,
    active_context_config: Arc<RwLock<Option<ContextSizeConfig>>>,
    download_progress: Arc<RwLock<Option<ProgressCallback>>>,
}

/// Model download status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: Option<u64>,
    pub is_downloaded: bool,
    pub is_active: bool,
    pub hardware_compatible: bool,
    pub context_requirements: Option<ContextSizeConfig>,
}

/// Model download progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub percentage: f32,
    pub speed_bytes_per_sec: Option<f32>,
}

/// Model recommendation with smart analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRecommendation {
    pub model_name: String,
    pub priority_score: i32,
    pub performance_estimate: ModelPerformance,
    pub reasons: Vec<String>,
    pub estimated_download_time: Option<std::time::Duration>,
    pub disk_space_required: u64,
}

/// Expected model performance level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelPerformance {
    Low,    // CPU-only or minimal GPU
    Medium, // Good GPU fit
    High,   // Excellent GPU fit with plenty of VRAM
}

impl ModelManager {
    /// Create a new model manager with lazy initialization
    pub async fn new(config: LlamaCppConfig) -> Result<Self, LocalLlmError> {
        info!("Initializing model manager (lazy mode)");

        let models_dir = {
            let model_path = Path::new(&config.model_path);
            let parent_dir = model_path.parent().unwrap_or(Path::new("models"));

            // Handle the specific case where the path is "../models/filename.gguf"
            // Convert "../models" to just "models" to make it relative to current directory
            let relative_path = if parent_dir == Path::new("../models") {
                Path::new("models")
            } else {
                parent_dir
            };

            // Ensure we have an absolute path
            if relative_path.is_absolute() {
                relative_path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|e| {
                        LocalLlmError::ModelLoadFailed(format!(
                            "Failed to get current directory: {}",
                            e
                        ))
                    })?
                    .join(relative_path)
            }
        };

        // Ensure models directory exists
        fs::create_dir_all(&models_dir).await.map_err(|e| {
            LocalLlmError::ModelLoadFailed(format!("Failed to create models directory: {}", e))
        })?;

        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(600)) // 10 minutes total timeout for large files
            .connect_timeout(std::time::Duration::from_secs(30)) // 30 seconds to establish connection
            .pool_idle_timeout(Some(std::time::Duration::from_secs(90))) // Keep connections alive
            .tcp_keepalive(Some(std::time::Duration::from_secs(60))) // TCP keepalive for long downloads
            .user_agent("SanguineScribe/1.0") // Identify ourselves properly
            .build()
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("HTTP client error: {}", e)))?;

        let manager = Self {
            config,
            http_client,
            models_dir,
            active_model: Arc::new(RwLock::new(None)),
            active_context_config: Arc::new(RwLock::new(None)),
            download_progress: Arc::new(RwLock::new(None)),
        };

        // Check if any models are already downloaded and auto-select the best one
        manager.initialize_from_existing_models().await?;

        Ok(manager)
    }

    /// Initialize from existing downloaded models (lazy approach)
    async fn initialize_from_existing_models(&self) -> Result<(), LocalLlmError> {
        info!("Initializing from existing models (lazy mode)");

        // Detect hardware for compatibility checking
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        // Find the best already-downloaded model that's compatible with current hardware
        let models = self.list_models().await?;
        let best_existing = models
            .into_iter()
            .filter(|m| m.is_downloaded && m.hardware_compatible)
            .max_by_key(|m| {
                // Prioritize models by capability (rough scoring)
                match m.name.as_str() {
                    name if name.contains("qwen3") && name.contains("30b") => 4,
                    name if name.contains("gemma") && name.contains("27b") => 3,
                    name if name.contains("gpt-oss") && name.contains("20b") => 2,
                    _ => 1,
                }
            });

        if let Some(best_model) = best_existing {
            info!("Found existing compatible model: {}", best_model.name);
            let mut active = self.active_model.write().await;
            *active = Some(best_model.name);
        } else {
            info!("No existing models found. Use recommend_models() to see download options.");
        }

        Ok(())
    }

    /// Get smart model recommendations based on hardware capabilities
    pub async fn recommend_models(&self) -> Result<Vec<ModelRecommendation>, LocalLlmError> {
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        let models = self.list_models().await?;
        let mut recommendations = Vec::new();

        for model in models {
            if !model.hardware_compatible {
                continue;
            }

            let recommendation = self.analyze_model_recommendation(&model, &hardware).await;
            recommendations.push(recommendation);
        }

        // Sort by recommendation priority (best first)
        recommendations.sort_by_key(|r| std::cmp::Reverse(r.priority_score));

        Ok(recommendations)
    }

    /// Analyze a model and create a recommendation
    async fn analyze_model_recommendation(
        &self,
        model: &ModelStatus,
        hardware: &HardwareCapabilities,
    ) -> ModelRecommendation {
        let model_variant = ModelSelection::all_models()
            .into_iter()
            .find(|m| m.filename() == model.name)
            .expect("Model variant should exist");

        let requirements = model_variant.requirements();

        // Calculate priority score (higher = better)
        let mut priority_score = 0;
        let mut reasons = Vec::new();
        let mut performance_estimate = ModelPerformance::Medium;

        // Already downloaded gets highest priority
        if model.is_downloaded {
            priority_score += 1000;
            reasons.push("Already downloaded".to_string());
        }

        // GPU availability and VRAM scoring
        if let Some(min_vram) = requirements.min_vram_gb {
            if let Some(best_gpu) = hardware
                .gpu_info
                .iter()
                .filter(|gpu| gpu.vram_gb.map_or(false, |vram| vram >= min_vram))
                .max_by_key(|gpu| gpu.vram_gb.unwrap_or(0.0) as i32)
            {
                let vram_ratio = best_gpu.vram_gb.unwrap_or(0.0) / min_vram;
                if vram_ratio >= 1.5 {
                    priority_score += 300;
                    performance_estimate = ModelPerformance::High;
                    reasons.push(format!(
                        "Excellent GPU fit ({:.1}GB VRAM available)",
                        best_gpu.vram_gb.unwrap_or(0.0)
                    ));
                } else if vram_ratio >= 1.2 {
                    priority_score += 200;
                    performance_estimate = ModelPerformance::Medium;
                    reasons.push("Good GPU fit".to_string());
                } else {
                    priority_score += 100;
                    performance_estimate = ModelPerformance::Low;
                    reasons.push("Minimum GPU requirements met".to_string());
                }
            }
        } else {
            // CPU-only model
            priority_score += 50;
            performance_estimate = ModelPerformance::Low;
            reasons.push("CPU-only model (slower but compatible)".to_string());
        }

        // Model capability scoring
        match model.name.as_str() {
            name if name.contains("qwen3") && name.contains("30b") => {
                priority_score += 40;
                reasons.push("Latest Qwen3 model with excellent reasoning".to_string());
            }
            name if name.contains("gemma") && name.contains("27b") => {
                priority_score += 30;
                reasons.push("Google Gemma model with good performance".to_string());
            }
            name if name.contains("gpt-oss") && name.contains("20b") => {
                priority_score += 20;
                reasons.push("Reliable GPT-OSS model".to_string());
            }
            _ => {}
        }

        // RAM scoring
        let ram_ratio = hardware.available_ram_gb / requirements.min_ram_gb;
        if ram_ratio >= 2.0 {
            priority_score += 20;
        } else if ram_ratio >= 1.5 {
            priority_score += 10;
        }

        // CPU scoring
        if hardware.cpu_cores >= requirements.min_cpu_cores * 2 {
            priority_score += 15;
        } else if hardware.cpu_cores >= requirements.min_cpu_cores {
            priority_score += 5;
        }

        ModelRecommendation {
            model_name: model.name.clone(),
            priority_score,
            performance_estimate,
            reasons,
            estimated_download_time: if model.is_downloaded {
                None
            } else {
                Some(self.estimate_download_time(&model_variant))
            },
            disk_space_required: model_variant.download_size_bytes(),
        }
    }

    /// Estimate download time based on model size and average connection speed
    fn estimate_download_time(&self, model: &ModelSelection) -> std::time::Duration {
        let size_bytes = model.download_size_bytes();
        // Assume average download speed of 10 Mbps (1.25 MB/s)
        let assumed_speed_bytes_per_sec = 1.25 * 1024.0 * 1024.0; // 1.25 MB/s
        let seconds = (size_bytes as f64) / assumed_speed_bytes_per_sec;
        std::time::Duration::from_secs(seconds as u64)
    }

    /// Get the best recommended model for immediate download
    pub async fn get_best_recommendation(
        &self,
    ) -> Result<Option<ModelRecommendation>, LocalLlmError> {
        let recommendations = self.recommend_models().await?;
        Ok(recommendations.into_iter().next())
    }

    /// Download and activate the best recommended model
    pub async fn download_best_model(&self) -> Result<String, LocalLlmError> {
        let recommendation = self.get_best_recommendation().await?.ok_or_else(|| {
            LocalLlmError::ModelLoadFailed("No compatible models found".to_string())
        })?;

        // If already downloaded, just activate it
        if self.models_dir.join(&recommendation.model_name).exists() {
            self.switch_model(&recommendation.model_name).await?;
            return Ok(recommendation.model_name);
        }

        // Find the model variant and download it
        let model_variant = ModelSelection::all_models()
            .into_iter()
            .find(|m| m.filename() == recommendation.model_name)
            .ok_or_else(|| LocalLlmError::ModelLoadFailed("Model variant not found".to_string()))?;

        info!(
            "Downloading recommended model: {}",
            recommendation.model_name
        );
        let _path = self.download_model(&model_variant).await?;

        // Activate the downloaded model
        self.switch_model(&recommendation.model_name).await?;

        Ok(recommendation.model_name)
    }

    /// Download a model from remote URL
    #[instrument(skip(self))]
    pub async fn download_model(&self, model: &ModelSelection) -> Result<PathBuf, LocalLlmError> {
        let model_filename = model.filename();
        let download_url = model.download_url();
        let local_path = self.models_dir.join(&model_filename);

        info!(
            "Starting download of {} from {}",
            model_filename, download_url
        );

        // Check if file already exists
        if local_path.exists() {
            info!("Model {} already exists, skipping download", model_filename);
            return Ok(local_path);
        }

        // Create temporary download path
        let temp_path = local_path.with_extension("tmp");

        // Start HTTP request
        let response = self
            .http_client
            .get(&download_url)
            .send()
            .await
            .map_err(|e| {
                LocalLlmError::ModelDownloadFailed(format!("HTTP request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(LocalLlmError::ModelDownloadFailed(format!(
                "HTTP error {}: {}",
                response.status(),
                download_url
            )));
        }

        // Get content length for progress tracking
        let total_size = response.content_length().unwrap_or(0);
        info!("Downloading {} bytes", total_size);

        // Create file for writing
        let mut file = fs::File::create(&temp_path).await.map_err(|e| {
            LocalLlmError::ModelDownloadFailed(format!("Failed to create file: {}", e))
        })?;

        // Download with progress tracking and retry logic
        let mut downloaded = 0u64;
        let mut stream = response.bytes_stream();
        let start_time = std::time::Instant::now();
        let mut consecutive_errors = 0u32;
        const MAX_CONSECUTIVE_ERRORS: u32 = 3;

        loop {
            let chunk_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(30), // 30 second timeout per chunk
                futures::StreamExt::next(&mut stream),
            )
            .await;

            match chunk_result {
                Ok(Some(chunk_result)) => {
                    match chunk_result {
                        Ok(chunk) => {
                            // Reset error counter on successful chunk
                            consecutive_errors = 0;

                            // Write chunk to file with flushing
                            file.write_all(&chunk).await.map_err(|e| {
                                LocalLlmError::ModelDownloadFailed(format!("Write error: {}", e))
                            })?;
                            file.flush().await.map_err(|e| {
                                LocalLlmError::ModelDownloadFailed(format!("Flush error: {}", e))
                            })?;

                            downloaded += chunk.len() as u64;
                        }
                        Err(e) => {
                            consecutive_errors += 1;
                            warn!(
                                "Download chunk error (attempt {}/{}): {}",
                                consecutive_errors, MAX_CONSECUTIVE_ERRORS, e
                            );

                            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                                return Err(LocalLlmError::ModelDownloadFailed(format!(
                                    "Too many consecutive chunk errors: {}",
                                    e
                                )));
                            }

                            // Wait a bit before trying next chunk
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    // Stream ended normally
                    break;
                }
                Err(_) => {
                    // Chunk timeout
                    consecutive_errors += 1;
                    warn!(
                        "Download chunk timeout (attempt {}/{})",
                        consecutive_errors, MAX_CONSECUTIVE_ERRORS
                    );

                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        return Err(LocalLlmError::ModelDownloadFailed(
                            "Too many consecutive chunk timeouts".to_string(),
                        ));
                    }

                    // Wait a bit before trying next chunk
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            }

            // Update progress
            if total_size > 0 {
                let progress = DownloadProgress {
                    total_bytes: total_size,
                    downloaded_bytes: downloaded,
                    percentage: (downloaded as f32 / total_size as f32) * 100.0,
                    speed_bytes_per_sec: Some(
                        downloaded as f32 / start_time.elapsed().as_secs_f32(),
                    ),
                };

                // Call progress callback if set
                if let Some(callback) = self.download_progress.read().await.as_ref() {
                    callback(downloaded, total_size);
                }

                if downloaded % (10 * 1024 * 1024) == 0 {
                    // Log every 10MB
                    debug!(
                        "Download progress: {:.1}% ({}/{})",
                        progress.percentage, downloaded, total_size
                    );
                }
            }
        }

        // Flush and close file
        file.flush()
            .await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Flush error: {}", e)))?;
        drop(file);

        // Rename temp file to final path
        fs::rename(&temp_path, &local_path)
            .await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Rename error: {}", e)))?;

        info!(
            "Successfully downloaded {} to {}",
            model_filename,
            local_path.display()
        );
        Ok(local_path)
    }

    /// Get list of available models and their status
    pub async fn list_models(&self) -> Result<Vec<ModelStatus>, LocalLlmError> {
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        let active_model = self.active_model.read().await.clone();
        let mut models = Vec::new();

        info!("ModelManager::list_models: Starting model enumeration");
        info!("ModelManager: models_dir = {:?}", self.models_dir);
        info!("ModelManager: active_model = {:?}", active_model);

        // List all actual files in models directory for comparison
        info!(
            "ModelManager: About to read directory: {:?}",
            self.models_dir
        );
        info!(
            "ModelManager: Directory exists: {}",
            self.models_dir.exists()
        );
        info!(
            "ModelManager: Directory is_dir: {}",
            self.models_dir.is_dir()
        );

        match fs::read_dir(&self.models_dir).await {
            Ok(mut entries) => {
                info!("ModelManager: Successfully opened directory for reading");
                info!("ModelManager: Files found in models directory:");
                let mut found_any = false;
                let mut count = 0;

                loop {
                    match entries.next_entry().await {
                        Ok(Some(entry)) => {
                            count += 1;
                            if let Some(filename) = entry.file_name().to_str() {
                                found_any = true;
                                info!(
                                    "  - {} ({})",
                                    filename,
                                    if filename.ends_with(".gguf") {
                                        "GGUF"
                                    } else {
                                        "other"
                                    }
                                );

                                // Extra debug for GGUF files
                                if filename.ends_with(".gguf") {
                                    let file_path = entry.path();
                                    if let Ok(metadata) = fs::metadata(&file_path).await {
                                        info!("    File size: {} bytes", metadata.len());
                                        info!("    File permissions: {:?}", metadata.permissions());
                                    }
                                }
                            } else {
                                info!("  - [unreadable filename]");
                            }
                        }
                        Ok(None) => {
                            info!(
                                "ModelManager: Finished reading directory, processed {} entries",
                                count
                            );
                            break;
                        }
                        Err(e) => {
                            error!("ModelManager: Error reading directory entry: {}", e);
                            break;
                        }
                    }
                }

                if !found_any {
                    warn!(
                        "ModelManager: No files found in models directory after reading {} entries!",
                        count
                    );
                }
            }
            Err(e) => {
                error!(
                    "ModelManager: Failed to read models directory {:?}: {}",
                    self.models_dir, e
                );

                // Try synchronous fallback for debugging
                info!("ModelManager: Attempting synchronous fallback directory read");
                match std::fs::read_dir(&self.models_dir) {
                    Ok(entries) => {
                        info!("ModelManager: Synchronous directory read succeeded!");
                        for (i, entry) in entries.enumerate() {
                            match entry {
                                Ok(entry) => {
                                    if let Some(filename) = entry.file_name().to_str() {
                                        info!(
                                            "  Sync entry {}: {} ({})",
                                            i,
                                            filename,
                                            if filename.ends_with(".gguf") {
                                                "GGUF"
                                            } else {
                                                "other"
                                            }
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("  Sync entry {} error: {}", i, e);
                                }
                            }
                        }
                    }
                    Err(sync_e) => {
                        error!("ModelManager: Both async and sync directory reads failed!");
                        error!("  Async error: {}", e);
                        error!("  Sync error: {}", sync_e);

                        // Try one more approach - check if we can list with ls command
                        use std::process::Command;
                        match Command::new("ls")
                            .args(["-la", &self.models_dir.to_string_lossy()])
                            .output()
                        {
                            Ok(output) => {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                info!("ModelManager: Command 'ls -la' output:");
                                info!("  stdout: {}", stdout);
                                if !stderr.is_empty() {
                                    warn!("  stderr: {}", stderr);
                                }
                            }
                            Err(cmd_e) => {
                                error!("ModelManager: Even 'ls' command failed: {}", cmd_e);
                            }
                        }
                    }
                }
            }
        }

        for model_variant in ModelSelection::all_models() {
            let filename = model_variant.filename();
            let path = self.models_dir.join(&filename);
            let is_downloaded = path.exists();
            let is_active = active_model
                .as_ref()
                .map_or(false, |active| active == &filename);

            // Enhanced debug logging for all models
            debug!("ModelManager: Checking model variant:");
            debug!("  - Base model: {}", model_variant.base_model.name);
            debug!("  - Quantization: {:?}", model_variant.quantization);
            debug!("  - Expected filename: {}", filename);
            debug!("  - Full path: {:?}", path);
            debug!("  - File exists: {}", is_downloaded);
            debug!("  - Is active: {}", is_active);

            // Extra logging for the problematic model
            if filename.contains("gpt-oss-20b") {
                info!("ModelManager: GPT-OSS-20B model details:");
                info!("  - filename: {}", filename);
                info!("  - path: {:?}", path);
                info!("  - exists: {}", is_downloaded);
                info!("  - is_active: {}", is_active);

                // Check if any similar files exist with different naming
                if !is_downloaded {
                    if let Ok(entries) = fs::read_dir(&self.models_dir).await {
                        let mut dir_entries = entries;
                        while let Some(entry) = dir_entries.next_entry().await.unwrap_or(None) {
                            if let Some(entry_filename) = entry.file_name().to_str() {
                                if entry_filename.contains("gpt-oss")
                                    || entry_filename.contains("20b")
                                {
                                    info!("  - Found similar file: {}", entry_filename);
                                }
                            }
                        }
                    }
                }
            }

            // Check hardware compatibility
            let requirements = model_variant.requirements();
            let hardware_compatible = hardware.available_ram_gb >= requirements.min_ram_gb
                && hardware.cpu_cores >= requirements.min_cpu_cores
                && if let Some(min_vram) = requirements.min_vram_gb {
                    hardware.gpu_info.iter().any(|gpu| {
                        gpu.vram_gb.map_or(false, |vram| vram >= min_vram)
                            && (!requirements.requires_cuda || gpu.cuda_capable)
                    })
                } else {
                    true // CPU-only model
                };

            // Get file size if downloaded
            let size_bytes = if is_downloaded {
                fs::metadata(&path).await.ok().map(|m| m.len())
            } else {
                None
            };

            // Calculate context requirements if hardware compatible
            let context_requirements = if hardware_compatible {
                Some(calculate_optimal_context_size(&model_variant, &hardware))
            } else {
                None
            };

            models.push(ModelStatus {
                name: filename,
                path,
                size_bytes,
                is_downloaded,
                is_active,
                hardware_compatible,
                context_requirements,
            });
        }

        Ok(models)
    }

    /// Get the currently active model name
    pub fn get_active_model(&self) -> Option<String> {
        // This is a synchronous version that tries to read without blocking
        self.active_model
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Get the currently active model name (async version)
    pub async fn get_active_model_async(&self) -> Option<String> {
        self.active_model.read().await.clone()
    }

    /// Get the current context configuration for the active model
    pub async fn get_active_context_config(&self) -> Option<ContextSizeConfig> {
        self.active_context_config.read().await.clone()
    }

    /// Get adaptive configuration for the currently active model
    /// This returns a LlamaCppConfig with adaptive context settings applied
    pub async fn get_adaptive_config(&self) -> Result<LlamaCppConfig, LocalLlmError> {
        let active_model_name = self
            .get_active_model_async()
            .await
            .ok_or_else(|| LocalLlmError::ModelLoadFailed("No active model set".to_string()))?;

        let context_config = self.get_active_context_config().await.ok_or_else(|| {
            LocalLlmError::ModelLoadFailed("No context configuration available".to_string())
        })?;

        // Create a new config based on the current one but with adaptive settings
        let mut adaptive_config = self.config.clone();
        adaptive_config.context_size = context_config.optimal_context_size;
        adaptive_config.gpu_layers = context_config.optimal_gpu_layers;

        // Update model path to point to the active model
        let model_path = self.get_model_path(Some(&active_model_name)).await?;
        adaptive_config.model_path = model_path.to_string_lossy().to_string();

        info!(
            "Generated adaptive config for {}: context_size={}, gpu_layers={:?}",
            active_model_name, adaptive_config.context_size, adaptive_config.gpu_layers
        );

        Ok(adaptive_config)
    }

    /// Switch to a different model
    pub async fn switch_model(&self, model_filename: &str) -> Result<(), LocalLlmError> {
        info!("Switching to model: {}", model_filename);

        // Check if model file exists
        let model_path = self.models_dir.join(model_filename);
        if !model_path.exists() {
            return Err(LocalLlmError::ModelLoadFailed(format!(
                "Model file not found: {}",
                model_path.display()
            )));
        }

        // Validate hardware compatibility
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        // Find the model variant
        let model_variant = ModelSelection::all_models()
            .into_iter()
            .find(|m| m.filename() == model_filename)
            .ok_or_else(|| {
                LocalLlmError::ModelLoadFailed(format!("Unknown model variant: {}", model_filename))
            })?;

        let requirements = model_variant.requirements();

        // Check basic requirements
        if hardware.available_ram_gb < requirements.min_ram_gb {
            return Err(LocalLlmError::InsufficientResources {
                ram_gb: requirements.min_ram_gb,
                vram_gb: requirements.min_vram_gb.unwrap_or(0.0),
            });
        }

        if hardware.cpu_cores < requirements.min_cpu_cores {
            return Err(LocalLlmError::InsufficientResources {
                ram_gb: requirements.min_ram_gb,
                vram_gb: requirements.min_vram_gb.unwrap_or(0.0),
            });
        }

        // Check GPU requirements
        if let Some(min_vram) = requirements.min_vram_gb {
            let gpu_compatible = hardware.gpu_info.iter().any(|gpu| {
                gpu.vram_gb.map_or(false, |vram| vram >= min_vram)
                    && (!requirements.requires_cuda || gpu.cuda_capable)
            });

            if !gpu_compatible {
                return Err(LocalLlmError::InsufficientResources {
                    ram_gb: requirements.min_ram_gb,
                    vram_gb: min_vram,
                });
            }
        }

        // Calculate adaptive context configuration
        let context_config = calculate_optimal_context_size(&model_variant, &hardware);

        if let Some(ref warning) = context_config.memory_warning {
            warn!(
                "Context configuration warning for {}: {}",
                model_filename, warning
            );
        }

        info!(
            "Adaptive context for {}: size={}, gpu_layers={:?}",
            model_filename, context_config.optimal_context_size, context_config.optimal_gpu_layers
        );

        // Set as active model and store context configuration
        let mut active = self.active_model.write().await;
        let mut context = self.active_context_config.write().await;
        *active = Some(model_filename.to_string());
        *context = Some(context_config);

        info!("Successfully switched to model: {}", model_filename);
        Ok(())
    }

    /// Delete a downloaded model
    pub async fn delete_model(&self, model_filename: &str) -> Result<(), LocalLlmError> {
        info!("Deleting model: {}", model_filename);

        let model_path = self.models_dir.join(model_filename);

        if !model_path.exists() {
            warn!(
                "Model file not found for deletion: {}",
                model_path.display()
            );
            return Ok(());
        }

        // Don't delete if it's the active model
        if let Some(active) = self.get_active_model_async().await {
            if active == model_filename {
                return Err(LocalLlmError::ModelLoadFailed(
                    "Cannot delete active model. Switch to another model first.".to_string(),
                ));
            }
        }

        fs::remove_file(&model_path).await.map_err(|e| {
            LocalLlmError::ModelLoadFailed(format!("Failed to delete model: {}", e))
        })?;

        info!("Successfully deleted model: {}", model_filename);
        Ok(())
    }

    /// Get model file path
    pub async fn get_model_path(
        &self,
        model_filename: Option<&str>,
    ) -> Result<PathBuf, LocalLlmError> {
        let filename = match model_filename {
            Some(name) => name.to_string(),
            None => self
                .get_active_model_async()
                .await
                .ok_or_else(|| LocalLlmError::ModelLoadFailed("No active model set".to_string()))?,
        };

        let path = self.models_dir.join(&filename);

        if !path.exists() {
            return Err(LocalLlmError::ModelLoadFailed(format!(
                "Model file not found: {}",
                path.display()
            )));
        }

        Ok(path)
    }

    /// Set download progress callback
    pub async fn set_progress_callback(&self, callback: Option<ProgressCallback>) {
        let mut progress = self.download_progress.write().await;
        *progress = callback;
    }

    /// Get models directory path
    pub fn get_models_dir(&self) -> &PathBuf {
        &self.models_dir
    }

    /// Get estimated disk space required for all models
    pub fn get_total_disk_space_required() -> u64 {
        // Calculate space required for all available models
        ModelSelection::all_models()
            .iter()
            .map(|model| model.download_size_bytes())
            .sum()
    }

    /// Activate a specific model by name
    pub async fn activate_model(&self, model_name: &str) -> Result<(), LocalLlmError> {
        info!("Activating model: {}", model_name);

        // Normalize the model name - handle different formats
        let normalized_name = if model_name.ends_with(".gguf") {
            model_name.to_string()
        } else {
            // Try to match against existing files first
            let models = self.list_models().await?;
            if let Some(existing_model) = models.iter().find(|m| {
                m.name.to_lowercase().contains(&model_name.to_lowercase())
                    || model_name
                        .to_lowercase()
                        .contains(&m.name.to_lowercase().replace(".gguf", ""))
            }) {
                existing_model.name.clone()
            } else {
                // Fall back to adding .gguf extension
                format!("{}.gguf", model_name)
            }
        };

        // Check if the model file exists
        let model_path = self.models_dir.join(&normalized_name);
        if !model_path.exists() {
            return Err(LocalLlmError::ModelNotFound(format!(
                "Model file not found: {}",
                model_path.display()
            )));
        }

        // Find the model variant for context calculation
        let model_variant = ModelSelection::all_models()
            .into_iter()
            .find(|m| m.filename() == normalized_name)
            .ok_or_else(|| {
                LocalLlmError::ModelNotFound(format!("Unknown model variant: {}", normalized_name))
            })?;

        // Detect hardware for context calculation
        let hardware =
            detect_hardware().map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;

        // Calculate adaptive context configuration
        let context_config = calculate_optimal_context_size(&model_variant, &hardware);

        if let Some(ref warning) = context_config.memory_warning {
            warn!(
                "Context configuration warning for {}: {}",
                normalized_name, warning
            );
        }

        info!(
            "Adaptive context for {}: size={}, gpu_layers={:?}",
            normalized_name, context_config.optimal_context_size, context_config.optimal_gpu_layers
        );

        // Set as active model and store context configuration
        let mut active_model = self.active_model.write().await;
        let mut context = self.active_context_config.write().await;
        *active_model = Some(normalized_name.clone());
        *context = Some(context_config);

        info!("Model activated successfully: {}", normalized_name);
        Ok(())
    }
}

#[cfg(feature = "local-llm")]
impl ModelManager {
    /// Create a mock model manager for testing
    pub fn new_mock() -> Self {
        Self {
            config: LlamaCppConfig::default(),
            http_client: HttpClient::new(),
            models_dir: PathBuf::from("test_models"),
            active_model: Arc::new(RwLock::new(Some("test-model.gguf".to_string()))),
            active_context_config: Arc::new(RwLock::new(None)),
            download_progress: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    async fn create_test_manager() -> (ModelManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = LlamaCppConfig::default();
        config.model_path = temp_dir
            .path()
            .join("test-model.gguf")
            .to_string_lossy()
            .to_string();

        let manager = ModelManager::new(config).await.unwrap();
        (manager, temp_dir)
    }

    #[tokio::test]
    async fn test_model_manager_creation() {
        let (manager, _temp_dir) = create_test_manager().await;
        assert!(manager.models_dir.exists());
        assert!(manager.get_active_model().is_some());
    }

    #[tokio::test]
    async fn test_list_models() {
        let (manager, _temp_dir) = create_test_manager().await;
        let models = manager.list_models().await.unwrap();

        assert!(!models.is_empty());

        // Check that all models have required fields
        for model in models {
            assert!(!model.name.is_empty());
            assert!(model.path.extension().is_some());
            // Hardware compatibility depends on actual hardware, so we don't assert it
        }
    }

    #[tokio::test]
    async fn test_model_path_operations() {
        let (manager, temp_dir) = create_test_manager().await;

        // Create a dummy model file
        let model_filename = "test-model.gguf";
        let model_path = temp_dir.path().join(model_filename);
        tokio::fs::write(&model_path, b"dummy model content")
            .await
            .unwrap();

        // Test getting model path
        let retrieved_path = manager.get_model_path(Some(model_filename)).await.unwrap();
        assert_eq!(retrieved_path, model_path);
    }

    #[tokio::test]
    async fn test_switch_model_validation() {
        let (manager, _temp_dir) = create_test_manager().await;

        // Try to switch to non-existent model
        let result = manager.switch_model("non-existent.gguf").await;
        assert!(result.is_err());

        if let Err(LocalLlmError::ModelLoadFailed(msg)) = result {
            assert!(msg.contains("not found"));
        } else {
            panic!("Expected ModelLoadFailed error");
        }
    }

    #[test]
    fn test_disk_space_calculation() {
        let total_space = ModelManager::get_total_disk_space_required();
        assert!(total_space > 0);
        assert!(total_space < 100_000_000_000); // Less than 100GB (sanity check)
    }

    #[tokio::test]
    async fn test_progress_callback() {
        let (manager, _temp_dir) = create_test_manager().await;

        let progress_called = Arc::new(tokio::sync::Mutex::new(false));
        let progress_called_clone = Arc::clone(&progress_called);

        let callback: ProgressCallback = Arc::new(move |downloaded, total| {
            let progress_called = Arc::clone(&progress_called_clone);
            tokio::spawn(async move {
                let mut called = progress_called.lock().await;
                *called = true;
            });
        });

        manager.set_progress_callback(Some(callback)).await;

        // Verify callback was set (we can't easily test actual progress without real downloads)
        let has_callback = manager.download_progress.read().await.is_some();
        assert!(has_callback);
    }
}
