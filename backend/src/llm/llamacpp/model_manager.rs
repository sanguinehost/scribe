// backend/src/llm/llamacpp/model_manager.rs
// Model downloading, caching, and lifecycle management

use crate::llm::llamacpp::{LocalLlmError, LlamaCppConfig};
use crate::llm::llamacpp::hardware::{ModelSelection, HardwareCapabilities, detect_hardware, select_model_variant};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Model download progress callback
pub type ProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Model manager for downloading and caching models
#[derive(Clone)]
pub struct ModelManager {
    config: LlamaCppConfig,
    http_client: HttpClient,
    models_dir: PathBuf,
    active_model: Arc<RwLock<Option<String>>>,
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
            let relative_path = Path::new(&config.model_path).parent()
                .unwrap_or(Path::new("models"));
            
            // Ensure we have an absolute path
            if relative_path.is_absolute() {
                relative_path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|e| LocalLlmError::ModelLoadFailed(format!("Failed to get current directory: {}", e)))?
                    .join(relative_path)
            }
        };
        
        // Ensure models directory exists
        fs::create_dir_all(&models_dir).await
            .map_err(|e| LocalLlmError::ModelLoadFailed(format!("Failed to create models directory: {}", e)))?;
        
        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(300)) // 5 minutes for downloads
            .build()
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("HTTP client error: {}", e)))?;
        
        let manager = Self {
            config,
            http_client,
            models_dir,
            active_model: Arc::new(RwLock::new(None)),
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
        let hardware = detect_hardware()
            .map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;
        
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
        let hardware = detect_hardware()
            .map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;
        
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
    async fn analyze_model_recommendation(&self, model: &ModelStatus, hardware: &HardwareCapabilities) -> ModelRecommendation {
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
            if let Some(best_gpu) = hardware.gpu_info.iter()
                .filter(|gpu| gpu.vram_gb.map_or(false, |vram| vram >= min_vram))
                .max_by_key(|gpu| gpu.vram_gb.unwrap_or(0.0) as i32) {
                
                let vram_ratio = best_gpu.vram_gb.unwrap_or(0.0) / min_vram;
                if vram_ratio >= 1.5 {
                    priority_score += 300;
                    performance_estimate = ModelPerformance::High;
                    reasons.push(format!("Excellent GPU fit ({:.1}GB VRAM available)", best_gpu.vram_gb.unwrap_or(0.0)));
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
            },
            name if name.contains("gemma") && name.contains("27b") => {
                priority_score += 30;
                reasons.push("Google Gemma model with good performance".to_string());
            },
            name if name.contains("gpt-oss") && name.contains("20b") => {
                priority_score += 20;
                reasons.push("Reliable GPT-OSS model".to_string());
            },
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
    pub async fn get_best_recommendation(&self) -> Result<Option<ModelRecommendation>, LocalLlmError> {
        let recommendations = self.recommend_models().await?;
        Ok(recommendations.into_iter().next())
    }
    
    /// Download and activate the best recommended model
    pub async fn download_best_model(&self) -> Result<String, LocalLlmError> {
        let recommendation = self.get_best_recommendation().await?
            .ok_or_else(|| LocalLlmError::ModelLoadFailed("No compatible models found".to_string()))?;
        
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
        
        info!("Downloading recommended model: {}", recommendation.model_name);
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
        let local_path = self.models_dir.join(model_filename);
        
        info!("Starting download of {} from {}", model_filename, download_url);
        
        // Check if file already exists
        if local_path.exists() {
            info!("Model {} already exists, skipping download", model_filename);
            return Ok(local_path);
        }
        
        // Create temporary download path
        let temp_path = local_path.with_extension("tmp");
        
        // Start HTTP request
        let response = self.http_client.get(download_url).send().await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("HTTP request failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(LocalLlmError::ModelDownloadFailed(
                format!("HTTP error {}: {}", response.status(), download_url)
            ));
        }
        
        // Get content length for progress tracking
        let total_size = response.content_length().unwrap_or(0);
        info!("Downloading {} bytes", total_size);
        
        // Create file for writing
        let mut file = fs::File::create(&temp_path).await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Failed to create file: {}", e)))?;
        
        // Download with progress tracking
        let mut downloaded = 0u64;
        let mut stream = response.bytes_stream();
        let start_time = std::time::Instant::now();
        
        while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
            let chunk = chunk
                .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Download chunk error: {}", e)))?;
            
            file.write_all(&chunk).await
                .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Write error: {}", e)))?;
            
            downloaded += chunk.len() as u64;
            
            // Update progress
            if total_size > 0 {
                let progress = DownloadProgress {
                    total_bytes: total_size,
                    downloaded_bytes: downloaded,
                    percentage: (downloaded as f32 / total_size as f32) * 100.0,
                    speed_bytes_per_sec: Some(downloaded as f32 / start_time.elapsed().as_secs_f32()),
                };
                
                // Call progress callback if set
                if let Some(callback) = self.download_progress.read().await.as_ref() {
                    callback(downloaded, total_size);
                }
                
                if downloaded % (10 * 1024 * 1024) == 0 { // Log every 10MB
                    debug!("Download progress: {:.1}% ({}/{})", 
                           progress.percentage, downloaded, total_size);
                }
            }
        }
        
        // Flush and close file
        file.flush().await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Flush error: {}", e)))?;
        drop(file);
        
        // Rename temp file to final path
        fs::rename(&temp_path, &local_path).await
            .map_err(|e| LocalLlmError::ModelDownloadFailed(format!("Rename error: {}", e)))?;
        
        info!("Successfully downloaded {} to {}", model_filename, local_path.display());
        Ok(local_path)
    }
    
    /// Get list of available models and their status
    pub async fn list_models(&self) -> Result<Vec<ModelStatus>, LocalLlmError> {
        let hardware = detect_hardware()
            .map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;
        
        let active_model = self.active_model.read().await.clone();
        let mut models = Vec::new();
        
        for model_variant in ModelSelection::all_models() {
            let filename = model_variant.filename();
            let path = self.models_dir.join(filename);
            let is_downloaded = path.exists();
            let is_active = active_model.as_ref().map_or(false, |active| active == filename);
            
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
            
            models.push(ModelStatus {
                name: filename.to_string(),
                path,
                size_bytes,
                is_downloaded,
                is_active,
                hardware_compatible,
            });
        }
        
        Ok(models)
    }
    
    /// Get the currently active model name
    pub fn get_active_model(&self) -> Option<String> {
        // This is a synchronous version that tries to read without blocking
        self.active_model.try_read().ok().and_then(|guard| guard.clone())
    }
    
    /// Get the currently active model name (async version)
    pub async fn get_active_model_async(&self) -> Option<String> {
        self.active_model.read().await.clone()
    }
    
    /// Switch to a different model
    pub async fn switch_model(&self, model_filename: &str) -> Result<(), LocalLlmError> {
        info!("Switching to model: {}", model_filename);
        
        // Check if model file exists
        let model_path = self.models_dir.join(model_filename);
        if !model_path.exists() {
            return Err(LocalLlmError::ModelLoadFailed(
                format!("Model file not found: {}", model_path.display())
            ));
        }
        
        // Validate hardware compatibility
        let hardware = detect_hardware()
            .map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;
        
        // Find the model variant
        let model_variant = ModelSelection::all_models()
            .into_iter()
            .find(|m| m.filename() == model_filename)
            .ok_or_else(|| LocalLlmError::ModelLoadFailed(
                format!("Unknown model variant: {}", model_filename)
            ))?;
        
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
        
        // Set as active model
        let mut active = self.active_model.write().await;
        *active = Some(model_filename.to_string());
        
        info!("Successfully switched to model: {}", model_filename);
        Ok(())
    }
    
    /// Delete a downloaded model
    pub async fn delete_model(&self, model_filename: &str) -> Result<(), LocalLlmError> {
        info!("Deleting model: {}", model_filename);
        
        let model_path = self.models_dir.join(model_filename);
        
        if !model_path.exists() {
            warn!("Model file not found for deletion: {}", model_path.display());
            return Ok(());
        }
        
        // Don't delete if it's the active model
        if let Some(active) = self.get_active_model_async().await {
            if active == model_filename {
                return Err(LocalLlmError::ModelLoadFailed(
                    "Cannot delete active model. Switch to another model first.".to_string()
                ));
            }
        }
        
        fs::remove_file(&model_path).await
            .map_err(|e| LocalLlmError::ModelLoadFailed(format!("Failed to delete model: {}", e)))?;
        
        info!("Successfully deleted model: {}", model_filename);
        Ok(())
    }
    
    /// Get model file path
    pub async fn get_model_path(&self, model_filename: Option<&str>) -> Result<PathBuf, LocalLlmError> {
        let filename = match model_filename {
            Some(name) => name.to_string(),
            None => self.get_active_model_async().await
                .ok_or_else(|| LocalLlmError::ModelLoadFailed("No active model set".to_string()))?
        };
        
        let path = self.models_dir.join(&filename);
        
        if !path.exists() {
            return Err(LocalLlmError::ModelLoadFailed(
                format!("Model file not found: {}", path.display())
            ));
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
        // Rough estimates based on typical model sizes
        // This could be made more accurate by checking actual model sizes
        ModelSelection::all_models().iter().map(|model| {
            match model {
                ModelSelection::GptOss20bQ4 { .. } => 12_000_000_000, // ~12GB
                ModelSelection::Qwen3_30B_A3B_Thinking_Q4 { .. } => 19_000_000_000, // ~19GB
                ModelSelection::Qwen3_30B_A3B_Instruct_Q4 { .. } => 19_000_000_000, // ~19GB
                ModelSelection::Gemma3_27B_IT_Q4 { .. } => 17_000_000_000, // ~17GB
            }
        }).sum()
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
        config.model_path = temp_dir.path().join("test-model.gguf").to_string_lossy().to_string();
        
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
        tokio::fs::write(&model_path, b"dummy model content").await.unwrap();
        
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