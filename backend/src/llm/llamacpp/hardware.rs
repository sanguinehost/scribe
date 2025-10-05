// backend/src/llm/llamacpp/hardware.rs
// Hardware detection and capability assessment for LlamaCpp

use crate::llm::llamacpp::LocalLlmError;
use serde::{Deserialize, Serialize};
use std::process::Command;
use sysinfo::System;
use tracing::{debug, error, warn};

/// Hardware requirements for different model configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareRequirements {
    pub min_ram_gb: f32,
    pub min_vram_gb: Option<f32>, // None for CPU-only
    pub min_cpu_cores: usize,
    pub recommended_ram_gb: f32,
    pub recommended_vram_gb: Option<f32>,
    pub requires_cuda: bool,
}

/// Detected hardware capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub total_ram_gb: f32,
    pub available_ram_gb: f32,
    pub cpu_cores: usize,
    pub cpu_arch: String,
    pub gpu_info: Vec<GpuInfo>,
    pub has_cuda: bool,
    pub has_metal: bool,
    pub os: String,
}

/// GPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vram_gb: Option<f32>,
    pub cuda_capable: bool,
    pub metal_capable: bool,
}

/// Quantization levels available for models
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuantizationLevel {
    Q2_K,   // ~2.63 bits per weight - most compressed
    Q3_K_S, // ~3.50 bits per weight - small 3-bit
    Q3_K_M, // ~3.91 bits per weight - medium 3-bit
    Q4_0,   // ~4.55 bits per weight - legacy 4-bit
    Q4_K_S, // ~4.14 bits per weight - small 4-bit
    Q4_K_M, // ~4.83 bits per weight - medium 4-bit (recommended)
    Q5_0,   // ~5.54 bits per weight - legacy 5-bit
    Q5_K_S, // ~5.54 bits per weight - small 5-bit
    Q5_K_M, // ~6.15 bits per weight - medium 5-bit
    Q6_K,   // ~6.56 bits per weight - 6-bit
    Q8_0,   // ~8.50 bits per weight - 8-bit (very high quality)
}

impl QuantizationLevel {
    /// Get the file suffix for this quantization level
    pub fn file_suffix(&self) -> &'static str {
        match self {
            Self::Q2_K => "Q2_K",
            Self::Q3_K_S => "Q3_K_S",
            Self::Q3_K_M => "Q3_K_M",
            Self::Q4_0 => "Q4_0",
            Self::Q4_K_S => "Q4_K_S",
            Self::Q4_K_M => "Q4_K_M",
            Self::Q5_0 => "Q5_0",
            Self::Q5_K_S => "Q5_K_S",
            Self::Q5_K_M => "Q5_K_M",
            Self::Q6_K => "Q6_K",
            Self::Q8_0 => "Q8_0",
        }
    }

    /// Get the approximate compression ratio compared to FP16
    pub fn compression_ratio(&self) -> f32 {
        match self {
            Self::Q2_K => 6.08,   // ~16/2.63
            Self::Q3_K_S => 4.57, // ~16/3.50
            Self::Q3_K_M => 4.09, // ~16/3.91
            Self::Q4_0 => 3.52,   // ~16/4.55
            Self::Q4_K_S => 3.86, // ~16/4.14
            Self::Q4_K_M => 3.31, // ~16/4.83
            Self::Q5_0 => 2.89,   // ~16/5.54
            Self::Q5_K_S => 2.89, // ~16/5.54
            Self::Q5_K_M => 2.60, // ~16/6.15
            Self::Q6_K => 2.44,   // ~16/6.56
            Self::Q8_0 => 1.88,   // ~16/8.50
        }
    }

    /// Get quality score (0-100, higher is better)
    pub fn quality_score(&self) -> u8 {
        match self {
            Self::Q2_K => 60,
            Self::Q3_K_S => 70,
            Self::Q3_K_M => 75,
            Self::Q4_0 => 80,
            Self::Q4_K_S => 82,
            Self::Q4_K_M => 85, // Sweet spot
            Self::Q5_0 => 88,
            Self::Q5_K_S => 90,
            Self::Q5_K_M => 92,
            Self::Q6_K => 95,
            Self::Q8_0 => 98,
        }
    }

    /// Get speed score (0-100, higher is faster)
    pub fn speed_score(&self) -> u8 {
        match self {
            Self::Q2_K => 95,
            Self::Q3_K_S => 90,
            Self::Q3_K_M => 88,
            Self::Q4_0 => 85,
            Self::Q4_K_S => 87,
            Self::Q4_K_M => 83,
            Self::Q5_0 => 80,
            Self::Q5_K_S => 78,
            Self::Q5_K_M => 75,
            Self::Q6_K => 70,
            Self::Q8_0 => 65,
        }
    }

    /// Get all quantization levels ordered by quality (best first)
    pub fn all_by_quality() -> Vec<Self> {
        vec![
            Self::Q8_0,
            Self::Q6_K,
            Self::Q5_K_M,
            Self::Q5_K_S,
            Self::Q5_0,
            Self::Q4_K_M,
            Self::Q4_K_S,
            Self::Q4_0,
            Self::Q3_K_M,
            Self::Q3_K_S,
            Self::Q2_K,
        ]
    }

    /// Get human-readable quality description
    pub fn quality_description(&self) -> &'static str {
        match self {
            Self::Q8_0 => "Very High Quality",
            Self::Q6_K => "High Quality",
            Self::Q5_K_M => "Good Quality",
            Self::Q5_K_S => "Good Quality",
            Self::Q5_0 => "Good Quality",
            Self::Q4_K_M => "Balanced",
            Self::Q4_K_S => "Balanced",
            Self::Q4_0 => "Balanced",
            Self::Q3_K_M => "Compact",
            Self::Q3_K_S => "Compact",
            Self::Q2_K => "Very Compact",
        }
    }
}

/// Base model without quantization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseModel {
    pub name: String,
    pub description: String,
    pub parameter_count: String,
    pub context_window: u32,
    pub huggingface_repo: String,
    pub base_size_gb: f32, // Size in FP16
}

/// Available model selections with their requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSelection {
    pub base_model: BaseModel,
    pub quantization: QuantizationLevel,
    pub requirements: HardwareRequirements,
}

impl ModelSelection {
    /// Get all available base models
    pub fn get_base_models() -> Vec<BaseModel> {
        vec![
            BaseModel {
                name: "llama-3.3-70b-instruct".to_string(),
                description:
                    "Llama-3.3-70B-Instruct - Latest Meta model with excellent performance"
                        .to_string(),
                parameter_count: "70B".to_string(),
                context_window: 131072,
                huggingface_repo: "bartowski/Llama-3.3-70B-Instruct-GGUF".to_string(),
                base_size_gb: 140.0, // Rough FP16 estimate
            },
            BaseModel {
                name: "gemma-3-27b-it".to_string(),
                description:
                    "Gemma-3-27B-IT - Google's multimodal instruction-tuned model with 128K context"
                        .to_string(),
                parameter_count: "27B".to_string(),
                context_window: 131072,
                huggingface_repo: "unsloth/gemma-3-27b-it-GGUF".to_string(),
                base_size_gb: 54.0,
            },
            BaseModel {
                name: "qwen2.5-14b-instruct".to_string(),
                description: "Qwen2.5-14B-Instruct - Excellent reasoning model, great for RTX GPUs"
                    .to_string(),
                parameter_count: "14B".to_string(),
                context_window: 131072,
                huggingface_repo: "bartowski/Qwen2.5-14B-Instruct-GGUF".to_string(),
                base_size_gb: 28.0,
            },
            BaseModel {
                name: "gpt-oss-20b".to_string(),
                description: "GPT-OSS-20B - Open source 20B parameter model".to_string(),
                parameter_count: "20B".to_string(),
                context_window: 32768,
                huggingface_repo: "unsloth/gpt-oss-20b-GGUF".to_string(),
                base_size_gb: 40.0,
            },
            BaseModel {
                name: "llama-3.1-8b-instruct".to_string(),
                description: "Llama-3.1-8B-Instruct - Popular balanced model, fast and capable"
                    .to_string(),
                parameter_count: "8B".to_string(),
                context_window: 131072,
                huggingface_repo: "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF".to_string(),
                base_size_gb: 16.0,
            },
            BaseModel {
                name: "qwen2.5-7b-instruct".to_string(),
                description: "Qwen2.5-7B-Instruct - Compact model perfect for mid-range GPUs"
                    .to_string(),
                parameter_count: "7B".to_string(),
                context_window: 131072,
                huggingface_repo: "bartowski/Qwen2.5-7B-Instruct-GGUF".to_string(),
                base_size_gb: 14.0,
            },
            BaseModel {
                name: "llama-3.2-3b-instruct".to_string(),
                description: "Llama-3.2-3B-Instruct - Ultra-compact model for lower-end hardware"
                    .to_string(),
                parameter_count: "3B".to_string(),
                context_window: 131072,
                huggingface_repo: "bartowski/Llama-3.2-3B-Instruct-GGUF".to_string(),
                base_size_gb: 6.0,
            },
        ]
    }

    /// Get all available model selections with their requirements
    pub fn all_models() -> Vec<Self> {
        let mut models = Vec::new();

        for base_model in Self::get_base_models() {
            for quantization in QuantizationLevel::all_by_quality() {
                let model_size = base_model.base_size_gb / quantization.compression_ratio();

                // Calculate VRAM requirements (model + context buffer)
                let context_buffer_gb = 2.0; // Reserve for context/KV cache
                let min_vram = model_size + context_buffer_gb;
                let recommended_vram = min_vram * 1.3; // 30% headroom

                // RAM requirements (for CPU offloading scenarios)
                let min_ram = model_size * 1.5; // Allow for some CPU offloading
                let recommended_ram = model_size * 2.0; // Full model in RAM

                // CPU requirements based on model size
                let min_cpu_cores = match base_model.parameter_count.as_str() {
                    param if param.contains("30B") => 8,
                    param if param.contains("27B") => 6,
                    param if param.contains("20B") => 4,
                    param if param.contains("14B") => 4,
                    param if param.contains("7B") => 2,
                    _ => 4,
                };

                let requirements = HardwareRequirements {
                    min_ram_gb: min_ram,
                    min_vram_gb: if min_vram <= 32.0 {
                        Some(min_vram)
                    } else {
                        None
                    }, // Don't require GPU for huge models
                    min_cpu_cores,
                    recommended_ram_gb: recommended_ram,
                    recommended_vram_gb: if recommended_vram <= 32.0 {
                        Some(recommended_vram)
                    } else {
                        None
                    },
                    requires_cuda: false, // All models can work on CPU if needed
                };

                models.push(Self {
                    base_model: base_model.clone(),
                    quantization,
                    requirements,
                });
            }
        }

        models
    }

    /// Get the model file name
    pub fn filename(&self) -> String {
        format!(
            "{}-{}.gguf",
            self.base_model.name,
            self.quantization.file_suffix()
        )
    }

    /// Get the download URL for this model
    pub fn download_url(&self) -> String {
        format!(
            "https://huggingface.co/{}/resolve/main/{}-{}.gguf?download=true",
            self.base_model.huggingface_repo,
            self.base_model.name,
            self.quantization.file_suffix()
        )
    }

    /// Get the SHA256 checksum for this model (for integrity verification)
    pub fn sha256_checksum(&self) -> Option<&str> {
        // TODO: Add real checksums after downloading and verifying each model
        // This would be maintained in a separate checksum database
        None
    }

    /// Get the approximate download size in bytes
    pub fn download_size_bytes(&self) -> u64 {
        let base_size_gb = self.base_model.base_size_gb;
        let compressed_size_gb = base_size_gb / self.quantization.compression_ratio();
        (compressed_size_gb * 1024.0 * 1024.0 * 1024.0) as u64
    }

    /// Get the approximate download size in GB
    pub fn download_size_gb(&self) -> f32 {
        self.download_size_bytes() as f32 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get the base model name without quantization
    pub fn base_model_name(&self) -> &str {
        &self.base_model.name
    }

    /// Get quantization level as string
    pub fn quantization_level(&self) -> String {
        format!("{:?}", self.quantization)
    }

    /// Get the hardware requirements for this model
    pub fn requirements(&self) -> &HardwareRequirements {
        &self.requirements
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        let quantization_desc = match self.quantization {
            QuantizationLevel::Q8_0 => "Very High Quality",
            QuantizationLevel::Q6_K => "High Quality",
            QuantizationLevel::Q5_K_M | QuantizationLevel::Q5_K_S | QuantizationLevel::Q5_0 => {
                "Good Quality"
            }
            QuantizationLevel::Q4_K_M | QuantizationLevel::Q4_K_S | QuantizationLevel::Q4_0 => {
                "Balanced"
            }
            QuantizationLevel::Q3_K_M | QuantizationLevel::Q3_K_S => "Compact",
            QuantizationLevel::Q2_K => "Very Compact",
        };

        let vram_req = if let Some(vram) = self.requirements.min_vram_gb {
            format!(" ({:.0}GB+ VRAM)", vram)
        } else {
            " (CPU Compatible)".to_string()
        };

        format!(
            "{} ({}) - {} - {}{}",
            self.base_model.description,
            self.quantization.file_suffix(),
            quantization_desc,
            self.base_model.parameter_count,
            vram_req
        )
    }

    /// Get the context window size for this model in tokens
    pub fn context_window_size(&self) -> u32 {
        self.base_model.context_window
    }

    /// Get the maximum output tokens for this model
    pub fn max_output_tokens(&self) -> u32 {
        // Conservative max output to leave room for input context (6% of context window)
        (self.base_model.context_window as f32 * 0.06) as u32
    }

    /// Get the model ID for API usage
    pub fn model_id(&self) -> String {
        format!(
            "{}-{}",
            self.base_model.name.replace("_", "-"),
            self.quantization.file_suffix().to_lowercase()
        )
    }
}

/// Detect hardware capabilities of the current system
pub fn detect_hardware() -> Result<HardwareCapabilities, LocalLlmError> {
    debug!("Starting hardware detection");

    let mut sys = System::new_all();
    sys.refresh_all();

    // Get basic system info
    let total_ram_gb = sys.total_memory() as f32 / (1024.0 * 1024.0 * 1024.0);
    let available_ram_gb = sys.available_memory() as f32 / (1024.0 * 1024.0 * 1024.0);
    let cpu_cores = sys.cpus().len();
    let cpu_arch = std::env::consts::ARCH.to_string();
    let os = std::env::consts::OS.to_string();

    debug!(
        "System info - RAM: {:.1}GB total, {:.1}GB available, CPU cores: {}, arch: {}, OS: {}",
        total_ram_gb, available_ram_gb, cpu_cores, cpu_arch, os
    );

    // Detect GPU capabilities
    let gpu_info = detect_gpu_info(&os)?;
    let has_cuda = gpu_info.iter().any(|gpu| gpu.cuda_capable);
    let has_metal = gpu_info.iter().any(|gpu| gpu.metal_capable);

    debug!(
        "GPU detection - CUDA: {}, Metal: {}, GPUs: {}",
        has_cuda,
        has_metal,
        gpu_info.len()
    );

    Ok(HardwareCapabilities {
        total_ram_gb,
        available_ram_gb,
        cpu_cores,
        cpu_arch,
        gpu_info,
        has_cuda,
        has_metal,
        os,
    })
}

/// Detect GPU information for the current platform
fn detect_gpu_info(os: &str) -> Result<Vec<GpuInfo>, LocalLlmError> {
    let mut gpu_info = Vec::new();

    match os {
        "linux" | "windows" => {
            // Try to detect NVIDIA GPUs using nvidia-smi with extended info
            if let Ok(output) = Command::new("nvidia-smi")
                .args(&[
                    "--query-gpu=name,memory.total,compute_cap",
                    "--format=csv,noheader,nounits",
                ])
                .output()
            {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    for line in output_str.lines() {
                        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 2 {
                            let name = parts[0].to_string();
                            let vram_mb: Option<f32> = parts[1].parse().ok();
                            let vram_gb = vram_mb.map(|mb| mb / 1024.0);

                            // Enhanced CUDA capability detection
                            let cuda_capable = if parts.len() >= 3 {
                                // Check compute capability version
                                if let Ok(compute_cap) = parts[2].parse::<f32>() {
                                    compute_cap >= 3.5 // Minimum for modern CUDA
                                } else {
                                    true // Assume CUDA capable if we can't parse
                                }
                            } else {
                                true // Assume CUDA capable for NVIDIA GPUs
                            };

                            debug!(
                                "Detected NVIDIA GPU: {} with {:.1}GB VRAM, CUDA: {}",
                                name,
                                vram_gb.unwrap_or(0.0),
                                cuda_capable
                            );

                            gpu_info.push(GpuInfo {
                                name,
                                vram_gb,
                                cuda_capable,
                                metal_capable: false,
                            });
                        }
                    }
                }
            }

            // Try alternative NVIDIA detection if nvidia-smi failed
            if gpu_info.is_empty() {
                if let Ok(output) = Command::new("nvidia-smi")
                    .args(&[
                        "--query-gpu=name,memory.total",
                        "--format=csv,noheader,nounits",
                    ])
                    .output()
                {
                    if output.status.success() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        for line in output_str.lines() {
                            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                            if parts.len() >= 2 {
                                let name = parts[0].to_string();
                                let vram_mb: Option<f32> = parts[1].parse().ok();
                                let vram_gb = vram_mb.map(|mb| mb / 1024.0);

                                debug!(
                                    "Detected NVIDIA GPU (fallback): {} with {:.1}GB VRAM",
                                    name,
                                    vram_gb.unwrap_or(0.0)
                                );

                                gpu_info.push(GpuInfo {
                                    name,
                                    vram_gb,
                                    cuda_capable: true,
                                    metal_capable: false,
                                });
                            }
                        }
                    }
                }
            }

            // Try to detect AMD GPUs using rocm-smi (if available)
            if let Ok(output) = Command::new("rocm-smi")
                .args(&["--showproductname", "--showmeminfo", "vram"])
                .output()
            {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    // Parse AMD GPU info (basic implementation)
                    // This would need more sophisticated parsing in practice
                    if output_str.contains("AMD") || output_str.contains("Radeon") {
                        debug!("AMD GPU detected, adding basic info");
                        gpu_info.push(GpuInfo {
                            name: "AMD GPU (ROCm Compatible)".to_string(),
                            vram_gb: None, // Would need more parsing
                            cuda_capable: false,
                            metal_capable: false,
                        });
                    }
                }
            }

            if gpu_info.is_empty() {
                debug!("No NVIDIA or AMD GPUs detected, or GPU tools not available");
            }
        }
        "macos" => {
            // Enhanced macOS GPU detection
            if std::env::consts::ARCH == "aarch64" {
                // Try to get system info about GPU
                if let Ok(output) = Command::new("system_profiler")
                    .args(&["SPDisplaysDataType", "-json"])
                    .output()
                {
                    if output.status.success() {
                        // Basic Apple Silicon detection
                        gpu_info.push(GpuInfo {
                            name: "Apple GPU".to_string(),
                            vram_gb: None, // Unified memory architecture
                            cuda_capable: false,
                            metal_capable: true,
                        });
                        debug!("Apple Silicon GPU detected with Metal support");
                    }
                }
            } else {
                // Intel Mac - check for discrete GPU
                if let Ok(output) = Command::new("system_profiler")
                    .args(&["SPDisplaysDataType"])
                    .output()
                {
                    if output.status.success() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        if output_str.contains("AMD") {
                            gpu_info.push(GpuInfo {
                                name: "AMD GPU (macOS)".to_string(),
                                vram_gb: None, // Would need parsing
                                cuda_capable: false,
                                metal_capable: true,
                            });
                            debug!("Intel Mac with AMD GPU detected");
                        }
                    }
                }
            }
        }
        _ => {
            debug!("Unknown OS: {}, skipping GPU detection", os);
        }
    }

    Ok(gpu_info)
}

/// Select the best model variant based on hardware capabilities with smart quantization
pub fn select_model_variant(hw: &HardwareCapabilities) -> ModelSelection {
    debug!("Selecting model variant for hardware: {:#?}", hw);

    let models = ModelSelection::all_models();
    let mut compatible_models = Vec::new();

    // Find all compatible models
    for model in models {
        let requirements = model.requirements();

        // Check basic requirements
        if hw.available_ram_gb >= requirements.min_ram_gb
            && hw.cpu_cores >= requirements.min_cpu_cores
        {
            // Check GPU requirements if specified
            if let Some(min_vram) = requirements.min_vram_gb {
                if let Some(gpu) = hw.gpu_info.iter().find(|gpu| {
                    gpu.vram_gb.map_or(false, |vram| vram >= min_vram)
                        && (!requirements.requires_cuda || gpu.cuda_capable)
                }) {
                    let score = calculate_model_score(&model, hw, Some(gpu));
                    compatible_models.push((model, Some(gpu), score));
                }
            } else {
                // CPU-only model
                let score = calculate_model_score(&model, hw, None);
                compatible_models.push((model, None, score));
            }
        }
    }

    if compatible_models.is_empty() {
        // No compatible models found, create a minimal fallback
        warn!("No compatible models found for hardware, creating CPU-only fallback");
        return create_fallback_model();
    }

    // Sort by score (highest first) and select the best
    compatible_models.sort_by(|a, b| b.2.total_cmp(&a.2));
    let (best_model, best_gpu, score) = &compatible_models[0];

    debug!(
        "Selected model: {} with score {:.2}",
        best_model.description(),
        score
    );
    if let Some(gpu) = best_gpu {
        debug!(
            "Using GPU: {} with {:.1}GB VRAM",
            gpu.name,
            gpu.vram_gb.unwrap_or(0.0)
        );
    }

    best_model.clone()
}

/// Calculate a score for model selection (higher is better)
fn calculate_model_score(
    model: &ModelSelection,
    hw: &HardwareCapabilities,
    gpu: Option<&GpuInfo>,
) -> f32 {
    let mut score = 0.0;

    // Base score from model quality and quantization
    score += model.quantization.quality_score() as f32;

    // Parameter count bonus (larger models are generally better if they fit)
    let param_bonus = match model.base_model.parameter_count.as_str() {
        param if param.contains("30B") => 100.0,
        param if param.contains("27B") => 90.0,
        param if param.contains("20B") => 80.0,
        param if param.contains("14B") => 70.0,
        param if param.contains("7B") => 60.0,
        _ => 50.0,
    };
    score += param_bonus;

    // GPU utilization bonus
    if let Some(gpu) = gpu {
        if let Some(vram) = gpu.vram_gb {
            let model_vram_req = model.requirements().min_vram_gb.unwrap_or(0.0);
            let vram_ratio = vram / model_vram_req;

            // Optimal VRAM utilization (between 70-90% usage gets highest score)
            let utilization = model_vram_req / vram;
            let utilization_score = if utilization > 0.9 {
                // Too close to limit, penalize
                -20.0
            } else if utilization > 0.7 {
                // Good utilization
                50.0 * utilization
            } else if utilization > 0.5 {
                // Reasonable utilization
                30.0 * utilization
            } else {
                // Underutilized, but still bonus for having GPU
                20.0 * utilization
            };
            score += utilization_score;
        }
    }

    // Memory headroom bonus
    let ram_ratio = hw.available_ram_gb / model.requirements().min_ram_gb;
    if ram_ratio > 2.0 {
        score += 15.0;
    } else if ram_ratio > 1.5 {
        score += 10.0;
    } else if ram_ratio > 1.2 {
        score += 5.0;
    }

    // CPU headroom bonus
    let cpu_ratio = hw.cpu_cores as f32 / model.requirements().min_cpu_cores as f32;
    if cpu_ratio > 2.0 {
        score += 10.0;
    } else if cpu_ratio > 1.5 {
        score += 5.0;
    }

    // Special bonus for reasoning models (Thinking variants)
    if model.base_model.name.contains("thinking") {
        score += 20.0;
    }

    score
}

/// Create a minimal fallback model for very limited hardware
fn create_fallback_model() -> ModelSelection {
    let base_model = BaseModel {
        name: "llama-3.3-7b-instruct".to_string(),
        description: "Llama 3.3 7B Instruct - Minimal fallback model".to_string(),
        parameter_count: "7B".to_string(),
        context_window: 131072,
        huggingface_repo: "unsloth/Llama-3.3-7B-Instruct-GGUF".to_string(),
        base_size_gb: 14.0,
    };

    let quantization = QuantizationLevel::Q2_K; // Most compressed

    let requirements = HardwareRequirements {
        min_ram_gb: 4.0,
        min_vram_gb: None, // CPU-only
        min_cpu_cores: 2,
        recommended_ram_gb: 8.0,
        recommended_vram_gb: None,
        requires_cuda: false,
    };

    ModelSelection {
        base_model,
        quantization,
        requirements,
    }
}

/// Select optimal quantization level for a given base model and hardware
pub fn select_optimal_quantization(
    base_model: &BaseModel,
    hw: &HardwareCapabilities,
    prefer_quality: bool,
) -> QuantizationLevel {
    let available_vram = hw
        .gpu_info
        .iter()
        .filter_map(|gpu| gpu.vram_gb)
        .max_by(|a, b| a.total_cmp(b))
        .unwrap_or(0.0);

    let context_buffer = 2.0; // GB reserved for context
    let usable_vram = available_vram - context_buffer;

    debug!(
        "Selecting quantization for {} with {:.1}GB usable VRAM",
        base_model.name, usable_vram
    );

    if usable_vram <= 0.0 {
        // CPU-only, use most compressed
        return QuantizationLevel::Q2_K;
    }

    // Try quantization levels in order of preference
    let quantizations = if prefer_quality {
        QuantizationLevel::all_by_quality()
    } else {
        // For speed preference, reverse the order
        let mut levels = QuantizationLevel::all_by_quality();
        levels.reverse();
        levels
    };

    for quant in quantizations {
        let model_size = base_model.base_size_gb / quant.compression_ratio();
        if model_size <= usable_vram {
            debug!(
                "Selected {} quantization: model size {:.1}GB fits in {:.1}GB VRAM",
                quant.file_suffix(),
                model_size,
                usable_vram
            );
            return quant;
        }
    }

    // If nothing fits, use most compressed
    debug!("No quantization fits in VRAM, using most compressed (Q2_K)");
    QuantizationLevel::Q2_K
}

/// Check if hardware meets recommended specs for the selected model
pub fn check_recommended_specs(hw: &HardwareCapabilities, model: &ModelSelection) -> bool {
    let requirements = model.requirements();

    let ram_ok = hw.available_ram_gb >= requirements.recommended_ram_gb;

    let gpu_ok = if let Some(recommended_vram) = requirements.recommended_vram_gb {
        hw.gpu_info
            .iter()
            .any(|gpu| gpu.vram_gb.map_or(false, |vram| vram >= recommended_vram))
    } else {
        true // No GPU requirements
    };

    ram_ok && gpu_ok
}

/// Context size configuration for adaptive sizing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSizeConfig {
    pub optimal_context_size: usize,
    pub fallback_sizes: Vec<usize>, // In descending order of preference
    pub requires_cpu_offloading: bool,
    pub optimal_gpu_layers: Option<i32>,
    pub memory_warning: Option<String>,
}

impl Default for ContextSizeConfig {
    fn default() -> Self {
        Self {
            optimal_context_size: 32768,
            fallback_sizes: vec![16384, 8192, 4096, 2048],
            requires_cpu_offloading: false,
            optimal_gpu_layers: Some(999), // All layers to GPU by default
            memory_warning: None,
        }
    }
}

/// Calculate optimal context size based on model and hardware capabilities
pub fn calculate_optimal_context_size(
    model: &ModelSelection,
    hw: &HardwareCapabilities,
) -> ContextSizeConfig {
    debug!(
        "Calculating optimal context size for model: {}",
        model.base_model_name()
    );

    // Get the best GPU for this model
    let best_gpu = hw
        .gpu_info
        .iter()
        .filter(|gpu| gpu.cuda_capable) // Only consider CUDA GPUs for now
        .filter_map(|gpu| gpu.vram_gb.map(|vram| (gpu, vram)))
        .max_by_key(|(_, vram)| (*vram * 1000.0) as u64)
        .map(|(gpu, _)| gpu);

    if let Some(gpu) = best_gpu {
        calculate_gpu_context_config(model, gpu, hw)
    } else {
        // CPU-only fallback
        calculate_cpu_context_config(model, hw)
    }
}

/// Calculate context configuration for GPU usage
fn calculate_gpu_context_config(
    model: &ModelSelection,
    gpu: &GpuInfo,
    hw: &HardwareCapabilities,
) -> ContextSizeConfig {
    let available_vram = gpu.vram_gb.unwrap_or(0.0);
    let model_size_gb = model.download_size_gb();

    debug!(
        "GPU config calculation - Available VRAM: {:.1}GB, Model size: {:.1}GB",
        available_vram, model_size_gb
    );

    // Reserve memory for system and other processes
    let system_reserve_gb = 1.5; // Reserve 1.5GB for system
    let safety_margin_gb = 0.5; // Additional safety margin
    let usable_vram = available_vram - system_reserve_gb - safety_margin_gb;

    if model_size_gb > usable_vram {
        // Model won't fit in GPU, use CPU-only configuration
        debug!("Model too large for GPU, using CPU configuration");
        return calculate_cpu_context_config(model, hw);
    }

    // Calculate available memory for KV cache
    let kv_cache_budget = usable_vram - model_size_gb;
    debug!("KV cache budget: {:.1}GB", kv_cache_budget);

    if kv_cache_budget < 0.5 {
        // Very tight on memory, use CPU offloading
        debug!("Very tight VRAM budget, enabling CPU offloading");
        return calculate_hybrid_context_config(model, gpu, hw);
    }

    // Context size calculation based on model architecture
    // KV cache size ≈ 2 * n_layers * n_heads * head_dim * seq_len * precision_bytes / 1024³
    // For simplicity, use empirical formulas based on known model sizes

    let context_sizes = vec![32768, 16384, 8192, 4096, 2048];
    let mut optimal_context = 2048; // Conservative default
    let mut fallback_sizes = Vec::new();

    for &ctx_size in &context_sizes {
        let estimated_kv_cache = estimate_kv_cache_size_gb(model, ctx_size);
        debug!(
            "Context size {} estimated KV cache: {:.2}GB",
            ctx_size, estimated_kv_cache
        );

        if estimated_kv_cache <= kv_cache_budget {
            if optimal_context == 2048 {
                // First size that fits
                optimal_context = ctx_size;
            }
        } else {
            // This size is too large, add smaller sizes to fallbacks
            fallback_sizes.push(ctx_size / 2);
        }
    }

    // Add smaller fallback sizes
    let mut current_size = optimal_context;
    while current_size >= 1024 {
        current_size /= 2;
        if current_size >= 1024 {
            fallback_sizes.push(current_size);
        }
    }

    // Remove duplicates and sort descending
    fallback_sizes.sort_by(|a, b| b.cmp(a));
    fallback_sizes.dedup();

    let memory_warning = if kv_cache_budget < 2.0 {
        Some(format!(
            "Limited VRAM budget ({:.1}GB available for context). Consider using a smaller model for larger contexts.",
            kv_cache_budget
        ))
    } else {
        None
    };

    ContextSizeConfig {
        optimal_context_size: optimal_context,
        fallback_sizes,
        requires_cpu_offloading: false,
        optimal_gpu_layers: Some(999), // All layers on GPU
        memory_warning,
    }
}

/// Calculate context configuration for CPU-only usage
fn calculate_cpu_context_config(
    model: &ModelSelection,
    hw: &HardwareCapabilities,
) -> ContextSizeConfig {
    debug!("Calculating CPU-only context configuration");

    let model_size_gb = model.download_size_gb();
    let safety_margin = 2.0; // Reserve 2GB for system
    let available_for_context = (hw.available_ram_gb - model_size_gb - safety_margin).max(0.0);

    // For CPU, context memory usage is lower since we don't need to store KV cache in contiguous GPU memory
    let optimal_context = if available_for_context > 8.0 {
        32768 // Plenty of RAM
    } else if available_for_context > 4.0 {
        16384 // Decent RAM
    } else if available_for_context > 2.0 {
        8192 // Limited RAM
    } else {
        4096 // Very limited RAM
    };

    let memory_warning = if available_for_context < 4.0 {
        Some("Running on CPU with limited RAM. Performance will be slow.".to_string())
    } else {
        Some("Running on CPU. Consider upgrading GPU for better performance.".to_string())
    };

    ContextSizeConfig {
        optimal_context_size: optimal_context,
        fallback_sizes: vec![16384, 8192, 4096, 2048, 1024],
        requires_cpu_offloading: false, // Already CPU-only
        optimal_gpu_layers: Some(0),    // No GPU layers
        memory_warning,
    }
}

/// Calculate hybrid GPU+CPU configuration when VRAM is very limited
fn calculate_hybrid_context_config(
    model: &ModelSelection,
    gpu: &GpuInfo,
    hw: &HardwareCapabilities,
) -> ContextSizeConfig {
    debug!("Calculating hybrid GPU+CPU context configuration");

    let available_vram = gpu.vram_gb.unwrap_or(0.0);
    let model_size_gb = model.download_size_gb();

    // Calculate how many layers we can fit on GPU
    // Rough estimate: each layer is about 1/60th of the model for a typical transformer
    let layers_estimate = 60; // Typical for most models
    let layer_size_gb = model_size_gb / layers_estimate as f32;
    let system_reserve = 2.0; // More conservative for hybrid setup
    let usable_vram = available_vram - system_reserve;
    let gpu_layers = ((usable_vram / layer_size_gb) as i32)
        .max(1)
        .min(layers_estimate);

    debug!(
        "Hybrid config: Using {} GPU layers out of ~{}",
        gpu_layers, layers_estimate
    );

    // With hybrid setup, we can use more context since some compute is on CPU
    let optimal_context = if hw.available_ram_gb > 16.0 {
        16384 // Good RAM for CPU portion
    } else if hw.available_ram_gb > 8.0 {
        8192 // Decent RAM
    } else {
        4096 // Limited RAM
    };

    ContextSizeConfig {
        optimal_context_size: optimal_context,
        fallback_sizes: vec![8192, 4096, 2048, 1024],
        requires_cpu_offloading: true,
        optimal_gpu_layers: Some(gpu_layers),
        memory_warning: Some(format!(
            "Using hybrid GPU+CPU setup with {} GPU layers due to VRAM constraints.",
            gpu_layers
        )),
    }
}

/// Estimate KV cache memory usage in GB for a given model and context size
fn estimate_kv_cache_size_gb(model: &ModelSelection, context_size: usize) -> f32 {
    // Rough estimation based on model parameter count and context size
    // KV cache ≈ 2 * n_layers * hidden_size * context_length * precision_bytes

    let param_multiplier = match model.base_model.parameter_count.as_str() {
        p if p.contains("3B") => 0.8, // Small models
        p if p.contains("7B") => 1.0, // Base multiplier
        p if p.contains("13B") => 1.4,
        p if p.contains("20B") => 1.8,
        p if p.contains("27B") => 2.0,
        p if p.contains("30B") => 2.2,
        p if p.contains("70B") => 3.5,
        _ => 1.0, // Default
    };

    // Base KV cache size formula (empirically derived)
    // This accounts for key and value tensors stored in memory
    let base_kv_cache_gb = (context_size as f32 * param_multiplier * 2.0) / (1024.0 * 1024.0);

    // Add quantization factor (lower precision = less memory)
    let quant_factor = match model.quantization {
        QuantizationLevel::Q2_K => 0.3,
        QuantizationLevel::Q3_K_S | QuantizationLevel::Q3_K_M => 0.4,
        QuantizationLevel::Q4_0 | QuantizationLevel::Q4_K_S | QuantizationLevel::Q4_K_M => 0.5,
        QuantizationLevel::Q5_0 | QuantizationLevel::Q5_K_S | QuantizationLevel::Q5_K_M => 0.6,
        QuantizationLevel::Q6_K => 0.7,
        QuantizationLevel::Q8_0 => 0.8,
    };

    base_kv_cache_gb * quant_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_selection_properties() {
        let models = ModelSelection::all_models();
        assert!(!models.is_empty());

        for model in models {
            assert!(!model.filename().is_empty());
            assert!(!model.download_url().is_empty());
            assert!(!model.description().is_empty());

            let reqs = model.requirements();
            assert!(reqs.min_ram_gb > 0.0);
            assert!(reqs.recommended_ram_gb >= reqs.min_ram_gb);
            assert!(reqs.min_cpu_cores > 0);
        }
    }

    #[test]
    fn test_hardware_detection() {
        // This test will run on the actual system
        match detect_hardware() {
            Ok(hw) => {
                assert!(hw.total_ram_gb > 0.0);
                assert!(hw.cpu_cores > 0);
                assert!(!hw.cpu_arch.is_empty());
                assert!(!hw.os.is_empty());
            }
            Err(e) => {
                // Hardware detection might fail in some test environments
                eprintln!(
                    "Hardware detection failed (this might be expected in CI): {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_model_selection_with_minimal_hardware() {
        let minimal_hw = HardwareCapabilities {
            total_ram_gb: 4.0,
            available_ram_gb: 2.5,
            cpu_cores: 2,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![],
            has_cuda: false,
            has_metal: false,
            os: "linux".to_string(),
        };

        let selected = select_model_variant(&minimal_hw);
        // Should fall back to a minimal model for limited hardware
        assert_eq!(selected.base_model.parameter_count, "7B");
        assert_eq!(selected.requirements.min_vram_gb, None); // CPU-only
        assert!(selected.requirements.min_ram_gb <= 4.0);
    }

    #[test]
    fn test_model_selection_with_rtx_5080() {
        let rtx5080_hw = HardwareCapabilities {
            total_ram_gb: 32.0,
            available_ram_gb: 28.0,
            cpu_cores: 16,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![GpuInfo {
                name: "RTX 5080".to_string(),
                vram_gb: Some(16.0), // RTX 5080 has 16GB VRAM
                cuda_capable: true,
                metal_capable: false,
            }],
            has_cuda: true,
            has_metal: false,
            os: "linux".to_string(),
        };

        let selected = select_model_variant(&rtx5080_hw);
        // Should select a model that fits in 16GB VRAM
        if let Some(vram_req) = selected.requirements.min_vram_gb {
            assert!(
                vram_req <= 16.0,
                "Selected model requires {}GB but RTX 5080 only has 16GB",
                vram_req
            );
        }

        // Should prefer higher parameter count models that fit
        assert!(selected.base_model.parameter_count.contains("B")); // Should be a model with billions of parameters
        println!("Selected for RTX 5080: {}", selected.description());
    }

    #[test]
    fn test_model_selection_with_high_end_gpu() {
        let high_end_hw = HardwareCapabilities {
            total_ram_gb: 64.0,
            available_ram_gb: 56.0,
            cpu_cores: 24,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![GpuInfo {
                name: "RTX 4090".to_string(),
                vram_gb: Some(24.0),
                cuda_capable: true,
                metal_capable: false,
            }],
            has_cuda: true,
            has_metal: false,
            os: "linux".to_string(),
        };

        let selected = select_model_variant(&high_end_hw);
        // Should select a high-end model for powerful hardware with 24GB VRAM
        assert!(selected.base_model.parameter_count.contains("B"));
        if let Some(vram_req) = selected.requirements.min_vram_gb {
            assert!(
                vram_req <= 24.0,
                "Selected model requires more VRAM than available"
            );
        }
        println!("Selected for RTX 4090: {}", selected.description());
    }

    #[test]
    fn test_quantization_selection() {
        let base_model = BaseModel {
            name: "test-model".to_string(),
            description: "Test model".to_string(),
            parameter_count: "7B".to_string(),
            context_window: 8192,
            huggingface_repo: "test/repo".to_string(),
            base_size_gb: 14.0,
        };

        // Test with high VRAM (should select high quality)
        let high_vram_hw = HardwareCapabilities {
            total_ram_gb: 32.0,
            available_ram_gb: 28.0,
            cpu_cores: 8,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![GpuInfo {
                name: "High-end GPU".to_string(),
                vram_gb: Some(16.0),
                cuda_capable: true,
                metal_capable: false,
            }],
            has_cuda: true,
            has_metal: false,
            os: "linux".to_string(),
        };

        let high_quality = select_optimal_quantization(&base_model, &high_vram_hw, true);
        assert!(high_quality.quality_score() >= 85); // Should select high quality quantization

        // Test with low VRAM (should select more compressed)
        let low_vram_hw = HardwareCapabilities {
            total_ram_gb: 16.0,
            available_ram_gb: 12.0,
            cpu_cores: 4,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![GpuInfo {
                name: "Mid-range GPU".to_string(),
                vram_gb: Some(6.0),
                cuda_capable: true,
                metal_capable: false,
            }],
            has_cuda: true,
            has_metal: false,
            os: "linux".to_string(),
        };

        let compressed = select_optimal_quantization(&base_model, &low_vram_hw, true);
        assert!(compressed.quality_score() < 85); // Should select more compressed quantization
    }

    #[test]
    fn test_adaptive_context_size_calculation() {
        // Create a test model
        let test_model = ModelSelection {
            base_model: BaseModel {
                name: "test-27b".to_string(),
                description: "Test 27B model".to_string(),
                parameter_count: "27B".to_string(),
                context_window: 131072,
                huggingface_repo: "test/repo".to_string(),
                base_size_gb: 54.0,
            },
            quantization: QuantizationLevel::Q3_K_M,
            requirements: HardwareRequirements {
                min_ram_gb: 16.0,
                min_vram_gb: Some(14.0),
                min_cpu_cores: 4,
                recommended_ram_gb: 32.0,
                recommended_vram_gb: Some(18.0),
                requires_cuda: false,
            },
        };

        // Test with RTX 5080 (16GB VRAM) - should trigger adaptive sizing
        let rtx5080_hw = HardwareCapabilities {
            total_ram_gb: 32.0,
            available_ram_gb: 28.0,
            cpu_cores: 16,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![GpuInfo {
                name: "RTX 5080".to_string(),
                vram_gb: Some(16.0),
                cuda_capable: true,
                metal_capable: false,
            }],
            has_cuda: true,
            has_metal: false,
            os: "linux".to_string(),
        };

        let context_config = calculate_optimal_context_size(&test_model, &rtx5080_hw);

        // Should calculate an appropriate context size for the available VRAM
        assert!(context_config.optimal_context_size > 0);
        assert!(context_config.optimal_context_size <= 32768); // Should be reasonable
        assert!(!context_config.fallback_sizes.is_empty()); // Should have fallback options

        // Should prefer GPU if possible
        if let Some(gpu_layers) = context_config.optimal_gpu_layers {
            assert!(gpu_layers > 0, "Should prefer GPU when CUDA is available");
        }

        println!("RTX 5080 context config: {:#?}", context_config);
    }

    #[test]
    fn test_context_size_cpu_fallback() {
        let test_model = ModelSelection {
            base_model: BaseModel {
                name: "test-7b".to_string(),
                description: "Test 7B model".to_string(),
                parameter_count: "7B".to_string(),
                context_window: 32768,
                huggingface_repo: "test/repo".to_string(),
                base_size_gb: 14.0,
            },
            quantization: QuantizationLevel::Q4_K_M,
            requirements: HardwareRequirements {
                min_ram_gb: 8.0,
                min_vram_gb: Some(6.0),
                min_cpu_cores: 2,
                recommended_ram_gb: 16.0,
                recommended_vram_gb: Some(8.0),
                requires_cuda: false,
            },
        };

        // Test with CPU-only hardware (no GPU)
        let cpu_only_hw = HardwareCapabilities {
            total_ram_gb: 16.0,
            available_ram_gb: 12.0,
            cpu_cores: 8,
            cpu_arch: "x86_64".to_string(),
            gpu_info: vec![],
            has_cuda: false,
            has_metal: false,
            os: "linux".to_string(),
        };

        let context_config = calculate_optimal_context_size(&test_model, &cpu_only_hw);

        // Should configure for CPU-only usage
        assert_eq!(context_config.optimal_gpu_layers, Some(0)); // No GPU layers
        assert!(!context_config.requires_cpu_offloading); // Already CPU-only
        assert!(context_config.memory_warning.is_some()); // Should warn about CPU usage

        println!("CPU-only context config: {:#?}", context_config);
    }

    #[test]
    fn test_kv_cache_estimation() {
        let test_model = ModelSelection {
            base_model: BaseModel {
                name: "test-7b".to_string(),
                description: "Test model".to_string(),
                parameter_count: "7B".to_string(),
                context_window: 32768,
                huggingface_repo: "test/repo".to_string(),
                base_size_gb: 14.0,
            },
            quantization: QuantizationLevel::Q4_K_M,
            requirements: HardwareRequirements {
                min_ram_gb: 8.0,
                min_vram_gb: Some(6.0),
                min_cpu_cores: 2,
                recommended_ram_gb: 16.0,
                recommended_vram_gb: Some(8.0),
                requires_cuda: false,
            },
        };

        // Test KV cache size estimation
        let kv_cache_32k = estimate_kv_cache_size_gb(&test_model, 32768);
        let kv_cache_16k = estimate_kv_cache_size_gb(&test_model, 16384);
        let kv_cache_8k = estimate_kv_cache_size_gb(&test_model, 8192);

        // KV cache should scale with context size
        assert!(kv_cache_32k > kv_cache_16k);
        assert!(kv_cache_16k > kv_cache_8k);
        assert!(kv_cache_8k > 0.0);

        // Should be reasonable values (not too large or too small)
        assert!(
            kv_cache_32k < 10.0,
            "KV cache estimate seems too large: {:.2}GB",
            kv_cache_32k
        );
        assert!(
            kv_cache_8k > 0.01,
            "KV cache estimate seems too small: {:.2}GB",
            kv_cache_8k
        );

        println!(
            "KV cache estimates - 32K: {:.2}GB, 16K: {:.2}GB, 8K: {:.2}GB",
            kv_cache_32k, kv_cache_16k, kv_cache_8k
        );
    }
}
