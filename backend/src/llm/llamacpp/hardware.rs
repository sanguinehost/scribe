// backend/src/llm/llamacpp/hardware.rs
// Hardware detection and capability assessment for LlamaCpp

use crate::llm::llamacpp::LocalLlmError;
use serde::{Deserialize, Serialize};
use std::process::Command;
use sysinfo::System;
use tracing::{debug, warn, error};

/// Hardware requirements for different model configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareRequirements {
    pub min_ram_gb: f32,
    pub min_vram_gb: Option<f32>,  // None for CPU-only
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

/// Available model selections with their requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelSelection {
    /// GPT-OSS 20B Q4 - High quality model for powerful GPUs (16GB+ VRAM)
    GptOss20bQ4 {
        requirements: HardwareRequirements,
    },
    /// Qwen3-30B-A3B-Thinking Q4 - MoE reasoning model (20GB+ VRAM, only 3.3B active params)
    Qwen3_30B_A3B_Thinking_Q4 {
        requirements: HardwareRequirements,
    },
    /// Qwen3-30B-A3B-Instruct Q4 - MoE instruction model (20GB+ VRAM, only 3.3B active params)
    Qwen3_30B_A3B_Instruct_Q4 {
        requirements: HardwareRequirements,
    },
    /// Gemma-3-27B-IT Q4 - Google's instruction-tuned model (18GB+ VRAM)
    Gemma3_27B_IT_Q4 {
        requirements: HardwareRequirements,
    },
}

impl ModelSelection {
    /// Get all available model selections with their requirements
    pub fn all_models() -> Vec<Self> {
        vec![
            // Most powerful model first - prefer Thinking variant for reasoning
            Self::Qwen3_30B_A3B_Thinking_Q4 {
                requirements: HardwareRequirements {
                    min_ram_gb: 24.0,
                    min_vram_gb: Some(20.0), // Need 20GB+ for model + KV cache
                    min_cpu_cores: 6,
                    recommended_ram_gb: 32.0,
                    recommended_vram_gb: Some(24.0), // Optimal with RTX 3090/4090
                    requires_cuda: false, // Can work on CPU due to MoE efficiency
                },
            },
            Self::Qwen3_30B_A3B_Instruct_Q4 {
                requirements: HardwareRequirements {
                    min_ram_gb: 24.0,
                    min_vram_gb: Some(20.0), // Same as Thinking variant
                    min_cpu_cores: 6,
                    recommended_ram_gb: 32.0,
                    recommended_vram_gb: Some(24.0),
                    requires_cuda: false,
                },
            },
            Self::Gemma3_27B_IT_Q4 {
                requirements: HardwareRequirements {
                    min_ram_gb: 20.0,
                    min_vram_gb: Some(18.0), // Need 18GB+ for model + KV cache
                    min_cpu_cores: 4,
                    recommended_ram_gb: 32.0,
                    recommended_vram_gb: Some(20.0), // Optimal with 20GB+ VRAM
                    requires_cuda: false,
                },
            },
            Self::GptOss20bQ4 {
                requirements: HardwareRequirements {
                    min_ram_gb: 16.0,
                    min_vram_gb: Some(12.0), // Can work with 12GB VRAM with some CPU offload
                    min_cpu_cores: 4,
                    recommended_ram_gb: 32.0,
                    recommended_vram_gb: Some(16.0), // Optimal with 16GB+ VRAM
                    requires_cuda: false, // Can work on CPU if needed
                },
            },
        ]
    }

    /// Get the model file name
    pub fn filename(&self) -> &'static str {
        match self {
            Self::GptOss20bQ4 { .. } => "gpt-oss-20b-Q4_K_M.gguf",
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => "Qwen3-30B-A3B-Thinking-2507-Q4_K_M.gguf",
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => "Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf",
            Self::Gemma3_27B_IT_Q4 { .. } => "gemma-3-27b-it-Q4_K_M.gguf",
        }
    }

    /// Get the download URL for this model
    pub fn download_url(&self) -> &'static str {
        match self {
            Self::GptOss20bQ4 { .. } => {
                "https://huggingface.co/unsloth/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-Q4_K_M.gguf?download=true"
            }
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => {
                "https://huggingface.co/unsloth/Qwen3-30B-A3B-Thinking-2507-GGUF/resolve/main/Qwen3-30B-A3B-Thinking-2507-Q4_K_M.gguf?download=true"
            }
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => {
                "https://huggingface.co/unsloth/Qwen3-30B-A3B-Instruct-2507-GGUF/resolve/main/Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf?download=true"
            }
            Self::Gemma3_27B_IT_Q4 { .. } => {
                "https://huggingface.co/unsloth/gemma-3-27b-it-GGUF/resolve/main/gemma-3-27b-it-Q4_K_M.gguf?download=true"
            }
        }
    }

    /// Get the SHA256 checksum for this model (for integrity verification)
    pub fn sha256_checksum(&self) -> Option<&'static str> {
        match self {
            // TODO: Add real checksums after downloading and verifying each model
            Self::GptOss20bQ4 { .. } => None, // Checksum to be added
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => None, // Checksum to be added
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => None, // Checksum to be added
            Self::Gemma3_27B_IT_Q4 { .. } => None, // Checksum to be added
        }
    }

    /// Get the approximate download size in bytes
    pub fn download_size_bytes(&self) -> u64 {
        match self {
            Self::GptOss20bQ4 { .. } => 11_900_000_000, // ~11.9GB
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => 18_600_000_000, // ~18.6GB
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => 18_600_000_000, // ~18.6GB
            Self::Gemma3_27B_IT_Q4 { .. } => 16_500_000_000, // ~16.5GB
        }
    }

    /// Get the hardware requirements for this model
    pub fn requirements(&self) -> &HardwareRequirements {
        match self {
            Self::GptOss20bQ4 { requirements } => requirements,
            Self::Qwen3_30B_A3B_Thinking_Q4 { requirements } => requirements,
            Self::Qwen3_30B_A3B_Instruct_Q4 { requirements } => requirements,
            Self::Gemma3_27B_IT_Q4 { requirements } => requirements,
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::GptOss20bQ4 { .. } => "GPT-OSS 20B (Q4_K_M) - High quality model for powerful GPUs (16GB+ VRAM)",
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => "Qwen3-30B-A3B-Thinking (Q4_K_M) - MoE reasoning model, 30B params but only 3.3B active (20GB+ VRAM)",
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => "Qwen3-30B-A3B-Instruct (Q4_K_M) - MoE instruction model, 30B params but only 3.3B active (20GB+ VRAM)",
            Self::Gemma3_27B_IT_Q4 { .. } => "Gemma-3-27B-IT (Q4_K_M) - Google's instruction-tuned model with 128K context (18GB+ VRAM)",
        }
    }
    
    /// Get the context window size for this model in tokens
    pub fn context_window_size(&self) -> u32 {
        match self {
            // All current GGUF models support 131k context window
            Self::GptOss20bQ4 { .. } => 131072, // 131k tokens
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => 131072, // 131k tokens  
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => 131072, // 131k tokens
            Self::Gemma3_27B_IT_Q4 { .. } => 131072, // 131k tokens
        }
    }
    
    /// Get the maximum output tokens for this model  
    pub fn max_output_tokens(&self) -> u32 {
        match self {
            // Conservative max output to leave room for input context
            Self::GptOss20bQ4 { .. } => 8192, // ~6% of context window
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => 8192,
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => 8192, 
            Self::Gemma3_27B_IT_Q4 { .. } => 8192,
        }
    }
    
    /// Get the model ID for API usage
    pub fn model_id(&self) -> &'static str {
        match self {
            Self::GptOss20bQ4 { .. } => "gpt-oss-20b-q4",
            Self::Qwen3_30B_A3B_Thinking_Q4 { .. } => "qwen3-30b-a3b-thinking-q4",
            Self::Qwen3_30B_A3B_Instruct_Q4 { .. } => "qwen3-30b-a3b-instruct-q4",
            Self::Gemma3_27B_IT_Q4 { .. } => "gemma3-27b-it-q4",
        }
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

    debug!("GPU detection - CUDA: {}, Metal: {}, GPUs: {}", has_cuda, has_metal, gpu_info.len());

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
            // Try to detect NVIDIA GPUs using nvidia-smi
            if let Ok(output) = Command::new("nvidia-smi")
                .args(&["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
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
            
            if gpu_info.is_empty() {
                debug!("No NVIDIA GPUs detected or nvidia-smi not available");
            }
        }
        "macos" => {
            // On macOS, assume Metal support for Apple Silicon
            if std::env::consts::ARCH == "aarch64" {
                // Try to get system info about GPU
                if let Ok(output) = Command::new("system_profiler")
                    .args(&["SPDisplaysDataType", "-json"])
                    .output()
                {
                    if output.status.success() {
                        // For now, just assume Metal support without detailed parsing
                        gpu_info.push(GpuInfo {
                            name: "Apple GPU".to_string(),
                            vram_gb: None, // Unified memory architecture
                            cuda_capable: false,
                            metal_capable: true,
                        });
                    }
                }
            } else {
                // Intel Mac - might have discrete GPU
                debug!("Intel Mac detected - checking for discrete GPU");
            }
        }
        _ => {
            debug!("Unknown OS: {}, skipping GPU detection", os);
        }
    }

    Ok(gpu_info)
}

/// Select the best model based on hardware capabilities
pub fn select_model_variant(hw: &HardwareCapabilities) -> ModelSelection {
    debug!("Selecting model variant for hardware: {:#?}", hw);
    
    let models = ModelSelection::all_models();
    
    // Sort by preference (most powerful first)
    for model in models {
        let requirements = model.requirements();
        
        // Check if hardware meets minimum requirements
        if hw.available_ram_gb >= requirements.min_ram_gb
            && hw.cpu_cores >= requirements.min_cpu_cores
        {
            // Check GPU requirements
            if let Some(min_vram) = requirements.min_vram_gb {
                // Model requires GPU
                if let Some(gpu) = hw.gpu_info.iter().find(|gpu| {
                    gpu.vram_gb.map_or(false, |vram| vram >= min_vram)
                        && (requirements.requires_cuda && gpu.cuda_capable || !requirements.requires_cuda)
                }) {
                    debug!("Selected GPU model: {:?} for GPU: {}", model, gpu.name);
                    return model;
                }
            } else {
                // CPU-only model
                debug!("Selected CPU model: {:?}", model);
                return model;
            }
        }
    }
    
    // Fallback to CPU-only GPT-OSS model if no GPU requirements can be met
    warn!("Hardware doesn't meet GPU requirements for any preferred model, falling back to GPT-OSS CPU-only");
    ModelSelection::GptOss20bQ4 {
        requirements: HardwareRequirements {
            min_ram_gb: 16.0,
            min_vram_gb: None, // CPU-only fallback
            min_cpu_cores: 4,
            recommended_ram_gb: 32.0,
            recommended_vram_gb: None,
            requires_cuda: false,
        },
    }
}

/// Check if hardware meets recommended specs for the selected model
pub fn check_recommended_specs(hw: &HardwareCapabilities, model: &ModelSelection) -> bool {
    let requirements = model.requirements();
    
    let ram_ok = hw.available_ram_gb >= requirements.recommended_ram_gb;
    
    let gpu_ok = if let Some(recommended_vram) = requirements.recommended_vram_gb {
        hw.gpu_info.iter().any(|gpu| {
            gpu.vram_gb.map_or(false, |vram| vram >= recommended_vram)
        })
    } else {
        true // No GPU requirements
    };
    
    ram_ok && gpu_ok
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
                eprintln!("Hardware detection failed (this might be expected in CI): {}", e);
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
        // Should fall back to CPU-only GPT-OSS for minimal hardware
        match selected {
            ModelSelection::GptOss20bQ4 { requirements } => {
                // Should be the CPU-only fallback variant
                assert_eq!(requirements.min_vram_gb, None);
            },
            _ => panic!("Expected GPT-OSS CPU-only fallback for minimal hardware"),
        }
    }

    #[test]
    fn test_model_selection_with_gpu() {
        let gpu_hw = HardwareCapabilities {
            total_ram_gb: 32.0,
            available_ram_gb: 24.0,
            cpu_cores: 16,
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
        
        let selected = select_model_variant(&gpu_hw);
        // Should select Qwen3 Thinking model for powerful hardware with 24GB VRAM
        match selected {
            ModelSelection::Qwen3_30B_A3B_Thinking_Q4 { .. } => (),
            _ => panic!("Expected Qwen3 Thinking model for high-end hardware with 24GB VRAM"),
        }
    }
}