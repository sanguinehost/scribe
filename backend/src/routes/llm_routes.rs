// backend/src/routes/llm_routes.rs
// API routes for local LLM management

use crate::{
    auth::token_auth::UnifiedAuth,
    errors::AppError,
    models::user_settings::{UpdateUserSettingsRequest, UserSettingsResponse},
    services::user_settings_service::UserSettingsService,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, put},
    Router,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[cfg(feature = "local-llm")]
use crate::llm::llamacpp::{hardware::detect_hardware, LlamaCppClient, ModelManager};
#[cfg(feature = "local-llm")]
use futures::Stream;
#[cfg(feature = "local-llm")]
use std::time::Duration;
#[cfg(feature = "local-llm")]
use tokio_stream::wrappers::UnboundedReceiverStream;
#[cfg(feature = "local-llm")]
use tracing::{debug, error};

#[derive(Debug, Serialize)]
pub struct LlmInfoResponse {
    pub local_llm_enabled: bool, // Feature is available
    pub server_running: bool,    // Server is actually running
    pub hardware: crate::DbJson, // Hardware capabilities as JSON
    pub models: Vec<ModelInfo>,
    pub download_progress: Option<DownloadProgressInfo>,
}

#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub filename: String,
    pub size_gb: f32,
    pub vram_required: f32,
    pub compatible: bool,
    pub downloaded: bool,
    pub active: bool,
    pub description: String,
    pub context_window_size: u32,
    pub max_output_tokens: u32,
    pub provider: String,
    pub is_local: bool,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct GroupedModelInfo {
    pub base_model_id: String,
    pub base_model_name: String,
    pub description: String,
    pub parameter_count: String,
    pub context_window: u32,
    pub huggingface_repo: String,
    pub variants: Vec<ModelVariantInfo>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct ModelVariantInfo {
    pub id: String,
    pub quantization: String,
    pub filename: String,
    pub size_gb: f32,
    pub vram_required: f32,
    pub compatible: bool,
    pub downloaded: bool,
    pub active: bool,
    pub recommended: bool,     // For smart recommendations
    pub quality_level: String, // Very Compact, Compact, Balanced, Good Quality, etc.
}

#[derive(Debug, Serialize)]
pub struct DownloadProgressInfo {
    pub model_id: String,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub percentage: f32,
    pub speed_bytes_per_sec: Option<f32>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Deserialize)]
pub struct DownloadModelRequest {
    pub model_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TestLlmRequest {
    pub model_id: Option<String>, // None = test user's preferred model
    pub prompt: String,
}

#[derive(Debug, Serialize)]
pub struct TestLlmResponse {
    pub success: bool,
    pub response: Option<String>,
    pub model_used: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LlmStatusResponse {
    pub local_llm_available: bool,
    pub error: Option<String>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct DownloadModelResponse {
    pub success: bool,
    pub message: String,
    pub download_id: Option<String>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct ServerStatusResponse {
    pub state: String,
    pub uptime_seconds: Option<u64>,
    pub pid: Option<u32>,
    pub model_loaded: Option<String>,
    pub last_error: Option<String>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct ServerActionResponse {
    pub success: bool,
    pub message: String,
    pub new_state: Option<String>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug, Serialize)]
pub struct CurrentModelResponse {
    pub model_name: Option<String>,
    pub model_path: Option<String>,
    pub is_active: bool,
}

/// Create the LLM management router
pub fn llm_router() -> Router<AppState> {
    #[cfg(feature = "local-llm")]
    {
        use axum::routing::{delete, post}; // Add delete and post methods
        Router::new()
            .route("/info", get(get_llm_info))
            .route("/models/download", post(download_model))
            .route("/models/{model_id}", delete(delete_model))
            .route("/models/{model_id}/activate", post(activate_model))
            .route("/models/deactivate", post(deactivate_model))
            .route("/download/progress", get(download_progress_stream))
            .route("/download/status/{model_id}", get(get_download_status))
            .route("/recommendations", get(get_model_recommendations))
            .route("/recommendations/best", get(get_best_recommendation))
            .route("/download/best", post(download_best_model))
            .route("/models/grouped", get(get_grouped_models))
            .route("/status", get(get_llm_status))
            .route("/test", post(test_llm))
            .route("/preferences", get(get_user_preferences))
            .route("/preferences", put(update_user_preferences))
            // Model capabilities endpoints
            .route("/models/all", get(get_all_models))
            .route(
                "/models/{model_id}/capabilities",
                get(get_model_capabilities),
            )
            // Server management endpoints
            .route("/server/status", get(get_server_status))
            .route("/server/restart", post(restart_server))
            .route("/server/shutdown", post(shutdown_server))
            .route("/models/switch/{model_id}", post(switch_model))
            .route("/models/current", get(get_current_model))
    }

    #[cfg(not(feature = "local-llm"))]
    {
        // Limited router when local-llm feature is disabled (preferences still work)
        Router::new()
            .route("/info", get(get_llm_info))
            .route("/status", get(get_llm_status))
            .route("/preferences", get(get_user_preferences))
            .route("/preferences", put(update_user_preferences))
            // Model capabilities endpoints (cloud models only)
            .route("/models/all", get(get_all_models))
            .route(
                "/models/{model_id}/capabilities",
                get(get_model_capabilities),
            )
    }
}

/// GET /api/llm/info - Get LLM system information (Stub for non-local-llm mode)
#[cfg(not(feature = "local-llm"))]
async fn get_llm_info(_auth: UnifiedAuth) -> Result<Json<LlmInfoResponse>, StatusCode> {
    Ok(Json(LlmInfoResponse {
        local_llm_enabled: false,
        server_running: false,
        hardware: crate::db::Json(serde_json::json!({})),
        models: Vec::new(),
        download_progress: None,
    }))
}

/// GET /api/llm/info - Get LLM system information
#[cfg(feature = "local-llm")]
async fn get_llm_info(auth: UnifiedAuth) -> Result<Json<LlmInfoResponse>, StatusCode> {
    // Verify user is authenticated
    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    info!("Getting LLM system information");

    // Detect hardware capabilities
    let hardware = detect_hardware().map_err(|e| {
        error!("Failed to detect hardware: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert hardware to JSON for serialization
    let hardware_json =
        serde_json::to_value(&hardware).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create ModelManager to get accurate model status
    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create ModelManager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get available models with accurate download/active status
    let models = get_model_info_list_with_manager(&hardware, &model_manager)
        .await
        .map_err(|e| {
            error!("Failed to get model list: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Check if server is actually running by trying to connect
    let server_running = check_server_running().await;

    Ok(Json(LlmInfoResponse {
        local_llm_enabled: true, // Feature is compiled and available
        server_running,
        hardware: hardware_json,
        models,
        download_progress: None, // TODO: Get actual download progress
    }))
}

/// Check if the LlamaCpp server is actually running
#[cfg(feature = "local-llm")]
async fn check_server_running() -> bool {
    use reqwest::Client;
    use std::time::Duration;

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let url = format!(
        "http://{}:{}/health",
        config.server_host, config.server_port
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| Client::new());

    match client.get(&url).send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

/// Helper function to get model information list with accurate status
#[cfg(feature = "local-llm")]
async fn get_model_info_list_with_manager(
    hardware: &crate::llm::llamacpp::hardware::HardwareCapabilities,
    model_manager: &ModelManager,
) -> Result<Vec<ModelInfo>, crate::llm::llamacpp::LocalLlmError> {
    use crate::llm::llamacpp::hardware::ModelSelection;

    // Start with ALL available models from ModelSelection
    let all_variants = ModelSelection::all_models();
    debug!(
        "ModelSelection::all_models() returned {} variants",
        all_variants.len()
    );

    // Get the actual status from ModelManager for downloaded models
    let model_statuses = model_manager.list_models().await?;
    let active_model = model_manager.get_active_model();
    debug!(
        "ModelManager found {} downloaded models",
        model_statuses.len()
    );

    let mut models = Vec::new();

    for variant in all_variants {
        let filename = variant.filename();
        let model_id = variant.model_id();

        // Find corresponding status from ModelManager (if downloaded)
        let model_status = model_statuses.iter().find(|status| status.name == filename);

        // Determine actual status
        let (downloaded, active, actual_size_gb) = if let Some(status) = model_status {
            let actual_size = if let Some(actual_bytes) = status.size_bytes {
                actual_bytes as f32 / (1024.0 * 1024.0 * 1024.0)
            } else {
                variant.download_size_gb()
            };
            (status.is_downloaded, status.is_active, actual_size)
        } else {
            (false, false, variant.download_size_gb())
        };

        // Check if this is the active model
        let is_active = active
            || (active_model
                .as_ref()
                .map_or(false, |am| am.contains(&filename)));

        models.push(ModelInfo {
            id: model_id,
            name: variant.base_model_name().to_string(),
            filename,
            size_gb: actual_size_gb,
            vram_required: variant.requirements.min_vram_gb.unwrap_or(0.0),
            compatible: is_model_compatible(hardware, &variant),
            downloaded,
            active: is_active,
            description: format!(
                "{} ({})",
                variant.base_model.description,
                variant.quantization.quality_description()
            ),
            context_window_size: variant.context_window_size(),
            max_output_tokens: variant.max_output_tokens(),
            provider: "llamacpp".to_string(),
            is_local: true,
        });
    }

    debug!("Returning {} models to frontend", models.len());
    Ok(models)
}

/// Check if a model is compatible with the current hardware
#[cfg(feature = "local-llm")]
fn is_model_compatible(
    hardware: &crate::llm::llamacpp::hardware::HardwareCapabilities,
    model: &crate::llm::llamacpp::hardware::ModelSelection,
) -> bool {
    let requirements = &model.requirements;

    // Check RAM requirements
    if hardware.available_ram_gb < requirements.min_ram_gb {
        return false;
    }

    // Check VRAM requirements if the model needs GPU
    if let Some(min_vram) = requirements.min_vram_gb {
        let has_sufficient_vram = hardware
            .gpu_info
            .iter()
            .any(|gpu| gpu.vram_gb.map_or(false, |vram| vram >= min_vram));
        if !has_sufficient_vram {
            return false;
        }
    }

    // Check CPU cores
    if hardware.cpu_cores < requirements.min_cpu_cores {
        return false;
    }

    // Check CUDA requirement
    if requirements.requires_cuda && !hardware.has_cuda {
        return false;
    }

    true
}

/// Build grouped model information
#[cfg(feature = "local-llm")]
async fn build_grouped_models(
    hardware: &crate::llm::llamacpp::hardware::HardwareCapabilities,
    model_manager: &ModelManager,
    recommendations: &[crate::llm::llamacpp::model_manager::ModelRecommendation],
) -> Result<Vec<GroupedModelInfo>, crate::llm::llamacpp::LocalLlmError> {
    use crate::llm::llamacpp::hardware::{BaseModel, ModelSelection};
    use std::collections::HashMap;

    // Get all model variants
    let all_variants = ModelSelection::all_models();
    let model_statuses = model_manager.list_models().await?;
    let active_model = model_manager.get_active_model();

    // Create a lookup for recommendations
    let rec_lookup: HashMap<String, &crate::llm::llamacpp::model_manager::ModelRecommendation> =
        recommendations
            .iter()
            .map(|r| (r.model_name.clone(), r))
            .collect();

    // Group variants by base model
    let mut base_models: HashMap<String, BaseModel> = HashMap::new();
    let mut grouped_variants: HashMap<String, Vec<ModelVariantInfo>> = HashMap::new();

    for variant in all_variants {
        let base_model_name = variant.base_model.name.clone();
        base_models.insert(base_model_name.clone(), variant.base_model.clone());

        // Find corresponding model status
        let filename = variant.filename();
        let model_status = model_statuses.iter().find(|s| s.name == filename);

        let (size_gb, downloaded) = if let Some(status) = model_status {
            let size_gb = if let Some(actual_bytes) = status.size_bytes {
                actual_bytes as f32 / (1024.0 * 1024.0 * 1024.0)
            } else {
                variant.download_size_gb()
            };
            (size_gb, status.is_downloaded)
        } else {
            (variant.download_size_gb(), false)
        };

        // Calculate hardware compatibility correctly
        let compatible = is_model_compatible(hardware, &variant);

        let is_active = active_model
            .as_ref()
            .map_or(false, |active| active == &filename);
        let is_recommended = rec_lookup.contains_key(&filename);

        let variant_info = ModelVariantInfo {
            id: filename
                .strip_suffix(".gguf")
                .unwrap_or(&filename)
                .to_string(),
            quantization: format!("{:?}", variant.quantization),
            filename,
            size_gb,
            vram_required: variant.requirements().min_vram_gb.unwrap_or(0.0),
            compatible,
            downloaded,
            active: is_active,
            recommended: is_recommended,
            quality_level: variant.quantization.quality_description().to_string(),
        };

        grouped_variants
            .entry(base_model_name)
            .or_insert_with(Vec::new)
            .push(variant_info);
    }

    // Build final grouped models, sort variants by quality
    let mut result = Vec::new();
    for (base_name, base_model) in base_models {
        if let Some(mut variants) = grouped_variants.remove(&base_name) {
            // Sort variants by quality (best first) and recommendation
            variants.sort_by(|a, b| {
                // Recommended variants first
                match (a.recommended, b.recommended) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => {
                        // Then by quality (based on file suffix parsing)
                        let a_quality = quality_rank(&a.quantization);
                        let b_quality = quality_rank(&b.quantization);
                        a_quality.cmp(&b_quality)
                    }
                }
            });

            result.push(GroupedModelInfo {
                base_model_id: base_name.clone(),
                base_model_name: base_model.name,
                description: base_model.description,
                parameter_count: base_model.parameter_count,
                context_window: base_model.context_window,
                huggingface_repo: base_model.huggingface_repo,
                variants,
            });
        }
    }

    // Sort base models by parameter count (largest first)
    result.sort_by(|a, b| {
        let a_params = extract_param_number(&a.parameter_count);
        let b_params = extract_param_number(&b.parameter_count);
        b_params
            .partial_cmp(&a_params)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(result)
}

/// Extract parameter count for sorting
#[cfg(feature = "local-llm")]
fn extract_param_number(param_str: &str) -> f32 {
    if param_str.contains("70B") {
        70.0
    } else if param_str.contains("30B") {
        30.0
    } else if param_str.contains("27B") {
        27.0
    } else if param_str.contains("20B") {
        20.0
    } else if param_str.contains("14B") {
        14.0
    } else if param_str.contains("8B") {
        8.0
    } else if param_str.contains("7B") {
        7.0
    } else if param_str.contains("3B") {
        3.0
    } else if param_str.contains("1B") {
        1.0
    } else {
        0.0
    }
}

/// Get quality rank for sorting (lower is better quality)
#[cfg(feature = "local-llm")]
fn quality_rank(quantization: &str) -> u8 {
    match quantization {
        s if s.contains("Q8_0") => 0,
        s if s.contains("Q6_K") => 1,
        s if s.contains("Q5_K_M") => 2,
        s if s.contains("Q5_K_S") => 3,
        s if s.contains("Q5_0") => 4,
        s if s.contains("Q4_K_M") => 5,
        s if s.contains("Q4_K_S") => 6,
        s if s.contains("Q4_0") => 7,
        s if s.contains("Q3_K_M") => 8,
        s if s.contains("Q3_K_S") => 9,
        s if s.contains("Q2_K") => 10,
        _ => 99,
    }
}

/// Helper function to get model information list (legacy - kept for compatibility)
#[cfg(feature = "local-llm")]
async fn get_model_info_list(
    hardware: &crate::llm::llamacpp::hardware::HardwareCapabilities,
) -> Vec<ModelInfo> {
    use crate::llm::llamacpp::hardware::ModelSelection;

    let mut models = Vec::new();

    for model_variant in ModelSelection::all_models() {
        let requirements = model_variant.requirements();
        let filename = model_variant.filename();

        // Check hardware compatibility
        let ram_ok = hardware.available_ram_gb >= requirements.min_ram_gb;
        let cpu_ok = hardware.cpu_cores >= requirements.min_cpu_cores;
        let gpu_ok = if let Some(min_vram) = requirements.min_vram_gb {
            hardware.gpu_info.iter().any(|gpu| {
                gpu.vram_gb.map_or(false, |vram| vram >= min_vram)
                    && (!requirements.requires_cuda || gpu.cuda_capable)
            })
        } else {
            true // CPU-only model
        };

        let compatible = ram_ok && cpu_ok && gpu_ok;

        // Generate model ID from filename (remove .gguf extension)
        let model_id = filename
            .strip_suffix(".gguf")
            .unwrap_or(&filename)
            .to_string();

        let size_gb = model_variant.download_size_bytes() as f32 / (1024.0 * 1024.0 * 1024.0);
        let vram_required = requirements.min_vram_gb.unwrap_or(0.0);

        models.push(ModelInfo {
            id: model_id,
            name: filename.to_string(),
            filename: filename.to_string(),
            size_gb,
            vram_required,
            compatible,
            downloaded: false, // TODO: Check if actually downloaded
            active: false,     // TODO: Check if currently active
            description: model_variant.description().to_string(),
            context_window_size: model_variant.context_window_size(),
            max_output_tokens: model_variant.max_output_tokens(),
            provider: "llamacpp".to_string(),
            is_local: true,
        });
    }

    models
}

/// POST /api/llm/models/download - Start downloading a model
#[cfg(feature = "local-llm")]
async fn download_model(
    State(app_state): State<AppState>,
    Json(request): Json<DownloadModelRequest>,
) -> Result<Json<DownloadModelResponse>, StatusCode> {
    info!("Starting download for model: {}", request.model_id);

    // Get model manager from app state
    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Find the requested model variant
    let model_variant = crate::llm::llamacpp::hardware::ModelSelection::all_models()
        .into_iter()
        .find(|m| {
            let filename = m.filename();
            let model_id = filename.strip_suffix(".gguf").unwrap_or(&filename);
            model_id == request.model_id
        })
        .ok_or_else(|| {
            error!("Model variant not found: {}", request.model_id);
            StatusCode::NOT_FOUND
        })?;

    // Start download
    match model_manager.download_model(&model_variant).await {
        Ok(_path) => {
            info!(
                "Successfully started download for model: {}",
                request.model_id
            );
            Ok(Json(DownloadModelResponse {
                success: true,
                message: format!("Download started for model: {}", request.model_id),
                download_id: Some(format!("download_{}", request.model_id)),
            }))
        }
        Err(e) => {
            error!("Failed to download model {}: {}", request.model_id, e);
            Ok(Json(DownloadModelResponse {
                success: false,
                message: format!("Download failed: {}", e),
                download_id: None,
            }))
        }
    }
}

/// DELETE /api/llm/models/:model_id - Delete a downloaded model
#[cfg(feature = "local-llm")]
async fn delete_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    info!("Deleting model: {}", model_id);

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert model_id to filename if needed
    let model_filename = if model_id.ends_with(".gguf") {
        model_id.clone()
    } else {
        format!("{}.gguf", model_id)
    };

    match model_manager.delete_model(&model_filename).await {
        Ok(()) => Ok(Json(serde_json::json!({
            "success": true,
            "message": format!("Model {} deleted successfully", model_id)
        }))),
        Err(e) => {
            error!("Failed to delete model {}: {}", model_id, e);
            Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Failed to delete model: {}", e)
            })))
        }
    }
}

/// POST /api/llm/models/:model_id/activate - Activate a model
#[cfg(feature = "local-llm")]
async fn activate_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    info!("Activating model: {}", model_id);

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert model_id to filename if needed
    let model_filename = if model_id.ends_with(".gguf") {
        model_id.clone()
    } else {
        format!("{}.gguf", model_id)
    };

    match client.switch_model(&model_filename).await {
        Ok(()) => {
            info!("Model {} activated successfully", model_id);
            Ok(Json(serde_json::json!({
                "success": true,
                "message": format!("Model {} activated successfully", model_id)
            })))
        }
        Err(e) => {
            error!("Failed to activate model {}: {}", model_id, e);
            Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Failed to activate model: {}", e)
            })))
        }
    }
}

/// POST /api/llm/models/deactivate - Deactivate the current local model
#[cfg(feature = "local-llm")]
async fn deactivate_model(
    State(_app_state): State<AppState>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    info!("Deactivating current local model");

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match client.shutdown().await {
        Ok(()) => {
            info!("Local model server stopped successfully");
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Local model deactivated successfully"
            })))
        }
        Err(e) => {
            error!("Failed to deactivate model: {}", e);
            Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Failed to deactivate model: {}", e)
            })))
        }
    }
}

/// GET /api/llm/download/status/:model_id - Check download status for a specific model
#[cfg(feature = "local-llm")]
async fn get_download_status(
    Path(model_id): Path<String>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    info!("Checking download status for model: {}", model_id);

    // Get model manager
    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Find the requested model variant
    let model_variant = crate::llm::llamacpp::hardware::ModelSelection::all_models()
        .into_iter()
        .find(|m| {
            let filename = m.filename();
            let variant_id = filename.strip_suffix(".gguf").unwrap_or(&filename);
            variant_id == model_id
        })
        .ok_or_else(|| {
            error!("Model variant not found: {}", model_id);
            StatusCode::NOT_FOUND
        })?;

    let filename = model_variant.filename();
    let models_dir = std::path::Path::new("models"); // Use same logic as model_manager
    let model_path = models_dir.join(&filename);
    let temp_path = model_path.with_extension("tmp");

    let status = if model_path.exists() {
        "completed"
    } else if temp_path.exists() {
        "downloading"
    } else {
        "not_started"
    };

    info!("Download status for {}: {}", model_id, status);

    Ok(Json(serde_json::json!({
        "model_id": model_id,
        "status": status,
        "model_path": model_path.to_string_lossy(),
        "temp_path": temp_path.to_string_lossy()
    })))
}

/// GET /api/llm/download/progress - Server-Sent Events for download progress
#[cfg(feature = "local-llm")]
async fn download_progress_stream() -> Sse<impl futures::Stream<Item = Result<Event, axum::Error>>>
{
    info!("Client connected to download progress stream");

    // Create a channel for sending progress updates
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn a task to send periodic updates (placeholder)
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut progress = 0;

        loop {
            interval.tick().await;
            progress += 10;

            let event_data = serde_json::json!({
                "model_id": "example_model",
                "total_bytes": 1000000,
                "downloaded_bytes": progress * 10000,
                "percentage": (progress as f32).min(100.0),
                "speed_bytes_per_sec": 100000
            });

            let event = Event::default()
                .data(event_data.to_string())
                .event("download_progress");

            if tx.send(Ok(event)).is_err() {
                break; // Client disconnected
            }

            if progress >= 100 {
                break;
            }
        }
    });

    let stream = UnboundedReceiverStream::new(rx);
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    )
}

/// GET /api/llm/recommendations - Get smart model recommendations
#[cfg(feature = "local-llm")]
async fn get_model_recommendations(
    State(app_state): State<AppState>,
) -> Result<Json<Vec<crate::llm::llamacpp::model_manager::ModelRecommendation>>, StatusCode> {
    info!("Getting model recommendations");

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match model_manager.recommend_models().await {
        Ok(recommendations) => Ok(Json(recommendations)),
        Err(e) => {
            error!("Failed to get model recommendations: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/llm/recommendations/best - Get the best model recommendation
#[cfg(feature = "local-llm")]
async fn get_best_recommendation(
    State(app_state): State<AppState>,
) -> Result<Json<Option<crate::llm::llamacpp::model_manager::ModelRecommendation>>, StatusCode> {
    info!("Getting best model recommendation");

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match model_manager.get_best_recommendation().await {
        Ok(recommendation) => Ok(Json(recommendation)),
        Err(e) => {
            error!("Failed to get best model recommendation: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/llm/models/grouped - Get models grouped by base model
#[cfg(feature = "local-llm")]
async fn get_grouped_models(
    auth: UnifiedAuth,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<GroupedModelInfo>>, StatusCode> {
    // Verify user is authenticated
    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    info!("Getting grouped models");

    // Detect hardware capabilities
    let hardware = detect_hardware().map_err(|e| {
        error!("Failed to detect hardware: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Create ModelManager to get accurate model status
    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create ModelManager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get recommendations for scoring
    let recommendations = model_manager.recommend_models().await.map_err(|e| {
        error!("Failed to get recommendations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build grouped models
    let mut grouped_models = build_grouped_models(&hardware, &model_manager, &recommendations)
        .await
        .map_err(|e| {
            error!("Failed to build grouped models: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        "get_grouped_models: Built {} model groups",
        grouped_models.len()
    );
    for group in &grouped_models {
        info!(
            "  Group: {} ({} variants)",
            group.base_model_name,
            group.variants.len()
        );
        for variant in &group.variants {
            if variant.id.contains("gpt-oss-20b") {
                info!(
                    "    GPT-OSS-20B variant: id={}, downloaded={}, compatible={}, filename={}",
                    variant.id, variant.downloaded, variant.compatible, variant.filename
                );
            } else {
                debug!(
                    "    Variant: id={}, downloaded={}, compatible={}",
                    variant.id, variant.downloaded, variant.compatible
                );
            }
        }
    }

    // Apply filters based on query parameters
    let show_incompatible = params
        .get("show_incompatible")
        .map_or(true, |v| v == "true"); // Default to true
    let only_downloaded = params.get("only_downloaded").map_or(false, |v| v == "true");
    let only_recommended = params
        .get("only_recommended")
        .map_or(false, |v| v == "true");

    info!(
        "get_grouped_models: Applying filters - show_incompatible={}, only_downloaded={}, only_recommended={}",
        show_incompatible, only_downloaded, only_recommended
    );

    // Only filter if specific filters are requested
    if only_downloaded || only_recommended || !show_incompatible {
        for group in &mut grouped_models {
            let original_count = group.variants.len();
            group.variants.retain(|variant| {
                let compatible_check = show_incompatible || variant.compatible;
                let downloaded_check = !only_downloaded || variant.downloaded;
                let recommended_check = !only_recommended || variant.recommended;

                compatible_check && downloaded_check && recommended_check
            });

            if group.variants.len() != original_count {
                info!(
                    "  Group {} filtered: {} -> {} variants",
                    group.base_model_name,
                    original_count,
                    group.variants.len()
                );
            }
        }

        // Remove groups with no variants
        let original_group_count = grouped_models.len();
        grouped_models.retain(|group| !group.variants.is_empty());

        if grouped_models.len() != original_group_count {
            info!(
                "  Removed empty groups: {} -> {}",
                original_group_count,
                grouped_models.len()
            );
        }
    }

    info!(
        "get_grouped_models: Returning {} model groups",
        grouped_models.len()
    );
    Ok(Json(grouped_models))
}

/// POST /api/llm/download/best - Download and activate the best recommended model
#[cfg(feature = "local-llm")]
async fn download_best_model(
    State(app_state): State<AppState>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    info!("Downloading and activating best model");

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let model_manager = ModelManager::new(config).await.map_err(|e| {
        error!("Failed to create model manager: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match model_manager.download_best_model().await {
        Ok(model_name) => Ok(Json(serde_json::json!({
            "success": true,
            "message": format!("Successfully downloaded and activated model: {}", model_name),
            "active_model": model_name
        }))),
        Err(e) => {
            error!("Failed to download best model: {}", e);
            Ok(Json(serde_json::json!({
                "success": false,
                "message": format!("Failed to download best model: {}", e)
            })))
        }
    }
}

/// GET /api/llm/status - Check if local LLM is available
async fn get_llm_status(auth: UnifiedAuth) -> Result<Json<LlmStatusResponse>, StatusCode> {
    // Verify user is authenticated
    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    #[cfg(feature = "local-llm")]
    {
        // Try to detect hardware to see if local LLM could work
        match detect_hardware() {
            Ok(_hardware) => Ok(Json(LlmStatusResponse {
                local_llm_available: true,
                error: None,
            })),
            Err(e) => Ok(Json(LlmStatusResponse {
                local_llm_available: false,
                error: Some(format!("Hardware detection failed: {}", e)),
            })),
        }
    }

    #[cfg(not(feature = "local-llm"))]
    {
        Ok(Json(LlmStatusResponse {
            local_llm_available: false,
            error: Some("Local LLM feature not compiled".to_string()),
        }))
    }
}

/// POST /api/llm/test - Test LLM with a sample prompt (using secure wrapper)
#[cfg(feature = "local-llm")]
async fn test_llm(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
    session_dek: SessionDek,
    Json(request): Json<TestLlmRequest>,
) -> Result<Json<TestLlmResponse>, StatusCode> {
    info!("Testing LLM with prompt: {} (secure)", request.prompt);

    let user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    // Use the secure AI client factory to get a properly wrapped client
    let secure_client = match app_state
        .ai_client_factory
        .get_secure_client_for_provider(
            user.id,
            None, // Use default provider
            request.model_id.as_deref(),
            Some(&session_dek),
            &Arc::new(app_state.clone()),
        )
        .await
    {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get secure AI client for user {}: {}", user.id, e);
            return Ok(Json(TestLlmResponse {
                success: false,
                response: None,
                model_used: request.model_id.unwrap_or_else(|| "default".to_string()),
                error: Some(format!("Failed to create secure client: {}", e)),
            }));
        }
    };

    // Create a simple chat request
    use crate::llm::RigCompletionRequest;
    let rig_req = RigCompletionRequest {
        model_name: request
            .model_id
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        provider: "gemini".to_string(), // Default to gemini
        prompt: request.prompt,
        ..Default::default()
    };

    let model_name = request.model_id.as_deref().unwrap_or("default");
    match secure_client.completion(rig_req).await {
        Ok(response) => {
            let model_used = request.model_id.unwrap_or_else(|| "default".to_string());
            let response_text = response.content;

            info!(
                "Secure LLM test completed successfully for user {}",
                user.id
            );
            Ok(Json(TestLlmResponse {
                success: true,
                response: Some(response_text),
                model_used,
                error: None,
            }))
        }
        Err(e) => {
            warn!("Secure LLM test failed for user {}: {}", user.id, e);
            let model_used = request.model_id.unwrap_or_else(|| "default".to_string());
            Ok(Json(TestLlmResponse {
                success: false,
                response: None,
                model_used,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// GET /api/llm/preferences - Get user's LLM preferences
async fn get_user_preferences(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Json<UserSettingsResponse>, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    let settings =
        UserSettingsService::get_user_settings(&app_state.pool, user.id, &app_state.config).await?;

    Ok(Json(settings))
}

/// PUT /api/llm/preferences - Update user's LLM preferences
async fn update_user_preferences(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
    Json(request): Json<UpdateUserSettingsRequest>,
) -> Result<Json<UserSettingsResponse>, AppError> {
    let user = auth
        .user()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

    let updated_settings = UserSettingsService::update_user_settings(
        &app_state.pool,
        user.id,
        request,
        &app_state.config,
    )
    .await?;

    Ok(Json(updated_settings))
}

/// GET /api/llm/server/status - Get detailed server status
#[cfg(feature = "local-llm")]
async fn get_server_status(
    State(app_state): State<AppState>,
) -> Result<Json<ServerStatusResponse>, StatusCode> {
    info!("Getting server status");

    // Create a temporary client to check server status
    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let server_info = client.get_server_status().await;
    Ok(Json(ServerStatusResponse {
        state: format!("{:?}", server_info.state),
        uptime_seconds: server_info.uptime.map(|d| d.as_secs()),
        pid: server_info.pid,
        model_loaded: server_info.model_loaded,
        last_error: None, // ServerInfo doesn't have last_error field
    }))
}

/// POST /api/llm/server/restart - Restart the server
#[cfg(feature = "local-llm")]
async fn restart_server(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Json<ServerActionResponse>, StatusCode> {
    info!("Restarting server");

    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match client.restart_server().await {
        Ok(()) => {
            // Get new status
            let server_info = client.get_server_status().await;
            let new_state = format!("{:?}", server_info.state);

            Ok(Json(ServerActionResponse {
                success: true,
                message: "Server restarted successfully".to_string(),
                new_state: Some(new_state),
            }))
        }
        Err(e) => {
            error!("Failed to restart server: {}", e);
            Ok(Json(ServerActionResponse {
                success: false,
                message: format!("Failed to restart server: {}", e),
                new_state: None,
            }))
        }
    }
}

/// POST /api/llm/server/shutdown - Shutdown the server
#[cfg(feature = "local-llm")]
async fn shutdown_server(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Json<ServerActionResponse>, StatusCode> {
    info!("Shutting down server");

    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match client.shutdown().await {
        Ok(()) => Ok(Json(ServerActionResponse {
            success: true,
            message: "Server shutdown successfully".to_string(),
            new_state: Some("Stopped".to_string()),
        })),
        Err(e) => {
            error!("Failed to shutdown server: {}", e);
            Ok(Json(ServerActionResponse {
                success: false,
                message: format!("Failed to shutdown server: {}", e),
                new_state: None,
            }))
        }
    }
}

/// POST /api/llm/models/switch/:model_id - Switch to a different model
#[cfg(feature = "local-llm")]
async fn switch_model(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
    Path(model_id): Path<String>,
) -> Result<Json<ServerActionResponse>, StatusCode> {
    info!("Switching to model: {}", model_id);

    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert model_id to filename if needed
    let model_filename = if model_id.ends_with(".gguf") {
        model_id.clone()
    } else {
        format!("{}.gguf", model_id)
    };

    match client.switch_model(&model_filename).await {
        Ok(()) => {
            // Get new status to confirm the switch
            let server_info = client.get_server_status().await;
            let new_state = format!("{:?}", server_info.state);

            Ok(Json(ServerActionResponse {
                success: true,
                message: format!("Successfully switched to model: {}", model_id),
                new_state: Some(new_state),
            }))
        }
        Err(e) => {
            error!("Failed to switch to model {}: {}", model_id, e);
            Ok(Json(ServerActionResponse {
                success: false,
                message: format!("Failed to switch to model: {}", e),
                new_state: None,
            }))
        }
    }
}

/// GET /api/llm/models/current - Get the currently active model
#[cfg(feature = "local-llm")]
async fn get_current_model(
    State(app_state): State<AppState>,
) -> Result<Json<CurrentModelResponse>, StatusCode> {
    info!("Getting current model");

    let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
    let client = LlamaCppClient::new(config).await.map_err(|e| {
        error!("Failed to create LlamaCpp client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let current_model = client.get_current_model();
    let is_active = current_model.is_some();

    Ok(Json(CurrentModelResponse {
        model_name: current_model.clone(),
        model_path: current_model.map(|name| format!("models/{}", name)),
        is_active,
    }))
}

/// GET /api/llm/models/all - Get all available models with capabilities
async fn get_all_models(auth: UnifiedAuth) -> Result<Json<crate::DbJson>, StatusCode> {
    // Verify user is authenticated
    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;

    use crate::llm::ModelRegistry;

    info!("Getting all available models");

    let registry = ModelRegistry::new();

    // First, populate the registry with ALL available models from ModelSelection
    #[cfg(feature = "local-llm")]
    {
        use crate::llm::llamacpp::hardware::ModelSelection;

        for model_variant in ModelSelection::all_models() {
            let model_id = model_variant.model_id();

            // Add model to registry with default availability (not downloaded)
            registry.set_model_availability(&model_id, false);

            // Add metadata from ModelSelection
            registry.set_model_metadata(
                &model_id,
                "size_gb",
                &model_variant.download_size_gb().to_string(),
            );
            registry.set_model_metadata(
                &model_id,
                "vram_required",
                &model_variant
                    .requirements
                    .min_vram_gb
                    .unwrap_or(0.0)
                    .to_string(),
            );
            registry.set_model_metadata(&model_id, "filename", &model_variant.filename());
            registry.set_model_metadata(&model_id, "download_url", &model_variant.download_url());
            registry.set_model_metadata(
                &model_id,
                "description",
                &format!(
                    "{} ({})",
                    model_variant.base_model.description,
                    model_variant.quantization.quality_description()
                ),
            );
        }
    }

    // Now update local model availability based on actual download status
    #[cfg(feature = "local-llm")]
    {
        let config = crate::llm::llamacpp::LlamaCppConfig::from_env();
        if let Ok(model_manager) = ModelManager::new(config).await {
            // Get actual model status from ModelManager
            if let Ok(model_statuses) = model_manager.list_models().await {
                for model_status in model_statuses {
                    // Find the corresponding ModelSelection variant to get the proper model ID
                    use crate::llm::llamacpp::hardware::ModelSelection;

                    if let Some(model_variant) = ModelSelection::all_models()
                        .into_iter()
                        .find(|variant| variant.filename() == model_status.name)
                    {
                        let model_id = model_variant.model_id();
                        // Update availability based on whether the model is actually downloaded
                        registry.set_model_availability(&model_id, model_status.is_downloaded);

                        // Add size information to metadata if the model is downloaded
                        if model_status.is_downloaded {
                            let size_gb = model_status.size_bytes.unwrap_or(0) as f32
                                / (1024.0 * 1024.0 * 1024.0);
                            registry.set_model_metadata(&model_id, "size_gb", &size_gb.to_string());
                            registry.set_model_metadata(
                                &model_id,
                                "filename",
                                model_status.name.as_str(),
                            );
                        }
                    }
                }
            } else {
                warn!("Failed to get model status from ModelManager");
            }
        } else {
            warn!("Failed to create ModelManager for availability check");
        }
    }

    let all_models = registry.get_all_models();

    // Convert to a format suitable for the API
    let mut models_response = serde_json::Map::new();

    for (model_id, capabilities) in all_models {
        let model_info = serde_json::json!({
            "id": model_id,
            "context_window_size": capabilities.context_window_size,
            "max_output_tokens": capabilities.max_output_tokens,
            "provider": capabilities.provider,
            "is_local": capabilities.is_local,
            "is_available": capabilities.is_available,
            "metadata": capabilities.metadata
        });

        models_response.insert(model_id.clone(), model_info);
    }

    Ok(Json(crate::db::Json(serde_json::Value::Object(
        models_response,
    ))))
}

/// GET /api/llm/models/:model_id/capabilities - Get specific model capabilities
async fn get_model_capabilities(
    auth: UnifiedAuth,
    Path(model_id): Path<String>,
) -> Result<Json<crate::DbJson>, StatusCode> {
    // Verify user is authenticated
    let _user = auth.user().cloned().ok_or(StatusCode::UNAUTHORIZED)?;
    use crate::llm::ModelRegistry;

    info!("Getting capabilities for model: {}", model_id);

    let registry = ModelRegistry::new();

    match registry.get_capabilities(&model_id) {
        Some(capabilities) => {
            let response = serde_json::json!({
                "model_id": model_id,
                "context_window_size": capabilities.context_window_size,
                "max_output_tokens": capabilities.max_output_tokens,
                "provider": capabilities.provider,
                "is_local": capabilities.is_local,
                "is_available": capabilities.is_available,
                "metadata": capabilities.metadata,
                "recommended_settings": registry.get_recommended_context_settings(&model_id)
            });

            Ok(Json(crate::db::Json(response)))
        }
        None => {
            warn!("Model not found: {}", model_id);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
