use crate::errors::AppError;
use crate::state::AppState;
use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ComponentStatus {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "unhealthy")]
    Unhealthy,
}

impl std::fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentStatus::Ok => write!(f, "ok"),
            ComponentStatus::Degraded => write!(f, "degraded"),
            ComponentStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComponentHealthInfo {
    pub status: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCheckResponse {
    pub status: ComponentStatus,
    pub version: String,
    pub components: HashMap<String, ComponentHealthInfo>,
    pub timestamp: DateTime<Utc>,
}

impl HealthCheckResponse {
    pub fn new() -> Self {
        Self {
            status: ComponentStatus::Ok,
            version: env!("CARGO_PKG_VERSION").to_string(),
            components: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    pub fn add_component(&mut self, name: String, info: ComponentHealthInfo) {
        // Update overall status based on component status
        match info.status {
            ComponentStatus::Unhealthy => {
                self.status = ComponentStatus::Unhealthy;
            }
            ComponentStatus::Degraded => {
                // Only upgrade to degraded if currently Ok
                if self.status == ComponentStatus::Ok {
                    self.status = ComponentStatus::Degraded;
                }
                // If already Unhealthy or Degraded, don't change
            }
            ComponentStatus::Ok => {
                // Don't downgrade status
            }
        }
        self.components.insert(name, info);
    }
}

/// Enhanced health check endpoint with database and external service connectivity checks.
pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<HealthCheckResponse>, AppError> {
    tracing::debug!("Enhanced health check endpoint called");
    let mut health_response = HealthCheckResponse::new();

    // Check database connectivity
    let db_start = Instant::now();
    let db_health = check_database_health(&state).await;
    let db_duration = db_start.elapsed().as_millis() as u64;

    health_response.add_component(
        "database".to_string(),
        ComponentHealthInfo {
            status: if db_health.is_ok() {
                ComponentStatus::Ok
            } else {
                ComponentStatus::Unhealthy
            },
            response_time_ms: Some(db_duration),
            message: db_health.err().map(|e| e.to_string()),
        },
    );

    // Check Qdrant connectivity
    let qdrant_start = Instant::now();
    let qdrant_health = check_qdrant_health(&state).await;
    let qdrant_duration = qdrant_start.elapsed().as_millis() as u64;

    health_response.add_component(
        "qdrant".to_string(),
        ComponentHealthInfo {
            status: if qdrant_health.is_ok() {
                ComponentStatus::Ok
            } else {
                ComponentStatus::Degraded
            },
            response_time_ms: Some(qdrant_duration),
            message: qdrant_health.err().map(|e| e.to_string()),
        },
    );

    // Check system resources (disk space)
    let disk_health = check_disk_space().await;
    health_response.add_component(
        "disk_space".to_string(),
        ComponentHealthInfo {
            status: match disk_health {
                Ok(available_gb) if available_gb > 5.0 => ComponentStatus::Ok,
                Ok(available_gb) if available_gb > 1.0 => ComponentStatus::Degraded,
                _ => ComponentStatus::Unhealthy,
            },
            response_time_ms: None,
            message: match disk_health {
                Ok(available_gb) => Some(format!("Available: {:.1} GB", available_gb)),
                Err(e) => Some(e.to_string()),
            },
        },
    );

    tracing::info!(
        overall_status = %health_response.status,
        db_status = %health_response.components.get("database").unwrap().status,
        qdrant_status = %health_response.components.get("qdrant").unwrap().status,
        "Health check completed"
    );

    // Return appropriate HTTP status code based on health
    match health_response.status {
        ComponentStatus::Ok => Ok(Json(health_response)),
        ComponentStatus::Degraded => {
            // Still return 200 for degraded services to avoid triggering alerts for non-critical issues
            Ok(Json(health_response))
        }
        ComponentStatus::Unhealthy => {
            // Return 503 Service Unavailable for unhealthy status
            Err(AppError::ServiceUnavailable(
                "Service unhealthy".to_string(),
            ))
        }
    }
}

/// Check database connectivity by performing a simple query
async fn check_database_health(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    conn.interact(move |conn| {
        use diesel::RunQueryDsl;
        use diesel::sql_query;
        use diesel::sql_types::Integer;

        #[derive(diesel::QueryableByName)]
        struct HealthCheck {
            #[diesel(sql_type = Integer)]
            _result: i32,
        }

        sql_query("SELECT 1 as _result")
            .get_result::<HealthCheck>(conn)
            .map(|_| ())
            .map_err(|e| format!("Database health check failed: {}", e))
    })
    .await
    .map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        )) as Box<dyn std::error::Error + Send + Sync>
    })?
    .map_err(|e| {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
            as Box<dyn std::error::Error + Send + Sync>
    })
}

/// Check Qdrant connectivity by checking if the service is available
async fn check_qdrant_health(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Try to get health information from Qdrant
    match state.qdrant_service.health_check().await {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
    }
}

/// Check available disk space
async fn check_disk_space() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    use std::path::Path;

    tokio::task::spawn_blocking(|| {
        // Use statvfs to get filesystem statistics
        let path = Path::new("/");

        #[cfg(unix)]
        {
            use std::mem;
            use std::os::raw::c_char;

            unsafe extern "C" {
                fn statvfs(path: *const c_char, buf: *mut libc::statvfs) -> i32;
            }

            let path_cstr = std::ffi::CString::new(path.to_str().unwrap_or("/"))?;
            let mut stat: libc::statvfs = unsafe { mem::zeroed() };

            let result = unsafe { statvfs(path_cstr.as_ptr(), &mut stat) };

            if result == 0 {
                let available_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
                let available_gb = available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                Ok(available_gb)
            } else {
                Err("Failed to get disk statistics".into())
            }
        }

        #[cfg(not(unix))]
        {
            // Fallback for non-Unix systems
            Ok(10.0) // Assume 10GB available as a fallback
        }
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
}
