use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use scribe_core::types::ThermodynamicTelemetry;
use std::time::Instant;
use tracing::{info, warn};
use crate::middleware::PrivacySafeUserId;

/// Critical threshold for entropy variance.
/// Exceeding this triggers an OpControlBarrier.
pub const ENTROPY_SPIKE_THRESHOLD: f32 = 100.0;

/// Thermodynamic Telemetry Middleware
/// Replaces traditional logging with isomorphic state vectors.
pub async fn thermodynamic_telemetry_middleware(
    req: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    
    // Extract Client IP
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("unknown")
        .to_string();

    // Execute the request pipeline
    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f32();
    let status = response.status();

    // Extract user_id from response extensions (propagated from capture_user_id_middleware)
    let user_id = response
        .extensions()
        .get::<PrivacySafeUserId>()
        .map(|uid| uid.0.clone())
        .unwrap_or_else(|| "none".to_string());

    // Map HTTP state to Thermodynamic Manifold Vectors
    
    // Friston Free Energy: Surrogate for system surprise/error
    let friston_free_energy = if status.is_success() {
        0.05 // Stable equilibrium
    } else if status.is_client_error() {
        2.5 // Boundary mismatch
    } else {
        10.0 // Phase collapse (Internal Error)
    };

    // Entropy Variance: Measure of trajectory volatility (latency squared)
    let entropy_variance = (duration * 10.0).powi(2);

    // Action Gradient: Directional delta of the update
    let action_gradient = [
        if method == "GET" { 0.1 } else { 0.8 }, // Kinetic energy of the request
        if status.is_success() { 1.0 } else { -1.0 }, // Gradient direction
        duration.min(1.0), // Temporal mass
    ];

    // Auth Rotor: Non-linear identity verification vector (U(1) manifold)
    let auth_rotor = [1.0, 0.0];

    let telemetry = ThermodynamicTelemetry {
        friston_free_energy,
        action_gradient,
        entropy_variance,
        auth_rotor,
    };

    // Emit Isomorphic Telemetry
    info!(
        telemetry = ?telemetry,
        path = %path,
        method = %method,
        status = status.as_u16(),
        client_ip = %client_ip,
        user_id = %user_id,
        "Thermodynamic State Update"
    );

    // OpControlBarrier: Entropy Spike Detection
    if telemetry.entropy_variance > ENTROPY_SPIKE_THRESHOLD {
        warn!(
            entropy_variance = telemetry.entropy_variance,
            threshold = ENTROPY_SPIKE_THRESHOLD,
            path = %path,
            "ENTROPY SPIKE DETECTED: Triggering OpControlBarrier"
        );

        // Intentional dissociation to protect the network manifold
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OP_CONTROL_BARRIER: Thermodynamic equilibrium lost. Dissociating from manifold."
        ).into_response();
    }

    response
}
