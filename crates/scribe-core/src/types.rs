use serde::{Deserialize, Serialize};
use std::ops::Deref;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DbId(Uuid);

impl DbId {
    pub fn new() -> Self { Self(Uuid::new_v4()) }
    pub fn from_uuid(uuid: Uuid) -> Self { Self(uuid) }
    pub fn into_uuid(self) -> Uuid { self.0 }
    pub fn nil() -> Self { Self(Uuid::nil()) }
}

impl Default for DbId {
    fn default() -> Self { Self::new() }
}

impl Deref for DbId {
    type Target = Uuid;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DbTimestamp(DateTime<Utc>);

impl DbTimestamp {
    pub fn now() -> Self { Self(Utc::now()) }
    pub fn from_datetime(dt: DateTime<Utc>) -> Self { Self(dt) }
    pub fn into_datetime(self) -> DateTime<Utc> { self.0 }
}

impl Default for DbTimestamp {
    fn default() -> Self { Self::now() }
}

impl Deref for DbTimestamp {
    type Target = DateTime<Utc>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DbJson(pub serde_json::Value);

impl Deref for DbJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<serde_json::Value> for DbJson {
    fn from(v: serde_json::Value) -> Self { Self(v) }
}

/// Graded Algebra - Tier 1: U(1) Scalar
/// Massless pure phase shifts requiring minimal VRAM allocation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, bytemuck::Pod, bytemuck::Zeroable)]
#[serde(transparent)]
pub struct U1Scalar(pub f32);

/// Graded Algebra - Tier 2: Pauli SO(2) Rotor
/// Standard HNA state synchronization and action propagation.
/// Encodes local spatial geometry without maintaining global temporal history.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, bytemuck::Pod, bytemuck::Zeroable)]
#[serde(transparent)]
pub struct SO2Rotor(pub [f32; 2]);

impl SO2Rotor {
    pub fn new(cos: f32, sin: f32) -> Self {
        Self([cos, sin])
    }
}

/// Graded Algebra - Tier 3: Dirac 4x4 Tensor
/// Heavy, historical system state. Synchronized only via Deep Anchors.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, bytemuck::Pod, bytemuck::Zeroable)]
#[serde(transparent)]
pub struct DiracTensor(pub [f32; 16]);

/// Thermodynamic Telemetry
/// Replaces standard string-based logging with structural mathematical vectors.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ThermodynamicTelemetry {
    /// Surrogate for system surprise/error
    pub friston_free_energy: f32,
    /// Directional delta of the update
    pub action_gradient: [f32; 3],
    /// Measure of trajectory volatility
    pub entropy_variance: f32,
    /// Non-linear identity verification vector (Compositional Auth Rotor)
    pub auth_rotor: [f32; 2],
    /// Padding to enforce strict 16-byte Blackwell alignment (32 bytes total)
    pub _padding: f32,
}

impl ThermodynamicTelemetry {
    /// Creates a success telemetry update with specified free energy (surprise).
    pub fn success(ce: f32) -> Self {
        Self {
            friston_free_energy: ce,
            ..Default::default()
        }
    }

    /// Creates an error telemetry update with high free energy.
    pub fn error(ce: f32) -> Self {
        Self {
            friston_free_energy: ce,
            ..Default::default()
        }
    }

    /// Creates an action telemetry update with gradient.
    pub fn action(gradient: [f32; 3]) -> Self {
        Self {
            action_gradient: gradient,
            ..Default::default()
        }
    }
}

impl Default for ThermodynamicTelemetry {
    fn default() -> Self {
        Self {
            friston_free_energy: 0.0,
            action_gradient: [0.0; 3],
            entropy_variance: 0.0,
            auth_rotor: [1.0, 0.0], // Identity rotor
            _padding: 0.0,
        }
    }
}
