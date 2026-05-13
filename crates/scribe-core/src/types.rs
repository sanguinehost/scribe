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
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct U1Scalar(pub f32);

/// Graded Algebra - Tier 2: Pauli SO(2) Rotor
/// Standard HNA state synchronization and action propagation.
/// Encodes local spatial geometry without maintaining global temporal history.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SO2Rotor(pub [f32; 2]);

impl SO2Rotor {
    pub fn new(cos: f32, sin: f32) -> Self {
        Self([cos, sin])
    }
}

/// Graded Algebra - Tier 3: Dirac 4x4 Tensor
/// Heavy, historical system state. Synchronized only via Deep Anchors.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiracTensor(pub [f32; 16]);

/// Thermodynamic Telemetry
/// Replaces standard string-based logging with structural mathematical vectors.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ThermodynamicTelemetry {
    /// Surrogate for system surprise/error
    pub friston_free_energy: f32,
    /// Directional delta of the update
    pub action_gradient: [f32; 3],
    /// Measure of trajectory volatility
    pub entropy_variance: f32,
    /// Non-linear identity verification vector (Compositional Auth Rotor)
    pub auth_rotor: [f32; 2],
}
