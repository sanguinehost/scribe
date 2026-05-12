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
