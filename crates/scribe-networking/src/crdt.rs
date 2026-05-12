use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LwwRegister<T> {
    pub value: T,
    pub timestamp: DateTime<Utc>,
}

pub const MAX_FUTURE_OFFSET: Duration = Duration::seconds(60);

impl<T: Clone> LwwRegister<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            timestamp: Utc::now(),
        }
    }

    pub fn merge(&mut self, other: &Self) 
    where T: Clone + PartialEq + Serialize {
        let now = Utc::now();
        let max_future = now + MAX_FUTURE_OFFSET;

        // Security check: Ignore updates from the far future to prevent poisoning
        if other.timestamp > max_future {
            return;
        }

        let self_val_str = serde_json::to_string(&self.value).unwrap_or_default();
        let other_val_str = serde_json::to_string(&other.value).unwrap_or_default();
        
        if other.timestamp > self.timestamp || (other.timestamp == self.timestamp && other_val_str > self_val_str) {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrdtState {
    pub data: HashMap<String, LwwRegister<serde_json::Value>>,
}

impl CrdtState {
    pub fn update(&mut self, key: String, value: serde_json::Value) {
        let register = LwwRegister::new(value);
        self.data.insert(key, register);
    }

    pub fn merge(&mut self, other: &Self) {
        let now = Utc::now();
        let max_future = now + MAX_FUTURE_OFFSET;

        for (key, other_reg) in &other.data {
            // Check future offset at the state level too
            if other_reg.timestamp > max_future {
                continue;
            }

            if let Some(self_reg) = self.data.get_mut(key) {
                self_reg.merge(other_reg);
            } else {
                self.data.insert(key.clone(), other_reg.clone());
            }
        }
    }
}
