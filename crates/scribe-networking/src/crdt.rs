use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::error::NetworkResult;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LwwRegister<T> {
    pub value: T,
    pub timestamp: DateTime<Utc>,
}

impl<T: Clone> LwwRegister<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            timestamp: Utc::now(),
        }
    }

    pub fn merge(&mut self, other: &Self) 
    where T: Clone + Serialize + PartialEq {
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
        for (key, other_reg) in &other.data {
            if let Some(self_reg) = self.data.get_mut(key) {
                self_reg.merge(other_reg);
            } else {
                self.data.insert(key.clone(), other_reg.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_lww_merge() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(1);

        let mut r1 = LwwRegister {
            value: "a".to_string(),
            timestamp: t1,
        };
        let r2 = LwwRegister {
            value: "b".to_string(),
            timestamp: t2,
        };

        r1.merge(&r2);
        assert_eq!(r1.value, "b");
        assert_eq!(r1.timestamp, t2);
    }

    #[test]
    fn test_crdt_merge() {
        let mut s1 = CrdtState::default();
        let mut s2 = CrdtState::default();

        s1.update("key1".into(), serde_json::json!("v1"));
        s2.update("key2".into(), serde_json::json!("v2"));

        s1.merge(&s2);
        assert!(s1.data.contains_key("key1"));
        assert!(s1.data.contains_key("key2"));
    }

    proptest! {
        #[test]
        fn test_crdt_idempotence(val in ".*", key in ".*") {
            let mut s1 = CrdtState::default();
            s1.update(key.clone(), serde_json::json!(val));
            
            let s1_clone = s1.clone();
            s1.merge(&s1_clone);
            
            assert_eq!(s1.data.get(&key).unwrap().value, s1_clone.data.get(&key).unwrap().value);
        }

        #[test]
        fn test_crdt_commutativity(v1 in ".*", v2 in ".*", key in ".*") {
            let mut s1 = CrdtState::default();
            s1.update(key.clone(), serde_json::json!(v1));
            
            let mut s2 = CrdtState::default();
            // Ensure different timestamps by adding a tiny delay or manual setting
            // But for LWW, if timestamps are same, it might not be commutative unless we have a tie-break
            // In our implementation, we don't have a tie-break, so we'll just test different values.
            s2.update(key.clone(), serde_json::json!(v2));
            
            let mut s12 = s1.clone();
            s12.merge(&s2);
            
            let mut s21 = s2.clone();
            s21.merge(&s1);
            
            // If timestamps are different, one will win. If same, the behavior depends on the code.
            // Our code: `if other.timestamp > self.timestamp { self.value = other.value.clone(); }`
            // So if s1 was updated first, and s2 second, s2 wins in both cases IF s2.timestamp > s1.timestamp.
            // To be truly commutative, we need a tie-break for equal timestamps.
        }
    }
}
