use crate::models::game_state::GameState;
use tracing::{debug, info};

/// Actions that can be taken to reconcile LLM-generated state
#[derive(Debug, Clone, PartialEq)]
pub enum ReconciliationAction {
    /// Remove item from inventory (for consumption or storage)
    RemoveItem { item_id: String },

    /// Add currency that should have been added but wasn't
    AddCurrency { currency_name: String, amount: u32 },

    /// Update vital value that should have changed but didn't
    UpdateVital { vital_name: String, delta: f64 },

    /// Apply status effect that should have been created but wasn't
    ApplyStatusEffect {
        effect_name: String,
        target_vital: Option<String>,
    },
}

/// Detects when reconciliation is needed by analyzing player actions and state changes
pub struct ReconciliationDetector;

impl ReconciliationDetector {
    /// Create a new reconciliation detector
    pub fn new() -> Self {
        Self
    }

    /// Detect what reconciliation actions are needed based on:
    /// - Player action text (what they tried to do)
    /// - Current state (before action)
    /// - New state (LLM-generated after action)
    ///
    /// Returns a list of reconciliation actions to apply
    pub fn detect_needs(
        &self,
        player_action: &str,
        current_state: &GameState,
        new_state: &GameState,
    ) -> Vec<ReconciliationAction> {
        let mut actions = Vec::new();

        // Detect item removal needs
        actions.extend(self.detect_item_removals(player_action, current_state, new_state));

        // Detect currency updates
        actions.extend(self.detect_currency_updates(player_action, current_state, new_state));

        // Detect vital updates
        actions.extend(self.detect_vital_updates(player_action, current_state, new_state));

        // Detect status effects
        actions.extend(self.detect_status_effects(player_action, current_state, new_state));

        actions
    }

    /// Detect if items should have been removed but weren't
    fn detect_item_removals(
        &self,
        player_action: &str,
        current_state: &GameState,
        new_state: &GameState,
    ) -> Vec<ReconciliationAction> {
        let mut actions = Vec::new();
        let action_lower = player_action.to_lowercase();

        // Keywords indicating consumption or usage
        let consume_keywords = ["drink", "consume", "use", "eat", "throw", "drop"];

        let has_consume = consume_keywords.iter().any(|k| action_lower.contains(k));

        if !has_consume {
            return actions;
        }

        // Check items present in current inventory
        for item in &current_state.inventory {
            let item_name_lower = item.name.to_lowercase();

            // Check if item mentioned in action (case-insensitive substring match)
            if action_lower.contains(&item_name_lower) {
                // Check if item is still in new state with same quantity
                if let Some(new_item) = new_state.inventory.iter().find(|i| i.id == item.id) {
                    if new_item.quantity == item.quantity {
                        debug!(
                            item = %item.name,
                            action = %player_action,
                            "Detected item should be consumed/removed but still in inventory"
                        );

                        actions.push(ReconciliationAction::RemoveItem {
                            item_id: item.id.clone(),
                        });
                    }
                }
            }
        }

        actions
    }

    /// Detect if currency should have been updated but wasn't
    fn detect_currency_updates(
        &self,
        player_action: &str,
        current_state: &GameState,
        new_state: &GameState,
    ) -> Vec<ReconciliationAction> {
        let mut actions = Vec::new();
        let action_lower = player_action.to_lowercase();

        // Keywords indicating currency gain
        let gain_keywords = ["loot", "find", "take", "coin", "gold", "reward"];

        if !gain_keywords.iter().any(|k| action_lower.contains(k)) {
            return actions;
        }

        // Extract currency amount from action text
        if let Some(amount) = self.extract_currency_amount(&action_lower) {
            // Check if gold/coin item increased
            let currency_names = ["Gold", "Coin", "Credits"];
            let mut currency_increased = false;

            for name in currency_names {
                let current_qty = current_state
                    .inventory
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case(name))
                    .map(|i| i.quantity)
                    .unwrap_or(0);

                let new_qty = new_state
                    .inventory
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case(name))
                    .map(|i| i.quantity)
                    .unwrap_or(0);

                if new_qty > current_qty {
                    currency_increased = true;
                    break;
                }
            }

            if !currency_increased {
                debug!(
                    amount = amount,
                    action = %player_action,
                    "Detected currency should be added"
                );

                actions.push(ReconciliationAction::AddCurrency {
                    currency_name: "Gold".to_string(), // Default to Gold
                    amount: amount as u32,
                });
            }
        }

        actions
    }

    /// Extract currency amount from text using simple parsing
    fn extract_currency_amount(&self, text: &str) -> Option<f64> {
        let words: Vec<&str> = text.split_whitespace().collect();

        for (i, word) in words.iter().enumerate() {
            // Check if word is a number
            if let Ok(amount) = word.parse::<f64>() {
                // Check if next word or word after is currency keyword
                if i + 1 < words.len() {
                    let next = words[i + 1].to_lowercase();
                    if next.contains("gold") || next.contains("coin") || next.contains("credit") {
                        return Some(amount);
                    }
                }
                if i + 2 < words.len() {
                    let next2 = words[i + 2].to_lowercase();
                    if next2.contains("gold") || next2.contains("coin") || next2.contains("credit")
                    {
                        return Some(amount);
                    }
                }
            }
        }

        None
    }

    /// Detect if vitals should have been updated but weren't
    fn detect_vital_updates(
        &self,
        player_action: &str,
        current_state: &GameState,
        new_state: &GameState,
    ) -> Vec<ReconciliationAction> {
        let mut actions = Vec::new();
        let action_lower = player_action.to_lowercase();

        // Healing detection
        if action_lower.contains("heal") || action_lower.contains("potion") {
            if let (Some(current_hp), Some(new_hp)) = (
                current_state.vitals.get("health"),
                new_state.vitals.get("health"),
            ) {
                // If health didn't increase
                if new_hp.current <= current_hp.current {
                    let expected_heal = 30.0; // Default assumption for generic healing

                    debug!(
                        current = current_hp.current,
                        new = new_hp.current,
                        "Detected healing should occur but didn't"
                    );

                    actions.push(ReconciliationAction::UpdateVital {
                        vital_name: "health".to_string(),
                        delta: expected_heal,
                    });
                }
            } else if current_state.vitals.contains_key("health") {
                // Health exists in current but was REMOVED in new state during a healing action?
                // This is likely an LLM error, but we'll let standard reconciliation handle it
                // unless we want to force it back. For now, we just don't crash.
            }
        }

        // Damage detection (simple)
        if action_lower.contains("hurt")
            || action_lower.contains("damage")
            || action_lower.contains("hit")
        {
            if let (Some(current_hp), Some(new_hp)) = (
                current_state.vitals.get("health"),
                new_state.vitals.get("health"),
            ) {
                // If health didn't decrease
                if new_hp.current >= current_hp.current {
                    let expected_damage = -10.0; // Default assumption

                    debug!(
                        current = current_hp.current,
                        new = new_hp.current,
                        "Detected damage should occur but didn't"
                    );

                    actions.push(ReconciliationAction::UpdateVital {
                        vital_name: "health".to_string(),
                        delta: expected_damage,
                    });
                }
            }
        }

        actions
    }

    /// Detect if status effects should have been applied but weren't
    fn detect_status_effects(
        &self,
        player_action: &str,
        _current_state: &GameState,
        _new_state: &GameState,
    ) -> Vec<ReconciliationAction> {
        let mut actions = Vec::new();
        let action_lower = player_action.to_lowercase();

        // Strength/Power buff
        if (action_lower.contains("strength") || action_lower.contains("power"))
            && action_lower.contains("potion")
        {
            actions.push(ReconciliationAction::ApplyStatusEffect {
                effect_name: "Strength Boost".to_string(),
                target_vital: None,
            });
        }

        // Poison
        if action_lower.contains("poison") {
            actions.push(ReconciliationAction::ApplyStatusEffect {
                effect_name: "Poisoned".to_string(),
                target_vital: Some("health".to_string()),
            });
        }

        actions
    }
}

impl Default for ReconciliationDetector {
    fn default() -> Self {
        Self::new()
    }
}
