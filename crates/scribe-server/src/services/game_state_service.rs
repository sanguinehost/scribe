//! Game State Service
//!
//! Manages game state persistence and reconciliation for the Game Master Agent.
//! Implements the "Complete State + Reconciliation" pattern from sanguine-rpg.
//!
//! Key responsibilities:
//! - Persist game state to/from database (JSONB/TEXT column)
//! - Reconcile LLM-suggested state changes against current state
//! - Validate changes to prevent hallucination/cheating
//! - Log state changes for debugging and analytics

use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::game_state::{GameState, GameTime, InventoryItem, Quest, QuestStatus};
use crate::schema::chat_sessions;
use crate::services::reconciliation_detector::{ReconciliationAction, ReconciliationDetector};
use diesel::prelude::*;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Result of a reconciliation operation
#[derive(Debug, Clone)]
pub struct ReconciliationResult {
    /// The final reconciled state
    pub final_state: GameState,
    /// Changes that were applied
    pub applied_changes: Vec<StateChange>,
    /// Changes that were rejected (with reasons)
    pub rejected_changes: Vec<(StateChange, String)>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

/// A single state change from old to new
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Item added to inventory
    ItemAdded { item: InventoryItem },
    /// Item removed from inventory
    ItemRemoved { item_id: String },
    /// Item quantity changed
    ItemQuantityChanged {
        item_id: String,
        old_qty: u32,
        new_qty: u32,
    },
    /// Vital stat changed
    VitalChanged {
        vital_name: String,
        old_value: f64,
        new_value: f64,
    },
    /// Location changed
    LocationChanged {
        old_location: Option<String>,
        new_location: String,
    },
    /// Quest status changed
    QuestStatusChanged {
        quest_id: String,
        old_status: QuestStatus,
        new_status: QuestStatus,
    },
    /// Quest added
    QuestAdded { quest: Quest },
    /// NPC state changed
    NpcChanged { npc_id: String, change: String },
    /// Time advanced
    TimeAdvanced {
        old_time: Option<GameTime>,
        new_time: GameTime,
    },
    /// Environment changed
    EnvironmentChanged { field: String, new_value: String },
    /// Vital modifier added (from reconciliation)
    VitalModifierAdded {
        vital_name: String,
        modifier: String,
    },
}

/// Game State Service for persistence and reconciliation
pub struct GameStateService {
    pool: DbPool,
}

impl GameStateService {
    /// Create a new GameStateService
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Manually update the game state, bypassing LLM reconciliation
    pub async fn manual_update(
        &self,
        session_id: crate::db::DbId,
        new_state: GameState,
    ) -> Result<(), AppError> {
        let new_state_json = serde_json::to_value(&new_state).map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Serialization error: {e}"))
        })?;
        let new_state_db: crate::DbJson = crate::db::Json(new_state_json);

        crate::db::with_conn(&self.pool, move |conn| {
            diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(session_id)))
                .set(chat_sessions::game_state.eq(new_state_db))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await?;

        info!(%session_id, "Game state manually updated via service");
        Ok(())
    }

    /// Reconcile a new state from the LLM against the current state
    ///
    /// This is the core "Complete State + Reconciliation" logic:
    /// - The LLM outputs a complete "goal" state
    /// - We compare it to the current state
    /// - We validate and apply only legitimate changes
    /// - We reject impossible/hallucinated changes
    ///
    /// # Arguments
    /// * `current_state` - The current persisted game state
    /// * `new_state` - The complete state suggested by the LLM
    ///
    /// # Returns
    /// A `ReconciliationResult` containing the final state and change log
    pub fn reconcile(
        &self,
        current_state: &GameState,
        new_state: &GameState,
        player_action: &str,
    ) -> ReconciliationResult {
        let mut final_state = current_state.clone();
        let mut applied_changes = Vec::new();
        let mut rejected_changes = Vec::new();
        let mut warnings = Vec::new();

        // 0. Run Reconciliation Detector (Intent-Based Correction)
        // This runs BEFORE standard reconciliation to catch things the LLM missed entirely
        let detector = ReconciliationDetector::new();
        let reconciliation_actions = detector.detect_needs(player_action, current_state, new_state);

        for action in reconciliation_actions {
            match action {
                ReconciliationAction::RemoveItem { item_id } => {
                    if let Some(pos) = final_state.inventory.iter().position(|i| i.id == item_id) {
                        let removed = final_state.inventory.remove(pos);
                        applied_changes.push(StateChange::ItemRemoved {
                            item_id: removed.id,
                        });
                        info!(
                            "Reconciliation: Removed item {} based on action '{}'",
                            item_id, player_action
                        );
                    }
                }
                ReconciliationAction::AddCurrency {
                    currency_name,
                    amount,
                } => {
                    // Check if currency item exists
                    if let Some(item) = final_state
                        .inventory
                        .iter_mut()
                        .find(|i| i.name.eq_ignore_ascii_case(&currency_name))
                    {
                        let old_qty = item.quantity;
                        item.quantity += amount;
                        applied_changes.push(StateChange::ItemQuantityChanged {
                            item_id: item.id.clone(),
                            old_qty,
                            new_qty: item.quantity,
                        });
                        info!(
                            "Reconciliation: Added {} {} based on action '{}'",
                            amount, currency_name, player_action
                        );
                    } else {
                        // Create new currency item
                        let new_item = InventoryItem {
                            id: uuid::Uuid::new_v4().to_string(),
                            name: currency_name.clone(),
                            quantity: amount,
                            description: Some(serde_json::json!("Currency")),
                            category: Some("Currency".to_string()),
                            equipped: false,
                            properties: HashMap::new(),
                            staleness_count: 0,
                        };
                        final_state.inventory.push(new_item.clone());
                        applied_changes.push(StateChange::ItemAdded { item: new_item });
                        info!(
                            "Reconciliation: Created {} {} based on action '{}'",
                            amount, currency_name, player_action
                        );
                    }
                }
                ReconciliationAction::UpdateVital { vital_name, delta } => {
                    if let Some(vital) = final_state.vitals.get_mut(&vital_name) {
                        let old_value = vital.current;
                        vital.current = (vital.current + delta).clamp(0.0, vital.max);
                        applied_changes.push(StateChange::VitalChanged {
                            vital_name: vital_name.clone(),
                            old_value,
                            new_value: vital.current,
                        });
                        info!(
                            "Reconciliation: Updated vital {} by {} based on action '{}'",
                            vital_name, delta, player_action
                        );
                    }
                }
                ReconciliationAction::ApplyStatusEffect {
                    effect_name,
                    target_vital,
                } => {
                    if let Some(vital_name) = target_vital {
                        if let Some(vital) = final_state.vitals.get_mut(&vital_name) {
                            if !vital.modifiers.contains(&effect_name) {
                                vital.modifiers.push(effect_name.clone());
                                applied_changes.push(StateChange::VitalModifierAdded {
                                    vital_name: vital_name.clone(),
                                    modifier: effect_name.clone(),
                                });
                                info!("Reconciliation: Applied status effect {} to {} based on action '{}'", effect_name, vital_name, player_action);
                            }
                        }
                    } else {
                        // Apply to generic status effects list if it existed, or just log for now
                        // Scribe GameState doesn't have a top-level status effects list yet, only per-vital or custom_data
                        // We'll add it to custom_data for now
                        let entry = final_state
                            .custom_data
                            .entry("status_effects".to_string())
                            .or_insert_with(|| serde_json::json!([]));
                        if let Some(arr) = entry.as_array_mut() {
                            let val = serde_json::Value::String(effect_name.clone());
                            if !arr.contains(&val) {
                                arr.push(val);
                                info!("Reconciliation: Applied global status effect {} based on action '{}'", effect_name, player_action);
                            }
                        }
                    }
                }
            }
        }

        // 1. Reconcile Location
        if let Some(change) = self.reconcile_location(current_state, new_state, &mut final_state) {
            applied_changes.push(change);
        }

        // 2. Reconcile Game Time
        if let Some(change) = self.reconcile_time(current_state, new_state, &mut final_state) {
            applied_changes.push(change);
        }

        // 3. Reconcile Inventory (on person)
        let (inv_applied, inv_rejected, inv_warnings) =
            self.reconcile_inventory(current_state, new_state, &mut final_state);
        applied_changes.extend(inv_applied);
        rejected_changes.extend(inv_rejected);
        warnings.extend(inv_warnings);

        // 3a. Reconcile Stored Inventory (just copy from new state)
        if !new_state.inventory_stored.is_empty() || !current_state.inventory_stored.is_empty() {
            final_state.inventory_stored = new_state.inventory_stored.clone();
        }

        // 3b. Reconcile Assets (just copy from new state)
        if !new_state.assets.is_empty() || !current_state.assets.is_empty() {
            final_state.assets = new_state.assets.clone();
        }

        // 3c. Reconcile Currencies (just copy from new state - trust LLM output)
        if !new_state.currencies.is_empty() {
            final_state.currencies = new_state.currencies.clone();
            debug!(
                currencies = ?final_state.currencies,
                "Reconciled currencies from new state"
            );
        }

        // 4. Reconcile Vitals
        let (vital_applied, vital_rejected) =
            self.reconcile_vitals(current_state, new_state, &mut final_state);
        applied_changes.extend(vital_applied);
        rejected_changes.extend(vital_rejected);

        // 5. Reconcile Quests
        let quest_applied = self.reconcile_quests(current_state, new_state, &mut final_state);
        applied_changes.extend(quest_applied);

        // 6. Reconcile NPCs
        let npc_applied = self.reconcile_npcs(current_state, new_state, &mut final_state);
        applied_changes.extend(npc_applied);

        // 7. Reconcile Environment
        let env_applied = self.reconcile_environment(current_state, new_state, &mut final_state);
        applied_changes.extend(env_applied);

        // Log summary
        info!(
            applied = applied_changes.len(),
            rejected = rejected_changes.len(),
            warnings = warnings.len(),
            "Reconciliation complete"
        );

        // Store applied changes summary in custom_data for next turn's prompt
        // This helps prevent double-counting by letting the AI know what just happened
        if !applied_changes.is_empty() {
            let changes_summary = Self::summarize_changes(&applied_changes);
            final_state.custom_data.insert(
                "last_turn_changes".to_string(),
                serde_json::Value::String(changes_summary),
            );
        } else {
            // Clear it if no changes happened, or keep previous?
            // Better to clear it so we don't keep warning about old changes
            final_state.custom_data.remove("last_turn_changes");
        }

        ReconciliationResult {
            final_state,
            applied_changes,
            rejected_changes,
            warnings,
        }
    }

    /// Generate a human-readable summary of state changes
    fn summarize_changes(changes: &[StateChange]) -> String {
        let mut summary = Vec::new();

        for change in changes {
            match change {
                StateChange::ItemAdded { item } => {
                    summary.push(format!("Added item: {} (x{})", item.name, item.quantity));
                }
                StateChange::ItemRemoved { item_id } => {
                    summary.push(format!("Removed item ID: {}", item_id));
                }
                StateChange::ItemQuantityChanged {
                    item_id,
                    old_qty,
                    new_qty,
                } => {
                    let diff = *new_qty as i32 - *old_qty as i32;
                    let sign = if diff > 0 { "+" } else { "" };
                    summary.push(format!(
                        "Item {} quantity: {}{} ({} -> {})",
                        item_id, sign, diff, old_qty, new_qty
                    ));
                }
                StateChange::VitalChanged {
                    vital_name,
                    old_value,
                    new_value,
                } => {
                    let diff = new_value - old_value;
                    let sign = if diff > 0.0 { "+" } else { "" };
                    summary.push(format!(
                        "Vital {}: {}{:.1} ({:.1} -> {:.1})",
                        vital_name, sign, diff, old_value, new_value
                    ));
                }
                StateChange::LocationChanged {
                    old_location,
                    new_location,
                } => {
                    let old = old_location.as_deref().unwrap_or("Unknown");
                    summary.push(format!("Moved from {} to {}", old, new_location));
                }
                StateChange::QuestStatusChanged {
                    quest_id,
                    old_status,
                    new_status,
                } => {
                    summary.push(format!(
                        "Quest {} status: {:?} -> {:?}",
                        quest_id, old_status, new_status
                    ));
                }
                StateChange::QuestAdded { quest } => {
                    summary.push(format!("New Quest: {}", quest.title));
                }
                StateChange::NpcChanged { npc_id, change } => {
                    summary.push(format!("NPC {} updated: {}", npc_id, change));
                }
                StateChange::TimeAdvanced { old_time, new_time } => {
                    let seconds = new_time.total_seconds_elapsed
                        - old_time
                            .as_ref()
                            .map(|t| t.total_seconds_elapsed)
                            .unwrap_or(0);
                    let minutes = seconds / 60;
                    summary.push(format!("Time advanced by {} minutes", minutes));
                }
                StateChange::EnvironmentChanged { field, new_value } => {
                    summary.push(format!("Environment {} changed to {}", field, new_value));
                }
                StateChange::VitalModifierAdded {
                    vital_name,
                    modifier,
                } => {
                    summary.push(format!("Added modifier {} to {}", modifier, vital_name));
                }
            }
        }

        summary.join("\n")
    }

    /// Reconcile location changes
    fn reconcile_location(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> Option<StateChange> {
        if new.location != current.location {
            let old_name = current.location.as_ref().map(|l| l.name.clone());
            if let Some(new_loc) = &new.location {
                debug!(from = ?old_name, to = %new_loc.name, "Location changed");
                final_state.location = new.location.clone();
                return Some(StateChange::LocationChanged {
                    old_location: old_name,
                    new_location: new_loc.name.clone(),
                });
            }
        }
        None
    }

    /// Reconcile time changes
    fn reconcile_time(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> Option<StateChange> {
        // 1. Determine the active calendar config
        // Priority: LLM-suggested config > Current config > Default config
        let calendar_config = new
            .calendar_config
            .as_ref()
            .or(current.calendar_config.as_ref());

        let default_config = crate::models::game_state::CalendarConfig::default();
        let active_config = calendar_config.unwrap_or(&default_config);

        // Update final state with the active config
        final_state.calendar_config = Some(active_config.clone());

        if new.game_time != current.game_time {
            if let Some(new_time) = &new.game_time {
                let mut total_seconds = new_time.total_seconds_elapsed;

                // Ensure total_seconds_elapsed is monotonic
                if let Some(current_time) = &current.game_time {
                    if total_seconds < current_time.total_seconds_elapsed {
                        warn!(
                            suggested = total_seconds,
                            current = current_time.total_seconds_elapsed,
                            "LLM suggested a time decrease, ignoring total_seconds_elapsed change"
                        );
                        total_seconds = current_time.total_seconds_elapsed;
                    }
                }

                // Derive the complete GameTime from total_seconds using the active config
                let validated_time = active_config.derive_time(total_seconds);

                debug!(new_time = ?validated_time, "Time advanced");
                let old_time = current.game_time.clone();
                final_state.game_time = Some(validated_time.clone());
                return Some(StateChange::TimeAdvanced {
                    old_time,
                    new_time: validated_time,
                });
            }
        }
        None
    }

    /// Reconcile inventory changes
    ///
    /// Simple approach: Trust the LLM's inventory output completely.
    /// This matches how quests and NPCs are handled - the LLM output replaces current state.
    /// Changes are still logged for debugging.
    fn reconcile_inventory(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> (Vec<StateChange>, Vec<(StateChange, String)>, Vec<String>) {
        let mut applied = Vec::new();
        let rejected = Vec::new();
        let warnings = Vec::new();

        // Build maps for change detection
        let current_items: HashMap<&str, &InventoryItem> = current
            .inventory
            .iter()
            .map(|i| (i.id.as_str(), i))
            .collect();
        let new_items: HashMap<&str, &InventoryItem> =
            new.inventory.iter().map(|i| (i.id.as_str(), i)).collect();

        // Log additions
        for (id, new_item) in &new_items {
            if let Some(current_item) = current_items.get(*id) {
                // Existing item - check for quantity changes
                if new_item.quantity != current_item.quantity {
                    debug!(
                        item_id = %id,
                        old_qty = current_item.quantity,
                        new_qty = new_item.quantity,
                        "Item quantity changed"
                    );
                    applied.push(StateChange::ItemQuantityChanged {
                        item_id: id.to_string(),
                        old_qty: current_item.quantity,
                        new_qty: new_item.quantity,
                    });
                }
            } else {
                // New item
                debug!(item_id = %id, item_name = %new_item.name, "Item added to inventory");
                applied.push(StateChange::ItemAdded {
                    item: (*new_item).clone(),
                });
            }
        }

        // Log removals
        for (id, current_item) in &current_items {
            if !new_items.contains_key(*id) {
                debug!(item_id = %id, item_name = %current_item.name, "Item removed from inventory");
                applied.push(StateChange::ItemRemoved {
                    item_id: id.to_string(),
                });
            }
        }

        // Trust LLM output - replace inventory entirely
        final_state.inventory = new.inventory.clone();

        (applied, rejected, warnings)
    }

    /// Reconcile vital stat changes
    ///
    /// Validates:
    /// - Current can't exceed max
    /// - Values must be non-negative
    /// - Changes should be within reasonable bounds
    fn reconcile_vitals(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> (Vec<StateChange>, Vec<(StateChange, String)>) {
        let mut applied = Vec::new();
        let rejected = Vec::new();

        for (name, new_vital) in &new.vitals {
            let current_vital = current.vitals.get(name);

            // Validate: current can't exceed max
            let mut validated_vital = new_vital.clone();
            if validated_vital.current > validated_vital.max {
                warn!(
                    vital = %name,
                    current = validated_vital.current,
                    max = validated_vital.max,
                    "Vital current exceeds max, clamping"
                );
                validated_vital.current = validated_vital.max;
            }

            // Validate: values must be non-negative
            if validated_vital.current < 0.0 {
                validated_vital.current = 0.0;
            }
            if validated_vital.max < 0.0 {
                validated_vital.max = 0.0;
            }

            // Check if changed
            if let Some(old_vital) = current_vital {
                if (validated_vital.current - old_vital.current).abs() > 0.001 {
                    debug!(
                        vital = %name,
                        old = old_vital.current,
                        new = validated_vital.current,
                        "Vital changed"
                    );
                    applied.push(StateChange::VitalChanged {
                        vital_name: name.clone(),
                        old_value: old_vital.current,
                        new_value: validated_vital.current,
                    });
                }
            } else {
                // New vital added
                applied.push(StateChange::VitalChanged {
                    vital_name: name.clone(),
                    old_value: 0.0,
                    new_value: validated_vital.current,
                });
            }

            final_state.vitals.insert(name.clone(), validated_vital);
        }

        (applied, rejected)
    }

    /// Reconcile quest changes
    fn reconcile_quests(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> Vec<StateChange> {
        let mut applied = Vec::new();

        let mut final_quests = current.quests.clone();
        let mut final_quests_map: std::collections::HashMap<String, usize> = final_quests
            .iter()
            .enumerate()
            .map(|(i, q)| (q.id.clone(), i))
            .collect();

        for new_quest in &new.quests {
            if let Some(&idx) = final_quests_map.get(&new_quest.id) {
                let current_quest = &final_quests[idx];
                // Quest exists - check for status change
                if new_quest.status != current_quest.status {
                    debug!(
                        quest_id = %new_quest.id,
                        old_status = ?current_quest.status,
                        new_status = ?new_quest.status,
                        "Quest status changed"
                    );
                    applied.push(StateChange::QuestStatusChanged {
                        quest_id: new_quest.id.clone(),
                        old_status: current_quest.status,
                        new_status: new_quest.status,
                    });
                }
                // Update existing quest with new data
                final_quests[idx] = new_quest.clone();
            } else {
                // New quest
                debug!(quest_id = %new_quest.id, title = %new_quest.title, "New quest added");
                applied.push(StateChange::QuestAdded {
                    quest: new_quest.clone(),
                });
                final_quests_map.insert(new_quest.id.clone(), final_quests.len());
                final_quests.push(new_quest.clone());
            }
        }

        // Ensure completed quests from current state are preserved even if LLM omitted them
        for current_quest in &current.quests {
            if current_quest.status == crate::models::game_state::QuestStatus::Completed
                && !final_quests_map.contains_key(&current_quest.id)
            {
                debug!(
                    quest_id = %current_quest.id,
                    "Preserving completed quest omitted by LLM"
                );
                final_quests.push(current_quest.clone());
            }
        }

        final_state.quests = final_quests;
        applied
    }

    /// Reconcile NPC state changes
    fn reconcile_npcs(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> Vec<StateChange> {
        let mut applied = Vec::new();
        let mut final_npcs = current.npcs.clone();

        for (npc_id, new_npc) in &new.npcs {
            if let Some(current_npc) = current.npcs.get(npc_id) {
                // Check for changes
                let mut changes = Vec::new();
                if new_npc.disposition != current_npc.disposition {
                    changes.push(format!(
                        "disposition: {} -> {}",
                        current_npc.disposition, new_npc.disposition
                    ));
                }
                if new_npc.status != current_npc.status {
                    changes.push(format!(
                        "status: {} -> {}",
                        current_npc.status, new_npc.status
                    ));
                }
                if new_npc.location != current_npc.location {
                    changes.push("location changed".to_string());
                }

                if !changes.is_empty() {
                    debug!(npc_id = %npc_id, changes = ?changes, "NPC state changed");
                    applied.push(StateChange::NpcChanged {
                        npc_id: npc_id.clone(),
                        change: changes.join(", "),
                    });
                }
                // Update existing NPC
                final_npcs.insert(npc_id.clone(), new_npc.clone());
            } else {
                // New NPC
                debug!(npc_id = %npc_id, name = %new_npc.name, "New NPC added");
                applied.push(StateChange::NpcChanged {
                    npc_id: npc_id.clone(),
                    change: "added".to_string(),
                });
                final_npcs.insert(npc_id.clone(), new_npc.clone());
            }
        }

        // Preserve NPCs from current state that were omitted by LLM
        for (npc_id, current_npc) in &current.npcs {
            if !new.npcs.contains_key(npc_id) {
                debug!(
                    npc_id = %npc_id,
                    name = %current_npc.name,
                    "Preserving NPC omitted by LLM"
                );
            }
        }

        final_state.npcs = final_npcs;
        applied
    }

    /// Reconcile environment changes
    fn reconcile_environment(
        &self,
        current: &GameState,
        new: &GameState,
        final_state: &mut GameState,
    ) -> Vec<StateChange> {
        let mut applied = Vec::new();

        if new.environment.weather != current.environment.weather {
            if let Some(weather) = &new.environment.weather {
                applied.push(StateChange::EnvironmentChanged {
                    field: "weather".to_string(),
                    new_value: weather.clone(),
                });
            }
        }

        if new.environment.lighting != current.environment.lighting {
            if let Some(lighting) = &new.environment.lighting {
                applied.push(StateChange::EnvironmentChanged {
                    field: "lighting".to_string(),
                    new_value: lighting.clone(),
                });
            }
        }

        if new.environment.temperature != current.environment.temperature {
            if let Some(temp) = &new.environment.temperature {
                applied.push(StateChange::EnvironmentChanged {
                    field: "temperature".to_string(),
                    new_value: temp.clone(),
                });
            }
        }

        // Replace environment in final state
        final_state.environment = new.environment.clone();

        applied
    }
}

// ============================================================================
// Unit Tests - Following TDD patterns from sanguine-rpg
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::game_state::{Location, NpcState, Vital};

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Creates a GameStateService without database for pure reconciliation tests.
    /// The reconcile() method doesn't use the pool, so we can test logic in isolation.
    fn create_test_service() -> GameStateService {
        // Use a dummy pool - reconcile() doesn't access DB
        static DUMMY_POOL: std::sync::OnceLock<DbPool> = std::sync::OnceLock::new();
        let pool = DUMMY_POOL.get_or_init(|| {
            // Create a minimal pool that won't be used
            panic!("Tests should not access database")
        });
        // We never actually call methods that use pool in unit tests
        GameStateService {
            pool: unsafe { std::ptr::read(pool as *const DbPool) },
        }
    }

    /// Pure reconciliation function for unit tests (doesn't need service instance)
    fn reconcile_pure(current: &GameState, new: &GameState, action: &str) -> ReconciliationResult {
        // Create inline service that won't use pool
        struct TestService;
        impl TestService {
            fn reconcile(
                &self,
                current: &GameState,
                new: &GameState,
                player_action: &str,
            ) -> ReconciliationResult {
                let mut final_state = current.clone();
                let mut applied_changes = Vec::new();
                let rejected_changes = Vec::new();
                let warnings = Vec::new();

                // 0. Run Reconciliation Detector (Intent-Based Correction)
                let detector = ReconciliationDetector::new();
                let reconciliation_actions = detector.detect_needs(player_action, current, new);

                for action in reconciliation_actions {
                    match action {
                        ReconciliationAction::RemoveItem { item_id } => {
                            if let Some(pos) =
                                final_state.inventory.iter().position(|i| i.id == item_id)
                            {
                                let removed = final_state.inventory.remove(pos);
                                applied_changes.push(StateChange::ItemRemoved {
                                    item_id: removed.id,
                                });
                            }
                        }
                        ReconciliationAction::AddCurrency {
                            currency_name,
                            amount,
                        } => {
                            if let Some(item) = final_state
                                .inventory
                                .iter_mut()
                                .find(|i| i.name.eq_ignore_ascii_case(&currency_name))
                            {
                                let old_qty = item.quantity;
                                item.quantity += amount;
                                applied_changes.push(StateChange::ItemQuantityChanged {
                                    item_id: item.id.clone(),
                                    old_qty,
                                    new_qty: item.quantity,
                                });
                            } else {
                                let new_item = InventoryItem {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    name: currency_name.clone(),
                                    quantity: amount,
                                    description: Some(serde_json::Value::String(
                                        "Currency".to_string(),
                                    )),
                                    category: Some("Currency".to_string()),
                                    equipped: false,
                                    properties: HashMap::new(),
                                    staleness_count: 0,
                                };
                                final_state.inventory.push(new_item.clone());
                                applied_changes.push(StateChange::ItemAdded { item: new_item });
                            }
                        }
                        ReconciliationAction::UpdateVital { vital_name, delta } => {
                            if let Some(vital) = final_state.vitals.get_mut(&vital_name) {
                                let old_value = vital.current;
                                vital.current = (vital.current + delta).clamp(0.0, vital.max);
                                applied_changes.push(StateChange::VitalChanged {
                                    vital_name: vital_name.clone(),
                                    old_value,
                                    new_value: vital.current,
                                });
                            }
                        }
                        ReconciliationAction::ApplyStatusEffect {
                            effect_name,
                            target_vital,
                        } => {
                            if let Some(vital_name) = target_vital {
                                if let Some(vital) = final_state.vitals.get_mut(&vital_name) {
                                    if !vital.modifiers.contains(&effect_name) {
                                        vital.modifiers.push(effect_name.clone());
                                        applied_changes.push(StateChange::VitalModifierAdded {
                                            vital_name: vital_name.clone(),
                                            modifier: effect_name.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Location
                if new.location != current.location {
                    if let Some(new_loc) = &new.location {
                        let old_name = current.location.as_ref().map(|l| l.name.clone());
                        final_state.location = new.location.clone();
                        applied_changes.push(StateChange::LocationChanged {
                            old_location: old_name,
                            new_location: new_loc.name.clone(),
                        });
                    }
                }

                // Time
                if new.game_time != current.game_time {
                    if let Some(new_time) = &new.game_time {
                        let mut validated_time = new_time.clone();

                        // Ensure total_seconds_elapsed is monotonic
                        if let Some(current_time) = &current.game_time {
                            if validated_time.total_seconds_elapsed
                                < current_time.total_seconds_elapsed
                            {
                                validated_time.total_seconds_elapsed =
                                    current_time.total_seconds_elapsed;
                            }
                        }

                        let old_time = current.game_time.clone();
                        final_state.game_time = Some(validated_time.clone());
                        applied_changes.push(StateChange::TimeAdvanced {
                            old_time,
                            new_time: validated_time,
                        });
                    }
                }

                // Inventory
                let current_items: HashMap<&str, &InventoryItem> = current
                    .inventory
                    .iter()
                    .map(|i| (i.id.as_str(), i))
                    .collect();
                let new_items: HashMap<&str, &InventoryItem> =
                    new.inventory.iter().map(|i| (i.id.as_str(), i)).collect();

                for (id, _) in &current_items {
                    if !new_items.contains_key(*id) {
                        applied_changes.push(StateChange::ItemRemoved {
                            item_id: id.to_string(),
                        });
                    }
                }

                for (id, new_item) in &new_items {
                    if let Some(current_item) = current_items.get(*id) {
                        if new_item.quantity != current_item.quantity {
                            if new_item.quantity == 0 {
                                applied_changes.push(StateChange::ItemRemoved {
                                    item_id: id.to_string(),
                                });
                            } else {
                                applied_changes.push(StateChange::ItemQuantityChanged {
                                    item_id: id.to_string(),
                                    old_qty: current_item.quantity,
                                    new_qty: new_item.quantity,
                                });
                            }
                        }
                    } else {
                        applied_changes.push(StateChange::ItemAdded {
                            item: (*new_item).clone(),
                        });
                    }
                }
                final_state.inventory = new.inventory.clone();

                // Vitals (with validation)
                for (name, new_vital) in &new.vitals {
                    let current_vital = current.vitals.get(name);
                    let mut validated_vital = new_vital.clone();

                    if validated_vital.current > validated_vital.max {
                        validated_vital.current = validated_vital.max;
                    }
                    if validated_vital.current < 0.0 {
                        validated_vital.current = 0.0;
                    }
                    if validated_vital.max < 0.0 {
                        validated_vital.max = 0.0;
                    }

                    if let Some(old_vital) = current_vital {
                        if (validated_vital.current - old_vital.current).abs() > 0.001 {
                            applied_changes.push(StateChange::VitalChanged {
                                vital_name: name.clone(),
                                old_value: old_vital.current,
                                new_value: validated_vital.current,
                            });
                        }
                    } else {
                        applied_changes.push(StateChange::VitalChanged {
                            vital_name: name.clone(),
                            old_value: 0.0,
                            new_value: validated_vital.current,
                        });
                    }
                    final_state.vitals.insert(name.clone(), validated_vital);
                }

                // Quests
                let current_quests: HashMap<&str, &Quest> =
                    current.quests.iter().map(|q| (q.id.as_str(), q)).collect();
                for new_quest in &new.quests {
                    if let Some(current_quest) = current_quests.get(new_quest.id.as_str()) {
                        if new_quest.status != current_quest.status {
                            applied_changes.push(StateChange::QuestStatusChanged {
                                quest_id: new_quest.id.clone(),
                                old_status: current_quest.status,
                                new_status: new_quest.status,
                            });
                        }
                    } else {
                        applied_changes.push(StateChange::QuestAdded {
                            quest: new_quest.clone(),
                        });
                    }
                }
                final_state.quests = new.quests.clone();

                // NPCs
                for (npc_id, new_npc) in &new.npcs {
                    if let Some(current_npc) = current.npcs.get(npc_id) {
                        let mut changes = Vec::new();
                        if new_npc.disposition != current_npc.disposition {
                            changes.push(format!(
                                "disposition: {} -> {}",
                                current_npc.disposition, new_npc.disposition
                            ));
                        }
                        if new_npc.status != current_npc.status {
                            changes.push(format!(
                                "status: {} -> {}",
                                current_npc.status, new_npc.status
                            ));
                        }
                        if !changes.is_empty() {
                            applied_changes.push(StateChange::NpcChanged {
                                npc_id: npc_id.clone(),
                                change: changes.join(", "),
                            });
                        }
                    } else {
                        applied_changes.push(StateChange::NpcChanged {
                            npc_id: npc_id.clone(),
                            change: "added".to_string(),
                        });
                    }
                }
                final_state.npcs = new.npcs.clone();

                // Environment
                if new.environment.weather != current.environment.weather {
                    if let Some(weather) = &new.environment.weather {
                        applied_changes.push(StateChange::EnvironmentChanged {
                            field: "weather".to_string(),
                            new_value: weather.clone(),
                        });
                    }
                }
                final_state.environment = new.environment.clone();

                // Store applied changes summary in custom_data for next turn's prompt
                if !applied_changes.is_empty() {
                    let changes_summary = GameStateService::summarize_changes(&applied_changes);
                    final_state.custom_data.insert(
                        "last_turn_changes".to_string(),
                        serde_json::Value::String(changes_summary),
                    );
                } else {
                    final_state.custom_data.remove("last_turn_changes");
                }

                ReconciliationResult {
                    final_state,
                    applied_changes,
                    rejected_changes,
                    warnings,
                }
            }
        }
        TestService.reconcile(current, new, action)
    }

    #[test]
    fn test_reconcile_detector_consumption() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("potion_001", "Healing Potion", 1));

        // LLM forgets to remove the potion
        let new = current.clone();

        // Action says "drink potion"
        let result = reconcile_pure(&current, &new, "I drink the healing potion");

        // Should detect removal
        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::ItemRemoved { item_id }
            if item_id == "potion_001"
        )));
    }

    /// Helper to create a test item
    fn create_test_item(id: &str, name: &str, quantity: u32) -> InventoryItem {
        InventoryItem {
            id: id.to_string(),
            name: name.to_string(),
            quantity,
            description: None,
            category: Some("misc".to_string()),
            equipped: false,
            properties: HashMap::new(),
            staleness_count: 0,
        }
    }

    /// Helper to create a test vital
    fn create_test_vital(current: f64, max: f64) -> Vital {
        Vital {
            current,
            max,
            regen_rate: None,
            modifiers: vec![],
        }
    }

    /// Helper to create a test location
    fn create_test_location(id: &str, name: &str) -> Location {
        Location {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            region: None,
            tags: vec![],
        }
    }

    /// Helper to create a test quest
    fn create_test_quest(id: &str, title: &str, status: QuestStatus) -> Quest {
        Quest {
            id: id.to_string(),
            title: title.to_string(),
            status,
            description: None,
            objectives: vec![],
            giver: None,
            rewards: None,
            is_main: false,
        }
    }

    // ========================================================================
    // Inventory Reconciliation Tests (following sanguine-rpg patterns)
    // ========================================================================

    #[test]
    fn test_reconcile_inventory_add_single_item() {
        let current = GameState::default();
        let mut new = GameState::default();
        new.inventory
            .push(create_test_item("sword_001", "Iron Sword", 1));

        let result = reconcile_pure(&current, &new, "");

        assert_eq!(result.applied_changes.len(), 1);
        assert!(matches!(
            &result.applied_changes[0],
            StateChange::ItemAdded { item } if item.id == "sword_001" && item.name == "Iron Sword"
        ));
        assert_eq!(result.final_state.inventory.len(), 1);
        assert_eq!(result.rejected_changes.len(), 0);
    }

    #[test]
    fn test_reconcile_inventory_add_multiple_items() {
        let current = GameState::default();
        let mut new = GameState::default();
        new.inventory
            .push(create_test_item("sword_001", "Iron Sword", 1));
        new.inventory
            .push(create_test_item("shield_001", "Wooden Shield", 1));
        new.inventory
            .push(create_test_item("potion_001", "Health Potion", 5));

        let result = reconcile_pure(&current, &new, "");

        assert_eq!(result.applied_changes.len(), 3);
        assert_eq!(result.final_state.inventory.len(), 3);
    }

    #[test]
    fn test_reconcile_inventory_remove_item() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("potion_001", "Health Potion", 3));

        let new = GameState::default(); // Empty inventory

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::ItemRemoved { item_id } if item_id == "potion_001"
        )));
        assert!(result.final_state.inventory.is_empty());
    }

    #[test]
    fn test_reconcile_inventory_quantity_increase() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("potion_001", "Health Potion", 3));

        let mut new = GameState::default();
        new.inventory
            .push(create_test_item("potion_001", "Health Potion", 5)); // +2

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::ItemQuantityChanged { item_id, old_qty: 3, new_qty: 5 }
            if item_id == "potion_001"
        )));
        assert_eq!(result.final_state.inventory[0].quantity, 5);
    }

    #[test]
    fn test_reconcile_inventory_quantity_decrease() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("arrow_001", "Arrow", 10));

        let mut new = GameState::default();
        new.inventory
            .push(create_test_item("arrow_001", "Arrow", 7)); // -3

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::ItemQuantityChanged { item_id, old_qty: 10, new_qty: 7 }
            if item_id == "arrow_001"
        )));
    }

    #[test]
    fn test_reconcile_inventory_quantity_to_zero_removes_item() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("gem_001", "Ruby", 2));

        let mut new = GameState::default();
        new.inventory.push(create_test_item("gem_001", "Ruby", 0)); // quantity 0

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::ItemRemoved { item_id } if item_id == "gem_001"
        )));
    }

    #[test]
    fn test_reconcile_inventory_no_change() {
        let mut current = GameState::default();
        current
            .inventory
            .push(create_test_item("sword_001", "Iron Sword", 1));

        let new = current.clone();

        let result = reconcile_pure(&current, &new, "");

        // No inventory changes should be detected
        let inventory_changes: Vec<_> = result
            .applied_changes
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    StateChange::ItemAdded { .. }
                        | StateChange::ItemRemoved { .. }
                        | StateChange::ItemQuantityChanged { .. }
                )
            })
            .collect();
        assert!(inventory_changes.is_empty());
    }

    // ========================================================================
    // Vitals Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_vitals_damage_applied() {
        let mut current = GameState::default();
        current
            .vitals
            .insert("health".to_string(), create_test_vital(100.0, 100.0));

        let mut new = GameState::default();
        new.vitals
            .insert("health".to_string(), create_test_vital(75.0, 100.0)); // -25 damage

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::VitalChanged { vital_name, old_value, new_value }
            if vital_name == "health" && (*old_value - 100.0).abs() < 0.01 && (*new_value - 75.0).abs() < 0.01
        )));
    }

    #[test]
    fn test_reconcile_vitals_healing_applied() {
        let mut current = GameState::default();
        current
            .vitals
            .insert("health".to_string(), create_test_vital(50.0, 100.0));

        let mut new = GameState::default();
        new.vitals
            .insert("health".to_string(), create_test_vital(80.0, 100.0)); // +30 heal

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::VitalChanged { vital_name, old_value, new_value }
            if vital_name == "health" && (*old_value - 50.0).abs() < 0.01 && (*new_value - 80.0).abs() < 0.01
        )));
    }

    #[test]
    fn test_reconcile_vitals_clamp_to_max() {
        let mut current = GameState::default();
        current
            .vitals
            .insert("health".to_string(), create_test_vital(100.0, 100.0));

        let mut new = GameState::default();
        new.vitals
            .insert("health".to_string(), create_test_vital(150.0, 100.0)); // Invalid: exceeds max

        let result = reconcile_pure(&current, &new, "");

        // Should clamp to max
        let final_health = result.final_state.vitals.get("health").unwrap();
        assert_eq!(final_health.current, 100.0);
    }

    #[test]
    fn test_reconcile_vitals_clamp_to_zero() {
        let mut current = GameState::default();
        current
            .vitals
            .insert("health".to_string(), create_test_vital(10.0, 100.0));

        let mut new = GameState::default();
        new.vitals
            .insert("health".to_string(), create_test_vital(-10.0, 100.0)); // Invalid: negative

        let result = reconcile_pure(&current, &new, "");

        let final_health = result.final_state.vitals.get("health").unwrap();
        assert_eq!(final_health.current, 0.0);
    }

    #[test]
    fn test_reconcile_vitals_new_vital_added() {
        let current = GameState::default();

        let mut new = GameState::default();
        new.vitals
            .insert("mana".to_string(), create_test_vital(50.0, 100.0));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::VitalChanged { vital_name, old_value, new_value }
            if vital_name == "mana" && *old_value == 0.0 && (*new_value - 50.0).abs() < 0.01
        )));
        assert!(result.final_state.vitals.contains_key("mana"));
    }

    // ========================================================================
    // Quest Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_quest_status_active_to_completed() {
        let mut current = GameState::default();
        current.quests.push(create_test_quest(
            "quest_001",
            "Find the Artifact",
            QuestStatus::Active,
        ));

        let mut new = GameState::default();
        new.quests.push(create_test_quest(
            "quest_001",
            "Find the Artifact",
            QuestStatus::Completed,
        ));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::QuestStatusChanged {
                quest_id,
                old_status: QuestStatus::Active,
                new_status: QuestStatus::Completed,
            } if quest_id == "quest_001"
        )));
    }

    #[test]
    fn test_reconcile_quest_added() {
        let current = GameState::default();

        let mut new = GameState::default();
        new.quests.push(create_test_quest(
            "quest_002",
            "Rescue the Princess",
            QuestStatus::Active,
        ));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::QuestAdded { quest } if quest.id == "quest_002"
        )));
    }

    #[test]
    fn test_reconcile_quest_failed() {
        let mut current = GameState::default();
        current.quests.push(create_test_quest(
            "quest_003",
            "Protect the Village",
            QuestStatus::Active,
        ));

        let mut new = GameState::default();
        new.quests.push(create_test_quest(
            "quest_003",
            "Protect the Village",
            QuestStatus::Failed,
        ));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::QuestStatusChanged {
                quest_id,
                old_status: QuestStatus::Active,
                new_status: QuestStatus::Failed,
            } if quest_id == "quest_003"
        )));
    }

    // ========================================================================
    // Location Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_location_change() {
        let mut current = GameState::default();
        current.location = Some(create_test_location("tavern_001", "The Rusty Anchor"));

        let mut new = GameState::default();
        new.location = Some(create_test_location("forest_001", "Dark Forest"));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::LocationChanged { old_location, new_location }
            if old_location.as_ref().map(|s| s.as_str()) == Some("The Rusty Anchor")
                && new_location == "Dark Forest"
        )));
    }

    #[test]
    fn test_reconcile_location_from_none() {
        let current = GameState::default(); // No location

        let mut new = GameState::default();
        new.location = Some(create_test_location("town_001", "Starting Town"));

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::LocationChanged { old_location: None, new_location }
            if new_location == "Starting Town"
        )));
    }

    // ========================================================================
    // Time Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_time_advanced() {
        let mut current = GameState::default();
        current.game_time = Some(GameTime {
            day: 1,
            hour: 10,
            minute: 0,
            second: 0,
            period: "morning".to_string(),
            season: Some("spring".to_string()),
            total_seconds_elapsed: 36000,
            calendar_system: "Earth".to_string(),
            date: "2025-01-01".to_string(),
            weekday: None,
        });

        let mut new = GameState::default();
        new.game_time = Some(GameTime {
            day: 1,
            hour: 14,
            minute: 0,
            second: 0,
            period: "afternoon".to_string(),
            season: Some("spring".to_string()),
            total_seconds_elapsed: 50400,
            calendar_system: "Earth".to_string(),
            date: "2025-01-01".to_string(),
            weekday: None,
        });

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::TimeAdvanced { old_time: Some(_), new_time }
            if new_time.hour == 14 && new_time.period == "afternoon" && new_time.total_seconds_elapsed == 50400
        )));
    }

    #[test]
    fn test_reconcile_time_monotonic() {
        let mut current = GameState::default();
        current.game_time = Some(GameTime {
            day: 1,
            hour: 10,
            minute: 0,
            second: 0,
            period: "morning".to_string(),
            season: Some("spring".to_string()),
            total_seconds_elapsed: 36000,
            calendar_system: "Earth".to_string(),
            date: "2025-01-01".to_string(),
            weekday: None,
        });

        let mut new = GameState::default();
        new.game_time = Some(GameTime {
            day: 1,
            hour: 9, // LLM hallucinated a time decrease
            minute: 0,
            second: 0,
            period: "morning".to_string(),
            season: Some("spring".to_string()),
            total_seconds_elapsed: 32400, // Decrease!
            calendar_system: "Earth".to_string(),
            date: "2025-01-01".to_string(),
            weekday: None,
        });

        let result = reconcile_pure(&current, &new, "");

        // Should have clamped total_seconds_elapsed to current
        if let Some(StateChange::TimeAdvanced { new_time, .. }) = result
            .applied_changes
            .iter()
            .find(|c| matches!(c, StateChange::TimeAdvanced { .. }))
        {
            assert_eq!(new_time.total_seconds_elapsed, 36000);
        } else {
            panic!("TimeAdvanced change not found");
        }
    }

    // ========================================================================
    // NPC Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_npc_disposition_change() {
        let mut current = GameState::default();
        current.npcs.insert(
            "npc_001".to_string(),
            NpcState {
                id: "npc_001".to_string(),
                name: "Friendly Merchant".to_string(),
                location: None,
                disposition: "friendly".to_string(),
                status: "alive".to_string(),
                role: "Merchant".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let mut new = GameState::default();
        new.npcs.insert(
            "npc_001".to_string(),
            NpcState {
                id: "npc_001".to_string(),
                name: "Friendly Merchant".to_string(),
                location: None,
                disposition: "hostile".to_string(), // Changed!
                status: "alive".to_string(),
                role: "Merchant".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::NpcChanged { npc_id, change }
            if npc_id == "npc_001" && change.contains("disposition")
        )));
    }

    #[test]
    fn test_reconcile_npc_added() {
        let current = GameState::default();

        let mut new = GameState::default();
        new.npcs.insert(
            "npc_002".to_string(),
            NpcState {
                id: "npc_002".to_string(),
                name: "New Character".to_string(),
                location: None,
                disposition: "neutral".to_string(),
                status: "alive".to_string(),
                role: "Unknown".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::NpcChanged { npc_id, change }
            if npc_id == "npc_002" && change == "added"
        )));
    }

    // ========================================================================
    // Environment Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_environment_weather_change() {
        let mut current = GameState::default();
        current.environment.weather = Some("sunny".to_string());

        let mut new = GameState::default();
        new.environment.weather = Some("rainy".to_string());

        let result = reconcile_pure(&current, &new, "");

        assert!(result.applied_changes.iter().any(|c| matches!(
            c,
            StateChange::EnvironmentChanged { field, new_value }
            if field == "weather" && new_value == "rainy"
        )));
    }

    // ========================================================================
    // Complex Multi-Change Reconciliation Tests
    // ========================================================================

    #[test]
    fn test_reconcile_multiple_simultaneous_changes() {
        let mut current = GameState::default();
        current.location = Some(create_test_location("dungeon_01", "Dark Dungeon"));
        current
            .vitals
            .insert("health".to_string(), create_test_vital(100.0, 100.0));
        current
            .inventory
            .push(create_test_item("torch_001", "Torch", 1));

        let mut new = GameState::default();
        new.location = Some(create_test_location("dungeon_02", "Deeper Dungeon"));
        new.vitals
            .insert("health".to_string(), create_test_vital(80.0, 100.0)); // took damage
        new.inventory
            .push(create_test_item("key_001", "Golden Key", 1)); // found key
                                                                 // torch is gone (used up)

        let result = reconcile_pure(&current, &new, "");

        // Should have: location change, health change, item removed (torch), item added (key)
        assert!(result.applied_changes.len() >= 4);

        // Verify specific changes
        assert!(result
            .applied_changes
            .iter()
            .any(|c| matches!(c, StateChange::LocationChanged { .. })));
        assert!(result.applied_changes.iter().any(
            |c| matches!(c, StateChange::VitalChanged { vital_name, .. } if vital_name == "health")
        ));
        assert!(result
            .applied_changes
            .iter()
            .any(|c| matches!(c, StateChange::ItemRemoved { item_id } if item_id == "torch_001")));
        assert!(result
            .applied_changes
            .iter()
            .any(|c| matches!(c, StateChange::ItemAdded { item } if item.id == "key_001")));
    }

    #[test]
    fn test_reconcile_no_changes_returns_empty() {
        let mut state = GameState::default();
        state.location = Some(create_test_location("home", "Player's Home"));
        state
            .vitals
            .insert("health".to_string(), create_test_vital(100.0, 100.0));

        let current_state = state;
        let new_state = current_state.clone();
        let result = reconcile_pure(&current_state, &new_state, "");

        assert!(result.applied_changes.is_empty());
        assert!(result.rejected_changes.is_empty());
    }

    #[test]
    fn test_last_turn_changes_persistence() {
        let current = GameState::default();
        let mut new = GameState::default();

        // Add an item in the new state
        new.inventory.push(InventoryItem {
            id: "gold_coin".to_string(),
            name: "Gold Coin".to_string(),
            quantity: 50,
            description: None,
            category: Some("Currency".to_string()),
            equipped: false,
            properties: HashMap::new(),
            staleness_count: 0,
        });

        let result = reconcile_pure(&current, &new, "Found some gold");

        // Verify changes were applied
        assert_eq!(result.applied_changes.len(), 1);

        // Verify custom_data contains the summary
        assert!(result
            .final_state
            .custom_data
            .contains_key("last_turn_changes"));
        let summary = result
            .final_state
            .custom_data
            .get("last_turn_changes")
            .unwrap()
            .as_str()
            .unwrap();

        assert!(summary.contains("Added item: Gold Coin (x50)"));
    }
}
