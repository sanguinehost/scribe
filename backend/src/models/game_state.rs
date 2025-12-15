//! Game State models for the Game Master Agent.
//!
//! These structures represent the complete game world state that is managed
//! by the Sidecar agent and reconciled by the backend.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete game state, stored as JSON in the `chat_sessions.game_state` column.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GameState {
    /// Current location of the player
    pub location: Option<Location>,
    /// In-game time (narrative time, not real time)
    pub game_time: Option<GameTime>,
    /// Player's inventory
    pub inventory: Vec<InventoryItem>,
    /// Player's vital statistics (health, mana, stamina, etc.)
    pub vitals: HashMap<String, Vital>,
    /// Active and completed quests
    pub quests: Vec<Quest>,
    /// NPC states (disposition, location, status)
    pub npcs: HashMap<String, NpcState>,
    /// Environmental conditions and tags
    pub environment: EnvironmentState,
    /// Custom key-value data for game-specific state
    pub custom_data: HashMap<String, serde_json::Value>,
}

/// Represents a location in the game world.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Location {
    /// Unique identifier for the location
    pub id: String,
    /// Display name
    pub name: String,
    /// Optional description (can be string or object)
    pub description: Option<serde_json::Value>,
    /// Parent region/area (for hierarchical locations)
    pub region: Option<String>,
    /// Tags for semantic search and rules lookup
    pub tags: Vec<String>,
}

/// In-game time representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameTime {
    /// Day number (1-indexed)
    pub day: u32,
    /// Hour (0-23)
    pub hour: u8,
    /// Time of day descriptor (dawn, morning, noon, afternoon, dusk, evening, night)
    pub period: String,
    /// Optional season
    pub season: Option<String>,
}

/// An item in the player's inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryItem {
    /// Unique identifier for the item
    pub id: String,
    /// Display name
    pub name: String,
    /// Quantity (for stackable items)
    pub quantity: u32,
    /// Optional description
    pub description: Option<serde_json::Value>,
    /// Item category (weapon, armor, consumable, quest, misc)
    pub category: Option<String>,
    /// Whether the item is currently equipped
    pub equipped: bool,
    /// Custom properties (durability, enchantments, etc.)
    pub properties: HashMap<String, serde_json::Value>,
}

/// A vital statistic (health, mana, stamina, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vital {
    /// Current value
    pub current: f64,
    /// Maximum value
    pub max: f64,
    /// Optional: regeneration rate per game-time unit
    pub regen_rate: Option<f64>,
    /// Status effects affecting this vital (e.g., "poisoned", "blessed")
    pub modifiers: Vec<String>,
}

/// A quest or objective.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Quest {
    /// Unique identifier
    pub id: String,
    /// Quest title
    pub title: String,
    /// Current status
    pub status: QuestStatus,
    /// Description or objective text
    pub description: Option<serde_json::Value>,
    /// Sub-objectives or steps
    pub objectives: Vec<QuestObjective>,
    /// NPC who gave the quest
    pub giver: Option<String>,
    /// Rewards (textual description or structured data)
    pub rewards: Option<serde_json::Value>,
}

/// Quest status enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum QuestStatus {
    #[default]
    Active,
    Completed,
    Failed,
    Abandoned,
}

/// A sub-objective within a quest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuestObjective {
    /// Description of the objective
    pub description: String,
    /// Whether this objective is complete
    pub completed: bool,
    /// Optional progress (e.g., "3/5 wolves killed")
    pub progress: Option<serde_json::Value>,
}

/// State of an NPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpcState {
    /// NPC's unique identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Current location (location ID)
    pub location: Option<String>,
    /// Disposition towards player (hostile, neutral, friendly, allied)
    pub disposition: String,
    /// Current status (alive, dead, unconscious, absent)
    pub status: String,
    /// Active objectives or goals (for "Director" pattern)
    pub objectives: Vec<String>,
    /// Custom data
    pub data: HashMap<String, serde_json::Value>,
}

/// Environmental conditions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentState {
    /// Weather condition
    pub weather: Option<String>,
    /// Lighting level (bright, dim, dark)
    pub lighting: Option<String>,
    /// Temperature descriptor
    pub temperature: Option<String>,
    /// Active environmental hazards
    pub hazards: Vec<String>,
    /// Tags for semantic matching
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_state_serialization() {
        let state = GameState {
            location: Some(Location {
                id: "tavern_001".to_string(),
                name: "The Rusty Anchor".to_string(),
                description: Some(serde_json::json!("A cozy tavern by the docks")),
                region: Some("Harbor District".to_string()),
                tags: vec!["indoor".to_string(), "safe".to_string()],
            }),
            game_time: Some(GameTime {
                day: 3,
                hour: 21,
                period: "night".to_string(),
                season: Some("autumn".to_string()),
            }),
            inventory: vec![InventoryItem {
                id: "sword_001".to_string(),
                name: "Iron Sword".to_string(),
                quantity: 1,
                description: Some(serde_json::json!("A well-worn blade")),
                category: Some("weapon".to_string()),
                equipped: true,
                properties: HashMap::new(),
            }],
            vitals: {
                let mut v = HashMap::new();
                v.insert(
                    "health".to_string(),
                    Vital {
                        current: 85.0,
                        max: 100.0,
                        regen_rate: Some(1.0),
                        modifiers: vec![],
                    },
                );
                v
            },
            quests: vec![Quest {
                id: "quest_001".to_string(),
                title: "Find the Lost Heirloom".to_string(),
                status: QuestStatus::Active,
                description: Some(serde_json::json!(
                    "Retrieve the family ring from the old mine"
                )),
                objectives: vec![QuestObjective {
                    description: "Enter the abandoned mine".to_string(),
                    completed: false,
                    progress: None,
                }],
                giver: Some("Old Man Jenkins".to_string()),
                rewards: Some(serde_json::json!("50 gold, Family's gratitude")),
            }],
            npcs: HashMap::new(),
            environment: EnvironmentState {
                weather: Some("rainy".to_string()),
                lighting: Some("dim".to_string()),
                temperature: Some("cool".to_string()),
                hazards: vec![],
                tags: vec!["atmospheric".to_string()],
            },
            custom_data: HashMap::new(),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state).expect("Failed to serialize");
        assert!(json.contains("The Rusty Anchor"));
        assert!(json.contains("Iron Sword"));

        // Deserialize back
        let deserialized: GameState = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_default_game_state() {
        let state = GameState::default();
        assert!(state.location.is_none());
        assert!(state.inventory.is_empty());
        assert!(state.vitals.is_empty());
        assert!(state.quests.is_empty());
    }
}
