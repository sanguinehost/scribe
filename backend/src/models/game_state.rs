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
    /// Player's inventory (items on person)
    #[serde(default)]
    pub inventory: Vec<InventoryItem>,
    /// Items stored at named locations (e.g., "Home" -> items, "Bank" -> items)
    #[serde(default)]
    pub inventory_stored: HashMap<String, Vec<InventoryItem>>,
    /// Major possessions (vehicles, property, etc.) - plaintext list
    #[serde(default)]
    pub assets: Vec<String>,
    /// Player's currencies (gold, credits, gems, etc.) - key is currency name, value is amount
    #[serde(default)]
    pub currencies: HashMap<String, i64>,
    /// Player's vital statistics (health, mana, stamina, etc.)
    #[serde(default)]
    pub vitals: HashMap<String, Vital>,
    /// Active and completed quests
    #[serde(default)]
    pub quests: Vec<Quest>,
    /// NPC states (disposition, location, status)
    #[serde(default)]
    pub npcs: HashMap<String, NpcState>,
    /// Environmental conditions and tags
    #[serde(default)]
    pub environment: EnvironmentState,
    /// Custom key-value data for game-specific state
    #[serde(default)]
    pub custom_data: HashMap<String, serde_json::Value>,
    /// Items explicitly removed by the AI (bypasses staleness tracking).
    /// Contains item IDs that should be immediately deleted from inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_items: Vec<String>,
    /// Configuration for the in-game calendar system.
    /// If None, a default Earth-like calendar is assumed.
    pub calendar_config: Option<CalendarConfig>,
}

/// Represents a location in the game world.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Location {
    /// Unique identifier for the location
    #[serde(default)]
    pub id: String,
    /// Display name
    #[serde(default)]
    pub name: String,
    /// Optional description (can be string or object)
    pub description: Option<serde_json::Value>,
    /// Parent region/area (for hierarchical locations)
    pub region: Option<String>,
    /// Tags for semantic search and rules lookup
    #[serde(default)]
    pub tags: Vec<String>,
}

/// In-game time representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameTime {
    /// Day number (1-indexed)
    #[serde(default)]
    pub day: u32,
    /// Hour (0-23)
    #[serde(default)]
    pub hour: u8,
    /// Minute (0-59)
    #[serde(default)]
    pub minute: u8,
    /// Second (0-59) - useful for combat-level granularity
    #[serde(default)]
    pub second: u8,
    /// Time of day descriptor (dawn, morning, noon, afternoon, dusk, evening, night)
    #[serde(default)]
    pub period: String,
    /// Optional season
    pub season: Option<String>,
    /// Total seconds elapsed since game start (primary source of truth)
    #[serde(default)]
    pub total_seconds_elapsed: u64,
    /// The calendar system being used (e.g., "Earth", "Fantasy", "Sci-Fi")
    #[serde(default)]
    pub calendar_system: String,
    /// Current date string (e.g., "2024-03-15" or "15th of Sun's Height")
    pub date: String,
    /// Current weekday (e.g., "Monday", "Fredas")
    pub weekday: Option<String>,
}

/// Configuration for a custom calendar system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalendarConfig {
    /// Name of the calendar system
    #[serde(default = "default_calendar_name")]
    pub name: String,
    #[serde(default = "default_60")]
    pub seconds_per_minute: u64,
    #[serde(default = "default_60")]
    pub minutes_per_hour: u64,
    #[serde(default = "default_24")]
    pub hours_per_day: u64,
    /// Days per month.
    #[serde(default = "default_days_per_month")]
    pub days_per_month: Vec<u32>,
    /// Month names
    #[serde(default = "default_month_names")]
    pub month_names: Vec<String>,
    /// Weekday names
    #[serde(default = "default_weekday_names")]
    pub weekday_names: Vec<String>,
}

fn default_calendar_name() -> String {
    "Earth".to_string()
}
fn default_60() -> u64 {
    60
}
fn default_24() -> u64 {
    24
}
fn default_days_per_month() -> Vec<u32> {
    vec![31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}
fn default_month_names() -> Vec<String> {
    vec![
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
fn default_weekday_names() -> Vec<String> {
    vec![
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl Default for CalendarConfig {
    fn default() -> Self {
        Self {
            name: default_calendar_name(),
            seconds_per_minute: default_60(),
            minutes_per_hour: default_60(),
            hours_per_day: default_24(),
            days_per_month: default_days_per_month(),
            month_names: default_month_names(),
            weekday_names: default_weekday_names(),
        }
    }
}

impl CalendarConfig {
    /// Derive a complete GameTime from total seconds elapsed.
    pub fn derive_time(&self, total_seconds: u64) -> GameTime {
        let mut remaining = total_seconds;

        let second = (remaining % self.seconds_per_minute) as u8;
        remaining /= self.seconds_per_minute;

        let minute = (remaining % self.minutes_per_hour) as u8;
        remaining /= self.minutes_per_hour;

        let hour = (remaining % self.hours_per_day) as u8;
        remaining /= self.hours_per_day;

        // remaining is now total days
        let total_days = remaining;
        let weekday = if !self.weekday_names.is_empty() {
            let day_of_week_index = (total_days % self.weekday_names.len() as u64) as usize;
            self.weekday_names.get(day_of_week_index).cloned()
        } else {
            None
        };

        // Calculate year and month
        let days_per_year: u64 = self.days_per_month.iter().map(|&d| d as u64).sum();
        let (year, mut day_of_year) = if days_per_year > 0 {
            (
                (total_days / days_per_year) as u32,
                total_days % days_per_year,
            )
        } else {
            (0, total_days)
        };

        let mut month_index = 0;
        let mut day_of_month = (day_of_year + 1) as u32; // Default if no months defined

        for (i, &days) in self.days_per_month.iter().enumerate() {
            if day_of_year < days as u64 {
                month_index = i;
                day_of_month = (day_of_year + 1) as u32; // 1-indexed
                break;
            }
            day_of_year -= days as u64;
        }

        let month_name = self.month_names.get(month_index).cloned();
        let date = match month_name {
            Some(m) => format!("Day {} of {}, Year {}", day_of_month, m, year + 1),
            None => format!("Day {}, Year {}", day_of_month, year + 1),
        };

        // Period logic
        let period = match hour {
            5..=7 => "dawn",
            8..=11 => "morning",
            12 => "noon",
            13..=16 => "afternoon",
            17..=19 => "dusk",
            20..=23 | 0..=4 => "night",
            _ => "unknown",
        }
        .to_string();

        GameTime {
            day: (total_days + 1) as u32,
            hour,
            minute,
            second,
            period,
            season: None, // Could be derived from month_index if needed
            total_seconds_elapsed: total_seconds,
            calendar_system: self.name.clone(),
            date,
            weekday,
        }
    }
}

/// An item in the player's inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryItem {
    /// Unique identifier for the item
    #[serde(default)]
    pub id: String,
    /// Display name
    #[serde(default)]
    pub name: String,
    /// Quantity (for stackable items)
    #[serde(default)]
    pub quantity: u32,
    /// Optional description
    pub description: Option<serde_json::Value>,
    /// Item category (weapon, armor, consumable, quest, misc)
    pub category: Option<String>,
    /// Whether the item is currently equipped
    #[serde(default)]
    pub equipped: bool,
    /// Custom properties (durability, enchantments, etc.)
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
    /// How many reconciliation cycles since this item was last referenced in narrative.
    /// Used for auto-cleanup of stale items. Increments each turn if AI doesn't include item.
    /// Items with staleness >= threshold are candidates for removal.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub staleness_count: u32,
}

/// Helper for serde skip_serializing_if
fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// A vital statistic (health, mana, stamina, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vital {
    /// Current value
    #[serde(default)]
    pub current: f64,
    /// Maximum value
    #[serde(default)]
    pub max: f64,
    /// Optional: regeneration rate per game-time unit
    pub regen_rate: Option<f64>,
    /// Status effects affecting this vital (e.g., "poisoned", "blessed")
    #[serde(default)]
    pub modifiers: Vec<String>,
}

/// A quest or objective.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Quest {
    /// Unique identifier
    #[serde(default)]
    pub id: String,
    /// Quest title
    #[serde(default)]
    pub title: String,
    /// Whether this is the main quest (vs optional/side quest)
    #[serde(default)]
    pub is_main: bool,
    /// Current status
    #[serde(default)]
    pub status: QuestStatus,
    /// Description or objective text
    pub description: Option<serde_json::Value>,
    /// Sub-objectives or steps
    #[serde(default)]
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
    /// Description of the objective (can be string or structured object)
    #[serde(default)]
    pub description: serde_json::Value,
    /// Whether this objective is complete
    #[serde(default)]
    pub completed: bool,
    /// Optional progress (e.g., "3/5 wolves killed")
    pub progress: Option<serde_json::Value>,
}

/// State of an NPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpcState {
    /// NPC's unique identifier
    #[serde(default)]
    pub id: String,
    /// Display name
    #[serde(default)]
    pub name: String,
    /// Current location (location ID)
    pub location: Option<String>,
    /// Disposition towards player (hostile, neutral, friendly, allied)
    #[serde(default)]
    pub disposition: String,
    /// Role or archetype (e.g., "Merchant", "Guard", "Villager")
    #[serde(default)]
    pub role: String,
    /// Current status (alive, dead, unconscious, absent)
    #[serde(default)]
    pub status: String,
    /// Detailed physical description
    #[serde(default)]
    pub description: Option<String>,
    /// Personality traits and behavioral notes
    #[serde(default)]
    pub personality: Option<String>,
    /// Whether this NPC is narratively important (persists in context even when absent)
    #[serde(default = "default_true")]
    pub is_important: bool,
    /// Active objectives or goals (for "Director" pattern)
    #[serde(default)]
    pub objectives: Vec<String>,
    /// Custom data bag for flexibility
    #[serde(default)]
    pub data: serde_json::Value,
}

fn default_true() -> bool {
    true
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
    #[serde(default)]
    pub hazards: Vec<String>,
    /// Tags for semantic matching
    #[serde(default)]
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_state_serialization() {
        let state = GameState {
            assets: vec![],
            currencies: HashMap::new(),
            inventory_stored: HashMap::new(),
            removed_items: vec![],
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
                minute: 30,
                second: 0,
                period: "night".to_string(),
                season: Some("autumn".to_string()),
                total_seconds_elapsed: 250200,
                calendar_system: "Earth".to_string(),
                date: "2025-01-03".to_string(),
                weekday: None,
            }),
            inventory: vec![InventoryItem {
                id: "sword_001".to_string(),
                name: "Iron Sword".to_string(),
                quantity: 1,
                description: Some(serde_json::json!("A well-worn blade")),
                category: Some("weapon".to_string()),
                equipped: true,
                properties: HashMap::new(),
                staleness_count: 0,
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
                    description: serde_json::json!("Enter the abandoned mine"),
                    completed: false,
                    progress: None,
                }],
                giver: Some("Old Man Jenkins".to_string()),
                rewards: Some(serde_json::json!("50 gold, Family's gratitude")),
                is_main: false,
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
            calendar_config: None,
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

    #[test]
    fn test_custom_calendar_derivation() {
        let config = CalendarConfig {
            name: "Aethelgard".to_string(),
            seconds_per_minute: 60,
            minutes_per_hour: 60,
            hours_per_day: 24,
            days_per_month: vec![30, 30, 30], // 3 months of 30 days
            month_names: vec!["Dawn".to_string(), "Noon".to_string(), "Dusk".to_string()],
            weekday_names: vec!["Sun".to_string(), "Moon".to_string()],
            ..Default::default()
        };

        // 1 day = 86400 seconds
        // Day 1, Year 1 = 0 seconds
        let time = config.derive_time(0);
        assert_eq!(time.day, 1);
        assert_eq!(time.date, "Day 1 of Dawn, Year 1");
        assert_eq!(time.weekday, Some("Sun".to_string()));

        // Day 31 = 30 * 86400 = 2592000 seconds
        // Should be Day 1 of Noon, Year 1
        let time = config.derive_time(2592000);
        assert_eq!(time.day, 31);
        assert_eq!(time.date, "Day 1 of Noon, Year 1");
        assert_eq!(time.weekday, Some("Sun".to_string())); // 30 is even, so 30 % 2 = 0

        // Day 91 = 90 * 86400 = 7776000 seconds
        // Should be Day 1 of Dawn, Year 2
        let time = config.derive_time(7776000);
        assert_eq!(time.day, 91);
        assert_eq!(time.date, "Day 1 of Dawn, Year 2");
    }
}
