// backend/src/models/characters.rs
#![allow(dead_code)] // Allow dead code for fields not yet actively used
// use crate::schema::characters; // Removed unused import
// use crate::schema::users; // Removed unused import
use chrono::{DateTime, Utc}; // Removed unused NaiveDateTime
use diesel::prelude::*;
// use chrono::{DateTime, Utc, NaiveDateTime};
use serde::{Deserialize, Serialize};
// use serde_json::Value as JsonValue; // Removed unused import
use uuid::Uuid;
use crate::services::character_parser::ParsedCharacterCard;

#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = crate::schema::characters)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Character {
    pub id: Uuid,
    pub user_id: Uuid,
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<serde_json::Value>,
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Represents fields that can be updated from a parsed card
// Using Option<&'a str> allows updating only provided fields
// without allocating new Strings.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = crate::schema::characters)]
pub struct UpdatableCharacter<'a> {
    pub spec: Option<&'a str>,
    pub spec_version: Option<&'a str>,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub personality: Option<&'a str>,
    pub first_mes: Option<&'a str>,
    pub mes_example: Option<&'a str>,
    pub scenario: Option<&'a str>,
    pub system_prompt: Option<&'a str>,
    pub creator_notes: Option<&'a str>,
    // Use Vec<&'a str> for slices of strings
    pub tags: Option<Vec<&'a str>>,
    pub creator: Option<&'a str>,
    pub character_version: Option<&'a str>,
    pub alternate_greetings: Option<Vec<&'a str>>,
    // JSON needs separate handling, maybe Option<&'a Value>?
    // pub metadata_json: Option<&'a Value>, // Correct type?
    // Map other DB fields if needed
}

impl<'a> From<&'a ParsedCharacterCard> for UpdatableCharacter<'a> {
    fn from(parsed_card: &'a ParsedCharacterCard) -> Self {
        match parsed_card {
            ParsedCharacterCard::V3(card_v3) => {
                // Corrected map_string helper
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                // Corrected map_vec helper
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v.iter()
                                                .filter(|s| !s.is_empty())
                                                .map(|s| s.as_str()) // Use as_str()
                                                .collect(); // Compiler should infer Vec<&str>
                    if mapped.is_empty() { None } else { Some(mapped) }
                };

                Self {
                    spec: Some(&card_v3.spec),
                    spec_version: Some(&card_v3.spec_version),
                    name: card_v3.data.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_string(&card_v3.data.description),
                    personality: map_string(&card_v3.data.personality),
                    first_mes: map_string(&card_v3.data.first_mes),
                    mes_example: map_string(&card_v3.data.mes_example),
                    scenario: map_string(&card_v3.data.scenario),
                    system_prompt: map_string(&card_v3.data.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&card_v3.data.creator_notes),
                    tags: map_vec(&card_v3.data.tags),
                    creator: map_string(&card_v3.data.creator),
                    character_version: map_string(&card_v3.data.character_version),
                    alternate_greetings: map_vec(&card_v3.data.alternate_greetings),
                }
            }
            ParsedCharacterCard::V2Fallback(data_v2) => {
                let map_string = |s: &'a String| -> Option<&'a str> {
                     if s.is_empty() { None } else { Some(s.as_str()) }
                 };
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                      let mapped: Vec<&'a str> = v.iter()
                                                  .filter(|s| !s.is_empty())
                                                  .map(|s| s.as_str()) // Use as_str()
                                                  .collect();
                      if mapped.is_empty() { None } else { Some(mapped) }
                  };

                 Self {
                    spec: None,
                    spec_version: None,
                    name: data_v2.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_string(&data_v2.description),
                    personality: map_string(&data_v2.personality),
                    first_mes: map_string(&data_v2.first_mes),
                    mes_example: map_string(&data_v2.mes_example),
                    scenario: map_string(&data_v2.scenario),
                    system_prompt: map_string(&data_v2.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&data_v2.creator_notes),
                    tags: map_vec(&data_v2.tags),
                    creator: map_string(&data_v2.creator),
                    character_version: map_string(&data_v2.character_version),
                    alternate_greetings: map_vec(&data_v2.alternate_greetings),
                 }
            }
        }
    }
} 