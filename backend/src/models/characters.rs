// backend/src/models/characters.rs
use crate::schema::characters;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{NaiveDateTime, DateTime};
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
    pub creation_date: Option<NaiveDateTime>,
    pub modification_date: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = characters)]
pub struct NewCharacter {
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub scenario: Option<String>,
    pub system_prompt: Option<String>,
    pub spec: Option<String>,
    pub spec_version: Option<String>,
    pub creator_notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<String>>,
    pub nickname: Option<String>,
    pub source: Option<Vec<String>>,
    pub group_only_greetings: Option<Vec<String>>,
    pub creation_date: Option<NaiveDateTime>,
    pub modification_date: Option<NaiveDateTime>,
}

// Helper to create NewCharacter from ParsedCharacterCard
impl NewCharacter {
    pub fn from_parsed_card(parsed_card: &ParsedCharacterCard, user_id: Uuid) -> Self {
        match parsed_card {
            ParsedCharacterCard::V3(card_v3) => {
                let map_string_owned = |s: &String| -> Option<String> {
                    if s.is_empty() { None } else { Some(s.clone()) }
                };
                let map_vec_owned = |v: &Vec<String>| -> Option<Vec<String>> {
                    let mapped: Vec<String> = v.iter()
                                                .filter(|s| !s.is_empty())
                                                .map(|s| s.clone())
                                                .collect();
                    if mapped.is_empty() { None } else { Some(mapped) }
                };

                NewCharacter {
                    user_id,
                    name: card_v3.data.name.clone().unwrap_or_default(),
                    description: map_string_owned(&card_v3.data.description),
                    personality: map_string_owned(&card_v3.data.personality),
                    first_mes: map_string_owned(&card_v3.data.first_mes),
                    mes_example: map_string_owned(&card_v3.data.mes_example),
                    scenario: map_string_owned(&card_v3.data.scenario),
                    system_prompt: map_string_owned(&card_v3.data.system_prompt),
                    spec: Some(card_v3.spec.clone()),
                    spec_version: Some(card_v3.spec_version.clone()),
                    creator_notes: map_string_owned(&card_v3.data.creator_notes),
                    tags: map_vec_owned(&card_v3.data.tags),
                    creator: map_string_owned(&card_v3.data.creator),
                    character_version: map_string_owned(&card_v3.data.character_version),
                    alternate_greetings: map_vec_owned(&card_v3.data.alternate_greetings),
                    nickname: card_v3.data.nickname.clone(),
                    source: map_vec_owned(&card_v3.data.source.clone().unwrap_or_default()),
                    group_only_greetings: map_vec_owned(&card_v3.data.group_only_greetings),
                    creation_date: card_v3.data.creation_date.map(|ts| DateTime::from_timestamp(ts, 0).map(|dt| dt.naive_utc())).flatten(),
                    modification_date: card_v3.data.modification_date.map(|ts| DateTime::from_timestamp(ts, 0).map(|dt| dt.naive_utc())).flatten(),
                }
            }
            ParsedCharacterCard::V2Fallback(data_v2) => {
                let map_string_owned = |s: &String| -> Option<String> {
                    if s.is_empty() { None } else { Some(s.clone()) }
                };
                let map_vec_owned = |v: &Vec<String>| -> Option<Vec<String>> {
                    let mapped: Vec<String> = v.iter()
                                                .filter(|s| !s.is_empty())
                                                .map(|s| s.clone())
                                                .collect();
                    if mapped.is_empty() { None } else { Some(mapped) }
                };

                NewCharacter {
                    user_id,
                    name: data_v2.name.clone().unwrap_or_default(),
                    description: map_string_owned(&data_v2.description),
                    personality: map_string_owned(&data_v2.personality),
                    first_mes: map_string_owned(&data_v2.first_mes),
                    mes_example: map_string_owned(&data_v2.mes_example),
                    scenario: map_string_owned(&data_v2.scenario),
                    system_prompt: map_string_owned(&data_v2.system_prompt),
                    spec: None,
                    spec_version: None,
                    creator_notes: map_string_owned(&data_v2.creator_notes),
                    tags: map_vec_owned(&data_v2.tags),
                    creator: map_string_owned(&data_v2.creator),
                    character_version: map_string_owned(&data_v2.character_version),
                    alternate_greetings: map_vec_owned(&data_v2.alternate_greetings),
                    nickname: data_v2.nickname.clone(),
                    source: map_vec_owned(&data_v2.source.clone().unwrap_or_default()),
                    group_only_greetings: map_vec_owned(&data_v2.group_only_greetings),
                    creation_date: data_v2.creation_date.map(|ts| DateTime::from_timestamp(ts, 0).map(|dt| dt.naive_utc())).flatten(),
                    modification_date: data_v2.modification_date.map(|ts| DateTime::from_timestamp(ts, 0).map(|dt| dt.naive_utc())).flatten(),
                }
            }
        }
    }
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