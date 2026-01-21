use crate::schema::template_preferences;
use chrono::{DateTime, NaiveDateTime};
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone, Debug)]
#[diesel(table_name = template_preferences)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct TemplatePreference {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub template_id: Option<String>,

    // Narrative style variables
    pub tense: String,
    pub narration: String,
    pub perspective: String,
    pub length: String,

    // Optional enhancements for future use
    pub enable_info_box: bool,
    pub enable_stats_tracker: bool,
    pub enable_thinking: bool,

    // Timestamps
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = template_preferences)]
#[diesel(treat_none_as_null = true)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewTemplatePreference {
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub template_id: Option<String>,

    pub tense: String,
    pub narration: String,
    pub perspective: String,
    pub length: String,

    pub enable_info_box: bool,
    pub enable_stats_tracker: bool,
    pub enable_thinking: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateTemplatePreferenceRequest {
    pub template_id: Option<String>,

    pub tense: Option<String>,
    pub narration: Option<String>,
    pub perspective: Option<String>,
    pub length: Option<String>,

    pub enable_info_box: Option<bool>,
    pub enable_stats_tracker: Option<bool>,
    pub enable_thinking: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TemplatePreferenceResponse {
    pub template_id: Option<String>,

    pub tense: String,
    pub narration: String,
    pub perspective: String,
    pub length: String,

    pub enable_info_box: bool,
    pub enable_stats_tracker: bool,
    pub enable_thinking: bool,

    // Timestamps
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl From<TemplatePreference> for TemplatePreferenceResponse {
    fn from(pref: TemplatePreference) -> Self {
        Self {
            template_id: pref.template_id,
            tense: pref.tense,
            narration: pref.narration,
            perspective: pref.perspective,
            length: pref.length,
            enable_info_box: pref.enable_info_box,
            enable_stats_tracker: pref.enable_stats_tracker,
            enable_thinking: pref.enable_thinking,
            created_at: DateTime::from_naive_utc_and_offset(pref.created_at, chrono::Utc),
            updated_at: DateTime::from_naive_utc_and_offset(pref.updated_at, chrono::Utc),
        }
    }
}
