use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::sql_query;
use tracing::{info, instrument, warn};

use crate::{
    errors::AppError,
    models::template_preferences::{
        NewTemplatePreference, TemplatePreference, TemplatePreferenceResponse,
        UpdateTemplatePreferenceRequest,
    },
    schema::template_preferences,
    state::DbPool,
};

/// Helper function to convert Diesel errors to AppError with FK constraint detection
fn map_diesel_error(e: DieselError) -> AppError {
    match e {
        DieselError::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, _) => {
            AppError::BadRequest("Cannot create preferences for non-existent character".to_string())
        }
        _ => AppError::DatabaseQueryError(e.to_string()),
    }
}

/// Helper function to convert tuple to TemplatePreference
fn tuple_to_template_preference(
    tuple: (
        crate::db::DbId,
        crate::db::DbId,
        Option<crate::db::DbId>,
        Option<String>,
        String,
        String,
        String,
        String,
        bool,
        bool,
        bool,
        chrono::NaiveDateTime,
        chrono::NaiveDateTime,
    ),
) -> TemplatePreference {
    TemplatePreference {
        id: tuple.0,
        user_id: tuple.1,
        character_id: tuple.2,
        template_id: tuple.3,
        tense: tuple.4,
        narration: tuple.5,
        perspective: tuple.6,
        length: tuple.7,
        enable_info_box: tuple.8,
        enable_stats_tracker: tuple.9,
        enable_thinking: tuple.10,
        created_at: tuple.11,
        updated_at: tuple.12,
    }
}

pub struct TemplatePreferenceService;

impl TemplatePreferenceService {
    /// Gets template preferences for a specific user and optional character.
    /// If character_id is None, returns user's default preferences.
    /// Creates default preferences if none exist.
    #[instrument(skip(pool), err)]
    pub async fn get_template_preferences(
        pool: &DbPool,
        user_id: crate::db::DbId,
        character_id: Option<crate::db::DbId>,
    ) -> Result<TemplatePreferenceResponse, AppError> {
        crate::db::with_conn(pool, move |conn| {
            info!(%user_id, ?character_id, "GET: Looking for template preferences");

            // Try to find existing preferences for this user+character combination
            // Use .is_null() for None and .eq() for Some(uuid) to properly handle NULLs in Diesel
            let mut query = template_preferences::table
                .filter(template_preferences::user_id.eq(user_id))
                .into_boxed();

            match character_id {
                Some(char_id) => {
                    query = query.filter(template_preferences::character_id.eq(char_id));
                }
                None => {
                    query = query.filter(template_preferences::character_id.is_null());
                }
            }

            // Use manual tuple selection instead of .as_select() for SQLite compatibility
            let existing = query
                .select((
                    template_preferences::id,
                    template_preferences::user_id,
                    template_preferences::character_id,
                    template_preferences::template_id,
                    template_preferences::tense,
                    template_preferences::narration,
                    template_preferences::perspective,
                    template_preferences::length,
                    template_preferences::enable_info_box,
                    template_preferences::enable_stats_tracker,
                    template_preferences::enable_thinking,
                    template_preferences::created_at,
                    template_preferences::updated_at,
                ))
                .first::<(
                    crate::db::DbId,
                    crate::db::DbId,
                    Option<crate::db::DbId>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                    bool,
                    bool,
                    chrono::NaiveDateTime,
                    chrono::NaiveDateTime,
                )>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            info!(%user_id, ?character_id, found = existing.is_some(), "GET: Query result");

            match existing {
                Some(tuple) => {
                    let prefs = tuple_to_template_preference(tuple);
                    info!(
                        %user_id, ?character_id,
                        tense = %prefs.tense,
                        narration = %prefs.narration,
                        "GET: Found existing template preferences"
                    );
                    Ok(TemplatePreferenceResponse::from(prefs))
                }
                None => {
                    info!(%user_id, ?character_id, "GET: No template preferences found, creating defaults");

                    // Generate ID for the new template_preferences record
                    let preference_id = crate::db::DbId::new();

                    // Create default preferences
                    let tense = "past-tense".to_string();
                    let narration = "third-person".to_string();
                    let perspective = "omniscient".to_string();
                    let length = "flexible".to_string();
                    let enable_info_box = false;
                    let enable_stats_tracker = false;
                    let enable_thinking = false;
                    let now = chrono::Utc::now().naive_utc();

                    // Insert with raw SQL to explicitly set ID field (SQLite doesn't support DEFAULT uuid_generate_v4())
                    let query = sql_query(
                        r#"
                        INSERT INTO template_preferences (
                            id, user_id, character_id, template_id, tense, narration,
                            perspective, length, enable_info_box, enable_stats_tracker,
                            enable_thinking, created_at, updated_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                        "#,
                    );

                    #[cfg(feature = "postgres-backend")]
                    let query = query
                        .bind::<diesel::sql_types::Uuid, _>(preference_id)
                        .bind::<diesel::sql_types::Uuid, _>(user_id)
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(character_id);

                    #[cfg(feature = "sqlite-backend")]
                    let query = query
                        .bind::<diesel::sql_types::Text, _>(preference_id)
                        .bind::<diesel::sql_types::Text, _>(user_id)
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(character_id);

                    let query = query
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(None::<String>) // template_id
                        .bind::<diesel::sql_types::Text, _>(&tense)
                        .bind::<diesel::sql_types::Text, _>(&narration)
                        .bind::<diesel::sql_types::Text, _>(&perspective)
                        .bind::<diesel::sql_types::Text, _>(&length)
                        .bind::<diesel::sql_types::Bool, _>(enable_info_box)
                        .bind::<diesel::sql_types::Bool, _>(enable_stats_tracker)
                        .bind::<diesel::sql_types::Bool, _>(enable_thinking)
                        .bind::<diesel::sql_types::Timestamp, _>(now)
                        .bind::<diesel::sql_types::Timestamp, _>(now);

                    query.execute(conn).map_err(map_diesel_error)?;

                    // Query back using the known ID
                    let tuple = template_preferences::table
                        .filter(template_preferences::id.eq(preference_id))
                        .select((
                            template_preferences::id,
                            template_preferences::user_id,
                            template_preferences::character_id,
                            template_preferences::template_id,
                            template_preferences::tense,
                            template_preferences::narration,
                            template_preferences::perspective,
                            template_preferences::length,
                            template_preferences::enable_info_box,
                            template_preferences::enable_stats_tracker,
                            template_preferences::enable_thinking,
                            template_preferences::created_at,
                            template_preferences::updated_at,
                        ))
                        .first::<(
                            crate::db::DbId,
                            crate::db::DbId,
                            Option<crate::db::DbId>,
                            Option<String>,
                            String,
                            String,
                            String,
                            String,
                            bool,
                            bool,
                            bool,
                            chrono::NaiveDateTime,
                            chrono::NaiveDateTime,
                        )>(conn)
                        .map_err(map_diesel_error)?;

                    let created = tuple_to_template_preference(tuple);

                    info!(%user_id, ?character_id, "Created default template preferences");
                    Ok(TemplatePreferenceResponse::from(created))
                }
            }
        })
        .await
    }

    /// Updates template preferences for a specific user and optional character.
    /// Creates default preferences if none exist, then updates them.
    #[instrument(skip(pool), err)]
    pub async fn update_template_preferences(
        pool: &DbPool,
        user_id: crate::db::DbId,
        character_id: Option<crate::db::DbId>,
        update_request: UpdateTemplatePreferenceRequest,
    ) -> Result<TemplatePreferenceResponse, AppError> {
        crate::db::with_conn(pool, move |conn| {
            // Find or create preferences
            // Use .is_null() for None and .eq() for Some(uuid) to properly handle NULLs in Diesel
            let mut query = template_preferences::table
                .filter(template_preferences::user_id.eq(user_id))
                .into_boxed();

            match character_id {
                Some(char_id) => {
                    query = query.filter(template_preferences::character_id.eq(char_id));
                }
                None => {
                    query = query.filter(template_preferences::character_id.is_null());
                }
            }

            // Use manual tuple selection instead of .as_select() for SQLite compatibility
            let existing = query
                .select((
                    template_preferences::id,
                    template_preferences::user_id,
                    template_preferences::character_id,
                    template_preferences::template_id,
                    template_preferences::tense,
                    template_preferences::narration,
                    template_preferences::perspective,
                    template_preferences::length,
                    template_preferences::enable_info_box,
                    template_preferences::enable_stats_tracker,
                    template_preferences::enable_thinking,
                    template_preferences::created_at,
                    template_preferences::updated_at,
                ))
                .first::<(
                    crate::db::DbId,
                    crate::db::DbId,
                    Option<crate::db::DbId>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                    bool,
                    bool,
                    chrono::NaiveDateTime,
                    chrono::NaiveDateTime,
                )>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Get or create the existing preferences
            let existing_prefs = match existing {
                Some(tuple) => tuple_to_template_preference(tuple),
                None => {
                    // Generate ID for the new template_preferences record
                    let preference_id = crate::db::DbId::new();

                    // Create defaults WITH the update request values instead of hardcoded defaults
                    let template_id = update_request.template_id.clone();
                    let tense = update_request
                        .tense
                        .clone()
                        .unwrap_or_else(|| "past-tense".to_string());
                    let narration = update_request
                        .narration
                        .clone()
                        .unwrap_or_else(|| "third-person".to_string());
                    let perspective = update_request
                        .perspective
                        .clone()
                        .unwrap_or_else(|| "omniscient".to_string());
                    let length = update_request
                        .length
                        .clone()
                        .unwrap_or_else(|| "flexible".to_string());
                    let enable_info_box = update_request.enable_info_box.unwrap_or(false);
                    let enable_stats_tracker = update_request.enable_stats_tracker.unwrap_or(false);
                    let enable_thinking = update_request.enable_thinking.unwrap_or(false);
                    let now = chrono::Utc::now().naive_utc();

                    // Insert with raw SQL to explicitly set ID field (SQLite doesn't support DEFAULT uuid_generate_v4())
                    let query = sql_query(
                        r#"
                        INSERT INTO template_preferences (
                            id, user_id, character_id, template_id, tense, narration,
                            perspective, length, enable_info_box, enable_stats_tracker,
                            enable_thinking, created_at, updated_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                        "#,
                    );

                    #[cfg(feature = "postgres-backend")]
                    let query = query
                        .bind::<diesel::sql_types::Uuid, _>(preference_id)
                        .bind::<diesel::sql_types::Uuid, _>(user_id)
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(
                            character_id,
                        );

                    #[cfg(feature = "sqlite-backend")]
                    let query = query
                        .bind::<diesel::sql_types::Text, _>(preference_id)
                        .bind::<diesel::sql_types::Text, _>(user_id)
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                            character_id,
                        );

                    let query = query
                        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                            template_id,
                        )
                        .bind::<diesel::sql_types::Text, _>(&tense)
                        .bind::<diesel::sql_types::Text, _>(&narration)
                        .bind::<diesel::sql_types::Text, _>(&perspective)
                        .bind::<diesel::sql_types::Text, _>(&length)
                        .bind::<diesel::sql_types::Bool, _>(enable_info_box)
                        .bind::<diesel::sql_types::Bool, _>(enable_stats_tracker)
                        .bind::<diesel::sql_types::Bool, _>(enable_thinking)
                        .bind::<diesel::sql_types::Timestamp, _>(now)
                        .bind::<diesel::sql_types::Timestamp, _>(now);

                    query.execute(conn).map_err(map_diesel_error)?;

                    // Query back using the known ID
                    let tuple = template_preferences::table
                        .filter(template_preferences::id.eq(preference_id))
                        .select((
                            template_preferences::id,
                            template_preferences::user_id,
                            template_preferences::character_id,
                            template_preferences::template_id,
                            template_preferences::tense,
                            template_preferences::narration,
                            template_preferences::perspective,
                            template_preferences::length,
                            template_preferences::enable_info_box,
                            template_preferences::enable_stats_tracker,
                            template_preferences::enable_thinking,
                            template_preferences::created_at,
                            template_preferences::updated_at,
                        ))
                        .first::<(
                            crate::db::DbId,
                            crate::db::DbId,
                            Option<crate::db::DbId>,
                            Option<String>,
                            String,
                            String,
                            String,
                            String,
                            bool,
                            bool,
                            bool,
                            chrono::NaiveDateTime,
                            chrono::NaiveDateTime,
                        )>(conn)
                        .map_err(map_diesel_error)?;

                    let created = tuple_to_template_preference(tuple);

                    info!(
                        %user_id, ?character_id,
                        tense = %created.tense,
                        "Created template preferences with requested values"
                    );

                    // Return early - no need to UPDATE
                    return Ok(TemplatePreferenceResponse::from(created));
                }
            };

            // Apply updates to existing values (use existing values as defaults)
            let updated_template_id = update_request
                .template_id
                .or(existing_prefs.template_id.clone());
            let updated_tense = update_request
                .tense
                .unwrap_or_else(|| existing_prefs.tense.clone());
            let updated_narration = update_request
                .narration
                .unwrap_or_else(|| existing_prefs.narration.clone());
            let updated_perspective = update_request
                .perspective
                .unwrap_or_else(|| existing_prefs.perspective.clone());
            let updated_length = update_request
                .length
                .unwrap_or_else(|| existing_prefs.length.clone());
            let updated_enable_info_box = update_request
                .enable_info_box
                .unwrap_or(existing_prefs.enable_info_box);
            let updated_enable_stats_tracker = update_request
                .enable_stats_tracker
                .unwrap_or(existing_prefs.enable_stats_tracker);
            let updated_enable_thinking = update_request
                .enable_thinking
                .unwrap_or(existing_prefs.enable_thinking);

            info!(
                %user_id, ?character_id,
                ?updated_template_id, %updated_tense, %updated_narration,
                "About to update template preferences"
            );

            // Update all fields at once
            let rows_affected = diesel::update(
                template_preferences::table.filter(template_preferences::id.eq(existing_prefs.id)),
            )
            .set((
                template_preferences::template_id.eq(&updated_template_id),
                template_preferences::tense.eq(&updated_tense),
                template_preferences::narration.eq(&updated_narration),
                template_preferences::perspective.eq(&updated_perspective),
                template_preferences::length.eq(&updated_length),
                template_preferences::enable_info_box.eq(updated_enable_info_box),
                template_preferences::enable_stats_tracker.eq(updated_enable_stats_tracker),
                template_preferences::enable_thinking.eq(updated_enable_thinking),
            ))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            info!(%user_id, ?character_id, rows_affected, "Updated template preferences in DB");

            // Retrieve updated preferences using manual tuple selection
            let tuple = template_preferences::table
                .filter(template_preferences::id.eq(existing_prefs.id))
                .select((
                    template_preferences::id,
                    template_preferences::user_id,
                    template_preferences::character_id,
                    template_preferences::template_id,
                    template_preferences::tense,
                    template_preferences::narration,
                    template_preferences::perspective,
                    template_preferences::length,
                    template_preferences::enable_info_box,
                    template_preferences::enable_stats_tracker,
                    template_preferences::enable_thinking,
                    template_preferences::created_at,
                    template_preferences::updated_at,
                ))
                .first::<(
                    crate::db::DbId,
                    crate::db::DbId,
                    Option<crate::db::DbId>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                    bool,
                    bool,
                    chrono::NaiveDateTime,
                    chrono::NaiveDateTime,
                )>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            let updated = tuple_to_template_preference(tuple);

            info!(
                %user_id, ?character_id,
                updated_tense = %updated.tense,
                updated_narration = %updated.narration,
                "Returning updated template preferences from service"
            );
            Ok(TemplatePreferenceResponse::from(updated))
        })
        .await
    }

    /// Deletes template preferences for a specific user and optional character.
    /// This resets to system defaults (preferences will be recreated on next access).
    #[instrument(skip(pool), err)]
    pub async fn delete_template_preferences(
        pool: &DbPool,
        user_id: crate::db::DbId,
        character_id: Option<crate::db::DbId>,
    ) -> Result<(), AppError> {
        crate::db::with_conn(pool, move |conn| {
            // Use .is_null() for None and .eq() for Some(uuid) to properly handle NULLs in Diesel
            let deleted_count = match character_id {
                Some(char_id) => diesel::delete(
                    template_preferences::table
                        .filter(template_preferences::user_id.eq(user_id))
                        .filter(template_preferences::character_id.eq(char_id)),
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?,
                None => diesel::delete(
                    template_preferences::table
                        .filter(template_preferences::user_id.eq(user_id))
                        .filter(template_preferences::character_id.is_null()),
                )
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?,
            };

            if deleted_count > 0 {
                info!(%user_id, ?character_id, deleted_count, "Deleted template preferences");
            } else {
                warn!(%user_id, ?character_id, "No template preferences found to delete");
            }

            Ok(())
        })
        .await
    }
}
