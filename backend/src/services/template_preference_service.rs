use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
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

            let existing = query
                .select(TemplatePreference::as_select())
                .first::<TemplatePreference>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            info!(%user_id, ?character_id, found = existing.is_some(), "GET: Query result");

            match existing {
                Some(prefs) => {
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

                    // Create default preferences
                    let new_prefs = NewTemplatePreference {
                        user_id,
                        character_id,
                        template_id: None,
                        tense: "past-tense".to_string(),
                        narration: "third-person".to_string(),
                        perspective: "omniscient".to_string(),
                        length: "flexible".to_string(),
                        enable_info_box: false,
                        enable_stats_tracker: false,
                        enable_thinking: false,
                    };

                    #[cfg(feature = "postgres-backend")]
                    let created = {
                        diesel::insert_into(template_preferences::table)
                            .values(&new_prefs)
                            .get_result::<TemplatePreference>(conn)
                            .map_err(map_diesel_error)?
                    };

                    #[cfg(feature = "sqlite-backend")]
                    let created = {
                        use diesel::prelude::*;
                        let user_id_clone = new_prefs.user_id;
                        let character_id_clone = new_prefs.character_id;

                        diesel::insert_into(template_preferences::table)
                            .values(&new_prefs)
                            .execute(conn)
                            .map_err(map_diesel_error)?;

                        // Query back using unique constraint (user_id, character_id)
                        template_preferences::table
                            .filter(template_preferences::user_id.eq(user_id_clone))
                            .filter(template_preferences::character_id.eq(character_id_clone))
                            .select(TemplatePreference::as_select())
                            .first::<TemplatePreference>(conn)
                            .map_err(map_diesel_error)?
                    };

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

            let existing = query
                .select(TemplatePreference::as_select())
                .first::<TemplatePreference>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Get or create the existing preferences
            let existing_prefs = match existing {
                Some(prefs) => prefs,
                None => {
                    // Create defaults WITH the update request values instead of hardcoded defaults
                    let new_prefs = NewTemplatePreference {
                        user_id,
                        character_id,
                        template_id: update_request.template_id.clone(),
                        tense: update_request
                            .tense
                            .clone()
                            .unwrap_or_else(|| "past-tense".to_string()),
                        narration: update_request
                            .narration
                            .clone()
                            .unwrap_or_else(|| "third-person".to_string()),
                        perspective: update_request
                            .perspective
                            .clone()
                            .unwrap_or_else(|| "omniscient".to_string()),
                        length: update_request
                            .length
                            .clone()
                            .unwrap_or_else(|| "flexible".to_string()),
                        enable_info_box: update_request.enable_info_box.unwrap_or(false),
                        enable_stats_tracker: update_request.enable_stats_tracker.unwrap_or(false),
                        enable_thinking: update_request.enable_thinking.unwrap_or(false),
                    };

                    // Insert with the requested values, no need to UPDATE after
                    #[cfg(feature = "postgres-backend")]
                    let created = {
                        diesel::insert_into(template_preferences::table)
                            .values(&new_prefs)
                            .get_result::<TemplatePreference>(conn)
                            .map_err(map_diesel_error)?
                    };

                    #[cfg(feature = "sqlite-backend")]
                    let created = {
                        use diesel::prelude::*;
                        let user_id_clone = new_prefs.user_id;
                        let character_id_clone = new_prefs.character_id;

                        diesel::insert_into(template_preferences::table)
                            .values(&new_prefs)
                            .execute(conn)
                            .map_err(map_diesel_error)?;

                        // Query back using unique constraint (user_id, character_id)
                        template_preferences::table
                            .filter(template_preferences::user_id.eq(user_id_clone))
                            .filter(template_preferences::character_id.eq(character_id_clone))
                            .select(TemplatePreference::as_select())
                            .first::<TemplatePreference>(conn)
                            .map_err(map_diesel_error)?
                    };

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

            // Retrieve updated preferences
            let updated = template_preferences::table
                .filter(template_preferences::id.eq(existing_prefs.id))
                .select(TemplatePreference::as_select())
                .first::<TemplatePreference>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

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
