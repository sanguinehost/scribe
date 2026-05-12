// Directly reference the crate
// extern crate axum_login;

use crate::schema::sessions;
use async_trait::async_trait;
// use axum_login::AuthSessionStore;
// use axum_login::AuthUser;
// use axum_login::AuthSession;
use diesel::prelude::*;

// use secrecy::{ExposeSecret, SecretString};
use std::fmt::{self, Debug};
// use std::marker::PhantomData;
// Import backend-agnostic DateTime type
use crate::db::DbPool; // Use the DbPool type alias from our db.rs
use axum_login::tower_sessions::{
    session::{Id, Record}, // Use tower_sessions::session types
    session_store,
    SessionStore,
};
use chrono::DateTime; // Use chrono DateTime
use serde_json;
use time::OffsetDateTime;
use tracing::{debug, error, info, instrument};

// --- Session Data Struct ---
// This mirrors the table structure in schema.rs for the sessions table
#[derive(Queryable, Selectable, Insertable, AsChangeset, Identifiable, Debug, Clone)]
#[diesel(table_name = sessions)]
#[diesel(primary_key(id))] // Explicitly define primary key if not id by convention
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct SessionRecord {
    pub id: String, // Keep as String to match DB schema (Text)
    // Use chrono::DateTime<Utc> for TIMESTAMPTZ
    pub expires: Option<crate::db::DbTimestamp>,
    // Session data is likely stringified JSON or similar
    pub session: String,
}

// --- Diesel Session Store Implementation for tower-sessions ---
#[derive(Clone)]
pub struct DieselSessionStore {
    pool: DbPool, // Use the DbPool type alias from state.rs
}

// Manually implement Debug because DbPool (containing PgConnection) doesn't implement it.
impl Debug for DieselSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DieselSessionStore")
            // Avoid printing the pool itself
            .field("pool", &"<DbPool>")
            .finish()
    }
}

impl DieselSessionStore {
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // Helper to convert DieselError to session_store::Error
    // Note: tower-sessions expects Box<dyn std::error::Error + Send + Sync + 'static>

    // Helper to convert JSON error to session_store::Error
    fn map_json_error(e: &serde_json::Error) -> session_store::Error {
        error!(error = ?e, "Session JSON serialization/deserialization failed");
        session_store::Error::Decode(e.to_string()) // Use Decode variant for JSON errors
    }

    /// Gets a list of all session metadata (IDs and expiration times) without exposing session content
    ///
    /// This method is useful for administrative purposes such as monitoring session counts
    /// or trimming expired sessions, while maintaining user privacy by not exposing session data.
    #[allow(dead_code)]
    #[instrument(skip(self), err)]
    async fn get_session_metadata(&self) -> Result<Vec<SessionMetadata>, session_store::Error> {
        info!("DieselSessionStore::get_session_metadata ENTERED");

        let pool = self.pool.clone();
        debug!("Retrieving session metadata (IDs and expiration times only)...");

        let metadata_result = crate::db::with_conn(&pool, move |conn| {
            let result = sessions::table
                .select((sessions::id, sessions::expires))
                .load::<(String, Option<crate::db::DbTimestamp>)>(conn) // Load ID as String from DB
                .map(|rows| {
                    rows.into_iter()
                        .map(|(id, expires)| SessionMetadata { id, expires })
                        .collect::<Vec<_>>()
                })
                .map_err(|e| scribe_core::CoreError::Internal(e.to_string()))?;
            Ok(result)
        })
        .await;

        // Log the result
        match &metadata_result {
            Ok(metadata) => info!(
                count = metadata.len(),
                "Successfully retrieved session metadata"
            ),
            Err(e) => error!(error = ?e, "Failed to retrieve session metadata"),
        }

        metadata_result.map_err(|e| session_store::Error::Backend(e.to_string()))
    }

    /// Deletes sessions that have expired based on their expiration timestamp
    ///
    /// This method is useful for cleaning up old sessions without accessing their content
    #[allow(dead_code)]
    #[instrument(skip(self), err)]
    async fn delete_expired_sessions(&self) -> Result<usize, session_store::Error> {
        info!("DieselSessionStore::delete_expired_sessions ENTERED");

        let pool = self.pool.clone();

        debug!("Attempting to delete expired sessions...");

        let delete_result = crate::db::with_conn(&pool, move |conn| {
            let count = diesel::delete(
                sessions::table.filter(
                    sessions::expires
                        .lt(diesel::dsl::now)
                        .or(sessions::expires.is_null()),
                ),
            )
            .execute(conn)
            .map_err(|e| scribe_core::CoreError::Internal(e.to_string()))?;
            Ok(count)
        })
        .await;

        // Log the result
        match &delete_result {
            Ok(count) => info!(
                deleted_count = count,
                "Successfully deleted expired sessions"
            ),
            Err(e) => error!(error = ?e, "Failed to delete expired sessions"),
        }

        delete_result.map_err(|e| session_store::Error::Backend(e.to_string()))
    }
}

// Helper function to convert time::OffsetDateTime to chrono::DateTime<Utc>
#[must_use]
pub fn offset_to_utc(offset_dt: Option<OffsetDateTime>) -> Option<crate::db::DbTimestamp> {
    // Made pub
    offset_dt.and_then(|dt| DateTime::from_timestamp(dt.unix_timestamp(), 0).map(|dt| dt.into()))
}

// Helper function to convert chrono::DateTime<Utc> to time::OffsetDateTime
fn utc_to_offset(utc_dt: Option<crate::db::DbTimestamp>) -> Option<OffsetDateTime> {
    utc_dt.and_then(|dt| OffsetDateTime::from_unix_timestamp(dt.timestamp()).ok())
}

/// Session metadata structure that includes only non-sensitive data
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub id: String, // Keep as String to match DB schema
    pub expires: Option<crate::db::DbTimestamp>,
}

#[async_trait]
impl SessionStore for DieselSessionStore {
    #[instrument(skip(self, session), err)]
    async fn save(&self, session: &Record) -> session_store::Result<()> {
        info!(session_id = %session.id, ">>> DieselSessionStore::save ENTERED");

        // --- Add log right after entry ---
        debug!(session_id = %session.id, ">>> save method entered successfully.");

        // --- Log the full session.data HashMap ---
        debug!(session_id = %session.id, session_data_keys = ?session.data.keys().collect::<Vec<_>>(), "DieselSessionStore::save: current session.data keys before serialization");

        let session_data_json_string =
            serde_json::to_string(&session.data).map_err(|e| Self::map_json_error(&e))?; // Serialize session.data directly

        // Convert time::OffsetDateTime to chrono::DateTime<Utc>
        let expires_utc = offset_to_utc(Some(session.expiry_date));

        let record = SessionRecord {
            id: session.id.0.to_string(), // Convert i128 from Id to String for DB
            expires: expires_utc,
            session: session_data_json_string.clone(), // Clone session_data_json_string for logging
        };

        // --- Added Log ---
        debug!(session_id = %record.id, expires = ?record.expires, "Attempting to save session record to DB"); // Removed session_db_string

        let pool = self.pool.clone();
        let save_result = crate::db::with_conn(&pool, move |conn| {
            // Use insert + on_conflict_do_update (upsert)
            let rows_affected = diesel::insert_into(sessions::table)
                .values(&record)
                .on_conflict(sessions::id)
                .do_update()
                .set((
                    sessions::expires.eq(&record.expires),
                    sessions::session.eq(&record.session),
                ))
                .execute(conn)
                .map_err(|e| scribe_core::CoreError::Internal(e.to_string()))?;
            Ok(rows_affected)
        })
        .await;

        // --- Added Log ---
        match &save_result {
            Ok(rows_affected) => {
                debug!(session_id = %session.id, %rows_affected, "DB interact for session save successful.");
            }
            Err(e) => {
                error!(session_id = %session.id, error = ?e, "DB interact for session save failed.");
            }
        }

        let final_result = save_result
            .map(|_| ())
            .map_err(|e| session_store::Error::Backend(e.to_string())); // Discard row count

        // --- Add log before returning ---
        debug!(session_id = %session.id, result = ?final_result, ">>> save method attempting to return.");

        final_result
    }

    #[instrument(skip(self), err)]
    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let session_id_str = session_id.0.to_string(); // Convert i128 from Id to String for query
                                                       // --- Modified Log ---
        info!(session_id = %session_id_str, "DieselSessionStore::load ENTERED");

        let pool = self.pool.clone();
        // --- Log before interact ---
        debug!(session_id = %session_id_str, "Attempting to load session record from DB...");

        // Clone session_id_str *before* the closure
        let session_id_clone_for_closure = session_id_str.clone();

        let maybe_db_record = crate::db::with_conn(&pool, move |conn| {
            // Move the clone into the closure
            let result = sessions::table
                .find(&session_id_clone_for_closure) // Use the String clone here
                .first::<SessionRecord>(conn) // Load as SessionRecord (DB representation)
                .optional() // Handle not found gracefully within Diesel
                .map_err(|e| scribe_core::CoreError::Internal(e.to_string()))?;
            Ok(result)
        })
        .await
        .map_err(|e| session_store::Error::Backend(e.to_string()))?;

        if let Some(db_record) = maybe_db_record {
            // --- Log found ---
            // Use the original session_id_str for logging here
            debug!(session_id = %session_id_str, db_record_id = %db_record.id, db_record_expires = ?db_record.expires, "Session record found in DB. Deserializing session data string..."); // Removed db_session_string

            // Deserialize the db_record.session (JSON string) into HashMap<String, String> or appropriate type for session.data
            // tower_sessions::Record expects session.data to be HashMap<String, Value> where Value is usually String for JSON.
            // For axum-login, the user is typically serialized into a specific key.
            let session_data_map: std::collections::HashMap<String, crate::db::unified_types::DbJson> =
                serde_json::from_str(&db_record.session).map_err(|e| Self::map_json_error(&e))?;

            // --- Log the deserialized session.data HashMap ---
            debug!(session_id = %session_id_str, deserialized_session_data_keys = ?session_data_map.keys().collect::<Vec<_>>(), "DieselSessionStore::load: deserialized session.data keys from DB string");

            let mut session_record_for_tower = Record {
                // Construct tower_sessions::Record
                id: *session_id, // Use original Id
                data: session_data_map
                    .into_iter()
                    .map(|(k, v)| (k, v.0))
                    .collect(), // Convert DbJson to Value (SqliteJson → Value on SQLite)
                expiry_date: OffsetDateTime::now_utc(), // Placeholder, will be overwritten
            };

            // Convert chrono::DateTime<Utc> back to time::OffsetDateTime
            if let Some(expiry_offset) = utc_to_offset(db_record.expires) {
                session_record_for_tower.expiry_date = expiry_offset;

                // Check if the session is expired
                if session_record_for_tower.expiry_date <= OffsetDateTime::now_utc() {
                    // If expired based on OffsetDateTime, delete it and return None
                    // Use the original session_id_str for logging here
                    info!(session_id = %session_id_str, "Session loaded but expired, deleting.");
                    self.delete(session_id).await?;
                    Ok(None)
                } else {
                    // --- Log success ---
                    info!(session_id = %db_record.id, "Session loaded and deserialized successfully.");
                    Ok(Some(session_record_for_tower))
                }
            } else {
                // If expiry could not be converted (e.g., was NULL in DB and conversion failed),
                // treat as invalid/unloadable.
                error!(session_id = %session_id_str, "Session loaded but expiry date is invalid or missing from DB record, treating as unloadable.");
                // Delete the problematic session record.
                self.delete(session_id).await?;
                Ok(None)
            }
        } else {
            // --- Log not found ---
            debug!(session_id = %session_id_str, "Session record not found in DB.");
            Ok(None) // Session not found is not an error for load
        }
    }

    #[instrument(skip(self), err)]
    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        let session_id_str = session_id.0.to_string(); // Convert i128 from Id to String for query
                                                       // --- Modified Log ---
        info!(session_id = %session_id_str, "DieselSessionStore::delete ENTERED");

        let pool = self.pool.clone();
        // --- Log before interact ---
        debug!(session_id = %session_id_str, "Attempting to delete session record from DB...");
        let delete_result = crate::db::with_conn(&pool, move |conn| {
            let rows_affected = diesel::delete(sessions::table.find(session_id_str)) // Use String value
                .execute(conn)
                .map_err(|e| scribe_core::CoreError::Internal(e.to_string()))?;
            Ok(rows_affected)
        })
        .await;

        // --- Added Log ---
        match &delete_result {
            Ok(rows_affected) => {
                info!(session_id = %session_id, %rows_affected, "DB interact for session delete successful.");
            }
            Err(e) => {
                error!(session_id = %session_id, error = ?e, "DB interact for session delete failed.");
            }
        }

        delete_result
            .map(|_| ())
            .map_err(|e| session_store::Error::Backend(e.to_string())) // Discard row count
    }
}
