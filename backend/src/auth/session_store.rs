// Directly reference the crate
// extern crate axum_login;

use crate::schema::sessions;
use async_trait::async_trait;
// use axum_login::AuthSessionStore;
// use axum_login::AuthUser;
// use axum_login::AuthSession;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
// use secrecy::{ExposeSecret, SecretString};
use std::fmt::{self, Debug};
// use std::marker::PhantomData;
use crate::state::DbPool; // Import DbPool type alias
use axum_login::tower_sessions::{
    SessionStore,
    session::{Id, Record}, // Use tower_sessions::session types
    session_store,
};
use chrono::{DateTime, Utc}; // Use chrono DateTime
use serde_json;
use time::OffsetDateTime;
use tracing::{debug, error, info, instrument};

// --- Session Data Struct ---
// This mirrors the table structure in schema.rs for the sessions table
#[derive(Queryable, Insertable, AsChangeset, Identifiable, Debug, Clone)]
#[diesel(table_name = sessions)]
#[diesel(primary_key(id))] // Explicitly define primary key if not id by convention
pub struct SessionRecord {
    pub id: String, // Keep as String to match DB schema (Text)
    // Use chrono::DateTime<Utc> for TIMESTAMPTZ
    pub expires: Option<DateTime<Utc>>,
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
    fn map_diesel_error(e: &DieselError) -> session_store::Error {
        error!(error = ?e, "Diesel operation failed");
        match e {
            DieselError::NotFound => {
                session_store::Error::Backend("Session record not found in DB".into())
            }
            _ => session_store::Error::Backend(e.to_string()),
        }
    }

    // Helper to convert Deadpool pool error to session_store::Error
    fn map_pool_error(e: &deadpool_diesel::PoolError) -> session_store::Error {
        error!(error = ?e, "Failed to get connection from pool");
        session_store::Error::Backend(e.to_string())
    }

    // Helper to convert Interact error to session_store::Error
    fn map_interact_error(e: &deadpool_diesel::InteractError) -> session_store::Error {
        error!(error = ?e, "Interact error during DB operation");
        session_store::Error::Backend(e.to_string())
    }

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

        let metadata_result = pool
            .get()
            .await
            .map_err(|e| Self::map_pool_error(&e))?
            .interact(move |conn| {
                sessions::table
                    .select((sessions::id, sessions::expires))
                    .load::<(String, Option<DateTime<Utc>>)>(conn) // Load ID as String from DB
                    .map(|rows| {
                        rows.into_iter()
                            .map(|(id, expires)| SessionMetadata { id, expires })
                            .collect::<Vec<_>>()
                    })
                    .map_err(|e| Self::map_diesel_error(&e))
            })
            .await
            .map_err(|e| Self::map_interact_error(&e));

        // Log the result
        match &metadata_result {
            Ok(Ok(metadata)) => info!(
                count = metadata.len(),
                "Successfully retrieved session metadata"
            ),
            Ok(Err(e)) => error!(error = ?e, "Failed to retrieve session metadata (Diesel error)"),
            Err(e) => error!(error = ?e, "Failed to retrieve session metadata (Interact error)"),
        }

        // Flatten Result<Result<...>>
        metadata_result?
    }

    /// Deletes sessions that have expired based on their expiration timestamp
    ///
    /// This method is useful for cleaning up old sessions without accessing their content
    #[allow(dead_code)]
    #[instrument(skip(self), err)]
    async fn delete_expired_sessions(&self) -> Result<usize, session_store::Error> {
        info!("DieselSessionStore::delete_expired_sessions ENTERED");

        let pool = self.pool.clone();
        let now = Utc::now();

        debug!(now = %now, "Attempting to delete expired sessions...");

        let delete_result = pool
            .get()
            .await
            .map_err(|e| Self::map_pool_error(&e))?
            .interact(move |conn| {
                diesel::delete(
                    sessions::table
                        .filter(sessions::expires.lt(now).or(sessions::expires.is_null())),
                )
                .execute(conn)
                .map_err(|e| Self::map_diesel_error(&e))
            })
            .await
            .map_err(|e| Self::map_interact_error(&e));

        // Log the result
        match &delete_result {
            Ok(Ok(count)) => info!(
                deleted_count = count,
                "Successfully deleted expired sessions"
            ),
            Ok(Err(e)) => error!(error = ?e, "Failed to delete expired sessions (Diesel error)"),
            Err(e) => error!(error = ?e, "Failed to delete expired sessions (Interact error)"),
        }

        // Flatten Result<Result<...>>
        delete_result?
    }
}

// Helper function to convert time::OffsetDateTime to chrono::DateTime<Utc>
#[must_use]
pub fn offset_to_utc(offset_dt: Option<OffsetDateTime>) -> Option<DateTime<Utc>> {
    // Made pub
    offset_dt.and_then(|dt| DateTime::from_timestamp(dt.unix_timestamp(), 0))
}

// Helper function to convert chrono::DateTime<Utc> to time::OffsetDateTime
fn utc_to_offset(utc_dt: Option<DateTime<Utc>>) -> Option<OffsetDateTime> {
    utc_dt.and_then(|dt| OffsetDateTime::from_unix_timestamp(dt.timestamp()).ok())
}

/// Session metadata structure that includes only non-sensitive data
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub id: String, // Keep as String to match DB schema
    pub expires: Option<DateTime<Utc>>,
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
        let save_result = pool
            .get()
            .await
            .map_err(|e| Self::map_pool_error(&e))?
            .interact(move |conn| {
                // Use insert + on_conflict_do_update (upsert)
                diesel::insert_into(sessions::table)
                    .values(&record)
                    .on_conflict(sessions::id)
                    .do_update()
                    .set((
                        sessions::expires.eq(&record.expires),
                        sessions::session.eq(&record.session),
                    ))
                    .execute(conn)
                    .map_err(|e| Self::map_diesel_error(&e))
            })
            .await
            .map_err(|e| Self::map_interact_error(&e));

        // --- Added Log ---
        match &save_result {
            Ok(Ok(rows_affected)) => {
                debug!(session_id = %session.id, %rows_affected, "DB interact for session save successful.");
            }
            Ok(Err(e)) => {
                error!(session_id = %session.id, error = ?e, "DB interact for session save failed (Diesel error).");
            }
            Err(e) => {
                error!(session_id = %session.id, error = ?e, "DB interact for session save failed (Interact error).");
            }
        }

        let final_result = save_result?.map(|_| ()); // Flatten Result<Result<...>> and discard row count

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

        let maybe_db_record = pool // Renamed to maybe_db_record to avoid confusion with session::Record
            .get()
            .await
            .map_err(|e| Self::map_pool_error(&e))?
            .interact(move |conn| {
                // Move the clone into the closure
                sessions::table
                    .find(&session_id_clone_for_closure) // Use the String clone here
                    .first::<SessionRecord>(conn) // Load as SessionRecord (DB representation)
                    .optional() // Handle not found gracefully within Diesel
                    .map_err(|e| Self::map_diesel_error(&e))
            })
            .await
            .map_err(|e| Self::map_interact_error(&e))??; // Flatten Result<Result<...>>

        if let Some(db_record) = maybe_db_record {
            // --- Log found ---
            // Use the original session_id_str for logging here
            debug!(session_id = %session_id_str, db_record_id = %db_record.id, db_record_expires = ?db_record.expires, "Session record found in DB. Deserializing session data string..."); // Removed db_session_string

            // Deserialize the db_record.session (JSON string) into HashMap<String, String> or appropriate type for session.data
            // tower_sessions::Record expects session.data to be HashMap<String, Value> where Value is usually String for JSON.
            // For axum-login, the user is typically serialized into a specific key.
            let session_data_map: std::collections::HashMap<String, serde_json::Value> =
                serde_json::from_str(&db_record.session).map_err(|e| Self::map_json_error(&e))?;

            // --- Log the deserialized session.data HashMap ---
            debug!(session_id = %session_id_str, deserialized_session_data_keys = ?session_data_map.keys().collect::<Vec<_>>(), "DieselSessionStore::load: deserialized session.data keys from DB string");

            let mut session_record_for_tower = Record {
                // Construct tower_sessions::Record
                id: *session_id,                        // Use original Id
                data: session_data_map,                 // Assign deserialized map
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
        let delete_result = pool
            .get()
            .await
            .map_err(|e| Self::map_pool_error(&e))?
            .interact(move |conn| {
                diesel::delete(sessions::table.find(session_id_str)) // Use String value
                    .execute(conn)
                    .map_err(|e| Self::map_diesel_error(&e))
            })
            .await
            .map_err(|e| Self::map_interact_error(&e));

        // --- Added Log ---
        match &delete_result {
            Ok(Ok(rows_affected)) => {
                info!(session_id = %session_id, %rows_affected, "DB interact for session delete successful.");
            }
            Ok(Err(e)) => {
                error!(session_id = %session_id, error = ?e, "DB interact for session delete failed (Diesel error).");
            }
            Err(e) => {
                error!(session_id = %session_id, error = ?e, "DB interact for session delete failed (Interact error).");
            }
        }

        delete_result?.map(|_| ()) // Flatten Result<Result<...>> and discard row count
    }
}
