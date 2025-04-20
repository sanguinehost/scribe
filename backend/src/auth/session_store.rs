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
use tracing::{debug, error, info, instrument};
use crate::state::DbPool; // Import DbPool type alias
use axum_login::tower_sessions::{
    session::{Id, Record}, // Use tower_sessions::session types
    session_store, SessionStore,
};
use time::OffsetDateTime;

// --- Session Data Struct ---
// This mirrors the table structure in schema.rs for the sessions table
#[derive(Queryable, Insertable, AsChangeset, Identifiable, Debug, Clone)]
#[diesel(table_name = sessions)]
struct SessionRecord {
    id: String, // Session ID (PK)
    #[diesel(sql_type = diesel::sql_types::Timestamptz)] // Explicitly map to TIMESTAMPTZ
    expires: Option<OffsetDateTime>,
    session: String, // Serialized tower_sessions::session::Record data
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
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // Helper to convert DieselError to session_store::Error
    // Note: tower-sessions expects Box<dyn std::error::Error + Send + Sync + 'static>
    fn map_diesel_error(e: DieselError) -> session_store::Error {
        error!(error = ?e, "Diesel operation failed");
        match e {
            DieselError::NotFound => session_store::Error::Backend(
                "Session record not found in DB".into(), // Use Backend variant
            ),
            _ => session_store::Error::Backend(e.to_string()), // Ensure it's Boxed Error
        }
    }

    // Helper to convert Deadpool pool error to session_store::Error
    fn map_pool_error(e: deadpool_diesel::PoolError) -> session_store::Error {
         error!(error = ?e, "Failed to get connection from pool");
         session_store::Error::Backend(e.to_string()) // Ensure it's Boxed Error
    }

     // Helper to convert Interact error to session_store::Error
    fn map_interact_error(e: deadpool_diesel::InteractError) -> session_store::Error {
        error!(error = ?e, "Interact error during DB operation");
        session_store::Error::Backend(e.to_string()) // Ensure it's Boxed Error
    }

     // Helper to convert JSON error to session_store::Error
    fn map_json_error(e: serde_json::Error) -> session_store::Error {
        error!(error = ?e, "Session JSON serialization/deserialization failed");
        session_store::Error::Decode(e.to_string()) // Use Decode variant for JSON errors
    }
}

#[async_trait]
impl SessionStore for DieselSessionStore {
    #[instrument(skip(self, session), err)]
    async fn save(&self, session: &Record) -> session_store::Result<()> {
        info!(session_id = %session.id, ">>> DieselSessionStore::save ENTERED");

        // --- Add log right after entry ---
        debug!(session_id = %session.id, ">>> save method entered successfully.");

        let session_data = serde_json::to_string(session).map_err(Self::map_json_error)?;

        // Use session.expiry_date directly, as it's already Option<OffsetDateTime>
        let record = SessionRecord {
            id: session.id.to_string(),
            expires: Some(session.expiry_date),
            session: session_data.clone(), // Clone session_data for logging
        };

        // --- Added Log ---
        debug!(session_id = %record.id, expires = ?record.expires, session_data = %session_data, "Attempting to save session record to DB");

        let pool = self.pool.clone();
        let save_result = pool.get()
            .await.map_err(Self::map_pool_error)?
            .interact(move |conn| {
                // Use insert + on_conflict_do_update (upsert)
                diesel::insert_into(sessions::table)
                    .values(&record)
                    .on_conflict(sessions::id)
                    .do_update()
                    .set(&record) // AsChangeset updates all fields
                    .execute(conn)
                    // .map(|_| ()) // Discard row count - Keep result for logging
                    .map_err(Self::map_diesel_error)
            })
            .await.map_err(Self::map_interact_error);

        // --- Added Log ---
        match &save_result {
            Ok(Ok(rows_affected)) => debug!(session_id = %session.id, %rows_affected, "DB interact for session save successful."),
            Ok(Err(e)) => error!(session_id = %session.id, error = ?e, "DB interact for session save failed (Diesel error)."),
            Err(e) => error!(session_id = %session.id, error = ?e, "DB interact for session save failed (Interact error)."),
        }

        let final_result = save_result?.map(|_| ()); // Flatten Result<Result<...>> and discard row count

        // --- Add log before returning ---
        debug!(session_id = %session.id, result = ?final_result, ">>> save method attempting to return.");

        final_result
    }

    #[instrument(skip(self), err)]
    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let session_id_str = session_id.to_string();
        // --- Modified Log ---
        info!(session_id = %session_id_str, "DieselSessionStore::load ENTERED");

        let pool = self.pool.clone();
        // --- Log before interact ---
        debug!(session_id = %session_id_str, "Attempting to load session record from DB...");
        let maybe_record = pool.get()
            .await.map_err(Self::map_pool_error)?
            .interact(move |conn| {
                sessions::table
                    .find(&session_id_str) // Use reference here
                    .first::<SessionRecord>(conn)
                    .optional() // Handle not found gracefully within Diesel
                    .map_err(Self::map_diesel_error)
            })
            .await.map_err(Self::map_interact_error)??; // Flatten Result<Result<...>>

        match maybe_record {
            Some(record) => {
                // --- Log found --- 
                debug!(session_id = %record.id, "Session record found in DB. Deserializing...");
                let session_record = serde_json::from_str::<Record>(&record.session).map_err(Self::map_json_error)?;

                // tower-sessions handles expiration check internally based on loaded expiry_date
                // We just need to load and return the Record object.

                // Optional: Clean up expired sessions proactively if desired, but not required by trait.
                // if let Some(expires) = record.expires {
                //     if expires < Utc::now() {
                //          warn!(session_id = %record.id, "Loaded session appears expired based on DB time, but letting tower-sessions confirm.");
                //          // Could spawn a task to delete it, but might interfere with tower-sessions logic
                //     }
                // }
                // --- Log success --- 
                info!(session_id = %record.id, "Session loaded and deserialized successfully.");
                Ok(Some(session_record))
            }
            None => {
                // --- Log not found --- 
                debug!(session_id = %session_id, "Session record not found in DB.");
                Ok(None) // Session not found is not an error for load
            }
        }
    }

    #[instrument(skip(self), err)]
    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
         let session_id_str = session_id.to_string();
         // --- Modified Log --- 
         info!(session_id = %session_id_str, "DieselSessionStore::delete ENTERED");

         let pool = self.pool.clone();
         // --- Log before interact --- 
         debug!(session_id = %session_id_str, "Attempting to delete session record from DB...");
         let delete_result = pool.get()
             .await.map_err(Self::map_pool_error)?
             .interact(move |conn| {
                 diesel::delete(sessions::table.find(session_id_str))
                     .execute(conn)
                     // .map(|_| ()) // Discard result count - Keep for logging
                     .map_err(Self::map_diesel_error)
             })
             .await.map_err(Self::map_interact_error);
        
         // --- Added Log --- 
         match &delete_result {
            Ok(Ok(rows_affected)) => info!(session_id = %session_id, %rows_affected, "DB interact for session delete successful."),
            Ok(Err(e)) => error!(session_id = %session_id, error = ?e, "DB interact for session delete failed (Diesel error)."),
            Err(e) => error!(session_id = %session_id, error = ?e, "DB interact for session delete failed (Interact error)."),
        }

        delete_result?.map(|_| ()) // Flatten Result<Result<...>> and discard row count
    }
} 