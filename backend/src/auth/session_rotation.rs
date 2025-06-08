use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Utc};
use tower_sessions::Session;
use tracing::{debug, error, warn};

const SESSION_ROTATION_INTERVAL_HOURS: i64 = 1; // Rotate sessions every hour
const LAST_ROTATION_KEY: &str = "last_rotation";

/// Middleware that rotates session IDs periodically to enhance security
pub async fn session_rotation_middleware(
    session: Session,
    request: Request,
    next: Next,
) -> Response {
    // Check if session needs rotation based on time
    if should_rotate_session(&session).await {
        match rotate_session_if_needed(&session).await {
            Ok(rotated) => {
                if rotated {
                    debug!(session_id = ?session.id(), "Session ID rotated due to periodic rotation");
                }
            }
            Err(e) => {
                error!(session_id = ?session.id(), error = ?e, "Failed to rotate session during periodic check");
                // Continue with request even if rotation fails - don't break user experience
            }
        }
    }

    next.run(request).await
}

/// Check if a session should be rotated based on time since last rotation
async fn should_rotate_session(session: &Session) -> bool {
    // Don't rotate empty sessions or sessions without IDs
    if session.is_empty().await || session.id().is_none() {
        return false;
    }

    match get_last_rotation_time(session).await {
        Ok(Some(last_rotation)) => {
            let now = Utc::now();
            let hours_since_rotation = (now - last_rotation).num_hours();
            
            debug!(
                session_id = ?session.id(),
                hours_since_rotation = hours_since_rotation,
                "Checking if session needs rotation"
            );

            hours_since_rotation >= SESSION_ROTATION_INTERVAL_HOURS
        }
        Ok(None) => {
            // No last rotation time recorded, set it now and don't rotate
            if let Err(e) = set_last_rotation_time(session, Utc::now()).await {
                warn!(session_id = ?session.id(), error = ?e, "Failed to set initial rotation time");
            }
            false
        }
        Err(e) => {
            warn!(session_id = ?session.id(), error = ?e, "Failed to get last rotation time");
            false
        }
    }
}

/// Rotate the session ID and update the last rotation time
async fn rotate_session_if_needed(session: &Session) -> Result<bool, tower_sessions::session::Error> {
    // Cycle the session ID
    session.cycle_id().await?;
    
    // Update the last rotation time
    set_last_rotation_time(session, Utc::now()).await?;
    
    // Save the session to ensure changes are persisted
    session.save().await?;
    
    Ok(true)
}

/// Get the last rotation time from the session
async fn get_last_rotation_time(session: &Session) -> Result<Option<DateTime<Utc>>, tower_sessions::session::Error> {
    match session.get::<String>(LAST_ROTATION_KEY).await? {
        Some(time_str) => {
            match DateTime::parse_from_rfc3339(&time_str) {
                Ok(dt) => Ok(Some(dt.with_timezone(&Utc))),
                Err(e) => {
                    warn!(session_id = ?session.id(), error = ?e, "Failed to parse last rotation time");
                    Ok(None)
                }
            }
        }
        None => Ok(None),
    }
}

/// Set the last rotation time in the session
async fn set_last_rotation_time(session: &Session, time: DateTime<Utc>) -> Result<(), tower_sessions::session::Error> {
    let time_str = time.to_rfc3339();
    session.insert(LAST_ROTATION_KEY, time_str).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    async fn test_should_rotate_session_no_last_rotation() {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        
        // Should not rotate a session without last rotation time
        assert!(!should_rotate_session(&session).await);
    }

    #[tokio::test]
    async fn test_should_rotate_session_recent_rotation() {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        
        // Set a recent rotation time (30 minutes ago)
        let recent_time = Utc::now() - chrono::Duration::minutes(30);
        set_last_rotation_time(&session, recent_time).await.unwrap();
        
        // Should not rotate because it's too recent
        assert!(!should_rotate_session(&session).await);
    }

    #[tokio::test]
    async fn test_should_rotate_session_old_rotation() {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        
        // Set an old rotation time (2 hours ago)
        let old_time = Utc::now() - chrono::Duration::hours(2);
        set_last_rotation_time(&session, old_time).await.unwrap();
        
        // Should rotate because it's been more than 1 hour
        assert!(should_rotate_session(&session).await);
    }

    #[tokio::test]
    async fn test_rotate_session_if_needed() {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        
        // Force a session ID to be created
        session.insert("test", "value").await.unwrap();
        let original_id = session.id();
        
        // Rotate the session
        let rotated = rotate_session_if_needed(&session).await.unwrap();
        assert!(rotated);
        
        // Session ID should be different
        assert_ne!(original_id, session.id());
        
        // Last rotation time should be set
        let last_rotation = get_last_rotation_time(&session).await.unwrap();
        assert!(last_rotation.is_some());
    }
}