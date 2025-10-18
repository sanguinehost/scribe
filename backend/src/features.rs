//! Feature detection module for build-time feature flag checking
//!
//! This module provides utilities to detect which features are enabled at compile time.

/// Returns true if the desktop feature is enabled
pub fn is_desktop_mode() -> bool {
    cfg!(feature = "desktop")
}

/// Returns true if the cloud feature is enabled
pub fn is_cloud_mode() -> bool {
    cfg!(feature = "cloud")
}

/// Returns true if SQLite backend is enabled
pub fn is_sqlite_backend() -> bool {
    cfg!(feature = "sqlite-backend")
}

/// Returns true if PostgreSQL backend is enabled
pub fn is_postgres_backend() -> bool {
    cfg!(feature = "postgres-backend")
}

/// Returns true if embedded vector store (LanceDB) is enabled
pub fn is_embedded_vector() -> bool {
    cfg!(feature = "embedded-vector")
}

/// Returns true if remote vector store (Qdrant) is enabled
pub fn is_remote_vector() -> bool {
    cfg!(feature = "remote-vector")
}

/// Returns a string describing the current feature configuration
pub fn feature_summary() -> String {
    let mut features = Vec::new();

    if is_desktop_mode() {
        features.push("desktop");
    }
    if is_cloud_mode() {
        features.push("cloud");
    }
    if is_sqlite_backend() {
        features.push("sqlite");
    }
    if is_postgres_backend() {
        features.push("postgres");
    }
    if is_embedded_vector() {
        features.push("lancedb");
    }
    if is_remote_vector() {
        features.push("qdrant");
    }

    if features.is_empty() {
        "no features enabled".to_string()
    } else {
        features.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_summary_returns_string() {
        // Just verify the function returns a non-empty string
        let summary = feature_summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_at_least_one_backend_enabled() {
        // Verify that at least one database backend is enabled
        assert!(
            is_sqlite_backend() || is_postgres_backend(),
            "At least one database backend must be enabled"
        );
    }

    #[test]
    fn test_at_least_one_vector_store_enabled() {
        // Verify that at least one vector store is enabled
        assert!(
            is_embedded_vector() || is_remote_vector(),
            "At least one vector store must be enabled"
        );
    }
}
