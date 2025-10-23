use crate::db::DbId;
use crate::db::DbTimestamp;
use chrono::Utc;
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

// Document model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = crate::schema::old_documents)]
#[diesel(primary_key(id, created_at))]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct Document {
    pub id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: crate::db::DbId,
}

impl std::fmt::Debug for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Document")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("title", &self.title)
            .field("content", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("user_id", &self.user_id)
            .finish()
    }
}

// New Document for insertion
#[derive(Insertable)]
#[diesel(table_name = crate::schema::old_documents)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewDocument {
    pub id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: crate::db::DbId,
}

impl std::fmt::Debug for NewDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDocument")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("title", &self.title)
            .field("content", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("user_id", &self.user_id)
            .finish()
    }
}

// Suggestion model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = crate::schema::old_suggestions)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct Suggestion {
    pub id: crate::db::DbId,
    pub document_id: crate::db::DbId,
    pub document_created_at: DbTimestamp,
    pub original_text: String,
    pub suggested_text: String,
    #[diesel(sql_type = Nullable<diesel::sql_types::Text>)] // Re-added explicit SQL type
    pub description: Option<String>,
    pub is_resolved: bool,
    pub user_id: crate::db::DbId,
    pub created_at: DbTimestamp,
}

impl std::fmt::Debug for Suggestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Suggestion")
            .field("id", &self.id)
            .field("document_id", &self.document_id)
            .field("document_created_at", &self.document_created_at)
            .field("original_text", &"[REDACTED]")
            .field("suggested_text", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("is_resolved", &self.is_resolved)
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// New Suggestion for insertion
#[derive(Insertable)]
#[diesel(table_name = crate::schema::old_suggestions)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    feature = "sqlite-backend",
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewSuggestion {
    pub id: crate::db::DbId,
    pub document_id: crate::db::DbId,
    pub document_created_at: DbTimestamp,
    pub original_text: String,
    pub suggested_text: String,
    pub description: Option<String>,
    pub is_resolved: bool,
    pub user_id: crate::db::DbId,
    pub created_at: DbTimestamp,
}

impl std::fmt::Debug for NewSuggestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSuggestion")
            .field("id", &self.id)
            .field("document_id", &self.document_id)
            .field("document_created_at", &self.document_created_at)
            .field("original_text", &"[REDACTED]")
            .field("suggested_text", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("is_resolved", &self.is_resolved)
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// Request/Response DTOs
#[derive(Deserialize)]
pub struct CreateDocumentRequest {
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
}

impl std::fmt::Debug for CreateDocumentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateDocumentRequest")
            .field("title", &self.title)
            .field("content", &"[REDACTED]")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Serialize)]
pub struct DocumentResponse {
    pub id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: crate::db::DbId,
}

impl std::fmt::Debug for DocumentResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentResponse")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("title", &self.title)
            .field("content", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct CreateSuggestionRequest {
    pub document_id: crate::db::DbId,
    pub document_created_at: DbTimestamp,
    pub original_text: String,
    pub suggested_text: String,
    pub description: Option<String>,
}

impl std::fmt::Debug for CreateSuggestionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateSuggestionRequest")
            .field("document_id", &self.document_id)
            .field("document_created_at", &self.document_created_at)
            .field("original_text", &"[REDACTED]")
            .field("suggested_text", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .finish()
    }
}
