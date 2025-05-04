use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Document model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = crate::schema::old_documents)] // Use old_documents
#[diesel(primary_key(id, created_at))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Document {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: Uuid,
}

// New Document for insertion
#[derive(Insertable, Debug)]
#[diesel(table_name = crate::schema::old_documents)] // Use old_documents
pub struct NewDocument {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: Uuid,
}

// Suggestion model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = crate::schema::old_suggestions)] // Use old_suggestions
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Suggestion {
    pub id: Uuid,
    pub document_id: Uuid,
    pub document_created_at: DateTime<Utc>,
    pub original_text: String,
    pub suggested_text: String,
    #[diesel(sql_type = Nullable<diesel::sql_types::Text>)] // Re-added explicit SQL type
    pub description: Option<String>,
    pub is_resolved: bool,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

// New Suggestion for insertion
#[derive(Insertable, Debug)]
#[diesel(table_name = crate::schema::old_suggestions)] // Use old_suggestions
pub struct NewSuggestion {
    pub id: Uuid,
    pub document_id: Uuid,
    pub document_created_at: DateTime<Utc>,
    pub original_text: String,
    pub suggested_text: String,
    pub description: Option<String>,
    pub is_resolved: bool,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

// Request/Response DTOs
#[derive(Deserialize, Debug)]
pub struct CreateDocumentRequest {
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
}

#[derive(Serialize, Debug)]
pub struct DocumentResponse {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub title: String,
    pub content: Option<String>,
    pub kind: String,
    pub user_id: Uuid,
}

#[derive(Deserialize, Debug)]
pub struct CreateSuggestionRequest {
    pub document_id: Uuid,
    pub document_created_at: DateTime<Utc>,
    pub original_text: String,
    pub suggested_text: String,
    pub description: Option<String>,
} 