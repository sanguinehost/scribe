use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::models::documents::{
    CreateDocumentRequest, CreateSuggestionRequest, Document, DocumentResponse, NewDocument,
    NewSuggestion, Suggestion,
};
use crate::state::AppState;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
};
use axum_login::AuthSession; // Removed AuthUser
use chrono::Utc;
use diesel::prelude::*;
use diesel::{ExpressionMethods, RunQueryDsl}; // Added missing trait imports
use uuid::Uuid;

// Shorthand for auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn document_routes() -> Router<crate::state::AppState> {
    Router::new()
        .route("/documents", post(create_document_handler))
        .route("/documents/{id}", get(get_documents_by_id_handler))
        .route("/documents/{id}/latest", get(get_document_by_id_handler))
        .route(
            "/documents/{id}/timestamp/{timestamp}",
            delete(delete_documents_by_id_after_timestamp_handler),
        )
        .route("/suggestions", post(create_suggestion_handler))
        .route(
            "/suggestions/document/{id}",
            get(get_suggestions_by_document_id_handler),
        )
}

// Create a new document
async fn create_document_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateDocumentRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let new_document = NewDocument {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        title: payload.title,
        content: payload.content,
        kind: payload.kind,
        user_id: user.id,
    };

    let document = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(crate::schema::old_documents::table) // Use old_documents
                .values(new_document)
                .returning(Document::as_returning())
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let response = DocumentResponse {
        id: document.id,
        created_at: document.created_at,
        title: document.title,
        content: document.content,
        kind: document.kind,
        user_id: document.user_id,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

// Get all documents with a specific ID
async fn get_documents_by_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let documents = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let documents = crate::schema::old_documents::table // Use old_documents
                .filter(crate::schema::old_documents::dsl::id.eq(id)) // Use old_documents
                .order_by(crate::schema::old_documents::dsl::created_at.asc()) // Use old_documents
                .load::<Document>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            // Check if the user has access to these documents
            if let Some(doc) = documents.first() {
                if doc.user_id != user.id {
                    return Err(AppError::Forbidden); // Changed to unit variant
                }
            }

            Ok(documents)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let responses: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            created_at: doc.created_at,
            title: doc.title,
            content: doc.content,
            kind: doc.kind,
            user_id: doc.user_id,
        })
        .collect();

    Ok(Json(responses))
}

// Get the latest document with a specific ID
async fn get_document_by_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    let document = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let document = crate::schema::old_documents::table // Use old_documents
                .filter(crate::schema::old_documents::dsl::id.eq(id)) // Use old_documents
                .order_by(crate::schema::old_documents::dsl::created_at.desc()) // Use old_documents
                .first::<Document>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            // Check if the user has access to this document
            if document.user_id != user.id {
                return Err(AppError::Forbidden); // Changed to unit variant
            }

            Ok(document)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let response = DocumentResponse {
        id: document.id,
        created_at: document.created_at,
        title: document.title,
        content: document.content,
        kind: document.kind,
        user_id: document.user_id,
    };

    Ok(Json(response))
}

// Delete documents after a specific timestamp
async fn delete_documents_by_id_after_timestamp_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path((id, timestamp)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // Parse the timestamp
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map_err(|_| AppError::BadRequest("Invalid timestamp format".to_string()))?
        .with_timezone(&Utc);

    // Verify ownership first
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let document = crate::schema::old_documents::table // Use old_documents
                .filter(crate::schema::old_documents::dsl::id.eq(id)) // Use old_documents
                .first::<Document>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            if let Some(doc) = document {
                if doc.user_id != user.id {
                    return Err(AppError::Forbidden); // Changed to unit variant
                }
            }

            Ok(())
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Now perform the deletion
    let user_id = user.id;
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            // First delete related suggestions
            diesel::delete(
                crate::schema::old_suggestions::table // Use old_suggestions
                    .filter(crate::schema::old_suggestions::dsl::document_id.eq(id)) // Use old_suggestions
                    .filter(crate::schema::old_suggestions::dsl::document_created_at.gt(timestamp)), // Use old_suggestions
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            // Then delete documents
            diesel::delete(
                crate::schema::old_documents::table // Use old_documents
                    .filter(crate::schema::old_documents::dsl::id.eq(id)) // Use old_documents
                    .filter(crate::schema::old_documents::dsl::created_at.gt(timestamp)) // Use old_documents
                    .filter(crate::schema::old_documents::dsl::user_id.eq(user_id)), // Use old_documents
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    Ok(StatusCode::NO_CONTENT)
}

// Create a new suggestion
async fn create_suggestion_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateSuggestionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // Verify document exists and user has access to it
    let document_id = payload.document_id;
    let document_created_at = payload.document_created_at;

    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let document = crate::schema::old_documents::table // Use old_documents
                .filter(crate::schema::old_documents::dsl::id.eq(document_id)) // Use old_documents
                .filter(crate::schema::old_documents::dsl::created_at.eq(document_created_at)) // Use old_documents
                .first::<Document>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            if let Some(doc) = document {
                if doc.user_id != user.id {
                    return Err(AppError::Forbidden); // Changed to unit variant
                }
            } else {
                return Err(AppError::NotFound("Document not found".to_string()));
            }

            Ok(())
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    let new_suggestion = NewSuggestion {
        id: Uuid::new_v4(),
        document_id: payload.document_id,
        document_created_at: payload.document_created_at,
        original_text: payload.original_text,
        suggested_text: payload.suggested_text,
        description: payload.description,
        is_resolved: false,
        user_id: user.id,
        created_at: Utc::now(),
    };

    let suggestion = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            diesel::insert_into(crate::schema::old_suggestions::table) // Use old_suggestions
                .values(new_suggestion)
                .returning(Suggestion::as_returning())
                .get_result(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    Ok((StatusCode::CREATED, Json(suggestion)))
}

// Get suggestions for a document
async fn get_suggestions_by_document_id_handler(
    auth_session: CurrentAuthSession,
    State(state): State<AppState>,
    Path(document_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or(AppError::Unauthorized("Not logged in".to_string()))?;
    let pool = state.pool.clone();

    // Verify document exists and user has access to it
    pool.get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            let document = crate::schema::old_documents::table // Use old_documents
                .filter(crate::schema::old_documents::dsl::id.eq(document_id)) // Use old_documents
                .first::<Document>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?; // Added .to_string()

            if let Some(doc) = document {
                if doc.user_id != user.id {
                    return Err(AppError::Forbidden); // Changed to unit variant
                }
            } else {
                return Err(AppError::NotFound("Document not found".to_string()));
            }

            Ok(())
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    // Get all suggestions for the document
    let suggestions = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            crate::schema::old_suggestions::table // Use old_suggestions
                .filter(crate::schema::old_suggestions::dsl::document_id.eq(document_id)) // Use old_suggestions
                .load::<Suggestion>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string())) // Added .to_string()
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;

    Ok(Json(suggestions))
}
