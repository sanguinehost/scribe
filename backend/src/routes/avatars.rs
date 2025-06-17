// backend/src/routes/avatars.rs

use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::models::user_assets::{NewUserAsset, UserAsset};
use crate::schema::user_assets::dsl::user_assets;
use crate::state::AppState;
use axum::body::Bytes;
use axum::{
    Router,
    body::Body,
    debug_handler,
    extract::{Path, State, multipart::Multipart},
    http::StatusCode,
    response::{Json, Response},
    routing::{delete, get, post},
};
use axum_login::AuthSession;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use image::ImageFormat;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

type CurrentAuthSession = AuthSession<AuthBackend>;

pub fn avatar_routes() -> Router<AppState> {
    Router::new()
        .route("/users/:user_id/avatar", get(get_user_avatar))
        .route("/users/:user_id/avatar", post(upload_user_avatar))
        .route("/users/:user_id/avatar", delete(delete_user_avatar))
        .route("/personas/:persona_id/avatar", get(get_persona_avatar))
        .route("/personas/:persona_id/avatar", post(upload_persona_avatar))
        .route(
            "/personas/:persona_id/avatar",
            delete(delete_persona_avatar),
        )
}

// Get user avatar
#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn get_user_avatar(
    Path(user_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
) -> Result<Response<Body>, AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Users can only access their own avatars
    if current_user.id != user_id {
        return Err(AppError::Forbidden(
            "Access denied to user avatar".to_string(),
        ));
    }

    // Load the user avatar from database
    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let asset = conn
        .interact(move |conn_block| {
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.is_null())
                .filter(crate::schema::user_assets::asset_type.eq("avatar"))
                .select(UserAsset::as_select())
                .first::<UserAsset>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset lookup interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}")))?;

    let asset = asset.ok_or_else(|| AppError::NotFound("User avatar not found".to_string()))?;

    // Get the image data from the asset
    let image_data = asset
        .data
        .ok_or_else(|| AppError::NotFound("Avatar asset has no image data".to_string()))?;

    // Get content type, default to image/png
    let content_type = asset
        .content_type
        .unwrap_or_else(|| "image/png".to_string());

    // Return the image with appropriate headers
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
        .body(Body::from(image_data.clone()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(user_id = %user_id, content_type = %content_type, image_data_len = image_data.len(), "User avatar served successfully");
    Ok(response)
}

// Upload user avatar
#[debug_handler]
#[instrument(skip(state, auth_session, multipart), err)]
pub async fn upload_user_avatar(
    Path(user_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Users can only upload their own avatars
    if current_user.id != user_id {
        return Err(AppError::Forbidden(
            "Access denied to upload avatar".to_string(),
        ));
    }

    let mut image_data: Option<Bytes> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "avatar" {
            content_type = field.content_type().map(std::string::ToString::to_string); // Extract content type
            let data = field.bytes().await?;
            image_data = Some(data);
            break;
        }
    }

    let image_bytes = image_data
        .ok_or_else(|| AppError::BadRequest("Missing 'avatar' field in upload".to_string()))?;

    // Validate image data using the 'image' crate
    if let Some(ct) = &content_type {
        if ct.starts_with("image/") {
            let format = match ct.as_str() {
                "image/png" => Some(ImageFormat::Png),
                "image/jpeg" => Some(ImageFormat::Jpeg),
                _ => None,
            };

            if let Some(fmt) = format {
                match image::load_from_memory_with_format(&image_bytes, fmt) {
                    Ok(_) => info!("Image data validated successfully as {}", ct),
                    Err(e) => {
                        error!("Failed to decode image data as {}: {}", ct, e);
                        return Err(AppError::BadRequest(format!("Invalid image data: {}", e)));
                    }
                }
            } else {
                warn!("Unsupported image content type: {}", ct);
                // Allow upload but log warning, or return error if strict
            }
        }
    } else {
        warn!("No content type provided for user avatar upload.");
    }

    // Create user asset record
    let new_asset = NewUserAsset::new_user_avatar(
        user_id,
        &format!("{}_avatar", current_user.username),
        image_bytes.to_vec(),
        content_type, // Pass the extracted content_type
    );

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    // Insert or replace existing avatar
    let asset_result = conn
        .interact(move |conn_block| {
            // First, delete any existing user avatar
            diesel::delete(
                user_assets
                    .filter(crate::schema::user_assets::user_id.eq(user_id))
                    .filter(crate::schema::user_assets::persona_id.is_null())
                    .filter(crate::schema::user_assets::asset_type.eq("avatar")),
            )
            .execute(conn_block)?;

            // Then insert the new avatar
            diesel::insert_into(user_assets)
                .values(new_asset)
                .returning(UserAsset::as_returning())
                .get_result::<UserAsset>(conn_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset insert interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}")))?;

    info!(user_id = %user_id, asset_id = asset_result.id, "User avatar uploaded successfully");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Avatar uploaded successfully",
            "asset_id": asset_result.id
        })),
    ))
}

// Delete user avatar
#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn delete_user_avatar(
    Path(user_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
) -> Result<StatusCode, AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Users can only delete their own avatars
    if current_user.id != user_id {
        return Err(AppError::Forbidden(
            "Access denied to delete avatar".to_string(),
        ));
    }

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let deleted_count = conn
        .interact(move |conn_block| {
            diesel::delete(
                user_assets
                    .filter(crate::schema::user_assets::user_id.eq(user_id))
                    .filter(crate::schema::user_assets::persona_id.is_null())
                    .filter(crate::schema::user_assets::asset_type.eq("avatar")),
            )
            .execute(conn_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset delete interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset delete DB error: {e}")))?;

    if deleted_count == 0 {
        return Err(AppError::NotFound("User avatar not found".to_string()));
    }

    info!(user_id = %user_id, "User avatar deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

// Get persona avatar
#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn get_persona_avatar(
    Path(persona_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
) -> Result<Response<Body>, AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Load the persona avatar from database (with user ownership check)
    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let asset = conn
        .interact(move |conn_block| {
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(current_user.id))
                .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                .filter(crate::schema::user_assets::asset_type.eq("avatar"))
                .select(UserAsset::as_select())
                .first::<UserAsset>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset lookup interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}")))?;

    let asset = asset.ok_or_else(|| AppError::NotFound("Persona avatar not found".to_string()))?;

    // Get the image data from the asset
    let image_data = asset
        .data
        .ok_or_else(|| AppError::NotFound("Avatar asset has no image data".to_string()))?;

    // Get content type, default to image/png
    let content_type = asset
        .content_type
        .unwrap_or_else(|| "image/png".to_string());

    // Return the image with appropriate headers
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
        .body(Body::from(image_data.clone()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(persona_id = %persona_id, content_type = %content_type, image_data_len = image_data.len(), "Persona avatar served successfully");
    Ok(response)
}

// Upload persona avatar
#[debug_handler]
#[instrument(skip(state, auth_session, multipart), err)]
pub async fn upload_persona_avatar(
    Path(persona_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Verify persona ownership (user can only upload avatars for their own personas)
    // This would require checking the persona table, but for now we'll trust the persona_id

    let mut image_data: Option<Bytes> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "avatar" {
            content_type = field.content_type().map(std::string::ToString::to_string); // Extract content type
            let data = field.bytes().await?;
            image_data = Some(data);
            break;
        }
    }

    let image_bytes = image_data
        .ok_or_else(|| AppError::BadRequest("Missing 'avatar' field in upload".to_string()))?;

    // Validate image data using the 'image' crate
    if let Some(ct) = &content_type {
        if ct.starts_with("image/") {
            let format = match ct.as_str() {
                "image/png" => Some(image::ImageFormat::Png),
                "image/jpeg" => Some(image::ImageFormat::Jpeg),
                _ => None,
            };

            if let Some(fmt) = format {
                match image::load_from_memory_with_format(&image_bytes, fmt) {
                    Ok(_) => info!("Image data validated successfully as {}", ct),
                    Err(e) => {
                        error!("Failed to decode image data as {}: {}", ct, e);
                        return Err(AppError::BadRequest(format!("Invalid image data: {}", e)));
                    }
                }
            } else {
                warn!("Unsupported image content type: {}", ct);
                // Allow upload but log warning, or return error if strict
            }
        }
    } else {
        warn!("No content type provided for persona avatar upload.");
    }

    // Create persona asset record
    let new_asset = NewUserAsset::new_persona_avatar(
        current_user.id,
        persona_id,
        &format!("persona_{}_avatar", persona_id),
        image_bytes.to_vec(),
        content_type, // Pass the extracted content_type
    );

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    // Insert or replace existing persona avatar
    let asset_result = conn
        .interact(move |conn_block| {
            // First, delete any existing persona avatar
            diesel::delete(
                user_assets
                    .filter(crate::schema::user_assets::user_id.eq(current_user.id))
                    .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                    .filter(crate::schema::user_assets::asset_type.eq("avatar")),
            )
            .execute(conn_block)?;

            // Then insert the new avatar
            diesel::insert_into(user_assets)
                .values(new_asset)
                .returning(UserAsset::as_returning())
                .get_result::<UserAsset>(conn_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset insert interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}")))?;

    info!(persona_id = %persona_id, asset_id = asset_result.id, "Persona avatar uploaded successfully");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Persona avatar uploaded successfully",
            "asset_id": asset_result.id
        })),
    ))
}

// Delete persona avatar
#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn delete_persona_avatar(
    Path(persona_id): Path<Uuid>,
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
) -> Result<StatusCode, AppError> {
    // Get the user from the session
    let current_user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let deleted_count = conn
        .interact(move |conn_block| {
            diesel::delete(
                user_assets
                    .filter(crate::schema::user_assets::user_id.eq(current_user.id))
                    .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                    .filter(crate::schema::user_assets::asset_type.eq("avatar")),
            )
            .execute(conn_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset delete interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset delete DB error: {e}")))?;

    if deleted_count == 0 {
        return Err(AppError::NotFound("Persona avatar not found".to_string()));
    }

    info!(persona_id = %persona_id, "Persona avatar deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}
