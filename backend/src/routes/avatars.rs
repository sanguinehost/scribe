// backend/src/routes/avatars.rs

use crate::auth::token_auth::UnifiedAuth;
use crate::errors::AppError;
use crate::models::user_assets::{NewUserAsset, UserAsset};
use crate::schema::user_assets::dsl::user_assets;
use crate::state::AppState;
use axum::body::Bytes;
use axum::{
    body::Body,
    debug_handler,
    extract::{multipart::Multipart, Path, State},
    http::StatusCode,
    response::{Json, Response},
    routing::{delete, get, post},
    Router,
};
#[cfg(feature = "postgres-backend")]
use diesel::SelectableHelper;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl};
use image::ImageFormat;
use tracing::{debug, error, info, instrument, warn};

pub fn avatar_routes() -> Router<AppState> {
    Router::new()
        .route("/users/{user_id}/avatar", get(get_user_avatar))
        .route("/users/{user_id}/avatar", post(upload_user_avatar))
        .route("/users/{user_id}/avatar", delete(delete_user_avatar))
        .route("/personas/{persona_id}/avatar", get(get_persona_avatar))
        .route("/personas/{persona_id}/avatar", post(upload_persona_avatar))
        .route(
            "/personas/{persona_id}/avatar",
            delete(delete_persona_avatar),
        )
        .route("/personas/{persona_id}/banner", get(get_persona_banner))
        .route("/personas/{persona_id}/banner", post(upload_persona_banner))
        .route(
            "/personas/{persona_id}/banner",
            delete(delete_persona_banner),
        )
}

// Get user avatar
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn get_user_avatar(
    Path(user_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Response<Body>, AppError> {
    // Get the user from the session
    let current_user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Users can only access their own avatars
    if current_user.id != user_id {
        return Err(AppError::Forbidden(
            "Access denied to user avatar".to_string(),
        ));
    }

    // Load the user avatar from database
    let asset = crate::db::with_conn(&state.pool, move |conn_block| {
        user_assets
            .filter(crate::schema::user_assets::user_id.eq(user_id))
            .filter(crate::schema::user_assets::persona_id.is_null())
            .filter(crate::schema::user_assets::asset_type.eq("avatar"))
            .first::<UserAsset>(conn_block)
            .optional()
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}"))
            })
    })
    .await?;

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
    let image_data_len = image_data.len();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
        .body(Body::from(image_data.into_bytes()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(user_id = %user_id, content_type = %content_type, image_data_len = image_data_len, "User avatar served successfully");
    Ok(response)
}

// Upload user avatar
#[debug_handler]
#[instrument(skip(state, auth, multipart), err)]
pub async fn upload_user_avatar(
    Path(user_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<crate::DbJson>), AppError> {
    // Get the user from the session
    let current_user = auth
        .user()
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
        crate::db::DbBlob::from(image_bytes.to_vec()),
        content_type, // Pass the extracted content_type
    );

    // Insert or replace existing avatar
    let asset_result = crate::db::with_conn(&state.pool, move |conn_block| {
        // First, delete any existing user avatar
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.is_null())
                .filter(crate::schema::user_assets::asset_type.eq("avatar")),
        )
        .execute(conn_block)?;

        // Then insert the new avatar
        #[cfg(feature = "postgres-backend")]
        {
            diesel::insert_into(user_assets)
                .values(new_asset)
                .returning(UserAsset::as_returning())
                .get_result::<UserAsset>(conn_block)
                .map_err(Into::into)
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            // SQLite doesn't support RETURNING, so we insert and query back
            diesel::insert_into(user_assets)
                .values(&new_asset)
                .execute(conn_block)?;

            // Query back the just-inserted avatar using unique filters
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.is_null())
                .filter(crate::schema::user_assets::asset_type.eq("avatar"))
                .first::<UserAsset>(conn_block)
                .map_err(Into::into)
        }
    })
    .await
    .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}")))?;

    info!(user_id = %user_id, asset_id = ?asset_result.id, "User avatar uploaded successfully");

    Ok((
        StatusCode::CREATED,
        Json(crate::db::Json(serde_json::json!({
            "message": "Avatar uploaded successfully",
            "asset_id": asset_result.id
        }))),
    ))
}

// Delete user avatar
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn delete_user_avatar(
    Path(user_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<StatusCode, AppError> {
    // Get the user from the session
    let current_user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    // Users can only delete their own avatars
    if current_user.id != user_id {
        return Err(AppError::Forbidden(
            "Access denied to delete avatar".to_string(),
        ));
    }

    let deleted_count = crate::db::with_conn(&state.pool, move |conn_block| {
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.is_null())
                .filter(crate::schema::user_assets::asset_type.eq("avatar")),
        )
        .execute(conn_block)
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset delete DB error: {e}")))
    })
    .await?;

    if deleted_count == 0 {
        return Err(AppError::NotFound("User avatar not found".to_string()));
    }

    info!(user_id = %user_id, "User avatar deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

// Get persona avatar
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn get_persona_avatar(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Response<Body>, AppError> {
    // Get the user from the session
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

    // Load the persona avatar from database (with user ownership check)
    let asset = crate::db::with_conn(&state.pool, move |conn_block| {
        user_assets
            .filter(crate::schema::user_assets::user_id.eq(user_id))
            .filter(crate::schema::user_assets::persona_id.eq(persona_id))
            .filter(crate::schema::user_assets::asset_type.eq("avatar"))
            .first::<UserAsset>(conn_block)
            .optional()
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}"))
            })
    })
    .await?;

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
    let image_data_len = image_data.len();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
        .body(Body::from(image_data.into_bytes()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(persona_id = %persona_id, content_type = %content_type, image_data_len = image_data_len, "Persona avatar served successfully");
    Ok(response)
}

// Upload persona avatar
#[debug_handler]
#[instrument(skip(state, auth, multipart), err)]
pub async fn upload_persona_avatar(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<crate::DbJson>), AppError> {
    // Get the user from the session
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

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
        user_id,
        persona_id,
        &format!("persona_{}_avatar", persona_id),
        crate::db::DbBlob::from(image_bytes.to_vec()),
        content_type, // Pass the extracted content_type
    );

    // Insert or replace existing persona avatar
    let asset_result = crate::db::with_conn(&state.pool, move |conn_block| {
        // First, delete any existing persona avatar
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                .filter(crate::schema::user_assets::asset_type.eq("avatar")),
        )
        .execute(conn_block)?;

        // Then insert the new avatar
        #[cfg(feature = "postgres-backend")]
        {
            diesel::insert_into(user_assets)
                .values(new_asset)
                .returning(UserAsset::as_returning())
                .get_result::<UserAsset>(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}"))
                })
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            // SQLite doesn't support RETURNING, so we insert and query back
            diesel::insert_into(user_assets)
                .values(&new_asset)
                .execute(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}"))
                })?;

            // Query back the just-inserted avatar using unique filters
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                .filter(crate::schema::user_assets::asset_type.eq("avatar"))
                .first::<UserAsset>(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset query DB error: {e}"))
                })
        }
    })
    .await?;

    info!(persona_id = %persona_id, asset_id = ?asset_result.id, "Persona avatar uploaded successfully");

    Ok((
        StatusCode::CREATED,
        Json(crate::db::Json(serde_json::json!({
            "message": "Persona avatar uploaded successfully",
            "asset_id": asset_result.id
        }))),
    ))
}

// Delete persona avatar
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn delete_persona_avatar(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<StatusCode, AppError> {
    // Get the user from the session
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

    let deleted_count = crate::db::with_conn(&state.pool, move |conn_block| {
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(Some(persona_id)))
                .filter(crate::schema::user_assets::asset_type.eq("avatar")),
        )
        .execute(conn_block)
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset delete DB error: {e}")))
    })
    .await?;

    if deleted_count == 0 {
        return Err(AppError::NotFound("Persona avatar not found".to_string()));
    }

    info!(persona_id = %persona_id, "Persona avatar deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

// Get persona banner
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn get_persona_banner(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Response<Body>, AppError> {
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

    let asset = crate::db::with_conn(&state.pool, move |conn_block| {
        user_assets
            .filter(crate::schema::user_assets::user_id.eq(user_id))
            .filter(crate::schema::user_assets::persona_id.eq(persona_id))
            .filter(crate::schema::user_assets::asset_type.eq("banner"))
            .first::<UserAsset>(conn_block)
            .optional()
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}"))
            })
    })
    .await?;

    let asset = asset.ok_or_else(|| AppError::NotFound("Persona banner not found".to_string()))?;

    let image_data = asset
        .data
        .ok_or_else(|| AppError::NotFound("Banner asset has no image data".to_string()))?;

    let content_type = asset
        .content_type
        .unwrap_or_else(|| "image/png".to_string());

    let image_data_len = image_data.len();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600")
        .body(Body::from(image_data.into_bytes()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(persona_id = %persona_id, content_type = %content_type, image_data_len = image_data_len, "Persona banner served successfully");
    Ok(response)
}

// Upload persona banner
#[debug_handler]
#[instrument(skip(state, auth, multipart), err)]
pub async fn upload_persona_banner(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<crate::DbJson>), AppError> {
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

    let mut image_data: Option<Bytes> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "banner" || field_name == "file" || field_name == "avatar" {
            content_type = field.content_type().map(std::string::ToString::to_string);
            let data = field.bytes().await?;
            image_data = Some(data);
            break;
        }
    }

    let image_bytes = image_data
        .ok_or_else(|| AppError::BadRequest("Missing 'banner' field in upload".to_string()))?;

    // Validate size constraint (5MB)
    if image_bytes.len() > 5 * 1024 * 1024 {
        return Err(AppError::BadRequest(
            "File exceeds 5MB size limit".to_string(),
        ));
    }

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
                        return Err(AppError::BadRequest(format!(
                            "Invalid image file format/content: {}",
                            e
                        )));
                    }
                }
            } else {
                return Err(AppError::BadRequest(format!(
                    "Unsupported image format: {}. Only PNG and JPEG are allowed.",
                    ct
                )));
            }
        } else {
            return Err(AppError::BadRequest(
                "Invalid MIME type. Must be an image.".to_string(),
            ));
        }
    } else {
        return Err(AppError::BadRequest(
            "No content type provided for persona banner upload.".to_string(),
        ));
    }

    let new_asset = NewUserAsset::new_persona_banner(
        user_id,
        persona_id,
        &format!("persona_{}_banner", persona_id),
        crate::db::DbBlob::from(image_bytes.to_vec()),
        content_type,
    );

    let asset_result = crate::db::with_conn(&state.pool, move |conn_block| {
        // Delete existing banner first
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                .filter(crate::schema::user_assets::asset_type.eq("banner")),
        )
        .execute(conn_block)?;

        #[cfg(feature = "postgres-backend")]
        {
            diesel::insert_into(user_assets)
                .values(new_asset)
                .returning(UserAsset::as_returning())
                .get_result::<UserAsset>(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}"))
                })
        }

        #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
        {
            diesel::insert_into(user_assets)
                .values(&new_asset)
                .execute(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset insert DB error: {e}"))
                })?;

            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(persona_id))
                .filter(crate::schema::user_assets::asset_type.eq("banner"))
                .first::<UserAsset>(conn_block)
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!("Asset query DB error: {e}"))
                })
        }
    })
    .await?;

    info!(persona_id = %persona_id, asset_id = ?asset_result.id, "Persona banner uploaded successfully");

    Ok((
        StatusCode::CREATED,
        Json(crate::db::Json(serde_json::json!({
            "message": "Persona banner uploaded successfully",
            "asset_id": asset_result.id,
            "url": format!("/api/v1/personas/{}/banner", persona_id)
        }))),
    ))
}

// Delete persona banner
#[debug_handler]
#[instrument(skip(state, auth), err)]
pub async fn delete_persona_banner(
    Path(persona_id): Path<crate::db::DbId>,
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<StatusCode, AppError> {
    let user_id = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?
        .id;

    let deleted_count = crate::db::with_conn(&state.pool, move |conn_block| {
        diesel::delete(
            user_assets
                .filter(crate::schema::user_assets::user_id.eq(user_id))
                .filter(crate::schema::user_assets::persona_id.eq(Some(persona_id)))
                .filter(crate::schema::user_assets::asset_type.eq("banner")),
        )
        .execute(conn_block)
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset delete DB error: {e}")))
    })
    .await?;

    if deleted_count == 0 {
        return Err(AppError::NotFound("Persona banner not found".to_string()));
    }

    info!(persona_id = %persona_id, "Persona banner deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}
