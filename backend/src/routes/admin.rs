use crate::auth::token_auth::UnifiedAuth;
use crate::errors::AppError;
use crate::models::users::{AccountStatus, UserDbQuery, UserRole};
use crate::schema::users;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

// DTO for user list display
#[derive(Debug, Serialize)]
pub struct AdminUserListResponse {
    pub id: crate::db::DbId,
    pub username: String,
    pub role: UserRole,
    pub account_status: String,                 // "active" or "locked"
    pub last_login: Option<crate::DbTimestamp>, // We'll use updated_at for now as proxy for last login
}

// DTO for user details
#[derive(Debug, Serialize)]
pub struct AdminUserDetailResponse {
    pub id: crate::db::DbId,
    pub username: String,
    pub email: Option<String>, // Nullable in SQLite, NOT NULL in PostgreSQL
    pub role: UserRole,
    pub account_status: String,
    pub created_at: crate::DbTimestamp,
    pub updated_at: crate::DbTimestamp, // Using as last login for now
}

// Update user role request payload
#[derive(Debug, Deserialize)]
pub struct UpdateUserRoleRequest {
    pub role: UserRole,
}

// Middleware to check if user is Admin
fn require_admin(auth: &UnifiedAuth) -> Result<(), AppError> {
    auth.user().map_or_else(|| {
            warn!("Unauthorized access attempt to admin endpoint");
            Err(AppError::Unauthorized("Not logged in".to_string()))
        }, |user| {
            // Access role from User struct
            let user_id = user.id;
            let username = user.username.clone();

            // Ideally we would have role here directly, but we need to get it from the database
            // since we added it after the auth system was set up
            match user.role {
                UserRole::Administrator => {
                    debug!(user_id = %user_id, username = %username, "User has Administrator role, access granted");
                    Ok(())
                }
                role => {
                    warn!(user_id = %user_id, username = %username, role = ?role, "User does not have Administrator role");
                    Err(AppError::Forbidden("Access denied - admin privileges required".to_string()))
                }
            }
        })
}

// List all users
#[instrument(skip(state, auth), err)]
async fn list_users_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
) -> Result<Response, AppError> {
    // Verify the user is an administrator
    require_admin(&auth)?;

    info!("Admin: listing all users");

    // Fetch all users from the database
    let users = crate::db::with_conn(&state.pool, |conn| {
        users::table
            .load::<UserDbQuery>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await?;

    // Transform to DTOs for response
    let user_list: Vec<AdminUserListResponse> = users
        .into_iter()
        .map(|user| AdminUserListResponse {
            id: user.id,
            username: user.username,
            role: user.role,
            account_status: format!("{:?}", user.account_status).to_lowercase(),
            last_login: Some(user.updated_at), // Using updated_at as proxy for last login
        })
        .collect();

    Ok(Json(user_list).into_response())
}

// Get a specific user
#[instrument(skip(state, auth), err)]
async fn get_user_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(user_id): Path<crate::db::DbId>,
) -> Result<Response, AppError> {
    // Verify the user is an administrator
    require_admin(&auth)?;

    info!(user_id = %user_id, "Admin: getting specific user details");

    // Fetch the user from the database
    let user = crate::db::with_conn(&state.pool, move |conn| {
        users::table
            .filter(users::id.eq(user_id))
            .first::<UserDbQuery>(conn)
            .map_err(|e| {
                if e == diesel::result::Error::NotFound {
                    AppError::UserNotFound
                } else {
                    AppError::DatabaseQueryError(e.to_string())
                }
            })
    })
    .await?;

    // Transform to DTO for response
    let user_detail = AdminUserDetailResponse {
        id: user.id,
        username: user.username,
        #[cfg(feature = "sqlite-backend")]
        email: user.email,
        #[cfg(feature = "postgres-backend")]
        email: Some(user.email),
        role: user.role,
        account_status: format!("{:?}", user.account_status).to_lowercase(),
        created_at: user.created_at,
        updated_at: user.updated_at, // Using as last login for now
    };

    Ok(Json(user_detail).into_response())
}

// Implement user account locking
#[instrument(skip(state, auth), err)]
async fn lock_user_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(user_id): Path<crate::db::DbId>,
) -> Result<Response, AppError> {
    // Verify the user is an administrator
    require_admin(&auth)?;

    info!(user_id = %user_id, "Admin: locking user account");

    // Prevent locking own account
    if let Some(admin_user) = &auth.session.user {
        if admin_user.id == user_id {
            warn!(user_id = %user_id, "Admin tried to lock their own account");
            return Err(AppError::BadRequest(
                "Cannot lock your own account".to_string(),
            ));
        }
    }

    // Update the user's account status in the database
    let updated_user = crate::db::with_conn(&state.pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::account_status.eq(AccountStatus::Locked))
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING on UPDATE, so we update and query back
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::account_status.eq(AccountStatus::Locked))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            users::table
                .find(user_id)
                .first::<UserDbQuery>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }
    })
    .await?;

    // Return success message
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": format!("User account '{}' has been locked", updated_user.username)
        })),
    )
        .into_response())
}

// Implement user account unlocking
#[instrument(skip(state, auth), err)]
async fn unlock_user_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(user_id): Path<crate::db::DbId>,
) -> Result<Response, AppError> {
    // Verify the user is an administrator
    require_admin(&auth)?;

    info!(user_id = %user_id, "Admin: unlocking user account");

    // Update the user's account status in the database
    let updated_user = crate::db::with_conn(&state.pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::account_status.eq(AccountStatus::Active))
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING on UPDATE, so we update and query back
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::account_status.eq(AccountStatus::Active))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            users::table
                .find(user_id)
                .first::<UserDbQuery>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }
    })
    .await?;

    // Return success message
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": format!("User account '{}' has been unlocked", updated_user.username)
        })),
    )
        .into_response())
}

// Update user role
#[instrument(skip(state, auth, payload), err)]
async fn update_user_role_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(user_id): Path<crate::db::DbId>,
    Json(payload): Json<UpdateUserRoleRequest>,
) -> Result<Response, AppError> {
    // Verify the user is an administrator
    require_admin(&auth)?;

    info!(user_id = %user_id, new_role = ?payload.role, "Admin: updating user role");

    // Prevent changing own role
    if let Some(admin_user) = &auth.session.user {
        if admin_user.id == user_id {
            warn!(user_id = %user_id, "Admin tried to change their own role");
            return Err(AppError::BadRequest(
                "Cannot change your own role".to_string(),
            ));
        }
    }

    // Update the user's role in the database
    let updated_user = crate::db::with_conn(&state.pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::role.eq(payload.role))
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING on UPDATE, so we update and query back
            diesel::update(users::table)
                .filter(users::id.eq(user_id))
                .set(users::role.eq(payload.role))
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            users::table
                .find(user_id)
                .first::<UserDbQuery>(conn)
                .map_err(|e| {
                    if e == diesel::result::Error::NotFound {
                        AppError::UserNotFound
                    } else {
                        AppError::DatabaseQueryError(e.to_string())
                    }
                })
        }
    })
    .await?;

    // Transform to DTO for response
    let user_detail = AdminUserDetailResponse {
        id: updated_user.id,
        username: updated_user.username,
        #[cfg(feature = "sqlite-backend")]
        email: updated_user.email,
        #[cfg(feature = "postgres-backend")]
        email: Some(updated_user.email),
        role: updated_user.role,
        account_status: format!("{:?}", updated_user.account_status).to_lowercase(),
        created_at: updated_user.created_at,
        updated_at: updated_user.updated_at,
    };

    Ok(Json(user_detail).into_response())
}

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users_handler))
        .route("/users/:user_id", get(get_user_handler))
        .route("/users/:user_id/lock", put(lock_user_handler))
        .route("/users/:user_id/unlock", put(unlock_user_handler))
        .route("/users/:user_id/role", put(update_user_role_handler))
}
