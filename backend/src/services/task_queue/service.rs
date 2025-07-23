// backend/src/services/task_queue/service.rs
//
// Task Queue Service Implementation for Epic 8: Orchestrator-Driven Intelligent Agent System

use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use tracing::{debug, error, info, warn, instrument};
use axum_login::AuthnBackend;
use secrecy::ExposeSecret;

use crate::{
    PgPool,
    errors::AppError,
    services::encryption_service::EncryptionService,
    auth::session_dek::SessionDek,
    auth::user_store::Backend as AuthBackend,
    schema::world_enrichment_tasks,
};

use super::types::{
    EnrichmentTask, NewEnrichmentTask, EnrichmentTaskPayload, 
    CreateTaskRequest, DequeuedTask, TaskStatus,
};

/// Task Queue Service providing durable, encrypted task queue for background enrichment
#[derive(Clone)]
pub struct TaskQueueService {
    db_pool: PgPool,
    encryption_service: Arc<EncryptionService>,
    auth_backend: Arc<AuthBackend>,
}

impl TaskQueueService {
    /// Create new TaskQueueService instance
    pub fn new(
        db_pool: PgPool,
        encryption_service: Arc<EncryptionService>,
        auth_backend: Arc<AuthBackend>,
    ) -> Self {
        Self {
            db_pool,
            encryption_service,
            auth_backend,
        }
    }

    /// Enqueue a new background enrichment task
    #[instrument(skip(self, request), fields(user_id = %request.user_id, session_id = %request.session_id))]
    pub async fn enqueue_task(
        &self,
        request: CreateTaskRequest,
    ) -> Result<EnrichmentTask, AppError> {
        debug!("Enqueuing enrichment task with priority {:?}", request.priority);

        // Get user's DEK for encryption
        let user = self.auth_backend
            .get_user(&request.user_id)
            .await
            .map_err(|e| {
                error!("Failed to get user for DEK: {}", e);
                AppError::AuthError(format!("Failed to retrieve user: {e}"))
            })?
            .ok_or_else(|| {
                error!("User not found for task queue: {}", request.user_id);
                AppError::UserNotFound
            })?;
            
        let session_dek = user.dek
            .as_ref()
            .ok_or_else(|| {
                error!("User DEK not available for task queue: {}", request.user_id);
                AppError::EncryptionError("User DEK not available".to_string())
            })
            .map(|dek| SessionDek::new(dek.0.expose_secret().clone()))?;

        // Serialize and encrypt the payload
        let payload_json = serde_json::to_string(&request.payload)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        let (encrypted_payload, payload_nonce) = self.encryption_service
            .encrypt(&payload_json, session_dek.expose_bytes())
            .map_err(|e| {
                error!("Failed to encrypt task payload: {}", e);
                AppError::EncryptionError("Failed to encrypt task payload".to_string())
            })?;

        // Create new task record
        let new_task = NewEnrichmentTask {
            session_id: request.session_id,
            user_id: request.user_id,
            status: TaskStatus::Pending as i32,
            priority: request.priority as i32,
            encrypted_payload,
            payload_nonce,
            retry_count: 0,
        };

        // Insert into database using Diesel pool.interact pattern
        let pool = self.db_pool.clone();
        let task = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                diesel::insert_into(world_enrichment_tasks::table)
                    .values(&new_task)
                    .returning(EnrichmentTask::as_returning())
                    .get_result(conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during task insert: {e}"
                ))
            })??;

        info!("Successfully enqueued task {} for user {}", task.id, request.user_id);
        Ok(task)
    }

    /// Atomically dequeue the next pending task for processing
    #[instrument(skip(self), fields(worker_id = %worker_id))]
    pub async fn dequeue_task(
        &self,
        worker_id: Uuid,
    ) -> Result<Option<DequeuedTask>, AppError> {
        debug!("Attempting to dequeue task for worker {}", worker_id);

        // Atomic dequeue with priority ordering using pool.interact
        let pool = self.db_pool.clone();
        let task_result: Result<EnrichmentTask, AppError> = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                conn.transaction(|conn| -> Result<EnrichmentTask, DieselError> {
            // Find next pending task ordered by priority then creation time
            let task_id: Option<Uuid> = world_enrichment_tasks::table
                .select(world_enrichment_tasks::id)
                .filter(world_enrichment_tasks::status.eq(TaskStatus::Pending as i32))
                .order((
                    world_enrichment_tasks::priority.asc(),
                    world_enrichment_tasks::created_at.asc(),
                ))
                .first::<Uuid>(conn)
                .optional()?;

            match task_id {
                Some(id) => {
                    // Atomically claim the task
                    diesel::update(world_enrichment_tasks::table.find(id))
                        .set((
                            world_enrichment_tasks::status.eq(TaskStatus::InProgress as i32),
                            world_enrichment_tasks::worker_id.eq(Some(worker_id)),
                        ))
                        .returning(EnrichmentTask::as_returning())
                        .get_result(conn)
                }
                    None => Err(DieselError::NotFound), // No pending tasks
                }
            })
            .map_err(AppError::from)
        })
        .await
        .map_err(|e| {
            AppError::DbInteractError(format!(
                "Database interaction error during task dequeue: {e}"
            ))
        })?;

        match task_result {
            Ok(task) => {
                debug!("Dequeued task {} for worker {}", task.id, worker_id);
                
                // Decrypt the payload
                let decrypted_task = self.decrypt_task_payload(&task).await?;
                Ok(Some(decrypted_task))
            }
            Err(AppError::NotFound(_)) => {
                debug!("No pending tasks available for worker {}", worker_id);
                Ok(None)
            }
            Err(e) => {
                error!("Failed to dequeue task: {}", e);
                Err(e)
            }
        }
    }

    /// Update task status and optionally set error message
    #[instrument(skip(self, error_message), fields(task_id = %task_id, status = ?status))]
    pub async fn update_task_status(
        &self,
        task_id: Uuid,
        status: TaskStatus,
        error_message: Option<String>,
    ) -> Result<(), AppError> {
        debug!("Updating task {} to status {:?}", task_id, status);

        // Handle error encryption if provided - need to get task first for user DEK
        let pool = self.db_pool.clone();
        let (encrypted_error, error_nonce) = if let Some(error) = error_message {
            // Get task to determine user for DEK
            let task: EnrichmentTask = pool
                .get()
                .await
                .map_err(|e| {
                    AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
                })?
                .interact(move |conn| {
                    world_enrichment_tasks::table
                        .find(task_id)
                        .first::<EnrichmentTask>(conn)
                        .map_err(AppError::from)
                })
                .await
                .map_err(|e| {
                    AppError::DbInteractError(format!(
                        "Database interaction error during task lookup: {e}"
                    ))
                })??;

            let user = self.auth_backend
                .get_user(&task.user_id)
                .await
                .map_err(|e| AppError::AuthError(format!("Failed to retrieve user: {e}")))?  
                .ok_or_else(|| AppError::UserNotFound)?;
                
            let session_dek = user.dek
                .as_ref()
                .ok_or_else(|| AppError::EncryptionError("User DEK not available".to_string()))
                .map(|dek| SessionDek::new(dek.0.expose_secret().clone()))?;

            let (encrypted, nonce) = self.encryption_service
                .encrypt(&error, session_dek.expose_bytes())
                .map_err(|e| AppError::EncryptionError(e.to_string()))?;

            (Some(encrypted), Some(nonce))
        } else {
            (None, None)
        };

        // Update task status
        let pool_for_update = self.db_pool.clone();
        let updated_rows = pool_for_update
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                diesel::update(world_enrichment_tasks::table.find(task_id))
                    .set((
                        world_enrichment_tasks::status.eq(status as i32),
                        world_enrichment_tasks::encrypted_error.eq(encrypted_error),
                        world_enrichment_tasks::error_nonce.eq(error_nonce),
                    ))
                    .execute(conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during status update: {e}"
                ))
            })??;

        if updated_rows == 0 {
            warn!("Task {} not found for status update", task_id);
            return Err(AppError::NotFound("Task not found".to_string()));
        }

        info!("Updated task {} to status {:?}", task_id, status);
        Ok(())
    }

    /// Retry a failed task by resetting to pending status
    #[instrument(skip(self), fields(task_id = %task_id))]
    pub async fn retry_task(&self, task_id: Uuid) -> Result<(), AppError> {
        debug!("Retrying task {}", task_id);

        let pool = self.db_pool.clone();
        let updated_rows = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                diesel::update(world_enrichment_tasks::table.find(task_id))
                    .set((
                        world_enrichment_tasks::status.eq(TaskStatus::Pending as i32),
                        world_enrichment_tasks::worker_id.eq(None::<Uuid>),
                        world_enrichment_tasks::retry_count.eq(world_enrichment_tasks::retry_count + 1),
                    ))
                    .execute(conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during task retry: {e}"
                ))
            })??;

        if updated_rows == 0 {
            warn!("Task {} not found for retry", task_id);
            return Err(AppError::NotFound("Task not found".to_string()));
        }

        info!("Retried task {}", task_id);
        Ok(())
    }

    /// Get a specific task by ID
    #[instrument(skip(self), fields(task_id = %task_id))]
    pub async fn get_task(&self, task_id: Uuid) -> Result<Option<EnrichmentTask>, AppError> {
        let pool = self.db_pool.clone();
        let task = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                world_enrichment_tasks::table
                    .find(task_id)
                    .first::<EnrichmentTask>(conn)
                    .optional()
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during task lookup: {e}"
                ))
            })??;

        Ok(task)
    }

    /// Get a task by ID with user ownership validation
    #[instrument(skip(self), fields(task_id = %task_id, user_id = %user_id))]
    pub async fn get_task_as_user(
        &self,
        task_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<EnrichmentTask>, AppError> {
        let pool = self.db_pool.clone();
        let task = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                world_enrichment_tasks::table
                    .find(task_id)
                    .filter(world_enrichment_tasks::user_id.eq(user_id))
                    .first::<EnrichmentTask>(conn)
                    .optional()
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during user task lookup: {e}"
                ))
            })??;

        Ok(task)
    }

    /// Get all tasks for a specific session
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn get_session_tasks(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<EnrichmentTask>, AppError> {
        let pool = self.db_pool.clone();
        let tasks = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                world_enrichment_tasks::table
                    .filter(world_enrichment_tasks::session_id.eq(session_id))
                    .order(world_enrichment_tasks::created_at.desc())
                    .load::<EnrichmentTask>(conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during session tasks lookup: {e}"
                ))
            })??;

        Ok(tasks)
    }

    /// Clean up old completed/failed tasks
    #[instrument(skip(self), fields(max_age = ?max_age))]
    pub async fn cleanup_old_tasks(&self, max_age: Duration) -> Result<usize, AppError> {
        let cutoff_time = Utc::now() - max_age;
        debug!("Cleaning up tasks older than {}", cutoff_time);

        let pool = self.db_pool.clone();
        let deleted_count = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                diesel::delete(
                    world_enrichment_tasks::table
                        .filter(world_enrichment_tasks::status.eq_any(vec![
                            TaskStatus::Completed as i32,
                            TaskStatus::Failed as i32,
                        ]))
                        .filter(world_enrichment_tasks::updated_at.lt(cutoff_time))
                )
                .execute(conn)
                .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during cleanup: {e}"
                ))
            })??;

        info!("Cleaned up {} old tasks", deleted_count);
        Ok(deleted_count)
    }

    /// Decrypt error message from encrypted task
    #[instrument(skip(self, task), fields(task_id = %task.id))]
    pub async fn decrypt_error(&self, task: &EnrichmentTask) -> Result<Option<String>, AppError> {
        match (&task.encrypted_error, &task.error_nonce) {
            (Some(encrypted), Some(nonce)) => {
                let user = self.auth_backend
                    .get_user(&task.user_id)
                    .await
                    .map_err(|e| AppError::AuthError(format!("Failed to retrieve user: {e}")))?  
                    .ok_or_else(|| AppError::UserNotFound)?;
                    
                let session_dek = user.dek
                    .as_ref()
                    .ok_or_else(|| AppError::EncryptionError("User DEK not available".to_string()))
                    .map(|dek| SessionDek::new(dek.0.expose_secret().clone()))?;

                let decrypted = self.encryption_service
                    .decrypt(encrypted, nonce, session_dek.expose_bytes())
                    .map_err(|e| AppError::EncryptionError(e.to_string()))?;

                let error_message = String::from_utf8(decrypted)
                    .map_err(|e| AppError::SerializationError(e.to_string()))?;

                Ok(Some(error_message))
            }
            _ => Ok(None),
        }
    }


    /// Decrypt task payload using user's DEK
    async fn decrypt_task_payload(&self, task: &EnrichmentTask) -> Result<DequeuedTask, AppError> {
        let user = self.auth_backend
            .get_user(&task.user_id)
            .await
            .map_err(|e| AppError::AuthError(format!("Failed to retrieve user: {e}")))?  
            .ok_or_else(|| AppError::UserNotFound)?;
            
        let session_dek = user.dek
            .as_ref()
            .ok_or_else(|| AppError::EncryptionError("User DEK not available".to_string()))
            .map(|dek| SessionDek::new(dek.0.expose_secret().clone()))?;

        let decrypted_bytes = self.encryption_service
            .decrypt(&task.encrypted_payload, &task.payload_nonce, session_dek.expose_bytes())
            .map_err(|e| AppError::EncryptionError(e.to_string()))?;

        let payload_json = String::from_utf8(decrypted_bytes)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        let payload: EnrichmentTaskPayload = serde_json::from_str(&payload_json)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        Ok(DequeuedTask {
            task: task.clone(),
            payload,
        })
    }
}