use crate::client::{
    build_url, handle_response, 
    ReqwestClientWrapper,
    AdminUserListResponse, AdminUserDetailResponse, 
    UpdateUserRoleRequest,
};
use crate::error::CliError;
use async_trait::async_trait;
use uuid::Uuid;

// Implementation of admin API methods for the ReqwestClientWrapper
impl ReqwestClientWrapper {
    pub async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError> {
        let url = build_url(&self.base_url, "/api/admin/users")?;
        tracing::info!(%url, "Admin: Listing all users");
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        handle_response(response).await
    }

    pub async fn admin_get_user(&self, user_id: Uuid) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}", user_id))?;
        tracing::info!(%url, %user_id, "Admin: Getting user details by ID");
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        handle_response(response).await
    }

    pub async fn admin_get_user_by_username(&self, username: &str) -> Result<AdminUserDetailResponse, CliError> {
        // Typically this would be a separate endpoint or query parameter
        // For now, we'll implement a placeholder that will be updated when the backend API is ready
        let url = build_url(&self.base_url, &format!("/api/admin/users?username={}", username))?;
        tracing::info!(%url, %username, "Admin: Getting user details by username");
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        handle_response(response).await
    }

    pub async fn admin_update_user_role(&self, user_id: Uuid, role: &str) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/role", user_id))?;
        tracing::info!(%url, %user_id, %role, "Admin: Updating user role");
        
        let payload = UpdateUserRoleRequest {
            role: role.to_string(),
        };
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .put(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        handle_response(response).await
    }

    pub async fn admin_lock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/lock", user_id))?;
        tracing::info!(%url, %user_id, "Admin: Locking user account");
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .put(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        // Check for success status
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            
            tracing::error!(%status, error_body = %error_text, "Admin: Lock user API request failed");
            
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    pub async fn admin_unlock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/unlock", user_id))?;
        tracing::info!(%url, %user_id, "Admin: Unlocking user account");
        
        // This will throw an error until the API is implemented in the backend
        let response = self
            .client
            .put(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        // Check for success status
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            
            tracing::error!(%status, error_body = %error_text, "Admin: Unlock user API request failed");
            
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }
}