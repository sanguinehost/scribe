use crate::schema::player_chronicles;
use chrono::{DateTime, Utc};
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// PlayerChronicle represents a story container that groups related chat sessions and events
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = player_chronicles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PlayerChronicle {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// NewPlayerChronicle for creating new chronicles
#[derive(Debug, Clone, Insertable, Serialize, Deserialize, Validate)]
#[diesel(table_name = player_chronicles)]
pub struct NewPlayerChronicle {
    pub user_id: Uuid,
    #[validate(length(min = 1, max = 255, message = "Chronicle name must be between 1 and 255 characters"))]
    pub name: String,
    #[validate(length(max = 5000, message = "Chronicle description must be less than 5000 characters"))]
    pub description: Option<String>,
}

/// UpdatePlayerChronicle for updating existing chronicles
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdatePlayerChronicle {
    #[validate(length(min = 1, max = 255, message = "Chronicle name must be between 1 and 255 characters"))]
    pub name: Option<String>,
    #[validate(length(max = 5000, message = "Chronicle description must be less than 5000 characters"))]
    pub description: Option<String>,
}

/// PlayerChronicleWithCounts includes additional data for UI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerChronicleWithCounts {
    #[serde(flatten)]
    pub chronicle: PlayerChronicle,
    pub event_count: i64,
    pub chat_session_count: i64,
}

/// DTO for chronicle creation from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateChronicleRequest {
    #[validate(length(min = 1, max = 255, message = "Chronicle name must be between 1 and 255 characters"))]
    pub name: String,
    #[validate(length(max = 5000, message = "Chronicle description must be less than 5000 characters"))]
    pub description: Option<String>,
}

/// DTO for chronicle update from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateChronicleRequest {
    #[validate(length(min = 1, max = 255, message = "Chronicle name must be between 1 and 255 characters"))]
    pub name: Option<String>,
    #[validate(length(max = 5000, message = "Chronicle description must be less than 5000 characters"))]
    pub description: Option<String>,
}

impl From<CreateChronicleRequest> for NewPlayerChronicle {
    fn from(request: CreateChronicleRequest) -> Self {
        Self {
            user_id: Uuid::nil(), // Will be set by the service
            name: request.name,
            description: request.description,
        }
    }
}

impl From<UpdateChronicleRequest> for UpdatePlayerChronicle {
    fn from(request: UpdateChronicleRequest) -> Self {
        Self {
            name: request.name,
            description: request.description,
        }
    }
}