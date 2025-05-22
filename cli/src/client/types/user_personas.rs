//! User Persona related DTOs for client-server communication.
//! These are typically re-exports from the backend crate's models.

// Re-export the DTOs from the backend.
// Adjust the path if your backend crate has a different name or structure.
pub use scribe_backend::models::user_personas::{
    CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient,
};
pub use uuid::Uuid; // Often needed with these DTOs