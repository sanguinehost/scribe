// cli/src/client/mod.rs

// Declare modules
pub mod types;
pub mod util;
pub mod interface;
pub mod implementation;

#[cfg(test)]
mod client_tests; // Test module doesn't need to be pub

// Re-export public API
pub use self::interface::HttpClient; // Explicit self for clarity
pub use self::implementation::ReqwestClientWrapper; // Explicit self for clarity

// Re-export types that are part of the public interface of this client module.
// These are types defined *within* this client module (primarily in types.rs)
// that consumers of the client module (e.g., handlers) will need.
pub use self::types::{ // Explicit self for clarity
    HealthStatus,
    AuthUserResponse, // The one with the role field, as decided
    StreamEvent,
    ClientCharacterDataForClient,
    RegisterPayload, // CLI specific payload for registration
    AdminUserListResponse,
    AdminUserDetailResponse,
    UpdateUserRoleRequest,
    // Json<T> // Not typically part of public API unless methods return it directly and it's a client-specific Json wrapper
    // NonStreamingResponse // This is an internal detail for response handling, not for public consumption
};

// Note: Types from `scribe_backend` (like `LoginPayload`, `User`, `Chat`, `ChatMessage`, etc.)
// that are used in `HttpClient` method signatures are usually imported directly
// by the code calling the client methods (e.g., in `handlers.rs`).
// Re-exporting them here can be a convenience but also tightly couples
// this module's public API to backend specifics. For now, we'll assume
// consumers will import them directly from `scribe_backend::models::*` as needed.