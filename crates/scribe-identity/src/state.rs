use std::sync::Arc;
use crate::auth::token_service::TokenService;
use crate::auth::user_store::Backend as AuthBackend;
use crate::db::DbPool;

/// Minimal state required for authentication and identity middleware
#[derive(Clone)]
pub struct AuthAppState {
    pub pool: DbPool,
    pub auth_backend: Arc<AuthBackend>,
    pub token_service: Option<Arc<TokenService>>,
}

impl AuthAppState {
    pub fn new(pool: DbPool, auth_backend: Arc<AuthBackend>, token_service: Option<Arc<TokenService>>) -> Self {
        Self {
            pool,
            auth_backend,
            token_service,
        }
    }
}
