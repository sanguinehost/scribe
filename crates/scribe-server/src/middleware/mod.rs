// backend/src/middleware/mod.rs
// Middleware modules

pub mod auth_middleware;
pub mod capture_user;
pub mod llm_security;
pub mod plan_enforcement;
pub mod rate_limit;

pub use rate_limit::{
    create_template_rate_limiter, credit_check_middleware, credit_purchase_rate_limit_middleware,
    rate_limit_logger, security_headers, subscription_rate_limit_middleware,
    template_rate_limit_middleware, webhook_rate_limit_middleware, SimpleRateLimiter,
};

#[cfg(feature = "payment")]
pub use rate_limit::soft_limit_enforcement_middleware;

pub use llm_security::{
    llm_security_middleware, security_headers_middleware, LlmRateLimiter, RateLimitError,
};

pub use plan_enforcement::{
    plan_enforcement_middleware, with_enforcement_config, EnforcementConfig,
};

pub use auth_middleware::unified_login_required;
pub use capture_user::{capture_user_id_middleware, PrivacySafeUserId};
