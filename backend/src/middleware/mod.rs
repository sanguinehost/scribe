// backend/src/middleware/mod.rs
// Middleware modules

pub mod llm_security;
pub mod plan_enforcement;
pub mod rate_limit;

pub use rate_limit::{
    SimpleRateLimiter, create_template_rate_limiter, template_rate_limit_middleware,
    rate_limit_logger, security_headers,
    credit_purchase_rate_limit_middleware, subscription_rate_limit_middleware,
    webhook_rate_limit_middleware, credit_check_middleware,
};

#[cfg(feature = "payment")]
pub use rate_limit::soft_limit_enforcement_middleware;

pub use llm_security::{
    LlmRateLimiter, RateLimitError, llm_security_middleware, security_headers_middleware,
};

pub use plan_enforcement::{
    plan_enforcement_middleware, EnforcementConfig, with_enforcement_config,
};
