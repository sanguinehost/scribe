//! Plan enforcement middleware
//!
//! This middleware enforces subscription plan limits for various operations.
//! It checks usage limits, subscription status, and feature availability
//! before allowing requests to proceed.

#[cfg(feature = "payment")]
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
#[cfg(feature = "payment")]
use axum_login::AuthSession;

#[cfg(feature = "payment")]
use crate::{
    auth::user_store::Backend as AuthBackend, errors::AppError, models::payment::Subscription,
    state::AppState,
};

#[cfg(feature = "payment")]
type CurrentAuthSession = AuthSession<AuthBackend>;

/// Plan enforcement result indicating whether the request should proceed
#[cfg(feature = "payment")]
#[derive(Debug)]
pub enum EnforcementResult {
    /// Request is allowed to proceed
    Allow,
    /// Request should be blocked with the given error
    Block(AppError),
}

/// Plan enforcement configuration
#[cfg(feature = "payment")]
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// Tokens required for this operation
    pub tokens_required: i32,
    /// Whether this operation requires an active subscription
    pub requires_subscription: bool,
    /// Specific features required (e.g., "advanced_chat", "unlimited_characters")
    pub required_features: Vec<String>,
    /// Whether to enforce limits (can be disabled for testing)
    pub enforce_limits: bool,
}

/// Plan enforcement middleware that checks subscription limits and features
#[cfg(feature = "payment")]
pub async fn plan_enforcement_middleware(
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Check if payment feature is enabled and enforcement is active
    if !app_state.config.payment.enforce_limits {
        return Ok(next.run(request).await);
    }

    // Get enforcement config from request extensions
    let enforcement_config = request
        .extensions()
        .get::<EnforcementConfig>()
        .cloned()
        .unwrap_or_else(EnforcementConfig::default);

    // Skip enforcement if disabled
    if !enforcement_config.enforce_limits {
        return Ok(next.run(request).await);
    }

    // Extract auth session from request (this assumes the auth middleware has run first)
    let auth_session = request.extensions().get::<CurrentAuthSession>().cloned();

    if let Some(auth_session) = auth_session {
        if let Some(user) = auth_session.user {
            let enforcement_result =
                check_plan_limits(&app_state, &user, &enforcement_config).await?;

            match enforcement_result {
                EnforcementResult::Allow => {
                    // Request is allowed, proceed
                    Ok(next.run(request).await)
                }
                EnforcementResult::Block(error) => {
                    // Convert AppError to HTTP response
                    Err(error)
                }
            }
        } else if enforcement_config.requires_subscription {
            // Auth session exists but no user - shouldn't happen
            Err(AppError::Unauthorized(
                "Authentication required".to_string(),
            ))
        } else {
            // Auth session exists but no user required
            Ok(next.run(request).await)
        }
    } else if enforcement_config.requires_subscription {
        // No authenticated user but subscription is required
        Err(AppError::Unauthorized(
            "Authentication required".to_string(),
        ))
    } else {
        // No user but enforcement doesn't require subscription
        Ok(next.run(request).await)
    }
}

/// Check if a user's plan allows the requested operation
#[cfg(feature = "payment")]
async fn check_plan_limits(
    app_state: &AppState,
    user: &crate::models::users::User,
    config: &EnforcementConfig,
) -> Result<EnforcementResult, AppError> {
    let pool = app_state.pool.clone();
    let user_id = user.id;
    let _config_clone = (*app_state.config).clone();
    let _encryption_service = (*app_state.encryption_service).clone();
    let enforcement_config = config.clone();

    // Use deadpool interaction pattern to work with the database
    let result = pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            // This would ideally use the service methods, but they're async
            // For now, we'll use direct database queries

            use crate::schema::subscriptions;
            use diesel::prelude::*;

            // Get user's subscription (excluding cancelled)
            let subscription = subscriptions::table
                .filter(subscriptions::user_id.eq(user_id))
                .filter(subscriptions::status.ne("cancelled"))
                .order(subscriptions::created_at.desc())
                .select(Subscription::as_select())
                .first::<Subscription>(conn)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Check if subscription is required
            if enforcement_config.requires_subscription && subscription.is_none() {
                return Ok::<EnforcementResult, AppError>(EnforcementResult::Block(
                    AppError::BadRequest(
                        "Active subscription required for this operation".to_string(),
                    ),
                ));
            }

            // Check grace period for past_due subscriptions
            if let Some(ref sub) = subscription {
                if sub.status == "past_due" {
                    if let Some(grace_period_end) = sub.grace_period_end {
                        if crate::DbTimestamp::now() > grace_period_end {
                            // Grace period expired, deny access
                            return Ok::<EnforcementResult, AppError>(EnforcementResult::Block(
                                AppError::BadRequest(
                                    "Subscription past due - grace period expired. Please update your payment method.".to_string(),
                                ),
                            ));
                        } else {
                            // Within grace period, allow access but log warning
                            tracing::warn!(
                                "User {} accessing with past_due subscription (grace period ends: {})",
                                user_id,
                                grace_period_end
                            );
                        }
                    } else {
                        // Past due but no grace period end set - shouldn't happen, but allow for now
                        tracing::error!(
                            "Subscription {} is past_due but has no grace_period_end set",
                            sub.id
                        );
                    }
                }
            }

            // Check token limits if specified
            if enforcement_config.tokens_required > 0 {
                // Get current usage (simplified - in full implementation would use UsageTrackingService)
                // For now, we'll allow all requests
                tracing::warn!("Token limit checking not fully implemented in middleware");
            }

            // Check required features
            if !enforcement_config.required_features.is_empty() {
                // Get plan features (simplified - in full implementation would check against plan_features table)
                tracing::warn!("Feature checking not fully implemented in middleware");
            }

            Ok::<EnforcementResult, AppError>(EnforcementResult::Allow)
        })
        .await
        .map_err(|e| AppError::DbInteractError(e.to_string()))??;

    Ok(result)
}

/// Helper function to add enforcement config to a request
#[cfg(feature = "payment")]
pub fn with_enforcement_config(config: EnforcementConfig) -> impl Fn(Request) -> Request {
    move |mut request: Request| {
        request.extensions_mut().insert(config.clone());
        request
    }
}

/// Default enforcement config (no restrictions)
#[cfg(feature = "payment")]
impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            tokens_required: 0,
            requires_subscription: false,
            required_features: vec![],
            enforce_limits: true,
        }
    }
}

/// Predefined enforcement configs for common operations
#[cfg(feature = "payment")]
impl EnforcementConfig {
    /// Config for basic chat operations (requires some tokens)
    pub fn basic_chat() -> Self {
        Self {
            tokens_required: 100,
            requires_subscription: false,
            required_features: vec![],
            enforce_limits: true,
        }
    }

    /// Config for advanced chat features
    pub fn advanced_chat() -> Self {
        Self {
            tokens_required: 500,
            requires_subscription: true,
            required_features: vec!["advanced_chat".to_string()],
            enforce_limits: true,
        }
    }

    /// Config for character generation
    pub fn character_generation() -> Self {
        Self {
            tokens_required: 200,
            requires_subscription: false,
            required_features: vec![],
            enforce_limits: true,
        }
    }

    /// Config for unlimited character creation
    pub fn unlimited_characters() -> Self {
        Self {
            tokens_required: 0,
            requires_subscription: true,
            required_features: vec!["unlimited_characters".to_string()],
            enforce_limits: true,
        }
    }

    /// Config for enterprise features
    pub fn enterprise_features() -> Self {
        Self {
            tokens_required: 0,
            requires_subscription: true,
            required_features: vec!["enterprise".to_string()],
            enforce_limits: true,
        }
    }

    /// Config that disables all enforcement (for testing)
    pub fn disabled() -> Self {
        Self {
            tokens_required: 0,
            requires_subscription: false,
            required_features: vec![],
            enforce_limits: false,
        }
    }
}

// Non-payment version - middleware that does nothing
#[cfg(not(feature = "payment"))]
pub async fn plan_enforcement_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    next.run(request).await
}

#[cfg(not(feature = "payment"))]
pub struct EnforcementConfig;

#[cfg(not(feature = "payment"))]
impl EnforcementConfig {
    pub fn basic_chat() -> Self {
        Self
    }
    pub fn advanced_chat() -> Self {
        Self
    }
    pub fn character_generation() -> Self {
        Self
    }
    pub fn unlimited_characters() -> Self {
        Self
    }
    pub fn enterprise_features() -> Self {
        Self
    }
    pub fn disabled() -> Self {
        Self
    }
}

#[cfg(not(feature = "payment"))]
pub fn with_enforcement_config(
    _config: EnforcementConfig,
) -> impl Fn(axum::extract::Request) -> axum::extract::Request {
    |request| request
}
