//! Payment processing services
//! 
//! This module contains all payment-related services, gated behind the "payment" feature flag.
//! When the payment feature is disabled, this module is completely excluded from compilation.

#[cfg(feature = "payment")]
pub mod paddle_service;

#[cfg(feature = "payment")]
pub mod subscription_service;

#[cfg(feature = "payment")]
pub mod usage_tracking_service;

#[cfg(feature = "payment")]
pub use paddle_service::PaddleService;

#[cfg(feature = "payment")]
pub use subscription_service::SubscriptionService;

#[cfg(feature = "payment")]
pub use usage_tracking_service::UsageTrackingService;