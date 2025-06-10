use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};

/// Errors that can occur when sending emails
#[derive(Error, Debug)]
pub enum EmailError {
    #[error("Failed to send email: {0}")]
    SendFailed(String),
    #[error("Invalid email configuration: {0}")]
    ConfigurationError(String),
}

/// Result type for email operations
pub type EmailResult<T> = Result<T, EmailError>;

/// Trait defining email sending capabilities
#[async_trait]
pub trait EmailService: Send + Sync {
    /// Send an email verification message
    async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> EmailResult<()>;
}

/// Development email service that logs verification links to console
/// instead of sending actual emails
#[derive(Debug, Clone)]
pub struct LoggingEmailService {
    base_url: String,
}

impl LoggingEmailService {
    /// Create a new logging email service
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

#[async_trait]
impl EmailService for LoggingEmailService {
    async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> EmailResult<()> {
        let verification_link = format!("{}/verify-email?token={}", self.base_url, verification_token);
        
        info!(
            to_email = %to_email,
            username = %username,
            verification_link = %verification_link,
            "📧 EMAIL VERIFICATION (DEV MODE) - Click the link below to verify your account:"
        );
        
        println!("\n🔗 EMAIL VERIFICATION LINK for {}:", username);
        println!("   {}", verification_link);
        println!("   (This would normally be sent to: {})\n", to_email);
        
        Ok(())
    }
}

/// Production email service using AWS SES
#[derive(Debug, Clone)]
pub struct SesEmailService {
    _base_url: String,
    // Future: AWS SES client would go here
}

impl SesEmailService {
    /// Create a new SES email service
    pub fn new(base_url: String) -> Self {
        Self {
            _base_url: base_url,
        }
    }
}

#[async_trait]
impl EmailService for SesEmailService {
    async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> EmailResult<()> {
        // TODO: Implement AWS SES integration
        warn!(
            to_email = %to_email,
            username = %username,
            token = %verification_token,
            "SES email service not yet implemented - would send verification email"
        );
        
        error!("SES email service is not yet implemented");
        Err(EmailError::ConfigurationError(
            "SES email service is not yet implemented".to_string(),
        ))
    }
}

/// Create an email service based on environment configuration
pub fn create_email_service(app_env: &str, base_url: String) -> Arc<dyn EmailService + Send + Sync> {
    match app_env {
        "production" => {
            info!("Creating SES email service for production");
            Arc::new(SesEmailService::new(base_url))
        }
        _ => {
            info!("Creating logging email service for development");
            Arc::new(LoggingEmailService::new(base_url))
        }
    }
}