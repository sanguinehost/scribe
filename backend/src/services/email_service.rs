use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_ses::{
    Client as SesClient, types::Body, types::Content, types::Destination, types::Message,
};
use std::error::Error as StdError;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info};

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
        let verification_link = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

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
    client: SesClient,
    base_url: String,
    from_email: String,
}

impl SesEmailService {
    /// Create a new SES email service
    pub async fn new(base_url: String, from_email: String) -> Result<Self, EmailError> {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

        let client = SesClient::new(&config);

        Ok(Self {
            client,
            base_url,
            from_email,
        })
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
        let verification_link = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

        let subject = "Verify your Sanguine Scribe account";
        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to Sanguine Scribe</h1>
                </div>
                
                <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
                    <h2 style="color: #333; margin-top: 0;">Hi {}!</h2>
                    
                    <p>Thank you for signing up for Sanguine Scribe. To complete your registration and start your journey into creative writing with AI, please verify your email address.</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email Address</a>
                    </div>
                    
                    <p>If the button above doesn't work, you can also click on this link:</p>
                    <p style="word-break: break-all; color: #667eea;"><a href="{}" style="color: #667eea;">{}</a></p>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    
                    <p style="font-size: 14px; color: #666;">
                        This verification link will expire in 24 hours. If you didn't create an account with us, you can safely ignore this email.
                    </p>
                    
                    <p style="font-size: 14px; color: #666;">
                        Best regards,<br>
                        The Sanguine Scribe Team
                    </p>
                </div>
            </body>
            </html>
            "#,
            username, verification_link, verification_link, verification_link
        );

        let text_body = format!(
            "Hi {}!\n\nThank you for signing up for Sanguine Scribe. To complete your registration, please verify your email address by clicking the link below:\n\n{}\n\nThis link will expire in 24 hours. If you didn't create an account with us, you can safely ignore this email.\n\nBest regards,\nThe Sanguine Scribe Team",
            username, verification_link
        );

        let destination = Destination::builder().to_addresses(to_email).build();

        let subject_content = Content::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .map_err(|e| {
                EmailError::ConfigurationError(format!("Failed to build subject: {}", e))
            })?;

        let html_content = Content::builder()
            .data(html_body)
            .charset("UTF-8")
            .build()
            .map_err(|e| {
                EmailError::ConfigurationError(format!("Failed to build HTML content: {}", e))
            })?;

        let text_content = Content::builder()
            .data(text_body)
            .charset("UTF-8")
            .build()
            .map_err(|e| {
                EmailError::ConfigurationError(format!("Failed to build text content: {}", e))
            })?;

        let body = Body::builder()
            .html(html_content)
            .text(text_content)
            .build();

        let message = Message::builder()
            .subject(subject_content)
            .body(body)
            .build();

        match self
            .client
            .send_email()
            .source(&self.from_email)
            .destination(destination)
            .message(message)
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    to_email = %to_email,
                    username = %username,
                    "Successfully sent verification email via AWS SES"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    to_email = %to_email,
                    username = %username,
                    error = %e,
                    error_debug = ?e,
                    error_source = ?e.source(),
                    "Failed to send verification email via AWS SES"
                );
                Err(EmailError::SendFailed(format!(
                    "AWS SES error: {} (source: {:?})",
                    e,
                    e.source()
                )))
            }
        }
    }
}

/// Create an email service based on environment configuration
pub async fn create_email_service(
    app_env: &str,
    base_url: String,
    from_email: Option<String>,
) -> Result<Arc<dyn EmailService + Send + Sync>, EmailError> {
    match app_env {
        "production" | "staging" => {
            info!("Creating SES email service for {}", app_env);
            let from_email = from_email.ok_or_else(|| {
                EmailError::ConfigurationError(format!(
                    "FROM_EMAIL environment variable is required for {}",
                    app_env
                ))
            })?;
            let service = SesEmailService::new(base_url, from_email).await?;
            Ok(Arc::new(service))
        }
        _ => {
            info!("Creating logging email service for development");
            Ok(Arc::new(LoggingEmailService::new(base_url)))
        }
    }
}
