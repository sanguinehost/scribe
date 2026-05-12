use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("Failed to send email: {0}")]
    SendFailed(String),
    #[error("Invalid email configuration: {0}")]
    ConfigurationError(String),
}

pub type EmailResult<T> = Result<T, EmailError>;

#[async_trait]
pub trait EmailService: Send + Sync {
    async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> EmailResult<()>;
}
