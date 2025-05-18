use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;

/// Handler function for checking the backend health status
pub async fn handle_health_check_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nChecking backend health...")?;
    match client.health_check().await {
        Ok(health_status) => {
            io_handler.write_line(&format!("Backend status: {}", health_status.status))?;
            Ok(())
        }
        Err(e) => Err(e), // Error is logged by the main loop caller
    }
}
