use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;

/// Handler function for model settings submenu
pub async fn handle_model_settings_action<H: IoHandler, C: HttpClient>(
    _client: &C, // Not used yet, but keep for consistency
    io_handler: &mut H,
    current_model: &mut String,
) -> Result<(), CliError> {
    // Define the full model names for clarity in prompts/examples
    const FLASH_MODEL: &str = "gemini-2.5-flash-preview-04-17"; // Recommended stable model
    const PRO_PREVIEW_MODEL: &str = "gemini-2.5-pro-preview-05-06"; // Latest paid model with more capabilities
    const EXPERIMENTAL_MODEL: &str = "gemini-2.5-pro-exp-03-25"; // Most likely to hit rate limits

    loop {
        io_handler.write_line("\n--- Model Settings ---")?;
        // Display the current full model name
        io_handler.write_line(&format!(
            "[1] View Current Model (Currently: {current_model})"
        ))?;
        io_handler.write_line("[2] Change Model")?;
        io_handler.write_line("[b] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice:")?;

        match choice.as_str() {
            "1" => {
                // Explicitly confirm the current full model name
                io_handler
                    .write_line(&format!("The current model is set to: {current_model}"))?;
            }
            "2" => {
                // Offer specific model options
                io_handler.write_line("Available models:")?;
                io_handler.write_line(&format!(
                    "[1] {FLASH_MODEL} (RECOMMENDED - stable, less rate limiting)"
                ))?;
                io_handler.write_line(&format!(
                    "[2] {PRO_PREVIEW_MODEL} (more capabilities, may have quota)"
                ))?;
                io_handler.write_line(&format!(
                    "[3] {EXPERIMENTAL_MODEL} (experimental, frequent rate limiting)"
                ))?;
                io_handler.write_line("[4] Custom model name")?;

                let model_choice = io_handler.read_line("Select model (1-4):")?;

                let new_model = match model_choice.trim() {
                    "1" => FLASH_MODEL.to_string(),
                    "2" => PRO_PREVIEW_MODEL.to_string(),
                    "3" => EXPERIMENTAL_MODEL.to_string(),
                    "4" => {
                        let custom_prompt = "Enter the full custom model name:";
                        io_handler.read_line(custom_prompt)?.trim().to_string()
                    }
                    _ => {
                        io_handler.write_line("Invalid selection. No changes made.")?;
                        continue;
                    }
                };

                if new_model.is_empty() {
                    io_handler.write_line("Model name cannot be empty. No changes made.")?;
                } else {
                    // Store the model name
                    *current_model = new_model;
                    tracing::info!(new_model = %current_model, "Chat model updated");
                    io_handler.write_line(&format!("Model updated to: {current_model}"))?;

                    // Add warning for experimental model
                    if current_model == EXPERIMENTAL_MODEL {
                        io_handler.write_line("\nWARNING: You selected the experimental model which is most likely to hit rate limits.")?;
                        io_handler.write_line("If you encounter '429 Too Many Requests' errors, please switch to the Flash model.")?;
                    }
                }
            }
            "b" | "B" => {
                io_handler.write_line("Returning to main menu.")?;
                return Ok(()); // Exit the settings submenu loop
            }
            _ => {
                io_handler.write_line("Invalid choice, please try again.")?;
            }
        }
    }
    // Note: The loop is infinite until 'b' is chosen, so this Ok(()) is unreachable,
    // but needed for the function signature. Loop exit returns Ok explicitly.
}
