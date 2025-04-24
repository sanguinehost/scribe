use crate::error::CliError;
use std::io::{stdin, stdout, Write}; // For reading user input

/// Trait for handling Command Line Input/Output to allow mocking in tests.
#[async_trait::async_trait] // Added async_trait if methods become async
pub trait IoHandler { // Made pub
    // Changed return type to use crate::error::CliError
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError>;
    fn write_line(&mut self, line: &str) -> Result<(), CliError>;
    /// Writes a string to the output without appending a newline.
    fn write_raw(&mut self, text: &str) -> Result<(), CliError>;
    // Add other methods if needed, e.g., read_password
}

/// Standard I/O handler using stdin and stdout.
#[derive(Default)] // Added default derive
pub struct StdIoHandler; // Made pub

impl IoHandler for StdIoHandler {
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
        print!("{} ", prompt);
        stdout().flush().map_err(CliError::Io)?;
        let mut input = String::new();
        stdin().read_line(&mut input).map_err(CliError::Io)?;
        Ok(input.trim().to_string())
    }

    fn write_line(&mut self, line: &str) -> Result<(), CliError> {
        println!("{}", line);
        Ok(())
    }

    fn write_raw(&mut self, text: &str) -> Result<(), CliError> {
        print!("{}", text);
        stdout().flush().map_err(CliError::Io)?;
        Ok(())
    }
}