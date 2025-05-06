use crate::error::CliError;
use std::io::{Write, stdin, stdout}; // For reading user input

/// Trait for handling Command Line Input/Output to allow mocking in tests.
pub trait IoHandler {
    // Made pub
    // Changed return type to use crate::error::CliError
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError>;
    fn write_line(&mut self, line: &str) -> Result<(), CliError>;
    /// Writes a string to the output without appending a newline.
    fn write_raw(&mut self, text: &str) -> Result<(), CliError>;
    /// Flushes the underlying output stream.
    fn flush(&mut self) -> Result<(), CliError>;
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

    fn flush(&mut self) -> Result<(), CliError> {
        stdout().flush().map_err(CliError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    // A testable implementation of IoHandler that reads from a string buffer
    // and writes to a string buffer
    struct TestIoHandler {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    
    impl TestIoHandler {
        fn new(input: &str) -> Self {
            Self {
                input: Cursor::new(input.as_bytes().to_vec()),
                output: Vec::new(),
            }
        }
        
        fn output_as_string(&self) -> String {
            String::from_utf8_lossy(&self.output).to_string()
        }
    }
    
    impl IoHandler for TestIoHandler {
        fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
            self.write_raw(prompt)?;
            self.write_raw(" ")?;
            
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut self.input, &mut buf)
                .map_err(CliError::Io)?;
            
            Ok(buf.trim().to_string())
        }
        
        fn write_line(&mut self, line: &str) -> Result<(), CliError> {
            writeln!(&mut self.output, "{}", line).map_err(CliError::Io)?;
            Ok(())
        }
        
        fn write_raw(&mut self, text: &str) -> Result<(), CliError> {
            write!(&mut self.output, "{}", text).map_err(CliError::Io)?;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), CliError> {
            Write::flush(&mut self.output).map_err(CliError::Io)
        }
    }
    
    #[test]
    fn test_read_line() {
        let mut io = TestIoHandler::new("test input\n");
        let result = io.read_line("Prompt:").unwrap();
        assert_eq!(result, "test input");
        assert_eq!(io.output_as_string(), "Prompt: ");
    }
    
    #[test]
    fn test_write_line() {
        let mut io = TestIoHandler::new("");
        io.write_line("Hello, world!").unwrap();
        assert_eq!(io.output_as_string(), "Hello, world!\n");
    }
    
    #[test]
    fn test_write_raw() {
        let mut io = TestIoHandler::new("");
        io.write_raw("No newline").unwrap();
        assert_eq!(io.output_as_string(), "No newline");
    }
    
    #[test]
    fn test_multiple_operations() {
        let mut io = TestIoHandler::new("first\nsecond\n");
        
        let result1 = io.read_line("First prompt:").unwrap();
        io.write_line("You entered:").unwrap();
        io.write_raw(result1.as_str()).unwrap();
        io.write_line("").unwrap();
        
        let result2 = io.read_line("Second prompt:").unwrap();
        io.write_line(&format!("Response: {}", result2)).unwrap();
        
        let expected = "First prompt: You entered:\nfirst\nSecond prompt: Response: second\n";
        assert_eq!(io.output_as_string(), expected);
    }
}
