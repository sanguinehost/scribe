#![cfg(test)]
use super::*; // Import items from parent module (logging.rs)

#[test]
fn test_init_subscriber_runs() {
    // This test primarily ensures the function can be called without panicking.
    // It doesn't verify the logger output, which is harder in unit tests.
    // We expect it might print info during test runs if RUST_LOG isn't set.
    init_subscriber();
    // No panic means success for this basic test.
}