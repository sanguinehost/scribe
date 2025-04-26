---
description: 
globs: 
alwaysApply: true
---
When working with external libraries or unfamiliar APIs (especially in Rust):

1.  **Avoid Assumptions:** Do not guess method names, struct fields, or the necessary sequence of operations for external library calls.
2.  **Consult Documentation First:** Before proposing code changes involving external APIs, *actively use available tools* (like `cargo doc` for Rust, or other relevant documentation lookup methods) to verify the correct usage in the official documentation.
3.  **If Tools Are Insufficient, Ask:** If the tools cannot directly provide the necessary API details (e.g., `cargo doc --open` requires user interaction), clearly state what information is needed and ask the user to look it up in the documentation.
4.  **Verify Systematically:** Confirm the existence and correct usage of specific structs, fields, and methods relevant to the task *before* writing code that uses them.
5.  **Learn from Errors:** If a proposed change leads to an error, treat it as a signal to re-consult the documentation for the specific API elements involved, rather than making another assumption.