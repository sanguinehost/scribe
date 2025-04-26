---
description: 
globs: 
alwaysApply: true
---
Follow this TDD-focused process for all Scribe changes:

1.  **Analyze & Plan:**
    * Understand the request and problem.
    * Consult relevant `/docs` (Architecture, Implementation Plan, etc.).
    * Read existing code – no assumptions.
    * Plan the solution using clear abstractions.

2.  **Test First (TDD):**
    * Write comprehensive tests (unit, integration, API) for the planned abstractions *before* implementation.
    * Cover success, failure, and edge cases.

3.  **Implement & Iterate:**
    * Write minimal, clean Rust code to pass tests for one abstraction at a time.
    * Refactor for clarity and best practices.
    * Repeat iteratively until the feature/fix is complete.

4.  **Verify & Document:**
    * Ensure the code meets the project's Definition of Done (passing tests, works with real DBs/APIs).
    * Update code comments and relevant project documentation.

**Key Principles:** Prioritize Abstraction & TDD. Consult Docs. Iterate Incrementally.