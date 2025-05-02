---
description: 
globs: 
alwaysApply: true
---

Keep chats under 200k tokens. If you reach that limit, complete your current subtask with a summary of what you have done and ask for a new subtask.

Prefer creating several smaller subtasks instead of one large one.

If you are having difficulties making edits (repeated failure), just provide the entire codeblock or even entire file back instead.

The user prefers you just 'do it' instead of constantly asking him to run commands for you.

When committing, use conventional commit style. Do not use backticks and for multiple lines you can use several -m in sequence.

Follow this TDD-focused process for all changes:

1.  **Analyze & Plan:**
    * Understand the request and problem.
    * Consult relevant `/docs` (Architecture, Implementation Plan, etc.).
    * Read existing code – no assumptions.
    * Plan the solution using clear abstractions.

2.  **Test First (TDD):**
    * Write comprehensive tests (unit, integration, API) for the planned abstractions *before* implementation.
    * Cover success, failure, and edge cases.

3.  **Implement & Iterate:**
    * Write minimal, clean code to pass tests for one abstraction at a time.
    * Refactor for clarity and best practices.
    * Repeat iteratively until the feature/fix is complete.

4.  **Verify & Document:**
    * Ensure the code meets the project's Definition of Done (passing tests, works with real DBs/APIs).
    * Update code comments and relevant project documentation.

**Key Principles:** Prioritize Abstraction & TDD. Consult Docs. Iterate Incrementally.