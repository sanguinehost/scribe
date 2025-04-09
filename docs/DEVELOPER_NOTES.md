# Scribe - Developer Quick Notes

This document provides a quick reference for key technical decisions, architectural points, and implementation considerations based on the `CONCEPT.md`, `ARCHITECTURE.md`, and `IMPLEMENTATION_PLAN.md`.

## Key Reminders

1.  **Core Tech Stack:**
    *   **Backend:** Rust with Axum (leverage `async`/`tokio`).
    *   **Frontend:** SvelteKit with TypeScript.
    *   **Relational DB:** PostgreSQL (using the `Diesel` ORM).
    *   **Vector DB:** Qdrant.
    *   **Environment:** Use `docker-compose` (Task 0.3) for local DB setup early on.

2.  **Strict Definition of Done:**
    *   Refer to `IMPLEMENTATION_PLAN.md`.
    *   Tasks require: Implementation + **Passing Tests** (Unit, Integration, API, Component) + Works with **Real Databases** + **Updated Docs**.
    *   No shortcuts on testing!

3.  **Character Card Parsing:**
    *   Task 1.1 involves reading V2 data from PNG `tEXt` chunks (`chara` key, Base64 encoded JSON).
    *   Ensure the parsing logic correctly handles this specific format (reference `src/character-card-parser.js` if available/needed).

4.  **RAG Implementation Details (MVP Focus - Epic 3):**
    *   **Chunking Strategy (Task 3.3):** Requires careful consideration and possibly experimentation.
    *   **Async Pipeline (Task 3.4):** Embedding/storage **must** be asynchronous (`tokio::spawn` suggested) to avoid blocking chat.
    *   **Context Injection (Task 3.6):** Formatting and placement of retrieved context (`[Retrieved Memories]...`) in the final prompt is crucial for effectiveness.

5.  **Configuration & Secrets:**
    *   Manage API keys (Google Gemini) and database connection strings securely (Environment Variables recommended).
    *   **Do not hardcode secrets.**

6.  **Authentication (Task 0.5):**
    *   Implement JWT logic carefully.
    *   Pay attention to secure JWT storage on the frontend (HttpOnly cookies suggested).
    *   Auth middleware is essential for protecting backend routes.

7.  **Test-Driven Development (TDD):**
    *   The implementation plan relies heavily on TDD.
    *   Write tests *before* or *alongside* implementation. This is crucial for correctness and maintainability, especially with Rust.

**In Short:** Adhere to the tech stack, follow the strict Definition of Done, pay close attention to character parsing and RAG details, manage secrets correctly, and embrace TDD. 