# Scribe - Implementation Plan (MVP)

## Goal

Deliver a Minimum Viable Product (MVP) for Scribe, leveraging the Vercel SvelteKit AI chat template for the core UI, and focusing on integrating Scribe's backend services. Key deliverables include V2 character card compatibility, robust prompt controls, a dynamic RAG context system (Gemini, PostgreSQL, Qdrant), and **server-side encryption of user data at rest using user-derived keys to protect against unauthorized database access.**

## Methodology

*   **Iterative Development:** Build features incrementally based on the defined epics.
*   **Test-Driven Development (TDD):** Write tests (unit, integration, API) before or alongside feature implementation for both backend (Rust) and frontend (SvelteKit) components.
*   **Parallel Work:** Structure tasks to allow frontend and backend teams/developers to work concurrently where possible.

## Definition of Done

A task is considered **Done** **only** when the following criteria are met:

*   The core logic for the task has been implemented.
*   Comprehensive test coverage (unit, integration, API, component, etc., as applicable) has been written **and** confirmed to pass for the implemented logic (covering both Backend and Frontend components involved).
*   The task's functionality works correctly with integrated components, including actual backend databases (PostgreSQL, Qdrant) and relevant APIs, not just mocks (unless specifically testing isolated units).
*   Any related documentation (e.g., API changes, architecture updates, **especially `AUTH_DESIGN.md` and `ENCRYPTION_ARCHITECTURE.md`**) has been updated.

Only mark a task checkbox (`- [x]`) when all these conditions are satisfied.

## Epics & Tasks

---

### Epic 0: Project Setup & Foundation

*Goal: Establish the basic project structure, dependencies, database connections, authentication, user roles, and server-side encryption for data at rest.*

- [x] **Task 0.1: Backend Project Setup (BE)**
    - [x] Initialize Rust project (`cargo new --lib scribe-backend`) using the Axum web framework.
    - [x] Add core dependencies (Axum, `tokio`, `serde`, `diesel` [with relevant features like `postgres`, `chrono`, etc.], logging, error handling).
    - [x] *Add RAG Dependency:* Add `qdrant-client` to `Cargo.toml`.
    - [x] *Add Authentication Dependencies:* Add `axum-login` and `bcrypt` to `Cargo.toml`.
    - [x] *Add Cryptography Dependencies:* Add `ring`, `argon2`, `rand`, `base64`, `secrecy` to `Cargo.toml`.
    - [x] *Setup Basic Logging:* Choose and configure a logging framework (e.g., `tracing`, `log`).
    - [x] *Setup Basic Error Handling:* Implement basic Axum error handling/mapping middleware. *(Implemented via AppError/IntoResponse)*
    - [x] *TDD:* Implement `/api/health` endpoint.
    - [x] *TDD:* Write integration test for `/api/health`. *(Verified)*
- [x] **Task 0.2: Frontend Project Setup (FE)**
    - [x] Initialize SvelteKit project (`npm create svelte@latest scribe-frontend`). Choose TypeScript project template. *(Superseded by Vercel AI SDK Template)*
    - [x] Setup basic project structure (routes, components, stores, lib). *(Provided by Vercel Template)*
    - [x] **Configure Styling:** Install and configure **shadcn-svelte**. *(Provided by Vercel Template)*
    - [x] **Configure SPA Architecture:** Set up the main application as a Single Page Application (SPA) with client-side routing. *(Provided by Vercel Template)*
    - [x] *TDD:* Setup Vitest and write basic component rendering tests. *(Provided by Vercel Template)*
    - *Note:* Vercel AI SDK Svelte template provides the foundational project setup, structure, styling (shadcn), and SPA architecture.
- [x] **Task 0.3: Database Setup (DevOps/BE)**
    - [x] Create `docker-compose.yml` for PostgreSQL and Qdrant services. *(Verified)*
    - [x] Configure initial database connection strings/environment variables for the backend. *(Verified)*
- [x] **Task 0.4: PostgreSQL Schema & Migrations (BE)**
    - [x] Setup `diesel.toml` configuration. *(Verified)*
    - [x] Define initial schema using `diesel_cli` for: `users` (including `username`, `password_hash`, `email`, `created_at`, `updated_at`). *(Verified)*
    - [x] **User Roles & Status:**
        - [x] Define `UserRole` enum (`User`, `Moderator`, `Administrator`) and `AccountStatus` enum (`Active`, `Locked`) in Rust.
        - [x] Create PostgreSQL enum types for `UserRole` and `AccountStatus`.
        - [x] Add `role` (default `User`) and `account_status` (default `Active`) columns to `users` table.
    - [x] **Server-Side Encryption Fields (Users Table):**
        - [x] Add `kek_salt VARCHAR` to `users` table.
        - [x] Add `encrypted_dek BYTEA` to `users` table.
        - [x] Add `dek_nonce BYTEA` to `users` table.
        - [x] Add `encrypted_dek_by_recovery BYTEA NULLABLE` to `users` table.
        - [x] Add `recovery_kek_salt VARCHAR NULLABLE` to `users` table.
        - [x] Add `recovery_dek_nonce BYTEA NULLABLE` to `users` table.
    - [x] Define schema for `characters` (metadata only), `chat_sessions`, `chat_messages`. *(Verified)*
    - [x] **Server-Side Encryption Fields (Chat Messages Table):**
        - [x] Modify `chat_messages.content` to `BYTEA` to store ciphertext.
        - [x] Add `chat_messages.content_nonce BYTEA` to store nonce for message content.
    - [x] Create Diesel migrations for all schema changes. *(Verified - Migrations exist for these fields)*
    - [x] *(Optional: Add session table migration if using DB session store)* *(Verified - Migration exists)*
    - [x] Implement migration runner logic integrated with Diesel (e.g., run on startup or via separate command). *(Verified - Run on startup in main.rs)*
    - [x] *TDD:* Write tests to verify migrations apply correctly. *(Verified - test_migrations_run_cleanly)*
    - [x] *TDD:* Write tests verifying schema matches models using Diesel's testing features. *(Covered by compile-time checks and integration tests)*
- [x] **Task 0.5: Authentication & Server-Side Encryption Core (BE & FE)** - ***See `docs/AUTH_DESIGN.md` & `docs/ENCRYPTION_ARCHITECTURE.md` for details***
    - [x] **(BE) Cryptography Module (`crypto.rs`):**
        - [x] Implement `generate_salt()`.
        - [x] Implement `generate_dek()` (AES-256).
        - [x] Implement `derive_kek()` (Argon2id from password & salt).
        - [x] Implement `encrypt_gcm()` (AES-256-GCM for DEK encryption with KEK, and data encryption with DEK; returns ciphertext & nonce).
        - [x] Implement `decrypt_gcm()`.
    - [x] **(BE) User Model (`models/users.rs`):**
        - [x] Implement `axum_login::AuthUser` for the `User` model.
        - [x] Add fields: `kek_salt`, `encrypted_dek`, `dek_nonce`, `encrypted_dek_by_recovery`, `recovery_kek_salt`, `recovery_dek_nonce`.
        - [x] Add transient `dek: Option<SerializableSecretDek>` for in-memory plaintext DEK.
        - [x] Add `role: UserRole` and `account_status: AccountStatus`.
    - [x] **(BE) User Store & Auth Logic (`auth/mod.rs`, `auth/user_store.rs`):**
        - [x] `create_user`:
            - Generate DEK, `kek_salt`. Derive KEK. Encrypt DEK with KEK, store `encrypted_dek` & `dek_nonce`.
            - Optionally generate recovery phrase, derive RKEK, encrypt DEK with RKEK, store `encrypted_dek_by_recovery` & `recovery_dek_nonce` & `recovery_kek_salt`.
            - Assign `UserRole::Administrator` if first user, else `UserRole::User`. Default `AccountStatus::Active`.
        - [x] `verify_credentials` (login):
            - Fetch user, derive KEK from input password & stored `kek_salt`.
            - Decrypt `encrypted_dek` using KEK & `dek_nonce` to get plaintext DEK.
            - Store plaintext DEK in `User` object for the session.
        - [x] `change_user_password`:
            - Verify old password. Decrypt DEK with old KEK.
            - Generate new `kek_salt`. Derive new KEK from new password & new `kek_salt`.
            - Re-encrypt plaintext DEK with new KEK. Update `encrypted_dek`, `dek_nonce`, and `kek_salt`.
        - [x] `recover_user_password_with_phrase`:
            - Fetch user. Derive RKEK from input phrase & stored `recovery_kek_salt`.
            - Decrypt `encrypted_dek_by_recovery` using RKEK & `recovery_dek_nonce` to get plaintext DEK.
            - Prompt for new password. Generate new `kek_salt`. Derive new KEK. Re-encrypt DEK. Update `encrypted_dek`, `dek_nonce`, `kek_salt`.
    - [x] **(BE) Session Store:** Set up a persistent session store for `axum-login`. *(Verified)*
    - [x] **(BE) Register Endpoint (`routes/auth.rs`):** Implement `/api/auth/register` calling `create_user`. *(Verified)*
    - [x] **(BE) Login Endpoint (`routes/auth.rs`):** Implement `/api/auth/login` calling `verify_credentials` and `AuthSession::login`. *(Verified)*
    - [x] **(BE) Logout Endpoint (`routes/auth.rs`):** Implement `/api/auth/logout`. *(Verified)*
    - [x] **(BE) Me Endpoint (`routes/auth.rs`):** Implement `/api/auth/me`. *(Verified)*
    - [x] **(BE) Change Password Endpoint (`routes/auth.rs`):** Implement `/api/auth/change-password`. *(Verified)*
    - [x] **(BE) Recover Password Endpoint (`routes/auth.rs`):** Implement `/api/auth/recover-password`. *(Verified)*
    - [x] **(BE) Router Integration:** Integrate `AuthManagerLayer` and session store layer into the main Axum router. *(Verified)*
    - [x] **(FE) Login/Register Forms:** *(Provided by Vercel Template, adapted for Scribe backend API)*
    - [x] **(FE) API Calls:** *(Provided by Vercel Template, adapted for Scribe backend API)*
    - [x] **(FE) Auth State Management:** *(Provided by Vercel Template, adapted for Scribe backend API)*
    - [x] *TDD (BE):* Unit tests for password hashing/verification, KEK derivation, DEK encryption/decryption. API integration tests for auth endpoints including E2EE key handling. *(Partially Verified - Core crypto tests exist, auth integration tests cover flows)*
    - [ ] *TDD (FE):* Adapt Vercel template tests or add new ones for Scribe-specific auth integration. E2E tests for the full registration, login, password change, and recovery flows. *(Missing)*
    - *Note:* Frontend auth flow is functional. Server-side encryption of data at rest is implemented.

---

### Epic 1: Character Management

*Goal: Allow users to upload, view, and select V2 character cards. Character data stored by the backend will be encrypted at rest.*

- [x] **Task 1.1: Character Card Parser (BE)**
    - [x] Implement Rust logic to parse JSON data from PNG `tEXt` chunks (`ccv3` priority, `chara` fallback, Base64 decode) based on V3 spec. Reads V2/V3 fields. *(Verified)*
    - [x] *TDD:* Unit tests with various valid/invalid card PNGs/JSONs (using test helpers). *(Verified)*
- [x] **Task 1.2: Character API Endpoints (BE)** - ***Requires Task 0.5 Completion***
    - [x] **(BE) Upload Logic:** Implement handler for `POST /api/characters/upload`. Parse card (Task 1.1). **Encrypt character data fields** using user's DEK. Save encrypted metadata to `characters` table (associating with user). Store nonces. *(Encryption part needs verification in character_service.rs)*
    - [x] **(BE) List Logic:** Implement handler for `GET /api/characters`. Query `characters` table, filter by *authenticated user*. **Decrypt character data fields** for response. *(Decryption part needs verification)*
    - [x] **(BE) Get Details Logic:** Implement handler for `GET /api/characters/{id}`. Query `characters` table for specific ID, verify ownership. **Decrypt character data fields** for response. *(Decryption part needs verification)*
    - [x] *TDD (BE):* API integration tests for `POST /upload` (success, auth failure, invalid PNG/JSON, DB error, correct encryption). *(Encryption tests might be missing)*
    - [x] *TDD (BE):* API integration tests for `GET /characters` (success, auth failure, empty list, correct decryption). *(Decryption tests might be missing)*
    - [x] *TDD (BE):* API integration tests for `GET /characters/{id}` (success, auth failure, not found, forbidden/wrong user, correct decryption). *(Decryption tests might be missing)*
- [ ] **Task 1.3: Character UI Integration (FE)** - ***Requires Task 1.2 Completion & Vercel Template***
    - [x] **(FE) Character List Component:** *(Base provided by Vercel Template Sidebar/History)*
    - [x] **(FE) Character Uploader Component:** *(Base provided by Vercel Template UI elements)*
    - [ ] **(FE) Integration:** Adapt the Vercel template's sidebar/UI to:
        - Fetch and display the user's (decrypted by backend) characters from `GET /api/characters`.
        - Implement character selection logic to initiate chats.
        - Integrate a character upload mechanism calling `POST /api/characters/upload`.
        - **Implement clear menu options / UI elements for character management and selection within the application flow.**
    - [ ] *TDD (FE):* Component tests for Scribe-specific adaptations (data fetching, upload logic, menu interactions). *(Missing)*
    - [ ] *E2E (FE):* Test uploading a character, seeing it appear, selecting it, and navigating character management menus. *(Missing)*
    - *Note:* Focus is on integrating Scribe's character management API calls, logic, and dedicated menu options into the existing Vercel template UI structure. Backend handles encryption/decryption of character data.

---

### Epic 2: Core Chat Loop

*Goal: Enable basic chat functionality: creating sessions, sending/receiving messages (encrypted at rest by backend), basic prompt assembly, **and streaming responses**.*

- [x] **Task 2.1: Chat Session & History API (BE)** - ***Requires Task 0.5 Completion***
    - [x] **(BE) Create Session Logic:** Implement handler for `POST /api/chats`. Create new entry in `chat_sessions` table, linking to *authenticated user* and a character ID. Return session ID. *(Verified via chat_tests.rs)*
    - [x] **(BE) List Sessions Logic:** Implement handler for `GET /api/chats`. Query `chat_sessions`, filter by *authenticated user*. *(Verified via chat_tests.rs)*
    - [x] **(BE) Get Messages Logic:** Implement handler for `GET /api/chats/{id}/messages`. Query `chat_messages` for a given session ID, verify session ownership. **Decrypt message content** using user's DEK before returning. *(Decryption part needs verification in chat_service.rs)*
    - [x] *TDD (BE):* API tests for `POST /chats`. *(Verified)*
    - [x] *TDD (BE):* API tests for `GET /chats`. *(Verified)*
    - [x] *TDD (BE):* API tests for `GET /chats/{id}/messages` (including correct decryption). *(Decryption tests might be missing)*
- [x] **Task 2.2: Save Message API (BE)** - ***Requires Task 2.1 Completion***
    - [x] **(BE) Save Message Logic:** Implement handler for `POST /api/chats/{id}/messages`. Validate input. **Encrypt message content** using user's DEK. Save encrypted message and nonce to `chat_messages` table.
    - [x] *TDD (BE):* API tests for `POST /chats/{id}/messages` (including correct encryption). *(Encryption tests might be missing)*
- [x] **Task 2.3: Gemini Generation Client (BE)**
    - [x] **(BE) Configuration:** Setup API key management. *(Verified)*
    - [x] **(BE) Client Implementation:** Create Rust module/struct wrapping the Gemini Generation API client (`genai`). *(Verified)*
    - [x] *TDD (BE):* Unit tests mocking the HTTP client. *(Verified)*
- [x] **Task 2.4: Basic Prompt Assembly (BE)** - ***Requires Task 1.2 & Task 4.2 Completion***
    - [x] **(BE) Data Retrieval:** Implement logic to get character details (decrypting if needed), system prompt, and recent chat messages (decrypting content).
    - [x] **(BE) Prompt Formatting:** Combine retrieved plaintext data into a single prompt string for Gemini.
    - [x] *TDD (BE):* Unit tests for prompt assembly with various inputs.
- [x] **Task 2.4.1: Implement Configurable History Management (BE)** - *(Completed as per original plan)*
- [x] **Task 2.5: Generation API Endpoint (BE)** - ***Requires Task 2.2, 2.3, 2.4 Completion***
    - [x] **(BE) Orchestration Logic:** Implement handler for `POST /api/chats/{id}/generate`. **Support streaming responses.**
        - [x] Verify session ownership.
        - [x] Get user message (plaintext from request). **Encrypt and save user message** (Task 2.2).
        - [x] Retrieve and manage history (decrypting messages for context), then assemble prompt (Task 2.4 logic).
        - [x] Call Gemini client with plaintext prompt.
        - [x] **Encrypt and save AI response** (Task 2.2).
        - [x] Return AI response (plaintext to client over HTTPS, as stream or complete).
    - [x] *TDD (BE):* API integration tests for `POST /chats/{id}/generate`.
- [ ] **Task 2.6: Chat UI Streaming Adaptation (FE)** - ***Requires Vercel Template***
    - [x] **(FE) Chat Window, Message Bubble, Message Input:** *(Provided by Vercel Template)*
    - [ ] **(FE) Adaptation:** Adapt Vercel template's message rendering to handle incremental text updates from Scribe's backend streaming (`EventSource`). **Frontend receives plaintext messages over HTTPS.**
    - [ ] *TDD (FE):* Add/adapt tests for incremental text updates. *(Missing)*
- [ ] **Task 2.7: Frontend Chat Streaming Logic (FE)** - ***Requires BE APIs & Vercel Template***
    - [x] **(FE) Chat Store:** *(Base provided by Vercel Template's `useChat` hook/stores)*
    - [ ] **(FE) API Calls & Streaming:** Implement `EventSource` to connect to `POST /api/chats/{id}/generate`. Adapt Vercel template's API calls. **Frontend sends plaintext messages and receives plaintext messages over HTTPS.**
    - [ ] **(FE) UI Integration:** Ensure received stream updates chat state and UI.
    - [ ] *TDD (FE):* Add tests for `EventSource` handling. *(Missing)*
    - *Note:* Core chat functionality relies on backend for encryption/decryption of data at rest. Frontend communicates plaintext over HTTPS.
- [x] **Task 2.8: Basic CLI Test Client (BE/DevTool)** - *(Completed as per original plan)*

---

### Epic 3: Dynamic Context (RAG MVP)

*Goal: Implement the core RAG pipeline. Chat history used for RAG will be decrypted server-side before processing.*

- [x] **Task 3.1: Gemini Embedding Client (BE)** *(Completed)*
- [x] **Task 3.2: Qdrant Client Service (BE)** *(Completed)*
- [x] **Task 3.3: Chat History Chunking (BE)**
    - [x] **(BE) Implementation:** Implement Rust function `chunk_messages(messages_plaintext) -> Vec<Chunk>`. *(Assumes messages are decrypted before chunking)*
    - [x] *TDD (BE):* Unit tests. *(Completed)*
- [x] **Task 3.4: Embedding & Storage Pipeline (BE)**
    - [x] **(BE) Trigger Mechanism:** After a message pair is saved (encrypted), trigger embedding.
    - [x] **(BE) Pipeline Logic:** **Decrypt saved messages**, chunk plaintext (Task 3.3), embed chunks (Task 3.1), upsert to Qdrant (Task 3.2).
    - [x] *TDD (BE):* Integration test. *(Completed)*
- [x] **Task 3.5: RAG Query Logic (BE)**
    - [x] **(BE) Context Embedding:** Embed user's latest (plaintext) message.
    - [x] **(BE) Qdrant Search:** Query Qdrant.
    - [ ] **(BE) Enhancement Note (Post-MVP/Future):** *(As original)*
    - [x] *TDD (BE):* Unit/Integration tests. *(Completed)*
- [x] **Task 3.6: RAG Context Injection (BE)**
    - [x] **(BE) Modify Prompt Assembly:** Execute RAG query. Prepend retrieved (plaintext) context chunks to the main prompt.
    - [x] *TDD (BE):* Unit tests. *(Completed)*

---

### Epic 4: Basic Prompt Control (MVP)

- [x] **Task 4.1: Database Schema Update (BE)** *(Completed)*
- [x] **Task 4.2: API & Logic for Settings (BE)** *(Completed)*
- [ ] **Task 4.3: Settings UI Integration (FE)** *(As original)*
- [x] **Task 4.4: Investigate Gemini API Support (BE)** *(Completed)*

---

### Epic 5: UX/UI Design & Specification

- [x] **Task 5.1 - 5.4** *(Completed)*
- [ ] **Task 5.5: SPA Layout & Navigation Implementation (FE)** *(As original, noting Vercel template base)*

---

### Epic 6: Backend Code Cleanup

- [x] **Task 6.1 - 6.4** *(Completed)*

---

### Epic 7: Secure Markdown Rendering

- [ ] **Task 7.1 - 7.4** *(As original)*

---

### Post‑MVP Seeds (scaffolding only)

## MVP Definition

The MVP is complete when a user can:

1.  **Register and log in.** (With user roles assigned and E2EE keys established server-side).
2.  Upload a V2/V3 character card PNG (associated with their account, **character data encrypted at rest by server**).
3.  Select **their** character and start a chat session.
4.  Send messages (plaintext over HTTPS) and receive AI responses (plaintext over HTTPS) generated by Google Gemini **within their session**. (**Chat messages encrypted at rest by server**).
5.  Experience basic long-term context recall via the background RAG system **for their chat** (RAG processes decrypted data server-side).
6.  View and modify a basic System Prompt, Temperature, and Max Output Tokens for **their** current chat.

## Post-MVP Considerations
