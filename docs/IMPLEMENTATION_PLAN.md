# Scribe - Implementation Plan (MVP)

## Goal

Deliver a Minimum Viable Product (MVP) for Scribe, focusing on the core chat loop, V2 character card compatibility, basic prompt controls, and the foundational dynamic RAG context system using Google Gemini, PostgreSQL, and Qdrant.

## Methodology

*   **Iterative Development:** Build features incrementally based on the defined epics.
*   **Test-Driven Development (TDD):** Write tests (unit, integration, API) before or alongside feature implementation for both backend (Rust) and frontend (SvelteKit) components.
*   **Parallel Work:** Structure tasks to allow frontend and backend teams/developers to work concurrently where possible.

## Definition of Done

A task is considered **Done** **only** when the following criteria are met:

*   The core logic for the task has been implemented.
*   Comprehensive test coverage (unit, integration, API, component, etc., as applicable) has been written **and** confirmed to pass for the implemented logic (covering both Backend and Frontend components involved).
*   The task's functionality works correctly with integrated components, including actual backend databases (PostgreSQL, Qdrant) and relevant APIs, not just mocks (unless specifically testing isolated units).
*   Any related documentation (e.g., API changes, architecture updates, **especially `AUTH_DESIGN.md`**) has been updated.

Only mark a task checkbox (`- [x]`) when all these conditions are satisfied.

## Epics & Tasks

---

### Epic 0: Project Setup & Foundation

*Goal: Establish the basic project structure, dependencies, database connections, and authentication.*

- [ ] **Task 0.1: Backend Project Setup (BE)**
    *   Initialize Rust project (`cargo new --lib scribe-backend`) using the Axum web framework.
    *   Add core dependencies (Axum, `tokio`, `serde`, `diesel` [with relevant features like `postgres`, `chrono`, etc.], `qdrant-client`, logging, error handling). *(Partially complete: missing qdrant-client, advanced logging/error middleware)*
    *   *Add Authentication Dependencies:* Add `axum-login` and `bcrypt` to `Cargo.toml`.
    *   Configure basic logging and error handling middleware.
    *   *TDD:* Implement `/api/health` endpoint and corresponding test. *(Endpoint exists, test status unconfirmed)*
- [ ] **Task 0.2: Frontend Project Setup (FE)**
    *   Initialize SvelteKit project (`npm create svelte@latest scribe-frontend`). Choose Skeleton project with TypeScript.
    *   Setup basic project structure (routes, components, stores, lib).
    *   Configure basic styling (e.g., TailwindCSS or basic CSS).
    *   *TDD:* Basic component rendering tests (e.g., using Vitest).
- [x] **Task 0.3: Database Setup (DevOps/BE)**
    *   Create `docker-compose.yml` for PostgreSQL and Qdrant services.
    *   Configure initial database connection strings/environment variables for the backend.
- [ ] **Task 0.4: PostgreSQL Schema & Migrations (BE)**
    *   Define initial schema using `diesel_cli` and Diesel migrations for: `users`, `characters` (metadata only), `chat_sessions`, `chat_messages`.
    *   *(Optional: Add session table migration if using DB session store)*
    *   Setup `diesel.toml` configuration.
    *   Implement migration runner integrated with Diesel.
    *   *TDD:* Write tests to verify migrations apply correctly and schema matches expectations using Diesel's testing features. *(Migrations exist, schema generated, test status unconfirmed)*
- [ ] **Task 0.5: Authentication (BE & FE)** - ***See `docs/AUTH_DESIGN.md` for details***
    *   **(BE) Implement `AuthUser` Trait:** Implement `axum_login::AuthUser` for the `User` model.
    *   **(BE) Implement User Store Logic:** Create functions to get user by ID, get user by username, and verify credentials (using `bcrypt`).
    *   **(BE) Implement Session Store:** Set up a persistent session store for `axum-login` (e.g., database-backed, potentially requiring a Diesel adapter).
    *   **(BE) Implement API Endpoints:** Create `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, and optionally `/api/auth/me` handlers using `axum-login`'s `AuthSession`.
    *   **(BE) Configure Axum Layers:** Integrate `AuthManagerLayer` and session store layer into the main Axum router.
    *   **(FE) Create Login/Register Pages:** Implement Svelte components for login/register forms.
    *   **(FE) Implement API Calls:** Call backend auth endpoints from the frontend.
    *   **(FE) Handle Auth State:** Manage user authentication state in the frontend (e.g., using Svelte stores, handling redirects based on login status).
    *   *TDD:* (BE) Unit tests for hashing, user store logic, API tests for auth endpoints. (FE) Component tests for login/register forms, potentially E2E tests for login flow.

---

### Epic 1: Character Management

*Goal: Allow users to upload, view, and select V2 character cards.*

- [x] **Task 1.1: Character Card Parser (BE)**
    *   Implement Rust logic to parse JSON data from PNG `tEXt` chunks (`ccv3` priority, `chara` fallback, Base64 decode) based on V3 spec. Reads V2/V3 fields.
    *   *TDD:* Unit tests with various valid/invalid card PNGs/JSONs (using test helpers).
- [ ] **Task 1.2: Character API Endpoints (BE)** - ***Requires Task 0.5 Completion***
    *   `POST /api/characters/upload`: Accepts PNG data, uses parser, **saves character metadata to DB associated with the authenticated user**.
    *   `GET /api/characters`: **Retrieves list of characters owned by the authenticated user** from PostgreSQL.
    *   `GET /api/characters/{id}`: **Retrieves details for a character if owned by the authenticated user**.
    *   *TDD:* API integration tests verifying functionality *and* ownership checks.
- [ ] **Task 1.3: Character UI (FE)** - ***Requires Task 1.2 Completion***
    *   Create `CharacterList` Svelte component: Fetches characters via API, displays them.
    *   Implement character selection logic.
    *   Create `CharacterUploader` Svelte component: Handles file input and calls upload API.
    *   *TDD:* Component tests for list rendering, selection, and upload interaction.

---

### Epic 2: Core Chat Loop

*Goal: Enable basic chat functionality: creating sessions, sending/receiving messages, basic prompt assembly.*

- [ ] **Task 2.1: Chat Session & History API (BE)** - ***Requires Task 0.5 Completion***
    *   `POST /api/chats`: Creates a new chat session linked to the **authenticated user** and a character ID.
    *   `GET /api/chats`: Lists chat sessions for the **authenticated user**.
    *   `GET /api/chats/{id}/messages`: Retrieves messages for a session **owned by the authenticated user**.
    *   *TDD:* API tests verifying functionality *and* ownership checks.
- [ ] **Task 2.2: Save Message API (BE)** - ***Requires Task 2.1 Completion***
    *   `POST /api/chats/{id}/messages`: Saves user/AI messages to a session **owned by the authenticated user**.
    *   *TDD:* API tests for message saving, including ownership checks.
- [ ] **Task 2.3: Gemini Generation Client (BE)**
    *   Implement Rust module to interact with the Google Gemini Generation API.
    *   *TDD:* Unit tests mocking the Gemini API client interface.
- [ ] **Task 2.4: Basic Prompt Assembly (BE)** - ***Requires Task 1.2 & Task 4.2 Completion***
    *   Implement logic to retrieve character data, system prompt, and recent chat history.
    *   Combine into a basic prompt string.
    *   *TDD:* Unit tests for prompt assembly logic.
- [ ] **Task 2.5: Generation API Endpoint (BE)** - ***Requires Task 2.2, 2.3, 2.4 Completion***
    *   `POST /api/chats/{id}/generate`: Orchestrates prompt assembly, Gemini call, response saving for a session **owned by the authenticated user**.
    *   *TDD:* API integration tests for the generation flow (mocking Gemini), including ownership checks.
- [ ] **Task 2.6: Chat UI Components (FE)**
    *   Create `ChatWindow`, `MessageBubble`, `MessageInput` Svelte components.
    *   *TDD:* Component tests.
- [ ] **Task 2.7: Frontend Chat Logic (FE)** - ***Requires BE APIs (Task 2.1, 2.2, 2.5) Completion***
    *   Implement Svelte store/state management for chat.
    *   Logic to call APIs for sending/generating messages.
    *   Handle receiving and displaying responses.

---

### Epic 3: Dynamic Context (RAG MVP)

*Goal: Implement the core RAG pipeline using Gemini embeddings and Qdrant.*

- [ ] **Task 3.1: Gemini Embedding Client (BE)**
    *   Implement Rust module to interact with the Google Gemini Embedding API.
    *   *TDD:* Unit tests mocking the Gemini Embedding API client.
- [ ] **Task 3.2: Qdrant Client Service (BE)**
    *   *(Dependency: Add `qdrant-client` crate to `Cargo.toml` - Ref Task 0.1)*
    *   Implement Rust service to interact with Qdrant.
    *   *TDD:* Integration tests against a local Qdrant instance.
- [ ] **Task 3.3: Chat History Chunking (BE)**
    *   Implement logic to divide chat messages into chunks.
    *   *TDD:* Unit tests for chunking strategies.
- [ ] **Task 3.4: Embedding & Storage Pipeline (BE)** - ***Requires Task 2.2, 3.1, 3.2, 3.3 Completion***
    *   Implement asynchronous mechanism triggered after message saving.
    *   Gets chunks, embeds them, stores vectors in Qdrant.
    *   *TDD:* Integration test for the end-to-end embedding pipeline.
- [ ] **Task 3.5: RAG Query Logic (BE)** - ***Requires Task 3.1, 3.2 Completion***
    *   Modify Core Logic: Embed recent context, query Qdrant for similar chunks.
    *   *TDD:* Unit/Integration tests for the RAG query process.
- [ ] **Task 3.6: RAG Context Injection (BE)** - ***Requires Task 2.4, 3.5 Completion***
    *   Modify Prompt Assembly: Integrate retrieved chunks into the final prompt.
    *   *TDD:* Unit tests verifying correct injection formatting.

---

### Epic 4: Basic Prompt Control (MVP)

*Goal: Allow users to set basic generation parameters and a system prompt.*

- [ ] **Task 4.1: Database Schema Update (BE)**
    *   Add columns to `characters` or `chat_sessions` for `system_prompt`, `temperature`, `max_output_tokens`.
    *   Update migrations (Task 0.4).
- [ ] **Task 4.2: API & Logic for Settings (BE)** - ***Requires Task 0.5 Completion***
    *   API endpoints (e.g., `PUT /api/chats/{id}/settings`) to update/retrieve settings for sessions/characters **owned by the authenticated user**.
    *   Modify Prompt Assembly (Task 2.4) to use the stored settings.
    *   Modify Gemini Client call (Task 2.3 / Task 2.5) to pass parameters.
    *   *TDD:* API tests for settings endpoints (including ownership), Unit tests for parameter application.
- [ ] **Task 4.3: Settings UI (FE)** - ***Requires Task 4.2 Completion***
    *   Create `SettingsPanel` Svelte component.
    *   Implement logic to fetch/save settings via API.
    *   *TDD:* Component tests.

---

### Epic 5: UX/UI Design & Specification

*Goal: Define and document the User Experience (UX) and User Interface (UI) for the Scribe MVP using structured methods suitable for both human developers and AI collaboration, ensuring a clean, modern, and intuitive interface.*

*Methodology Note: This epic will leverage Markdown descriptions, Mermaid diagrams (for flows, states, structure), and potentially JSON/YAML (for component props/themes) as outlined in the UX/UI communication guidelines.*

- [ ] **Task 5.1: Define Overall Layout, Navigation & Theme**
    *   Document the main application layout (e.g., sidebar, main content area).
    *   Define primary navigation structure.
    *   Establish a basic visual theme: colors (hex/rgb), typography (fonts, sizes, weights), spacing units using Markdown and potentially a JSON/YAML theme definition.
- [ ] **Task 5.2: Document Core UI Components**
    *   For each key component (e.g., Button, InputField, ChatBubble, CharacterCard, Modal, SettingsInput):
        *   Provide Markdown descriptions of appearance and behavior.
        *   Define states (default, hover, focus, active, disabled, loading, error) with visual descriptions.
        *   Use JSON/YAML to list component props (name, type, default, description).
        *   Use Mermaid `stateDiagram-v2` where helpful to visualize complex component states.
- [ ] **Task 5.3: Map User Flows**
    *   Create Mermaid `graph TD` or `flowchart TD` diagrams for key user flows:
        *   Registration & Login Flow.
        *   Character Upload & Selection Flow.
        *   Starting a New Chat Session.
        *   Sending/Receiving Messages within a Chat.
        *   Accessing and Modifying Chat Settings.
- [ ] **Task 5.4: Specify Key Screens/Views**
    *   For each main screen (Login/Register, Dashboard/Character List, Chat View, Settings Panel):
        *   Provide detailed Markdown description of layout and elements present.
        *   List the core components used on the screen (linking back to Task 5.2 definitions).
        *   Describe key interactions and state changes specific to the screen.
        *   Optionally include references to wireframe images (e.g., `login-view.png`) stored elsewhere, but ensure the Markdown is the source of truth.

---

## MVP Definition

The MVP is complete when a user can:

1.  **Register and log in.**
2.  Upload a V2 character card PNG **(associated with their account)**.
3.  Select **their** character and start a chat session.
4.  Send messages and receive AI responses generated by Google Gemini **within their session**.
5.  Experience basic long-term context recall via the background RAG system **for their chat**.
6.  View and modify a basic System Prompt, Temperature, and Max Output Tokens for **their** current chat.

## Post-MVP Considerations

*   Support for local models (Llama.cpp, Ollama).
*   Advanced prompt controls (Jailbreaks, Author's Notes, Instruct Mode).
*   UI for managing RAG memories ("forgetting").
*   More sophisticated chunking/summarization strategies for RAG.
*   Character editing interface.
*   UI Polish and Theming.
*   Group Chats, World Info (Static).
*   Streaming improvements/alternatives (WebSockets).
*   More robust error handling and user feedback.
*   **Security Enhancements:** Separate User DB, Advanced Microsegmentation, Refresh Tokens, Rate Limiting, Account Lockout, MFA, External IdP Integration, Audit Logging.
