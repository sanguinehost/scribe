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
    - [x] Initialize Rust project (`cargo new --lib scribe-backend`) using the Axum web framework.
    - [ ] Add core dependencies (Axum, `tokio`, `serde`, `diesel` [with relevant features like `postgres`, `chrono`, etc.], logging, error handling). *(Partially complete: Missing logging setup, advanced error handling middleware)*
    - [ ] *Add RAG Dependency:* Add `qdrant-client` to `Cargo.toml`.
    - [x] *Add Authentication Dependencies:* Add `axum-login` and `bcrypt` to `Cargo.toml`.
    - [ ] *Setup Basic Logging:* Choose and configure a logging framework (e.g., `tracing`, `log`).
    - [ ] *Setup Basic Error Handling:* Implement basic Axum error handling/mapping middleware. *(Partially complete: Route-specific errors exist, no central middleware)*
    - [x] *TDD:* Implement `/api/health` endpoint.
    - [x] *TDD:* Write integration test for `/api/health`. *(Verified)*
- [ ] **Task 0.2: Frontend Project Setup (FE)**
    - [x] Initialize SvelteKit project (`npm create svelte@latest scribe-frontend`). Choose Skeleton project with TypeScript.
    - [ ] Setup basic project structure (routes, components, stores, lib). *(Partially complete: Missing components/stores folders)*
    - [ ] Configure basic styling (e.g., TailwindCSS or basic CSS). *(Partially complete: Tailwind installed but needs config)*
    - [x] *TDD:* Setup Vitest and write basic component rendering tests (e.g., for a placeholder component). *(Verified)*
- [x] **Task 0.3: Database Setup (DevOps/BE)**
    - [x] Create `docker-compose.yml` for PostgreSQL and Qdrant services. *(Verified)*
    - [x] Configure initial database connection strings/environment variables for the backend. *(Verified)*
- [ ] **Task 0.4: PostgreSQL Schema & Migrations (BE)**
    - [x] Setup `diesel.toml` configuration. *(Verified)*
    - [x] Define initial schema using `diesel_cli` for: `users`. *(Verified)*
    - [ ] Create Diesel migrations for `users` table. *(Implied by schema.rs, but only initial setup migration found)*
    - [x] Define schema for `characters` (metadata only), `chat_sessions`, `chat_messages`. *(Verified)*
    - [ ] Create Diesel migrations for `characters`, `chat_sessions`, `chat_messages` tables. *(Missing: Only initial setup migration found)*
    - [ ] *(Optional: Add session table migration if using DB session store)*
    - [ ] Implement migration runner logic integrated with Diesel (e.g., run on startup or via separate command). *(Missing)*
    - [ ] *TDD:* Write tests to verify migrations apply correctly. *(Missing)*
    - [ ] *TDD:* Write tests verifying schema matches models using Diesel's testing features. *(Missing)*
- [ ] **Task 0.5: Authentication (BE & FE)** - ***See `docs/AUTH_DESIGN.md` for details***
    - [ ] **(BE) Model Update:** Implement `axum_login::AuthUser` for the `User` model. *(Missing)*
    - [ ] **(BE) User Store Logic:** Implement functions: `get_user(id)`, `get_user_by_username(username)`, `verify_credentials(username, password)` (using `bcrypt`). *(Missing)*
    - [ ] **(BE) Session Store:** Set up a persistent session store for `axum-login` (e.g., using `sqlx` or a Diesel adapter). Implement required traits. *(Missing)*
    - [ ] **(BE) Register Endpoint:** Implement `/api/auth/register` handler (hash password, save user). *(Missing)*
    - [ ] **(BE) Login Endpoint:** Implement `/api/auth/login` handler (use `AuthSession::login`). *(Missing)*
    - [ ] **(BE) Logout Endpoint:** Implement `/api/auth/logout` handler (use `AuthSession::logout`). *(Missing)*
    - [ ] **(BE) Me Endpoint:** Implement optional `/api/auth/me` handler (return current user data). *(Missing)*
    - [ ] **(BE) Router Integration:** Integrate `AuthManagerLayer` and session store layer into the main Axum router. *(Missing)*
    - [ ] **(FE) Login/Register Forms:** Create Svelte components (`LoginForm.svelte`, `RegisterForm.svelte`). *(Missing)*
    - [ ] **(FE) API Calls:** Implement frontend functions to call `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`. *(Missing)*
    - [ ] **(FE) Auth State Management:** Implement a Svelte store (`authStore`) to manage user state (logged in status, user info). Implement guards/redirects based on auth state. *(Missing)*
    - [ ] *TDD (BE):* Unit tests for password hashing/verification. Unit tests for user store functions. API integration tests for auth endpoints. *(Missing)*
    - [ ] *TDD (FE):* Component tests for `LoginForm`, `RegisterForm`. E2E tests (e.g., using Playwright) for the full registration and login flow. *(Missing)*

---

### Epic 1: Character Management

*Goal: Allow users to upload, view, and select V2 character cards.*

- [x] **Task 1.1: Character Card Parser (BE)**
    - [x] Implement Rust logic to parse JSON data from PNG `tEXt` chunks (`ccv3` priority, `chara` fallback, Base64 decode) based on V3 spec. Reads V2/V3 fields. *(Verified)*
    - [x] *TDD:* Unit tests with various valid/invalid card PNGs/JSONs (using test helpers). *(Verified)*
- [ ] **Task 1.2: Character API Endpoints (BE)** - ***Requires Task 0.5 Completion***
    - [ ] **(BE) Upload Logic:** Implement handler for `POST /api/characters/upload`. Parse card (Task 1.1), save metadata to `characters` table, associate with the *authenticated user*. *(Partially complete: Parses, but no DB save or auth)*
    - [ ] **(BE) List Logic:** Implement handler for `GET /api/characters`. Query `characters` table, filter by *authenticated user*. *(Partially complete: Queries, but no auth filter)*
    - [ ] **(BE) Get Details Logic:** Implement handler for `GET /api/characters/{id}`. Query `characters` table for specific ID, verify ownership by *authenticated user*. *(Partially complete: Queries, but no ownership check)*
    - [ ] *TDD (BE):* API integration tests for `POST /upload` (success, auth failure, invalid PNG/JSON, DB error). *(Partially complete: Basic tests exist, missing DB/auth coverage)*
    - [ ] *TDD (BE):* API integration tests for `GET /characters` (success, auth failure, empty list). *(Partially complete: Basic success test exists, missing auth/varied state)*
    - [ ] *TDD (BE):* API integration tests for `GET /characters/{id}` (success, auth failure, not found, forbidden/wrong user). *(Partially complete: Success/Not Found tests exist, missing auth/forbidden)*
- [ ] **Task 1.3: Character UI (FE)** - ***Requires Task 1.2 Completion***
    - [ ] **(FE) Character List Component:** Create `CharacterList.svelte`. Fetch data from `GET /api/characters` on mount. Display characters (e.g., name, avatar). Implement selection mechanism (e.g., click sets active character in a store). *(Missing)*
    - [ ] **(FE) Character Uploader Component:** Create `CharacterUploader.svelte`. Handle file input (`<input type="file">`). Call `POST /api/characters/upload` with file data. Handle loading/success/error states. Refresh list on success. *(Missing)*
    - [ ] *TDD (FE):* Component tests for `CharacterList` (rendering mock data, selection interaction). *(Missing)*
    - [ ] *TDD (FE):* Component tests for `CharacterUploader` (file input simulation, form submission simulation). *(Missing)*
    - [ ] *E2E (FE):* Test uploading a character and seeing it appear in the list. *(Missing)*

---

### Epic 2: Core Chat Loop

*Goal: Enable basic chat functionality: creating sessions, sending/receiving messages, basic prompt assembly.*

- [ ] **Task 2.1: Chat Session & History API (BE)** - ***Requires Task 0.5 Completion***
    - [ ] **(BE) Create Session Logic:** Implement handler for `POST /api/chats`. Create new entry in `chat_sessions` table, linking to *authenticated user* and a character ID. Return session ID.
    - [ ] **(BE) List Sessions Logic:** Implement handler for `GET /api/chats`. Query `chat_sessions`, filter by *authenticated user*.
    - [ ] **(BE) Get Messages Logic:** Implement handler for `GET /api/chats/{id}/messages`. Query `chat_messages` for a given session ID, verify session ownership by *authenticated user*.
    - [ ] *TDD (BE):* API tests for `POST /chats` (success, auth failure, invalid character ID).
    - [ ] *TDD (BE):* API tests for `GET /chats` (success, auth failure, empty list).
    - [ ] *TDD (BE):* API tests for `GET /chats/{id}/messages` (success, auth failure, session not found, forbidden/wrong user).
- [ ] **Task 2.2: Save Message API (BE)** - ***Requires Task 2.1 Completion***
    - [ ] **(BE) Save Message Logic:** Implement handler for `POST /api/chats/{id}/messages`. Validate input (user/AI type, content). Save message to `chat_messages` table, ensuring session is owned by *authenticated user*.
    - [ ] *TDD (BE):* API tests for `POST /chats/{id}/messages` (success, auth failure, session not found, forbidden/wrong user, invalid input).
- [ ] **Task 2.3: Gemini Generation Client (BE)**
    - [ ] **(BE) Configuration:** Setup API key management (e.g., environment variables).
    - [ ] **(BE) Client Implementation:** Create Rust module/struct wrapping the Gemini Generation API client (e.g., using `reqwest`). Implement function like `generate_content(prompt, settings)`. Handle API errors.
    - [ ] *TDD (BE):* Unit tests mocking the HTTP client interface to test request building and response parsing.
- [ ] **Task 2.4: Basic Prompt Assembly (BE)** - ***Requires Task 1.2 & Task 4.2 Completion***
    - [ ] **(BE) Data Retrieval:** Implement logic to get character details (from DB), system prompt (from DB - see Task 4.2), and recent chat messages (from DB).
    - [ ] **(BE) Prompt Formatting:** Combine retrieved data into a single prompt string according to Gemini API requirements.
    - [ ] *TDD (BE):* Unit tests for prompt assembly logic with various inputs (different character data, history lengths, system prompts).
- [ ] **Task 2.5: Generation API Endpoint (BE)** - ***Requires Task 2.2, 2.3, 2.4 Completion***
    - [ ] **(BE) Orchestration Logic:** Implement handler for `POST /api/chats/{id}/generate`.
        - [ ] Verify session ownership by *authenticated user*.
        - [ ] Get user message from request body. Save user message (using Task 2.2 logic/service).
        - [ ] Assemble prompt (using Task 2.4 logic).
        - [ ] Call Gemini client (Task 2.3).
        - [ ] Save AI response (using Task 2.2 logic/service).
        - [ ] Return AI response.
    - [ ] *TDD (BE):* API integration tests for `POST /chats/{id}/generate` (mocking the Gemini client call). Test success case, auth failure, session not found, downstream errors (saving message, assembling prompt).
- [ ] **Task 2.6: Chat UI Components (FE)**
    - [ ] **(FE) Chat Window:** Create `ChatWindow.svelte` (main container).
    - [ ] **(FE) Message Bubble:** Create `MessageBubble.svelte` (display individual user/AI messages).
    - [ ] **(FE) Message Input:** Create `MessageInput.svelte` (textarea, send button).
    - [ ] *TDD (FE):* Component tests for each component (rendering props, basic interactions like button click).
- [ ] **Task 2.7: Frontend Chat Logic (FE)** - ***Requires BE APIs (Task 2.1, 2.2, 2.5) Completion***
    - [ ] **(FE) Chat Store:** Implement Svelte store (`chatStore`) to manage current session ID, messages, loading state.
    - [ ] **(FE) API Calls:** Implement functions to: create session (`POST /api/chats`), fetch messages (`GET /api/chats/{id}/messages`), send message & trigger generation (`POST /api/chats/{id}/generate`).
    - [ ] **(FE) UI Integration:** Connect `ChatWindow`, `MessageInput` to the store and API functions. Display messages. Handle loading indicators. Handle errors from API calls.

---

### Epic 3: Dynamic Context (RAG MVP)

*Goal: Implement the core RAG pipeline using Gemini embeddings and Qdrant.*

- [ ] **Task 3.1: Gemini Embedding Client (BE)**
    - [ ] **(BE) Configuration:** Setup API key management.
    - [ ] **(BE) Client Implementation:** Create Rust module/struct wrapping the Gemini Embedding API client. Implement function like `embed_content(text)`. Handle API errors.
    - [ ] *TDD (BE):* Unit tests mocking the HTTP client interface.
- [ ] **Task 3.2: Qdrant Client Service (BE)**
    - [ ] *(Dependency: Add `qdrant-client` crate - Covered in Task 0.1)*
    - [ ] **(BE) Configuration:** Setup Qdrant connection details (URL, API key if any).
    - [ ] **(BE) Service Implementation:** Create Rust service wrapping `qdrant-client`. Implement functions for ensuring collection exists, upserting points (vectors + payload), searching points.
    - [ ] *TDD (BE):* Integration tests against a local Qdrant instance (via Docker Compose) for service functions.
- [ ] **Task 3.3: Chat History Chunking (BE)**
    - [ ] **(BE) Strategy Definition:** Decide on a chunking strategy (e.g., by message pair, fixed token count).
    - [ ] **(BE) Implementation:** Implement Rust function `chunk_messages(messages) -> Vec<Chunk>`.
    - [ ] *TDD (BE):* Unit tests for the chunking function with different message list scenarios.
- [ ] **Task 3.4: Embedding & Storage Pipeline (BE)** - ***Requires Task 2.2, 3.1, 3.2, 3.3 Completion***
    - [ ] **(BE) Trigger Mechanism:** Modify message saving logic (Task 2.2) or use a background task runner (e.g., `tokio::spawn`) to trigger embedding *after* a message pair (user + AI) is saved.
    - [ ] **(BE) Pipeline Logic:** Implement function that takes saved messages, chunks them (Task 3.3), embeds chunks (Task 3.1), and upserts vectors/payloads to Qdrant (Task 3.2). Associate vectors with session ID and user ID in Qdrant payload for filtering.
    - [ ] *TDD (BE):* Integration test for the end-to-end embedding pipeline (mocking Gemini Embedding API, interacting with real Qdrant).
- [ ] **Task 3.5: RAG Query Logic (BE)** - ***Requires Task 3.1, 3.2 Completion***
    - [ ] **(BE) Context Embedding:** Embed the user's latest message (or recent conversational turn) using Task 3.1.
    - [ ] **(BE) Qdrant Search:** Implement logic to query Qdrant (Task 3.2) using the generated embedding. Filter by relevant session ID / user ID. Retrieve top N relevant chunks.
    - [ ] *TDD (BE):* Unit/Integration tests for the RAG query process (mocking embedding API, using real Qdrant).
- [ ] **Task 3.6: RAG Context Injection (BE)** - ***Requires Task 2.4, 3.5 Completion***
    - [ ] **(BE) Modify Prompt Assembly:** Update Task 2.4 logic. Before generating the final prompt, execute RAG query (Task 3.5). Prepend retrieved context chunks (formatted appropriately) to the main prompt section.
    - [ ] *TDD (BE):* Unit tests verifying correct injection formatting in the assembled prompt.

---

### Epic 4: Basic Prompt Control (MVP)

*Goal: Allow users to set basic generation parameters and a system prompt.*

- [ ] **Task 4.1: Database Schema Update (BE)**
    - [ ] **(BE) Decision:** Decide whether settings (`system_prompt`, `temperature`, `max_output_tokens`) belong to `characters` or `chat_sessions`. **Decision: Add to `chat_sessions` for per-chat control.** Make columns nullable with sensible defaults.
    - [ ] **(BE) Create Migration:** Use `diesel_cli` to generate a new migration file adding these columns to `chat_sessions`.
    - [ ] **(BE) Apply Migration:** Ensure the migration runner (from Task 0.4) applies this migration.
    - [ ] *TDD (BE):* Update schema verification tests (Task 0.4) to reflect new columns. Run migration tests.
- [ ] **Task 4.2: API & Logic for Settings (BE)** - ***Requires Task 0.5, Task 2.1 Completion***
    - [ ] **(BE) Get Settings Logic:** Implement handler for `GET /api/chats/{id}/settings`. Query `chat_sessions` table for the specified session ID, verify ownership by *authenticated user*. Return the settings values (or defaults if NULL).
    - [ ] **(BE) Update Settings Logic:** Implement handler for `PUT /api/chats/{id}/settings`. Verify session ownership by *authenticated user*. Validate input data (e.g., temperature range, token limits). Update the corresponding row in `chat_sessions`.
    - [ ] **(BE) Update Prompt Assembly:** Modify Task 2.4 logic to fetch `system_prompt` from the session settings (retrieved via Task 4.2 logic or passed in) and include it in the prompt.
    - [ ] **(BE) Update Gemini Client Call:** Modify Task 2.5 logic to fetch `temperature` and `max_output_tokens` from session settings and pass them to the Gemini client (Task 2.3).
    - [ ] *TDD (BE):* API tests for `GET /api/chats/{id}/settings` (success, auth failure, not found, forbidden).
    - [ ] *TDD (BE):* API tests for `PUT /api/chats/{id}/settings` (success, auth failure, not found, forbidden, invalid data).
    - [ ] *TDD (BE):* Update Unit tests for Prompt Assembly (Task 2.4) to verify system prompt usage.
    - [ ] *TDD (BE):* Update Unit tests/Integration tests for Generation Endpoint (Task 2.5) to verify settings are passed to the mocked Gemini client.
- [ ] **Task 4.3: Settings UI (FE)** - ***Requires Task 4.2 Completion***
    - [ ] **(FE) Settings Panel Component:** Create `SettingsPanel.svelte`. Could be a modal or a sidebar section.
    - [ ] **(FE) Input Components:** Add inputs for System Prompt (textarea), Temperature (slider/number input), Max Output Tokens (number input).
    - [ ] **(FE) API Calls:** Implement logic to fetch current settings using `GET /api/chats/{id}/settings` when the panel opens for the current chat session. Implement logic to save settings using `PUT /api/chats/{id}/settings` on change or via a save button. Handle loading/success/error states.
    - [ ] *TDD (FE):* Component tests for `SettingsPanel` (rendering inputs, handling input changes, simulating API calls for fetch/save).

---

### Epic 5: UX/UI Design & Specification

*Goal: Define and document the User Experience (UX) and User Interface (UI) for the Scribe MVP using structured methods suitable for both human developers and AI collaboration, ensuring a clean, modern, and intuitive interface.*

*Methodology Note: This epic will leverage Markdown descriptions, Mermaid diagrams (for flows, states, structure), and potentially JSON/YAML (for component props/themes) as outlined in the UX/UI communication guidelines.*

- [ ] **Task 5.1: Define Overall Layout, Navigation & Theme**
    - [ ] **Task 5.1.1:** Document the main application layout (e.g., sidebar, main content area).
    - [ ] **Task 5.1.2:** Define primary navigation structure.
    - [ ] **Task 5.1.3:** Establish a basic visual theme: colors (hex/rgb), typography (fonts, sizes, weights), spacing units using Markdown and potentially a JSON/YAML theme definition.
- [ ] **Task 5.2: Document Core UI Components**
    *   For each key component (e.g., Button, InputField, ChatBubble, CharacterCard, Modal, SettingsInput):
        - [ ] Provide Markdown descriptions of appearance and behavior.
        - [ ] Define states (default, hover, focus, active, disabled, loading, error) with visual descriptions.
        - [ ] Use JSON/YAML to list component props (name, type, default, description).
        - [ ] Use Mermaid `stateDiagram-v2` where helpful to visualize complex component states.
- [ ] **Task 5.3: Map User Flows**
    *   Create Mermaid `graph TD` or `flowchart TD` diagrams for key user flows:
        - [ ] Registration & Login Flow.
        - [ ] Character Upload & Selection Flow.
        - [ ] Starting a New Chat Session.
        - [ ] Sending/Receiving Messages within a Chat.
        - [ ] Accessing and Modifying Chat Settings.
- [ ] **Task 5.4: Specify Key Screens/Views**
    *   For each main screen (Login/Register, Dashboard/Character List, Chat View, Settings Panel):
        - [ ] Provide detailed Markdown description of layout and elements present.
        - [ ] List the core components used on the screen (linking back to Task 5.2 definitions).
        - [ ] Describe key interactions and state changes specific to the screen.
        - [ ] Optionally include references to wireframe images (e.g., `login-view.png`) stored elsewhere, but ensure the Markdown is the source of truth.

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
