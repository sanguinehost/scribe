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

- [x] **Task 0.1: Backend Project Setup (BE)**
    - [x] Initialize Rust project (`cargo new --lib scribe-backend`) using the Axum web framework.
    - [x] Add core dependencies (Axum, `tokio`, `serde`, `diesel` [with relevant features like `postgres`, `chrono`, etc.], logging, error handling).
    - [x] *Add RAG Dependency:* Add `qdrant-client` to `Cargo.toml`.
    - [x] *Add Authentication Dependencies:* Add `axum-login` and `bcrypt` to `Cargo.toml`.
    - [x] *Setup Basic Logging:* Choose and configure a logging framework (e.g., `tracing`, `log`).
    - [x] *Setup Basic Error Handling:* Implement basic Axum error handling/mapping middleware. *(Implemented via AppError/IntoResponse)*
    - [x] *TDD:* Implement `/api/health` endpoint.
    - [x] *TDD:* Write integration test for `/api/health`. *(Verified)*
- [ ] **Task 0.2: Frontend Project Setup (FE)**
    - [x] Initialize SvelteKit project (`npm create svelte@latest scribe-frontend`). Choose Skeleton project with TypeScript.
    - [x] Setup basic project structure (routes, components, stores, lib). *(Created missing folders)*
    - [x] **Configure Styling:** Install and configure **shadcn-svelte** ([https://www.shadcn-svelte.com/docs/installation/manual](https://www.shadcn-svelte.com/docs/installation/manual)) following the manual installation guide. *(Requires shadcn-svelte setup)*
    - [x] *TDD:* Setup Vitest and write basic component rendering tests (e.g., for a placeholder component). *(Verified)*
- [x] **Task 0.3: Database Setup (DevOps/BE)**
    - [x] Create `docker-compose.yml` for PostgreSQL and Qdrant services. *(Verified)*
    - [x] Configure initial database connection strings/environment variables for the backend. *(Verified)*
- [ ] **Task 0.4: PostgreSQL Schema & Migrations (BE)**
    - [x] Setup `diesel.toml` configuration. *(Verified)*
    - [x] Define initial schema using `diesel_cli` for: `users`. *(Verified)*
    - [x] Create Diesel migrations for `users` table. *(Covered by initial migration)*
    - [x] Define schema for `characters` (metadata only), `chat_sessions`, `chat_messages`. *(Verified)*
    - [x] Create Diesel migrations for `characters`, `chat_sessions`, `chat_messages` tables. *(Covered by initial migration)*
    - [x] *(Optional: Add session table migration if using DB session store)* *(Verified - Migration exists)*
    - [x] Implement migration runner logic integrated with Diesel (e.g., run on startup or via separate command). *(Verified - Run on startup in main.rs)*
    - [x] *TDD:* Write tests to verify migrations apply correctly. *(Verified - test_migrations_run_cleanly)*
    - [x] *TDD:* Write tests verifying schema matches models using Diesel's testing features. *(Covered by compile-time checks and integration tests like `test_user_character_insert_and_query`)*
- [ ] **Task 0.5: Authentication (BE & FE)** - ***See `docs/AUTH_DESIGN.md` for details***
    - [x] **(BE) Model Update:** Implement `axum_login::AuthUser` for the `User` model. *(Verified)*
    - [x] **(BE) User Store Logic:** Implement functions: `get_user(id)`, `get_user_by_username(username)`, `verify_credentials(username, password)` (using `bcrypt`). *(Verified)*
    - [x] **(BE) Session Store:** Set up a persistent session store for `axum-login` (e.g., using `sqlx` or a Diesel adapter). Implement required traits. *(Verified)*
    - [x] **(BE) Register Endpoint:** Implement `/api/auth/register` handler (hash password, save user). *(Verified)*
    - [x] **(BE) Login Endpoint:** Implement `/api/auth/login` handler (use `AuthSession::login`). *(Verified)*
    - [x] **(BE) Logout Endpoint:** Implement `/api/auth/logout` handler (use `AuthSession::logout`). *(Verified)*
    - [x] **(BE) Me Endpoint:** Implement optional `/api/auth/me` handler (return current user data). *(Verified)*
    - [x] **(BE) Router Integration:** Integrate `AuthManagerLayer` and session store layer into the main Axum router. *(Verified)*
    - [ ] **(FE) Login/Register Forms:** Create Svelte components (`LoginForm.svelte`, `RegisterForm.svelte`). *(Missing)*
    - [ ] **(FE) API Calls:** Implement frontend functions to call `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`. *(Missing)*
    - [ ] **(FE) Auth State Management:** Implement a Svelte store (`authStore`) to manage user state (logged in status, user info). Implement guards/redirects based on auth state. *(Missing)*
    - [x] *TDD (BE):* Unit tests for password hashing/verification. Unit tests for user store functions. API integration tests for auth endpoints. *(Verified)*
    - [ ] *TDD (FE):* Component tests for `LoginForm`, `RegisterForm`. E2E tests (e.g., using Playwright) for the full registration and login flow. *(Missing)*

---

### Epic 1: Character Management

*Goal: Allow users to upload, view, and select V2 character cards.*

- [x] **Task 1.1: Character Card Parser (BE)**
    - [x] Implement Rust logic to parse JSON data from PNG `tEXt` chunks (`ccv3` priority, `chara` fallback, Base64 decode) based on V3 spec. Reads V2/V3 fields. *(Verified)*
    - [x] *TDD:* Unit tests with various valid/invalid card PNGs/JSONs (using test helpers). *(Verified)*
- [x] **Task 1.2: Character API Endpoints (BE)** - ***Requires Task 0.5 Completion***
    - [x] **(BE) Upload Logic:** Implement handler for `POST /api/characters/upload`. Parse card (Task 1.1), save metadata to `characters` table, associate with the *authenticated user*. *(Verified)*
    - [x] **(BE) List Logic:** Implement handler for `GET /api/characters`. Query `characters` table, filter by *authenticated user*. *(Verified)*
    - [x] **(BE) Get Details Logic:** Implement handler for `GET /api/characters/{id}`. Query `characters` table for specific ID, verify ownership by *authenticated user*. *(Verified)*
    - [x] *TDD (BE):* API integration tests for `POST /upload` (success, auth failure, invalid PNG/JSON, DB error). *(Verified)*
    - [x] *TDD (BE):* API integration tests for `GET /characters` (success, auth failure, empty list). *(Verified)*
    - [x] *TDD (BE):* API integration tests for `GET /characters/{id}` (success, auth failure, not found, forbidden/wrong user). *(Verified)*
- [ ] **Task 1.3: Character UI (FE)** - ***Requires Task 1.2 Completion***
    - [ ] **(FE) Character List Component:** Create `CharacterList.svelte` (Leverage Skeleton components like `<Card>`, `<Avatar>`, grid utilities). Fetch data from `GET /api/characters` on mount. Display characters. Implement selection mechanism. *(Missing)*
    - [ ] **(FE) Character Uploader Component:** Create `CharacterUploader.svelte` (Leverage Skeleton form components, file input handling). Call `POST /api/characters/upload`. Handle states. Refresh list. *(Missing)*
    - [ ] *TDD (FE):* Component tests for `CharacterList` (rendering mock data, selection interaction). *(Missing)*
    - [ ] *TDD (FE):* Component tests for `CharacterUploader` (file input simulation, form submission simulation). *(Missing)*
    - [ ] *E2E (FE):* Test uploading a character and seeing it appear in the list. *(Missing)*

---

### Epic 2: Core Chat Loop

*Goal: Enable basic chat functionality: creating sessions, sending/receiving messages, basic prompt assembly, **and streaming responses**.*

- [x] **Task 2.1: Chat Session & History API (BE)** - ***Requires Task 0.5 Completion***
    - [x] **(BE) Create Session Logic:** Implement handler for `POST /api/chats`. Create new entry in `chat_sessions` table, linking to *authenticated user* and a character ID. Return session ID. *(Verified via chat_tests.rs)*
    - [x] **(BE) List Sessions Logic:** Implement handler for `GET /api/chats`. Query `chat_sessions`, filter by *authenticated user*. *(Verified via chat_tests.rs)*
    - [x] **(BE) Get Messages Logic:** Implement handler for `GET /api/chats/{id}/messages`. Query `chat_messages` for a given session ID, verify session ownership by *authenticated user*. *(Verified via chat_tests.rs)*
    - [x] *TDD (BE):* API tests for `POST /chats` (success, auth failure, invalid character ID). *(Verified via chat_tests.rs)*
    - [x] *TDD (BE):* API tests for `GET /chats` (success, auth failure, empty list). *(Verified via chat_tests.rs)*
    - [x] *TDD (BE):* API tests for `GET /chats/{id}/messages` (success, auth failure, session not found, forbidden/wrong user). *(Verified via chat_tests.rs)*
- [x] **Task 2.2: Save Message API (BE)** - ***Requires Task 2.1 Completion***
    - [x] **(BE) Save Message Logic:** Implement handler for `POST /api/chats/{id}/messages`. Validate input (user/AI type, content). Save message to `chat_messages` table, ensuring session is owned by *authenticated user*.
    - [x] *TDD (BE):* API tests for `POST /chats/{id}/messages` (success, auth failure, session not found, forbidden/wrong user, invalid input).
- [x] **Task 2.3: Gemini Generation Client (BE)**
    - [x] **(BE) Configuration:** Setup API key management (e.g., environment variables). *(Verified - Implicitly handled by genai)*
    - [x] **(BE) Client Implementation:** Create Rust module/struct wrapping the Gemini Generation API client (`genai`). Implement function like `generate_content(prompt, settings)` (`generate_simple_response`). Handle API errors. **Investigate and implement streaming response handling if supported by `genai`/Gemini API.** *(Verified - Base client exists, streaming needs implementation)*
    - [x] *TDD (BE):* Unit tests mocking the HTTP client interface to test request building and response parsing. *(Verified - Basic client build test and integration test for generation)* **Add tests for streaming.** *(Verified via chat_tests.rs integration)*
    - *Note:* The current `genai` crate version (local v0.2.2) does not support sending the `thinkingBudget` parameter to control Gemini's internal thinking process. This capability is deferred to Post-MVP, where options include contributing to `genai` or implementing direct API calls. This is an accepted MVP limitation, similar to other unsupported generation parameters.
- [x] **Task 2.4: Basic Prompt Assembly (BE)** - ***Requires Task 1.2 & Task 4.2 Completion***
    - [x] **(BE) Data Retrieval:** Implement logic to get character details (from DB), system prompt (from DB - see Task 4.2), and recent chat messages (from DB).
    - [x] **(BE) Prompt Formatting:** Combine retrieved data into a single prompt string according to Gemini API requirements.
    - [x] *TDD (BE):* Unit tests for prompt assembly logic with various inputs (different character data, history lengths, system prompts).
- [x] **Task 2.4.1: Implement Configurable History Management (BE)** - ***Requires Task 2.2 Completion***
- [x] **(BE) History Retrieval Modification:** Update logic that fetches chat history (currently implicit in Task 2.4/2.5) to retrieve messages *before* applying management strategies.
- [x] **(BE) Implement Strategies:** In `chat_service.rs` (or a dedicated module), implement history management logic that runs *before* history is passed to `prompt_builder.rs`. Support initial strategies:
- **Sliding Window:** Keep only the most recent N messages or tokens (configurable per session/globally).
- **Simple Truncation:** Limit the total token count of the history sent (configurable).
- [x] **(BE) Configuration:** Integrate configuration options for selecting and parameterizing the history management strategy (e.g., via session settings - potentially extending Task 4.1/4.2).
- [x] *TDD (BE):* Unit tests for sliding window and truncation logic with various history sizes and configurations.
- *Note:* This step is crucial for handling long conversations within token limits. Future work (Post-MVP) could involve more advanced summarization techniques here.
- [x] **Task 2.5: Generation API Endpoint (BE)** - ***Requires Task 2.2, 2.3, 2.4 Completion***
    - [x] **(BE) Orchestration Logic:** Implement handler for `POST /api/chats/{id}/generate`. **Support streaming responses (e.g., Server-Sent Events).**
        - [x] Verify session ownership by *authenticated user*.
        - [x] Get user message from request body. Save user message (using Task 2.2 logic/service).
        - [x] Retrieve and manage history (Task 2.4.1), then assemble prompt (Task 2.4 logic).
        - [x] Call Gemini client (Task 2.3), **handling potential streaming.**
        - [x] Save AI response (using Task 2.2 logic/service) **(potentially after stream completion or incrementally if feasible)**.
        - [x] Return AI response **(as stream or complete response)**.
    - [x] *TDD (BE):* API integration tests for `POST /chats/{id}/generate` (mocking the Gemini client call). Test success case (both streaming and non-streaming), auth failure, session not found, downstream errors (saving message, assembling prompt). **Verify stream format (e.g., SSE).**
- [ ] **Task 2.6: Chat UI Components (FE)**
    - [ ] **(FE) Chat Window:** Create `ChatWindow.svelte` (main container, potentially using Skeleton layout components like `AppShell`).
    - [ ] **(FE) Message Bubble:** Create `MessageBubble.svelte` (display individual user/AI messages, style using Skeleton theme/utilities). **Must support rendering incrementally updating text for streaming.**
    - [ ] **(FE) Message Input:** Create `MessageInput.svelte` (Leverage Skeleton `<textarea>`, `<button>`).
    - [ ] *TDD (FE):* Component tests for each component (rendering props, basic interactions like button click). **Add tests for incremental text updates in `MessageBubble`.**
- [ ] **Task 2.7: Frontend Chat Logic (FE)** - ***Requires BE APIs (Task 2.1, 2.2, 2.5) Completion***
    - [ ] **(FE) Chat Store:** Implement Svelte store (`chatStore`) to manage current session ID, messages, loading state.
    - [ ] **(FE) API Calls:** Implement functions to: create session (`POST /api/chats`), fetch messages (`GET /api/chats/{id}/messages`), send message & trigger generation (`POST /api/chats/{id}/generate`). **Handle streaming responses (e.g., using `EventSource` for SSE).**
    - [ ] **(FE) UI Integration:** Connect `ChatWindow`, `MessageInput` to the store and API functions. Display messages. **Update messages incrementally during streaming.** Handle loading indicators. Handle errors from API calls.
    - [ ] *TDD (FE):* Add tests for handling streaming responses and updating the store/UI correctly.
- [x] **Task 2.8: Basic CLI Test Client (BE/DevTool)** - ***Requires BE APIs (Task 2.1, 2.2, 2.5) Completion***
   - [x] **(BE/CLI) Create Rust Binary:** Set up a separate Rust binary project or a binary target within the backend (`scribe-cli`). Add necessary dependencies (e.g., `reqwest`, `tokio`, `serde`, `clap` for arg parsing).
   - [x] **(BE/CLI) Implement API Client Logic:** Create functions within the CLI to interact with the backend API: login (`/api/auth/login`), list characters (`/api/characters`), create chat (`/api/chats`), generate response (`/api/chats/{id}/generate`). Handle session cookies.
   - [x] **(BE/CLI) Basic Interactive Loop:** Implement a simple command-line interface:
       - Prompt user for login credentials.
       - List available characters and prompt for selection.
       - Start a new chat session for the selected character.
       - Enter a loop: read user input, call the generate endpoint, print the AI response.
   - [x] *TDD (BE/CLI):* (Optional but recommended) Add basic integration tests for the CLI's API interaction logic, potentially mocking the server or using a test instance.
   - *Note:* CLI successfully tested against live backend (Register, Login, Logout, Char Upload/List/Details, Chat Create/Send/List/History/Resume).
   - *Note:* Minor path issue identified in CLI's "Create Test Character" helper (assumes path relative to `cli/` not workspace root). Manual upload works.
   - *Note:* Observed that character's `first_mes` isn't sent on chat start; AI includes greeting in response to user's first message. (Backend Task 2.5 behavior).

---

### Epic 3: Dynamic Context (RAG MVP)

*Goal: Implement the core RAG pipeline using Gemini embeddings and Qdrant.*

- [x] **Task 3.1: Gemini Embedding Client (BE)**
    - [x] **(BE) Configuration:** Setup API key management.
    - [x] **(BE) Client Implementation:** Create Rust module/struct wrapping the Gemini Embedding API client. Implement function like `embed_content(text)`. Handle API errors.
    - [x] *TDD (BE):* Unit tests mocking the HTTP client interface. *(Verified - httpmock tests cover various scenarios)*
- [x] **Task 3.2: Qdrant Client Service (BE)**
    - [x] *(Dependency: Add `qdrant-client` crate - Covered in Task 0.1)*
    - [x] **(BE) Configuration:** Setup Qdrant connection details (URL, API key if any).
    - [x] **(BE) Service Implementation:** Create Rust service wrapping `qdrant-client`. Implement functions for ensuring collection exists, upserting points (vectors + payload), searching points.
    - [x] *TDD (BE):* Integration tests against a local Qdrant instance (via Docker Compose) for service functions. *(Verified - Added in `vector_db/qdrant_client.rs`, marked with `#[ignore]`)*
- [x] **Task 3.3: Chat History Chunking (BE)**
    - [x] **(BE) Strategy Definition:** Decide on a chunking strategy (e.g., by message pair, fixed token count). *(Implemented: Paragraph/Sentence/Char Limit)*
    - [x] **(BE) Implementation:** Implement Rust function `chunk_messages(messages) -> Vec<Chunk>`. *(Implemented)*
    - [x] *TDD (BE):* Unit tests for the chunking function with different message list scenarios. *(Implemented & Passed)*
- [x] **Task 3.4: Embedding & Storage Pipeline (BE)** - ***Requires Task 2.2, 3.1, 3.2, 3.3 Completion***
    - [x] **(BE) Trigger Mechanism:** Modify message saving logic (Task 2.2) or use a background task runner (e.g., `tokio::spawn`) to trigger embedding *after* a message pair (user + AI) is saved. *(Verified via logs)*
    - [x] **(BE) Pipeline Logic:** Implement function that takes saved messages, chunks them (Task 3.3), embeds chunks (Task 3.1), and upserts vectors/payloads to Qdrant (Task 3.2). Associate vectors with session ID and user ID in Qdrant payload for filtering. *(Implemented via `process_and_embed_message` using `chunk_text`)*
    - [x] *TDD (BE):* Integration test for the end-to-end embedding pipeline (mocking Gemini Embedding API, interacting with real Qdrant). *(Verified via `test_process_and_embed_message_integration`)*
- [x] **Task 3.5: RAG Query Logic (BE)** - ***Requires Task 3.1, 3.2 Completion***
    - [x] **(BE) Context Embedding:** Embed the user's latest message (or potentially a summary/derived intent from recent turns - *See Enhancement Note*) using Task 3.1. *(Implemented in `retrieve_relevant_chunks`)*
    - [x] **(BE) Qdrant Search:** Implement logic to query Qdrant (Task 3.2) using the generated embedding. Filter by relevant session ID / user ID. Retrieve top N relevant chunks. *(Implemented in `retrieve_relevant_chunks`)*
    - [ ] **(BE) Enhancement Note (Post-MVP/Future):** Explore improving query relevance by:
        - Querying based on a summary or extracted intent of the last few turns, not just the raw last message.
        - Retrieving a larger number or different *types* of chunks (e.g., retrieving specific character lore/details alongside conversational history chunks based on query analysis).
    - [x] *TDD (BE):* Unit/Integration tests for the RAG query process (mocking embedding API, using real Qdrant). *(Verified - Integration tests now passing)*
- [x] **Task 3.6: RAG Context Injection (BE)** - ***Requires Task 2.4, 3.5 Completion***
    - [x] **(BE) Modify Prompt Assembly:** Update Task 2.4 logic. Before generating the final prompt, execute RAG query (Task 3.5). Prepend retrieved context chunks (formatted appropriately) to the main prompt section. *(Implemented in `build_prompt_with_rag`)*
    - [x] *TDD (BE):* Unit tests verifying correct injection formatting in the assembled prompt. *(Verified - Integration and unit tests now passing)*

---

### Epic 4: Basic Prompt Control (MVP)

*Goal: Allow users to set basic generation parameters and a system prompt.*

- [x] **Task 4.1: Database Schema Update (BE)**
    - [x] **(BE) Decision:** Decide whether settings (`system_prompt`, `temperature`, `max_output_tokens`, **`frequency_penalty`, `presence_penalty`, `top_k`, `top_p`, `repetition_penalty`, `min_p`, `top_a`, `seed`, `logit_bias` (JSON?)**) belong to `characters` or `chat_sessions`. **Decision: Add to `chat_sessions` for per-chat control.** Make columns nullable with sensible defaults. *(Verified for original 3)*
    - [x] **(BE) Create Migration:** Use `diesel_cli` to generate a new migration file adding these columns to `chat_sessions`. *(Verified - Migration created for all fields including new parameters)*
    - [x] **(BE) Apply Migration:** Ensure the migration runner (from Task 0.4) applies this migration. *(Verified)*
    - [x] *TDD (BE):* Update schema verification tests (Task 0.4) to reflect new columns. Run migration tests. *(Verified)*
- [x] **Task 4.2: API & Logic for Settings (BE)** - ***Requires Task 0.5, Task 2.1 Completion***
    - [x] **(BE) Get Settings Logic:** Implement handler for `GET /api/chats/{id}/settings`. Query `chat_sessions` table for the specified session ID, verify ownership by *authenticated user*. Return the settings values (or defaults if NULL). **Handle all new settings.** *(Verified)*
    - [x] **(BE) Update Settings Logic:** Implement handler for `PUT /api/chats/{id}/settings`. Verify session ownership by *authenticated user*. Validate input data (e.g., temperature range, token limits, penalty ranges, K/P/A values, seed format, logit bias structure). Update the corresponding row in `chat_sessions`. **Handle all new settings.** *(Verified)*
    - [x] **(BE) Update Prompt Assembly:** Modify Task 2.4 logic to fetch `system_prompt` from the session settings (retrieved via Task 4.2 logic or passed in) and include it in the prompt. *(Verified)*
    - [x] **(BE) Update Gemini Client Call:** Modify Task 2.5 logic to fetch **all relevant settings** (`temperature`, `max_output_tokens`, `frequency_penalty`, `presence_penalty`, `top_k`, `top_p`, etc.) from session settings and pass them to the Gemini client (Task 2.3). **Requires mapping to `genai::ChatOptions` / `genai::GenerationConfig` and verification of Gemini API support for each.** *(Verified)*
    - [x] *TDD (BE):* API tests for `GET /api/chats/{id}/settings` (success, auth failure, not found, forbidden). **Verify all settings returned.** *(Verified)*
    - [x] *TDD (BE):* API tests for `PUT /api/chats/{id}/settings` (success, auth failure, not found, forbidden, invalid data for *each* setting). **Verify all settings updated.** *(Verified)*
    - [x] *TDD (BE):* Update Unit tests for Prompt Assembly (Task 2.4) to verify system prompt usage. *(Verified)*
    - [x] *TDD (BE):* Update Unit tests/Integration tests for Generation Endpoint (Task 2.5) to verify **all applicable settings** are passed to the mocked Gemini client. *(Verified)*
- [ ] **Task 4.3: Settings UI (FE)** - ***Requires Task 4.2 Completion***
    - [ ] **(FE) Settings Panel Component:** Create `SettingsPanel.svelte` (Leverage Skeleton components like `<Modal>`, `<SlideOver>`, or integrate into `AppShell`).
    - [ ] **(FE) Input Components:** Use Skeleton form components (`<textarea>`, `<input type="range">`, `<input type="number">`, sliders, text inputs as appropriate) for System Prompt, Temperature, Max Output Tokens, **Frequency/Presence Penalty, Top K/P/A, Repetition Penalty, Min P, Seed, Logit Bias editor (potentially complex)**.
    - [ ] **(FE) API Calls:** Implement logic to fetch current settings using `GET /api/chats/{id}/settings` when the panel opens for the current chat session. Implement logic to save settings using `PUT /api/chats/{id}/settings` on change or via a save button. Handle loading/success/error states. **Ensure all settings are fetched/saved.**
    - [ ] *TDD (FE):* Component tests for `SettingsPanel` (rendering inputs, handling input changes, simulating API calls for fetch/save). **Verify all settings inputs.**
- [x] **Task 4.4: Investigate Gemini API Support (BE)** - ***Requires consulting `genai` / Google Gemini docs***
    - [x] **(BE) Research:** Systematically check the `genai` crate and official Google Gemini API documentation to confirm which of the newly added settings (`frequency_penalty`, `presence_penalty`, `top_k`, `top_p`, `repetition_penalty`, `min_p`, `top_a`, `seed`, `logit_bias`) are directly supported via API parameters in `ChatOptions` or `GenerationConfig`. *(Findings documented via comments/logs in chat.rs)*
    - [x] **(BE) Document Findings:** Update comments in the code or relevant documentation (`docs/LLM_INTEGRATION.md`?) to note which settings are supported, which might require workarounds (if any), and which are unsupported by the Gemini API. *(In-code comments/logs suffice for MVP)*

---

### Epic 5: UX/UI Design & Specification

*Goal: Define and document the User Experience (UX) and User Interface (UI) for the Scribe MVP using structured methods suitable for both human developers and AI collaboration, ensuring a clean, modern, and intuitive interface.*

*Methodology Note: This epic will leverage Markdown descriptions, Mermaid diagrams (for flows, states, structure), and potentially JSON/YAML (for component props/themes) as outlined in the UX/UI communication guidelines.*

- [x] **Task 5.1: Define Overall Layout, Navigation & Theme**
    - [x] **Task 5.1.1:** Document the main application layout (e.g., sidebar, main content area).
    - [x] **Task 5.1.2:** Define primary navigation structure.
    - [x] **Task 5.1.3:** Establish a basic visual theme: colors (hex/rgb), typography (fonts, sizes, weights), spacing units using Markdown and potentially a JSON/YAML theme definition.
- [x] **Task 5.2: Document Core UI Components**
    *   For each key component (e.g., Button, InputField, ChatBubble, CharacterCard, Modal, SettingsInput):
        - [x] Provide Markdown descriptions of appearance and behavior.
        - [x] Define states (default, hover, focus, active, disabled, loading, error) with visual descriptions.
        - [x] Use JSON/YAML to list component props (name, type, default, description).
        - [x] Use Mermaid `stateDiagram-v2` where helpful to visualize complex component states.
- [x] **Task 5.3: Map User Flows**
    *   Create Mermaid `graph TD` or `flowchart TD` diagrams for key user flows:
        - [x] Registration & Login Flow.
        - [x] Character Upload & Selection Flow.
        - [x] Starting a New Chat Session.
        - [x] Sending/Receiving Messages within a Chat.
        - [x] Accessing and Modifying Chat Settings.
- [x] **Task 5.4: Specify Key Screens/Views**
    *   For each main screen (Login/Register, Dashboard/Character List, Chat View, Settings Panel):
        - [x] Provide detailed Markdown description of layout and elements present.
        - [x] List the core components used on the screen (linking back to Task 5.2 definitions).
        - [x] Describe key interactions and state changes specific to the screen.
        - [x] Optionally include references to wireframe images (e.g., `login-view.png`) stored elsewhere, but ensure the Markdown is the source of truth.

---

### Epic 6: Backend Code Cleanup

*Goal: Implement key improvements identified during code review to fix security issues, improve performance, and remove redundancies.*

- [x] **Task 6.1: High Priority Fixes (BE)**
    - [x] **Security Fix:** Correct the `session_auth_hash` function in `models/users.rs` to use the password hash (`self.password_hash.as_bytes()`) instead of `self.id.as_bytes()` for proper session invalidation on password changes.
    - [x] **Performance Fix:** Update the registration handler in `routes/auth.rs` to use the async `auth::hash_password` helper instead of synchronous `bcrypt::hash` call.
    - [x] **Redundancy Cleanup:** Remove the duplicate `Character` model definition found in `models/character_card.rs` (lines 384-452) and ensure all code references the canonical model.

- [x] **Task 6.2: Test Coverage Improvements (BE)**
    - [x] Implement the placeholder integration tests in `backend/tests/characters_tests.rs` covering:
        - [x] List Characters API (success, auth failure, empty list)
        - [x] Get Character API (success, auth failure, not found, wrong user)
        - [x] Upload Character errors (malformed PNG, invalid JSON data, database errors)
    - [x] Add missing tests for the `GET /api/chats/{id}/messages` endpoint:
        - [x] Test unauthorized access (no login)
        - [x] Test session not found (invalid ID)
        - [x] Test forbidden access (wrong user's session)

- [x] **Task 6.3: Configuration Standardization (BE)**
    - [x] Centralize security-critical settings into the `Config` struct in `config.rs`:
        - [x] Move `COOKIE_SIGNING_KEY` from router setup into the config
        - [x] Add `PORT` configuration to Config
        - [x] Add session cookie `secure` flag configuration (`SESSION_COOKIE_SECURE`)
    - [x] Update `main.rs` to use these centralized settings consistently

- [x] **Task 6.4: Minor Improvements (BE)**
    - [x] Decide if character `first_mes` should be embedded for RAG context and implement in `chat_service::create_session_and_maybe_first_message` to call `chat_service::save_message` instead of direct insertion
    - [x] Standardize authentication method in `get_character_image` route to use `AuthSession` instead of `Extension<User>`
    - [x] Remove redundant code:
        - [x] Remove unused async `verify_password` helper from `auth/mod.rs`
        - [x] Consider removing unused `NewCharacterMetadata` struct from `models/characters.rs`
    - [x] Address TODOs:
        - [x] TODOs in `text_processing/chunking.rs` regarding token-based chunking
        - [x] TODOs for handling overly long sentences in chunking
        - [x] TODOs in `vector_db/qdrant_client.rs` for configurable parameters
    - [x] Make CLI more robust:
        - [x] Fix CLI test card path to be workspace-relative (using manifest dir) instead of CLI directory-relative
        - [x] Remove unnecessary `#[async_trait]` from `cli/src/io.rs::IoHandler` since methods are synchronous


## MVP Definition

The MVP is complete when a user can:

1.  **Register and log in.**
2.  Upload a V2/V3 character card PNG **(associated with their account)**.
3.  Select **their** character and start a chat session.
4.  Send messages and receive AI responses generated by Google Gemini **within their session**.
5.  Experience basic long-term context recall via the background RAG system **for their chat**.
6.  View and modify a basic System Prompt, Temperature, and Max Output Tokens for **their** current chat.

## Post-MVP Considerations

*   **High Priority:**
    *   **Function Calling:** Allow the LLM to call predefined tools/functions.
    *   **Web Search:** Integrate external web search capabilities into the LLM context.
    *   **Inline Image Handling:** Support sending and displaying images within chat for multimodal models.
*   **Localization:** Supporting multiple languages is a major priority and localizing the UI and API responses. Target audience is English, Chinese, and Spanish speakers with future plans for more (i.e., Russian, French, German, etc.).
*   **Federation Support:** Implementing federation protocols (e.g., ActivityPub) to allow instances to connect and share data/interactions.
*   **Advanced Moderation:** Building robust content moderation tools (AI classifiers, hash matching for illegal content), configurable policies (`policy.toml` concept), and moderation dashboards.
*   **Age Verification:** Integrating reliable age-gating mechanisms for compliance with local laws like GDPR, COPPA, etc. (e.g., ID scan, payment methods).
*   **Multi-Instance Deployment:** Strategies and tooling for deploying/managing both a central Sanguine Host instance and facilitating community self-hosting.
*   **Open-Core Features:** Clearly defining and potentially implementing premium features or services for the open-core model (e.g., advanced hosting, enterprise support, specialized integrations).
*   **Transparency Reporting:** Automating the generation and publication of moderation transparency reports.
*   **Authentication:** Implementing a more secure and flexible authentication system (e.g., OAuth, JWT, external IdP integration such as Google, Okta, etc.).
*   **Local Models:** Support for local models (Llama.cpp, Ollama).
*   **Advanced Prompt Controls:** Advanced prompt controls (Jailbreaks, Author's Notes, Instruct Mode).
*   **UI for Managing RAG Memories:** UI for managing RAG memories ("forgetting").
    *   **Advanced History Summarization:** Implement techniques (e.g., abstractive summarization) within the chat history management (Epic 2) to retain long-term context more effectively than simple truncation/windowing.
    *   **More Sophisticated Chunking/Summarization Strategies for RAG:** Improve RAG effectiveness with better chunking methods or summarizing retrieved context before injection.
    *   **Character Editing Interface:** Character editing interface.
    *   **UI Polish and Theming:** UI Polish and Theming.
    *   **Group Chats, World Info (Static).**
    *   **Streaming improvements/alternatives (WebSockets).**
    *   **More robust error handling and user feedback.**
    *   **Security Enhancements:** Separate User DB, Advanced Microsegmentation, Refresh Tokens, Rate Limiting, Account Lockout, MFA, External IdP Integration, Audit Logging.

### Epic 7 – Post‑MVP Seeds (scaffolding only)

- [ ] **Task 7.1 Tagging Migration (BE)**  
      *Add `content_rating` column (ENUM) to characters, chat_sessions, chat_messages; default `SFW`.*

- [ ] **Task 7.2 Plugin SDK Stub (BE)**  
      *Expose `/api/tools/invoke` → currently logs request; write unit test for accepted payload.*

- [ ] **Task 7.3 Federation Proof‑of‑Concept (DevOps)**  
      *Spin up a second docker‑compose stack (`node‑B`) with different BASE_URL; export a character from node‑A, import into node‑B with signature verification.*