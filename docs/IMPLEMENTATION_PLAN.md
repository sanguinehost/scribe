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
*   Any related documentation (e.g., API changes, architecture updates) has been updated.

Only mark a task checkbox (`- [x]`) when all these conditions are satisfied.

## Epics & Tasks

---

### Epic 0: Project Setup & Foundation

*Goal: Establish the basic project structure, dependencies, database connections, and authentication.*

- [ ] **Task 0.1: Backend Project Setup (BE)**
    *   Initialize Rust project (`cargo new --lib scribe-backend`) using the Axum web framework.
    *   Add core dependencies (Axum, `tokio`, `serde`, `diesel` [with relevant features like `postgres`, `chrono`, etc.], `qdrant-client`, `jsonwebtoken`, logging, error handling).
    *   Configure basic logging and error handling middleware.
    *   *TDD:* Implement `/api/health` endpoint and corresponding test.
- [ ] **Task 0.2: Frontend Project Setup (FE)**
    *   Initialize SvelteKit project (`npm create svelte@latest scribe-frontend`). Choose Skeleton project with TypeScript.
    *   Setup basic project structure (routes, components, stores, lib).
    *   Configure basic styling (e.g., TailwindCSS or basic CSS).
    *   *TDD:* Basic component rendering tests (e.g., using Vitest).
- [ ] **Task 0.3: Database Setup (DevOps/BE)**
    *   Create `docker-compose.yml` for PostgreSQL and Qdrant services.
    *   Configure initial database connection strings/environment variables for the backend.
- [ ] **Task 0.4: PostgreSQL Schema & Migrations (BE)**
    *   Define initial schema using `diesel_cli` and Diesel migrations for: `users`, `characters` (metadata only), `chat_sessions`, `chat_messages`.
    *   Setup `diesel.toml` configuration.
    *   Implement migration runner integrated with Diesel.
    *   *TDD:* Write tests to verify migrations apply correctly and schema matches expectations using Diesel's testing features.
- [ ] **Task 0.5: Authentication (BE & FE)**
    *   (BE) Implement JWT generation/validation logic.
    *   (BE) API endpoints: `/api/auth/register`, `/api/auth/login`. (Store hashed passwords in `users` table).
    *   (BE) Implement authentication middleware to protect private API routes.
    *   (FE) Create Login/Register page components.
    *   (FE) Implement API calls for login/register, store JWT securely (e.g., HttpOnly cookie or secure local storage).
    *   (FE) Implement routing guards/logic to handle authenticated state.
    *   *TDD:* (BE) Unit tests for JWT logic, API tests for auth endpoints. (FE) Component tests for login/register forms.

---

### Epic 1: Character Management

*Goal: Allow users to upload, view, and select V2 character cards.*

- [ ] **Task 1.1: Character Card Parser (BE)**
    *   Implement Rust logic to parse JSON data from PNG `tEXt` chunks (`chara` keyword, Base64 decode) based on `src/character-card-parser.js`. Focus on reading V2 spec fields (`name`, `description`, `personality`, `first_mes`, `mes_example`, `scenario`).
    *   *TDD:* Unit tests with various valid and invalid V2 card PNGs/JSONs.
- [ ] **Task 1.2: Character API Endpoints (BE)**
    *   `POST /api/characters/upload`: Accepts PNG file, uses parser (Task 1.1), saves essential metadata (`name`, `creator`, file reference, user ID) to PostgreSQL `characters` table. Store the original card file (or relevant data) for later use.
    *   `GET /api/characters`: Retrieves list of characters (metadata) for the authenticated user from PostgreSQL.
    *   `GET /api/characters/{id}`: Retrieves full details for a selected character (potentially reading card file on demand or storing more in DB).
    *   *TDD:* API integration tests for upload, list, and get endpoints.
- [ ] **Task 1.3: Character UI (FE)**
    *   Create `CharacterList` Svelte component: Fetches characters via API (Task 1.2), displays them (name, avatar preview).
    *   Implement character selection logic (update application state/store).
    *   Create `CharacterUploader` Svelte component: Handles file input and calls upload API (Task 1.2).
    *   *TDD:* Component tests for list rendering, selection, and upload interaction.

---

### Epic 2: Core Chat Loop

*Goal: Enable basic chat functionality: creating sessions, sending/receiving messages, basic prompt assembly.*

- [ ] **Task 2.1: Chat Session & History API (BE)**
    *   `POST /api/chats`: Creates a new chat session linked to a user and character ID in PostgreSQL `chat_sessions`.
    *   `GET /api/chats`: Lists chat sessions for the user.
    *   `GET /api/chats/{id}/messages`: Retrieves message history for a session from PostgreSQL `chat_messages`, implementing pagination.
    *   *TDD:* API tests for session CRUD and message retrieval.
- [ ] **Task 2.2: Save Message API (BE)**
    *   `POST /api/chats/{id}/messages`: Endpoint to receive and save user or AI messages to the `chat_messages` table (content, speaker, timestamp, session ID).
    *   *TDD:* API tests for message saving.
- [ ] **Task 2.3: Gemini Generation Client (BE)**
    *   Implement Rust module to interact with the Google Gemini Generation API (handling API key, request formatting, response parsing, basic error handling).
    *   *TDD:* Unit tests mocking the Gemini API client interface.
- [ ] **Task 2.4: Basic Prompt Assembly (BE)**
    *   Implement initial logic to retrieve character data (from DB/card), system prompt (from settings - see Epic 4), and recent chat history (from DB - Task 2.1).
    *   Combine these into a basic prompt string suitable for Gemini.
    *   *TDD:* Unit tests for prompt assembly logic with different inputs.
- [ ] **Task 2.5: Generation API Endpoint (BE)**
    *   `POST /api/chats/{id}/generate`:
        *   Receives trigger (e.g., user message ID or just session ID).
        *   Calls prompt assembly logic (Task 2.4).
        *   Sends prompt to Gemini client (Task 2.3).
        *   Handles response (streaming preferred via SSE or WebSockets, fallback to simple response).
        *   Saves AI response via Save Message API (Task 2.2).
        *   Returns AI response to frontend.
    *   *TDD:* API integration tests for the generation flow (mocking Gemini).
- [ ] **Task 2.6: Chat UI Components (FE)**
    *   Create `ChatWindow` Svelte component: Displays messages fetched from API (Task 2.1). Handles scrolling.
    *   Create `MessageBubble` component for rendering individual messages.
    *   Create `MessageInput` component for user text entry and send button.
    *   *TDD:* Component tests for rendering messages and input handling.
- [ ] **Task 2.7: Frontend Chat Logic (FE)**
    *   Implement Svelte store/state management for current chat session and messages.
    *   Logic to call API for sending user messages (Task 2.2) and triggering generation (Task 2.5).
    *   Handle receiving and displaying streamed/complete AI responses.
    *   Logic to fetch initial message history (Task 2.1).

---

### Epic 3: Dynamic Context (RAG MVP)

*Goal: Implement the core RAG pipeline using Gemini embeddings and Qdrant.*

- [ ] **Task 3.1: Gemini Embedding Client (BE)**
    *   Implement Rust module to interact with the Google Gemini Embedding API.
    *   *TDD:* Unit tests mocking the Gemini Embedding API client.
- [ ] **Task 3.2: Qdrant Client Service (BE)**
    *   Implement Rust service to interact with Qdrant (create collection, add points, search points) using the `qdrant-client` crate.
    *   *TDD:* Integration tests against a local Qdrant instance (via Docker).
- [ ] **Task 3.3: Chat History Chunking (BE)**
    *   Implement logic to divide chat messages into meaningful chunks (e.g., by message pairs, fixed token count, sentence boundaries - requires experimentation).
    *   *TDD:* Unit tests for various chunking strategies.
- [ ] **Task 3.4: Embedding & Storage Pipeline (BE)**
    *   Implement an asynchronous mechanism (e.g., background job queue like `tokio::spawn` or a dedicated queue system if scaling needed later) triggered after a message is saved (Task 2.2).
    *   This task takes message chunks (Task 3.3), gets embeddings via Gemini client (Task 3.1), and stores vectors + metadata in Qdrant via the Qdrant service (Task 3.2).
    *   *TDD:* Integration test for the end-to-end embedding pipeline.
- [ ] **Task 3.5: RAG Query Logic (BE)**
    *   Modify Core Logic (from Epic 2): Before prompt assembly, take recent context, get its embedding (Task 3.1).
    *   Query Qdrant service (Task 3.2) using this embedding to find top K similar historical chunks.
    *   *TDD:* Unit/Integration tests for the RAG query process.
- [ ] **Task 3.6: RAG Context Injection (BE)**
    *   Modify Prompt Assembly (Task 2.4): Integrate the retrieved chunks (Task 3.5) into the final prompt string (e.g., add a specific section like `[Retrieved Memories] ... snippets ... [/Retrieved Memories]`). Determine optimal formatting and placement.
    *   *TDD:* Unit tests verifying correct injection formatting.

---

### Epic 4: Basic Prompt Control (MVP)

*Goal: Allow users to set basic generation parameters and a system prompt.*

- [ ] **Task 4.1: Database Schema Update (BE)**
    *   Add columns to `characters` or `chat_sessions` table for `system_prompt` (text), `temperature` (float), `max_output_tokens` (integer).
    *   Update migrations (Task 0.4).
- [ ] **Task 4.2: API & Logic for Settings (BE)**
    *   API endpoints (e.g., `PUT /api/chats/{id}/settings`, `GET /api/chats/{id}/settings`) to update/retrieve these settings from PostgreSQL.
    *   Modify Prompt Assembly (Task 2.4) to use the stored `system_prompt`.
    *   Modify Gemini Client call (Task 2.3 / Task 2.5) to pass `temperature` and `max_output_tokens`.
    *   *TDD:* API tests for settings endpoints, Unit tests for parameter application.
- [ ] **Task 4.3: Settings UI (FE)**
    *   Create basic `SettingsPanel` Svelte component.
    *   Add inputs for System Prompt, Temperature, Max Tokens.
    *   Implement logic to fetch current settings (Task 4.2) and save changes via API.
    *   *TDD:* Component tests for settings display and input.

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

1.  Register and log in.
2.  Upload a V2 character card PNG.
3.  Select a character and start a chat session.
4.  Send messages and receive AI responses generated by Google Gemini.
5.  Experience basic long-term context recall via the background RAG system (Qdrant search results are injected into prompts).
6.  View and modify a basic System Prompt, Temperature, and Max Output Tokens for the current chat.

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