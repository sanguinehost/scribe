# Project Plan: Frontend-Backend Alignment and New Feature Scoping

**Objective:**
To conduct a full review of the frontend and backend code to align API interactions after significant backend changes. Scope and design the frontend implementation for new Lorebook and Persona management features.

**Phases:**

## Phase 1: Backend API and Data Structure Alignment

This phase focuses on ensuring the frontend correctly communicates with the updated backend API endpoints and handles data structures as expected.

1.  **Update Backend `CreateChatRequest` DTO:**
    *   **File:** `backend/src/models/chats.rs`
    *   **Action:** Modify the `CreateChatRequest` struct to include optional fields for `system_prompt: Option<String>`, `personality: Option<String>`, and `scenario: Option<String>`.
        ```diff
        // backend/src/models/chats.rs
        #[derive(Deserialize, Serialize)]
        pub struct CreateChatRequest {
            #[serde(default)]
            pub title: String,
            pub character_id: Uuid,
            #[serde(default)]
            pub lorebook_ids: Option<Vec<Uuid>>,
            #[serde(default)]
            pub active_custom_persona_id: Option<Uuid>,
        +   #[serde(default)]
        +   pub system_prompt: Option<String>,
        +   #[serde(default)]
        +   pub personality: Option<String>,
        +   #[serde(default)]
        +   pub scenario: Option<String>,
        }
        ```

2.  **Align Frontend API Client (`apiClient`) Calls:**
    *   **File:** `frontend/src/lib/api/index.ts`
    *   **Actions:**
        *   **Login/Session Handling:**
            *   Simplify frontend logic in `frontend/src/routes/(auth)/[authType=authType]/+page.server.ts` to *not* call its local `createSession` function after a successful login. The backend's `/api/auth/login` response (via `axum-login`) should now handle setting the necessary session cookie.
        *   **Logout:**
            *   Modify frontend logout logic (triggered by `frontend/src/routes/(auth)/signout/+page.server.ts`). Instead of `invalidateSession` calling `apiClient.deleteSession` (`DELETE /api/auth/session/:id`), it should call a new `apiClient` method that makes a `POST` request to `/api/auth/logout`.
            *   Add `logoutUser()` method to `ApiClient`:
                ```typescript
                // frontend/src/lib/api/index.ts
                async logoutUser(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<void, ApiError>> {
                    return this.fetch<void>('/api/auth/logout', { method: 'POST' }, fetchFn);
                }
                ```
            *   Update `frontend/src/lib/server/auth/index.ts` `invalidateSession` to call this new `apiClient.logoutUser()` or have `signout/+page.server.ts` call it directly, and remove the `deleteSessionTokenCookie` call as the backend should handle cookie invalidation.
        *   **Get Chat Session Details:**
            *   Modify `apiClient.getChatById(id)` to target `GET /api/chats/fetch/${id}` instead of `GET /api/chats/${id}`.
        *   **Get Character Details:**
            *   Modify `apiClient.getCharacter(id)` to target `GET /api/characters/fetch/${id}` instead of `GET /api/characters/${id}`.
        *   **Create Chat Session:**
            *   Modify `apiClient.createChat(data)` to target `POST /api/chats/create_session` instead of `POST /api/chats`.

3.  **Align Frontend Data Types with Backend DTOs:**
    *   **Files:** `frontend/src/lib/types.ts`, backend model files.
    *   **Actions:**
        *   **`ScribeChatSession` vs. `ChatForClient`:** Review and align fields, especially numeric types like `temperature` (frontend `number` vs. backend `BigDecimal`).
        *   **`ScribeCharacter` vs. `CharacterDataForClient`:** Confirm frontend's subset is sufficient.
        *   **`ScribeChatMessage` vs. `ChatMessageForClient`:** Confirm consistency.
        *   **`User` / `AuthUser` (Frontend) vs. `AuthResponse` (Backend):** Consider adding `role` and `default_persona_id` to frontend `User` type from backend's `AuthResponse`.

4.  **Verify SSE Event Handling for Chat:**
    *   **Files:** `frontend/src/lib/components/chat.svelte`, backend's `ScribeSseEvent` definition.
    *   **Action:** Confirm SSE event names and payloads match.

## Phase 2: Implement Missing Character CRUD Frontend

1.  **Design UI for Character CRUD:**
    *   Forms/dialogs for manual creation and editing.
    *   Confirmation for deletion.
    *   Define access points in UI (e.g., `CharacterCard.svelte`, `CharacterList.svelte`).

2.  **Implement Frontend Logic and API Calls:**
    *   **Create Character (Manual):** New component, add `createCharacterManual(data)` to `ApiClient` targeting `POST /api/characters/` (payload: `CharacterCreateDto`).
    *   **Update Character:** New/modified component, add `updateCharacter(id, data)` to `ApiClient` targeting `PUT /api/characters/:id` (payload: `CharacterUpdateDto`).
    *   **Delete Character:** Logic in `CharacterList.svelte` or `CharacterCard.svelte`, add `deleteCharacter(id)` to `ApiClient` targeting `DELETE /api/characters/remove/:id`.

3.  **Update `CharacterList.svelte` and `CharacterCard.svelte`:** Add UI elements and state update logic.

## Phase 3: Scope and Design New Lorebook Frontend Features

1.  **Define UI/UX Flows:** For listing, CRUD of lorebooks and entries, and chat association.
2.  **Propose Component Structure:** `LorebookList.svelte`, `LorebookListItem.svelte`, `LorebookForm.svelte`, `LorebookDetailView.svelte`, `LorebookEntryList.svelte`, `LorebookEntryForm.svelte`.
3.  **Map UI Actions to Backend API (`lorebook_routes.rs`):** Create `apiClient` methods for all operations.
4.  **Data Flow Diagram (Mermaid):**
    ```mermaid
    graph TD
        A[User clicks 'New Lorebook'] --> B(Display LorebookForm.svelte);
        B -- Submit Form --> C{apiClient.createLorebook};
        C -- POST /api/lorebooks --> D[Backend: create_lorebook_handler];
        D --> E[DB: lorebooks table];
        C -- Success --> F(Update LorebookList.svelte);

        G[User views Chat Settings] --> H(Display associated lorebooks);
        H --> I[User clicks 'Add Lorebook to Chat'];
        I --> J(Show Lorebook Selector);
        J -- Selects Lorebook & Submits --> K{apiClient.associateLorebookToChat};
        K -- POST /api/chats/:chat_id/lorebooks --> L[Backend: associate_lorebook_to_chat_handler];
        L --> M[DB: chat_session_lorebooks table];
    end
    ```

## Phase 4: Scope and Design New Persona Frontend Features

1.  **Define UI/UX Flows:** For listing, CRUD of personas, and setting default.
2.  **Propose Component Structure:** `PersonaList.svelte`, `PersonaListItem.svelte`, `PersonaForm.svelte`.
3.  **Map UI Actions to Backend API (`user_persona_routes.rs`, `user_settings_routes.rs`):** Create `apiClient` methods.
4.  **Data Flow Diagram (Mermaid):**
    ```mermaid
    graph TD
        A[User clicks 'New Persona'] --> B(Display PersonaForm.svelte);
        B -- Submit Form --> C{apiClient.createUserPersona};
        C -- POST /api/user-personas/ --> D[Backend: create_user_persona_handler];
        D --> E[DB: user_personas table];
        C -- Success --> F(Update PersonaList.svelte);

        G[User clicks 'Set as Default' on PersonaItem] --> H{apiClient.setDefaultPersona};
        H -- PUT /api/user-settings/set_default_persona/:persona_id --> I[Backend: set_default_persona_handler];
        I --> J[DB: users table (update default_persona_id)];
        J --> K(Update UI to reflect new default);
    end
    ```

## Phase 5: Documentation and Review

1.  **Update API Documentation.**
2.  **Frontend Design Documentation.**
3.  **Review Plan with User.**