# Frontend Design Overview

## 1. Introduction

This document serves as a central hub for understanding the frontend design related to major features developed and designed within the Sanguine Scribe project, specifically focusing on Character CRUD, Lorebooks, and Personas. It aims to consolidate information and provide links to more detailed design documents and plans created during Phases 2, 3, and 4 of the project as outlined in the [Project Plan: Frontend-Backend Alignment and New Feature Scoping](frontend_backend_alignment_and_new_features_plan.md).

## 2. Character CRUD Features

Character Create, Read, Update, and Delete (CRUD) functionalities form the foundation of managing character entities within the application.

*   **Summary of Capabilities:** The frontend was updated to support manual creation, editing, and deletion of characters. This involved designing and implementing UI forms/dialogs for these operations and integrating them with the backend API. Access points for these features were defined in components like `CharacterCard.svelte` and `CharacterList.svelte`.
*   **High-Level Design Reference:** The initial plan for these features is detailed in the [Project Plan: Frontend-Backend Alignment and New Feature Scoping - Phase 2](frontend_backend_alignment_and_new_features_plan.md#phase-2-implement-missing-character-crud-frontend).
*   **Backend/CLI Plan Context:** For more context on the backend implementation and CLI tool related to character creation, refer to the [Character Creator Plan](features/CHARACTER_CREATOR_PLAN.md).
*   **UI/UX Design Specification (Phase 2, Item 1):** As part of Phase 2, item 1, a UI/UX design specification was produced. This included:
    *   Forms and dialogs for manual character creation and editing.
    *   Confirmation mechanisms for character deletion.
    *   Defined user interface access points (e.g., within `CharacterCard.svelte`, `CharacterList.svelte`).
*   **Future Work Recommendation:** A review noted that "Character CRUD needs more detailed frontend UI/UX specification." This is an area for future enhancement.

## 3. Lorebook Features (Design Phase)

Lorebook features are designed to allow users to create, manage, and associate collections of lore entries with their chat sessions, providing richer context for interactions.

*   **Summary of Planned Features:** The design phase for Lorebooks included defining UI/UX flows for listing, creating, updating, and deleting lorebooks and their individual entries. It also covered how lorebooks would be associated with chat sessions.
*   **Detailed UI/UX Flows:** The specific user interface and user experience flows are documented in [Lorebook UI/UX Flows](lorebook_ui_ux_flows.md).
*   **Svelte Component Structure Proposal:** A proposed Svelte component structure was outlined to support these features. This includes components such as `LorebookList.svelte`, `LorebookListItem.svelte`, `LorebookForm.svelte`, `LorebookDetailView.svelte`, `LorebookEntryList.svelte`, and `LorebookEntryForm.svelte`. This is described in the [Project Plan - Phase 3, Item 2](frontend_backend_alignment_and_new_features_plan.md#phase-3-scope-and-design-new-lorebook-frontend-features).
*   **Data Flow Diagram:** The data flow for Lorebook operations, including creation and association with chats, is visualized in a Mermaid diagram within the [Project Plan - Phase 3, Item 4](frontend_backend_alignment_and_new_features_plan.md#data-flow-diagram-mermaid).
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

## 4. Persona Features (Design Phase)

Persona features are designed to allow users to define and manage different personas they can adopt during chat sessions, influencing the AI's responses.

*   **Summary of Planned Features:** The design phase for Personas included defining UI/UX flows for listing, creating, updating, and deleting user personas. It also covered the functionality for setting a default persona.
*   **Detailed UI/UX Flows:** The specific user interface and user experience flows are documented in [Persona UI/UX Flows](persona_ui_ux_flows.md).
*   **Svelte Component Structure Proposal:** A proposed Svelte component structure was outlined, including components like `PersonaList.svelte`, `PersonaListItem.svelte`, and `PersonaForm.svelte`. This is described in the [Project Plan - Phase 4, Item 2](frontend_backend_alignment_and_new_features_plan.md#phase-4-scope-and-design-new-persona-frontend-features).
*   **Data Flow Diagram:** The data flow for Persona operations, including creation and setting a default persona, is visualized in a Mermaid diagram within the [Project Plan - Phase 4, Item 4](frontend_backend_alignment_and_new_features_plan.md#data-flow-diagram-mermaid-1).
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

## 5. General Frontend Notes (Optional)

*   **Notification Store:** As part of general frontend improvements, a Svelte store for managing application notifications was created: [`frontend/src/lib/stores/notifications.ts`](../../frontend/src/lib/stores/notifications.ts). This provides a centralized way to display feedback and alerts to the user.