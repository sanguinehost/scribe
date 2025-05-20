# Scribe - Authentication & Authorization Design (MVP)

## 1. Overview

This document outlines the authentication and authorization strategy for the Scribe MVP. The primary goal is to provide a secure way for users to register, log in, and interact with their own data (characters, chat sessions) within the application, fulfilling Task 0.5 of the `IMPLEMENTATION_PLAN.md`.

To balance security best practices with MVP scope and complexity, this design utilizes the `axum-login` crate for session management within the application backend, backed by our existing PostgreSQL database.

**Future Considerations:** Integration with external Identity Providers (IdPs) like Okta, Auth0, or cloud provider services (Cognito, Azure AD B2C) and separating the user database are potential post-MVP enhancements for scalability and advanced features like SSO.

## 2. Chosen Framework: `axum-login`

We will use the `axum-login` crate (`axum-login = "0.14.0"` or latest compatible version).

*   **Rationale:** Provides secure session management, CSRF protection (optional but recommended), credential validation integration, and secure cookie handling, reducing the risk associated with manually implementing these features. Integrates well with the Axum framework.

## 3. User Store & Password Management

*   **User Model:** `axum-login` will interact with our existing `User` model (defined in `backend/src/models/users.rs` and the `users` table in PostgreSQL). We will need to implement the `axum_login::AuthUser` trait for our `User` model. The `User` model includes a `role` field (see Authorization section).
*   **Password Hashing:**
    *   **Algorithm:** `bcrypt` will be used for hashing user passwords before storing them in the `password_hash` column of the `users` table.
    *   **Crate:** The `bcrypt` crate (`bcrypt = "0.15.1"` or latest) will be added as a dependency.
    *   **Cost Factor:** A reasonable cost factor (e.g., 12) will be used.
*   **Storage:** Hashed passwords will be stored in the `password_hash` column (TEXT) of the `users` table within the primary PostgreSQL database.

## 4. Session Management & Token Handling

*   **Mechanism:** Session-based authentication managed by `axum-login`. JWTs are *not* directly exposed to the client for session management in this approach.
*   **Session Backend:** A persistent session store will be used, backed by the PostgreSQL database. `axum-login` provides backends like `axum_login::memory_store::MemoryStore` (for testing/simple cases) and requires implementing traits for database persistence (e.g., using `sqlx` or potentially adapting for `diesel`). We will need to implement or find a Diesel-compatible session store implementation for `axum-login`.
    *   *(Implementation Note: If a direct Diesel store isn't readily available for the latest `axum-login`, we might need to write a small adapter or consider if `sqlx` alongside `diesel` for just the session store is feasible, though potentially adding complexity).*
*   **Session Cookie:** `axum-login` will manage the session cookie.
    *   **Security Flags:** The cookie will be configured as `HttpOnly`, `Secure` (in production environments), and `SameSite=Lax` (or `Strict`).
    *   **Expiry:** Session expiry will be configured (e.g., rolling expiry based on activity, configurable duration).
*   **CSRF Protection:** `axum-login`'s built-in CSRF protection layer (`axum_login::axum_sessions::CsrfManagerLayer`) should be considered for enabling, even for API interactions initiated by the frontend, as a defense-in-depth measure.

## 5. API Endpoints & Flow

*   **`/api/auth/register` (POST):**
    *   **Request:** `Json({ username: "user", email: "user@example.com", password: "password", recovery_phrase: "optional phrase" })`
    *   **Logic:**
        1.  Validate input (username length, password complexity - basic checks for MVP, email format).
        2.  Check if username or email already exists. Return `409 Conflict` if so.
        3.  Hash the password using `bcrypt`.
        4.  Perform server-side encryption setup (generate DEK, KEK, encrypt DEK, etc. - see `ENCRYPTION_ARCHITECTURE.md`).
        5.  Assign `UserRole::Administrator` if first user, else `UserRole::User`.
        6.  Insert the new user (username, email, hashed password, role, encryption-related fields) into the `users` table.
    *   **Response:** `201 Created` (potentially with user ID, username, email, role, and generated recovery phrase if applicable) on success, appropriate error codes (`400 Bad Request`, `409 Conflict`, `500 Internal Server Error`) on failure. Does *not* log the user in automatically.
*   **`/api/auth/login` (POST):**
    *   **Request:** `Json({ identifier: "user_or_email", password: "password" })`
    *   **Logic:**
        1.  Find user by username or email. Return `401 Unauthorized` if not found.
        2.  Verify the provided password against the stored hash. Return `401 Unauthorized` if verification fails.
        3.  Check account status (e.g., if locked).
        4.  If verification succeeds, decrypt user's DEK using KEK (derived from password) and store plaintext DEK in session memory.
        5.  Use `AuthSession::login(&user)` to establish the session.
    *   **Response:** `200 OK` (potentially with user info: ID, username, email, role) on success, `401 Unauthorized` on failure, `500 Internal Server Error`.
*   **`/api/auth/logout` (POST):**
    *   **Logic:** Use `AuthSession::logout()` to clear the session (including the in-memory DEK).
    *   **Response:** `200 OK`.
*   **`/api/auth/me` (GET):**
    *   **Logic:** Requires authentication. Uses `AuthSession` to retrieve the current logged-in `User`.
    *   **Response:** `200 OK` with user details (ID, username, email, role), `401 Unauthorized` if not logged in.
*   **`/api/auth/change-password` (POST):**
    *   **Logic:** Requires authentication. Verifies current password, re-keys encrypted DEK with new KEK derived from new password.
    *   **Response:** `200 OK` on success.
*   **`/api/auth/recover-password` (POST):**
    *   **Logic:** Uses recovery phrase to decrypt DEK, allows setting a new password, re-keys DEK.
    *   **Response:** `200 OK` on success.

## 6. Backend Middleware & User Access

*   **`axum-login` Layers:** The necessary `axum_login::AuthManagerLayerBuilder` and session store layers will be added to the Axum router in `main.rs`.
*   **Accessing User:** Authenticated routes will use the `AuthSession` extractor provided by `axum-login` to access the current `User` object (or check if a user is logged in). The `User` object will contain the `role` and the in-memory plaintext DEK (if login was successful).
    *   Example: `async fn protected_route(auth_session: AuthSession)`
*   **Protected Routes:** Routes requiring authentication will extract `AuthSession` and check `auth_session.user`. If `None`, return `401 Unauthorized`. Further authorization checks (role/ownership) will be done within the handler.

## 7. Authorization (MVP)

*   **Strategy:** The MVP employs a combination of ownership-based access control and a basic role-based access control (RBAC) system.
*   **User Roles:**
    *   The system defines three primary roles: `User`, `Moderator`, and `Administrator` (enum `UserRole` in `models/users.rs`).
    *   The first registered user is automatically assigned the `Administrator` role. Subsequent users default to the `User` role during registration.
    *   Roles are stored in the `role` column of the `users` table.
*   **Ownership-Based Control:**
    *   Within authenticated API handlers (e.g., `get_character`, `list_characters`, `get_chat_session`), after retrieving the authenticated `User` object (containing the `user_id`) via `AuthSession`, database queries **must** include a filter condition comparing the resource's `user_id` column with the authenticated user's ID.
    *   Example (Diesel): `.filter(schema::characters::user_id.eq(authenticated_user.id))`
*   **Role-Based Control:**
    *   Specific API endpoints or functionalities (e.g., admin-only operations, moderation actions) can check the `user.role` field of the authenticated `User` object.
    *   Example: An admin dashboard route would verify `if auth_session.user.role == UserRole::Administrator { ... }`.
*   **Failure:**
    *   If a user attempts to access a resource they don't own, the handler should return `403 Forbidden` or `404 Not Found`.
    *   If a user attempts an action not permitted for their role, the handler should return `403 Forbidden`.

## 8. Security Considerations Summary for MVP

*   Use `axum-login` for session management.
*   Use `bcrypt` for password hashing.
*   Implement server-side encryption for sensitive data at rest using user-derived keys (see `ENCRYPTION_ARCHITECTURE.md`).
*   Configure secure HttpOnly cookies.
*   Implement user ownership checks and basic role checks rigorously in all relevant API handlers.
*   Keep user data and application data in separate tables within the single PostgreSQL instance.
*   Consider CSRF protection.

## 9. Post-MVP Security Enhancements

*   Separate User Database.
*   Advanced Microsegmentation (Infrastructure Level).
*   Refresh Tokens.
*   Rate Limiting on Auth Endpoints.
*   Account Lockout Mechanisms (basic status field exists, could be enhanced).
*   Advanced Role/Permission Management: Implementing a more granular permission system beyond the basic MVP roles (e.g., using `casbin-rs` or a similar library for object-level permissions or custom actions).
*   MFA (TOTP using `totp-rs` or `otpauth`).
*   Integration with External IdPs (OAuth/OIDC using `oauth2`).
*   Security Auditing / Logging (basic logging exists, can be enhanced for security events).
