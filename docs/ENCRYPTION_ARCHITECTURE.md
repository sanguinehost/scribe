# Scribe - Encryption Architecture for Data At Rest (Per-User Keys)

This document outlines the architecture for encrypting all user-generated content at rest within the Scribe system. It uses a unique Data Encryption Key (DEK) per user, which is protected by a Key Encryption Key (KEK) derived from their password. This model ensures that user data stored in the database is unreadable by administrators or in case of direct database compromise, as the server only handles plaintext DEKs in memory during an active, authenticated user session. It also includes provisions for user-controlled recovery.

**I. Core Components & Principles:**

1.  **Key Hierarchy:**
    *   **Data Encryption Key (DEK):** A strong, randomly generated symmetric key (e.g., AES-256, implemented as `SecretBox<Vec<u8>>`) unique to each user. This key directly encrypts the user's actual data (e.g., chat messages, character details).
    *   **Key Encryption Key (KEK):** Derived from the user's password and a unique, per-user salt (`kek_salt`) using a strong KDF (Argon2id). The KEK encrypts the user's DEK.
    *   **Encrypted DEK Storage:** The DEK, encrypted by the KEK (along with a nonce, `dek_nonce`), is stored in the database alongside the user's record.
    *   **DEK in Memory:** The plaintext DEK only exists in server memory (wrapped in `SerializableSecretDek` which holds a `SecretBox<Vec<u8>>`) during an active, authenticated user session after being decrypted by the KEK. It is **never stored persistently in plaintext**.
2.  **Key Derivation Salt (`kek_salt`):**
    *   A field, `kek_salt` (e.g., `String` storing Base64 encoded bytes), is added to the `users` table and relevant `User` structs.
    *   Generated randomly and uniquely for each user upon registration. Stored in the database.
3.  **Optional User-Controlled Recovery Key/Phrase:**
    *   Upon account creation (or later), users have the *option* to generate/provide a high-entropy recovery key/phrase.
    *   This recovery phrase is used to derive a **Recovery KEK (RKEK)** using a `recovery_kek_salt`.
    *   The user's DEK is *also* encrypted by this RKEK (along with a nonce, `recovery_dek_nonce`), and this second encrypted DEK (`encrypted_dek_by_recovery`) is stored in the database.
    *   The server **never stores the plaintext recovery phrase**. The user is solely responsible for its safekeeping.
    *   This allows a user who forgets their password to use their recovery phrase to decrypt their DEK and then set a new password (which involves re-encrypting the DEK with a new KEK derived from the new password).
4.  **Encryption Algorithm:**
    *   AES-256-GCM: Provides strong symmetric encryption with authentication (integrity).
    *   Each encrypted data value (including the DEK itself when encrypted by KEK/RKEK, and user content encrypted by DEK) requires a unique Initialization Vector (IV) / Nonce. The IV is not secret and is stored alongside the ciphertext (e.g., in a separate column like `dek_nonce`, `recovery_dek_nonce`, `content_nonce`).
5.  **Data Storage:**
    *   Database columns storing sensitive plaintext are changed to `BYTEA` (PostgreSQL binary type) to store raw ciphertext.
    *   Nonces (IVs) are stored alongside their respective ciphertexts.

**II. Implementation Steps (Reflecting Current Implementation):**

1.  **Database Schema Modification:**
    *   Added `kek_salt VARCHAR(128)` to `users` table.
    *   Added `encrypted_dek BYTEA` to `users` table.
    *   Added `dek_nonce BYTEA` to `users` table.
    *   Added `encrypted_dek_by_recovery BYTEA NULLABLE` to `users` table.
    *   Added `recovery_kek_salt VARCHAR(128) NULLABLE` to `users` table.
    *   Added `recovery_dek_nonce BYTEA NULLABLE` to `users` table.
    *   Modified data tables (e.g., `chat_messages.content` to `BYTEA`, added `chat_messages.content_nonce BYTEA`) for ciphertext and nonces.
    *   Diesel migrations created and applied.
2.  **Model Updates ([`backend/src/models/users.rs`](backend/src/models/users.rs)):**
    *   Added `pub kek_salt: String;`
    *   Added `pub encrypted_dek: Vec<u8>;`
    *   Added `pub dek_nonce: Vec<u8>;`
    *   Added `pub encrypted_dek_by_recovery: Option<Vec<u8>>;`
    *   Added `pub recovery_kek_salt: Option<String>;`
    *   Added `pub recovery_dek_nonce: Option<Vec<u8>>;`
    *   Added transient `pub dek: Option<SerializableSecretDek>; // Wraps SecretBox<Vec<u8>>` to `User` struct.
    *   Updated `NewUser` struct accordingly.
3.  **User Registration Flow (`register_handler` & `auth::create_user`):**
    *   In `crate::auth::create_user`:
        *   Generates a strong, random DEK (`SecretBox<Vec<u8>>`).
        *   Generates a random `kek_salt`.
        *   Derives KEK from user's password and `kek_salt`.
        *   Encrypts the DEK with the KEK using AES-GCM, obtaining `encrypted_dek` and `dek_nonce`.
        *   Saves `kek_salt`, `encrypted_dek`, and `dek_nonce` with the new user.
        *   If recovery phrase is provided/generated:
            *   Generates `recovery_kek_salt`.
            *   Derives RKEK from recovery phrase and `recovery_kek_salt`.
            *   Encrypts the *same* DEK with the RKEK, obtaining `encrypted_dek_by_recovery` and `recovery_dek_nonce`.
            *   Saves these recovery-related fields.
            *   Emphasizes to user the importance of password and recovery phrase.
4.  **Login Flow (`login_handler` & `auth::verify_credentials`):**
    *   After basic password verification:
        *   Retrieves `user.kek_salt`, `user.encrypted_dek`, and `user.dek_nonce`.
        *   Derives KEK from `payload.password` and `user.kek_salt`.
        *   Decrypts `user.encrypted_dek` using the derived KEK and `user.dek_nonce` to get the plaintext DEK.
        *   Stores plaintext DEK in `user.dek = Some(SerializableSecretDek(SecretBox::new(Box::new(plaintext_dek_bytes))));`.
        *   Proceeds with `auth_session.login(&user).await`.
5.  **Cryptographic Module (`crate::crypto`):**
    *   Functions for:
        *   KEK/RKEK derivation (Argon2id).
        *   DEK generation (secure random, returns `SecretBox<Vec<u8>>`).
        *   AES-256-GCM encryption/decryption (takes `&SecretBox<Vec<u8>>` for key, returns ciphertext and nonce separately for encryption; takes ciphertext, nonce, key for decryption).
    *   Handles nonces correctly.
6.  **Data Access Layer Modifications (e.g., `ChatService`, `CharacterService`):**
    *   **Writes:** Retrieve plaintext DEK from `auth_session.user.dek`. Pass DEK to `EncryptionService` (or use `crypto.rs` functions directly) to encrypt data. Store ciphertext + nonce.
    *   **Reads:** Retrieve plaintext DEK from `auth_session.user.dek`. Pass DEK, ciphertext, and nonce to `EncryptionService` (or `crypto.rs`) to decrypt data.
7.  **Password Change Functionality (`auth::change_user_password`):**
    *   User provides old password, new password.
    *   Verifies old password. Derives old KEK. Decrypts `encrypted_dek` (with `dek_nonce`) to get plaintext DEK.
    *   Generates new `kek_salt`. Derives *new* KEK from new password and new `kek_salt`.
    *   Re-encrypts the plaintext DEK with the *new* KEK, obtaining new `encrypted_dek` and new `dek_nonce`.
    *   Updates `password_hash`, `kek_salt`, `encrypted_dek`, and `dek_nonce` in the database.
    *   `encrypted_dek_by_recovery` and `recovery_dek_nonce` remain unchanged as the recovery phrase itself hasn't changed.
8.  **Password Recovery via Recovery Phrase (`auth::recover_user_password_with_phrase`):**
    *   User provides recovery phrase and new password.
    *   Server retrieves `user.encrypted_dek_by_recovery`, `user.recovery_kek_salt`, and `user.recovery_dek_nonce`.
    *   Derives RKEK from provided recovery phrase and `user.recovery_kek_salt`.
    *   Decrypts `user.encrypted_dek_by_recovery` using RKEK and `user.recovery_dek_nonce` to get plaintext DEK.
    *   Generates new `kek_salt`. Derives new KEK from new password and new `kek_salt`.
    *   Re-encrypts the plaintext DEK with this new KEK, obtaining new `encrypted_dek` and new `dek_nonce`.
    *   Updates `password_hash`, `kek_salt`, `encrypted_dek`, and `dek_nonce` in the database.
9.  **Data Export & Deletion (GDPR):**
    *   **Export:** User provides password -> KEK derived -> DEK decrypted -> Data decrypted and exported.
    *   **Deletion:** Delete user record (including salts, encrypted DEKs, nonces). Data becomes cryptographically irrecoverable.
10. **User Experience & Security Enhancements (Current & Planned):**
    *   Strong Password Guidance: During registration.
    *   Clear Communication: About password loss implications and recovery phrase importance.
    *   (Post-MVP) 2FA (TOTP/Hardware Key): Implement for account login (protects access to KEK derivation).
    *   (Post-MVP) "Remember Me" / Secure Session Management.

**III. Security Considerations & Best Practices:** (As implemented and planned)

*   Strong KDF parameters (Argon2id).
*   Unique Nonces (IVs) for every AES-GCM operation, stored alongside ciphertext.
*   Robust error handling in cryptographic operations.
*   Use vetted crypto libraries (`ring`, `argon2`, `rand`).
*   `secrecy` crate (`SecretString`, `SecretBox`) for in-memory secrets like passwords and DEKs.
*   Thorough testing of cryptographic flows. Security audits are recommended post-MVP.

**IV. Diagram: Updated Key Hierarchy and Data Flow**

```mermaid
graph TD
    subgraph User Registration
        U_Pass[User Password] -->|Argon2id KDF + KEK_Salt| KEK["Key Encryption Key (SecretBox)"]
        Rand_DEK["Random DEK Generated (SecretBox)"] -->|AES-GCM Encrypt with KEK + New DEK_Nonce| Enc_DEK_Bundle[Encrypted DEK + DEK_Nonce]
        Enc_DEK_Bundle --> DB_Users["(users.encrypted_dek, users.dek_nonce)"]
        KEK_Salt[KEK Salt Generated] --> DB_Users_Salt["(users.kek_salt)"]

        U_Recovery[Optional: User Recovery Phrase] -->|Argon2id KDF + Rec_KEK_Salt| RKEK["Recovery KEK (SecretBox)"]
        Rand_DEK -->|AES-GCM Encrypt with RKEK + New Rec_DEK_Nonce| Enc_DEK_Rec_Bundle[Encrypted DEK by Recovery + Rec_DEK_Nonce]
        Enc_DEK_Rec_Bundle --> DB_Users_Rec["(users.encrypted_dek_by_recovery, users.recovery_dek_nonce)"]
        Rec_KEK_Salt[Recovery KEK Salt Generated] --> DB_Users_Rec_Salt["(users.recovery_kek_salt)"]
    end

    subgraph User Login & Data Access
        Login_Pass[Login Password] -->|Argon2id KDF + users.kek_salt| Derived_KEK["Derived KEK (SecretBox)"]
        DB_Users_Login["(users.encrypted_dek, users.dek_nonce)"] -->|AES-GCM Decrypt with Derived_KEK & users.dek_nonce| Plain_DEK["Plaintext DEK (SecretBox)"]
        Plain_DEK --> Session_DEK["DEK in User Session (SerializableSecretDek wraps SecretBox)"]

        UserData_Plain["Plaintext User Data (e.g., chat message)"] <-->|AES-GCM Encrypt/Decrypt with Session_DEK + New Content_Nonce| UserData_Cipher_Bundle[Ciphertext User Data + Content_Nonce]
        UserData_Cipher_Bundle <--> DB_Data["(Database: chat_messages.content, chat_messages.content_nonce etc.)"]
    end

    subgraph Password Change
        Old_Pass[Old Password] -->|KDF + KEK_Salt| Old_KEK
        DB_Users_PChange["(users.encrypted_dek, users.dek_nonce)"] -->|Decrypt with Old_KEK & users.dek_nonce| Plain_DEK_PChange["Plaintext DEK (SecretBox)"]
        New_Pass[New Password] -->|KDF + New_KEK_Salt| New_KEK
        Plain_DEK_PChange -->|Encrypt with New_KEK + New_DEK_Nonce| New_Enc_DEK_Bundle[New Encrypted DEK + New DEK_Nonce]
        New_Enc_DEK_Bundle --> DB_Users_PChange_Update["(Update users.encrypted_dek, users.dek_nonce, users.kek_salt)"]
    end

    subgraph Password Recovery
        Recovery_Phrase[User's Recovery Phrase] -->|KDF + Rec_KEK_Salt_From_DB| Derived_RKEK
        DB_Users_PRec["(users.encrypted_dek_by_recovery, users.recovery_dek_nonce)"] -->|Decrypt with Derived_RKEK & users.recovery_dek_nonce| Plain_DEK_PRec["Plaintext DEK (SecretBox)"]
        Plain_DEK_PRec --> Prompt_New_Pass[Prompt for New Password]
        %% Then proceed similar to Password Change to set new KEK, new encrypted_dek, and new dek_nonce %%
    end