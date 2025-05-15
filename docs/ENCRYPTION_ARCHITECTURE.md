# Detailed Plan: Per-User End-to-End Encryption (Incorporating Review Feedback)

This plan aims to encrypt all user-generated content using a unique Data Encryption Key (DEK) per user, protected by a Key Encryption Key (KEK) derived from their password, ensuring administrators cannot decrypt user data. It also includes provisions for user-controlled recovery.

**I. Core Components & Principles:**

1.  **Key Hierarchy:**
    *   **Data Encryption Key (DEK):** A strong, randomly generated symmetric key (e.g., AES-256) unique to each user. This key directly encrypts the user's actual data.
    *   **Key Encryption Key (KEK):** Derived from the user's password and a unique, per-user salt (`kek_salt`) using a strong KDF (Argon2id recommended). The KEK encrypts the user's DEK.
    *   **Encrypted DEK Storage:** The DEK, encrypted by the KEK, is stored in the database alongside the user's record.
    *   **DEK in Memory:** The plaintext DEK only exists in server memory during an active, authenticated user session after being decrypted by the KEK. It is **never stored persistently in plaintext**.
2.  **Key Derivation Salt (`kek_salt`):**
    *   A new field, `kek_salt` (e.g., `String` storing Base64 or Hex encoded bytes), will be added to the `users` table and relevant `User` structs.
    *   Generated randomly and uniquely for each user upon registration. Stored in the database.
3.  **Optional User-Controlled Recovery Key/Phrase:**
    *   Upon account creation (or later), users will have the *option* to generate a high-entropy recovery key/phrase (e.g., 12-24 words).
    *   This recovery phrase will be used to derive a **Recovery KEK (RKEK)**.
    *   The user's DEK will *also* be encrypted by this RKEK, and this second encrypted DEK (let's call it `encrypted_dek_by_recovery`) will be stored in the database.
    *   The server **never stores the plaintext recovery phrase**. The user is solely responsible for its safekeeping.
    *   This allows a user who forgets their password to use their recovery phrase to decrypt their DEK and then set a new password (which involves re-encrypting the DEK with a new KEK derived from the new password).
4.  **Encryption Algorithm:**
    *   AES-256-GCM: Provides strong symmetric encryption with authentication (integrity).
    *   Each encrypted data value will require a unique Initialization Vector (IV) / Nonce. The IV is not secret and will be stored alongside the ciphertext (e.g., prepended or in a separate column).
5.  **Data Storage:**
    *   Database columns currently storing sensitive plaintext (e.g., `TEXT`, `VARCHAR`) will be changed to `BYTEA` (PostgreSQL binary type) to store raw ciphertext. Alternatively, Base64 encode ciphertext and store as `TEXT`.
    *   IVs will be stored with the ciphertext.

**II. Implementation Steps:**

1.  **Database Schema Modification:**
    *   Add `kek_salt VARCHAR(128)` (or similar) to `users` table.
    *   Add `encrypted_dek BYTEA` to `users` table (to store DEK encrypted by KEK).
    *   Add `encrypted_dek_by_recovery BYTEA NULLABLE` to `users` table.
    *   Add `recovery_kek_salt VARCHAR(128) NULLABLE` to `users` table (if recovery KEK derivation also needs a salt, which is good practice).
    *   Modify data tables (e.g., `chat_messages`) for `BYTEA` ciphertext and IVs.
    *   Create Diesel migrations.
2.  **Model Updates ([`backend/src/models/users.rs`](backend/src/models/users.rs)):**
    *   Add `pub kek_salt: String;`
    *   Add `pub encrypted_dek: Vec<u8>;`
    *   Add `pub encrypted_dek_by_recovery: Option<Vec<u8>>;`
    *   Add `pub recovery_kek_salt: Option<String>;`
    *   Add transient `#[serde(skip)] pub dek: Option<Secret<Vec<u8>>>;` to `User` struct.
    *   Update `NewUser` struct accordingly.
3.  **User Registration Flow (`register_handler` & `create_user`):**
    *   In `crate::auth::create_user`:
        *   Generate a strong, random DEK (e.g., 32 bytes for AES-256).
        *   Generate a random `kek_salt`.
        *   Derive KEK from user's password and `kek_salt`.
        *   Encrypt the DEK with the KEK. Store this as `encrypted_dek`.
        *   Save `kek_salt` and `encrypted_dek` with the new user.
        *   Prompt user *optionally* to set up a recovery phrase. If they agree:
            *   Client-side (or server-side if carefully managed) generates recovery phrase. User *must* write it down.
            *   Generate `recovery_kek_salt`.
            *   Derive RKEK from recovery phrase and `recovery_kek_salt`.
            *   Encrypt the *same* DEK with the RKEK. Store as `encrypted_dek_by_recovery`.
            *   Save `recovery_kek_salt`.
            *   **Emphasize strongly that if they lose both password AND recovery phrase, data is gone.**
4.  **Login Flow (`login_handler`):**
    *   After `auth_session.authenticate(payload).await` retrieves the `user` object (which now includes `kek_salt` and `encrypted_dek`):
        *   Derive KEK from `payload.password` and `user.kek_salt`.
        *   Decrypt `user.encrypted_dek` using the derived KEK to get the plaintext DEK.
        *   Store plaintext DEK in `user.dek = Some(Secret::new(plaintext_dek_bytes));`.
        *   Proceed with `auth_session.login(&user).await`.
5.  **Cryptographic Service/Module (`crate::crypto`):**
    *   Functions for:
        *   KEK/RKEK derivation (Argon2id).
        *   DEK generation (secure random).
        *   AES-256-GCM encryption/decryption (for data with DEK, and for DEK with KEK/RKEK).
    *   Handle IVs correctly.
6.  **Data Access Layer Modifications:**
    *   **Writes:** Retrieve DEK from `auth_session.user.dek`. Encrypt data. Store ciphertext + IV.
    *   **Reads:** Retrieve DEK from `auth_session.user.dek`. Decrypt data.
7.  **Password Change Functionality:**
    *   User provides old password, new password.
    *   **Step 1: Authenticate & Get Plaintext DEK:** Verify old password. Derive old KEK. Decrypt `encrypted_dek` to get plaintext DEK.
    *   **Step 2: Derive New KEK:** Derive *new* KEK from new password and the *same* `kek_salt`.
    *   **Step 3: Re-encrypt DEK:** Encrypt the plaintext DEK with the *new* KEK. Update `encrypted_dek` in the database.
    *   **Step 4: Update Password Hash:** Update `password_hash` for login.
    *   *No re-encryption of bulk user data is needed due to the KEK/DEK hierarchy.*
8.  **Password Recovery via Recovery Phrase:**
    *   User indicates they forgot password and have a recovery phrase.
    *   User provides recovery phrase.
    *   Server retrieves `user.encrypted_dek_by_recovery` and `user.recovery_kek_salt`.
    *   Derive RKEK from provided recovery phrase and `user.recovery_kek_salt`.
    *   Decrypt `user.encrypted_dek_by_recovery` using RKEK to get plaintext DEK.
    *   Prompt user to set a new password.
    *   Derive new KEK from new password and `user.kek_salt`.
    *   Re-encrypt the plaintext DEK with this new KEK. Update `user.encrypted_dek`.
    *   Update `password_hash` for login.
9.  **Data Export & Deletion (GDPR):**
    *   **Export:** User provides password -> KEK derived -> DEK decrypted -> Data decrypted and exported.
    *   **Deletion:** Delete user record (including salts, encrypted DEKs). Data becomes cryptographically irrecoverable.
10. **User Experience & Security Enhancements:**
    *   **Strong Password Guidance:** During registration.
    *   **Clear Communication:** About password loss implications and recovery phrase importance.
    *   **2FA (TOTP/Hardware Key):** Implement for account login (protects access to KEK derivation).
    *   **"Remember Me" / Secure Session Management:** Client-side secure storage of session tokens or DEK (encrypted with a device-specific key), if feasible and desired for UX.

**III. Security Considerations & Best Practices:** (As outlined in the previous plan and reinforced by the review)

*   Strong KDF parameters (Argon2id).
*   Unique IVs for every AES-GCM operation.
*   Robust error handling.
*   Use vetted crypto libraries.
*   `secrecy` crate for in-memory secrets.
*   Thorough testing and security audits.

**IV. Diagram: Updated Key Hierarchy and Data Flow**

```mermaid
graph TD
    subgraph User Registration
        U_Pass[User Password] -->|KDF + KEK_Salt| KEK[Key Encryption Key]
        Rand_DEK[Random DEK Generated] -->|AES-GCM Encrypt with KEK| Enc_DEK[Encrypted DEK]
        Enc_DEK --> DB_Users[(users.encrypted_dek)]
        KEK_Salt[KEK Salt Generated] --> DB_Users_Salt[(users.kek_salt)]

        U_Recovery[Optional: User Recovery Phrase] -->|KDF + Rec_KEK_Salt| RKEK[Recovery KEK]
        Rand_DEK -->|AES-GCM Encrypt with RKEK| Enc_DEK_Rec[Encrypted DEK by Recovery]
        Enc_DEK_Rec --> DB_Users_Rec[(users.encrypted_dek_by_recovery)]
        Rec_KEK_Salt[Recovery KEK Salt Generated] --> DB_Users_Rec_Salt[(users.recovery_kek_salt)]
    end

    subgraph User Login & Data Access
        Login_Pass[Login Password] -->|KDF + users.kek_salt| Derived_KEK[Derived KEK]
        DB_Users_Login[(users.encrypted_dek)] -->|AES-GCM Decrypt with Derived_KEK| Plain_DEK[Plaintext DEK (in-memory)]
        Plain_DEK --> Session_DEK[DEK in User Session (Secret<Vec<u8>>)]

        UserData_Plain[Plaintext User Data] <-->|AES-GCM Encrypt/Decrypt with Session_DEK + IV| UserData_Cipher[Ciphertext User Data + IV]
        UserData_Cipher <--> DB_Data[(Database: chat_messages etc.)]
    end

    subgraph Password Change
        Old_Pass[Old Password] -->|KDF + KEK_Salt| Old_KEK
        DB_Users_PChange[(users.encrypted_dek)] -->|Decrypt with Old_KEK| Plain_DEK_PChange
        New_Pass[New Password] -->|KDF + KEK_Salt| New_KEK
        Plain_DEK_PChange -->|Encrypt with New_KEK| New_Enc_DEK
        New_Enc_DEK --> DB_Users_PChange_Update[(Update users.encrypted_dek)]
    end

    subgraph Password Recovery
        Recovery_Phrase[User's Recovery Phrase] -->|KDF + Rec_KEK_Salt_From_DB| Derived_RKEK
        DB_Users_PRec[(users.encrypted_dek_by_recovery)] -->|Decrypt with Derived_RKEK| Plain_DEK_PRec
        Plain_DEK_PRec --> Prompt_New_Pass[Prompt for New Password]
        %% Then proceed similar to Password Change to set new KEK and encrypted_dek %%
    end