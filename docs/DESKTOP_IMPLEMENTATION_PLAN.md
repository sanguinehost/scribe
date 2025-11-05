# Scribe Desktop Implementation Plan

## Current Status (Updated: 2025-01-04)

### ✅ Completed Progress

**Phase 1.1: Project Setup & Feature Flags** - COMPLETE
- ✅ Tauri 2.0 initialized and dev server running
- ✅ Cargo feature flags configured (desktop/cloud modes)
- ✅ Dependencies added (lancedb, platform-specific libs)
- ✅ Basic Tauri commands implemented (token storage)

**Phase 1.2: Database Abstraction** - 70% COMPLETE
- ✅ Database backend trait with unified async interface
- ✅ PostgreSQL backend fully working (deadpool-diesel)
- ✅ SQLite type mappings complete (UUID, JSONB, arrays)
- ✅ Automated migration conversion script (425 lines)
- ✅ 67 SQLite migrations converted (100% frontend functionality)
- ⏳ SQLite migrations need testing
- ⏳ Models need multi-backend updates

**Current Work: Secure Quick Start Architecture** - IN PROGRESS
- 🔄 Pivoting from insecure DEK transmission to client-side key generation
- 🔄 Implementing P-256 ECDSA + ChaCha20Poly1305 E2EE architecture
- 🔄 Adding challenge-response authentication

### 🚨 Critical Architecture Pivot

**Previous Approach** (DEPRECATED - Security Issue):
```
Backend generates DEK → Transmits via HTTPS → Client stores → Sends in X-Scribe-Dek header
❌ Vulnerable to MitM attacks, DEK exposed in transit
```

**New Approach** (Gemini 2.5 Pro + User Approved):
```
Client generates P-256 keypair + DEK → Stores locally → Sends public key only → Challenge-response auth
✅ DEK never transmitted, client-side E2EE, challenge-response authentication
```

### 📊 Updated Timeline

**Completed**: ~25 hours (Phase 1.1 + 70% of Phase 1.2)

**Remaining Work**:
- **Security Architecture** (51-68 hours): Client-side keys, E2EE, challenge-response
- **Vector Store Integration** (12-15 hours): LanceDB + hybrid search
- **Platform Builds** (10-12 hours): Windows + macOS signed installers
- **Performance & Testing** (10-15 hours): Optimization + security validation

**Total Remaining**: 83-110 hours (2-3 weeks at 40hr/week)

**Target Release**: v1.0.0 with production-grade security (E2EE, no key transmission)

---

## Overview

This document outlines the implementation plan for Scribe Desktop, organized into phased epics with detailed tasks, subtasks, and checkboxes for tracking progress. Each phase follows Test-Driven Development (TDD) principles per `TESTING_PATTERNS.md` and integrates OWASP security testing per `OWASP-TOP-10.md`.

**Target Platforms**: Windows (x64), macOS (Intel + Apple Silicon)
**Binary Size Goal**: <200MB
**Security Model**: Client-side E2EE, zero knowledge architecture

## Compressed Timeline (For Reference)

Based on demonstrated velocity with AI-assisted development:

### Week 1: Foundation + Vector Store (20-25 hours)
- **Days 1-2**: Database abstraction (8 hours)
  - Feature flags, SQLite types, convert **67 migrations for full frontend functionality**
  - Includes: core (30) + frontend features (26) + usage analytics (5) + recent features (6)
  - AuthBackend multi-backend, encryption tests
- **Days 3-4**: LanceDB integration (8 hours)
  - VectorStoreService trait implementation
  - Hybrid search testing
- **Day 5**: Tauri setup (4-5 hours)
  - Initialize project, server commands, mode selection UI

### Week 2: Security + Platform Builds (20-25 hours)
- **Days 6-7**: OWASP security tests (8 hours)
- **Days 8-9**: Windows build + code signing (6 hours)
- **Day 10**: macOS build + notarization (6 hours)

### Week 3: Polish + Release (10-15 hours)
- **Days 11-12**: Performance optimization (6 hours)
- **Days 13-14**: Documentation + release (4-5 hours)
- **Day 15**: Buffer for unexpected issues (optional 4 hours)

**Phase 7 (Payment Integration)**: SKIPPED for MVP. All features work locally without cloud validation. Add in v1.1+.

**Key Optimizations vs Original Plan**:
- Migration scope: 176 → 67 (100% frontend functionality without cloud-only features)
  - Core schema (30) + Frontend features (26) + Usage analytics (5) + Recent features (6) = 67
  - Skipped: 21 payment/billing migrations (cloud-only hosted platform features)
- Payment phase skipped entirely (desktop uses Qdrant cloud, no local payment processing)
- Parallelized platform builds where possible
- Leveraged AI assistance for boilerplate and migration conversion

---

## Detailed Plan (Original Structure)

The following detailed breakdown maintains the original structure for completeness, but actual execution will follow the compressed timeline above.

## Phase 1: Foundation & Database Abstraction (Weeks 1-3)

### Epic 1.1: Project Setup & Feature Flags

**Goal**: Set up Tauri project structure and Cargo feature flags for backend selection

**Definition of Done**: `cargo check --all-features` passes, Tauri dev server runs

#### Tasks:

- [x] **Task 1.1.1**: Initialize Tauri 2.0 Project
  - [x] Subtask: Run `cargo install tauri-cli` (version 2.0+)
  - [x] Subtask: Run `cargo tauri init` in project root
  - [x] Subtask: Configure `tauri.conf.json` for multi-platform builds
  - [x] Subtask: Set app identifier: `com.sanguine.scribe`
  - [x] Subtask: Configure window settings (min size: 1024x768, resizable: true)
  - [x] **Test**: `cargo tauri dev` successfully launches empty app
  - [x] **DoD**: Tauri dev server runs without errors

- [x] **Task 1.1.2**: Configure Cargo Feature Flags
  - [x] Subtask: Update `backend/Cargo.toml` with feature definitions:
    ```toml
    [features]
    default = ["cloud"]  # Changed to cloud for backward compatibility
    desktop = ["sqlite-backend", "embedded-vector"]
    cloud = ["postgres-backend", "remote-vector"]
    sqlite-backend = ["diesel/sqlite"]
    postgres-backend = ["diesel/postgres"]
    embedded-vector = []  # lancedb to be added in 1.1.3
    remote-vector = []  # qdrant-client already direct dependency
    ```
  - [x] Subtask: Add conditional compilation attributes to `main.rs`
  - [x] Subtask: Create `backend/src/features.rs` with feature detection functions
  - [x] **Test**: `cargo check --features desktop` passes
  - [x] **Test**: `cargo check --features cloud` passes
  - [x] **Test**: `cargo check --no-default-features --features sqlite-backend` passes
  - [x] **DoD**: All feature combinations compile without errors

- [x] **Task 1.1.3**: Add Dependencies
  - [x] Subtask: Add to `backend/Cargo.toml`:
    ```toml
    [dependencies]
    # diesel already included with both postgres and sqlite features
    lancedb = { version = "0.22.2", optional = true }
    # tauri handled in desktop workspace member
    ```
  - [x] Subtask: Add platform-specific dependencies:
    ```toml
    [target.'cfg(windows)'.dependencies]
    winapi = "0.3"

    [target.'cfg(target_os = "macos")'.dependencies]
    cocoa = "0.25"
    ```
  - [x] **Test**: `cargo build --features desktop` succeeds
  - [x] **DoD**: All dependencies resolve without conflicts

### Epic 1.2: Database Abstraction Layer

**Goal**: Create abstraction layer supporting both PostgreSQL and SQLite

**Definition of Done**: Test suite passes with both backends, migrations run successfully

#### Tasks:

- [x] **Task 1.2.1**: Create Database Backend Trait
  - [x] Subtask: Created `backend/src/db/pool_helpers.rs` with unified async interface
  - [x] Subtask: Implemented feature-gated `get_conn()` and `with_conn()` helpers for both backends
  - [x] Subtask: PostgreSQL backend uses `deadpool-diesel` with native async (.interact())
  - [x] Subtask: SQLite backend uses `diesel::r2d2` wrapped in `tokio::task::spawn_blocking`
  - [x] Subtask: Created type aliases in `backend/src/db/mod.rs`:
    ```rust
    #[cfg(feature = "postgres-backend")]
    pub type DbConnection = diesel::pg::PgConnection;
    #[cfg(feature = "sqlite-backend")]
    pub type DbConnection = diesel::sqlite::SqliteConnection;

    #[cfg(feature = "postgres-backend")]
    pub type DbPool = deadpool_diesel::postgres::Pool;
    #[cfg(feature = "sqlite-backend")]
    pub type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<DbConnection>>;
    ```
  - [x] Subtask: Feature-gated schema enum types (PostgreSQL native enums vs SQLite TEXT)
  - [x] Subtask: Implemented manual `FromSql`/`ToSql` for `UserRole` and `AccountStatus` enums on SQLite
  - [x] Subtask: Made `deadpool-diesel` optional dependency
  - [x] Subtask: Feature-gated all `deadpool_diesel` imports throughout codebase
  - [x] Subtask: Replaced all `pool.get().await.interact()` patterns with unified `with_conn()`
  - [x] Subtask: Updated error handling for both backends
  - [x] **Test**: `cargo check --features cloud` passes (0 errors) ✓
  - [x] **Test**: SQLite backend partial (enum implementation complete, migration work pending)
  - [x] **DoD**: PostgreSQL backend compiles successfully with all features working

- [x] **Task 1.2.2**: Create Custom SQLite Type Mappings
  - [x] Subtask: Created `backend/src/db/sqlite_types.rs` with comprehensive type mappings
  - [x] Subtask: Implemented `FromSql<Text, Sqlite>` for `Uuid` (TEXT storage)
  - [x] Subtask: Implemented `ToSql<Text, Sqlite>` for `Uuid` (TEXT storage)
  - [x] Subtask: Created `JsonValue` wrapper for JSONB → TEXT conversion
  - [x] Subtask: Implemented `FromSql`/`ToSql` for `JsonValue` with serde_json serialization
  - [x] Subtask: Created `TextArray` wrapper for ARRAY<TEXT> → TEXT conversion (JSON array format)
  - [x] **Test**: `test_uuid_roundtrip_sqlite()` - Verifies UUID insert/retrieve
  - [x] **Test**: `test_jsonb_roundtrip_sqlite()` - Verifies JSON insert/retrieve
  - [x] **Test**: `test_array_roundtrip_sqlite()` - Verifies string array insert/retrieve
  - [x] **DoD**: All custom types have FromSql/ToSql implementations with embedded tests ✓
  - [x] **Note**: PostgreSQL backend still compiles successfully (verified)

- [x] **Task 1.2.3**: Automated Migration Conversion Script
  - [x] Subtask: Created `scripts/convert_migrations.py` (425 lines)
  - [x] Subtask: Implemented `MigrationConverter` class with comprehensive type mappings
    - UUID → TEXT, BYTEA → BLOB, JSONB → TEXT
    - TEXT[] → TEXT, VARCHAR(n) → TEXT
    - TIMESTAMPTZ → DATETIME, SERIAL → INTEGER
    - Custom enums (user_role, account_status, message_type) → TEXT
  - [x] Subtask: Implemented `_convert_create_tables()` with SERIAL/DEFAULT handling
  - [x] Subtask: Implemented `_convert_indexes()` with GIN index warnings
  - [x] Subtask: Implemented `_convert_alter_tables()` method
  - [x] Subtask: Added comprehensive logging with color-coded terminal output
  - [x] Subtask: Implemented extension/function/enum type removal
  - [x] Subtask: Implemented trigger conversion (diesel_manage_updated_at → SQLite triggers)
  - [x] **Test**: Successfully converted sample migration `2025-04-18-103148_create_sessions_table` ✓
  - [x] **Test**: Output verified - TIMESTAMPTZ→DATETIME, function removed, indexes preserved ✓
  - [x] **DoD**: Script runs without errors, generates valid SQLite SQL, produces detailed log ✓
  - [x] **Features**: CLI with `--all`, `--core`, `--migration` options
  - [x] **Features**: Identifies 30 core MVP migrations automatically

- [x] **Task 1.2.4**: Convert PostgreSQL Migrations to SQLite (Full Frontend Functionality)
  - [x] Subtask: Updated CORE_MIGRATIONS list from 30 → 67 migrations for 100% frontend functionality
  - [x] Subtask: Migration breakdown:
    - Original core MVP (30): Users, sessions, encryption, roles, personas, lorebooks, character overrides, chronicles
    - Essential frontend features (26): History management, model settings, Gemini options, frontend tables (documents/votes/suggestions), user settings, character avatars, SillyTavern V3 compatibility, agent context analysis, agentic mode
    - Usage analytics (5): Token tracking, usage tracking table, credits display (for showing Gemini API costs to users)
    - Recent features (6): Model provider selection, message variants, prompt templates, template preferences, narrative overrides
  - [x] Subtask: Ran `python scripts/convert_migrations.py --core` successfully (67/67 migrations)
  - [x] Subtask: Reviewed conversion warnings log - 14 expected warnings:
    - 3 ENUM types removed (message_type, user_role, account_status) → TEXT
    - 10 DEFAULT uuid_generate_v4()/gen_random_uuid() removed (UUIDs generated in application)
    - 1 GIN index converted to regular index (idx_chronicle_events_event_data_gin)
  - [x] Subtask: Created `backend/migrations_sqlite/` directory with 67 migrations (134 SQL files)
  - [x] Subtask: Verified conversion quality (UUID→TEXT, TIMESTAMPTZ→DATETIME, triggers created)
  - [x] Subtask: Fixed 7 migrations with unconverted PostgreSQL triggers:
    - Replaced `EXECUTE FUNCTION` syntax with SQLite `BEGIN...END` trigger bodies
    - Tables: user_settings, agent_context_analysis, chat_character_overrides, character_lorebooks, message_variants, chat_character_lorebook_overrides, template_preferences
  - [x] Subtask: Commented out 4 PostgreSQL `COMMENT ON` statements (not supported in SQLite)
  - [x] Subtask: Final verification - no remaining PostgreSQL-specific syntax (EXECUTE FUNCTION, WITH TIME ZONE, JSONB, UUID)
  - [ ] Subtask: Test all frontend migrations on SQLite
  - [ ] **Test**: `diesel migration run --database-url=sqlite://test.db --migration-dir=migrations_sqlite`
  - [ ] **Test**: Verify schema matches PostgreSQL for frontend tables
  - [ ] **DoD**: All 67 SQLite migrations run successfully, schema supports 100% frontend functionality
  - [x] **Note**: Skipped 21 payment/billing migrations (cloud-only) - desktop uses Qdrant cloud for vectors, no local payment processing needed

- [ ] **Task 1.2.5**: Update Models for Multi-Backend Support
  - [ ] Subtask: Add conditional compilation to `backend/src/models/*.rs`
  - [ ] Subtask: Replace `diesel::pg::data_types::PgTimestamp` with generic `chrono::NaiveDateTime`
  - [ ] Subtask: Replace `serde_json::Value` with `JsonValue` wrapper for JSONB fields
  - [ ] Subtask: Replace `Vec<String>` with `StringArray` wrapper for array fields
  - [ ] Subtask: Update `backend/src/schema.rs` with conditional types:
    ```rust
    #[cfg(feature = "sqlite-backend")]
    table! {
        users (id) {
            id -> Text,
            username -> Text,
            email -> Text,
            password_hash -> Text,
            encrypted_dek -> Blob,
            kek_salt -> Blob,
            // ...
        }
    }

    #[cfg(feature = "postgres-backend")]
    table! {
        users (id) {
            id -> Uuid,
            // ...
        }
    }
    ```
  - [ ] **Test**: Integration test `test_user_crud_sqlite()` - Create, read, update, delete user in SQLite
  - [ ] **Test**: Integration test `test_user_crud_postgres()` - Same operations in PostgreSQL
  - [ ] **Test**: Verify encrypted fields (BLOB) work correctly in SQLite
  - [ ] **DoD**: All models work with both backends, tests pass

### Epic 1.3: Encryption System Preservation

**Goal**: Ensure KEK/DEK encryption works identically in SQLite and PostgreSQL

**Definition of Done**: OWASP A02 (Cryptographic Failures) tests pass for both backends

#### Tasks:

- [ ] **Task 1.3.1**: Update AuthBackend for Multi-Backend
  - [ ] Subtask: Add conditional compilation to `backend/src/auth/mod.rs`
  - [ ] Subtask: Implement `AuthBackend<SqliteConnection>` with DEK cache
  - [ ] Subtask: Ensure `authenticate()` method works with SQLite types (TEXT UUID, BLOB)
  - [ ] Subtask: Verify DEK cache is in-memory only (never serialized)
  - [ ] **Test**: `test_sqlite_auth_login_success()` - Login with correct password
  - [ ] **Test**: `test_sqlite_auth_login_failure()` - Login with wrong password
  - [ ] **Test**: `test_sqlite_dek_cached_in_memory()` - Verify DEK in cache after login
  - [ ] **DoD**: Authentication works identically on SQLite and PostgreSQL

- [ ] **Task 1.3.2**: OWASP A02 Security Tests (Cryptographic Failures)
  - [ ] Subtask: Create `backend/tests/security/owasp_a02_cryptographic_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_dek_never_persisted_to_sqlite() {
        // Search SQLite file bytes for plaintext DEK
        // Assert NOT found
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_argon2id_parameters_meet_owasp_standards() {
        // Verify m=19456, t=2, p=1
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_encrypted_data_uses_unique_nonces() {
        // Verify 1000 encryptions use 1000 unique nonces
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_recovery_phrase_encryption_secure() {
        // Verify recovery phrase creates separate encrypted DEK
    }
    ```
  - [ ] **DoD**: All OWASP A02 tests pass for SQLite backend

- [ ] **Task 1.3.3**: Test Encryption Roundtrip
  - [ ] Subtask: Create integration test `test_chat_message_encryption_roundtrip_sqlite()`
  - [ ] Subtask: Steps:
    1. Create user with DEK
    2. Login to cache DEK
    3. Create chat session
    4. Send message (plaintext)
    5. Verify message stored encrypted (BLOB) in SQLite
    6. Retrieve message, verify decrypts to original plaintext
  - [ ] **Test**: Run test with `RUST_LOG=debug` to verify encryption logs
  - [ ] **Test**: Verify no plaintext in SQLite file using `hexdump | grep "test message"`
  - [ ] **DoD**: Encryption roundtrip works end-to-end in SQLite

## Phase 1.5: Secure Quick Start Architecture (NEW - Critical Security Uplift)

### Epic 1.5.1: Client-Side Key Generation & Storage ✅ COMPLETE

**Goal**: Replace insecure DEK transmission with client-side P-256 key generation

**Definition of Done**: Client generates and stores keys locally, no transmission to server

**Timeline**: 4-6 hours (Actual: ~4 hours)

**Completion Date**: 2025-01-04

#### Tasks:

- [x] **Task 1.5.1.1**: Add Tauri Key Generation Commands
  - [x] Subtask: Add `p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }` to `desktop/Cargo.toml`
  - [x] Subtask: Add `base64 = "0.21"` and `hex = "0.4"` for encoding
  - [x] Subtask: Create `#[tauri::command] generate_quick_start_keys()` - desktop/src/lib.rs:282
    - Generates P-256 ECDSA signing key using OsRng
    - Generates 32-byte DEK for ChaCha20Poly1305
    - Stores private key (PKCS#8 PEM) + DEK (base64) in Tauri secure storage
    - Returns PEM-encoded public key for backend registration
  - [x] Subtask: Create `#[tauri::command] sign_challenge(challenge: String)` - desktop/src/lib.rs:326
    - Loads private key from storage
    - Signs challenge with ECDSA
    - Returns hex-encoded signature
  - [x] Subtask: Create `#[tauri::command] get_local_dek()` - desktop/src/lib.rs:356
    - Returns DEK for client-side encryption (never transmitted)
  - [x] Subtask: Update `clear_tokens()` to clear JWT tokens + keypair + DEK - desktop/src/lib.rs:267
  - [x] **Test**: Unit tests for P-256 cryptography - desktop/src/lib.rs:681-879
    - `test_p256_keypair_generation()` - Validates PKCS#8 PEM key generation
    - `test_dek_generation()` - Validates 32-byte DEK and base64 encoding
    - `test_challenge_signing_and_verification()` - Full signing/verification flow
    - `test_signature_verification_fails_with_wrong_challenge()` - Security test
    - `test_signature_verification_fails_with_wrong_public_key()` - Security test
    - `test_private_key_roundtrip()` - PEM serialization/deserialization
    - `test_key_generation_entropy()` - Validates cryptographic randomness
    - **Result**: ✅ 7/7 tests passed in 0.01s
  - [x] **Test**: OWASP Security Tests - desktop/src/lib.rs:880-1196
    - **OWASP A02: Cryptographic Failures** (6 tests)
      - `test_owasp_a02_dek_length_validation()` - Validates 32-byte DEK requirement
      - `test_owasp_a02_private_key_never_exposed()` - Ensures PEM format for secure storage
      - `test_owasp_a02_public_key_safe_transmission()` - Validates public key transmission safety
      - `test_owasp_a02_weak_key_detection()` - Validates proper PEM structure and size
      - `test_owasp_a02_secure_rng()` - Validates OsRng for cryptographic randomness
      - `test_owasp_a02_base64_integrity()` - Validates base64 encoding/decoding integrity
    - **OWASP A07: Authentication Failures** (4 tests)
      - `test_owasp_a07_signature_replay_prevention()` - Prevents signature replay attacks
      - `test_owasp_a07_challenge_uniqueness()` - Ensures different challenges produce different signatures
      - `test_owasp_a07_key_confusion_prevention()` - Prevents key confusion attacks
      - `test_owasp_a07_empty_challenge_rejection()` - Validates empty challenge rejection
    - **OWASP A08: Data Integrity Failures** (2 tests)
      - `test_owasp_a08_signature_tampering_detection()` - Detects tampered signatures
      - `test_owasp_a08_challenge_tampering_detection()` - Detects tampered challenges
    - **Result**: ✅ 19/19 tests passed in 0.01s (7 cryptography + 12 OWASP security)
  - [x] **DoD**: ✅ Key generation commands implemented, tested, and compiling

### Epic 1.5.2: Backend Challenge-Response Authentication

**Goal**: Implement challenge-response auth using stored public keys

**Definition of Done**: Desktop users can authenticate via ECDSA signature verification

**Timeline**: 8-10 hours

#### Tasks:

- [ ] **Task 1.5.2.1**: Database Migration for Public Keys
  - [ ] Subtask: Create migration `add_public_key_to_users`:
    ```sql
    ALTER TABLE users ADD COLUMN public_key VARCHAR(128) NULLABLE;
    CREATE INDEX idx_users_public_key ON users(public_key) WHERE public_key IS NOT NULL;
    ```
  - [ ] Subtask: Apply to both PostgreSQL and SQLite migrations
  - [ ] **Test**: `diesel migration run` successful on both backends
  - [ ] **DoD**: `users.public_key` column exists

- [ ] **Task 1.5.2.2**: Update User Models
  - [ ] Subtask: Add `public_key: Option<String>` to User struct
  - [ ] Subtask: Update UserDbQuery with public_key field
  - [ ] Subtask: Update schema files (postgres + sqlite)
  - [ ] **DoD**: Models compile with new field

- [ ] **Task 1.5.2.3**: Create Challenge Service
  - [ ] Subtask: Create `backend/src/auth/challenge_service.rs`
  - [ ] Subtask: Implement in-memory challenge store (HashMap with 5min TTL)
  - [ ] Subtask: Create `generate_challenge(user_id)` → random 32-byte nonce
  - [ ] Subtask: Create `verify_signature(user_id, nonce, signature)` → verify P-256 ECDSA
  - [ ] Subtask: Implement nonce cleanup (expired challenges)
  - [ ] **Test**: Unit test `test_challenge_generation()`
  - [ ] **Test**: Unit test `test_signature_verification_valid()`
  - [ ] **Test**: Unit test `test_signature_verification_invalid()`
  - [ ] **DoD**: Challenge service works with valid/invalid signatures

- [ ] **Task 1.5.2.4**: Create Challenge Endpoints
  - [ ] Subtask: Create `POST /api/auth/desktop/challenge`:
    - Accept username or user_id
    - Generate challenge nonce
    - Return nonce to client
  - [ ] Subtask: Create `POST /api/auth/desktop/verify`:
    - Accept nonce + signature
    - Verify signature with stored public key
    - Issue JWT tokens on success
    - Return access_token + refresh_token
  - [ ] Subtask: Add endpoints to Axum router
  - [ ] **Test**: Integration test `test_challenge_response_flow()`
  - [ ] **DoD**: Challenge-response authentication works end-to-end

- [ ] **Task 1.5.2.5**: Update Desktop Setup Handler
  - [ ] Subtask: Modify `DesktopSetupPayload`:
    ```rust
    pub struct DesktopSetupPayload {
        pub auth_mode: String,
        pub public_key: Option<String>, // Base64 P-256 public key
    }
    ```
  - [ ] Subtask: Update `desktop_setup_handler`:
    - Accept public_key in request
    - Store public_key in users table
    - Remove DEK generation logic
    - Remove dek field from response
  - [ ] Subtask: Keep JWT token generation (already working)
  - [ ] **Test**: Integration test `test_setup_stores_public_key()`
  - [ ] **DoD**: Setup handler stores public key, doesn't generate DEK

### Epic 1.5.3: Frontend Auth Service Redesign

**Goal**: Update frontend to use client-side keys and challenge-response auth

**Definition of Done**: Desktop Quick Start uses new secure flow, no DEK transmission

**Timeline**: 6-8 hours

#### Tasks:

- [ ] **Task 1.5.3.1**: Update TypeScript Types
  - [ ] Subtask: Remove `dek?: string` from `TokenLoginResponse` interface
  - [ ] Subtask: Update API client types
  - [ ] **DoD**: Types reflect new architecture (no DEK in responses)

- [ ] **Task 1.5.3.2**: Implement Quick Start Setup Flow
  - [ ] Subtask: Create `setupQuickStart()` method in DesktopAuthService:
    1. Call Tauri `generate_quick_start_keys()` → get public_key
    2. POST `/api/auth/desktop/setup` with `{ auth_mode: "quick_start", public_key }`
    3. Store returned JWT tokens
    4. Store "keys_generated" flag for future auto-login
  - [ ] Subtask: Remove DEK storage logic (save_dek, load_dek calls)
  - [ ] **Test**: Unit test `test_quick_start_setup()`
  - [ ] **DoD**: Quick Start generates keys client-side, sends public key only

- [ ] **Task 1.5.3.3**: Implement Challenge-Response Auto-Login
  - [ ] Subtask: Create `challengeResponseLogin()` method:
    1. Check if keys exist in storage
    2. POST `/api/auth/desktop/challenge` → get nonce
    3. Call Tauri `sign_challenge(nonce)` → get signature
    4. POST `/api/auth/desktop/verify` with `{ nonce, signature }` → get tokens
    5. Store new JWT tokens
  - [ ] Subtask: Update `initialize()` to use challenge-response if keys exist
  - [ ] **Test**: Integration test `test_auto_login_with_challenge()`
  - [ ] **DoD**: Auto-login works via challenge-response (no password)

- [ ] **Task 1.5.3.4**: Remove DEK Transmission Logic
  - [ ] Subtask: Remove `dek` field from class
  - [ ] Subtask: Remove X-Scribe-Dek header from `getAuthHeaders()`
  - [ ] Subtask: Remove DEK loading in `initialize()`
  - [ ] Subtask: Remove DEK saving in `login()`
  - [ ] Subtask: Remove DEK clearing in `logout()` and `refreshAccessToken()`
  - [ ] **DoD**: No DEK transmission code remains

### Epic 1.5.4: Client-Side Encryption Layer

**Goal**: Implement full E2EE for sensitive data before API calls

**Definition of Done**: All sensitive data encrypted client-side with local DEK

**Timeline**: 12-16 hours

#### Tasks:

- [ ] **Task 1.5.4.1**: Create Encryption Service
  - [ ] Subtask: Add `@noble/ciphers` to `frontend/package.json`
  - [ ] Subtask: Create `frontend/src/lib/crypto/encryption.ts`
  - [ ] Subtask: Implement `encrypt(plaintext: string)`:
    - Get DEK from Tauri `get_local_dek()`
    - Encrypt with ChaCha20Poly1305
    - Return base64-encoded ciphertext + nonce
  - [ ] Subtask: Implement `decrypt(ciphertext: string)`:
    - Get DEK from Tauri
    - Decrypt with ChaCha20Poly1305
    - Return plaintext
  - [ ] **Test**: Unit test `test_encryption_roundtrip()`
  - [ ] **DoD**: Encryption service works end-to-end

- [ ] **Task 1.5.4.2**: Update API Client for E2EE
  - [ ] Subtask: Identify sensitive fields:
    - Chat messages: `content`, `system_prompt`
    - Character cards: `description`, `chat_history`
    - User personas: `attributes`
    - Lorebook entries: `content`
  - [ ] Subtask: Add encrypt/decrypt middleware to API client
  - [ ] Subtask: Encrypt before POST/PUT, decrypt after GET
  - [ ] **Test**: Integration test `test_encrypted_chat_message_roundtrip()`
  - [ ] **DoD**: Sensitive data encrypted before transmission

- [ ] **Task 1.5.4.3**: Update Backend for Encrypted Storage
  - [ ] Subtask: Change TEXT fields to BYTEA/BLOB for encrypted data
  - [ ] Subtask: Remove SessionDek extractor (no longer needed)
  - [ ] Subtask: Backend stores encrypted blobs, returns encrypted blobs
  - [ ] **DoD**: Backend never sees plaintext, only encrypted data

### Epic 1.5.5: Fresh Start Migration

**Goal**: Handle migration from old DEK transmission system to new secure system

**Definition of Done**: Users can migrate with data export/import

**Timeline**: 3-4 hours

#### Tasks:

- [ ] **Task 1.5.5.1**: Migration Detection
  - [ ] Subtask: Check for legacy DEK in Tauri storage on app start
  - [ ] Subtask: Display migration modal if detected
  - [ ] **DoD**: Legacy system detected

- [ ] **Task 1.5.5.2**: Migration UI
  - [ ] Subtask: Create migration modal component
  - [ ] Subtask: Options: "Export Data" → "Start Fresh" → "Cancel"
  - [ ] Subtask: Implement data export (characters, chats, personas to JSON)
  - [ ] Subtask: Clear database + storage on "Start Fresh"
  - [ ] **DoD**: Migration flow works

### Epic 1.5.6: Security Testing & Validation

**Goal**: Verify no key transmission, validate E2EE implementation

**Definition of Done**: All security tests pass, Wireshark confirms no DEK in traffic

**Timeline**: 8-10 hours

#### Tasks:

- [ ] **Task 1.5.6.1**: Network Traffic Analysis
  - [ ] Subtask: Capture HTTPS traffic with Wireshark during Quick Start
  - [ ] Subtask: Verify NO base64-encoded DEK in any request/response
  - [ ] Subtask: Verify only JWT tokens in Authorization headers
  - [ ] **DoD**: Network analysis confirms zero DEK transmission

- [ ] **Task 1.5.6.2**: Backend Security Tests
  - [ ] Subtask: Create `backend/tests/challenge_auth_tests.rs`
  - [ ] Subtask: Test challenge-response flow (valid + invalid signatures)
  - [ ] Subtask: Test public key storage and retrieval
  - [ ] Subtask: Verify DEK never appears in server logs
  - [ ] **DoD**: All backend security tests pass

- [ ] **Task 1.5.6.3**: E2E Encryption Tests
  - [ ] Subtask: Test encrypted chat message roundtrip
  - [ ] Subtask: Verify server stores encrypted blobs (hexdump check)
  - [ ] Subtask: Verify client decrypts correctly
  - [ ] **DoD**: E2EE works end-to-end

---

## Phase 2: Vector Store Integration (Weeks 4-5)

### Epic 2.1: LanceDB Integration

**Goal**: Replace Qdrant with embedded LanceDB for vector storage

**Definition of Done**: Hybrid search works in desktop mode, tests pass

#### Tasks:

- [ ] **Task 2.1.1**: Add LanceDB Dependency
  - [ ] Subtask: Add to `backend/Cargo.toml`:
    ```toml
    [dependencies]
    lancedb = { version = "0.10", optional = true }
    arrow = "53.0"
    tokio = { version = "1", features = ["full"] }
    ```
  - [ ] Subtask: Create feature flag `embedded-vector = ["lancedb", "arrow"]`
  - [ ] **Test**: `cargo check --features embedded-vector`
  - [ ] **DoD**: LanceDB compiles successfully

- [ ] **Task 2.1.2**: Implement LanceDB Client
  - [ ] Subtask: Create `backend/src/vector_db/lancedb_client.rs`
  - [ ] Subtask: Implement `LanceDbClient` struct:
    ```rust
    pub struct LanceDbClient {
        connection: Connection,
        table_name: String,
    }
    ```
  - [ ] Subtask: Implement `new(data_dir: &Path)` - Initialize connection
  - [ ] Subtask: Implement `ensure_table_exists(dimension: usize)` - Create table with schema
  - [ ] Subtask: Implement `store_points(points: Vec<PointStruct>)` - Convert to Arrow batch
  - [ ] Subtask: Implement `search_points(query_vector, limit, filter)` - Vector search
  - [ ] Subtask: Implement `hybrid_search(query_vector, query_text, limit, filter)` - Vector + Tantivy
  - [ ] **Test**: Unit test `test_lancedb_create_table()`
  - [ ] **Test**: Unit test `test_lancedb_store_and_retrieve()`
  - [ ] **DoD**: LanceDB client implements basic operations

- [ ] **Task 2.1.3**: Implement VectorStoreService Trait for LanceDB
  - [ ] Subtask: Update `backend/src/vector_db/mod.rs` with trait:
    ```rust
    #[async_trait]
    pub trait VectorStoreService {
        async fn ensure_collection_exists(&self, dimension: usize) -> Result<(), VectorDbError>;
        async fn store_points(&self, points: Vec<PointStruct>) -> Result<(), VectorDbError>;
        async fn search_points(&self, query_vector: Vec<f32>, limit: usize, filter: Option<Filter>) -> Result<Vec<ScoredPoint>, VectorDbError>;
        async fn hybrid_search(&self, query_vector: Vec<f32>, query_text: &str, limit: usize, filter: Option<Filter>) -> Result<Vec<ScoredPoint>, VectorDbError>;
    }
    ```
  - [ ] Subtask: Implement trait for `LanceDbClient`
  - [ ] Subtask: Convert Qdrant `Filter` to LanceDB SQL WHERE clause
  - [ ] Subtask: Convert LanceDB results to `ScoredPoint` format
  - [ ] **Test**: Integration test `test_lancedb_trait_implementation()`
  - [ ] **DoD**: LanceDB implements VectorStoreService trait

- [ ] **Task 2.1.4**: Test Hybrid Search
  - [ ] Subtask: Create test corpus of 1000 embedding vectors
  - [ ] Subtask: Insert test data into LanceDB
  - [ ] Subtask: Run vector-only search, verify results
  - [ ] Subtask: Run text-only search using Tantivy, verify results
  - [ ] Subtask: Run hybrid search (vector + text), verify merged results
  - [ ] **Test**: `test_hybrid_search_performance()` - Measure latency <50ms
  - [ ] **Test**: `test_hybrid_search_relevance()` - Verify top-k results are correct
  - [ ] **DoD**: Hybrid search works and meets performance targets

- [ ] **Task 2.1.5**: Update Context Processor for LanceDB
  - [ ] Subtask: Update `backend/src/services/context_processor.rs` to use `VectorStoreService` trait
  - [ ] Subtask: Replace `QdrantService` with conditional compilation:
    ```rust
    #[cfg(feature = "embedded-vector")]
    type VectorStore = LanceDbClient;

    #[cfg(feature = "remote-vector")]
    type VectorStore = QdrantClient;
    ```
  - [ ] Subtask: Update `process_chat_history()` to work with trait
  - [ ] **Test**: Integration test `test_context_processor_with_lancedb()`
  - [ ] **DoD**: Context processor works with both vector stores

## Phase 3: Tauri Integration & Mode Selection (Weeks 6-7)

### Epic 3.1: Tauri Backend Commands

**Goal**: Create Tauri commands for IPC between frontend and embedded backend

**Definition of Done**: Frontend can start/stop embedded server via Tauri commands

#### Tasks:

- [ ] **Task 3.1.1**: Create Tauri Command Module
  - [ ] Subtask: Create `backend/src/tauri_commands.rs`
  - [ ] Subtask: Define server modes:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ServerMode {
        Standalone,
        Client,
    }
    ```
  - [ ] Subtask: Define command responses:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ServerInfo {
        pub url: String,
        pub port: u16,
        pub mode: ServerMode,
    }
    ```
  - [ ] **DoD**: Types compile and serialize correctly

- [ ] **Task 3.1.2**: Implement Start Server Command
  - [ ] Subtask: Create `#[tauri::command]`:
    ```rust
    #[tauri::command]
    async fn start_embedded_server(
        app_handle: tauri::AppHandle,
        mode: ServerMode,
        config_path: String,
    ) -> Result<ServerInfo, String> {
        // Initialize database
        // Initialize vector store
        // Start Axum server on localhost
        // Return server info
    }
    ```
  - [ ] Subtask: Implement SQLite initialization in `~/.local/share/scribe/` (Linux) or `%APPDATA%/scribe/` (Windows)
  - [ ] Subtask: Implement LanceDB initialization in data directory
  - [ ] Subtask: Start Axum server on random available port or configured port
  - [ ] Subtask: Store server handle in Tauri state for shutdown
  - [ ] **Test**: Unit test `test_start_server_standalone_mode()`
  - [ ] **Test**: Verify SQLite database created in correct location
  - [ ] **DoD**: Server starts successfully and returns info

- [ ] **Task 3.1.3**: Implement Stop Server Command
  - [ ] Subtask: Create `#[tauri::command]`:
    ```rust
    #[tauri::command]
    async fn stop_embedded_server(
        app_handle: tauri::AppHandle,
    ) -> Result<(), String> {
        // Retrieve server handle from state
        // Gracefully shutdown Axum server
        // Clear DEK cache
        // Close database connections
    }
    ```
  - [ ] Subtask: Implement graceful shutdown with timeout (10 seconds)
  - [ ] Subtask: Ensure DEK cache is cleared from memory
  - [ ] **Test**: Unit test `test_stop_server_clears_dek_cache()`
  - [ ] **DoD**: Server stops gracefully, no DEKs remain in memory

- [ ] **Task 3.1.4**: Implement Configuration Commands
  - [ ] Subtask: Create `#[tauri::command] async fn get_config()` - Read config.json
  - [ ] Subtask: Create `#[tauri::command] async fn save_config()` - Write config.json
  - [ ] Subtask: Create `#[tauri::command] async fn get_data_dir()` - Return platform-specific data directory
  - [ ] Subtask: Implement config file encryption (optional, store API keys)
  - [ ] **Test**: Integration test `test_config_roundtrip()`
  - [ ] **DoD**: Config persistence works on all platforms

### Epic 3.2: Frontend Mode Selection UI

**Goal**: Create first-run setup UI for mode selection (Standalone vs Client)

**Definition of Done**: User can select mode, configure, and connect

#### Tasks:

- [ ] **Task 3.2.1**: Create Setup Page Component
  - [ ] Subtask: Create `frontend/src/routes/setup/+page.svelte`
  - [ ] Subtask: Create mode selection cards (Standalone, Client)
  - [ ] Subtask: Add descriptions and feature lists for each mode
  - [ ] Subtask: Implement mode selection state (Svelte rune)
  - [ ] **Test**: Component test `test_mode_selection_renders()`
  - [ ] **DoD**: Mode selection UI renders correctly

- [ ] **Task 3.2.2**: Standalone Mode Configuration Form
  - [ ] Subtask: Create form for data directory selection
  - [ ] Subtask: Implement directory picker using Tauri dialog API
  - [ ] Subtask: Add port configuration (default: 8080)
  - [ ] Subtask: Add "Start Server" button
  - [ ] Subtask: Call `start_embedded_server()` Tauri command on submit
  - [ ] Subtask: Display loading state during server startup
  - [ ] Subtask: Handle errors (port in use, permission denied, etc.)
  - [ ] **Test**: E2E test with Playwright - Select standalone mode, start server
  - [ ] **DoD**: Standalone mode configuration works end-to-end

- [ ] **Task 3.2.3**: Client Mode Configuration Form
  - [ ] Subtask: Create form for server URL input
  - [ ] Subtask: Add URL validation (https:// required)
  - [ ] Subtask: Add "Test Connection" button
  - [ ] Subtask: Implement connection test (fetch `/api/health`)
  - [ ] Subtask: Display success/failure status
  - [ ] Subtask: Save configuration on success
  - [ ] **Test**: Unit test `test_url_validation()`
  - [ ] **Test**: Integration test `test_connection_test_valid_url()`
  - [ ] **DoD**: Client mode configuration validates and connects

- [ ] **Task 3.2.4**: First-Run Detection Logic
  - [ ] Subtask: Create `frontend/src/lib/utils/first-run.ts`
  - [ ] Subtask: Check for config file existence using Tauri `fs` API
  - [ ] Subtask: Redirect to `/setup` if no config found
  - [ ] Subtask: Redirect to `/` if config exists
  - [ ] Subtask: Add loading spinner during detection
  - [ ] **Test**: Unit test `test_first_run_detection()`
  - [ ] **DoD**: First-run flow works correctly

## Phase 4: OWASP Security Testing (Week 8)

### Epic 4.1: Implement OWASP Top 10 Security Tests

**Goal**: Create comprehensive security test suite covering all OWASP Top 10 risks

**Definition of Done**: All OWASP security tests pass

#### Tasks:

- [ ] **Task 4.1.1**: A01 - Broken Access Control Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a01_access_control_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_file_permissions_restrictive() {
        // Verify data directory has chmod 700 (owner only)
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_session_timeout_enforced() {
        // Verify session expires after 15 min idle
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_user_cannot_access_other_user_data() {
        // Create two users, verify user A cannot read user B's chats
    }
    ```
  - [ ] **DoD**: All A01 tests pass

- [ ] **Task 4.1.2**: A02 - Cryptographic Failures Tests (Already done in Epic 1.3)
  - [ ] Subtask: Review existing tests in `owasp_a02_cryptographic_tests.rs`
  - [ ] Subtask: Add additional test:
    ```rust
    #[test]
    fn test_secure_memory_wiping_on_shutdown() {
        // Verify DEK is zeroed from memory on app shutdown
    }
    ```
  - [ ] **DoD**: All A02 tests pass

- [ ] **Task 4.1.3**: A03 - Injection Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a03_injection_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_sql_injection_prevention() {
        // Try username: "admin' OR '1'='1"
        // Verify Diesel prevents injection
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_no_raw_sql_queries() {
        // Grep codebase for ".execute(" or "sql_query("
        // Assert only parameterized queries used
    }
    ```
  - [ ] **DoD**: All A03 tests pass

- [ ] **Task 4.1.4**: A05 - Security Misconfiguration Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a05_misconfiguration_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_default_config_secure() {
        // Verify default bind is 127.0.0.1, not 0.0.0.0
        // Verify no default admin credentials
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_error_messages_no_sensitive_info() {
        // Verify error responses don't leak stack traces
    }
    ```
  - [ ] **DoD**: All A05 tests pass

- [ ] **Task 4.1.5**: A06 - Vulnerable Components Tests
  - [ ] Subtask: Add CI job in `.github/workflows/security.yml`:
    ```yaml
    - name: Cargo Audit
      run: cargo audit --deny warnings
    ```
  - [ ] Subtask: Create Dependabot config `.github/dependabot.yml`:
    ```yaml
    version: 2
    updates:
      - package-ecosystem: cargo
        directory: /backend
        schedule:
          interval: weekly
    ```
  - [ ] **Test**: Run `cargo audit` locally, verify no vulnerabilities
  - [ ] **DoD**: CI fails on vulnerable dependencies

- [ ] **Task 4.1.6**: A07 - Authentication Failures Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a07_authentication_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_password_strength_requirements() {
        // Verify password < 8 chars is rejected
        // Verify common passwords are rejected
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_rate_limiting_login_attempts() {
        // Try 10 failed logins
        // Verify 11th attempt is rate-limited
    }
    ```
  - [ ] **DoD**: All A07 tests pass

- [ ] **Task 4.1.7**: A08 - Software Integrity Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a08_integrity_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_database_integrity_check_on_startup() {
        // Verify SQLite PRAGMA integrity_check runs
    }
    ```
  - [ ] Subtask: Add code signing verification (manual test):
    - Windows: `signtool verify /pa scribe.exe`
    - macOS: `codesign --verify --deep --strict Scribe.app`
  - [ ] **DoD**: Database integrity checks work

- [ ] **Task 4.1.8**: A09 - Logging & Monitoring Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a09_logging_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_audit_log_completeness() {
        // Verify all sensitive operations are logged:
        // - Login attempts (success & failure)
        // - DEK encryption/decryption
        // - User creation/deletion
        // - Password changes
    }
    ```
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_no_sensitive_data_in_logs() {
        // Verify passwords, DEKs, plaintext messages NOT logged
    }
    ```
  - [ ] **DoD**: All A09 tests pass

- [ ] **Task 4.1.9**: A10 - SSRF Tests
  - [ ] Subtask: Create `backend/tests/security/owasp_a10_ssrf_tests.rs`
  - [ ] Subtask: Implement test:
    ```rust
    #[test]
    fn test_ssrf_prevention() {
        // Verify cloud API URLs are whitelisted
        // Try setting malicious URL, verify rejected
    }
    ```
  - [ ] **DoD**: All A10 tests pass

## Phase 5: Platform-Specific Builds (Weeks 9-10)

### Epic 5.1: Windows Build

**Goal**: Create signed, installable Windows executable

**Definition of Done**: Windows installer runs on clean Windows 10/11 VM

#### Tasks:

- [ ] **Task 5.1.1**: Configure Windows Build
  - [ ] Subtask: Update `tauri.conf.json`:
    ```json
    {
      "bundle": {
        "identifier": "com.sanguine.scribe",
        "targets": ["nsis"],
        "windows": {
          "wix": false,
          "nsis": {
            "installerIcon": "icons/icon.ico",
            "installMode": "perUser",
            "languages": ["en-US"],
            "template": "installer.nsi"
          }
        }
      }
    }
    ```
  - [ ] Subtask: Create NSIS installer template `installer.nsi`
  - [ ] Subtask: Configure WebView2 runtime installation
  - [ ] **Test**: Build on Windows: `cargo tauri build --target x86_64-pc-windows-msvc`
  - [ ] **DoD**: Windows .exe builds successfully

- [ ] **Task 5.1.2**: Code Signing (Windows)
  - [ ] Subtask: Obtain DigiCert code signing certificate
  - [ ] Subtask: Install certificate in Windows certificate store
  - [ ] Subtask: Sign executable:
    ```powershell
    signtool sign /sha1 <thumbprint> /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 scribe.exe
    ```
  - [ ] Subtask: Verify signature:
    ```powershell
    signtool verify /pa scribe.exe
    ```
  - [ ] **Test**: Right-click .exe → Properties → Digital Signatures tab shows valid signature
  - [ ] **DoD**: Executable is signed and verifiable

- [ ] **Task 5.1.3**: Test Windows Installer
  - [ ] Subtask: Create clean Windows 10 VM
  - [ ] Subtask: Install from `scribe-desktop-1.0.0-x64-setup.exe`
  - [ ] Subtask: Verify installation to `%PROGRAMFILES%/Scribe`
  - [ ] Subtask: Verify data directory creation in `%APPDATA%/Scribe`
  - [ ] Subtask: Launch app, complete first-run setup
  - [ ] Subtask: Test standalone mode (create user, send chat message)
  - [ ] **Test**: Uninstall and verify clean removal
  - [ ] **DoD**: Installer works end-to-end on Windows

### Epic 5.2: macOS Build

**Goal**: Create notarized, signed macOS .app bundle for Intel and Apple Silicon

**Definition of Done**: Universal .dmg installs and runs on macOS 11+ (Intel and M1/M2)

#### Tasks:

- [ ] **Task 5.2.1**: Configure macOS Build
  - [ ] Subtask: Update `tauri.conf.json`:
    ```json
    {
      "bundle": {
        "macOS": {
          "frameworks": [],
          "minimumSystemVersion": "11.0",
          "exceptionDomain": "",
          "signingIdentity": "Developer ID Application: Sanguine Software (TEAMID)",
          "entitlements": "entitlements.plist"
        }
      }
    }
    ```
  - [ ] Subtask: Create `entitlements.plist`:
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>com.apple.security.app-sandbox</key>
        <true/>
        <key>com.apple.security.files.user-selected.read-write</key>
        <true/>
        <key>com.apple.security.network.client</key>
        <true/>
    </dict>
    </plist>
    ```
  - [ ] Subtask: Build Intel binary: `cargo tauri build --target x86_64-apple-darwin`
  - [ ] Subtask: Build Apple Silicon binary: `cargo tauri build --target aarch64-apple-darwin`
  - [ ] **DoD**: Both binaries build successfully

- [ ] **Task 5.2.2**: Create Universal Binary
  - [ ] Subtask: Use `lipo` to combine binaries:
    ```bash
    lipo -create \
      target/x86_64-apple-darwin/release/scribe \
      target/aarch64-apple-darwin/release/scribe \
      -output target/universal/scribe
    ```
  - [ ] Subtask: Verify universal binary:
    ```bash
    lipo -info target/universal/scribe
    # Should show: x86_64 arm64
    ```
  - [ ] **Test**: Run on Intel Mac and M1 Mac
  - [ ] **DoD**: Universal binary works on both architectures

- [ ] **Task 5.2.3**: Code Signing and Notarization
  - [ ] Subtask: Obtain Apple Developer ID certificate
  - [ ] Subtask: Sign .app bundle:
    ```bash
    codesign --deep --force --verify --verbose \
      --sign "Developer ID Application: Sanguine Software" \
      --options runtime \
      --entitlements entitlements.plist \
      Scribe.app
    ```
  - [ ] Subtask: Create DMG with `create-dmg`:
    ```bash
    create-dmg \
      --volname "Scribe Installer" \
      --window-pos 200 120 \
      --window-size 800 400 \
      --icon-size 100 \
      --icon "Scribe.app" 200 190 \
      --hide-extension "Scribe.app" \
      --app-drop-link 600 185 \
      "scribe-desktop-1.0.0-universal.dmg" \
      "Scribe.app"
    ```
  - [ ] Subtask: Notarize DMG:
    ```bash
    xcrun notarytool submit scribe-desktop-1.0.0-universal.dmg \
      --apple-id developer@example.com \
      --team-id TEAMID \
      --password @keychain:AC_PASSWORD \
      --wait
    ```
  - [ ] Subtask: Staple notarization ticket:
    ```bash
    xcrun stapler staple scribe-desktop-1.0.0-universal.dmg
    ```
  - [ ] **Test**: Verify notarization:
    ```bash
    spctl -a -vvv -t install Scribe.app
    ```
  - [ ] **DoD**: DMG is signed and notarized

- [ ] **Task 5.2.4**: Test macOS Installer
  - [ ] Subtask: Test on macOS 11 (Intel)
  - [ ] Subtask: Test on macOS 14 (Apple Silicon)
  - [ ] Subtask: Verify data directory: `~/Library/Application Support/Scribe`
  - [ ] Subtask: Test first-run setup and standalone mode
  - [ ] **DoD**: Installer works on both architectures

## Phase 6: Performance Optimization (Week 11)

### Epic 6.1: Database Performance Tuning

**Goal**: Optimize SQLite for desktop workloads

**Definition of Done**: All benchmark targets met

#### Tasks:

- [ ] **Task 6.1.1**: Implement SQLite Pragmas
  - [ ] Subtask: Create `backend/src/db/sqlite_config.rs`
  - [ ] Subtask: Implement configuration:
    ```rust
    pub fn configure_sqlite(conn: &SqliteConnection) -> Result<(), DbError> {
        diesel::sql_query("PRAGMA journal_mode = WAL").execute(conn)?;
        diesel::sql_query("PRAGMA synchronous = NORMAL").execute(conn)?;
        diesel::sql_query("PRAGMA cache_size = -64000").execute(conn)?; // 64MB
        diesel::sql_query("PRAGMA temp_store = MEMORY").execute(conn)?;
        diesel::sql_query("PRAGMA mmap_size = 268435456").execute(conn)?; // 256MB
        Ok(())
    }
    ```
  - [ ] Subtask: Call during database initialization
  - [ ] **Test**: Benchmark query performance before/after pragmas
  - [ ] **DoD**: Pragmas improve performance by ≥30%

- [ ] **Task 6.1.2**: Add Database Indexes
  - [ ] Subtask: Review slow queries using `EXPLAIN QUERY PLAN`
  - [ ] Subtask: Create migration `add_performance_indexes.sql`:
    ```sql
    CREATE INDEX idx_chat_messages_session_id_created_at
    ON chat_messages(session_id, created_at);

    CREATE INDEX idx_characters_user_id
    ON characters(user_id);

    CREATE INDEX idx_chat_sessions_user_id_updated_at
    ON chat_sessions(user_id, updated_at DESC);
    ```
  - [ ] Subtask: Run migration, verify query plans
  - [ ] **Test**: Benchmark chat message retrieval (target: <10ms for 100 messages)
  - [ ] **DoD**: All query benchmarks meet targets

- [ ] **Task 6.1.3**: Implement Connection Pooling
  - [ ] Subtask: Configure r2d2 pool:
    ```rust
    let pool = Pool::builder()
        .max_size(10)
        .min_idle(Some(2))
        .connection_timeout(Duration::from_secs(5))
        .build(manager)?;
    ```
  - [ ] Subtask: Test concurrent queries
  - [ ] **Test**: Benchmark concurrent requests (10 simultaneous queries)
  - [ ] **DoD**: Connection pool handles concurrency without blocking

### Epic 6.2: Vector Store Performance Tuning

**Goal**: Optimize LanceDB for low-latency hybrid search

**Definition of Done**: Hybrid search <50ms for 10k vectors

#### Tasks:

- [ ] **Task 6.2.1**: Configure LanceDB Indexes
  - [ ] Subtask: Create IVF index for vector search:
    ```rust
    table.create_index(&["vector"])
        .ivf_pq()
        .num_partitions(256)
        .num_sub_vectors(16)
        .build()
        .await?;
    ```
  - [ ] Subtask: Create FTS index for text search (Tantivy)
  - [ ] **Test**: Benchmark vector search (target: <10ms)
  - [ ] **Test**: Benchmark text search (target: <20ms)
  - [ ] **DoD**: Indexes improve search speed by ≥50%

- [ ] **Task 6.2.2**: Benchmark Hybrid Search
  - [ ] Subtask: Create test dataset:
    - 10,000 embedding vectors (768 dimensions)
    - Associated text content (character messages)
  - [ ] Subtask: Insert test data into LanceDB
  - [ ] Subtask: Run hybrid search benchmark:
    ```rust
    let start = Instant::now();
    let results = client.hybrid_search(query_vector, "query text", 10, None).await?;
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_millis(50), "Hybrid search too slow: {:?}", elapsed);
    ```
  - [ ] **Test**: Run 100 iterations, verify P95 latency <50ms
  - [ ] **DoD**: Hybrid search meets performance target

### Epic 6.3: Startup Time Optimization

**Goal**: Reduce app startup time to <2 seconds

**Definition of Done**: Cold start <2s on all platforms

#### Tasks:

- [ ] **Task 6.3.1**: Profile Startup Time
  - [ ] Subtask: Add instrumentation to measure:
    - Tauri initialization time
    - Database connection time
    - Vector store initialization time
    - UI render time
  - [ ] Subtask: Log timings:
    ```rust
    tracing::info!("Tauri init: {:?}", tauri_elapsed);
    tracing::info!("DB connect: {:?}", db_elapsed);
    tracing::info!("Vector store init: {:?}", vector_elapsed);
    tracing::info!("Total startup: {:?}", total_elapsed);
    ```
  - [ ] **Test**: Measure baseline startup time
  - [ ] **DoD**: Startup breakdown identified

- [ ] **Task 6.3.2**: Lazy Initialization
  - [ ] Subtask: Move vector store initialization to background thread
  - [ ] Subtask: Load UI immediately, show "Initializing..." for background tasks
  - [ ] Subtask: Use tokio::spawn for async initialization
  - [ ] **Test**: Measure improvement in perceived startup time
  - [ ] **DoD**: UI appears in <1s, full initialization <2s

- [ ] **Task 6.3.3**: Binary Size Optimization
  - [ ] Subtask: Enable release profile optimizations in `Cargo.toml`:
    ```toml
    [profile.release]
    opt-level = "z"
    lto = true
    codegen-units = 1
    panic = "abort"
    strip = true
    ```
  - [ ] Subtask: Strip debug symbols: `strip target/release/scribe`
  - [ ] Subtask: Compress frontend assets with gzip
  - [ ] **Test**: Measure binary size (target: <200MB)
  - [ ] **DoD**: Binary size meets target

## Phase 7: Payment Integration (Week 12)

### Epic 7.1: Cloud Validation Service

**Goal**: Implement optional cloud connection for paid features

**Definition of Done**: Payment validation works, free features unaffected

#### Tasks:

- [ ] **Task 7.1.1**: Create Payment Validator Service
  - [ ] Subtask: Create `backend/src/services/payment_validator.rs`
  - [ ] Subtask: Implement validation cache (24h TTL):
    ```rust
    struct CachedValidation {
        is_valid: bool,
        expires_at: DateTime<Utc>,
    }

    pub struct PaymentValidator {
        cloud_client: Option<reqwest::Client>,
        cache: Arc<RwLock<HashMap<String, CachedValidation>>>,
    }
    ```
  - [ ] Subtask: Implement `validate_feature(user_id, feature)` method
  - [ ] Subtask: Handle offline mode (return cached result)
  - [ ] **Test**: Unit test `test_validation_cache_hit()`
  - [ ] **Test**: Unit test `test_validation_cache_miss()`
  - [ ] **DoD**: Validation service works with cache

- [ ] **Task 7.1.2**: Define Feature Tiers
  - [ ] Subtask: Create enum:
    ```rust
    #[derive(Debug, Clone, Copy)]
    pub enum Feature {
        CloudBackup,
        CloudSync,
        PremiumModels,
        CollaborativeSharing,
    }
    ```
  - [ ] Subtask: Create feature gate macro:
    ```rust
    macro_rules! require_feature {
        ($validator:expr, $user_id:expr, $feature:expr) => {
            if !$validator.validate_feature($user_id, $feature).await? {
                return Err(AppError::FeatureNotAvailable($feature));
            }
        };
    }
    ```
  - [ ] **DoD**: Feature gates compile

- [ ] **Task 7.1.3**: Integrate Cloud API
  - [ ] Subtask: Create cloud API client:
    ```rust
    pub struct CloudApiClient {
        base_url: String,
        api_key: String,
        client: reqwest::Client,
    }
    ```
  - [ ] Subtask: Implement `GET /api/subscription/status`
  - [ ] Subtask: Handle errors (network, auth, etc.)
  - [ ] **Test**: Integration test with mock cloud server
  - [ ] **DoD**: Cloud API integration works

- [ ] **Task 7.1.4**: Test Feature Gates
  - [ ] Subtask: Test free user accessing cloud backup → Error
  - [ ] Subtask: Test premium user accessing cloud backup → Success
  - [ ] Subtask: Test offline premium user with cached validation → Success
  - [ ] Subtask: Test offline premium user with expired cache → Graceful degradation
  - [ ] **DoD**: Feature gates work correctly

## Phase 8: Documentation & Release (Weeks 13-14)

### Epic 8.1: User Documentation

**Goal**: Create comprehensive user guide

**Definition of Done**: Documentation published, users can self-serve

#### Tasks:

- [ ] **Task 8.1.1**: Write Installation Guide
  - [ ] Subtask: Create `docs/user-guide/installation.md`
  - [ ] Subtask: Document Windows installation steps
  - [ ] Subtask: Document macOS installation steps
  - [ ] Subtask: Add screenshots for each step
  - [ ] Subtask: Document troubleshooting (WebView2, Gatekeeper, etc.)
  - [ ] **DoD**: Installation guide complete

- [ ] **Task 8.1.2**: Write First-Run Setup Guide
  - [ ] Subtask: Create `docs/user-guide/first-run.md`
  - [ ] Subtask: Document mode selection (Standalone vs Client)
  - [ ] Subtask: Document account creation
  - [ ] Subtask: Document data directory setup
  - [ ] **DoD**: First-run guide complete

- [ ] **Task 8.1.3**: Write Feature Documentation
  - [ ] Subtask: Create `docs/user-guide/features.md`
  - [ ] Subtask: Document character management
  - [ ] Subtask: Document chat functionality
  - [ ] Subtask: Document lorebook/chronicle system
  - [ ] Subtask: Document import/export
  - [ ] **DoD**: Feature documentation complete

- [ ] **Task 8.1.4**: Write FAQ
  - [ ] Subtask: Create `docs/user-guide/faq.md`
  - [ ] Subtask: Answer common questions:
    - How is my data encrypted?
    - Can I use my own AI API keys?
    - How do I migrate from SillyTavern?
    - What's the difference between modes?
  - [ ] **DoD**: FAQ covers common questions

### Epic 8.2: Developer Documentation

**Goal**: Document architecture for contributors

**Definition of Done**: Contributors can build and extend the app

#### Tasks:

- [ ] **Task 8.2.1**: Update ARCHITECTURE.md
  - [ ] Subtask: Add desktop-specific sections to `docs/ARCHITECTURE.md`
  - [ ] Subtask: Document Tauri integration
  - [ ] Subtask: Document multi-backend database design
  - [ ] **DoD**: Architecture docs reflect desktop version

- [ ] **Task 8.2.2**: Write Build Guide
  - [ ] Subtask: Create `docs/developer-guide/building.md`
  - [ ] Subtask: Document prerequisites (Rust, Node.js, platform tools)
  - [ ] Subtask: Document build commands:
    ```bash
    # Development
    cargo tauri dev

    # Production build
    cargo tauri build --target <target>
    ```
  - [ ] Subtask: Document code signing setup
  - [ ] **DoD**: Build guide complete

- [ ] **Task 8.2.3**: Write Contributing Guide
  - [ ] Subtask: Update `CONTRIBUTING.md`
  - [ ] Subtask: Document testing requirements (TDD, OWASP)
  - [ ] Subtask: Document code review process
  - [ ] **DoD**: Contributing guide updated

### Epic 8.3: Release Preparation

**Goal**: Prepare for v1.0.0 release

**Definition of Done**: Release published on GitHub

#### Tasks:

- [ ] **Task 8.3.1**: Create Release Checklist
  - [ ] Subtask: All tests pass (unit, integration, security)
  - [ ] Subtask: All documentation complete
  - [ ] Subtask: Installers signed and notarized
  - [ ] Subtask: Binary size <200MB
  - [ ] Subtask: Performance benchmarks met
  - [ ] **DoD**: All release criteria satisfied

- [ ] **Task 8.3.2**: Create GitHub Release
  - [ ] Subtask: Tag version: `git tag v1.0.0`
  - [ ] Subtask: Write release notes
  - [ ] Subtask: Upload installers:
    - `scribe-desktop-1.0.0-x64-setup.exe` (Windows)
    - `scribe-desktop-1.0.0-universal.dmg` (macOS)
  - [ ] Subtask: Upload checksums (SHA256)
  - [ ] **DoD**: Release published on GitHub

- [ ] **Task 8.3.3**: Announce Release
  - [ ] Subtask: Write announcement blog post
  - [ ] Subtask: Post to Reddit (r/SillyTavern, r/LocalLLaMA)
  - [ ] Subtask: Post to Discord (SillyTavern community)
  - [ ] Subtask: Tweet announcement
  - [ ] **DoD**: Release announced

## Testing Strategy Summary

### Test Coverage Requirements

**Per TESTING_PATTERNS.md**:
- Unit tests for all services (≥80% coverage)
- Integration tests for database operations
- Security tests for all OWASP Top 10 risks
- E2E tests for critical user flows

### Test Execution

**Development**:
```bash
# Run specific test file
cargo test --test <test_name> --message-format=short

# Run with debugging
RUST_BACKTRACE=1 RUST_LOG=debug cargo test --test <test_name> -- --nocapture

# Run security tests
cargo test --tests --message-format=short -- security::
```

**CI/CD** (`.github/workflows/desktop.yml`):
```yaml
name: Desktop Build & Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v3
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run Tests
        run: cargo test --all-targets --features desktop
      - name: Run Security Tests
        run: cargo test --tests -- security::
      - name: Cargo Audit
        run: cargo audit --deny warnings

  build:
    needs: test
    strategy:
      matrix:
        include:
          - os: windows-latest
            target: x86_64-pc-windows-msvc
          - os: macos-latest
            target: x86_64-apple-darwin
          - os: macos-latest
            target: aarch64-apple-darwin
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: cargo tauri build --target ${{ matrix.target }}
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: scribe-desktop-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/bundle/
```

## Risk Mitigation

### High-Risk Items

1. **Migration Conversion**: 176 migrations may have edge cases
   - **Mitigation**: Automated script + manual review + comprehensive testing

2. **LanceDB Maturity**: Newer technology than Qdrant
   - **Mitigation**: Extensive performance testing + fallback to Qdrant option

3. **Binary Size**: LanceDB + Tauri may exceed 200MB
   - **Mitigation**: Profile and optimize, consider compression

4. **Encryption Performance**: SQLite encryption overhead
   - **Mitigation**: Benchmark early, optimize pragmas

### Medium-Risk Items

1. **Platform Differences**: SQLite behavior varies by OS
   - **Mitigation**: Test on all platforms in CI/CD

2. **Code Signing**: Certificate acquisition delays
   - **Mitigation**: Start certificate procurement early (Week 1)

## Success Metrics

### Functional Metrics
- ✅ All OWASP security tests pass
- ✅ All unit/integration tests pass
- ✅ Installers work on all target platforms

### Performance Metrics
- ✅ Startup time <2s (cold start)
- ✅ Chat message retrieval <10ms (100 messages)
- ✅ Hybrid search <50ms (10k vectors)

### Quality Metrics
- ✅ Binary size <200MB
- ✅ Zero critical security vulnerabilities
- ✅ Documentation coverage ≥90%

## Timeline Summary

| Phase | Duration | Milestones |
|-------|----------|------------|
| Phase 1: Foundation | Weeks 1-3 | Database abstraction, migrations converted |
| Phase 2: Vector Store | Weeks 4-5 | LanceDB integrated, hybrid search working |
| Phase 3: Tauri Integration | Weeks 6-7 | Mode selection UI, server commands |
| Phase 4: Security Testing | Week 8 | All OWASP tests passing |
| Phase 5: Platform Builds | Weeks 9-10 | Signed installers for Windows/macOS |
| Phase 6: Performance | Week 11 | All benchmarks met |
| Phase 7: Payment | Week 12 | Cloud validation working |
| Phase 8: Release | Weeks 13-14 | Documentation complete, v1.0.0 released |

**Total**: 14 weeks (3.5 months)
