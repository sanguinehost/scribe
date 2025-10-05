# Payment System Encryption Inventory

This document provides a comprehensive inventory of all encrypted fields in the Sanguine Scribe payment system, documenting encryption strategies, field specifications, and security characteristics.

## Table of Contents

- [Encryption Strategy Overview](#encryption-strategy-overview)
- [Payment Transactions](#payment-transactions)
- [Credit Transactions](#credit-transactions)
- [Encryption Key Hierarchy](#encryption-key-hierarchy)
- [Security Characteristics](#security-characteristics)
- [Verification & Testing](#verification--testing)

---

## Encryption Strategy Overview

The payment system uses **AES-256-GCM** (Galois/Counter Mode) authenticated encryption with two distinct key derivation strategies:

1. **System-Level Encryption** - For payment transaction customer data
   - Uses `PAYMENT_DATA_ENCRYPTION_KEY` from environment/secrets
   - Applied to: Payment transaction `customer_data` field

2. **User-Level Encryption** - For credit transaction descriptions/metadata
   - Uses HMAC-SHA256 key derivation from user's encrypted DEK
   - Context string: `credit_transactions_{user_id}`
   - Applied to: Credit transaction `description` and `metadata` fields

### Why Two Strategies?

- **Payment transactions** contain customer PII that must be decryptable by system administrators for compliance/support purposes → system-level key
- **Credit transactions** contain user-specific financial data that should only be accessible with the user's session → user-level derived key

---

## Payment Transactions

### Table: `payment_transactions`

| Field | Type | Encrypted | Nonce Field | Key Strategy | Nullable | Notes |
|-------|------|-----------|-------------|--------------|----------|-------|
| `id` | UUID | ❌ No | N/A | N/A | No | Primary key |
| `user_id` | UUID | ❌ No | N/A | N/A | No | Foreign key to users |
| `paddle_transaction_id` | String | ❌ No | N/A | N/A | Yes | External reference |
| `paddle_subscription_id` | String | ❌ No | N/A | N/A | Yes | External reference |
| `amount_cents` | i32 | ❌ No | N/A | N/A | No | Stored in cents |
| `currency` | String | ❌ No | N/A | N/A | No | ISO currency code |
| `status` | String | ❌ No | N/A | N/A | No | Enum: pending/completed/failed |
| **`customer_data_encrypted`** | **Vec\<u8>** | **✅ Yes** | **`customer_data_nonce`** | **System-level** | **No** | **Customer PII (email, name, address)** |
| `customer_data_nonce` | Vec\<u8> | ❌ No | N/A | N/A | No | 12-byte nonce for AES-GCM |
| `created_at` | DateTime\<Utc> | ❌ No | N/A | N/A | Yes | Timestamp |
| `updated_at` | DateTime\<Utc> | ❌ No | N/A | N/A | Yes | Timestamp |

#### Encrypted Field Details: `customer_data_encrypted`

- **Algorithm**: AES-256-GCM
- **Key Source**: `PAYMENT_DATA_ENCRYPTION_KEY` environment variable
- **Key Derivation**: Direct use (no HMAC derivation)
- **Nonce Size**: 12 bytes
- **Nonce Storage**: `customer_data_nonce` column
- **Plaintext Structure**: JSON containing:
  ```json
  {
    "customer_email": "user@example.com",
    "customer_name": "John Doe",
    "customer_address": {
      "country_code": "US",
      "postal_code": "12345"
    }
  }
  ```
- **Decryption Context**: System administrators with access to `PAYMENT_DATA_ENCRYPTION_KEY`
- **Test Coverage**: `/backend/tests/payment_security_tests.rs`

---

## Credit Transactions

### Table: `credit_transactions`

| Field | Type | Encrypted | Nonce Field | Key Strategy | Nullable | Notes |
|-------|------|-----------|-------------|--------------|----------|-------|
| `id` | UUID | ❌ No | N/A | N/A | No | Primary key |
| `user_id` | UUID | ❌ No | N/A | N/A | No | Foreign key to users |
| `amount` | i32 | ❌ No | N/A | N/A | No | Credits added/deducted |
| `balance_after` | i32 | ❌ No | N/A | N/A | No | Snapshot balance |
| `transaction_type` | String | ❌ No | N/A | N/A | No | Enum: grant/purchase/deduction/reservation/release |
| **`description_encrypted`** | **Vec\<u8>** | **✅ Yes** | **`description_nonce`** | **User-level (HMAC-derived)** | **No** | **Transaction description** |
| `description_nonce` | Vec\<u8> | ❌ No | N/A | N/A | No | 12-byte nonce for AES-GCM |
| **`metadata_encrypted`** | **Vec\<u8>** | **✅ Yes** | **`metadata_nonce`** | **User-level (HMAC-derived)** | **Yes** | **Optional transaction metadata** |
| `metadata_nonce` | Vec\<u8> | ❌ No | N/A | N/A | Yes | 12-byte nonce for AES-GCM |
| `reference_id` | String | ❌ No | N/A | N/A | Yes | External reference (e.g., Paddle transaction ID) |
| `created_at` | DateTime\<Utc> | ❌ No | N/A | N/A | Yes | Timestamp |

#### Encrypted Field Details: `description_encrypted`

- **Algorithm**: AES-256-GCM
- **Key Source**: User's `encrypted_dek` (Data Encryption Key)
- **Key Derivation**:
  ```rust
  // HMAC-SHA256 with context string
  let context = format!("credit_transactions_{}", user_id);
  let mut mac = HmacSha256::new_from_slice(&user.encrypted_dek[..32.min(user.encrypted_dek.len())])?;
  mac.update(context.as_bytes());
  let key_material = mac.finalize().into_bytes();
  ```
- **Nonce Size**: 12 bytes (cryptographically random)
- **Nonce Storage**: `description_nonce` column
- **Plaintext Structure**: Plain text string (e.g., "Monthly subscription credit grant", "Credit purchase - 1000 credits")
- **Decryption Context**: Requires user's DEK (available during authenticated session or via fallback derivation)
- **Test Coverage**: `/backend/tests/credit_encryption_tests.rs`

#### Encrypted Field Details: `metadata_encrypted`

- **Algorithm**: AES-256-GCM
- **Key Source**: User's `encrypted_dek` (Data Encryption Key)
- **Key Derivation**: Same as `description_encrypted` (shared HMAC-derived key)
- **Nonce Size**: 12 bytes (cryptographically random, unique per field)
- **Nonce Storage**: `metadata_nonce` column
- **Plaintext Structure**: JSON containing optional structured data:
  ```json
  {
    "plan": "premium",
    "credits": 500,
    "period": "2025-10"
  }
  ```
- **Nullable**: Yes (many transactions have no metadata)
- **Decryption Context**: Same as `description_encrypted`
- **Test Coverage**: `/backend/tests/credit_encryption_tests.rs`

---

## Encryption Key Hierarchy

```
┌─────────────────────────────────────────────────────┐
│          Root Key Material                          │
│  (User Password → KEK via Argon2)                   │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
        ┌─────────────────────────────┐
        │   User's Encrypted DEK       │
        │   (stored in users table)    │
        └──────────┬──────────────────┘
                   │
        ┌──────────┴──────────────────────────────┐
        │                                          │
        ▼                                          ▼
┌───────────────────────┐            ┌─────────────────────────────┐
│  Session DEK (Memory) │            │  HMAC-Derived Credit Key    │
│  Used for characters, │            │  Context: credit_txns_{uid} │
│  messages, lorebook   │            │  Used for credit txns only  │
└───────────────────────┘            └─────────────────────────────┘


┌─────────────────────────────────────────────────────┐
│      PAYMENT_DATA_ENCRYPTION_KEY                    │
│      (Environment/Secrets Manager)                  │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
        ┌─────────────────────────────────┐
        │  Payment Transaction Customer   │
        │  Data (system-level encryption) │
        └─────────────────────────────────┘
```

### Key Characteristics

1. **User DEK** (Data Encryption Key)
   - Generated per-user during account creation
   - Encrypted with KEK (derived from password via Argon2)
   - Stored encrypted in `users.encrypted_dek`
   - Decrypted into session memory upon login

2. **HMAC-Derived Credit Key**
   - Derived from user's encrypted DEK (first 32 bytes)
   - Uses context string for domain separation
   - Ensures credit transactions can only be decrypted with user's key material
   - Supports fallback derivation when session DEK unavailable

3. **System Payment Key**
   - Single key for all payment transaction customer data
   - Managed via environment variables / AWS Secrets Manager
   - Rotatable independently of user keys
   - Accessible to authorized system administrators

---

## Security Characteristics

### Authentication Tags
All encrypted fields use **AES-GCM authenticated encryption**, which provides:
- **Confidentiality**: Ciphertext cannot be read without the key
- **Integrity**: Any tampering is detected via authentication tag mismatch
- **Non-malleability**: Attackers cannot modify ciphertext to produce predictable plaintext changes

### Nonce Management
- **Uniqueness**: Every encryption operation generates a fresh 12-byte cryptographically random nonce
- **Storage**: Nonces stored alongside ciphertext (required for decryption)
- **Security**: AES-GCM security critically depends on never reusing a nonce with the same key
- **Verification**: Test coverage includes nonce uniqueness checks (see `test_credit_encryption_nonce_uniqueness`)

### Key Isolation
- **Payment transactions**: System-level key (shared across all users for operational needs)
- **Credit transactions**: User-level keys (isolated per user via HMAC derivation)
- **Rationale**: Different threat models and access requirements

### PII Protection
All encrypted fields contain Personally Identifiable Information (PII):
- **Payment customer_data**: Email, name, postal address, country code
- **Credit descriptions**: Transaction narratives (may contain user-identifiable patterns)
- **Credit metadata**: Structured data about purchases, plans, billing periods

### Encryption at Rest
✅ **Verified**: Database contains only encrypted blobs and nonces, no plaintext PII
- Test coverage: `test_credit_description_encrypted_at_rest`, `test_credit_metadata_encrypted_at_rest`, `test_no_plaintext_pii_in_credit_transactions`
- Pattern scanning: Regex checks for SSN, credit card numbers, email, phone formats

### Error Handling
- **Decryption failures**: Return `AppError::DecryptionFailed` (not silent corruption)
- **Key mismatch**: Detected via authentication tag failure
- **Corrupted data**: AES-GCM authentication prevents silent corruption
- Test coverage: `test_credit_encryption_key_mismatch`, `test_credit_decryption_with_corrupted_data`

---

## Verification & Testing

### Test Suites

#### Credit Transaction Encryption (`/backend/tests/credit_encryption_tests.rs`)
- ✅ `test_credit_description_encrypted_at_rest` - Verifies no plaintext in DB
- ✅ `test_credit_metadata_encrypted_at_rest` - Verifies metadata encryption
- ✅ `test_credit_transaction_decryption_roundtrip` - End-to-end encrypt/decrypt
- ✅ `test_credit_encryption_key_mismatch` - Wrong key detection
- ✅ `test_credit_encryption_with_special_characters` - Unicode/emoji preservation
- ✅ `test_credit_encryption_nonce_uniqueness` - 50 transactions, all unique nonces
- ✅ `test_credit_decryption_with_corrupted_data` - Corruption detection
- ✅ `test_credit_encryption_without_metadata` - NULL metadata handling
- ✅ `test_no_plaintext_pii_in_credit_transactions` - PII pattern scanning

#### Payment Transaction Encryption (`/backend/tests/payment_security_tests.rs`)
- ✅ `test_transaction_customer_data_encrypted_at_rest`
- ✅ `test_transaction_encryption_with_special_characters`
- ✅ Additional payment-specific security tests

### Running Tests
```bash
# Credit encryption tests (requires integration test environment)
export RUN_INTEGRATION_TESTS=true
cargo test --test credit_encryption_tests --features payment

# Payment encryption tests
cargo test --test payment_security_tests --features payment

# All payment system tests
cargo test --features payment
```

### Manual Verification Checklist

When adding new encrypted fields:

- [ ] **Field Definition**: Encrypted field (`Vec<u8>`) + nonce field (`Vec<u8>`) in schema
- [ ] **Encryption Logic**: Implements `encrypt_gcm()` with appropriate key derivation
- [ ] **Decryption Logic**: Implements `decrypt_gcm()` with error handling
- [ ] **Nonce Generation**: Uses `generate_random_nonce()` for cryptographic randomness
- [ ] **Test Coverage**: At least 3 tests (at-rest encryption, roundtrip, edge cases)
- [ ] **Documentation**: Add to this inventory with specifications
- [ ] **Migration**: Create diesel migration for schema changes
- [ ] **Audit Logging**: Log encryption/decryption events (without plaintext)

---

## Related Documentation

- [FIX_PLAN.md](./FIX_PLAN.md) - Overall payment system security roadmap
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [SECURITY.md](./SECURITY.md) - General security practices
- Credit Service: `/backend/src/services/payment/credit_service.rs`
- Payment Service: `/backend/src/services/payment/paddle_service.rs`
- Encryption Utilities: `/backend/src/services/payment/encryption.rs`

---

**Last Updated**: 2025-10-03
**Status**: ✅ All documented fields verified with test coverage
**Next Review**: When adding new encrypted fields to payment system
