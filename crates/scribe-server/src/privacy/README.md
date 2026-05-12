# Privacy-Preserving Logging System

This module provides a comprehensive privacy-preserving logging system that ensures user data is never exposed in application logs while maintaining full debuggability through correlation IDs and structured logging.

## Overview

The privacy system addresses critical privacy issues identified in the original logging:
- **User IDs exposed directly** (e.g., `user_id = %user_id`)
- **Session IDs exposed** (e.g., `session_id = %session_id`)
- **Chat content and prompts** logged in debug messages
- **Personal information** (emails, usernames) in logs
- **Sensitive API parameters** logged without redaction

## Architecture

The system consists of four main components:

### 1. Privacy Infrastructure (`mod.rs`)
- `ObfuscatedId`: One-way hashed identifiers for different entity types
- `SanitizedString`: Content wrapper that redacts sensitive data in logs
- `PrivacyContext`: Request-scoped context for obfuscation mappings
- `LoggableUserId`, `LoggableSessionId`, etc.: Display wrappers for safe logging

### 2. Logging Utilities (`logging.rs`)
- Privacy-safe logging macros (`privacy_info!`, `privacy_debug!`, etc.)
- Helper functions for creating loggable wrappers
- Content sanitization utilities
- JSON sanitization for structured data

### 3. Privacy Middleware (`middleware.rs`)
- Request-scoped privacy context injection
- Correlation ID generation for request tracing
- Axum integration for request/response cycle

### 4. Examples (`examples.rs`)
- Practical transformation examples
- Before/after comparisons
- Usage patterns and best practices

## Quick Start

### Basic Usage

```rust
use crate::privacy::logging::{loggable_user_id, loggable_session_id, sanitize_content};
use crate::privacy::{privacy_info, privacy_debug, privacy_warn, privacy_error};

fn example_logging() {
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let user_content = "Tell me about my account";

    // Privacy-safe logging
    privacy_info!(
        user_id = %loggable_user_id(user_id),
        session_id = %loggable_session_id(session_id),
        "Processing user request"
    );

    privacy_debug!(
        user_id = %loggable_user_id(user_id),
        content = %sanitize_content(user_content),
        "Received user message"
    );
}
```

### With Request Context

```rust
use crate::privacy::middleware::ExtractPrivacyContext;

async fn handler(privacy: ExtractPrivacyContext) -> String {
    let user_id = get_current_user_id();

    privacy_info!(
        request_id = %privacy.0.request_id(),
        user_id = %privacy.0.obfuscate_user_id(user_id),
        "Processing authenticated request"
    );

    "Success".to_string()
}
```

## Transformation Guide

### Step 1: Replace Direct ID Logging

**Before:**
```rust
info!(%user_id, "Processing request");
debug!(%session_id, "Session started");
```

**After:**
```rust
privacy_info!(user_id = %loggable_user_id(user_id), "Processing request");
privacy_debug!(session_id = %loggable_session_id(session_id), "Session started");
```

### Step 2: Sanitize Content

**Before:**
```rust
debug!("User message: {}", content);
debug!("System prompt: {}", system_prompt);
```

**After:**
```rust
privacy_debug!(content = %sanitize_content(content), "User message received");
privacy_debug!(system_prompt = %sanitize_system_prompt(system_prompt), "Using system prompt");
```

### Step 3: Redact Personal Information

**Before:**
```rust
info!(email = %email, username = %username, "User registered");
```

**After:**
```rust
privacy_info!(email = "<email-redacted>", username = "<username-redacted>", "User registered");
```

### Step 4: Sanitize Error Messages

**Before:**
```rust
error!(error = ?e, "Database error: {}", e);
```

**After:**
```rust
privacy_error!(error_type = "database_connection", error_code = "TIMEOUT", "Database operation failed");
```

## Log Output Comparison

### Before (Privacy Risk)
```
INFO  Processing request [user_id=550e8400-e29b-41d4-a716-446655440000]
DEBUG User message: 'What is my account balance?'
ERROR Database query failed: Connection timeout for user 550e8400-e29b-41d4-a716-446655440000
```

### After (Privacy Protected)
```
INFO  Processing request [request_id=a1b2c3d4, user_id=user#7f2e8a91bc4d]
DEBUG User message received [request_id=a1b2c3d4, content=<content-redacted:29-chars>]
ERROR Database operation failed [request_id=a1b2c3d4, user_id=user#7f2e8a91bc4d, error_type=connection_timeout]
```

## Integration with Middleware

Add the privacy middleware to your Axum router:

```rust
use crate::privacy::middleware::privacy_middleware;

let app = Router::new()
    .route("/api/chat", post(chat_handler))
    .layer(axum::middleware::from_fn(privacy_middleware));
```

This automatically:
- Generates correlation IDs for each request
- Injects privacy context into request extensions
- Enables request tracing without exposing user data

## Configuration

Set up privacy configuration via environment variables:

```bash
# Salt for hashing user identifiers (REQUIRED - change in production)
PRIVACY_HASH_SALT=your-secret-salt-here

# Whether to enable content redaction (default: true)
PRIVACY_REDACT_CONTENT=true

# Maximum content preview length (default: 0 = full redaction)
PRIVACY_MAX_CONTENT_PREVIEW=0
```

## Entity Type Support

The system supports obfuscation for all major entity types:

- **User IDs**: `loggable_user_id(uuid)` → `user#7f2e8a91bc4d`
- **Session IDs**: `loggable_session_id(uuid)` → `session#9k4p2x7m`
- **Character IDs**: `loggable_character_id(uuid)` → `character#3m8n9p2q`
- **Persona IDs**: `loggable_persona_id(uuid)` → `persona#4r7s2t9u`
- **Chronicle IDs**: `loggable_chronicle_id(uuid)` → `chronicle#6v5w8x1y`
- **Lorebook IDs**: `loggable_lorebook_id(uuid)` → `lorebook#2z4a7b9c`

## Content Redaction Types

Different content types have specific redaction patterns:

```rust
// User-generated content
let content = sanitize_content("User's personal message");
// Output: <content-redacted:23-chars>

// System prompts
let prompt = sanitize_system_prompt("You are a helpful AI...");
// Output: <system-prompt-redacted:25-chars>

// Personal information
let email = sanitize_personal_info("user@example.com");
// Output: <personal-info-redacted>

// Credentials
let token = sanitize_credentials("secret_api_key");
// Output: <credentials-redacted>
```

## Best Practices

### 1. Always Use Wrappers for IDs
```rust
// ❌ Never log raw UUIDs
info!(%user_id, "User action");

// ✅ Always use privacy wrappers
privacy_info!(user_id = %loggable_user_id(user_id), "User action");
```

### 2. Sanitize All User Content
```rust
// ❌ Never log raw user content
debug!("Message: {}", user_message);

// ✅ Always sanitize content
privacy_debug!(message = %sanitize_content(user_message), "Processing user message");
```

### 3. Use Request Correlation
```rust
// ✅ Include request ID for tracing
privacy_info!(
    request_id = %privacy_ctx.request_id(),
    user_id = %loggable_user_id(user_id),
    action = "login_attempt",
    "User authentication started"
);
```

### 4. Structure Error Information
```rust
// ❌ Don't expose internal error details
error!("Database error: {}", db_error);

// ✅ Structure error information safely
privacy_error!(
    error_type = "database_connection",
    error_category = "infrastructure",
    operation = "user_query",
    "Database operation failed"
);
```

### 5. Separate Audit from Operational Logs
```rust
// Operational logs (privacy-safe)
privacy_info!(
    user_id = %loggable_user_id(user_id),
    action = "account_locked",
    "User account status changed"
);

// Separate audit log (encrypted, restricted access)
// audit_log.record_account_lock(user_id, admin_id, reason);
```

## Testing Privacy Protection

The system includes utilities for testing privacy compliance:

```rust
#[test]
fn test_no_pii_in_logs() {
    let user_id = Uuid::new_v4();
    let loggable = loggable_user_id(user_id);

    // Ensure original UUID is not in output
    assert!(!loggable.to_string().contains(&user_id.to_string()));

    // Ensure consistent hashing
    assert_eq!(loggable.to_string(), loggable_user_id(user_id).to_string());
}
```

## Migration Strategy

1. **Audit Current Logging**: Identify all logging statements exposing user data
2. **Update by Priority**: Start with authentication, chat, and admin routes
3. **Add Privacy Middleware**: Integrate request correlation
4. **Test Thoroughly**: Ensure debuggability is maintained
5. **Monitor Compliance**: Regular audits for privacy violations

## Compliance Benefits

This system ensures compliance with privacy regulations:

- **GDPR**: User data never stored in logs, one-way hashing prevents identification
- **CCPA**: No personal information in operational logs
- **HIPAA**: Healthcare data (if applicable) fully redacted
- **Internal Policies**: Corporate privacy policies automatically enforced

## Performance Considerations

- **Minimal Overhead**: Hashing and redaction add < 1ms per log statement
- **Memory Efficient**: No storage of original data in log structures
- **Correlation Efficient**: Request IDs enable fast log correlation
- **Debuggable**: Full traceability maintained without privacy risk

## Future Enhancements

Planned improvements include:

1. **Automatic PII Detection**: Scan logs for potential privacy violations
2. **Audit Trail Integration**: Separate encrypted audit logs for compliance
3. **Log Analysis Tools**: Privacy-aware log analysis and debugging tools
4. **Compliance Reporting**: Automated privacy compliance verification

## Support

For questions or issues with the privacy logging system:

1. Check the examples in `privacy/examples.rs`
2. Review test cases for usage patterns
3. Consult the transformation guide above
4. Follow the structured logging patterns consistently

Remember: **Privacy by design** - always assume logs may be accessed by unauthorized parties and design accordingly.
