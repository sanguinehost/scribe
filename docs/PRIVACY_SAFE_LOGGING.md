# Privacy-Safe Logging Guidelines

This document outlines the privacy and security practices for logging in the Sanguine Scribe payment system to maintain SAQ-A compliance and protect personally identifiable information (PII).

## Overview

Sanguine Scribe implements a comprehensive privacy framework to ensure that no PII or PCI-sensitive data is exposed in application logs. This is critical for:

- **SAQ-A Compliance**: Maintaining eligibility for the most restrictive PCI DSS self-assessment questionnaire
- **User Privacy**: Protecting user data from accidental exposure in logs
- **Security**: Preventing credential or sensitive data leaks through logging systems

## Privacy Framework Components

### 1. Privacy Module (`backend/src/privacy/`)

The privacy module provides comprehensive tools for safe logging:

- **ObfuscatedId**: One-way hashed identifiers for logging user/session/entity IDs
- **SanitizedString**: Wrapper for sensitive content that redacts when logged
- **LoggableUserId/SessionId/etc.**: Ready-to-use wrappers for common ID types
- **JSON Sanitization**: Automatic PII removal from JSON structures

### 2. Available Logging Utilities

#### Safe ID Logging
```rust
use crate::privacy::logging::loggable_user_id;

// ❌ NEVER do this:
tracing::info!("User {} performed action", user.id);

// ✅ DO this instead:
tracing::info!("User {} performed action", loggable_user_id(user.id));
```

#### Personal Information Redaction
```rust
use crate::privacy::logging::sanitize_personal_info;

// ❌ NEVER do this:
tracing::info!("Customer email: {}", user.email);

// ✅ DO this instead:
tracing::info!("Customer email: {}", sanitize_personal_info(&user.email));
```

#### JSON Structure Sanitization
```rust
use crate::privacy::logging::sanitize_json_value;

// ❌ NEVER do this:
tracing::debug!("Webhook data: {}", serde_json::to_string_pretty(&webhook_data));

// ✅ DO this instead:
let sanitized = sanitize_json_value(&webhook_data);
tracing::debug!("Webhook data: {}", serde_json::to_string_pretty(&sanitized));
```

## Data Classification and Handling

### 🔴 NEVER LOG (PII/PCI Data)
- **Email addresses** - Use `sanitize_personal_info()`
- **Usernames/Names** - Use `sanitize_personal_info()`
- **User UUIDs** - Use `loggable_user_id()`
- **Card numbers, CVV, expiry dates** - Should never be in system anyway (SAQ-A)
- **Full customer data from webhooks** - Use `sanitize_json_value()`
- **Billing addresses or phone numbers** - Use `sanitize_personal_info()`

### 🟡 LOG WITH CAUTION (Operational Data)
- **Transaction IDs** - These are Paddle references, not PII, but limit exposure
- **Customer IDs** - Paddle identifiers, not PII, but be conservative
- **Session IDs** - Use `loggable_session_id()`
- **Request IDs** - Safe to log as they're internal correlation IDs

### 🟢 SAFE TO LOG (Non-PII Data)
- **Plan types and features**
- **Token usage counts**
- **Error messages (without PII)**
- **System state and configuration**
- **Performance metrics**

## Implementation Examples

### Payment Route Logging

```rust
// User authentication logging
tracing::info!(
    user_id = %loggable_user_id(user.id),
    user_email = %sanitize_personal_info(&user.email),
    user_username = %sanitize_personal_info(&user.username),
    "User authenticated for payment operation"
);

// Webhook processing
let sanitized_json = sanitize_json_value(&webhook_data);
tracing::debug!(
    "Sanitized webhook structure: {}",
    serde_json::to_string_pretty(&sanitized_json).unwrap_or("unparseable".to_string())
);

// Customer processing
tracing::info!(
    "Processing transaction for customer email: {}",
    sanitize_personal_info(&customer_email)
);
```

### Test File Logging

```rust
// ❌ In test files, avoid:
println!("Testing for user: {}", user_id);
println!("Customer email: {}", email);

// ✅ Instead use:
// Testing payment functionality for test user
// Customer email: [REDACTED]
```

## Audit Logging vs Application Logging

### Audit Logs (Privacy-Focused)
The `PaymentAuditService` provides minimal, privacy-safe audit logging:

- **Hashed user IDs** (non-reversible)
- **Event types only** (credit_added, payment_processed, etc.)
- **Amounts and success status**
- **External reference hashes** (not full IDs)
- **Automatic purging** (30-day retention)

### Application Logs (Development/Operations)
Application logs use the privacy framework for operational debugging:

- **Obfuscated identifiers** (reversible with salt, but not exposed)
- **Redacted personal information**
- **Sanitized JSON structures**
- **Request correlation IDs**

## Verification and Monitoring

### Automated Checks
- **Pre-commit hooks** scan for card data patterns
- **CI/CD pipeline** validates payment security architecture
- **Pattern detection** identifies potential PII leakage

### Manual Review Process
1. **Code reviews** must verify privacy-safe logging practices
2. **Log analysis** should never reveal PII in production logs
3. **Audit preparation** relies on formal audit logs, not application logs

## Common Mistakes to Avoid

### ❌ Direct Structure Logging
```rust
// This could expose PII in nested structures
tracing::debug!("User data: {:?}", user);
tracing::info!("Webhook: {}", serde_json::to_string(&webhook));
```

### ❌ String Interpolation Without Redaction
```rust
// Direct exposure of sensitive data
tracing::warn!("Failed for user {}: {}", user.email, error);
```

### ❌ Test Data Exposure
```rust
// Test files can leak real data if run with production DBs
println!("User ID: {}", user_id);
```

### ❌ Error Message PII
```rust
// Error messages might contain PII from input validation
tracing::error!("Validation failed: {}", user_input);

// AppError format strings with raw user IDs
AppError::NotFound(format!("UserDbQuery for user {user_id} not found: {e}"))
```

### ❌ Auth/Session Debugging
```rust
// Raw user IDs in authentication debugging
tracing::warn!("Found user with ID: {}", user_id);
```

## SAQ-A Compliance Notes

This privacy framework specifically supports SAQ-A compliance by ensuring:

1. **No cardholder data in logs** - Card data never enters the system anyway
2. **No PII correlation** - User identifiers are hashed in audit logs
3. **Minimal data retention** - Audit logs auto-purge after 30 days
4. **External reference only** - Only Paddle transaction/customer IDs stored

## Environment Configuration

Set the privacy salt for production environments:

```bash
export PRIVACY_HASH_SALT="your-production-salt-here"
```

**Note**: Use a strong, unique salt for production that differs from development.

## Best Practices Summary

1. **Always use privacy wrappers** for user identifiers
2. **Sanitize personal information** before logging
3. **Use audit logs for compliance** and application logs for operations
4. **Review log output** in development to ensure no PII exposure
5. **Configure proper retention** for different log types
6. **Monitor for patterns** that might indicate PII leakage

## Implementation Checklist

- [x] Import privacy logging utilities in payment-related modules
- [x] Replace direct user ID logging with `loggable_user_id()`
- [x] Replace email/username logging with `sanitize_personal_info()`
- [x] Use `sanitize_json_value()` for webhook/request logging
- [x] Remove `println!` statements with PII from test files
- [x] Fix auth/session debugging logs to use obfuscated IDs
- [x] Update error messages to avoid raw user ID exposure
- [x] Fix service layer logging across user personas, characters, chats
- [ ] Configure `PRIVACY_HASH_SALT` for production
- [ ] Set up log monitoring for PII pattern detection
- [ ] Document privacy practices for new team members

## Files Updated for Privacy Compliance

### Backend Services and Routes
- `src/services/user_persona_service.rs` - 8 logging statements updated
- `src/routes/chat.rs` - Debug logging updated
- `src/routes/characters.rs` - Asset fetching log updated
- `src/routes/chats.rs` - 3 info/debug logs updated
- `src/routes/payment.rs` - Payment processing logs updated (previous)

### Authentication Layer
- `src/auth/user_store.rs` - Session user ID logging updated
- `src/auth/session_dek.rs` - DEK extraction logging updated (5 statements)

### Core Services
- `src/services/chat/generation.rs` - Error message updated
- `src/test_helpers.rs` - Test cleanup logging updated

### Test Files
- `tests/db_integration_tests.rs` - println! statements redacted
- `tests/payment_integration_tests.rs` - Customer data redacted (previous)
- `tests/payment_usage_tracking_validation_test.rs` - User IDs redacted (previous)

## Related Documentation

- [PCI DSS SAQ-A Compliance Checklist](./PAYMENT_COMPLIANCE.md)
- [Payment Security Architecture](./ARCHITECTURE.md)
- [Development Setup Guide](./DEVELOPMENT.md)

---

**Important**: This privacy framework is designed to work alongside, not replace, proper data handling practices. Always follow the principle of data minimization and avoid collecting unnecessary PII in the first place.
