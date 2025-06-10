# Testing Patterns and Best Practices

## Overview

This document outlines the improved testing patterns implemented to make the codebase more extensible and maintainable, particularly around service initialization and dependency management.

## The Problem

Previously, adding a new service to `AppStateServices` required updating every test file that created an instance, leading to:

- **Brittle tests**: Any new service broke existing tests
- **Code duplication**: Service initialization logic scattered across test files  
- **Maintenance burden**: Changes required touching many files
- **Developer friction**: Writing tests required boilerplate service setup

## The Solution: Builder Pattern with Defaults

We've implemented a builder pattern that provides:

1. **Sensible defaults** for all services
2. **Optional overrides** for testing specific behaviors
3. **Extensibility** without breaking existing code
4. **Centralized logic** for service creation

## New Testing Infrastructure

### AppStateServicesBuilder

Located in `src/state_builder.rs`, this builder provides a fluent API for creating `AppStateServices`:

```rust
use scribe_backend::state_builder::AppStateServicesBuilder;

// Create with minimal required dependencies
let services = AppStateServicesBuilder::new(db_pool, config)
    .with_ai_client(mock_ai_client)
    .with_embedding_client(mock_embedding_client) 
    .with_qdrant_service(mock_qdrant_service)
    .build();

let app_state = AppState::new(db_pool, config, services);
```

### TestFixtures

Located in `src/test_fixtures.rs`, provides convenience methods for common test scenarios:

```rust
use scribe_backend::test_fixtures::TestFixtures;

// Minimal test setup with all mocks
let app_state = TestFixtures::minimal_app_state(pool, config);

// Real services with mocked externals
let app_state = TestFixtures::real_services_app_state(pool, config);

// Custom builder for specific overrides
let app_state = AppState::new(
    pool.clone(),
    config.clone(), 
    TestFixtures::custom_app_state(pool, config)
        .with_email_service(custom_email_service)
        .build()
);
```

### Macro Support

For complex test setups, a macro is available:

```rust
let app_state = test_app_state!(
    pool,
    config,
    with_email_service = custom_email_service,
    with_token_counter = custom_counter
);
```

## Migration Guide

### Before: Manual Service Creation

```rust
// Old pattern - brittle and verbose
fn create_test_app_state(test_app: TestApp) -> Arc<AppState> {
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let tokenizer_service = TokenizerService::new("path/to/model")
        .expect("Failed to create tokenizer");
    let hybrid_token_counter = Arc::new(HybridTokenCounter::new_local_only(tokenizer_service));
    // ... many more lines of boilerplate
    
    let services = AppStateServices {
        ai_client: test_app.mock_ai_client.clone().expect("Mock AI client"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(embedding_pipeline_service),
        chat_override_service,
        user_persona_service,
        token_counter: hybrid_token_counter,
        encryption_service,
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service: Arc::new(LoggingEmailService::new("http://localhost:3000".to_string())),
    };

    Arc::new(AppState::new(test_app.db_pool, test_app.config, services))
}
```

### After: Builder Pattern

```rust
// New pattern - concise and extensible
fn create_test_app_state(test_app: TestApp) -> Arc<AppState> {
    let services = AppStateServicesBuilder::new(test_app.db_pool.clone(), test_app.config.clone())
        .with_ai_client(test_app.mock_ai_client.clone().expect("Mock AI client"))
        .with_embedding_client(test_app.mock_embedding_client.clone())
        .with_qdrant_service(test_app.qdrant_service.clone())
        .build();

    Arc::new(AppState::new(test_app.db_pool, test_app.config, services))
}
```

## Key Benefits

### 1. **Extensibility**
Adding a new service only requires:
- Adding the field to `AppStateServices`
- Adding a builder method to `AppStateServicesBuilder`
- Providing a sensible default in the `build()` method

Existing tests continue to work without modification.

### 2. **Default Services**
The builder automatically creates:
- `EncryptionService` with default settings
- `AuthBackend` connected to the database
- `FileStorageService` using config path
- `EmailService` with logging implementation
- `TokenCounter` with local tokenizer
- All other services with production-like defaults

### 3. **Test Isolation**
Tests can override only the services they care about:

```rust
// Only override the email service for email-specific tests
let app_state = AppStateServicesBuilder::new(pool, config)
    .with_ai_client(mock_ai)
    .with_embedding_client(mock_embedding)
    .with_qdrant_service(mock_qdrant)
    .with_email_service(custom_email_service)
    .build();
```

### 4. **Type Safety**
The builder pattern maintains full type safety while providing flexibility.

## Best Practices

### When Writing New Tests

1. **Start with TestFixtures**: Use `TestFixtures::minimal_app_state()` unless you need specific behavior
2. **Override minimally**: Only override services you're actually testing
3. **Use real services when possible**: Prefer `TestFixtures::real_services_app_state()` for integration tests
4. **Document custom services**: If you create custom mocks, document why

### When Adding New Services

1. **Add to AppStateServices**: Define the new service field
2. **Update the builder**: Add `with_service_name()` method
3. **Provide defaults**: Implement default creation in `build()`
4. **Update TestFixtures**: Add convenience methods if commonly used
5. **Test the builder**: Ensure new services work with existing patterns

### Common Patterns

```rust
// For unit tests - minimal setup
let app_state = TestFixtures::minimal_app_state(pool, config);

// For integration tests - real services
let app_state = TestFixtures::real_services_app_state(pool, config);

// For service-specific tests - targeted overrides
let app_state = AppState::new(
    pool.clone(),
    config.clone(),
    AppStateServicesBuilder::new(pool, config)
        .with_ai_client(mock_ai)
        .with_embedding_client(mock_embedding) 
        .with_qdrant_service(mock_qdrant)
        .with_lorebook_service(custom_lorebook_service) // Only override what you test
        .build()
);
```

## Future Enhancements

### Planned Improvements

1. **Service Templates**: Pre-configured builder templates for common test scenarios
2. **Mock Factories**: Centralized mock creation with common configurations
3. **Integration Helpers**: Utilities for setting up external service dependencies
4. **Performance Optimization**: Lazy initialization for expensive services

### Extension Points

The pattern is designed to accommodate:
- New service types
- Different mock implementations
- Environment-specific configurations
- Test-specific service behaviors

## Examples

See `backend/tests/embedding_pipeline_tests.rs` for a complete example of the migration from the old pattern to the new builder pattern.

For additional examples and patterns, refer to:
- `backend/src/test_fixtures.rs` - Core testing utilities
- `backend/src/state_builder.rs` - Builder implementation
- Test files using the new patterns