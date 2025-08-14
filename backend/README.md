# Sanguine Scribe Backend

High-performance Rust backend for Sanguine Scribe's privacy-first character AI platform, built with Axum, PostgreSQL, and Qdrant.

## Features

- **Server-Side Encryption**: Client-side password-derived keys with server-side encryption protect stored data (AI processing requires external API calls)
- **Fast & Safe**: Built with Rust for memory safety and performance suitable for real-time game integration
- **Type-Safe ORM**: Diesel for robust database interactions with encrypted data handling
- **Vector Search**: Qdrant integration for semantic search and RAG with encrypted content
- **Game-Ready Architecture**: EventSource::GameApi hooks and batch processing for future RPG/dating sim integration
- **Comprehensive Security**: OWASP Top 10 tests, end-to-end encryption, and extensive security validation
- **Production Ready**: Docker deployment with health checks and scalable architecture

## Prerequisites

- **Rust 1.75+** with Cargo
- **PostgreSQL 16+** 
- **Qdrant v1.14+**
- **Gemini API key** from [Google AI Studio](https://aistudio.google.com/app/apikey)

## Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/sanguinehost/scribe.git
cd scribe/backend
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` with your settings:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/scribe_dev

# Vector Database  
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-qdrant-key-if-needed

# AI Integration
GEMINI_API_KEY=your-gemini-api-key

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# Security (Critical for Zero-Knowledge Privacy)
JWT_SECRET=your-super-secret-jwt-key-here
ENCRYPTION_KEY=your-32-byte-encryption-key-here
SESSION_SECRET=your-session-secret-here
COOKIE_SIGNING_KEY=your-cookie-signing-key-here
```

### 3. Database Setup

```bash
# Install Diesel CLI
cargo install diesel_cli --no-default-features --features postgres

# Run migrations
diesel migration run

# Verify schema
diesel print-schema
```

### 4. Run Development Server

```bash
# Development with auto-reload
cargo install cargo-watch
cargo watch -x run

# Or standard run
cargo run
```

The API will be available at `http://localhost:8080`

## Testing

### Run All Tests

```bash
# Unit and integration tests
cargo test

# With output
cargo test -- --nocapture

# Specific test
cargo test test_name
```

### Security Tests

Security tests covering OWASP Top 10 vulnerabilities:

```bash
# Context enrichment security
cargo test --test context_enrichment_security_tests

# Chronicle security  
cargo test --test chronicle_security_tests

# All security tests
cargo test security_tests
```

### Test Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage
```

## Development

### Project Structure

```
src/
├── auth/           # Authentication & session management
├── config/         # Configuration & feature flags
├── llm/           # AI client integrations (Gemini)
├── models/        # Database models & DTOs
├── routes/        # HTTP route handlers
├── services/      # Business logic layer
│   ├── agentic/   # Context enrichment & narrative tools
│   ├── chat/      # Chat session management
│   └── lorebook/  # Knowledge base management
├── vector_db/     # Qdrant client integration
└── test_helpers.rs # Testing utilities
```

### Key Components

- **Server-Side Encryption**: Client-side password-derived keys with server-side encryption protect stored data (note: AI processing requires sending content to external APIs)
- **Context Enrichment**: Automatic RAG-based context management for character consistency
- **Chronicle System**: Narrative event extraction and storage with encrypted content
- **Game Integration Hooks**: EventSource::GameApi and batch processing architecture for future game engine integration
- **Rate Limiting**: DDoS protection and resource management
- **Health Checks**: Comprehensive service monitoring

### Database Migrations

```bash
# Generate new migration
diesel migration generate add_feature_name

# Apply migrations
diesel migration run

# Rollback latest migration
diesel migration redo

# Check migration status
diesel migration pending
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint with Clippy
cargo clippy

# Check without building
cargo check

# Full CI pipeline
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

## API Documentation

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/verify-email` - Email verification

### Chat Management
- `GET /api/chats` - List chat sessions
- `POST /api/chats` - Create chat session
- `GET /api/chats/{id}` - Get chat details
- `POST /api/chats/{id}/messages` - Send message
- `DELETE /api/chats/{id}` - Delete chat session

### Characters
- `GET /api/characters` - List characters
- `POST /api/characters` - Create character
- `PUT /api/characters/{id}` - Update character
- `DELETE /api/characters/{id}` - Delete character

### Chronicles (Narrative History)
- `GET /api/chronicles` - List chronicles
- `POST /api/chronicles` - Create chronicle
- `GET /api/chronicles/{id}/events` - Get chronicle events
- `POST /api/chronicles/{id}/events` - Add chronicle event

### Lorebooks (Knowledge Base)
- `GET /api/lorebooks` - List lorebooks
- `POST /api/lorebooks` - Create lorebook
- `GET /api/lorebooks/{id}/entries` - Get lorebook entries
- `POST /api/lorebooks/{id}/entries` - Create lorebook entry

### Health & Monitoring
- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics (if enabled)

## Deployment

### Docker

```bash
# Build image
docker build -t scribe-backend .

# Run container
docker run -p 8080:8080 --env-file .env scribe-backend
```

### Production Considerations

1. **Server-Side Encryption**: Ensure secure key derivation parameters and encryption key rotation policies (note: AI APIs receive decrypted content)
2. **Environment Variables**: Use secure secrets management (AWS Secrets Manager, HashiCorp Vault)
3. **Database**: Configure connection pooling, SSL, and encrypted backups
4. **TLS**: Use reverse proxy (nginx/Caddy) for HTTPS with proper certificate management
5. **Monitoring**: Enable structured logging and metrics without exposing encrypted content
6. **Backup**: Regular encrypted database backups and configuration backups
7. **Game Integration**: Plan for EventSource::GameApi endpoint scaling for future game engine integration

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

### Security Requirements

All security-sensitive code must include OWASP Top 10 tests with special focus on privacy:
- **Encryption Validation**: Verify encryption keys are properly derived and stored data is encrypted (understanding AI API limitations)
- **Access Control**: Multi-layer authorization with encrypted data boundaries
- **Encryption Verification**: End-to-end encryption testing with user-derived keys
- **Injection Prevention**: SQL injection, XSS, and prompt injection protection
- **Input Validation**: Comprehensive validation without exposing encrypted content
- **Error Handling**: Secure error messages that don't leak encrypted data or keys

Example security test files:
- `tests/context_enrichment_security_tests.rs`
- `tests/chronicle_security_tests.rs`

## Troubleshooting

### Database Connection Issues
- Verify PostgreSQL is running: `pg_isready`
- Check connection string in `.env`
- Ensure database exists: `createdb scribe_dev`

### Qdrant Connection Issues  
- Verify Qdrant is running: `curl http://localhost:6333/`
- Check API key if using authentication
- Review network configuration

### Build Errors
- Update Rust: `rustup update`
- Clean build cache: `cargo clean`
- Check system dependencies (OpenSSL, libpq)

### Test Failures
- Ensure test database is clean
- Check for conflicting processes on test ports
- Run tests sequentially: `cargo test -- --test-threads=1`

## License

MIT License - see [LICENSE](../LICENSE) file for details.