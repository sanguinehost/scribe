# Contributing to Sanguine Scribe

Thank you for your interest in contributing to Sanguine Scribe! This document provides guidelines and information for contributors.

## 🌟 Ways to Contribute

- **🐛 Bug Reports**: Help us identify and fix issues
- **💡 Feature Requests**: Suggest new functionality
- **💻 Code Contributions**: Implement features, fix bugs, improve performance
- **📖 Documentation**: Improve guides, add examples, fix typos
- **🧪 Testing**: Help test new features and report issues
- **🌐 Translations**: Add support for new languages
- **🎨 Design**: Improve UI/UX, create assets, design mockups

## 🚀 Getting Started

### Prerequisites

- **Node.js 18+** for frontend development
- **Rust 1.75+** for backend development
- **PostgreSQL 16+** for structured data
- **Qdrant v1.14+** vector database for semantic search
- **Docker** for development environment
- **Git** for version control

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/sanguine-scribe.git
   cd sanguine-scribe
   ```

2. **Backend Setup**
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env with your configuration
   diesel migration run     # Run database migrations
   cargo test              # Run tests
   cargo run               # Start backend server
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   pnpm install
   pnpm run dev            # Start development server
   pnpm run test           # Run tests
   pnpm run check          # TypeScript checking
   ```

4. **Full Stack Development**
   ```bash
   # Use Docker Compose for full environment (includes PostgreSQL 16 + Qdrant v1.14+)
   docker compose -f docker-compose.dev.yml up -d
   ```

## 📋 Development Workflow

### 1. **Issue First**
- Check existing issues before starting work
- Create an issue for bugs, features, or improvements
- Discuss your approach in the issue before starting

### 2. **Branch Naming**
Use descriptive branch names:
- `feat/add-voice-chat` - New features
- `fix/login-error` - Bug fixes
- `docs/api-examples` - Documentation
- `refactor/auth-service` - Code refactoring
- `test/chronicle-endpoints` - Testing improvements

### 3. **Commit Messages**
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
type(scope): description

feat(auth): add OAuth2 support
fix(chat): resolve message ordering issue
docs(api): add endpoint examples
test(backend): add integration tests for chronicles
refactor(frontend): simplify component structure
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code formatting (no logic changes)
- `refactor`: Code restructuring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### 4. **Pull Request Process**

1. **Before Submitting**
   - Ensure all tests pass
   - Run linters and formatters
   - Update documentation if needed
   - Add tests for new functionality

2. **PR Checklist**
   - [ ] Tests pass (`cargo test` and `pnpm run test`)
   - [ ] Security tests included for OWASP Top 10 risks (if applicable)
   - [ ] Code follows style guidelines
   - [ ] Documentation updated
   - [ ] No breaking changes (or clearly documented)
   - [ ] Commit messages follow conventional format
   - [ ] PR description explains what and why

3. **PR Template**
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Documentation update
   - [ ] Refactoring

   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Integration tests pass
   - [ ] OWASP Top 10 security tests included (if applicable)
   - [ ] Manual testing completed

   ## Screenshots (if applicable)
   
   ## Additional Notes
   ```

## 🧪 Testing Guidelines

### Backend Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with coverage
cargo tarpaulin --out Html
```

**Test Structure:**
- Unit tests in same file as code (`#[cfg(test)]`)
- Integration tests in `tests/` directory
- Security tests following OWASP Top 10 (see `docs/OWASP-TOP-10.md`)
- Use `test_helpers` for common setup
- Mock external services

**OWASP Top 10 Security Tests (Required):**
All new features and security-sensitive code must include tests covering:
- **A01 - Broken Access Control**: User isolation, authorization checks
- **A02 - Cryptographic Failures**: Data encryption at rest, secure transmission
- **A03 - Injection**: SQL injection, XSS, command injection prevention
- **A04 - Insecure Design**: Rate limiting, resource exhaustion prevention
- **A05 - Security Misconfiguration**: Error message sanitization
- **A07 - Authentication Failures**: Session validation, invalid token handling
- **A08 - Data Integrity**: Cascade operations, referential integrity
- **A09 - Logging Failures**: Security event logging (conceptual)
- **A10 - SSRF**: Server-side request forgery prevention

Examples: `backend/tests/context_enrichment_security_tests.rs`, `backend/tests/chronicle_security_tests.rs`

### Frontend Testing
```bash
# Run all tests
pnpm run test

# Run specific test
pnpm run test -- filename

# Run with coverage
pnpm run test:coverage
```

**Test Types:**
- Component tests using `@testing-library/svelte`
- Unit tests for utilities and stores
- E2E tests with Playwright (when applicable)

## 📝 Code Style

### Rust (Backend)
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy`
- Write documentation comments (`///`) for public APIs
- Use descriptive error types with `thiserror`

### TypeScript/Svelte (Frontend)
- Follow project ESLint configuration
- Use `prettier` for formatting: `pnpm run format`
- Use TypeScript strictly - avoid `any`
- Follow Svelte 5 patterns with runes
- Use semantic HTML and ARIA attributes

### Database
- **PostgreSQL + Diesel**: Use descriptive migration names with timestamps, migrations are in `backend/migrations/`, add comments to complex queries, use transactions for multi-step operations, follow PostgreSQL naming conventions, use Diesel ORM patterns
- **Qdrant**: Use meaningful collection names, optimize vector dimensions, implement proper indexing strategies, follow semantic search best practices

## 🏗️ Architecture Guidelines

### Backend Principles
- **Separation of Concerns**: Routes → Handlers → Services → Models
- **Error Handling**: Use `Result<T, AppError>` pattern
- **Testing**: Test-driven development with comprehensive coverage
- **Security**: Input validation, authentication, authorization
- **Performance**: Async/await, connection pooling, caching

### Frontend Principles
- **Component Architecture**: Reusable, composable components
- **State Management**: Svelte stores for global state, props for local
- **Type Safety**: Strong typing throughout the application
- **Accessibility**: WCAG 2.1 AA compliance
- **Performance**: Code splitting, lazy loading, optimization

## 📚 Documentation Standards

### Code Documentation
- **Rust**: Use `///` for public APIs, `//` for inline comments
- **TypeScript**: Use JSDoc comments for complex functions
- **README**: Each module should have clear setup instructions

### API Documentation
- Document endpoint behavior in code comments
- Include request/response examples in tests
- Document error codes and messages
- Keep documentation up-to-date with code changes

## 🐛 Bug Reports

Use the bug report template and include:

- **Description**: Clear description of the issue
- **Steps to Reproduce**: Numbered steps to reproduce
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, browser, versions
- **Screenshots**: If applicable
- **Logs**: Relevant error messages or logs

## 💡 Feature Requests

Use the feature request template and include:

- **Problem Statement**: What problem does this solve?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other solutions considered
- **Impact**: Who benefits and how?
- **Implementation**: Technical considerations (if known)

## 🚦 Review Process

### Code Review Criteria
- **Functionality**: Does it work as intended?
- **Performance**: Is it efficient and scalable?
- **Security**: Are there any security concerns?
- **Maintainability**: Is the code clear and well-structured?
- **Testing**: Are there adequate tests?
- **Documentation**: Is it properly documented?

### Review Timeline
- Initial review within 48 hours
- Follow-up reviews within 24 hours
- Approval from at least one core maintainer required

## 🏆 Recognition

Contributors are recognized in:
- **Contributors section** in README.md
- **Release notes** for significant contributions
- **Hall of Fame** for major contributors
- **Special thanks** in documentation

## 📞 Getting Help

- **Questions**: Ask in GitHub Discussions or Discord
- **Technical Issues**: Create an issue with details
- **Real-time Chat**: Join our Discord server
- **Documentation**: Check existing docs first

## 🎯 Good First Issues

Look for issues labeled:
- `good first issue` - Perfect for newcomers
- `help wanted` - Community help needed
- `documentation` - Documentation improvements
- `enhancement` - Feature improvements

## 📋 Development Environment

### Recommended Tools
- **IDE**: VS Code with Rust and Svelte extensions
- **Database**: CLI tools (psql for PostgreSQL, curl for Qdrant)
- **API Testing**: curl or your preferred CLI tool
- **Version Control**: Git CLI

### Useful Commands
```bash
# Backend development
cargo watch -x run                    # Auto-restart on changes
cargo expand                          # Expand macros
diesel print-schema                   # Print database schema

# Frontend development
pnpm run dev                          # Development server
pnpm run build                        # Production build
pnpm run preview                      # Preview production build
pnpm run check                        # Type checking

# Database (Diesel ORM)
psql -U postgres -d scribe_dev        # Connect to PostgreSQL
diesel migration run                   # Run migrations
diesel migration redo                  # Redo last migration
diesel migration generate add_feature  # Generate new migration

# Vector Database
curl http://localhost:6333/collections # List Qdrant collections
curl http://localhost:6333/dashboard   # Qdrant web UI
```

## 🔐 Security Considerations

- Never commit secrets, API keys, or passwords
- Use environment variables for configuration
- Follow security best practices in code
- Report security vulnerabilities privately (see SECURITY.md)
- Keep dependencies updated

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Sanguine Scribe!** 🚀

Your contributions help make AI roleplay better for everyone. Whether it's a small typo fix or a major feature, every contribution matters.