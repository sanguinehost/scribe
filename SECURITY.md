# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < main  | :x:                |

We currently only support the latest version from the `main` branch.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it privately using one of the following methods:

### Preferred: GitHub Security Advisories
1. Go to [Security Advisories](https://github.com/sanguinehost/scribe/security/advisories)
2. Click "New draft security advisory"
3. Fill out the form with details of the vulnerability

### Alternative: Email
Send an email to: **security@sanguinehost.com**

Include the following information:
- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

## Response Timeline

- **Initial response**: Within 48 hours of report
- **Status update**: Within 1 week with initial assessment
- **Resolution**: Target within 30 days for critical issues, 90 days for others

## Security Features

Sanguine Scribe implements several security measures:

### OWASP Top 10 Coverage
All security-sensitive code includes tests covering the [OWASP Top 10](docs/OWASP-TOP-10.md):
- **A01 - Broken Access Control**: User isolation, authorization checks
- **A02 - Cryptographic Failures**: Data encryption at rest, secure transmission
- **A03 - Injection**: SQL injection, XSS, command injection prevention
- **A04 - Insecure Design**: Rate limiting, resource exhaustion prevention
- **A05 - Security Misconfiguration**: Error message sanitization
- **A07 - Authentication Failures**: Session validation, invalid token handling
- **A08 - Data Integrity**: Cascade operations, referential integrity
- **A09 - Logging Failures**: Security event logging
- **A10 - SSRF**: Server-side request forgery prevention

### End-to-End Encryption
- All sensitive user data is encrypted at rest using user-derived keys
- Chat messages, character details, and personal information are protected
- Even database administrators cannot access plaintext user content

### Secure Architecture
- Rust backend with memory safety guarantees
- PostgreSQL with parameterized queries preventing SQL injection
- Session-based authentication with secure cookie handling
- Rate limiting and DoS protection
- Input validation and output sanitization

## Security Testing

We require security tests for all new features. Examples can be found in:
- `backend/tests/context_enrichment_security_tests.rs`
- `backend/tests/chronicle_security_tests.rs`

## Acknowledgments

We believe in responsible disclosure and will acknowledge security researchers who report vulnerabilities according to this policy. With permission, we will:

- Credit the reporter in our security advisories
- Include acknowledgment in release notes
- Provide recognition in our security acknowledgments section

## Questions?

If you have questions about our security policy, please contact: security@sanguinehost.com