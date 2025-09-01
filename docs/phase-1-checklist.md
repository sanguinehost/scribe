# Phase 1 Security & Quality Checklist

This checklist tracks the implementation of essential security, CI/CD, testing, and operational improvements to achieve a 9-10/10 production-ready codebase.

## Security and Compliance

### GitHub Security Features
- [ ] Enable GitHub Advanced Security: secret scanning and push protection
- [ ] Configure branch protection rules on main:
  - [ ] Required reviews
  - [ ] Required status checks
  - [ ] Signed commits
  - [ ] Dismiss stale reviews
- [ ] Add CODEOWNERS with clear ownership of key paths

### Supply Chain Security
- [ ] Add cargo-deny for license/vulnerability policies (Rust)
- [ ] Add npm audit or OSV scanning step (pnpm) and set severity thresholds
- [ ] Generate and publish SBOMs (Syft or cargo-about + syft for frontend)
- [ ] Attach SBOMs to releases and images
- [ ] Sign container images and release artifacts with Sigstore Cosign
- [ ] Publish SLSA provenance attestation

### Application Security Testing
- [ ] Dynamic security test in CI (OWASP ZAP baseline) against the dev server
- [ ] Fuzz critical parsers/handlers with cargo-fuzz
- [ ] Add a nightly fuzz job
- [ ] Create threat model doc with dataflow diagrams
- [ ] Track mitigations and open risks

### Privacy and Cryptography
- [ ] Tighten "end-to-end encryption" phrasing to accurately describe server-side encryption with client-derived keys
- [ ] Document any model-provider data flows
- [ ] Add or refine SECURITY.md with disclosure process, timelines, and scope

## CI/CD Quality Gates

### PR Checks
- [ ] Rust checks:
  - [ ] fmt check
  - [ ] clippy -D warnings
  - [ ] cargo test (unit + integration)
  - [ ] Optional tarpaulin/llvm-cov coverage
- [ ] Frontend checks:
  - [ ] pnpm lint
  - [ ] typecheck
  - [ ] vitest
  - [ ] build
- [ ] Monorepo workflow that caches Rust/pnpm, runs affected subsets, and posts a single status

### Coverage Reporting
- [ ] Upload combined coverage to Codecov or GitHub Test Coverage
- [ ] Set a threshold for failure on regressions

### Build and Publish
- [ ] Build and push backend/agent images to GHCR on main and tags
- [ ] Cross-platform release binaries for the CLI (Linux/macOS/Windows)
- [ ] Attach binaries to GitHub Releases

## Testing Depth

### Rust Testing
- [ ] Integration tests for API, DB migrations, and crypto boundaries
- [ ] Property tests (proptest/quickcheck) for enc/dec, tokenization, and parsing
- [ ] Criterion benchmarks for hot paths (e.g., encryption, query)

### Frontend Testing
- [ ] Component tests with Vitest + Testing Library
- [ ] Playwright end-to-end tests covering critical flows (auth, note CRUD, search, sync)
- [ ] Accessibility tests (axe-core) in CI

### Data Testing
- [ ] Seeded test data and deterministic fixtures
- [ ] Contract tests between frontend and backend (OpenAPI schemas or Zod validators)

## Release Engineering and Versioning

- [ ] Adopt semantic versioning and tag releases
- [ ] Automate CHANGELOG via Changesets or release-please
- [ ] Pre-releases (alpha/beta) from main; stable from a release branch
- [ ] Nightly canary build with automated smoke tests
- [ ] Add release notes templates with breaking change callouts and upgrade steps

## Documentation and Community Health

### Community Files
- [ ] Add CODE_OF_CONDUCT.md
- [ ] Add SUPPORT.md
- [ ] Add issue templates
- [ ] Add PR templates
- [ ] Add ROADMAP.md

### Technical Documentation
- [ ] Architecture doc with diagrams (components, dataflow, trust boundaries)
- [ ] API reference (OpenAPI/Swagger) published and versioned
- [ ] ADRs for key decisions (encryption model, storage/indexing, auth)

### Repository Enhancement
- [ ] Improve discoverability: repository topics, badges (CI, CodeQL, coverage, GHCR)
- [ ] Contributor UX: Makefile/justfile or taskfile
- [ ] Pre-commit hooks (lint, fmt, typecheck)

## Observability and Operations

### Telemetry
- [ ] Structured logs, metrics, and tracing (OpenTelemetry) in backend
- [ ] Trace context propagation from frontend where applicable

### Health Monitoring
- [ ] Readiness/liveness endpoints
- [ ] /health with dependency checks
- [ ] SLOs/SLIs defined (availability, latency)
- [ ] Alerts wired

### Deployment
- [ ] Helm chart or K8s manifests with secure defaults:
  - [ ] Non-root user
  - [ ] Read-only filesystem
  - [ ] Liveness/readiness probes
  - [ ] Resource limits
- [ ] Systemd units/quadlets refined for single-host deployments
- [ ] Zero-downtime DB migrations
- [ ] Backup and restore runbook

### Container Hardening
- [ ] Minimal base (distroless/ubi-micro)
- [ ] Non-root user
- [ ] Drop capabilities
- [ ] Read-only filesystem
- [ ] Trivy/Grype image scanning in CI

## Performance and Reliability

### Backend Performance
- [ ] Load tests with k6 or Locust
- [ ] Baseline performance budgets
- [ ] Profiling (pprof or tokio-console)
- [ ] Flamegraphs and regression detection

### Frontend Performance
- [ ] Lighthouse CI for performance/A11y/SEO with budgets
- [ ] Bundle size guardrails (size-limit)
- [ ] Per-PR bundle size report

### Resilience
- [ ] Chaos testing for dependency outages (Postgres, Qdrant)
- [ ] Retries, timeouts, and circuit breakers on external model APIs

## Product Polish and UX

- [ ] Accessibility: keyboard navigation, focus management, color contrast
- [ ] CI accessibility checks
- [ ] i18n scaffolding (even if English-only initially)
- [ ] Onboarding flows and sample data for quick evaluation
- [ ] CLI UX polish: consistent flags, --config, autocomplete scripts, and man pages

## Governance and Maintenance

- [ ] MAINTAINERS.md and triage policy
- [ ] Label taxonomy and GitHub Project board for roadmap/triage
- [ ] Automation for stale issues/PRs (with humane settings)
- [ ] Regular dependency update cadence documented
- [ ] Release cadence documented

## High-Impact Quick Wins

These items provide the highest impact with lowest effort:

- [ ] Add CODEOWNERS
- [ ] Configure branch protection
- [ ] Enable secret scanning push protection
- [ ] Introduce cargo-deny
- [ ] Add SBOM generation in CI
- [ ] Stand up minimal PR workflow (fmt/lint/test)
- [ ] Upload coverage reports
- [ ] Add issue/PR templates
- [ ] Add CODE_OF_CONDUCT
- [ ] Publish GHCR images
- [ ] Start tagging releases with automated changelogs
- [ ] Clarify encryption terminology across README/docs