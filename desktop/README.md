# Scribe Desktop

A standalone desktop application for Scribe, packaged using Tauri 2.0.

## Overview

Scribe Desktop wraps the existing SvelteKit frontend and Rust backend into a single distributable application for Windows and macOS. This provides:

- **Zero Docker Dependencies**: Self-contained binary with no container requirements
- **Dual-Mode Architecture**: Support for both standalone mode (embedded backend) and client mode (connect to remote server)
- **Full Encryption**: Complete KEK/DEK encryption system for local data protection
- **Cross-Platform**: Single codebase for Windows/macOS

## Architecture

The desktop application is structured as a Cargo workspace member:

```
desktop/
├── Cargo.toml          # Package configuration
├── tauri.conf.json     # Tauri configuration
├── build.rs            # Build script
├── build.sh            # Development build script
├── src/
│   ├── main.rs         # Application entry point
│   └── lib.rs          # Core Tauri logic
├── icons/              # Application icons
└── capabilities/       # Tauri capability definitions
```

## Development

### Prerequisites

- Rust 1.77.2+
- Node.js & pnpm
- Tauri CLI 2.0+ (`cargo install tauri-cli`)

### Building for Development

```bash
# Option 1: Use the build script
./desktop/build.sh

# Option 2: Manual steps
cd frontend && pnpm run build:desktop
cd ../desktop && cargo tauri dev
```

### Building for Production

```bash
cd desktop
cargo tauri build
```

## Configuration

### Tauri Configuration (`tauri.conf.json`)

- **App Identifier**: `com.sanguine.scribe`
- **Window Size**: 1280x800 (min: 1024x768)
- **Bundle Targets**: NSIS (Windows), DMG/App (macOS)

### Frontend Build

The frontend is built using `@sveltejs/adapter-static` with configuration in `frontend/svelte.config.desktop.js`. The built static files are output to `frontend/build/` and served by Tauri.

## Future Phases

This is Phase 1 (Task 1.1.1) - Basic Tauri initialization. Future phases will add:

- **Phase 1.2**: Database abstraction (SQLite support)
- **Phase 2**: Vector store integration (LanceDB)
- **Phase 3**: Dual-mode architecture (standalone vs client)
- **Phase 4**: OWASP security testing
- **Phase 5**: Platform-specific builds with code signing

## Resources

- [Tauri Documentation](https://tauri.app/)
- [Desktop Architecture](../docs/DESKTOP_ARCHITECTURE.md)
- [Implementation Plan](../docs/DESKTOP_IMPLEMENTATION_PLAN.md)
