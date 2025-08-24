# Sanguine Scribe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Backend-Rust-orange.svg)](https://www.rust-lang.org/)
[![Svelte](https://img.shields.io/badge/Frontend-SvelteKit-red.svg)](https://kit.svelte.dev/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue.svg)](https://www.postgresql.org/)

> **Privacy-first character-based AI roleplaying platform** - A fast, reactive alternative to SillyTavern with zero-knowledge encryption and intelligent context management, designed for interactive character conversations and future AI-driven game integration (RPGs, dating sims, interactive fiction).

## ✨ Features

- 🔒 **End-to-end encryption** - Your character data and chat history are encrypted on our servers, though AI processing requires sending messages to external APIs (Gemini)
- 🚀 **Fast responses** with intelligent background context enrichment
- 🧠 **Smart context management** - Chronicle system automatically tracks narrative history
- 🎮 **Game-ready architecture** - Built for future RPG, dating sim, and interactive fiction integration
- 📚 **Advanced lorebook system** - Rich world-building with vector search
- 🎭 **Character compatibility** - Full V2/V3 character card support
- 🌐 **Self-hostable** - Deploy your own instance with complete data sovereignty
- 🔗 **Federation ready** - Connect multiple instances (coming soon)
- 🤖 **Google AI integration** - Gemini API with planned Gemma 3 on-device support

## 🏗️ Architecture

**Modern Stack:**
- **Frontend**: SvelteKit + TypeScript + pnpm - Reactive, fast UI
- **Backend**: Rust + Axum - Type-safe, performant API
- **AI Integration**: [sanguinehost/rust-genai](https://github.com/sanguinehost/rust-genai) - Fork of [jeremychone/rust-genai](https://github.com/jeremychone/rust-genai)
- **Databases**: PostgreSQL 16 for structured data, Qdrant v1.14+ vector database for semantic search
- **Containerization**: Docker/Podman with multi-stage builds
- **Infrastructure**: AWS ECS/Fargate with Terraform IaC
- **Deployment**: Frontend on Vercel, backend containers on AWS

**Key Innovations for Character Roleplay:**
- **Server-Side Encryption**: Client-side password-derived keys encrypt your data on our servers (note: AI processing requires sending messages to Gemini API)
- **Context Enrichment**: Character responses with optional background context enrichment modes
- **Chronicle System**: Automatic extraction and indexing of character interactions and story beats
- **Context Enrichment Agent**: Smart retrieval of relevant character history and personality traits
- **Hybrid Search**: Combines keyword and semantic search for accurate character context
- **Game Integration Architecture**: Built for future RPG, dating sim, and interactive fiction integration with EventSource::GameApi hooks

## 🚀 Quick Start

### One-Command Setup (Recommended)

**Prerequisites:**
- Podman or Docker
- mkcert for local certificates
- Rust 1.75+ and Cargo (for local development)
- Node.js 18+ and pnpm (optional, for frontend)

```bash
git clone https://github.com/sanguinehost/scribe.git
cd scribe

# One command to rule them all! 🎯
./start.sh

# In another terminal, start the backend
cargo run --bin scribe-backend

# Optional: Start frontend too
./start.sh --frontend
```

Visit `https://localhost:5173` to start chatting with full TLS!

**What start.sh does:**
- 🔍 Auto-detects your container runtime (Podman preferred, Docker fallback)
- 🔒 Generates TLS certificates if missing
- 🐘 Starts PostgreSQL and Qdrant containers
- ✅ Runs health checks to ensure everything is ready
- 📋 Shows you exactly what to do next

### Alternative: Full Container Stack

For testing complete containerized deployments:

```bash
git clone https://github.com/sanguinehost/scribe.git
cd scribe

# Run everything in containers (including backend)
./start.sh --mode=container --frontend
```

Visit `https://localhost:8080` (backend) and `https://localhost:5173` (frontend) to start chatting!

**Benefits:** Complete containerization, matches production environment closely.

### Manual Setup (Advanced)

For full control over the setup process:

```bash
# Generate certificates manually
./scripts/certs/manage.sh local init

# Start services with specific runtime
./scripts/podman-dev.sh up    # or
./scripts/docker-dev.sh       # for Docker users

# Build and run backend
cd backend && cargo run --bin scribe-backend

# Start frontend
cd frontend && pnpm install && pnpm dev
```

### Systemd Quadlets (Linux)

**Prerequisites:**
- Podman 4.4+ with systemd integration
- systemd user services enabled

```bash
git clone https://github.com/sanguinehost/scribe.git
cd scribe
cp .env.example .env
# Edit .env with your API keys

# Deploy as systemd services
./scripts/deploy/quadlet.sh start
```

### Option 4: Cloud Deploy

[![Deploy with Terraform](https://img.shields.io/badge/Deploy%20with-Terraform-623CE4)](https://github.com/sanguinehost/scribe/tree/main/infrastructure/terraform)

```bash
# Deploy to AWS with Terraform
./scripts/deploy/aws.sh deploy staging
```

[![Deploy Frontend on Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/sanguinehost/scribe/tree/main/frontend)

See detailed setup instructions in [QUICKSTART.md](docs/QUICKSTART.md).

## 🎮 Usage

### 1. **Import Characters**
Load V2/V3 character cards from SillyTavern, Character.AI exports, or create new characters with our editor.

### 2. **Interactive Roleplay**
Engage in character-based conversations with fast, reactive AI responses and automatic context management.

### 3. **Enhance with Lorebooks**
Build rich character worlds with searchable lorebooks that provide relevant context during conversations.

### 4. **Automatic Chronicles**
Chronicle system tracks character interactions and story developments without manual intervention.

## 📖 Documentation

- [**Quickstart Guide**](docs/QUICKSTART.md) - Get running in 5 minutes
- [**Architecture Overview**](docs/ARCHITECTURE.md) - System design and technical details
- [**Deployment Guide**](docs/DEPLOYMENT.md) - Production deployment instructions
- [**API Documentation**](docs/API.md) - REST API reference
- [**Contributing Guide**](CONTRIBUTING.md) - How to contribute to the project

## 🆚 Comparison

| Feature | Sanguine Scribe | SillyTavern | Character.AI |
|---------|-----------------|-------------|--------------|
| **Data Protection** | 🔒 Server-side encryption (excl. AI APIs) | ❌ Local files only | ❌ Unknown/accessible |
| **Self-Hostable** | ✅ Full control | ✅ Local only | ❌ SaaS only |
| **Context Management** | 🚀 Automatic | 📝 Manual | 🤖 Black box |
| **Game Integration** | 🎮 Designed for RPGs/dating sims | ❌ No | ❌ No |
| **AI Models** | 🤖 Gemini + Gemma 3 | 🌐 All major APIs | 🏠 Proprietary only |
| **Performance** | ⚡ Fast server, AI-limited | 🐌 Can be slow | ⚡ Fast |
| **Open Source** | ✅ MIT License | ✅ AGPL | ❌ Proprietary |
| **Federation** | 🔜 Coming soon | ❌ No | ❌ No |

## 🏃‍♂️ Roadmap

### Phase 1: Alpha Release (Current)
- [x] Core chat functionality
- [x] Character and persona management
- [x] Chronicle system with automatic event extraction
- [x] Lorebook with semantic search
- [x] End-to-end encryption
- [x] Gemini API integration
- [ ] Gemma 3 on-device inference

### Phase 2: Federation & Scaling
- [ ] Multi-instance federation
- [ ] Advanced character gallery
- [ ] Real-time collaborative sessions
- [ ] Mobile app
- [ ] Plugin system

### Phase 3: Game Integration & Advanced Features
- [ ] Unity/Unreal Engine SDK for game integration
- [ ] Dating simulator UI components and mechanics
- [ ] RPG character stat tracking and combat integration
- [ ] Voice chat integration with character voices
- [ ] Image generation for character avatars and scenes
- [ ] Advanced prompt engineering tools
- [ ] Community marketplace
- [ ] Optional data sharing pipeline for open source model training (chat-by-chat opt-in)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

**Ways to help:**
- 🐛 Report bugs and suggest features
- 💻 Submit pull requests
- 📖 Improve documentation
- 🌐 Add translations
- 🧪 Help with testing (including OWASP Top 10 security tests)
- 🔒 Security testing following [OWASP Top 10](docs/OWASP-TOP-10.md)

## 🏢 Commercial Use

Sanguine Scribe is dual-purpose:

- **Open Source**: MIT licensed for self-hosting and development
- **Hosted Service**: Professional hosting available at [sanguinehost.com](https://sanguinehost.com)

The hosted service provides:
- **Server-side encryption** - Your character data and chat history are encrypted (note: AI processing requires external API calls)
- Managed infrastructure with 99.9% uptime SLA
- Automatic updates and security patches
- Bundled Gemini API access (flat-rate pricing)
- Professional support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Privacy & Security

### Data Protection

- **Server-Side Encryption**: Your character data and chat history are encrypted on our servers using keys derived from your password
- **AI Processing Limitation**: Chat messages are sent to Google's Gemini API for AI responses - this is required for the AI functionality
- **Self-Hosting Option**: For complete control, deploy your own instance with your own API keys

### Future Data Sharing (TBD)

We are planning an **optional, selective data sharing system** where:
- Users can choose to contribute individual chat conversations to help train open source AI models
- This will be **opt-in on a chat-by-chat basis** - never automatic
- Data will be scrubbed and disassociated from user accounts before use
- Only used for training open source models, never sold or used commercially
- This feature is currently **under development** and not yet implemented

### Security

Please see our [Security Policy](SECURITY.md) for reporting vulnerabilities.

## 🙋‍♀️ Support

- **Documentation**: Check our [docs](docs/) first
- **Community**: Join our [Discord server](https://discord.gg/Qd93Pascvp)
- **Issues**: [GitHub Issues](https://github.com/sanguinehost/scribe/issues)
- **Professional Support**: Available with hosted plans at [sanguinehost.com](https://sanguinehost.com)

## 🙏 Acknowledgments

Special thanks to:

- **[SillyTavern](https://github.com/SillyTavern/SillyTavern)** - The original inspiration and gold standard for AI roleplay platforms
- **[Google DeepMind](https://deepmind.google/)** - For providing the powerful Gemini API that powers our AI interactions
- **[Vercel](https://github.com/vercel/ai-chatbot-svelte)** - For the AI chatbot Svelte template that provided our frontend foundation
- **[shadcn-svelte](https://www.shadcn-svelte.com/)** - For the beautiful and accessible UI components that power our interface
- **[Qdrant](https://qdrant.tech/)** - For the exceptional vector database that enables our semantic search capabilities
- **[PostgreSQL Global Development Group](https://www.postgresql.org/)** - For the robust and reliable database that forms our data foundation
- **[Diesel](https://diesel.rs/)** - For the excellent Rust ORM and migration system that manages our database schema
- **[Axum](https://github.com/tokio-rs/axum)** - For the fast, ergonomic web framework powering our backend API
- **[Tokio](https://tokio.rs/)** - For the async runtime that enables our high-performance backend
- **[Tailwind CSS](https://tailwindcss.com/)** - For the utility-first CSS framework that styles our interface
- **[TypeScript](https://www.typescriptlang.org/)** - For bringing type safety to our frontend development
- **[Vite](https://vitejs.dev/)** - For the lightning-fast build tool that powers our development workflow
- **[Podman](https://podman.io/)** - For the rootless, secure containerization platform we recommend for deployment
- **[Docker](https://www.docker.com/)** - For the containerization platform that simplifies deployment
- **[Terraform](https://www.terraform.io/)** - For the Infrastructure as Code tool that manages our cloud deployments
- **[Jeremy Chone](https://github.com/jeremychone)** and contributors to [rust-genai](https://github.com/jeremychone/rust-genai) - Our AI integration is built on their excellent foundation
- **The Rust community** for creating such powerful tools and libraries
- **SvelteKit team** for the amazing frontend framework
- **GitHub** for providing the platform that hosts our code and powers our CI/CD
- **All contributors** who help make Sanguine Scribe better

---

<div align="center">
  <strong>Built with ❤️ for the AI roleplay community</strong>
  <br>
  <a href="https://sanguinehost.com">Hosted by Sanguine Host</a> • 
  <a href="https://github.com/sanguinehost/scribe">Star on GitHub</a> • 
  <a href="https://discord.gg/Qd93Pascvp">Join Discord</a>
</div>