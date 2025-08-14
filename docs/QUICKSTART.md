# Quickstart Guide

Get Sanguine Scribe running in under 5 minutes with Docker/Podman.

## Prerequisites

- **Docker** or **Podman** with Docker Compose support
- **Git** for cloning the repository
- **Gemini API key** from [Google AI Studio](https://aistudio.google.com/app/apikey)

## Quick Setup

### 1. Clone and Configure

```bash
git clone https://github.com/sanguinehost/scribe.git
cd scribe
cp .env.example .env
```

### 2. Add Your API Key

Edit `.env` and set your Gemini API key:

```bash
# Required: Your Gemini API key
GEMINI_API_KEY=your-api-key-here

# Optional: Change default database credentials
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_secure_password
```

### 3. Start Services

**With Docker:**
```bash
docker compose up -d
```

**With Podman (Recommended for security):**
```bash
podman-compose up -d
```

### 4. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **PostgreSQL**: localhost:5432
- **Qdrant Dashboard**: http://localhost:6333/dashboard

## First Steps

1. **Create Account**: Register at http://localhost:3000
2. **Import Character**: Upload a V2/V3 character card or create a new one
3. **Start Chatting**: Enjoy intelligent context management with chronicle system
4. **Explore Features**: Try lorebooks, personas, and advanced chat modes

## Verification

Check that all services are running:

```bash
docker compose ps
# or
podman-compose ps
```

You should see:
- `scribe_postgres` (healthy)
- `scribe_qdrant` (healthy)

## Troubleshooting

### Services Won't Start
- **Port conflicts**: Stop services using ports 3000, 5432, 6333, 8080
- **Permission issues**: Use `sudo` with Docker, or prefer Podman for rootless containers

### Can't Connect to Database
- Wait 30 seconds for PostgreSQL to initialize on first run
- Check logs: `docker compose logs postgres`

### API Key Issues
- Verify your Gemini API key at [Google AI Studio](https://aistudio.google.com/app/apikey)
- Ensure no quotes around the key in `.env`
- Restart services after changing environment variables

### Frontend Build Errors
- The frontend builds inside Docker - check logs: `docker compose logs frontend`
- Ensure you have enough disk space (>2GB free)

## Next Steps

- **Production deployment**: See [Terraform deployment guide](../terraform/README.md)
- **Development setup**: Check [backend](../backend/README.md) and [frontend](../frontend/README.md) guides
- **Configuration**: Review [Architecture docs](ARCHITECTURE.md)

## Need Help?

- **Documentation**: Browse the [docs/](.) directory
- **Issues**: [GitHub Issues](https://github.com/sanguinehost/scribe/issues)
- **Discord**: [Join our community](https://discord.gg/Qd93Pascvp)

---

**Note**: This quickstart uses development settings. For production, use proper TLS certificates and secure database credentials.