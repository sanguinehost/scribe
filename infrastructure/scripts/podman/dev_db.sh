#!/bin/bash

# Container runtime management script for development services
# Supports both Podman and Docker with automatic detection

COMMAND=$1

# Function to print usage
usage() {
  echo "Usage: $0 {up|down|reset|reset-up|logs|ps}"
  echo "  up      : Start containers in detached mode and run initial DB migrations"
  echo "  down    : Stop containers"
  echo "  reset   : Stop containers and remove volumes"
  echo "  reset-up: Reset containers and volumes, then start them up again"
  echo "  logs    : Follow logs for all services"
  echo "  ps      : List running containers"
  echo ""
  echo "Environment Variables:"
  echo "  CONTAINER_RUNTIME : Force runtime (podman|docker), otherwise auto-detect"
  echo "  COMPOSE_FILE      : Override compose file path"
  exit 1
}

# Detect container runtime and compose command
detect_runtime() {
  if [ -n "$CONTAINER_RUNTIME" ]; then
    RUNTIME="$CONTAINER_RUNTIME"
  elif command -v podman &> /dev/null; then
    RUNTIME="podman"
  elif command -v docker &> /dev/null; then
    RUNTIME="docker"
  else
    echo "Error: Neither podman nor docker found. Please install a container runtime."
    exit 1
  fi

  case "$RUNTIME" in
    podman)
      if command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
      elif podman compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="podman compose"
      else
        echo "Error: podman-compose not found. Install it with:"
        echo "  pip3 install podman-compose"
        echo "  OR"
        echo "  paru -S podman-compose"
        exit 1
      fi
      ;;
    docker)
      if docker compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
      elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
      else
        echo "Error: Neither 'docker compose' nor 'docker-compose' found."
        exit 1
      fi
      ;;
    *)
      echo "Error: Unknown runtime '$RUNTIME'. Use 'podman' or 'docker'."
      exit 1
      ;;
  esac

  echo "Using runtime: $RUNTIME with command: $COMPOSE_CMD"
}

# Set up paths and environment
setup_environment() {
  # Navigate to project root (3 levels up from this script)
  SCRIPT_DIR="$(dirname "$0")"
  PROJECT_ROOT="$(realpath "$SCRIPT_DIR/../../..")"
  cd "$PROJECT_ROOT" || exit 1

  # Set compose file path
  if [ -z "$COMPOSE_FILE" ]; then
    COMPOSE_FILE="infrastructure/containers/compose/podman-compose.yml"
  fi

  # Ensure compose file exists
  if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Error: Compose file not found at $COMPOSE_FILE"
    exit 1
  fi

  # Load environment variables if .env exists
  ENV_FILE="infrastructure/containers/compose/.env"
  if [ -f "$ENV_FILE" ]; then
    echo "Loading environment from $ENV_FILE"
    set -a  # Export all variables
    source "$ENV_FILE"
    set +a  # Stop exporting
  elif [ -f "infrastructure/containers/compose/.env.development" ]; then
    echo "Loading development environment"
    set -a
    source "infrastructure/containers/compose/.env.development"
    set +a
  fi

  # Set database URL for migrations
  DATABASE_URL="postgres://${DB_USER:-devuser}:${DB_PASSWORD:-devpassword}@localhost:${DB_PORT:-5432}/${DB_NAME:-sanguine_scribe_dev}"
}

# Run database migrations
run_migrations() {
  echo "Running database migrations..."
  if command -v diesel &> /dev/null; then
    (cd "$PROJECT_ROOT/backend" && DATABASE_URL="$DATABASE_URL" diesel migration run)
    MIGRATION_STATUS=$?
  else 
    echo "Warning: 'diesel' command not found. Skipping migrations."
    echo "Install diesel-cli: cargo install diesel_cli --no-default-features --features postgres"
    MIGRATION_STATUS=0
  fi

  if [ $MIGRATION_STATUS -ne 0 ]; then
    echo "Database migrations failed!"
    return $MIGRATION_STATUS
  fi
}

# Wait for database to be ready
wait_for_db() {
  echo "Waiting for database to initialize..."
  max_attempts=30
  attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    if command -v pg_isready &> /dev/null; then
      if pg_isready -h localhost -p "${DB_PORT:-5432}" -U "${DB_USER:-devuser}" &> /dev/null; then
        echo "Database is ready!"
        return 0
      fi
    else
      # Fallback: simple sleep
      sleep 2
      return 0
    fi
    
    echo "Attempt $attempt/$max_attempts: Database not ready yet..."
    sleep 2
    ((attempt++))
  done
  
  echo "Warning: Database may not be ready after $max_attempts attempts"
  return 1
}

# Main execution
detect_runtime
setup_environment

case "$COMMAND" in
  up)
    echo "Starting services in detached mode..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" up -d
    UP_STATUS=$?
    if [ $UP_STATUS -ne 0 ]; then
        echo "Container startup failed!"
        exit $UP_STATUS
    fi

    wait_for_db
    run_migrations
    ;;
  down)
    echo "Stopping services..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" down
    ;;
  reset)
    echo "Stopping services and removing volumes (clearing data)..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" down -v
    ;;
  reset-up)
    echo "Stopping services and removing volumes (clearing data)..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" down -v
    
    echo "Starting services in detached mode..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" up -d
    UP_STATUS=$?
    if [ $UP_STATUS -ne 0 ]; then
        echo "Container startup failed!"
        exit $UP_STATUS
    fi

    wait_for_db
    run_migrations
    ;;
  logs)
    echo "Following logs (Ctrl+C to stop)..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" logs -f
    ;;
  ps)
    echo "Listing container status..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" ps
    ;;
  *)
    usage
    ;;
esac

echo "Done."
exit 0