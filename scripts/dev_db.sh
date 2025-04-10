#!/bin/bash

# Simple utility script for managing development Docker Compose services

COMMAND=$1

# Function to print usage
usage() {
  echo "Usage: $0 {up|down|reset|logs|ps}"
  echo "  up    : Start containers in detached mode and run initial DB migrations (docker compose up -d && diesel migration run)"
  echo "  down  : Stop containers (docker compose down)"
  echo "  reset : Stop containers and remove volumes (docker compose down -v)"
  echo "  logs  : Follow logs for all services (docker compose logs -f)"
  echo "  ps    : List running containers (docker compose ps)"
  exit 1
}

# Check if docker compose or docker-compose exists
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
  DC_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
  DC_CMD="docker-compose"
else
  echo "Error: Neither 'docker compose' nor 'docker-compose' found. Please install Docker Compose."
  exit 1
fi

# Change to the project root directory (one level up from scripts) 
# to ensure docker-compose.yml and backend dir are found
PROJECT_ROOT="$(dirname "$0")/.."
cd "$PROJECT_ROOT" || exit

# Define Database URL based on docker-compose.yml
# IMPORTANT: Keep this consistent with docker-compose.yml and backend/.env if used
DATABASE_URL="postgres://devuser:devpassword@localhost:5432/sanguine_scribe_dev"

case "$COMMAND" in
  up)
    echo "Starting services in detached mode..."
    $DC_CMD up -d
    UP_STATUS=$?
    if [ $UP_STATUS -ne 0 ]; then
        echo "Docker compose up failed!"
        exit $UP_STATUS
    fi

    # Wait a few seconds for DB to be ready (simple approach)
    # A more robust solution would check DB readiness explicitly
    echo "Waiting for database to initialize..."
    sleep 5

    echo "Running database migrations..."
    # Ensure we run diesel from the backend directory
    if command -v diesel &> /dev/null; then
        (cd "$PROJECT_ROOT/backend" && DATABASE_URL=$DATABASE_URL diesel migration run) 
        MIGRATION_STATUS=$?
    else 
        echo "Warning: 'diesel' command not found. Skipping migrations."
        echo "Ensure diesel-cli is installed and in your PATH (e.g., via .idx/dev.nix or cargo install)."
        MIGRATION_STATUS=0 # Avoid hard failure if diesel isn't there yet
    fi

    if [ $MIGRATION_STATUS -ne 0 ]; then
        echo "Database migrations failed!"
        # Optionally stop containers if migrations fail: $DC_CMD down
        exit $MIGRATION_STATUS
    fi
    ;;
  down)
    echo "Stopping services..."
    $DC_CMD down
    ;;
  reset)
    echo "Stopping services and removing volumes (clearing data)..."
    $DC_CMD down -v
    ;;
  logs)
    echo "Following logs (Ctrl+C to stop)..."
    $DC_CMD logs -f
    ;;
  ps)
    echo "Listing container status..."
    $DC_CMD ps
    ;;
  *)
    usage
    ;;
esac

echo "Done."
exit 0
