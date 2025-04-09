#!/bin/bash

# Simple utility script for managing development Docker Compose services

COMMAND=$1

# Function to print usage
usage() {
  echo "Usage: $0 {up|down|reset|logs|ps}"
  echo "  up    : Start containers in detached mode (docker compose up -d)"
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
# to ensure docker-compose.yml is found
cd "$(dirname "$0")/.." || exit

case "$COMMAND" in
  up)
    echo "Starting services in detached mode..."
    $DC_CMD up -d
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