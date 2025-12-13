#!/bin/bash
# Deploy script for Security Scanner
# Stops containers, pulls latest code, rebuilds and restarts

set -e  # Exit on error

echo "=== Security Scanner Deploy ==="
echo ""

# Get script directory (works even if called from elsewhere)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Use docker compose (v2) or docker-compose (v1)
if command -v docker-compose &> /dev/null; then
    COMPOSE="docker-compose"
else
    COMPOSE="docker compose"
fi

echo "[1/4] Stopping containers..."
$COMPOSE down

echo ""
echo "[2/4] Pulling latest from git..."
git pull

echo ""
echo "[3/4] Rebuilding image..."
$COMPOSE build --no-cache

echo ""
echo "[4/4] Starting containers..."
$COMPOSE up -d

echo ""
echo "=== Deploy complete ==="
echo ""
echo "View logs: $COMPOSE logs -f"
echo "Dashboard: http://localhost:8080"
