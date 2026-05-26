#!/usr/bin/env bash
# ============================================================
#  OSINT Investigation Bot — Start Script
# ============================================================
# Run this to start the bot with proper environment setup.
#
# Usage: bash scripts/start.sh [--dev] [--docker]
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

MODE="production"

# Parse arguments
for arg in "$@"; do
    case $arg in
        --dev)
            MODE="development"
            ;;
        --docker)
            MODE="docker"
            ;;
    esac
done

echo "=========================================="
echo "  OSINT Bot — Starting ($MODE mode)"
echo "=========================================="

case $MODE in
    docker)
        if ! command -v docker &> /dev/null; then
            echo -e "${RED}Docker is not installed!${NC}"
            exit 1
        fi

        if [ ! -f ".env" ]; then
            echo -e "${RED}.env file not found! Copy .env.example to .env first.${NC}"
            exit 1
        fi

        echo "Starting with Docker Compose..."
        docker compose up -d --build
        echo ""
        echo -e "${GREEN}Bot is running in Docker!${NC}"
        echo "View logs: docker compose logs -f"
        echo "Stop:      docker compose down"
        ;;

    development)
        if [ ! -d "venv" ]; then
            echo -e "${YELLOW}Virtual environment not found. Run: bash scripts/setup.sh${NC}"
            exit 1
        fi

        source venv/bin/activate
        export PYTHONUNBUFFERED=1
        export PYTHONFAULTHANDLER=1

        echo -e "${YELLOW}Development mode — verbose output enabled${NC}"
        echo ""
        python -u main.py
        ;;

    production)
        if [ ! -d "venv" ]; then
            echo -e "${YELLOW}Virtual environment not found. Run: bash scripts/setup.sh${NC}"
            exit 1
        fi

        source venv/bin/activate
        export PYTHONUNBUFFERED=1

        python main.py
        ;;
esac
