#!/usr/bin/env bash
# ============================================================
#  OSINT Investigation Bot — Deploy Helper Script
# ============================================================
# Helps deploy to various platforms.
#
# Usage: bash scripts/deploy.sh [platform]
# Platforms: render, railway, fly, heroku, docker, vps
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

PLATFORM=${1:-""}

echo "=========================================="
echo "  OSINT Bot — Deployment Helper"
echo "=========================================="
echo ""

show_help() {
    echo "Usage: bash scripts/deploy.sh [platform]"
    echo ""
    echo "Platforms:"
    echo "  render   — Deploy to Render.com"
    echo "  railway  — Deploy to Railway.app"
    echo "  fly      — Deploy to Fly.io"
    echo "  heroku   — Deploy to Heroku"
    echo "  docker   — Deploy with Docker Compose"
    echo "  vps      — Deploy to a VPS (systemd)"
    echo ""
    echo "Pre-deployment checks:"
    echo "  preflight — Run deployment checks"
    echo ""
    echo "Examples:"
    echo "  bash scripts/deploy.sh preflight"
    echo "  bash scripts/deploy.sh docker"
}

preflight_check() {
    echo -e "${BLUE}Running preflight checks...${NC}"
    echo ""

    local errors=0

    # Check .env
    echo -n "  .env file... "
    if [ -f ".env" ]; then
        if grep -q "YOUR_BOT_TOKEN_HERE" .env 2>/dev/null; then
            echo -e "${RED}Missing TELEGRAM_TOKEN${NC}"
            errors=$((errors + 1))
        else
            echo -e "${GREEN}OK${NC}"
        fi
    else
        echo -e "${RED}Not found${NC}"
        errors=$((errors + 1))
    fi

    # Check .gitignore
    echo -n "  .gitignore... "
    if grep -q ".env" .gitignore 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}.env not in .gitignore!${NC}"
        errors=$((errors + 1))
    fi

    # Check requirements.txt
    echo -n "  requirements.txt... "
    if [ -f "requirements.txt" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}Missing${NC}"
        errors=$((errors + 1))
    fi

    # Check Dockerfile
    echo -n "  Dockerfile... "
    if [ -f "Dockerfile" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Missing (needed for Docker/Railway/Fly)${NC}"
    fi

    # Check git
    echo -n "  Git repo... "
    if git rev-parse --git-dir > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Not a git repo${NC}"
    fi

    # Check for committed secrets
    echo -n "  No secrets in git... "
    if git log --all --full-history -- "*.env" 2>/dev/null | grep -q "TELEGRAM_TOKEN"; then
        echo -e "${RED}SECRETS FOUND IN GIT HISTORY!${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}OK${NC}"
    fi

    echo ""
    if [ $errors -eq 0 ]; then
        echo -e "${GREEN}All checks passed! Ready to deploy.${NC}"
    else
        echo -e "${RED}$errors issue(s) found. Fix before deploying.${NC}"
    fi

    return $errors
}

deploy_docker() {
    echo -e "${BLUE}Deploying with Docker Compose...${NC}"
    if [ ! -f ".env" ]; then
        echo -e "${RED}Create .env file first!${NC}"
        exit 1
    fi
    docker compose up -d --build
    echo -e "${GREEN}Deployed! Logs: docker compose logs -f${NC}"
}

deploy_render() {
    echo -e "${BLUE}Deploying to Render...${NC}"
    echo ""
    echo "Steps:"
    echo "  1. Go to https://dashboard.render.com"
    echo "  2. Click 'New' > 'Web Service'"
    echo "  3. Connect your GitHub repo: gamingextra/osint-bot"
    echo "  4. Build: pip install -r requirements.txt"
    echo "  5. Start: python main.py"
    echo "  6. Set env vars from your .env file"
    echo ""
    echo -e "${YELLOW}A render.yaml Blueprint is included for auto-discovery.${NC}"
    echo "Docs: See deployment.md Part 4"
}

deploy_railway() {
    echo -e "${BLUE}Deploying to Railway...${NC}"
    echo ""
    echo "Steps:"
    echo "  1. Go to https://railway.app"
    echo "  2. New Project > Deploy from GitHub repo"
    echo "  3. Select: gamingextra/osint-bot"
    echo "  4. Add env vars in the Variables tab"
    echo "  5. Set Start Command: python main.py"
    echo ""
    echo "Docs: See deployment.md Part 5"
}

deploy_fly() {
    echo -e "${BLUE}Deploying to Fly.io...${NC}"

    if ! command -v flyctl &> /dev/null; then
        echo -e "${RED}flyctl not found! Install: curl -L https://fly.io/install.sh | sh${NC}"
        exit 1
    fi

    echo "Running: flyctl deploy"
    flyctl deploy
    echo -e "${GREEN}Deployed! Logs: flyctl logs${NC}"
}

deploy_heroku() {
    echo -e "${BLUE}Deploying to Heroku...${NC}"

    if ! command -v heroku &> /dev/null; then
        echo -e "${RED}heroku CLI not found! Install: https://devcenter.heroku.com/articles/heroku-cli${NC}"
        exit 1
    fi

    echo "Pushing to Heroku..."
    git push heroku main 2>/dev/null || {
        echo "Adding Heroku remote..."
        heroku create
        git push heroku main
    }
    heroku ps:scale worker=1
    echo -e "${GREEN}Deployed! Logs: heroku logs --tail${NC}"
}

deploy_vps() {
    echo -e "${BLUE}VPS Deployment Guide...${NC}"
    echo ""
    echo "Quick setup:"
    echo ""
    echo "  # On your VPS:"
    echo "  git clone https://github.com/gamingextra/osint-bot.git"
    echo "  cd osint-bot"
    echo "  bash scripts/setup.sh"
    echo "  cp .env.example .env  # Edit with your tokens"
    echo ""
    echo "  # Set up systemd service:"
    echo "  sudo cp osint-bot.service /etc/systemd/system/"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable osint-bot"
    echo "  sudo systemctl start osint-bot"
    echo ""
    echo "Docs: See deployment.md Part 9"
}

# ─── Main ─────────────────────────────────────────
case "$PLATFORM" in
    "")
        show_help
        ;;
    preflight)
        preflight_check
        ;;
    docker)
        preflight_check && deploy_docker
        ;;
    render)
        deploy_render
        ;;
    railway)
        deploy_railway
        ;;
    fly)
        preflight_check && deploy_fly
        ;;
    heroku)
        preflight_check && deploy_heroku
        ;;
    vps)
        deploy_vps
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown platform: $PLATFORM${NC}"
        show_help
        exit 1
        ;;
esac
