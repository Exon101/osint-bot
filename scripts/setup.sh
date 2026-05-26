#!/usr/bin/env bash
# ============================================================
#  OSINT Investigation Bot — Automated Setup Script
# ============================================================
# Run this script to set up the project from a fresh clone.
#
# Usage: bash scripts/setup.sh
# ============================================================

set -e

echo "=========================================="
echo "  OSINT Bot Setup Script"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ─── 1. Check Python version ─────────────────────
echo -n "Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; }; then
    echo -e "${RED}Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}$PYTHON_VERSION ✓${NC}"

# ─── 2. Create virtual environment ────────────────
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists. Skipping creation.${NC}"
else
    echo -n "Creating virtual environment... "
    python3 -m venv venv
    echo -e "${GREEN}✓${NC}"
fi

# ─── 3. Activate venv ────────────────────────────
echo -n "Activating virtual environment... "
source venv/bin/activate
echo -e "${GREEN}✓${NC}"

# ─── 4. Upgrade pip ──────────────────────────────
echo -n "Upgrading pip... "
pip install --upgrade pip -q
echo -e "${GREEN}✓${NC}"

# ─── 5. Install dependencies ─────────────────────
echo -n "Installing Python dependencies... "
pip install -r requirements.txt -q
echo -e "${GREEN}✓${NC}"

# ─── 6. Create .env from example ─────────────────
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}.env created from .env.example — add your tokens!${NC}"
    else
        touch .env
        echo -e "${YELLOW}.env file created — add your tokens!${NC}"
    fi
else
    echo -e "${YELLOW}.env already exists. Skipping.${NC}"
fi

# ─── 7. Create directories ────────────────────────
mkdir -p logs backups docs
echo -e "${GREEN}Directories created ✓${NC}"

# ─── 8. Check for bot token ──────────────────────
if grep -q "YOUR_BOT_TOKEN_HERE" .env 2>/dev/null; then
    echo ""
    echo -e "${RED}⚠️  TELEGRAM_TOKEN not set!${NC}"
    echo "   1. Go to https://t.me/BotFather"
    echo "   2. Create a bot and copy the token"
    echo "   3. Edit .env and replace YOUR_BOT_TOKEN_HERE"
    echo ""
fi

# ─── 9. Run basic health check ───────────────────
echo ""
echo -n "Running health check... "
python -c "
from config import config
from database import init_database
import sys

# Test imports
try:
    from handlers import start, ip_lookup, domain
    from handlers import username, hash_lookup, email
    from handlers import password_gen, code_runner, hash_tool
    from handlers import subdomain_enum, dns_recon, port_scan
    print('✓')
except ImportError as e:
    print(f'Import error: {e}')
    sys.exit(1)

# Init database
init_database()
print('Database initialized ✓')
"

echo ""
echo "=========================================="
echo -e "${GREEN}  Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your TELEGRAM_TOKEN"
echo "  2. (Optional) Add API keys for enhanced features"
echo "  3. Run the bot: python main.py"
echo ""
echo "Or use Make commands:"
echo "  make run      — Start the bot"
echo "  make dev      — Development mode"
echo "  make test     — Run tests"
echo "  make help     — See all commands"
