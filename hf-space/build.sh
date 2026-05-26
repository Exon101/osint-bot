#!/bin/bash
# ─────────────────────────────────────────────
# HF Spaces Deployment Packager
# Bundles only the files needed for HF Spaces
# ─────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR/.."
HF_DIR="$SCRIPT_DIR"

echo "=== HF Spaces Deployment Packager ==="
echo ""

# Clean previous build
rm -rf "$HF_DIR/build"
mkdir -p "$HF_DIR/build"

echo "[1/5] Copying Dockerfile & README..."
cp "$HF_DIR/Dockerfile" "$HF_DIR/build/"
cp "$HF_DIR/README.md" "$HF_DIR/build/"

echo "[2/5] Copying requirements.txt..."
cp "$REPO_DIR/requirements.txt" "$HF_DIR/build/"

echo "[3/5] Copying Python source code..."
cp "$REPO_DIR/config.py" "$HF_DIR/build/"
cp "$REPO_DIR/database.py" "$HF_DIR/build/"
cp "$REPO_DIR/main.py" "$HF_DIR/build/"
cp "$REPO_DIR/webhook_server.py" "$HF_DIR/build/"

# Copy all handlers
mkdir -p "$HF_DIR/build/handlers"
cp "$REPO_DIR/handlers/"*.py "$HF_DIR/build/handlers/"

# Copy all API clients
mkdir -p "$HF_DIR/build/api_clients"
cp "$REPO_DIR/api_clients/"*.py "$HF_DIR/build/api_clients/"

# Copy all utils
mkdir -p "$HF_DIR/build/utils"
cp "$REPO_DIR/utils/"*.py "$HF_DIR/build/utils/"

# Copy templates if any
if [ -d "$REPO_DIR/templates" ]; then
    cp -r "$REPO_DIR/templates" "$HF_DIR/build/"
fi

# Copy scripts if any
if [ -d "$REPO_DIR/scripts" ]; then
    cp -r "$REPO_DIR/scripts" "$HF_DIR/build/"
fi

echo "[4/5] Creating .dockerignore..."
cat > "$HF_DIR/build/.dockerignore" << 'EOF'
__pycache__/
*.py[cod]
.env
*.db
*.sqlite3
logs/
*.log
.git/
.github/
docs/
hf-space/
tests/
*.egg-info/
.DS_Store
Dockerfile.hf
README_SPACE.md
huggingface_deployment.md
deployment.md
docker-compose.yml
fly.toml
heroku.yml
render.yaml
osint-bot.service
Makefile
Procfile
runtime.txt
CHANGELOG.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
SECURITY.md
LICENSE
EOF

echo "[5/5] Creating .gitignore..."
cat > "$HF_DIR/build/.gitignore" << 'EOF'
__pycache__/
*.py[cod]
.env
*.db
*.sqlite3
logs/
*.log
.DS_Store
EOF

echo ""
echo "=== Build complete! ==="
echo ""
echo "Files in $HF_DIR/build/:"
ls -la "$HF_DIR/build/"
echo ""
echo "Total size:"
du -sh "$HF_DIR/build/"
echo ""
echo "Next steps:"
echo "  1. Go to: https://huggingface.co/new-space"
echo "  2. Create a Docker Space named 'osint-bot'"
echo "  3. Upload everything from: $HF_DIR/build/"
echo "  4. Add TELEGRAM_TOKEN as a secret"
echo "  5. Wait for build to complete (~2 min)"
