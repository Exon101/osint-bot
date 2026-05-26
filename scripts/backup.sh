#!/usr/bin/env bash
# ============================================================
#  OSINT Investigation Bot — Database Backup Script
# ============================================================
# Backs up the SQLite database with timestamp.
#
# Usage: bash scripts/backup.sh [--max N]
# ============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="$PROJECT_DIR/backups"
MAX_BACKUPS=${1:-10}

if [[ "$1" == "--max" ]]; then
    MAX_BACKUPS=$2
fi

mkdir -p "$BACKUP_DIR"

DB_FILE="$PROJECT_DIR/osint_bot.db"

if [ ! -f "$DB_FILE" ]; then
    echo "No database found at $DB_FILE"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/osint_bot_${TIMESTAMP}.db"

# Use SQLite's backup API if possible, otherwise copy
cp "$DB_FILE" "$BACKUP_FILE"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

echo "Backup created: $BACKUP_FILE ($SIZE)"

# Remove old backups, keep the most recent N
cd "$BACKUP_DIR"
ls -t osint_bot_*.db 2>/dev/null | tail -n +$((MAX_BACKUPS + 1)) | xargs -r rm --

REMAINING=$(ls osint_bot_*.db 2>/dev/null | wc -l)
echo "Backups kept: $REMAINING (max: $MAX_BACKUPS)"
