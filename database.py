"""
Database Module
SQLite operations for the OSINT Bot.
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

DB_PATH = Path("osint_bot.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_database() -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        first_name TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_queries INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS query_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        command TEXT NOT NULL,
        query TEXT,
        result TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tracked_repos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        repo_full_name TEXT NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, repo_full_name)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS rate_limits (
        user_id INTEGER PRIMARY KEY,
        request_count INTEGER DEFAULT 0,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_query_log_user ON query_log(user_id)
    """)
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp)
    """)

    # ── Proxies Table ────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS proxies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        proxy_type TEXT DEFAULT 'http',
        label TEXT DEFAULT '',
        enabled INTEGER DEFAULT 1,
        success_count INTEGER DEFAULT 0,
        fail_count INTEGER DEFAULT 0,
        avg_response_time REAL DEFAULT 0.0,
        last_tested TIMESTAMP,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_proxies_user ON proxies(user_id)
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def get_user(user_id: int) -> Optional[Dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(user_id: int, username: str = None, first_name: str = None) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO users (id, username, first_name) VALUES (?, ?, ?)",
        (user_id, username, first_name),
    )
    conn.commit()
    conn.close()


def increment_usage(user_id: int) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET total_queries = total_queries + 1, "
        "last_active = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


def log_query(user_id: int, command: str, query: str = "", result: str = "success") -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO query_log (user_id, command, query, result) VALUES (?, ?, ?, ?)",
        (user_id, command, query, result),
    )
    conn.commit()
    conn.close()


def get_user_stats(user_id: int) -> Dict[str, Any]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT total_queries, last_active FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "SELECT command, COUNT(*) as cnt FROM query_log "
            "WHERE user_id = ? GROUP BY command ORDER BY cnt DESC LIMIT 5",
            (user_id,),
        )
        top_commands = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {
            "total_queries": row["total_queries"],
            "last_active": row["last_active"],
            "top_commands": top_commands,
        }
    conn.close()
    return {}


def get_global_stats() -> Dict[str, Any]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM users")
    total_users = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM query_log")
    total_queries = cur.fetchone()["total"]
    cur.execute(
        "SELECT command, COUNT(*) as cnt FROM query_log "
        "GROUP BY command ORDER BY cnt DESC LIMIT 10"
    )
    top_commands = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "total_users": total_users,
        "total_queries": total_queries,
        "top_commands": top_commands,
    }


def add_tracked_repo(user_id: int, repo_full_name: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO tracked_repos (user_id, repo_full_name) VALUES (?, ?)",
        (user_id, repo_full_name),
    )
    conn.commit()
    conn.close()


def get_tracked_repos(user_id: int) -> List[str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT repo_full_name FROM tracked_repos WHERE user_id = ?", (user_id,)
    )
    rows = [r["repo_full_name"] for r in cur.fetchall()]
    conn.close()
    return rows


def remove_tracked_repo(user_id: int, repo_full_name: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM tracked_repos WHERE user_id = ? AND repo_full_name = ?",
        (user_id, repo_full_name),
    )
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected > 0
