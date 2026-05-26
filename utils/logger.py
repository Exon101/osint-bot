"""
Audit Logging System
"""

import logging
import json
import sys
from pathlib import Path
from datetime import datetime


LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)


def setup_logger(name: str = "osint_bot") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(LOG_DIR / "osint_bot.log")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


logger = logging.getLogger("osint_bot")


def log_query(user_id: int, command: str, query: str = "", result: str = "success") -> None:
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "uid": user_id,
        "cmd": command,
        "q": query,
        "res": result,
    }
    logger.info(json.dumps(entry))
