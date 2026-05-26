# Contributing to OSINT Investigation Bot

Thank you for your interest in contributing! This guide will help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Feature](#adding-a-new-feature)
- [Adding a New Handler Module](#adding-a-new-handler-module)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Be respectful, constructive, and inclusive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create** a feature branch
4. **Make** your changes
5. **Test** thoroughly
6. **Submit** a Pull Request

## Development Setup

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/osint-bot.git
cd osint-bot

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install dev dependencies (optional)
pip install pytest pytest-cov black flake8

# 5. Set up environment variables
cp .env.example .env
# Edit .env with your bot token

# 6. Run the bot
python main.py
```

## Project Structure

```
osint-bot/
├── main.py              # Entry point, handler registration
├── config.py            # All configuration and API keys
├── database.py          # SQLite database operations
├── handlers/            # Command handler modules
│   ├── start.py         # Core commands (start, help, stats)
│   ├── ip_lookup.py     # Example handler with API integration
│   └── ...              # All other handler modules
├── utils/               # Shared utilities
│   ├── validators.py    # Input validation
│   ├── rate_limiter.py  # Rate limiting
│   ├── logger.py        # Logging
│   └── formatters.py    # Telegram HTML formatting
├── api_clients/         # External API wrappers
│   └── ...              # One file per API service
└── tests/               # Unit tests
```

## Adding a New Feature

Follow these steps to add a new investigation feature:

### 1. Create the Handler

Create a new file in `handlers/` following this template:

```python
"""
Module Name Handler
Brief description of what this module does.
"""

import logging
from telegram import Update
from telegram.ext import ContextTypes
from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code

async def cmd_yourcommand(update: Update, context: ContextTypes.DEFAULT_TYPE):
    \"\"\"Handle /yourcommand command.\"\"\"
    user_id = update.effective_user.id

    # 1. Check rate limit
    if not check_rate_limit(user_id):
        await update.message.reply_text("Rate limit exceeded.")
        return

    # 2. Validate input
    if not context.args:
        await update.message.reply_text("Usage: /yourcommand <argument>")
        return

    query = sanitize_input(context.args[0])

    # 3. Perform the lookup/action
    try:
        # Your API call or logic here
        result = "Your result"

        # 4. Send response
        await update.message.reply_text(
            f"**Results:**\n{result}"
        )

        # 5. Log and update usage
        increment_usage(user_id)
        log_query(user_id, "yourcommand", query, "success")

    except Exception as e:
        logger.error(f"Command failed: {e}")
        await update.message.reply_text(f"Error: {str(e)[:200]}")
        log_query(user_id, "yourcommand", query, "failure")
```

### 2. Register in main.py

Add to `main.py` in the `register_handlers()` function:

```python
from handlers.your_module import cmd_yourcommand

# In register_handlers():
application.add_handler(CommandHandler("yourcommand", cmd_yourcommand))
```

### 3. Add to Help Text

Update `templates/messages.py` with your command description.

### 4. Write Tests

Add tests in `tests/test_your_module.py`.

## Coding Standards

- **Python 3.10+** — Use type hints where practical
- **Line length** — Maximum 100 characters
- **Docstrings** — All modules and public functions must have docstrings
- **Input validation** — Always use `sanitize_input()` on user-provided text
- **Rate limiting** — Always call `check_rate_limit()` at the start of handlers
- **Error handling** — Catch exceptions and log errors; never expose stack traces to users
- **Logging** — Log all queries for audit trail using `log_query()`
- **No secrets in code** — All API keys must come from environment variables via `config.py`
- **Async** — Use `async/await` for all I/O operations (API calls, file operations)
- **Telegram formatting** — Use `utils/formatters.py` helpers for HTML formatting

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
python -m pytest tests/test_validators.py -v
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new subdomain enumeration module
fix: handle timeout in IP lookup gracefully
docs: update deployment guide for Railway
refactor: simplify rate limiter implementation
test: add unit tests for validators
chore: update requirements.txt versions
```

## Pull Request Process

1. **Update documentation** if you change behavior
2. **Add tests** for new features
3. **Run `make test`** and ensure all tests pass
4. **Run `make lint`** and fix any style issues
5. **Keep PRs focused** — one feature or fix per PR
6. **Write a clear PR description** explaining what and why

## Questions?

Open a [GitHub Discussion](https://github.com/gamingextra/osint-bot/discussions) for questions or ideas.
