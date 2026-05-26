.PHONY: help install run dev test lint clean docker-build docker-up docker-down docker-logs backup logs status

# Default target
help: ## Show this help message
	@echo "OSINT Investigation Bot — Available Commands"
	@echo "============================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ─── Installation ────────────────────────────────

install: ## Create venv and install dependencies
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "✅ Installation complete. Activate with: source venv/bin/activate"

# ─── Running ─────────────────────────────────────

run: ## Run the bot (production mode)
	python main.py

dev: ## Run the bot in development mode with debug output
	PYTHONUNBUFFERED=1 python -u main.py

# ─── Testing ─────────────────────────────────────

test: ## Run all tests
	./venv/bin/python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	./venv/bin/python -m pytest tests/ -v --cov=. --cov-report=html --cov-report=term

# ─── Code Quality ────────────────────────────────

lint: ## Run code style checks
	./venv/bin/python -m flake8 handlers/ utils/ api_clients/ --max-line-length=100 --exclude=__pycache__

format: ## Auto-format code with black
	./venv/bin/python -m black handlers/ utils/ api_clients/ *.py --line-length=100

# ─── Docker ──────────────────────────────────────

docker-build: ## Build Docker image
	docker build -t osint-bot .

docker-up: ## Start with docker-compose
	docker compose up -d --build

docker-down: ## Stop docker-compose
	docker compose down

docker-logs: ## View Docker logs
	docker compose logs -f --tail=100

docker-restart: ## Restart Docker containers
	docker compose restart

# ─── Database ────────────────────────────────────

backup: ## Backup the database
	@mkdir -p backups
	cp osint_bot.db backups/osint_bot_$(shell date +%Y%m%d_%H%M%S).db
	@echo "✅ Database backed up to backups/"

clean-db: ## Delete database and logs (fresh start)
	rm -f osint_bot.db
	rm -rf logs/*.log
	@echo "✅ Database and logs cleared. Run 'make run' to recreate."

# ─── Logs ────────────────────────────────────────

logs: ## View recent logs
	tail -f logs/osint_bot.log 2>/dev/null || echo "No log file found. Run the bot first."

# ─── Clean ───────────────────────────────────────

clean: ## Remove venv, __pycache__, .pyc files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf venv/ .pytest_cache/ htmlcov/ .coverage
	@echo "✅ Cleaned"

# ─── Git ─────────────────────────────────────────

push: ## Commit, push to GitHub, and deploy
	git add -A
	git diff --cached --quiet || git commit -m "Update $(shell date +%Y-%m-%d)"
	git push origin main
	@echo "✅ Pushed to GitHub"

# ─── Status ──────────────────────────────────────

status: ## Show project status (files, tests, git)
	@echo "📦 Project Files:"
	@find . -name "*.py" -not -path "./venv/*" -not -path "./__pycache__/*" | wc -l | xargs echo "   Python files:"
	@find . -name "*.py" -not -path "./venv/*" -not -path "./__pycache__/*" -exec cat {} + | wc -l | xargs echo "   Total lines:"
	@echo ""
	@echo "📊 Git Status:"
	@git status --short 2>/dev/null | head -5 || echo "   Not a git repo"
	@echo ""
	@echo "🗄️  Database:"
	@ls -lh osint_bot.db 2>/dev/null || echo "   No database yet"
	@echo ""
	@echo "📝 Recent Logs:"
	@tail -3 logs/osint_bot.log 2>/dev/null || echo "   No logs yet"
