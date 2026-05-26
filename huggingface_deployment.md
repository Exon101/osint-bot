# 🤗 Hugging Face Spaces — Deployment Guide

> Deploy your OSINT Investigation Bot to Hugging Face Spaces for free using the Docker SDK.
> HF Spaces provides persistent storage, automatic restarts, and a generous free tier perfect for Telegram bots.

---

## 📑 Table of Contents

- [Why Hugging Face Spaces?](#-why-hugging-face-spaces)
- [Prerequisites](#-prerequisites)
- [Deployment Methods](#-deployment-methods)
  - [Method 1: Direct Upload (Recommended)](#-method-1-direct-upload-recommended)
  - [Method 2: Git Clone & Push](#-method-2-git-clone--push)
  - [Method 3: GitHub Repository Mirror](#-method-3-github-repository-mirror)
- [Configuring Environment Secrets](#-configuring-environment-secrets)
- [Persistent Storage](#-persistent-storage)
- [Monitoring & Logs](#-monitoring--logs)
- [Custom Domain (Optional)](#-custom-domain-optional)
- [Updating the Bot](#-updating-the-bot)
- [Troubleshooting](#-troubleshooting)
- [Free Tier Limitations](#-free-tier-limitations)
- [Comparison with Other Platforms](#-comparison-with-other-platforms)

---

## 🤔 Why Hugging Face Spaces?

Hugging Face Spaces is an excellent choice for hosting a Telegram bot for several reasons:

| Feature | Details |
|---------|---------|
| **Free Tier** | 2 CPU basic Spaces, each with 16GB RAM and 50GB persistent storage |
| **Persistent Storage** | SQLite database survives restarts and redeployments |
| **Auto Restart** | Automatically restarts if the container crashes |
| **Docker Support** | Full Docker SDK support — run any Python application |
| **No Web Server Required** | Telegram bots use long polling (outbound only), so no port exposure needed |
| **Secret Management** | Built-in encrypted environment variable storage |
| **Built-in Logging** | Real-time container logs via the HF web UI |
| **GitHub Integration** | Auto-deploy from GitHub on every push |
| **Community Visibility** | Share your bot with the HF community |

> **Note:** Since this bot uses Telegram long polling (outbound connections only), it does NOT need a publicly accessible URL. HF Spaces defaults to port 7860 for web apps, but our bot ignores this entirely and communicates directly with Telegram servers.

---

## ✅ Prerequisites

Before deploying, make sure you have:

1. **Hugging Face Account** — Sign up for free at [https://huggingface.co/join](https://huggingface.co/join)
2. **Telegram Bot Token** — From [@BotFather](https://t.me/botfather) (see `deployment.md` Part 1)
3. **Optional API Keys** — For enhanced features (see `deployment.md` Part 2)

---

## 📦 Deployment Methods

### 🚀 Method 1: Direct Upload (Recommended)

This is the simplest approach — upload your project files directly from the Hugging Face web interface.

#### Step 1: Create a New Space

1. Go to [https://huggingface.co/new-space](https://huggingface.co/new-space)
2. Fill in the form:
   - **Owner:** Your Hugging Face username
   - **Space name:** `osint-bot` (or any name you prefer)
   - **License:** MIT (or your preferred license)
   - **Select the Space SDK:** Choose **Docker**
   - **Space hardware:** Select **CPU basic** (free — 2 vCPU, 16GB RAM)
   - **Visibility:** Public or Private (your choice)
3. Click **Create Space**

#### Step 2: Upload Required Files

After the Space is created, you'll see an empty repository. Upload the following files from your local `osint-bot` project:

**Required files to upload:**

| File | Purpose |
|------|---------|
| `Dockerfile` | Container build instructions (use the HF-optimized version below) |
| `README.md` | Space description (use the HF template below) |
| `main.py` | Bot entry point |
| `config.py` | Configuration module |
| `database.py` | SQLite database operations |
| `requirements.txt` | Python dependencies |
| `handlers/` | Entire `handlers/` directory (all 31 modules) |
| `api_clients/` | Entire `api_clients/` directory (all 8 modules) |
| `utils/` | Entire `utils/` directory (all 6 modules) |
| `templates/` | Entire `templates/` directory |

**Upload methods:**

1. **Web UI drag-and-drop** — Drag files/folders directly into the HF file browser
2. **Git clone and push** — Clone the Space repo and push files locally (see Method 2)

> **Tip:** The easiest way is to use the Hugging Face CLI or clone the Space repo locally, copy your files in, and push.

#### Step 3: Configure Secrets

1. Go to your Space page on Hugging Face
2. Click the **Settings** tab
3. Scroll down to **Repository secrets**
4. Add the following secrets:

| Secret Name | Value | Required |
|-------------|-------|----------|
| `TELEGRAM_TOKEN` | Your bot token from BotFather | ✅ Yes |
| `IPINFO_API_KEY` | Your IPInfo key | ❌ Optional |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal key | ❌ Optional |
| `SHODAN_API_KEY` | Your Shodan key | ❌ Optional |
| `HUNTER_API_KEY` | Your Hunter.io key | ❌ Optional |
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB key | ❌ Optional |
| `GITHUB_TOKEN` | Your GitHub token | ❌ Optional |
| `GITHUB_GIST_TOKEN` | Your GitHub Gist token | ❌ Optional |
| `HIBP_API_KEY` | Your HIBP key | ❌ Optional |
| `CLEARBIT_API_KEY` | Your ClearBit key | ❌ Optional |
| `NUMVERIFY_API_KEY` | Your NumVerify key | ❌ Optional |
| `PHONEVALIDATION_API_KEY` | Your PhoneValidation key | ❌ Optional |
| `ENABLE_CODE_RUNNER` | `true` or `false` | ❌ Optional |
| `ENABLE_PASSWORD_GEN` | `true` or `false` | ❌ Optional |

5. Click **Save**

> **Important:** Secrets are encrypted and never shown in plaintext after you save them. They are injected as environment variables when your container starts.

#### Step 4: Build and Deploy

1. Go to the **App** tab of your Space
2. Hugging Face will automatically detect the `Dockerfile` and start building
3. Wait for the build to complete (first build takes 2-3 minutes)
4. You should see the build logs in real-time
5. Once built, the container starts and the bot comes online

**Success indicators in the logs:**
```
OSINT Investigation Bot - Starting
Bot is starting up...
Database initialized.
All handlers registered.
Bot is running. Press Ctrl+C to stop.
```

---

### 🔧 Method 2: Git Clone & Push

For more control, clone the Space repository locally and push files.

#### Step 1: Install and Login to HF CLI

```bash
# Install the Hugging Face CLI
pip install huggingface_hub

# Login to your Hugging Face account
huggingface-cli login
# This will prompt you to paste your access token
# Get your token from: https://huggingface.co/settings/tokens
```

#### Step 2: Clone the Space Repository

```bash
# Clone your Space (replace with your username and space name)
git clone https://huggingface.co/spaces/YOUR_USERNAME/osint-bot
cd osint-bot
```

#### Step 3: Copy Project Files

```bash
# Copy all bot files from your local project to the Space repo
# Adjust the source path to where your osint-bot project lives

# Copy all Python files and directories
cp /path/to/your/osint-bot/main.py .
cp /path/to/your/osint-bot/config.py .
cp /path/to/your/osint-bot/database.py .
cp /path/to/your/osint-bot/requirements.txt .

# Copy entire directories
cp -r /path/to/your/osint-bot/handlers/ ./handlers/
cp -r /path/to/your/osint-bot/api_clients/ ./api_clients/
cp -r /path/to/your/osint-bot/utils/ ./utils/
cp -r /path/to/your/osint-bot/templates/ ./templates/

# Copy the HF-specific Dockerfile and README
cp /path/to/your/osint-bot/Dockerfile.hf ./Dockerfile
cp /path/to/your/osint-bot/README_SPACE.md ./README.md
```

#### Step 4: Commit and Push

```bash
# Add all files
git add .

# Commit
git commit -m "Deploy OSINT Investigation Bot"

# Push to Hugging Face
git push
```

The Space will automatically rebuild and deploy after the push.

---

### 🔗 Method 3: GitHub Repository Mirror

If your bot code is on GitHub, you can set up automatic deployment from GitHub to HF Spaces.

#### Step 1: Create the Space

Create a new Space on Hugging Face using the **Docker** SDK (see Method 1, Step 1).

#### Step 2: Enable GitHub Sync

1. Go to your Space's **Settings** tab
2. Scroll down to **Repository**
3. Connect your GitHub account if not already connected
4. Select your `osint-bot` GitHub repository
5. Choose the branch to deploy from (typically `main`)

#### Step 3: Ensure HF-Specific Files Exist

Make sure your GitHub repository contains the HF-optimized `Dockerfile` (see the dedicated Dockerfile section below). You can maintain both the standard Dockerfile and the HF-specific one by naming them differently:

```
osint-bot/
├── Dockerfile              # Standard Docker deployment
├── Dockerfile.hf           # Hugging Face Spaces specific
└── README.md               # Standard GitHub README
```

Then in your HF Space settings, you can specify the build command or use a custom `README.md` in the Space repo that references `Dockerfile.hf`.

#### Step 4: Auto-Deploy

Every push to your GitHub `main` branch will automatically trigger a rebuild on Hugging Face Spaces.

---

## 🔐 Configuring Environment Secrets

Hugging Face Spaces uses **Repository Secrets** for secure environment variable storage. These are different from the `.env` file used in local development.

### Adding Secrets via Web UI

1. Go to your Space page: `https://huggingface.co/spaces/YOUR_USERNAME/osint-bot`
2. Click the **Settings** tab
3. Find the **Repository secrets** section
4. Click **New secret**
5. Enter the **Name** (e.g., `TELEGRAM_TOKEN`) and **Value** (your actual token)
6. Click **Add**

### Adding Secrets via CLI

```bash
# Set a secret using the HF CLI
huggingface-cli repo secrets set TELEGRAM_TOKEN "your_bot_token_here"
huggingface-cli repo secrets set VIRUSTOTAL_API_KEY "your_vt_key_here"
huggingface-cli repo secrets set IPINFO_API_KEY "your_ipinfo_key_here"

# List all secrets (values are hidden)
huggingface-cli repo secrets list
```

### Adding Secrets via Git

You can also manage secrets by creating a `.secrets` file locally (never commit this to Git):

```bash
# Create a secrets file (add to .gitignore!)
cat > .secrets << 'EOF'
TELEGRAM_TOKEN=your_bot_token_here
VIRUSTOTAL_API_KEY=your_vt_key_here
IPINFO_API_KEY=your_ipinfo_key_here
SHODAN_API_KEY=your_shodan_key_here
EOF
```

Then use the HF web UI to manually add each secret.

### How Secrets Become Environment Variables

Hugging Face automatically injects all repository secrets as environment variables into your Docker container at runtime. Your existing `config.py` already reads them with `os.getenv()`, so no code changes are needed:

```python
# config.py already does this — no changes required
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "YOUR_BOT_TOKEN_HERE")
IPINFO_API_KEY: Optional[str] = os.getenv("IPINFO_API_KEY")
```

---

## 💾 Persistent Storage

Hugging Face Spaces provides **persistent storage** that survives container restarts and rebuilds. This is critical for the SQLite database.

### How It Works

- Your Space gets a persistent disk mounted at `/data`
- All files in `/data` are preserved across restarts
- The disk size depends on your plan (50GB on the free tier)

### Configuring the Bot for Persistent Storage

The HF-optimized Dockerfile (below) configures the bot to store its database in `/data`:

```dockerfile
# In the Dockerfile, we set the working directory to /data
# and create a symlink so the database persists
WORKDIR /app
RUN mkdir -p /data && ln -sf /data/osint_bot.db /app/osint_bot.db
```

### Backing Up Your Database

You can download the persistent storage at any time:

1. Go to your Space's **Files** tab
2. Browse to `/data/osint_bot.db`
3. Download the file

Or use the CLI:

```bash
# List files in the Space
huggingface-cli repo files YOUR_USERNAME/osint-bot

# Download specific files
huggingface-cli download YOUR_USERNAME/osint-bot osint_bot.db --repo-type space
```

---

## 📊 Monitoring & Logs

### Viewing Real-Time Logs

1. Go to your Space page
2. Click the **Logs** tab (or click "Logs" in the top-right corner)
3. You'll see real-time container output including:
   - Bot startup messages
   - Handler registrations
   - Database initialization
   - Incoming command processing
   - Any errors or warnings

### Checking Container Status

The Space page shows the current status:
- **Building** — Docker image is being built
- **Running** — Container is up and the bot is operational
- **Error** — Something went wrong (check logs)

### Health Monitoring

The HF-optimized Dockerfile includes a health check. Hugging Face monitors this and will automatically restart the container if it becomes unhealthy.

### Log Levels

By default, the bot logs at `INFO` level. You can adjust this by setting a secret:

| Secret Name | Value | Effect |
|-------------|-------|--------|
| `LOG_LEVEL` | `DEBUG` | Verbose output (all messages) |
| `LOG_LEVEL` | `INFO` | Normal output (default) |
| `LOG_LEVEL` | `WARNING` | Only warnings and errors |
| `LOG_LEVEL` | `ERROR` | Only errors |

---

## 🌐 Custom Domain (Optional)

While not required for a Telegram bot, you can add a custom domain to your Space for professional branding:

1. Go to your Space's **Settings** tab
2. Find the **Custom Domain** section
3. Enter your domain (e.g., `bot.yourdomain.com`)
4. Configure DNS: add a CNAME record pointing to `your-username-osint-bot.hf.space`

---

## 🔄 Updating the Bot

### Method 1: Push Updates (Git)

```bash
# Navigate to your Space repo
cd osint-bot

# Make your changes locally
# ...

# Commit and push
git add .
git commit -m "Update: add new feature"
git push
```

The Space will automatically rebuild and redeploy.

### Method 2: Factory Rebuild

If something goes wrong and you need a clean rebuild:

1. Go to your Space's **Settings** tab
2. Click **Factory rebuild**
3. This will rebuild the Docker image from scratch, clearing any cached layers

### Method 3: Restart the Space

If you just need to restart without rebuilding:

1. Go to your Space page
2. Click the **"..."** menu in the top-right
3. Select **Restart**

---

## 🆘 Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| **Build fails** | Check the build logs for the specific error. Common causes: missing files, syntax errors in Dockerfile, pip install failures |
| **Bot starts but doesn't respond** | Verify `TELEGRAM_TOKEN` is set correctly as a repository secret. Check logs for `TELEGRAM_TOKEN not set!` error |
| **Database errors** | Ensure persistent storage is working. Check if `/data` directory exists. Try a Factory rebuild |
| **OOM (Out of Memory)** | The free tier has 16GB RAM which is more than sufficient. If you see this, there may be a memory leak — check logs |
| **Container keeps restarting** | Look at the logs for the crash reason. Common causes: syntax error in Python files, missing dependencies |
| **Slow first response** | HF Spaces may cold-start if the container was sleeping. First response after wake-up can take 10-30 seconds |
| **API key errors** | Verify secrets are set correctly in the Space settings. Remember that secret names must exactly match `os.getenv()` calls |
| **`ModuleNotFoundError`** | Ensure all handler files, `utils/`, `api_clients/`, and `templates/` directories were uploaded |

### Getting More Logs

Add this secret for verbose logging:

| Secret Name | Value |
|-------------|-------|
| `LOG_LEVEL` | `DEBUG` |

### Checking if the Bot is Running

1. Open Telegram and search for your bot
2. Send `/start`
3. If the bot responds, it's running correctly
4. If not, check the HF Space logs for errors

### Common Build Errors and Fixes

**Error:** `COPY failed: file not found in build context`

This means a file referenced in the Dockerfile is missing. Make sure all files and directories (`handlers/`, `api_clients/`, `utils/`, `templates/`) are uploaded to the Space.

**Error:** `pip install` fails for a package

Some packages may fail to build on the slim Python image. The HF Dockerfile includes `gcc` and `libffi-dev` to handle this. If a specific package still fails, check its documentation for system-level dependencies.

**Error:** Permission denied

The HF Dockerfile creates a non-root user for security. If you see permission errors, ensure the `/data` directory has correct write permissions (the Dockerfile handles this with `chmod`).

---

## 📋 Free Tier Limitations

| Resource | Free Tier Limit |
|----------|----------------|
| **Spaces** | Unlimited public Spaces, 2 private Spaces |
| **CPU** | 2 vCPU basic (shared) |
| **RAM** | 16GB |
| **Storage** | 50GB persistent |
| **Bandwidth** | Unlimited |
| **Sleep Policy** | Spaces sleep after 48 hours of inactivity |
| **Build Timeout** | 30 minutes |

### Keeping Your Bot Awake

Hugging Face Spaces may go to sleep after prolonged inactivity. Since Telegram bots use long polling, they maintain an active connection and are less likely to sleep. However, if the Space does sleep:

1. The bot will automatically wake up when the next Telegram message arrives
2. Wake-up time is typically 10-30 seconds
3. To prevent sleeping entirely, you can use a cron job (e.g., [cron-job.org](https://cron-job.org)) to send `/start` to your bot every 12 hours

### Upgrading for Better Performance

If you need better performance, you can upgrade your Space hardware:

| Hardware | Price | Specs |
|----------|-------|-------|
| CPU basic | Free | 2 vCPU (shared), 16GB RAM |
| CPU upgraded | $0.06/hour | 1 vCPU (dedicated), 16GB RAM |
| T4 small | $0.60/hour | 1x T4 GPU, 16GB RAM |
| A10G small | $1.59/hour | 1x A10G GPU, 24GB RAM |

> **Note:** For a Telegram bot, the free CPU basic tier is more than sufficient. GPU hardware is only needed for machine learning workloads.

---

## 📊 Comparison with Other Platforms

| Feature | HF Spaces | Render | Railway | Fly.io | Heroku |
|---------|-----------|--------|---------|--------|--------|
| **Free Tier** | Generous (16GB RAM) | Limited (idle) | $5 credit | 256MB RAM | $5/mo |
| **Persistent Storage** | 50GB | Ephemeral | Ephemeral | Volumes ($$$) | Add-ons |
| **Sleep Policy** | 48h inactivity | 15 min idle | Credit-based | 5h idle | 30 min idle |
| **Docker Support** | Full Docker SDK | Dockerfile | Dockerfile | Dockerfile | Docker |
| **Secret Management** | Built-in | Env vars | Env vars | Secrets | Config vars |
| **Auto Restart** | Yes | Yes | Yes | Yes | Yes |
| **Git Integration** | Built-in | GitHub | GitHub | CLI | Git push |
| **Best For** | Bots, ML apps | Web apps | General | Global | Production |

---

## 📁 HF Space Repository Structure

Your Hugging Face Space should have this file structure:

```
osint-bot (HF Space)/
├── Dockerfile              # HF-optimized Dockerfile
├── README.md               # Space description with SDK metadata
├── main.py                 # Bot entry point
├── config.py               # Configuration module
├── database.py             # SQLite operations
├── requirements.txt        # Python dependencies
│
├── handlers/               # All 31 command handler modules
│   ├── __init__.py
│   ├── start.py
│   ├── ip_lookup.py
│   ├── domain.py
│   ├── username.py
│   ├── ... (all other handlers)
│   └── photo_router.py
│
├── api_clients/            # All 8 API client modules
│   ├── __init__.py
│   ├── http_client.py
│   ├── ipinfo_client.py
│   ├── ... (all other clients)
│   └── virustotal_client.py
│
├── utils/                  # All 6 utility modules
│   ├── __init__.py
│   ├── validators.py
│   ├── rate_limiter.py
│   ├── logger.py
│   ├── formatters.py
│   └── proxy_manager.py
│
└── templates/              # Message templates
    └── messages.py
```

> **Note:** You do NOT need to upload `.env`, `.gitignore`, `tests/`, `scripts/`, `backups/`, `logs/`, or `docs/` to the Space. Only the files listed above are required for the bot to run.

---

## 🚀 Quick Deployment Checklist

- [ ] Hugging Face account created
- [ ] New Space created with **Docker** SDK selected
- [ ] All bot files uploaded (handlers/, api_clients/, utils/, templates/)
- [ ] `Dockerfile` uploaded (HF-optimized version)
- [ ] `README.md` uploaded with SDK metadata
- [ ] `TELEGRAM_TOKEN` secret configured
- [ ] Optional API keys configured as secrets
- [ ] Build completes successfully
- [ ] Bot responds to `/start` command
- [ ] Bot responds to `/help` command
- [ ] At least one OSINT command tested (e.g., `/ip 8.8.8.8`)
- [ ] Database persistence verified (restart and check data)

---

<p align="center">
Documentation for OSINT Investigation Bot<br>
<a href="https://github.com/gamingextra/osint-bot">View on GitHub</a> |
<a href="https://huggingface.co/spaces/gamingextra/osint-bot">View on Hugging Face</a>
</p>
