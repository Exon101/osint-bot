# 🚀 OSINT Bot — API Keys & Deployment Guide

> Complete guide for generating all API keys and deploying your OSINT Investigation Bot to production.

---

## 📑 Table of Contents

- [Part 1: Telegram Bot Token](#-part-1-telegram-bot-token-required)
- [Part 2: API Keys Setup (Optional)](#-part-2-api-keys-setup-optional)
  - [1. IPInfo API Key](#1-ipinfo-api-key)
  - [2. VirusTotal API Key](#2-virustotal-api-key)
  - [3. Shodan API Key](#3-shodan-api-key)
  - [4. Hunter.io API Key](#4-hunterio-api-key)
  - [5. AbuseIPDB API Key](#5-abuseipdb-api-key)
  - [6. GitHub Personal Access Token](#6-github-personal-access-token)
- [Part 3: Local Deployment](#-part-3-local-deployment)
- [Part 4: Deploy to Render](#-part-4-deploy-to-render)
- [Part 5: Deploy to Railway](#-part-5-deploy-to-railway)
- [Part 6: Deploy to Fly.io](#-part-6-deploy-to-flyio)
- [Part 7: Deploy to Heroku](#-part-7-deploy-to-heroku)
- [Part 8: Deploy using Docker](#-part-8-deploy-using-docker)
- [Part 9: Deploy to a VPS (Linux)](#-part-9-deploy-to-a-vps-linux)
- [Part 10: Deploy to Hugging Face Spaces](#-part-10-deploy-to-hugging-face-spaces)
- [Part 11: Deployment Checklist](#-part-11-deployment-checklist)

---

## 🔑 Part 1: Telegram Bot Token (REQUIRED)

This is the **only required key**. Without it, the bot cannot run.

### Step 1: Open Telegram and find BotFather

1. Open the Telegram app (desktop or mobile)
2. In the search bar, type **@BotFather** and select the official BotFather bot (verified with a blue checkmark)
3. Tap **Start** or send `/start`

### Step 2: Create a new bot

1. Send the command: `/newbot`
2. BotFather will ask for a **display name** — this is the human-readable name shown to users
   - Example: `OSINT Investigation Bot`
3. BotFather will then ask for a **username** — this must end with `bot` and be unique
   - Example: `my_osint_bot` or `osint_research_bot`
4. If the username is available, BotFather will respond with a **success message** containing your bot token

### Step 3: Copy and save your token

The token looks like this:
```
7123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Copy this token immediately and store it securely.** You will need it for the `TELEGRAM_TOKEN` environment variable.

### Step 4: Configure your bot (Optional)

You can use these BotFather commands to customize your bot:

| Command | Description |
|---------|-------------|
| `/setdescription` | Set a description shown when users start the bot |
| `/setabouttext` | Set the "About" text on the bot's profile |
| `/setuserpic` | Set a profile picture for the bot |
| `/setcommands` | Register commands so Telegram shows an auto-complete menu |
| `/setinline` | Enable or disable inline mode |

**Recommended commands to register** (send to BotFather after `/setcommands`):
```
start - Start the bot and show main menu
help - Show all available commands
stats - View your usage statistics
ip - IP geolocation and abuse check
domain - Domain analysis and DNS lookup
user - Username search across platforms
malware - File hash analysis
email - Email validation and breach check
phone - Phone number lookup
dork - Google dork generator
meta - EXIF metadata extraction
vuln - CVE vulnerability scanner
darkweb - Breach monitoring
news - Cybersecurity news feed
github - GitHub repo tracker
password - Secure password generator
run - Sandboxed code executor
encode - Hash and encoding tool
subdomain - Subdomain enumeration
dns - DNS record lookup
whois - WHOIS domain lookup
port - Port scanner
urlscan - URL safety analyzer
qr - QR code generator/decoder
```

### Step 5: Test your bot

1. Go to `https://t.me/<your_bot_username>` in your browser
2. Or search for your bot's username in the Telegram app
3. Click **Start** and send `/start`
4. You should see the welcome message

---

## 🔐 Part 2: API Keys Setup (Optional)

All API keys below are **optional**. The bot will work without them, using free fallback APIs where possible. However, adding API keys unlocks enhanced features and higher rate limits.

> **💡 Tip:** Every service below offers a **free tier**. You don't need to pay anything to use this bot.

---

### 1. IPInfo API Key

**Used for:** `/ip` command — IP geolocation, ISP, ASN, company info

**Free tier:** 50,000 requests/month

**Steps to generate:**

1. Open your browser and go to: **https://ipinfo.io/signup**
2. Fill in the registration form:
   - **Email:** Your email address
   - **Password:** Create a strong password
3. Click **Sign Up**
4. Check your email inbox for a **verification email** from IPInfo
5. Click the verification link in the email
6. You will be redirected to the IPInfo dashboard
7. On the dashboard, click on the **API Token** section in the left sidebar
8. Your API key will be displayed. It looks like: `a1b2c3d4e5f6g7h8`
9. Copy the key and add it to your `.env` file as `IPINFO_API_KEY=a1b2c3d4e5f6g7h8`

**What you get with this key:**
- Precise geolocation (city, region, country, postal code)
- ISP and ASN (Autonomous System Number) information
- Company name if the IP belongs to an organization
- Privacy detection (VPN, proxy, Tor, hosting detection)

---

### 2. VirusTotal API Key

**Used for:** `/malware`, `/domain`, `/urlscan` commands — Malware scanning, domain reputation, URL safety

**Free tier:** 500 requests/day

**Steps to generate:**

1. Go to: **https://www.virustotal.com/gui/join**
2. You can sign up with:
   - **Google account** (recommended, fastest)
   - **Email address**
3. Fill in the required fields and create your account
4. Check your email and click the **verification link**
5. Log in to VirusTotal at **https://www.virustotal.com/gui**
6. Click on your **profile icon** in the top-right corner
7. Select **API Key** from the dropdown menu
8. Your API key will be displayed. It looks like: `a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890`
9. Copy the key and add it to your `.env` file as `VIRUSTOTAL_API_KEY=your_key_here`

**What you get with this key:**
- File hash analysis against 70+ antivirus engines
- Domain and URL reputation checks
- Detection ratios and detailed reports
- Community comments and votes
- Historical data on analyzed files and URLs

---

### 3. Shodan API Key

**Used for:** `/ip`, `/port` commands — Open port data, vulnerability scanning, service fingerprinting

**Free tier:** 100 search queries/week, 100 scan credits/month, InternetDB is unlimited

**Steps to generate:**

1. Go to: **https://api.shodan.io/register**
2. You can sign up with:
   - **Google account**
   - **Email address**
3. Fill in the registration form with your email and a password
4. Complete the CAPTCHA verification
5. Check your email for a verification link from Shodan
6. Click the verification link
7. Go to **https://www.shodan.io/account** and log in
8. In your account dashboard, find the **API Key** section
9. Your API key will be displayed. It looks like: `aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q`
10. Copy the key and add it to your `.env` file as `SHODAN_API_KEY=your_key_here`

**What you get with this key:**
- Detailed information about open ports and running services
- CVE vulnerability data associated with discovered services
- Historical data on internet-facing devices
- SSL certificate information
- Screenhots of web services

> **Note:** The `/port` command uses Shodan InternetDB (https://internetdb.shodan.io) which is **completely free** and requires **no API key**. You only need the Shodan key for advanced `/ip` lookups.

---

### 4. Hunter.io API Key

**Used for:** `/email` command — Email verification, domain-based email discovery, deliverability checks

**Free tier:** 25 search requests/month, 1,000 email verifications/month

**Steps to generate:**

1. Go to: **https://hunter.io/api** or **https://hunter.io/users/sign_up**
2. Enter your email address and create a password
3. You can also sign up using **Google account** (quick option)
4. Complete the registration form with your name and organization (can be "Personal" or "Student")
5. Check your email and verify your account
6. Log in at **https://hunter.io/dashboard**
7. Click on **API** in the top navigation menu
8. Your API key will be displayed on the API dashboard page
9. Copy the key and add it to your `.env` file as `HUNTER_API_KEY=your_key_here`

**What you get with this key:**
- Find email addresses associated with any domain
- Verify if an email address is deliverable
- SMTP server and acceptance detection
- Email pattern discovery (first.last, firstlast@company.com, etc.)

---

### 5. AbuseIPDB API Key

**Used for:** `/ip` command — IP abuse reporting, confidence score, recent reports

**Free tier:** 1,000 checks/day

**Steps to generate:**

1. Go to: **https://www.abuseipdb.com/account/register**
2. Fill in the registration form:
   - **Username:** Choose a username
   - **Email:** Your email address
   - **Password:** Create a strong password
   - **Country:** Select your country
3. Check the **"I'm not a robot"** CAPTCHA
4. Check the **Terms of Service** box
5. Click **Register**
6. Check your email and click the verification link
7. Log in at **https://www.abuseipdb.com/account**
8. Go to the **API** tab in your account dashboard
9. Click **Generate API Key**
10. Your API key will be displayed. It looks like: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`
11. Copy the key and add it to your `.env` file as `ABUSEIPDB_API_KEY=your_key_here`

**What you get with this key:**
- Abuse confidence score (0-100%) for any IP address
- Number of abuse reports filed against an IP
- Categorization of abuse types (brute force, spam, DDoS, etc.)
- Country, ISP, and usage type information
- Ability to report abusive IPs directly from the API

---

### 6. GitHub Personal Access Token

**Used for:** `/github` command — Repository analysis, secret scanning, release tracking, trending repos

**Free tier:** 5,000 requests/hour (authenticated), 60 requests/hour (unauthenticated)

**Steps to generate:**

1. Go to: **https://github.com/settings/tokens**
2. If prompted, log in to your GitHub account
3. Click the **"Generate new token"** button (select "Generate new token (classic)")
4. Fill in the form:
   - **Note:** Enter a descriptive name like `OSINT Bot` so you remember what it's for
   - **Expiration:** Choose an expiration date (recommended: 90 days or custom)
   - **Select scopes:** Check the following boxes:
     - ✅ `public_repo` (Access public repositories)
     - ✅ `read:user` (Read user profile info)
5. Scroll down and click **"Generate token"**
6. Your token will be displayed at the top of the page. It looks like: `ghp_aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7`
7. **Copy the token immediately** — you will not be able to see it again
8. Add it to your `.env` file as `GITHUB_TOKEN=ghp_your_token_here`

**What you get with this key:**
- Repository information (stars, forks, language, topics)
- Latest releases and tags for any public repo
- File search capabilities (for secret scanning)
- GitHub Code Search API access
- Higher rate limits (5000/hr vs 60/hr)

> **⚠️ Security Warning:** Never share your GitHub token publicly. If it gets exposed, immediately go to https://github.com/settings/tokens and delete the compromised token, then generate a new one.

---

### 📋 API Keys Quick Reference

| Service | Free Tier | Sign-up URL | Required For |
|---------|-----------|-------------|-------------|
| Telegram Bot | Unlimited | t.me/BotFather | `/start`, all commands |
| IPInfo | 50k/month | ipinfo.io/signup | `/ip` (enhanced) |
| VirusTotal | 500/day | virustotal.com/gui/join | `/malware`, `/urlscan` |
| Shodan | 100/week | api.shodan.io/register | `/ip`, `/port` (enhanced) |
| Hunter.io | 25 searches + 1000 verifications/month | hunter.io/users/sign_up | `/email` (enhanced) |
| AbuseIPDB | 1000/day | abuseipdb.com/account/register | `/ip` (abuse score) |
| GitHub | 5000/hr | github.com/settings/tokens | `/github` (enhanced) |

---

## 💻 Part 3: Local Deployment

This is the simplest way to run the bot on your own machine for development and testing.

### Prerequisites

- **Python 3.10 or higher** — Download from [python.org](https://www.python.org/downloads/)
- **Git** — Download from [git-scm.com](https://git-scm.com/downloads)
- **Telegram Bot Token** — From @BotFather (see Part 1)

### Step-by-step

```bash
# 1. Clone your repository
git clone https://github.com/YOUR_USERNAME/osint-bot.git
cd osint-bot

# 2. Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your environment file
cp .env.example .env

# 5. Edit .env and add your tokens
# On Linux/macOS:
nano .env
# On Windows:
notepad .env

# 6. Run the bot
python main.py
```

You should see output like:
```
2026-05-24 13:00:00 | INFO     | osint_bot | ==================================================
2026-05-24 13:00:00 | INFO     | osint_bot | OSINT Investigation Bot - Starting
2026-05-24 13:00:00 | INFO     | osint_bot | ==================================================
2026-05-24 13:00:00 | INFO     | osint_bot | Bot is starting up...
2026-05-24 13:00:00 | INFO     | osint_bot | Database initialized successfully.
2026-05-24 13:00:00 | INFO     | osint_bot | All handlers registered.
2026-05-24 13:00:00 | INFO     | osint_bot | Bot is running. Press Ctrl+C to stop.
```

### Running in the Background (Linux/macOS)

To keep the bot running after you close the terminal:

```bash
# Option 1: nohup (simple)
nohup python main.py > bot.log 2>&1 &

# Option 2: screen (recommended)
screen -S osint-bot
python main.py
# Press Ctrl+A then D to detach
# To reattach: screen -r osint-bot

# Option 3: tmux
tmux new -s osint-bot
python main.py
# Press Ctrl+B then D to detach
# To reattach: tmux attach -t osint-bot
```

### Running in the Background (Windows)

```powershell
# Option 1: Start a new PowerShell window
Start-Process python -ArgumentList "main.py" -NoNewWindow

# Option 2: Run as a background job
Start-Job -ScriptBlock { cd osint-bot; python main.py }
```

### Running as a systemd Service (Linux)

This ensures the bot starts automatically on boot and restarts if it crashes.

```bash
# 1. Create a systemd service file
sudo nano /etc/systemd/system/osint-bot.service
```

Add the following content (replace paths with your actual paths):

```ini
[Unit]
Description=OSINT Investigation Telegram Bot
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/home/your_username/osint-bot
Environment=PATH=/home/your_username/osint-bot/venv/bin
ExecStart=/home/your_username/osint-bot/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# 2. Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable osint-bot
sudo systemctl start osint-bot

# 3. Check status
sudo systemctl status osint-bot

# 4. View logs
sudo journalctl -u osint-bot -f

# 5. To stop/restart
sudo systemctl stop osint-bot
sudo systemctl restart osint-bot
```

---

## ☁️ Part 4: Deploy to Render

[Render](https://render.com) is a popular cloud platform that offers free web services. It supports Python out of the box.

### Prerequisites

- A [Render](https://render.com) account (free, sign up with GitHub)
- Your bot code on GitHub

### Step 1: Prepare your repository

Create these two files in your project root (if they don't exist):

**`runtime.txt`** — Tells Render which Python version to use:
```
python-3.11.7
```

**`Dockerfile`** (optional, but recommended for flexibility):
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

### Step 2: Deploy on Render

1. Go to **https://dashboard.render.com**
2. Click **"New"** and select **"Web Service"**
3. Connect your GitHub account if you haven't already
4. Select the **osint-bot** repository
5. Configure the service:
   - **Name:** `osint-bot` (or any name you prefer)
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python main.py`
   - **Instance Type:** `Free`
6. Scroll down to **Environment Variables** and add your keys:
   | Key | Value |
   |-----|-------|
   | `TELEGRAM_TOKEN` | `your_telegram_bot_token` |
   | `IPINFO_API_KEY` | `your_ipinfo_key` (optional) |
   | `VIRUSTOTAL_API_KEY` | `your_vt_key` (optional) |
   | `SHODAN_API_KEY` | `your_shodan_key` (optional) |
   | `HUNTER_API_KEY` | `your_hunter_key` (optional) |
   | `ABUSEIPDB_API_KEY` | `your_abuseipdb_key` (optional) |
   | `GITHUB_TOKEN` | `your_github_token` (optional) |
7. Click **"Create Web Service"**

### Step 3: Monitor your deployment

- Render will automatically build and deploy your bot
- You can view logs in the **Logs** tab of your Render dashboard
- The bot will be assigned a URL like `https://osint-bot-xxxx.onrender.com`
- **Important:** Telegram bots do NOT need a public URL to receive messages (they use long polling), so the URL doesn't matter

### Step 4: Auto-deploy on push

Render automatically redeploys when you push to your `main` branch. To disable this:

- Go to your service settings on Render
- Toggle **"Auto-deploy"** off
- You can then deploy manually from the **"Manual Deploy"** button

### Free Tier Limitations on Render

- The free tier spins down after **15 minutes of inactivity**
- It takes **30-50 seconds** to spin back up when a message is received
- You get **750 hours/month** of free compute time
- This is sufficient for a Telegram bot that handles messages on demand

---

## 🚂 Part 5: Deploy to Railway

[Railway](https://railway.app) is a modern deployment platform with a generous free tier ($5/month credit).

### Prerequisites

- A [Railway](https://railway.app) account (sign up with GitHub)
- Your bot code on GitHub

### Step 1: Deploy via GitHub

1. Go to **https://railway.app**
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Choose the **osint-bot** repository
5. Railway will automatically detect the Python project and configure it

### Step 2: Add Environment Variables

1. In your Railway project dashboard, click on your deployed service
2. Go to the **"Variables"** tab
3. Add all your environment variables:
   - `TELEGRAM_TOKEN` = your bot token
   - All optional API keys as needed
4. Click **"Save"**

### Step 3: Configure Start Command

If Railway doesn't auto-detect the start command:

1. Go to your service settings
2. Set **Start Command** to: `python main.py`
3. Railway will automatically redeploy

### Step 4: Monitor and Debug

- View real-time logs in the **"Deployments"** tab
- Click on any deployment to see build and runtime logs
- Use the **"Exec"** tab to get a shell inside your running container

### Railway Pricing (Free Tier)

- **$5 USD/month** in free credits
- This is typically enough to run a Telegram bot 24/7
- You'll need to add a payment method if credits run out
- Estimated cost for this bot: ~$3-4/month

---

## 🛫 Part 6: Deploy to Fly.io

[Fly.io](https://fly.io) deploys applications close to users worldwide with a generous free allowance.

### Prerequisites

- Install the Fly CLI:
  - **macOS:** `brew install flyctl`
  - **Linux:** `curl -L https://fly.io/install.sh | sh`
  - **Windows:** `pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"`
- A [Fly.io](https://fly.io) account (sign up with GitHub or email)

### Step 1: Login to Fly.io

```bash
flyctl auth login
```

This will open your browser to authenticate.

### Step 2: Create the Dockerfile

Create a `Dockerfile` in your project root:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs

# Run the bot
CMD ["python", "main.py"]
```

### Step 3: Launch on Fly.io

```bash
# Launch the application (creates fly.toml)
flyctl launch

# When prompted:
# - App name: osint-bot (or your choice)
# - Region: Choose closest to your users (e.g., Singapore, London, etc.)
# - Would you like to set up a Postgresql database? No
# - Would you like to set up a Redis database? No
# - Do you want to deploy now? No (we'll set env vars first)
```

### Step 4: Set Environment Variables

```bash
# Set your bot token (required)
flyctl secrets set TELEGRAM_TOKEN="your_telegram_bot_token"

# Set optional API keys
flyctl secrets set IPINFO_API_KEY="your_ipinfo_key"
flyctl secrets set VIRUSTOTAL_API_KEY="your_virustotal_key"
flyctl secrets set SHODAN_API_KEY="your_shodan_key"
flyctl secrets set HUNTER_API_KEY="your_hunter_key"
flyctl secrets set ABUSEIPDB_API_KEY="your_abuseipdb_key"
flyctl secrets set GITHUB_TOKEN="your_github_token"

# Enable code runner feature (optional)
flyctl secrets set ENABLE_CODE_RUNNER="true"
flyctl secrets set ENABLE_PASSWORD_GEN="true"
```

### Step 5: Deploy

```bash
# First deploy
flyctl deploy

# Check deployment status
flyctl status

# View live logs
flyctl logs
```

### Fly.io Free Tier

- **3 shared-cpu-1x VMs** with **256MB RAM** each
- **160GB outbound data transfer** per month
- More than enough for a Telegram bot
- Note: Free VMs spin down after periods of inactivity and take ~30s to restart

---

## 🟣 Part 7: Deploy to Heroku

[Heroku](https://heroku.com) is a classic PaaS platform. Free dynos are back with Eco dynos.

### Prerequisites

- A [Heroku](https://heroku.com) account
- The [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli):
  - **macOS:** `brew tap heroku/brew && brew install heroku`
  - **Linux:** `snap install heroku --classic`
  - **Windows:** Download from [heroku.com/cli](https://devcenter.heroku.com/articles/heroku-cli)

### Step 1: Create a Procfile

Create a file named `Procfile` (no extension) in your project root:

```
worker: python main.py
```

### Step 2: Login and Create App

```bash
# Login to Heroku
heroku login

# Create a new Heroku app
heroku create osint-bot

# Or with a custom name
heroku create your-unique-bot-name
```

### Step 3: Add Buildpack (Python)

```bash
# Heroku auto-detects Python, but you can set it explicitly
heroku buildpacks:set heroku/python
```

### Step 4: Set Environment Variables

```bash
# Required
heroku config:set TELEGRAM_TOKEN="your_telegram_bot_token"

# Optional API keys
heroku config:set IPINFO_API_KEY="your_ipinfo_key"
heroku config:set VIRUSTOTAL_API_KEY="your_virustotal_key"
heroku config:set SHODAN_API_KEY="your_shodan_key"
heroku config:set HUNTER_API_KEY="your_hunter_key"
heroku config:set ABUSEIPDB_API_KEY="your_abuseipdb_key"
heroku config:set GITHUB_TOKEN="your_github_token"

# Feature flags
heroku config:set ENABLE_CODE_RUNNER="true"
heroku config:set ENABLE_PASSWORD_GEN="true"
```

### Step 5: Deploy

```bash
# Add Heroku remote to git (if not already added)
git remote add heroku https://git.heroku.com/your-app-name.git

# Push to deploy
git push heroku main

# View logs
heroku logs --tail

# Check if the worker is running
heroku ps
```

### Step 6: Scale the Worker

Heroku needs at least one worker dyno to run the bot:

```bash
# Scale to 1 worker
heroku ps:scale worker=1

# Check dyno status
heroku ps
```

### Heroku Eco Dyno Pricing

- **Eco Dynos** start at **$5/month** per dyno
- They sleep after 30 minutes of inactivity by default
- Add `heroku ps:scale worker=1 --type=eco` to use eco pricing

---

## 🐳 Part 8: Deploy using Docker

Docker deployment is the most portable option — works on any server, cloud platform, or local machine.

### Step 1: Create the Dockerfile

Create a `Dockerfile` in your project root:

```dockerfile
FROM python:3.11-slim

LABEL maintainer="your-email@example.com"
LABEL description="OSINT Investigation Bot for Telegram"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for logs and database
RUN mkdir -p logs

# Non-root user for security
RUN useradd --create-home botuser
USER botuser

# Health check (not required for Telegram bots, but good practice)
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sqlite3; conn = sqlite3.connect('osint_bot.db'); conn.execute('SELECT 1'); conn.close()" || exit 1

# Run the bot
CMD ["python", "main.py"]
```

### Step 2: Create docker-compose.yml (Optional)

For easier management with environment variables:

```yaml
version: '3.8'

services:
  osint-bot:
    build: .
    container_name: osint-bot
    restart: always
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
      - bot-data:/app
    healthcheck:
      test: ["CMD", "python", "-c", "import sqlite3; conn = sqlite3.connect('osint_bot.db'); conn.execute('SELECT 1'); conn.close()"]
      interval: 60s
      timeout: 10s
      retries: 3

volumes:
  bot-data:
```

### Step 3: Build and Run

**Option A: Docker Compose (recommended)**

```bash
# Copy env example
cp .env.example .env
# Edit .env with your tokens
nano .env

# Build and start
docker compose up -d --build

# View logs
docker compose logs -f

# Stop
docker compose down

# Restart
docker compose restart
```

**Option B: Plain Docker**

```bash
# Build the image
docker build -t osint-bot .

# Run the container
docker run -d \
  --name osint-bot \
  --restart always \
  -e TELEGRAM_TOKEN="your_token" \
  -e VIRUSTOTAL_API_KEY="your_vt_key" \
  -v osint-bot-data:/app \
  osint-bot

# View logs
docker logs -f osint-bot

# Stop
docker stop osint-bot

# Remove
docker rm osint-bot
```

### Step 4: Push to Docker Hub (Optional)

```bash
# Login to Docker Hub
docker login

# Tag the image
docker tag osint-bot your_dockerhub_username/osint-bot:latest

# Push
docker push your_dockerhub_username/osint-bot:latest
```

---

## 🖥️ Part 9: Deploy to a VPS (Linux)

For full control and the best uptime, deploy to a VPS (Virtual Private Server). Recommended providers:

| Provider | Starting Price | Free Tier |
|----------|---------------|-----------|
| [Oracle Cloud](https://cloud.oracle.com/free) | Free | ✅ 4 ARM instances, 24GB RAM |
| [DigitalOcean](https://digitalocean.com) | $4/month | ❌ |
| [Linode (Akamai)](https://linode.com) | $5/month | ❌ $100 credit for 60 days |
| [Hetzner](https://hetzner.com/cloud) | €3.29/month | ❌ |
| [AWS EC2](https://aws.amazon.com/ec2) | Free tier (12 months) | ✅ t2.micro (750 hrs/mo) |
| [Google Cloud](https://cloud.google.com/compute) | Free tier | ✅ e2-micro instance |

### Step 1: Connect to your VPS

```bash
ssh root@your_vps_ip
# Or with your SSH key
ssh -i ~/.ssh/your_key.pem ubuntu@your_vps_ip
```

### Step 2: Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python, pip, git, venv
sudo apt install -y python3 python3-pip python3-venv git

# Install Node.js (optional, for code runner JavaScript support)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install docker (optional, for containerized deployment)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

### Step 3: Clone and Configure

```bash
# Clone your repository
git clone https://github.com/YOUR_USERNAME/osint-bot.git
cd osint-bot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
nano .env
# Add all your tokens
```

### Step 4: Run with systemd (Recommended)

```bash
# Create systemd service
sudo nano /etc/systemd/system/osint-bot.service
```

Add this content (replace `your_username` and paths):

```ini
[Unit]
Description=OSINT Investigation Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=your_username
Group=your_username
WorkingDirectory=/home/your_username/osint-bot
EnvironmentFile=/home/your_username/osint-bot/.env
ExecStart=/home/your_username/osint-bot/venv/bin/python main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=osint-bot

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable osint-bot
sudo systemctl start osint-bot

# Check status
sudo systemctl status osint-bot

# View logs
sudo journalctl -u osint-bot -f
```

### Step 5: Set up a Firewall

```bash
# Install UFW
sudo apt install ufw

# Allow SSH (important: don't lock yourself out!)
sudo ufw allow 22/tcp

# Deny all other incoming traffic (Telegram bots use outbound only)
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

### Step 6: Automatic Updates (Optional)

```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades

# Enable it
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

---

## 🤗 Part 10: Deploy to Hugging Face Spaces

[Hugging Face Spaces](https://huggingface.co/spaces) offers a generous free tier with 16GB RAM, 50GB persistent storage, and full Docker SDK support — ideal for hosting a Telegram bot.

### Why Hugging Face Spaces?

| Feature | Details |
|---------|--------|
| **Free Tier** | 2 CPU basic Spaces, 16GB RAM, 50GB persistent storage |
| **Persistent Storage** | SQLite database survives restarts and rebuilds |
| **Auto Restart** | Container restarts automatically on crash |
| **Docker Support** | Full Docker SDK — runs any Python application |
| **No Public URL Needed** | Telegram bots use long polling (outbound only) |
| **Secret Management** | Built-in encrypted environment variable storage |

### Quick Deploy

```bash
# 1. Install HF CLI
pip install huggingface_hub
huggingface-cli login

# 2. Create a new Space (Docker SDK) at https://huggingface.co/new-space

# 3. Clone the Space repo
git clone https://huggingface.co/spaces/YOUR_USERNAME/osint-bot
cd osint-bot

# 4. Copy project files (use Dockerfile.hf for the Space)
cp /path/to/osint-bot/Dockerfile.hf ./Dockerfile
cp /path/to/osint-bot/README_SPACE.md ./README.md
cp /path/to/osint-bot/main.py ./main.py
cp /path/to/osint-bot/config.py ./config.py
cp /path/to/osint-bot/database.py ./database.py
cp /path/to/osint-bot/requirements.txt ./requirements.txt
cp -r /path/to/osint-bot/handlers/ ./handlers/
cp -r /path/to/osint-bot/api_clients/ ./api_clients/
cp -r /path/to/osint-bot/utils/ ./utils/
cp -r /path/to/osint-bot/templates/ ./templates/

# 5. Push to deploy
git add . && git commit -m "Deploy OSINT Bot" && git push
```

### Configure Secrets

Add these in your Space Settings > Repository secrets:

| Secret | Required |
|--------|----------|
| `TELEGRAM_TOKEN` | ✅ Yes |
| `IPINFO_API_KEY` | Optional |
| `VIRUSTOTAL_API_KEY` | Optional |
| `SHODAN_API_KEY` | Optional |
| `HUNTER_API_KEY` | Optional |
| `ABUSEIPDB_API_KEY` | Optional |
| `GITHUB_TOKEN` | Optional |

### Free Tier Notes

- Spaces may sleep after **48 hours** of inactivity (auto-wake on next message)
- Persistent storage at `/data` keeps your SQLite database across rebuilds
- 30-minute build timeout (plenty for this project)

### Full Guide

See [huggingface_deployment.md](./huggingface_deployment.md) for the complete deployment guide with troubleshooting, GitHub integration, and advanced configuration.

---

## ✅ Part 11: Deployment Checklist

Use this checklist to make sure your deployment is complete and secure:

### Before Deployment

- [ ] Telegram bot token obtained from @BotFather
- [ ] Bot commands registered with `/setcommands` in BotFather
- [ ] Bot description and about text set in BotFather
- [ ] `.env` file created with all required keys
- [ ] `.env` file added to `.gitignore` (never commit secrets!)
- [ ] Bot tested locally and all commands work
- [ ] Database is fresh or migrated properly

### Security

- [ ] No API keys or tokens committed to the repository
- [ ] `.gitignore` includes `.env`, `*.db`, `logs/`, `__pycache__/`
- [ ] Bot is not running as root user (use a dedicated user or Docker)
- [ ] Firewall configured (only necessary ports open)
- [ ] Rate limiting is enabled in `config.py`
- [ ] Audit logging is enabled (`ENABLE_LOGGING=True`)

### After Deployment

- [ ] Bot responds to `/start` command
- [ ] Bot responds to `/help` command
- [ ] Bot responds to at least one OSINT command
- [ ] Logs are being written correctly
- [ ] Database is being populated
- [ ] Auto-restart is configured (systemd, Docker restart policy, etc.)
- [ ] Monitoring is set up (check logs periodically)

### Maintenance

- [ ] Set a calendar reminder to check bot status weekly
- [ ] Monitor API key usage and rate limits monthly
- [ ] Keep Python and dependencies updated
- [ ] Pull latest code changes from GitHub and redeploy
- [ ] Rotate API tokens every 90 days (especially GitHub tokens)
- [ ] Back up the SQLite database periodically

---

## 🆘 Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `TELEGRAM_TOKEN not set!` | Make sure the `TELEGRAM_TOKEN` env var is set correctly in your `.env` file or deployment platform |
| `Bot is running but not responding` | Check if the bot is running with `python main.py` and look for errors in the console output |
| `Conflict: terminated by other getUpdates` | Only one instance of the bot can run at a time. Stop all other instances |
| `403 Forbidden` from API | Check if your API key is correct and hasn't expired |
| `429 Too Many Requests` | You've hit a rate limit. Wait a few minutes or increase `RATE_LIMIT` in config |
| `ModuleNotFoundError: No module named 'xxx'` | Run `pip install -r requirements.txt` again in the correct environment |
| Database locked errors | This is normal with SQLite under concurrent access. WAL mode is enabled by default to handle this |

### Platform-Specific Tips

- **Render:** The free tier has a 15-minute idle timeout. The bot will take 30-50 seconds to respond to the first message after waking up
- **Railway:** Free $5 monthly credit may not be enough for heavy usage. Monitor your spending in the dashboard
- **Fly.io:** Free VMs have only 256MB RAM. If you see OOM (Out of Memory) errors, you may need to upgrade
- **Heroku:** Eco dynos sleep after 30 minutes. Add `KEEP_AWAKE=true` env var or use a cron job to ping the bot periodically
- **Docker:** Always use `--restart always` to auto-restart the container if it crashes
- **VPS:** Use `systemd` for automatic restarts and `journalctl` for log management
- **Hugging Face Spaces:** Spaces sleep after 48 hours of inactivity. Use `Dockerfile.hf` for persistent storage at `/data`. Set secrets via the Space Settings page

---

## 📊 Platform Comparison

| Platform | Free Tier | Uptime | Setup Difficulty | Best For |
|----------|-----------|--------|-----------------|----------|
| Local | ✅ | When PC is on | Easy | Development & testing |
| Render | ✅ (idle) | ~95% | Very Easy | Students, hobbyists |
| Railway | $5 credit | ~99% | Easy | Small projects |
| Fly.io | ✅ (limited) | ~98% | Medium | Global deployment |
| Heroku | $5/mo eco | ~99% | Easy | Production |
| Docker | Varies | Depends on host | Medium | Portability |
| VPS | Oracle free tier | 99.9% | Advanced | Production, full control |
| **Hugging Face** | **16GB RAM free** | **~98%** | **Easy** | **Bots, ML apps, persistent storage** |

---

<p align="center">
Documentation for OSINT Investigation Bot<br>
<a href="https://github.com/gamingextra/osint-bot">View on GitHub</a>
</p>
