---
title: OSINT Investigation Bot
emoji: "🕵️"
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
license: mit
tags:
  - telegram-bot
  - osint
  - cybersecurity
  - python
app_port: 7860
---

# 🕵️ OSINT Investigation Bot

> A comprehensive Open Source Intelligence (OSINT) aggregation bot for Telegram with **30+ powerful modules**.

## 🚀 Quick Start

### Step 1: Deploy Telegram API Proxy (Required)

HuggingFace Spaces blocks direct access to `api.telegram.org`. You need a free Cloudflare Worker as a proxy (~2 minutes):

1. Go to [workers.cloudflare.com](https://workers.cloudflare.com) → Sign up (free)
2. Click **Create Worker** → name it `telegram-proxy`
3. Paste the code from `telegram-proxy-worker.js` (in this repo)
4. Click **Save and Deploy**
5. Copy your worker URL (e.g. `https://telegram-proxy.yourname.workers.dev`)

### Step 2: Configure This Space

Go to **Settings → Repository secrets** and add:

| Secret | Required | Value |
|--------|----------|-------|
| `TELEGRAM_TOKEN` | ✅ Yes | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_API_URL` | ✅ Yes | Your Cloudflare Worker URL from Step 1 |

### Step 3: Add Optional API Keys

| Secret | Description | Free Tier |
|--------|-------------|-----------|
| `IPINFO_API_KEY` | IP geolocation | 50k/month |
| `VIRUSTOTAL_API_KEY` | Malware/URL scanning | 500/day |
| `SHODAN_API_KEY` | Port/service data | 100/week |
| `HUNTER_API_KEY` | Email discovery | 25/month |
| `ABUSEIPDB_API_KEY` | IP abuse scoring | 1000/day |
| `GITHUB_TOKEN` | Repo analysis | 5000/hr |
| `HIBP_API_KEY` | Breach data lookup | — |
| `NUCLEI_API_KEY` | Vulnerability scanning | — |

### Step 4: Test

Send `/start` to your bot on Telegram. Done!

## 📋 Commands (30+ Modules)

| Category | Commands |
|----------|----------|
| **OSINT Tools** | `/ip` `/domain` `/user` `/malware` `/email` `/phone` `/dork` `/meta` |
| **Security** | `/vuln` `/nuclei` `/darkweb` `/news` `/github` `/breach` |
| **Network Recon** | `/subdomain` `/dns` `/whois` `/port` `/urlscan` |
| **Social & People** | `/social` `/emailrecon` `/number` |
| **Image Intelligence** | `/reverse` `/face` |
| **Developer Tools** | `/password` `/run` `/encode` `/qr` |
| **Proxy Management** | `/proxy` |

## 🏗️ Architecture

```
User → Telegram → https://your-space.hf.space/webhook/{token} → Bot
Bot → https://your-worker.workers.dev/bot{token}/sendMessage → Telegram → User
```

The Cloudflare Worker proxies all Telegram API calls, bypassing HF Spaces network restrictions. It's free, fast, and handles unlimited requests.

## 📄 License

MIT License — Educational use only.
