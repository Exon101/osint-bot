---
title: OSINT Investigation Bot
emoji: 🕵️
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
license: mit
---

# 🕵️ OSINT Investigation Bot

> A comprehensive Open Source Intelligence (OSINT) aggregation bot for Telegram with **31 powerful modules**.
> Built as an educational cybersecurity project demonstrating ethical intelligence gathering techniques.

## Features

| Category | Commands |
|----------|----------|
| **OSINT Tools** | `/ip` `/domain` `/user` `/malware` `/email` `/phone` `/dork` `/meta` |
| **Security** | `/vuln` `/darkweb` `/news` `/github` `/breach` |
| **Network Recon** | `/subdomain` `/dns` `/whois` `/port` `/urlscan` |
| **Social & People** | `/social` `/emailrecon` `/number` |
| **Image Intelligence** | `/reverse` `/face` |
| **Developer Tools** | `/password` `/run` `/encode` `/qr` |
| **Proxy Management** | `/proxy` |

## Deploying Your Own Instance

1. Create a new Space on Hugging Face with the **Docker** SDK
2. Clone this Space or upload the project files
3. Add `TELEGRAM_TOKEN` as a repository secret (from [@BotFather](https://t.me/botfather))
4. Optionally add API keys for enhanced features (IPInfo, VirusTotal, Shodan, etc.)
5. The Space will build and deploy automatically

See [huggingface_deployment.md](https://github.com/gamingextra/osint-bot/blob/main/huggingface_deployment.md) for the complete deployment guide.

## Environment Variables (Secrets)

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_TOKEN` | ✅ Yes | Bot token from @BotFather |
| `IPINFO_API_KEY` | Optional | IP geolocation (50k/month free) |
| `VIRUSTOTAL_API_KEY` | Optional | Malware/URL scanning (500/day free) |
| `SHODAN_API_KEY` | Optional | Port/service data (100/week free) |
| `HUNTER_API_KEY` | Optional | Email discovery (25/month free) |
| `ABUSEIPDB_API_KEY` | Optional | IP abuse scoring (1000/day free) |
| `GITHUB_TOKEN` | Optional | Repo analysis (5000/hr free) |

## Notes

- This bot uses **Telegram long polling** (outbound connections only) — no public URL needed
- SQLite database is stored in persistent storage (`/data`) and survives restarts
- All secrets are injected as environment variables at runtime

## License

MIT License — Educational use only.
