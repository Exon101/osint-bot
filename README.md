# 🕵️ OSINT Investigation Bot

> A comprehensive Open Source Intelligence (OSINT) aggregation bot for Telegram with **30+ powerful modules**.
> Built as an educational cybersecurity project demonstrating ethical intelligence gathering techniques.
>
> 🌐 **Live Demo:** [https://exon101.github.io/osint-bot](https://exon101.github.io/osint-bot/)

## ✨ Features Overview

### 🔍 OSINT Investigation Tools
| Command | Description |
|---------|-------------|
| `/ip` | IP geolocation, ISP, abuse score, Shodan data |
| `/domain` | DNS records, WHOIS, security headers, VirusTotal |
| `/user` | Cross-platform username hunting (30+ platforms) |
| `/social` | Detailed social media profile lookup (25 platforms) |
| `/malware` | File hash analysis via VirusTotal |
| `/email` | Email validation, disposable check, breach info |
| `/emailrecon` | Deep email reconnaissance (Gravatar, MX, ClearBit) |
| `/breach` | Data breach checker (HaveIBeenPwned) |
| `/phone` | Phone number validation & carrier lookup |
| `/number` | Advanced phone number analysis |
| `/dork` | Google dork generator (65+ dorks, 6 categories) |

### 🖼️ Image & Photo Intelligence
| Command | Description |
|---------|-------------|
| `/reverse` | Reverse image search (Google Lens, Yandex, TinEye, Bing) |
| `/face` | Face detection & analysis from photos |
| `/meta` | EXIF metadata extraction from images |

### 🛡️ Advanced Security Features
| Command | Description |
|---------|-------------|
| `/vuln` | CVE vulnerability scanner (NVD + MITRE) |
| `/nuclei` | Template-based vulnerability scanner (ProjectDiscovery) |
| `/darkweb` | Breach monitoring (14 major breaches) |
| `/news` | Cybersecurity news aggregator (3 sources) |
| `/github` | Repo tracker, security scanner, trending |

### 🧩 CTF & Developer Tools
| Command | Description |
|---------|-------------|
| `/password` | Secure password generator (5 modes, entropy calc) |
| `/run` | Sandboxed code executor (Python/JS/Bash) |
| `/encode` | Hash & encoding tool (MD5, SHA, Base64, Hex) |

### 🌐 Network Reconnaissance
| Command | Description |
|---------|-------------|
| `/subdomain` | Subdomain enumeration (crt.sh + Omnisint) |
| `/dns` | Full DNS recon (10 record types) |
| `/whois` | WHOIS domain registration lookup |
| `/port` | Port scanner (Shodan InternetDB + probing) |

### 🔗 URL, QR & Proxy Tools
| Command | Description |
|---------|-------------|
| `/urlscan` | URL safety analyzer (headers, patterns, VirusTotal) |
| `/qr` | QR code generator & decoder |
| `/proxy` | Proxy manager with rotation (HTTP/HTTPS/SOCKS4/SOCKS5) |

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Telegram Bot Token from [@BotFather](https://t.me/botfather)
- (Optional) Free API keys for enhanced features

### Installation

```bash
# Clone the repository
git clone https://github.com/gamingextra/osint-bot.git
cd osint-bot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your tokens

# Run the bot
python main.py
```

### Environment Variables

```bash
# Required
TELEGRAM_TOKEN=your_bot_token_here

# Optional (free tiers)
IPINFO_API_KEY=         # https://ipinfo.io/signup (50k/month)
VIRUSTOTAL_API_KEY=     # https://www.virustotal.com/gui/my-apikey (500/day)
SHODAN_API_KEY=         # https://api.shodan.io/register (100/week)
HUNTER_API_KEY=         # https://hunter.io/api (1000/month)
ABUSEIPDB_API_KEY=      # https://www.abuseipdb.com/account/api (1000/day)
GITHUB_TOKEN=           # https://github.com/settings/tokens (5000/hr)
NUCLEI_API_KEY=         # https://cloud.projectdiscovery.io (vuln scanning)
HIBP_API_KEY=           # https://haveibeenpwned.com/API/Key (breach data)
CLEARBIT_API_KEY=       # https://clearbit.com/docs (email enrichment)
```

## 📁 Project Structure

```
osint-bot/
├── main.py                  # Entry point & handler registration
├── config.py                # Configuration & API keys
├── database.py              # SQLite operations
├── requirements.txt         # Dependencies
├── .env.example             # Environment template
├── .gitignore
├── README.md
├── Dockerfile               # Production Docker image
├── Dockerfile.hf            # HuggingFace Spaces Dockerfile
├── docker-compose.yml       # Docker Compose setup
├── Makefile                 # Build & deploy shortcuts
├── handlers/                # Command handlers (30+ modules)
│   ├── start.py             # Welcome, help, stats, interactive menu
│   ├── ip_lookup.py         # IP investigation
│   ├── domain.py            # Domain analysis
│   ├── username.py          # Username search (30+ platforms)
│   ├── social_lookup.py     # Social media deep lookup
│   ├── hash_lookup.py       # Malware hash check
│   ├── email.py             # Email validation
│   ├── email_recon.py       # Deep email recon
│   ├── breach_lookup.py     # Data breach checker
│   ├── phone.py             # Phone lookup
│   ├── number_analysis.py   # Advanced number analysis
│   ├── google_dorks.py      # Dork generator
│   ├── metadata.py          # EXIF extractor
│   ├── vuln_scanner.py      # CVE scanner (NVD)
│   ├── nuclei_scanner.py    # Nuclei template vuln scanner
│   ├── darkweb_monitor.py   # Breach monitor
│   ├── hacker_news.py       # News aggregator
│   ├── github_tracker.py    # Repo tracker
│   ├── password_gen.py      # Password generator
│   ├── code_runner.py       # Code executor
│   ├── hash_tool.py         # Hash/encode tool
│   ├── subdomain_enum.py    # Subdomain finder
│   ├── dns_recon.py         # DNS lookup
│   ├── whois_lookup.py      # WHOIS lookup
│   ├── port_scan.py         # Port scanner
│   ├── url_scanner.py       # URL safety
│   ├── qr_tool.py           # QR generate/decode
│   ├── proxy.py             # Proxy manager
│   ├── reverse_image.py     # Reverse image search
│   ├── face_detect.py       # Face detection
│   └── photo_router.py      # Unified photo handler
├── utils/                   # Utilities
│   ├── validators.py        # Input validation
│   ├── rate_limiter.py      # Rate limiting
│   ├── logger.py            # Audit logging
│   ├── formatters.py        # Telegram HTML helpers
│   └── proxy_manager.py     # Proxy rotation engine
├── api_clients/             # External API wrappers
│   ├── http_client.py       # Generic HTTP client
│   ├── ipinfo_client.py     # IPInfo API
│   ├── virustotal_client.py # VirusTotal API
│   ├── shodan_client.py     # Shodan API
│   ├── nvd_client.py        # NVD API
│   ├── nuclei_client.py     # ProjectDiscovery Nuclei API
│   ├── github_client.py     # GitHub API
│   ├── hunter_client.py     # Hunter.io API
│   └── abuseipdb_client.py  # AbuseIPDB API
├── templates/
│   └── messages.py          # Message templates
├── docs/                    # GitHub Pages website
│   ├── index.html           # Landing page
│   ├── style.css            # Styles
│   ├── script.js            # Interactions
│   └── assets/              # Images & assets
├── tests/                   # Unit tests
├── scripts/                 # Setup & deploy scripts
├── deployment.md            # Deployment guide
└── huggingface_deployment.md # HuggingFace Spaces guide
```

## 🛡️ Security Features

- ✅ Input validation & sanitization on all commands
- ✅ Sliding-window rate limiting per user (10 req/60s)
- ✅ Audit logging of all queries (SQLite)
- ✅ Sandboxed code runner with blacklisted commands
- ✅ No sensitive data stored (passwords not logged)
- ✅ Proxy rotation support (HTTP/HTTPS/SOCKS4/SOCKS5)
- ✅ Private IP / cloud metadata endpoint blocking
- ✅ Educational disclaimers throughout

## ☢️ Nuclei Integration

The `/nuclei` command integrates [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) via their Cloud API for template-based vulnerability scanning:

```
/nuclei                         # Show interactive menu
/nuclei scan https://target.com  # Run a quick scan
/nuclei scan target.com critical # Scan with severity filter
/nuclei templates xss           # Search for templates
/nuclei status <scan_id>       # Check scan results
/nuclei list                    # List recent scans
/nuclei cancel <scan_id>       # Cancel a running scan
```

Get your API key at [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io).

## 🚢 Deployment

The bot can be deployed multiple ways:

| Platform | Guide |
|----------|-------|
| Docker | `docker build -t osint-bot . && docker run -d --env-file .env osint-bot` |
| VPS / Bare Metal | See [deployment.md](deployment.md) |
| Heroku / Railway / Render | See [deployment.md](deployment.md) |
| HuggingFace Spaces | See [huggingface_deployment.md](huggingface_deployment.md) |
| GitHub Pages | Set source to `docs/` folder |

## ⚠️ Ethical Disclaimer

This tool is designed for **EDUCATIONAL PURPOSES ONLY**.

- Use only for authorized security research
- Respect privacy laws and regulations
- Do not use for harassment or illegal activities
- All queries are logged for accountability
- Port scanning and vulnerability scanning only on authorized targets

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
Made with ❤️ for Cybersecurity Education
</p>
