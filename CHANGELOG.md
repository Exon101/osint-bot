# Changelog

All notable changes to the OSINT Investigation Bot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-05-24

### Added
- **22 command modules** for comprehensive OSINT investigations
- **OSINT Tools**: IP lookup, domain analysis, username search, email validation, phone lookup, Google dork generator, EXIF metadata extractor
- **Security Features**: CVE vulnerability scanner (NVD + MITRE), breach monitoring (14 major breaches), cybersecurity news aggregator, GitHub repository tracker
- **CTF Tools**: Secure password generator (5 modes with entropy calculation), sandboxed code runner (Python/JS/Bash), hash & encoding tool (MD5, SHA, Base64, Hex, URL)
- **Network Reconnaissance**: Subdomain enumeration (crt.sh + Omnisint), full DNS recon (10 record types), WHOIS lookup, port scanner (Shodan InternetDB + socket probing)
- **URL & QR Tools**: URL safety analyzer (headers, patterns, VirusTotal), QR code generator & decoder
- **Infrastructure**: SQLite database with user tracking and audit logging, sliding-window rate limiter, input validation & sanitization
- **API Clients**: IPInfo, VirusTotal, Shodan, NVD, GitHub, Hunter.io, AbuseIPDB, generic HTTP client
- **Deployment**: Docker support, docker-compose, Render Blueprint, Fly.io config, Heroku Procfile, systemd service template
- **Documentation**: README, deployment guide, API key setup instructions, contribution guide

### Architecture
- Modular handler-based architecture with clean separation of concerns
- Each handler is independent and can be enabled/disabled in `main.py`
- Centralized configuration via `config.py` with environment variable support
- Audit logging system with JSON-formatted entries
- Rate limiting per user to prevent API abuse

## [1.0.0] - 2026-05-24 (Initial)

### Added
- Initial project setup and core infrastructure
- Basic bot framework with python-telegram-bot v20+
- Configuration management and database layer
- Utility modules (validators, rate limiter, logger, formatters)
