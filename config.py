"""
OSINT Bot Configuration Module
Manages all settings, API keys, and feature flags.

Store sensitive keys as environment variables in production!
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class Config:
    """Central configuration class."""

    # ===========================================
    # TELEGRAM CONFIGURATION
    # ===========================================
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "YOUR_BOT_TOKEN_HERE")
    ADMIN_IDS: List[int] = field(default_factory=lambda: [123456789])

    # ===========================================
    # API KEYS (Free tiers available)
    # ===========================================
    # https://ipinfo.io/signup — 50k requests/month free
    IPINFO_API_KEY: Optional[str] = os.getenv("IPINFO_API_KEY")

    # https://www.virustotal.com/gui/my-apikey — 500/day free
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")

    # https://api.shodan.io/register — 100/week free
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")

    # https://hunter.io/api — 1000/month free
    HUNTER_API_KEY: Optional[str] = os.getenv("HUNTER_API_KEY")

    # https://www.abuseipdb.com/account/api — 1000/day free
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")

    # https://github.com/settings/tokens — 5000/hr (unauthenticated: 60/hr)
    GITHUB_TOKEN: Optional[str] = os.getenv("GITHUB_TOKEN")

    # https://docs.github.com/en/rest — for Gists API
    GITHUB_GIST_TOKEN: Optional[str] = os.getenv("GITHUB_GIST_TOKEN")

    # https://haveibeenpwned.com/API/Key — Breach data lookup
    HIBP_API_KEY: Optional[str] = os.getenv("HIBP_API_KEY")

    # https://clearbit.com/docs — Email enrichment (company data, social profiles)
    CLEARBIT_API_KEY: Optional[str] = os.getenv("CLEARBIT_API_KEY")

    # https://www.numverify.com — Phone validation
    NUMVERIFY_API_KEY: Optional[str] = os.getenv("NUMVERIFY_API_KEY")

    # https://phonevalidation.abstractapi.com — Phone validation fallback
    PHONEVALIDATION_API_KEY: Optional[str] = os.getenv("PHONEVALIDATION_API_KEY")

    # https://cloud.projectdiscovery.io — Nuclei vulnerability scanning
    NUCLEI_API_KEY: Optional[str] = os.getenv("NUCLEI_API_KEY")

    # ===========================================
    # DATABASE
    # ===========================================
    DATABASE_URL: str = "sqlite:///osint_bot.db"

    # ===========================================
    # RATE LIMITING
    # ===========================================
    RATE_LIMIT: int = 10          # requests per window
    RATE_WINDOW: int = 60         # seconds per window

    # ===========================================
    # CODE RUNNER SETTINGS
    # ===========================================
    CODE_RUNNER_TIMEOUT: int = 10  # max execution seconds
    CODE_RUNNER_MAX_OUTPUT: int = 4096  # max output chars

    # ===========================================
    # PROXY CONFIGURATION
    # ===========================================
    PROXY_ENABLED: bool = os.getenv("PROXY_ENABLED", "false").lower() in ("true", "1", "yes")
    PROXY_URL: Optional[str] = os.getenv("PROXY_URL", "")  # Single proxy: http://user:pass@host:port
    PROXY_LIST: Optional[str] = os.getenv("PROXY_LIST", "")  # Comma-separated: http://p1:8080,socks5://p2:1080
    PROXY_ROTATION: str = os.getenv("PROXY_ROTATION", "sequential")  # sequential|random|failover
    PROXY_TEST_URL: str = os.getenv("PROXY_TEST_URL", "https://httpbin.org/ip")
    PROXY_TEST_TIMEOUT: int = int(os.getenv("PROXY_TEST_TIMEOUT", "10"))

    # ===========================================
    # FEATURE FLAGS
    # ===========================================
    ENABLE_LOGGING: bool = True
    ENABLE_ANALYTICS: bool = True
    ENABLE_CODE_RUNNER: bool = True
    ENABLE_PASSWORD_GEN: bool = True


# Singleton config instance
config = Config()
