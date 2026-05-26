#!/usr/bin/env python3
"""
================================================
  OSINT Investigation Bot - Main Entry Point
================================================
A comprehensive Open Source Intelligence tool for Telegram.
Educational Purpose: Demonstrating ethical OSINT gathering.

Supports two run modes:
  - Polling (default / local / VPS)
  - Webhook  (HuggingFace Spaces / any environment with a public URL)
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

from config import config
from database import init_database

# ── Utility imports ──────────────────────────────
from utils.logger import setup_logger
from utils.rate_limiter import rate_limiter

# ── Handler imports ──────────────────────────────
from handlers.start import cmd_start, cmd_help, cmd_stats, cmd_menu_callback
from handlers.ip_lookup import cmd_ip, handle_ip_callback
from handlers.domain import cmd_domain, handle_domain_callback
from handlers.username import cmd_username, handle_username_callback
from handlers.hash_lookup import cmd_hash_lookup, handle_hash_lookup_callback
from handlers.email import cmd_email, handle_email_callback
from handlers.phone import cmd_phone, handle_phone_callback
from handlers.google_dorks import cmd_dork, handle_dork_callback
from handlers.metadata import cmd_metadata, handle_metadata_callback
from handlers.vuln_scanner import cmd_vuln, handle_vuln_callback
from handlers.darkweb_monitor import cmd_darkweb, handle_darkweb_callback
from handlers.hacker_news import cmd_news, handle_news_callback
from handlers.github_tracker import cmd_github, handle_github_callback
from handlers.password_gen import cmd_password, handle_password_callback
from handlers.code_runner import cmd_run, handle_run_callback
from handlers.hash_tool import cmd_encode, handle_hash_callback
from handlers.subdomain_enum import cmd_subdomain, handle_subdomain_callback
from handlers.dns_recon import cmd_dns, handle_dns_callback
from handlers.whois_lookup import cmd_whois, handle_whois_callback
from handlers.port_scan import cmd_port, handle_port_callback
from handlers.url_scanner import cmd_urlscan, handle_urlscan_callback
from handlers.qr_tool import cmd_qr, handle_qr_callback
from handlers.proxy import cmd_proxy, handle_proxy_callback
from handlers.reverse_image import cmd_reverse, handle_reverse_callback
from handlers.face_detect import cmd_face, handle_face_callback
from handlers.social_lookup import cmd_social, handle_social_callback
from handlers.email_recon import cmd_emailrecon, handle_emailrecon_callback
from handlers.breach_lookup import cmd_breach, handle_breach_callback
from handlers.number_analysis import cmd_number, handle_number_callback
from handlers.photo_router import handle_photo_router, handle_photo_callback
from handlers.nuclei_scanner import cmd_nuclei, handle_nuclei_callback

logger = setup_logger()


def register_handlers(application: Application) -> None:
    """Register all command and callback handlers."""

    # ── Core Commands ───────────────────────────
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("menu", cmd_start))
    application.add_handler(CommandHandler("stats", cmd_stats))

    # ── OSINT Investigation Tools ───────────────
    application.add_handler(CommandHandler("ip", cmd_ip))
    application.add_handler(CommandHandler("domain", cmd_domain))
    application.add_handler(CommandHandler("user", cmd_username))
    application.add_handler(CommandHandler("username", cmd_username))
    application.add_handler(CommandHandler("malware", cmd_hash_lookup))
    application.add_handler(CommandHandler("email", cmd_email))
    application.add_handler(CommandHandler("phone", cmd_phone))
    application.add_handler(CommandHandler("dork", cmd_dork))
    application.add_handler(CommandHandler("meta", cmd_metadata))

    # ── Advanced Security Features ──────────────
    application.add_handler(CommandHandler("vuln", cmd_vuln))
    application.add_handler(CommandHandler("vulnerability", cmd_vuln))
    application.add_handler(CommandHandler("cve", cmd_vuln))
    application.add_handler(CommandHandler("darkweb", cmd_darkweb))
    application.add_handler(CommandHandler("breach", cmd_darkweb))
    application.add_handler(CommandHandler("leak", cmd_darkweb))
    application.add_handler(CommandHandler("news", cmd_news))
    application.add_handler(CommandHandler("feed", cmd_news))
    application.add_handler(CommandHandler("github", cmd_github))
    application.add_handler(CommandHandler("repo", cmd_github))
    application.add_handler(CommandHandler("track", cmd_github))

    # ── CTF & Developer Tools ───────────────────
    application.add_handler(CommandHandler("password", cmd_password))
    application.add_handler(CommandHandler("genpass", cmd_password))
    application.add_handler(CommandHandler("pwd", cmd_password))
    application.add_handler(CommandHandler("run", cmd_run))
    application.add_handler(CommandHandler("exec", cmd_run))
    application.add_handler(CommandHandler("code", cmd_run))
    application.add_handler(CommandHandler("encode", cmd_encode))
    application.add_handler(CommandHandler("decode", cmd_encode))
    application.add_handler(CommandHandler("b64", cmd_encode))

    # ── NEW: Network Reconnaissance ─────────────
    application.add_handler(CommandHandler("subdomain", cmd_subdomain))
    application.add_handler(CommandHandler("sub", cmd_subdomain))
    application.add_handler(CommandHandler("dns", cmd_dns))
    application.add_handler(CommandHandler("whois", cmd_whois))
    application.add_handler(CommandHandler("port", cmd_port))
    application.add_handler(CommandHandler("scan", cmd_port))

    # ── NEW: URL & QR Tools ─────────────────────
    application.add_handler(CommandHandler("urlscan", cmd_urlscan))
    application.add_handler(CommandHandler("url", cmd_urlscan))
    application.add_handler(CommandHandler("qr", cmd_qr))

    # ── NEW: Social & People Lookup ─────────────
    application.add_handler(CommandHandler("social", cmd_social))
    application.add_handler(CommandHandler("sociallookup", cmd_social))

    # ── NEW: Advanced Email Tools ─────────────────
    application.add_handler(CommandHandler("emailrecon", cmd_emailrecon))
    application.add_handler(CommandHandler("breach", cmd_breach))

    # ── NEW: Phone Number Analysis ────────────────
    application.add_handler(CommandHandler("number", cmd_number))

    # ── NEW: Image Intelligence ───────────────────
    application.add_handler(CommandHandler("reverse", cmd_reverse))
    application.add_handler(CommandHandler("face", cmd_face))

    # ── Nuclei Vulnerability Scanner ────────────────
    application.add_handler(CommandHandler("nuclei", cmd_nuclei))
    application.add_handler(CommandHandler("nscan", cmd_nuclei))

    # ── Proxy Management ─────────────────────────
    application.add_handler(CommandHandler("proxy", cmd_proxy))

    # ── Photo Handler (unified router) ─────────────
    application.add_handler(MessageHandler(filters.PHOTO & ~filters.UpdateType.EDITED, handle_photo_router))

    # ── Callback Query Handlers ─────────────────
    application.add_handler(CallbackQueryHandler(cmd_menu_callback, pattern=r"^menu:"))
    application.add_handler(CallbackQueryHandler(handle_ip_callback, pattern=r"^ip:"))
    application.add_handler(CallbackQueryHandler(handle_domain_callback, pattern=r"^domain:"))
    application.add_handler(CallbackQueryHandler(handle_username_callback, pattern=r"^user:"))
    application.add_handler(CallbackQueryHandler(handle_hash_lookup_callback, pattern=r"^malware:"))
    application.add_handler(CallbackQueryHandler(handle_email_callback, pattern=r"^email:"))
    application.add_handler(CallbackQueryHandler(handle_dork_callback, pattern=r"^dork:"))
    application.add_handler(CallbackQueryHandler(handle_vuln_callback, pattern=r"^vuln:"))
    application.add_handler(CallbackQueryHandler(handle_darkweb_callback, pattern=r"^darkweb:"))
    application.add_handler(CallbackQueryHandler(handle_news_callback, pattern=r"^news:"))
    application.add_handler(CallbackQueryHandler(handle_github_callback, pattern=r"^github:"))
    application.add_handler(CallbackQueryHandler(handle_password_callback, pattern=r"^pwd:"))
    application.add_handler(CallbackQueryHandler(handle_run_callback, pattern=r"^run:"))
    application.add_handler(CallbackQueryHandler(handle_hash_callback, pattern=r"^hash:"))
    application.add_handler(CallbackQueryHandler(handle_subdomain_callback, pattern=r"^sub:"))
    application.add_handler(CallbackQueryHandler(handle_dns_callback, pattern=r"^dns:"))
    application.add_handler(CallbackQueryHandler(handle_port_callback, pattern=r"^port:"))
    application.add_handler(CallbackQueryHandler(handle_urlscan_callback, pattern=r"^url:"))
    application.add_handler(CallbackQueryHandler(handle_qr_callback, pattern=r"^qr:"))
    application.add_handler(CallbackQueryHandler(handle_proxy_callback, pattern=r"^proxy:"))
    application.add_handler(CallbackQueryHandler(handle_whois_callback, pattern=r"^whois:"))
    application.add_handler(CallbackQueryHandler(handle_metadata_callback, pattern=r"^meta:"))
    application.add_handler(CallbackQueryHandler(handle_phone_callback, pattern=r"^phone:"))
    application.add_handler(CallbackQueryHandler(handle_reverse_callback, pattern=r"^rev:"))
    application.add_handler(CallbackQueryHandler(handle_face_callback, pattern=r"^face:"))
    application.add_handler(CallbackQueryHandler(handle_social_callback, pattern=r"^social:"))
    application.add_handler(CallbackQueryHandler(handle_emailrecon_callback, pattern=r"^erecon:"))
    application.add_handler(CallbackQueryHandler(handle_breach_callback, pattern=r"^breach:"))
    application.add_handler(CallbackQueryHandler(handle_number_callback, pattern=r"^num:"))
    application.add_handler(CallbackQueryHandler(handle_photo_callback, pattern=r"^photo:"))
    application.add_handler(CallbackQueryHandler(handle_nuclei_callback, pattern=r"^nuclei:"))

    # ── Unknown Command Handler ─────────────────
    application.add_handler(
        MessageHandler(filters.COMMAND & ~filters.UpdateType.EDITED, _unknown_command)
    )

    logger.info("All handlers registered.")


async def _unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Unknown command. Use /help to see available commands."
    )


async def post_init(application: Application) -> None:
    """Run after bot initialization."""
    logger.info("Bot is starting up...")
    init_database()
    logger.info("Database initialized.")

    # Load proxy configuration from environment
    from utils.proxy_manager import proxy_manager
    proxy_manager.load_from_env()
    if proxy_manager.pool_size > 0:
        logger.info(
            "Proxy pool loaded: %d proxy(ies), routing %s",
            proxy_manager.pool_size,
            "ENABLED" if proxy_manager.enabled else "DISABLED",
        )


async def post_shutdown(application: Application) -> None:
    """Run before bot shutdown."""
    logger.info("Bot is shutting down...")


def _should_use_webhook() -> bool:
    """Determine whether to use webhook mode.

    Webhook mode is activated when:
      - WEBHOOK_MODE env var is explicitly set to true, OR
      - HF_SPACE_HOST is detected (running on HuggingFace Spaces)
    """
    if os.getenv("WEBHOOK_MODE", "").lower() in ("true", "1", "yes"):
        return True
    if os.getenv("HF_SPACE_HOST"):
        return True
    return False


def main() -> None:
    """Main entry point — auto-detects environment and chooses polling vs webhook."""
    logger.info("=" * 50)
    logger.info("OSINT Investigation Bot - Starting")
    logger.info("=" * 50)

    token = config.TELEGRAM_BOT_TOKEN
    if not token or token == "YOUR_BOT_TOKEN_HERE":
        logger.error("TELEGRAM_TOKEN not set! Please configure it.")
        sys.exit(1)

    # Build application
    builder = Application.builder().token(token)

    # If TELEGRAM_API_URL is set, route ALL Telegram API calls through
    # a proxy (e.g. Cloudflare Worker).  Required on HF Spaces which
    # blocks direct access to api.telegram.org.
    api_url = os.getenv("TELEGRAM_API_URL", "").rstrip("/")
    if api_url:
        logger.info("Using custom Telegram API URL: %s", api_url)

        # httpx treats the colon in bot tokens (e.g. 8875460717:AAFF_...)
        # as a port separator and raises InvalidURL.  We subclass
        # HTTPXRequest and URL-encode the colon to %3A before httpx
        # ever sees the URL.  The Cloudflare Worker decodes it back.
        from telegram.request import HTTPXRequest

        class ProxyHTTPXRequest(HTTPXRequest):
            """HTTPXRequest that percent-encodes the colon in the bot token."""

            async def do_request(self, url, *args, **kwargs):
                # URL format: {base}/bot<token>/<method>[?params]
                # Encode the colon inside the token: bot123:ABC → bot123%3AABC
                idx = url.find("/bot")
                if idx != -1:
                    after = url[idx + 4:]          # skip "/bot"
                    slash = after.find("/")
                    if slash != -1:
                        url = (
                            url[: idx + 4]
                            + after[:slash].replace(":", "%3A")
                            + after[slash:]
                        )
                return await super().do_request(url, *args, **kwargs)

        request = ProxyHTTPXRequest(
            connect_timeout=30, read_timeout=60, write_timeout=60,
        )
        builder = (
            builder
            .base_url(api_url)
            .base_file_url(f"{api_url}/file")
            .request(request)
        )

    application = (
        builder
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # Register handlers
    register_handlers(application)

    # Choose run mode based on environment
    if _should_use_webhook():
        logger.info("Webhook mode detected (HF Spaces / WEBHOOK_MODE=true)")
        from webhook_server import run_webhook_server
        run_webhook_server(application)
    else:
        logger.info("Polling mode (default)")
        logger.info("Bot is running. Press Ctrl+C to stop.")
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )


if __name__ == "__main__":
    main()
