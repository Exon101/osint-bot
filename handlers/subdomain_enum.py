"""
Subdomain Enumeration Handler
Uses Certificate Transparency logs (crt.sh) and other free APIs.
"""

import asyncio
import logging
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from config import config
from utils.validators import sanitize_input, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, escape_html
import aiohttp


async def cmd_subdomain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Wait a minute.")
        return

    if not context.args:
        text = (
            "🔍 <b>Subdomain Enumeration</b>\n\n"
            "Usage: <code>/subdomain example.com</code>\n\n"
            "Uses Certificate Transparency logs and\n"
            "free APIs to discover subdomains.\n\n"
            "⚠️ For authorized security research only."
        )
        await update.message.reply_text(text)
        return

    domain = sanitize_input(context.args[0].lower().strip())
    domain = re.sub(r'^https?://', '', domain).split('/')[0]

    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain format.")
        return

    msg = await update.message.reply_text(f"🔍 Enumerating subdomains for <b>{escape_html(domain)}</b>...")

    all_subdomains = set()

    # Source 1: crt.sh (Certificate Transparency)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower().rstrip(".")
                            if n.endswith(f".{domain}") or n == domain:
                                if "*" not in n:
                                    all_subdomains.add(n)
    except Exception as e:
        logger.warning(f"crt.sh failed: {e}")

    # Source 2: Omnisint sonar
    try:
        url = f"https://sonar.omnisint.io/subdomains/{domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list):
                        for s in data:
                            s = s.strip().lower().rstrip(".")
                            if "*" not in s:
                                all_subdomains.add(s)
    except Exception as e:
        logger.warning(f"sonar failed: {e}")

    # Remove main domain from results
    all_subdomains.discard(domain)

    increment_usage(user_id)
    log_query(user_id, "subdomain", domain, f"found_{len(all_subdomains)}")

    if not all_subdomains:
        await msg.edit_text(f"🔍 No subdomains found for <b>{escape_html(domain)}</b>.\n\n"
                           "This could mean:\n• No certificates issued for subdomains\n"
                           "• Domain is new\n• APIs are temporarily unavailable")
        return

    # Categorize subdomains
    categories = {
        "🌐 Web (www/api/app)": [],
        "📧 Email (mail/smtp)": [],
        "🔧 Dev (dev/staging/test)": [],
        "☁️ Cloud (cdn/cloud/s3)": [],
        "🔐 Auth (auth/login/sso)": [],
        "📊 Analytics (stats/tracking)": [],
        "📦 Other": [],
    }

    web_kw = ("www", "api", "app", "web", "portal", "dashboard", "admin", "panel")
    mail_kw = ("mail", "smtp", "pop", "imap", "mx")
    dev_kw = ("dev", "staging", "test", "qa", "uat", "ci", "cd", "build", "jenkins", "git")
    cloud_kw = ("cdn", "cloud", "s3", "azure", "aws", "gcp", "storage", "static", "media")
    auth_kw = ("auth", "login", "sso", "oauth", "id", "identity", "account")
    stats_kw = ("stats", "tracking", "analytics", "monitor", "grafana", "prometheus", "kibana")

    for sub in sorted(all_subdomains):
        prefix = sub.replace(f".{domain}", "")
        categorized = False
        for cat_name, keywords in [
            ("🌐 Web (www/api/app)", web_kw),
            ("📧 Email (mail/smtp)", mail_kw),
            ("🔧 Dev (dev/staging/test)", dev_kw),
            ("☁️ Cloud (cdn/cloud/s3)", cloud_kw),
            ("🔐 Auth (auth/login/sso)", auth_kw),
            ("📊 Analytics (stats/tracking)", stats_kw),
        ]:
            if any(kw in prefix for kw in keywords):
                categories[cat_name].append(sub)
                categorized = True
                break
        if not categorized:
            categories["📦 Other"].append(sub)

    # Build response
    lines = [f"🔍 <b>Subdomain Enumeration — {escape_html(domain)}</b>\n"]
    lines.append(f"📊 <b>Total unique subdomains</b>: {len(all_subdomains)}\n")

    total_displayed = 0
    for cat, subs in categories.items():
        if subs:
            lines.append(f"<b>{cat}</b> ({len(subs)}):")
            for s in subs[:10]:
                lines.append(f"  • <code>{s}</code>")
            if len(subs) > 10:
                lines.append(f"  ... and {len(subs) - 10} more")
            lines.append("")
            total_displayed += len(subs)

    # Show top 50 unique subdomains in a code block if > 50
    if len(all_subdomains) > 50:
        lines.append(f"\n<code>{chr(10).join(sorted(all_subdomains)[:50])}</code>")
        if len(all_subdomains) > 50:
            lines.append(f"\n<i>... and {len(all_subdomains) - 50} more</i>")

    await msg.edit_text("\n".join(lines))


async def handle_subdomain_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    # Future: export, drill-down, etc.
    await query.edit_message_text("Subdomain enumeration complete. Use /subdomain <domain> to search again.")
