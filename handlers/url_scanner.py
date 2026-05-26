"""
URL Scanner Handler
Analyze URL safety, headers, and suspicious patterns.
"""

import asyncio
import logging
import re
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.validators import sanitize_input, validate_url
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, italic, escape_html
import aiohttp
from api_clients.virustotal_client import VirusTotalClient

vt = VirusTotalClient()

# Suspicious patterns
SUSPICIOUS_PATTERNS = [
    (r'@', "Contains @ symbol (credential phishing)"),
    (r'(?:login|signin|account|verify|secure|update|confirm|banking)\.', "Login/account-related subdomain"),
    (r'(?:\.xyz|\.tk|\.ml|\.ga|\.cf|\.gq)(?:\/|$)', "Free TLD (often abused)"),
    (r'IP address as URL', None),  # Checked separately
    (r':\d{4,5}(?:\/|$)', "Non-standard port"),
    (r'(?:data|javascript|vbscript):', "Dangerous URI scheme"),
    (r' double-extension|\.exe|\.scr|\.bat|\.cmd|\.ps1', "Executable file extension"),
    (r'(url=|redirect|goto=|next=|return=)', "URL redirect parameter"),
    (r'(admin|root|backup|test|staging|dev)\.', "Development/admin subdomain"),
    (r'(password|pwd|secret|key|token|api)\.', "Sensitive keyword in subdomain"),
]

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "🔒"),
    "x-frame-options": ("X-Frame-Options", "🪟"),
    "x-content-type-options": ("X-Content-Type", "📄"),
    "x-xss-protection": ("X-XSS-Protection", "🛡️"),
    "content-security-policy": ("CSP", "📋"),
    "referrer-policy": ("Referrer-Policy", "🔗"),
    "permissions-policy": ("Permissions-Policy", "⚙️"),
    "x-powered-by": ("X-Powered-By", "⚡"),
}


async def cmd_urlscan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    if not context.args:
        await update.message.reply_text(
            "🔗 <b>URL Scanner</b>\n\n"
            "Usage: <code>/urlscan https://example.com</code>\n\n"
            "Analyzes:\n"
            "• Security headers\n"
            "• Suspicious patterns\n"
            "• HTTP status & redirects\n"
            "• VirusTotal reputation"
        )
        return

    url = sanitize_input(" ".join(context.args))
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not validate_url(url):
        await update.message.reply_text("❌ Invalid URL format.")
        return

    msg = await update.message.reply_text(f"🔗 Scanning <code>{escape_html(url)}</code>...")

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # Run checks concurrently
    header_task = _check_headers(url)
    vt_task = _check_vt(url, domain)
    pattern_results = _check_patterns(url, parsed)

    headers_result = await header_task
    vt_result = await vt_task

    increment_usage(user_id)
    log_query(user_id, "urlscan", url)

    # Build output
    lines = [f"🔗 <b>URL Scan Report</b>\n"]
    lines.append(f"🌐 URL: <code>{escape_html(url)}</code>")
    lines.append(f"📍 Domain: <code>{escape_html(domain)}</code>\n")

    # HTTP Status
    if headers_result:
        status = headers_result.get("status", "?")
        status_emoji = "✅" if str(status).startswith("2") else "🟡" if str(status).startswith("3") else "🔴"
        lines.append(f"📡 HTTP Status: {status_emoji} {status}")

        redirect = headers_result.get("redirect")
        if redirect:
            lines.append(f"↪️ Redirects to: <code>{escape_html(redirect)}</code>")

        # Security Headers
        lines.append(f"\n<b>🛡️ Security Headers</b> ({headers_result.get('secure_count', 0)}/"
                     f"{headers_result.get('total_checked', 0)}):")
        for hdr_name, (display, emoji) in SECURITY_HEADERS.items():
            present = headers_result.get("headers", {}).get(hdr_name)
            if present:
                lines.append(f"  {emoji} {display}: ✅ <code>{escape_html(str(present)[:60])}</code>")
            else:
                lines.append(f"  {emoji} {display}: ❌ Missing")
    else:
        lines.append("📡 Could not reach the URL.")

    # Suspicious Patterns
    lines.append(f"\n<b>🔍 Pattern Analysis</b>")
    if pattern_results:
        for finding in pattern_results:
            lines.append(f"  ⚠️ {finding}")
    else:
        lines.append("  ✅ No suspicious patterns detected")

    # VirusTotal
    lines.append(f"\n<b>🛡️ VirusTotal</b>")
    if vt_result and not vt_result.get("error"):
        attrs = vt_result.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        harmless = last_analysis.get("harmless", 0)
        total = sum(last_analysis.values()) or 1

        if malicious > 0:
            lines.append(f"  🔴 <b>Dangerous!</b> {malicious}/{total} engines flagged")
        elif total - harmless - malicious > 0:
            lines.append(f"  🟡 {malicious}/{total} suspicious — {total - harmless - malicious} undetected")
        else:
            lines.append(f"  🟢 Clean — {harmless}/{total} engines say safe")
    else:
        error_msg = vt_result.get("error", "Not checked") if vt_result else "Not checked (no API key)"
        lines.append(f"  ℹ️ {error_msg}")

    await msg.edit_text("\n".join(lines))


async def _check_headers(url: str) -> dict:
    from utils.validators import is_url_safe_for_fetch
    if not is_url_safe_for_fetch(url):
        return {"error": "URL targets a private/internal address — blocked for security"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False
            ) as resp:
                secure_count = 0
                total_checked = len(SECURITY_HEADERS)
                headers_dict = {}
                for hdr_name in SECURITY_HEADERS:
                    val = resp.headers.get(hdr_name)
                    headers_dict[hdr_name] = val
                    if val:
                        secure_count += 1

                redirect = None
                if 300 <= resp.status < 400:
                    redirect = resp.headers.get("Location", "")

                return {
                    "status": resp.status,
                    "headers": headers_dict,
                    "secure_count": secure_count,
                    "total_checked": total_checked,
                    "redirect": redirect,
                }
    except Exception as e:
        return {"error": str(e)}


async def _check_vt(url: str, domain: str) -> dict:
    # Check URL on VirusTotal
    result = await vt.lookup_url(url)
    if not result.get("error"):
        return result
    # Fallback: check domain
    result = await vt.lookup_domain(domain)
    return result


def _check_patterns(url: str, parsed) -> list:
    findings = []
    for pattern, desc in SUSPICIOUS_PATTERNS:
        if desc is None:
            continue
        if re.search(pattern, url, re.IGNORECASE):
            findings.append(desc)

    # Check for IP-as-URL
    import ipaddress
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        findings.append("IP address used as URL (no domain name)")
    except ValueError:
        pass

    # Check URL length
    if len(url) > 200:
        findings.append(f"Very long URL ({len(url)} chars) — possible obfuscation")

    return findings


async def handle_urlscan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("Use /urlscan <url> to analyze a URL.")
