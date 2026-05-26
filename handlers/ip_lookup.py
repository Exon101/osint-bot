"""
IP Lookup Handler
Queries IPInfo, AbuseIPDB, and Shodan InternetDB for comprehensive IP intelligence.
Falls back to free ipapi.co when no API keys are configured.
"""

import asyncio
import aiohttp

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_ip
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html

from api_clients.ipinfo_client import IPInfoClient
from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.shodan_client import ShodanClient

# Client singletons
ipinfo_client = IPInfoClient()
abuseipdb_client = AbuseIPDBClient()
shodan_client = ShodanClient()


async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /ip <address>.
    Gathers geo info, abuse score, and open ports/vulnerabilities.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    # Parse arguments
    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('ℹ️ Usage:')} {code('/ip <address>')}\n\n"
            f"Example: {code('/ip 8.8.8.8')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_ip = sanitize_input(args[0], max_length=45)
    if not validate_ip(raw_ip):
        await update.message.reply_text(
            f"❌ {bold('Invalid IP address.')}\n\n"
            f"Please provide a valid IPv4 or IPv6 address.\n"
            f"Example: {code('/ip 8.8.8.8')}",
            parse_mode=ParseMode.HTML,
        )
        return

    # Send initial "searching" message
    processing_msg = await update.message.reply_text(
        f"🔍 Looking up {code(raw_ip)} …",
        parse_mode=ParseMode.HTML,
    )

    ip = raw_ip
    increment_usage(user_id)

    try:
        geo_data, abuse_data, shodan_data = await asyncio.gather(
            _query_geo(ip),
            _query_abuse(ip),
            _query_shodan_internet_db(ip),
        )

        result_text = _format_ip_report(ip, geo_data, abuse_data, shodan_data)

        # Build action buttons
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "ip", query=ip, result="success")

    except Exception as exc:
        logger.error("IP lookup failed for %s: %s", ip, exc)
        await processing_msg.edit_text(
            f"❌ Lookup failed for {code(ip)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "ip", query=ip, result=f"error: {exc}")


async def handle_ip_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the IP lookup module."""
    query = update.callback_query
    await query.answer()

    # Extract data from callback: "ip:<action>:<value>"
    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "back":
        # Return to OSINT menu
        from handlers.start import cmd_menu_callback
        query.data = "menu:osint"
        await cmd_menu_callback(update, context)
        return

    # Default: just remove the inline buttons
    await query.edit_message_reply_markup(reply_markup=None)


# ── Data Query Functions ───────────────────────────────────────────────────────

async def _query_geo(ip: str) -> dict:
    """
    Query IPInfo API for geo-location data.
    Falls back to free ipapi.co if no API key is configured.
    """
    if config.IPINFO_API_KEY:
        data = await ipinfo_client.lookup(ip)
        if "error" not in data:
            return {"source": "IPInfo", **data}

    # Free fallback: ipapi.co
    try:
        url = f"https://ipapi.co/{ip}/json/"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"source": "ipapi.co", **data}
                return {"error": f"ipapi.co HTTP {resp.status}"}
    except Exception as exc:
        logger.warning("ipapi.co fallback failed: %s", exc)
        return {"error": str(exc)}


async def _query_abuse(ip: str) -> dict | None:
    """Query AbuseIPDB for abuse confidence score. Returns None if no key."""
    if not config.ABUSEIPDB_API_KEY:
        return None

    data = await abuseipdb_client.check(ip)
    return data if "error" not in data else None


async def _query_shodan_internet_db(ip: str) -> dict | None:
    """Query Shodan InternetDB for open ports and known vulnerabilities. Always free."""
    data = await shodan_client.internet_db(ip)
    return data if "error" not in data else None


# ── Report Formatter ───────────────────────────────────────────────────────────

def _format_ip_report(ip: str, geo: dict, abuse: dict | None, shodan: dict | None) -> str:
    """Build a nicely formatted IP intelligence report."""

    lines = [
        f"{bold('🔍 IP Intelligence Report')}",
        f"{'━' * 30}",
        "",
        f"📌 {bold('Target:')} {code(ip)}",
    ]

    # ── Geo-Location ───────────────────────────────────────────────────────
    geo_source = geo.get("source", "Unknown")
    city = escape_html(geo.get("city", "Unknown"))
    region = escape_html(geo.get("region", ""))
    country = escape_html(geo.get("country_name", geo.get("country", "Unknown")))
    loc = geo.get("loc", "")
    timezone = escape_html(geo.get("timezone", ""))
    org = escape_html(geo.get("org", geo.get("as", "Unknown")))
    postal = geo.get("postal", "")
    asn = geo.get("asn", "")

    location_parts = [city]
    if region and region != city:
        location_parts.append(region)
    location_parts.append(country)
    location_str = ", ".join(p for p in location_parts if p and p != "Unknown")

    lines.append("")
    lines.append(f"{bold('🌍 Location')}")
    lines.append(f"  📍 {location_str or 'Unknown'}")
    if postal:
        lines.append(f"  📮 Postal: {escape_html(str(postal))}")
    if loc:
        lines.append(f"  🗺️ Coords: {escape_html(loc)}")
    if timezone:
        lines.append(f"  🕐 Timezone: {timezone}")

    # ISP / Org / ASN
    lines.append("")
    lines.append(f"{bold('🏢 Network')}")
    lines.append(f"  🏢 Org: {org or 'Unknown'}")
    if asn:
        lines.append(f"  🔗 ASN: {escape_html(str(asn))}")

    # ── AbuseIPDB ──────────────────────────────────────────────────────────
    lines.append("")
    if abuse:
        data = abuse.get("data", abuse)
        abuse_score = data.get("abuseConfidenceScore", "N/A")
        total_reports = data.get("totalReports", "N/A")
        last_reported = data.get("lastReportedAt", "N/A")
        categories = data.get("categories", [])
        country_of_reporter = data.get("countryCode", "N/A")

        # Format categories
        cat_map = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
            10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
            13: "VPN IP", 14: "Port Scan", 15: "Brute-Force",
            16: "Botnet", 17: "Exploited Host", 18: "Web Attack",
            19: "SSH Brute-Force", 20: "IoT Target", 21: "Compromised",
            22: "Tor Exit Node", 23: "Self-Destructing",
        }
        cat_names = [cat_map.get(c, f"Cat#{c}") for c in categories[:5]]
        cat_str = ", ".join(cat_names) if cat_names else "None"

        # Color-code the abuse score
        score = int(abuse_score) if isinstance(abuse_score, (int, float, str)) and str(abuse_score).isdigit() else 0
        if score >= 75:
            score_emoji = "🔴"
        elif score >= 50:
            score_emoji = "🟠"
        elif score >= 25:
            score_emoji = "🟡"
        else:
            score_emoji = "🟢"

        lines.append(f"{bold('⚠️ Abuse Intelligence')}")
        lines.append(f"  {score_emoji} Abuse Score: {bold(str(abuse_score))}/100")
        lines.append(f"  📊 Total Reports: {total_reports}")
        lines.append(f"  📅 Last Reported: {escape_html(str(last_reported)[:10]) if last_reported != 'N/A' else 'Never'}")
        lines.append(f"  🏷️ Categories: {escape_html(cat_str)}")
        lines.append(f"  🌍 Reporter Country: {escape_html(str(country_of_reporter))}")
    else:
        lines.append(f"{bold('⚠️ Abuse Intelligence')}")
        lines.append(f"  {italic('No AbuseIPDB key configured — skipped.')}")

    # ── Shodan InternetDB ──────────────────────────────────────────────────
    lines.append("")
    if shodan:
        ports = shodan.get("ports", [])
        vulns = shodan.get("vulns", [])
        hostnames = shodan.get("hostnames", [])
        cpes = shodan.get("cpes", [])
        tags = shodan.get("tags", [])

        lines.append(f"{bold('🔓 Shodan InternetDB')}")
        if ports:
            ports_str = ", ".join(str(p) for p in ports[:15])
            lines.append(f"  🚪 Open Ports ({len(ports)}): {escape_html(ports_str)}")
            if len(ports) > 15:
                lines.append(f"     … and {len(ports) - 15} more")
        else:
            lines.append(f"  🚪 Open Ports: None detected")

        if vulns:
            vulns_str = ", ".join(str(v) for v in vulns[:10])
            lines.append(f"  🐛 Vulns ({len(vulns)}): {escape_html(vulns_str)}")
            if len(vulns) > 10:
                lines.append(f"     … and {len(vulns) - 10} more")
        else:
            lines.append(f"  🐛 Vulnerabilities: None known")

        if hostnames:
            lines.append(f"  🏷️ Hostnames: {escape_html(', '.join(hostnames[:5]))}")
        if tags:
            lines.append(f"  🏷️ Tags: {escape_html(', '.join(tags[:8]))}")
    else:
        lines.append(f"{bold('🔓 Shodan InternetDB')}")
        lines.append(f"  {italic('No data available for this IP.')}")

    # ── Footer ─────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 30}")
    lines.append(f"📡 Sources: IPInfo/ipapi.co + AbuseIPDB + Shodan InternetDB")
    lines.append(italic("Data sourced from public APIs. Verify before acting."))

    return "\n".join(lines)
