"""
Domain Reconnaissance Handler
DNS record lookup, basic WHOIS, security headers, and VirusTotal domain report.
"""

import asyncio
import socket
from datetime import datetime, timezone

import aiohttp
import dns.resolver

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html

from api_clients.virustotal_client import VirusTotalClient

# Client singleton
virustotal_client = VirusTotalClient()


async def cmd_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /domain <domain>.
    Resolves DNS records, checks VirusTotal, and attempts basic WHOIS.
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
            f"{bold('ℹ️ Usage:')} {code('/domain <name>')}\n\n"
            f"Example: {code('/domain example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_domain = sanitize_input(args[0].lower(), max_length=253)
    # Strip any leading protocol or path artifacts
    raw_domain = raw_domain.replace("http://", "").replace("https://", "").split("/")[0]

    if not validate_domain(raw_domain):
        await update.message.reply_text(
            f"❌ {bold('Invalid domain.')}\n\n"
            f"Please provide a valid domain name.\n"
            f"Example: {code('/domain example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    domain = raw_domain
    processing_msg = await update.message.reply_text(
        f"🔍 Investigating {code(domain)} …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        # Gather all data in parallel
        dns_results, vt_results, whois_results = await asyncio.gather(
            _query_dns_records(domain),
            _query_virustotal(domain),
            _query_whois(domain),
            return_exceptions=True,
        )

        result_text = _format_domain_report(
            domain=domain,
            dns=dns_results if not isinstance(dns_results, BaseException) else {"error": str(dns_results)},
            vt=vt_results if not isinstance(vt_results, BaseException) else {"error": str(vt_results)},
            whois=whois_results if not isinstance(whois_results, BaseException) else {"error": str(whois_results)},
        )

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

        log_query(user_id, "domain", query=domain, result="success")

    except Exception as exc:
        logger.error("Domain lookup failed for %s: %s", domain, exc)
        await processing_msg.edit_text(
            f"❌ Domain lookup failed for {code(domain)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "domain", query=domain, result=f"error: {exc}")


async def handle_domain_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the domain lookup module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "back":
        from handlers.start import cmd_menu_callback
        query.data = "menu:osint"
        await cmd_menu_callback(update, context)
        return

    await query.edit_message_reply_markup(reply_markup=None)


# ── Data Query Functions ───────────────────────────────────────────────────────

async def _query_dns_records(domain: str) -> dict:
    """
    Resolve DNS records using dnspython.
    Queries A, AAAA, MX, NS, TXT, and CNAME record types.
    """
    results: dict = {}

    record_types = {
        "A": "a",
        "AAAA": "aaaa",
        "MX": "mx",
        "NS": "ns",
        "TXT": "txt",
        "CNAME": "cname",
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for label, rtype in record_types.items():
        try:
            answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answer.rrset:
                records = []
                for rr in answer:
                    if label == "MX":
                        # MX records have preference + exchange
                        records.append(f"{rr.preference} {rr.exchange}")
                    else:
                        records.append(str(rr))
                results[label] = records
        except dns.resolver.NXDOMAIN:
            results[label] = None  # Domain does not exist
            break
        except dns.resolver.NoAnswer:
            results[label] = []
        except dns.resolver.LifetimeTimeout:
            results[label] = "TIMEOUT"
        except Exception as exc:
            results[label] = f"ERROR: {exc}"

    return results


async def _query_virustotal(domain: str) -> dict | None:
    """
    Query VirusTotal for domain reputation and analysis.
    Returns None if no API key is configured.
    """
    if not config.VIRUSTOTAL_API_KEY:
        return None

    data = await virustotal_client.lookup_domain(domain)
    return data if "error" not in data else None


async def _query_whois(domain: str) -> dict:
    """
    Attempt a basic WHOIS lookup using a free JSON WHOIS API.
    Falls back gracefully if the service is unavailable.
    """
    try:
        url = f"https://whoisjson.com/api/v1/whois?domain={domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"source": "whoisjson.com", **data}
    except Exception:
        pass

    # Fallback: try another free service
    try:
        url = f"https://whois-api.whoisxmlapi.com/api/v1?apiKey=demo&domainName={domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"source": "whoisxmlapi.com", **data}
    except Exception:
        pass

    return {"source": "unavailable", "error": "No WHOIS data available"}


# ── Report Formatter ───────────────────────────────────────────────────────────

def _format_domain_report(domain: str, dns: dict, vt: dict | None, whois: dict) -> str:
    """Build a comprehensive domain reconnaissance report."""

    lines = [
        f"{bold('🔍 Domain Reconnaissance Report')}",
        f"{'━' * 36}",
        "",
        f"📌 {bold('Target:')} {code(domain)}",
    ]

    # ── DNS Records ────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold('📡 DNS Records')}")

    if "error" in dns:
        lines.append(f"  ❌ {escape_html(dns['error'])}")
    else:
        # A Records
        a_records = dns.get("A")
        if a_records is None:
            lines.append(f"  ❌ Domain does not exist (NXDOMAIN)")
        elif isinstance(a_records, str):
            lines.append(f"  A: {escape_html(a_records)}")
        elif a_records:
            lines.append(f"  🌐 A Records ({len(a_records)}):")
            for rec in a_records[:8]:
                lines.append(f"    • {escape_html(rec)}")
            if len(a_records) > 8:
                lines.append(f"    … and {len(a_records) - 8} more")

        # AAAA Records
        aaaa = dns.get("AAAA")
        if aaaa:
            lines.append(f"  🌐 IPv6 ({len(aaaa)}):")
            for rec in aaaa[:5]:
                lines.append(f"    • {escape_html(rec)}")

        # MX Records
        mx = dns.get("MX")
        if mx:
            lines.append(f"  📧 MX Records ({len(mx)}):")
            for rec in mx[:5]:
                lines.append(f"    • {escape_html(rec)}")

        # NS Records
        ns = dns.get("NS")
        if ns:
            lines.append(f"  🔧 NS Records ({len(ns)}):")
            for rec in ns[:5]:
                lines.append(f"    • {escape_html(rec)}")

        # CNAME Records
        cname = dns.get("CNAME")
        if cname:
            lines.append(f"  🔀 CNAME: {escape_html(', '.join(str(c) for c in cname))}")

        # TXT Records
        txt = dns.get("TXT")
        if txt:
            lines.append(f"  📝 TXT Records ({len(txt)}):")
            for rec in txt[:6]:
                # Strip surrounding quotes from TXT records
                clean = str(rec).strip('"')
                # Truncate very long records (SPF, DKIM)
                if len(clean) > 80:
                    clean = clean[:77] + "…"
                lines.append(f"    • {escape_html(clean)}")
            if len(txt) > 6:
                lines.append(f"    … and {len(txt) - 6} more")

    # ── VirusTotal ─────────────────────────────────────────────────────────
    lines.append("")
    if vt:
        attrs = vt.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_date", 0)
        if last_analysis:
            dt = datetime.fromtimestamp(last_analysis, tz=timezone.utc)
            analysis_date = dt.strftime("%Y-%m-%d %H:%M UTC")
        else:
            analysis_date = "N/A"

        stats = attrs.get("last_analysis_stats", {})
        total_votes = attrs.get("total_votes", {})
        reputation = attrs.get("reputation", 0)
        categories = attrs.get("categories", {})

        # Format verdict from stats
        harmless = stats.get("harmless", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total_engines = harmless + malicious + suspicious + undetected

        # Verdict emoji
        if malicious > 0:
            verdict = f"🔴 {bold(f'{malicious}/{total_engines} malicious')}"
        elif suspicious > 0:
            verdict = f"🟠 {bold(f'{suspicious}/{total_engines} suspicious')}"
        else:
            verdict = f"🟢 {bold(f'{total_engines}/{total_engines} clean')}"

        # Community votes
        upvotes = total_votes.get("harmless", 0)
        downvotes = total_votes.get("malicious", 0)

        # Popular categories
        cat_values = list(set(categories.values()))[:5]
        cat_str = ", ".join(escape_html(c) for c in cat_values) if cat_values else "N/A"

        lines.append(f"{bold('🛡️ VirusTotal Report')}")
        lines.append(f"  📊 Verdict: {verdict}")
        lines.append(f"  👍 Community: {upvotes} up / {downvotes} down")
        lines.append(f"  📈 Reputation: {reputation}")
        lines.append(f"  🏷️ Categories: {cat_str}")
        lines.append(f"  📅 Last Analysis: {analysis_date}")

        # Threat tags
        tags = attrs.get("tags", [])
        if tags:
            lines.append(f"  ⚠️ Tags: {escape_html(', '.join(tags[:6]))}")
    else:
        lines.append(f"{bold('🛡️ VirusTotal Report')}")
        lines.append(f"  {italic('No VirusTotal API key configured — skipped.')}")

    # ── WHOIS ──────────────────────────────────────────────────────────────
    lines.append("")
    whois_source = whois.get("source", "")
    if "error" in whois and whois_source == "unavailable":
        lines.append(f"{bold('📋 WHOIS Registration')}")
        lines.append(f"  {italic('WHOIS data unavailable (no free service responding).')}")
    else:
        lines.append(f"{bold('📋 WHOIS Registration')}")

        registrant = whois.get("registrant", {})
        registrar = whois.get("registrar", "")
        creation = whois.get("creation_date", "")
        expiration = whois.get("expiration_date", "")
        updated = whois.get("updated_date", "")
        nameservers = whois.get("nameservers", [])
        status = whois.get("status", [])

        if registrar:
            lines.append(f"  🏢 Registrar: {escape_html(str(registrar))}")

        # Dates — handle both string and list formats
        def _format_date(d) -> str:
            if not d:
                return ""
            if isinstance(d, list):
                d = d[0] if d else ""
            s = str(d)
            # Truncate to readable date portion
            return s[:19].replace("T", " ")

        if creation:
            lines.append(f"  📅 Created: {_format_date(creation)}")
        if expiration:
            lines.append(f"  📅 Expires: {_format_date(expiration)}")
        if updated:
            lines.append(f"  📅 Updated: {_format_date(updated)}")

        if nameservers:
            ns_str = ", ".join(str(n) for n in nameservers[:4])
            lines.append(f"  🔧 Nameservers: {escape_html(ns_str)}")

        if status:
            # Show first 3 status codes
            status_str = ", ".join(str(s) for s in status[:3])
            lines.append(f"  📌 Status: {escape_html(status_str)}")

    # ── Footer ─────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 36}")
    lines.append(f"📡 Sources: dnspython + VirusTotal + WHOIS")
    lines.append(italic("Data sourced from public APIs. Verify before acting."))

    return "\n".join(lines)
