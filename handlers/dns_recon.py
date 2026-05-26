"""
DNS Reconnaissance Handler
Full DNS record lookup using dnspython + DNS-over-HTTPS fallback.
"""

import asyncio
import logging
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.validators import sanitize_input, validate_domain, validate_ip
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, escape_html
import aiohttp

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]


async def cmd_dns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    if not context.args:
        # Show record type selection
        buttons = []
        row = []
        for rt in RECORD_TYPES:
            row.append(InlineKeyboardButton(rt, callback_data=f"dns:help:{rt}"))
            if len(row) == 3:
                buttons.append(row)
                row = []
        if row:
            buttons.append(row)
        buttons.append([InlineKeyboardButton("📚 All Record Types", callback_data="dns:help:ALL")])

        text = (
            "🌐 <b>DNS Reconnaissance</b>\n\n"
            "Usage:\n"
            "  <code>/dns example.com</code> — All records\n"
            "  <code>/dns example.com A</code> — Specific type\n"
            "  <code>/dns example.com MX</code> — Mail records\n"
            "  <code>/dns 8.8.8.8 PTR</code> — Reverse DNS\n\n"
            "Supported types: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA"
        )
        await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(buttons))
        return

    target = sanitize_input(context.args[0].lower().strip())
    record_type = context.args[1].upper() if len(context.args) > 1 else "ALL"

    msg = await update.message.reply_text(f"🌐 Resolving DNS for <b>{escape_html(target)}</b>...")

    results = {}

    if record_type == "ALL":
        types_to_check = RECORD_TYPES
    elif record_type == "PTR" and validate_ip(target):
        types_to_check = ["PTR"]
    else:
        types_to_check = [record_type]

    # Method 1: dnspython
    if HAS_DNSPYTHON:
        for rt in types_to_check:
            try:
                if rt == "PTR" and validate_ip(target):
                    rev_name = dns.reversename.from_address(target)
                    answers = dns.resolver.resolve(rev_name, "PTR")
                    results[rt] = [(str(r).rstrip("."), None) for r in answers]
                elif rt == "MX":
                    answers = dns.resolver.resolve(target, rt)
                    results[rt] = [(str(r.exchange).rstrip("."), r.preference) for r in answers]
                elif rt == "SRV":
                    answers = dns.resolver.resolve(target, rt)
                    results[rt] = [(str(r.target).rstrip("."), f"port {r.port}, pri {r.priority}") for r in answers]
                elif rt == "CAA":
                    answers = dns.resolver.resolve(target, rt)
                    results[rt] = [(r.value.decode() if isinstance(r.value, bytes) else str(r.value), None) for r in answers]
                else:
                    answers = dns.resolver.resolve(target, rt)
                    results[rt] = [(str(r).rstrip("."), None) for r in answers]
            except dns.resolver.NXDOMAIN:
                results[rt] = "NXDOMAIN — Domain does not exist"
            except dns.resolver.NoAnswer:
                results[rt] = "No records found"
            except dns.resolver.NoNameservers:
                results[rt] = "No nameservers available"
            except Exception as e:
                results[rt] = f"Error: {str(e)[:80]}"
    else:
        # Fallback: DNS-over-HTTPS
        for rt in types_to_check:
            results[rt] = await _doh_lookup(target, rt)

    increment_usage(user_id)
    log_query(user_id, "dns", f"{target}/{record_type}")

    # Format output
    lines = [f"🌐 <b>DNS Reconnaissance — {escape_html(target)}</b>\n"]

    for rt in types_to_check:
        lines.append(f"<b>{rt} Records:</b>")
        data = results.get(rt)
        if isinstance(data, str):
            lines.append(f"  {data}")
        elif isinstance(data, list) and data:
            for val, extra in data:
                if extra:
                    lines.append(f"  • {code(val)} — {escape_html(str(extra))}")
                else:
                    lines.append(f"  • {code(val)}")
        else:
            lines.append("  (none found)")
        lines.append("")

    await msg.edit_text("\n".join(lines))


async def _doh_lookup(domain: str, record_type: str) -> list | str:
    """DNS-over-HTTPS via Google."""
    try:
        url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    if not answers:
                        return "No records found"
                    return [(a.get("data", ""), f"TTL: {a.get('ttl', '?')}") for a in answers]
                return f"HTTP {resp.status}"
    except Exception as e:
        return f"Error: {str(e)[:80]}"


async def handle_dns_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data.split(":")
    if len(data) == 3 and data[1] == "help":
        rt = data[2]
        await query.edit_message_text(
            f"📋 <b>{rt} Record Type</b>\n\n"
            f"{_record_descriptions().get(rt, 'DNS record type')}\n\n"
            f"Usage: <code>/dns domain.com {rt}</code>"
        )


def _record_descriptions() -> dict:
    return {
        "A": "IPv4 address mapping",
        "AAAA": "IPv6 address mapping",
        "MX": "Mail exchange servers (email routing)",
        "NS": "Authoritative nameservers",
        "TXT": "Text records (SPF, DKIM, verification)",
        "CNAME": "Canonical name (domain alias)",
        "SOA": "Start of Authority (primary NS info)",
        "SRV": "Service location (port + host)",
        "CAA": "Certificate Authority Authorization",
        "PTR": "Pointer record (reverse DNS)",
        "ALL": "Query all record types at once",
    }
