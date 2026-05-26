"""
WHOIS Lookup Handler
"""

import logging
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.validators import sanitize_input, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, italic, link, escape_html
from database import increment_usage
import aiohttp


def _nav_keyboard() -> InlineKeyboardMarkup:
    """Build navigation keyboard for WHOIS results."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="whois:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="whois:back_main"),
        ],
    ])


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard shown when /whois is used without args."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 How WHOIS Works", callback_data="whois:help"),
            InlineKeyboardButton("🔧 Common Uses", callback_data="whois:uses"),
        ],
        [
            InlineKeyboardButton("🌍 Try Example", callback_data="whois:example"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="whois:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="whois:back_main"),
        ],
    ])


async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    if not context.args:
        await update.message.reply_text(
            "📋 <b>WHOIS Lookup</b>\n\n"
            "Retrieve domain registration details.\n\n"
            f"Usage: {code('/whois example.com')}\n\n"
            "<b>What you get:</b>\n"
            "• 📝 Registrar info\n"
            "• 📅 Creation / Expiry dates\n"
            "• 📍 Name servers\n"
            "• 📋 Domain status\n"
            "• 🏢 Registrant details",
            reply_markup=_help_keyboard(),
        )
        return

    domain = sanitize_input(context.args[0].lower().strip())
    domain = re.sub(r'^https?://', '', domain).split('/')[0]

    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain format.", reply_markup=_nav_keyboard())
        return

    msg = await update.message.reply_text(f"📋 Looking up WHOIS for <b>{escape_html(domain)}</b>...")

    result = None

    # Try whoisjson.com (free)
    try:
        url = f"https://whoisjson.com/api/v1/whois?domain={domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") != "error":
                        result = data
    except Exception:
        pass

    # Fallback: whoisxmlapi free tier
    if not result:
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get("WhoisRecord")
        except Exception:
            pass

    # Fallback: python-whois
    if not result:
        try:
            import pythonwhois
            whois_data = pythonwhois.get_whois(domain)
            if whois_data:
                result = _parse_pythonwhois(whois_data)
        except Exception:
            pass

    increment_usage(user_id)
    log_query(user_id, "whois", domain)

    if not result:
        await msg.edit_text(
            f"❌ Could not retrieve WHOIS data for <b>{escape_html(domain)}</b>.\n\n"
            "Possible reasons:\n"
            "• Domain doesn't exist\n"
            "• WHOIS privacy enabled\n"
            "• API rate limited",
            reply_markup=_nav_keyboard(),
        )
        return

    # Format
    lines = [f"📋 <b>WHOIS — {escape_html(domain)}</b>\n"]

    fields = [
        ("🌐 Domain Name", "domain_name"),
        ("📝 Registrar", "registrar"),
        ("📅 Created", "creation_date"),
        ("📅 Updated", "updated_date"),
        ("📅 Expires", "expiration_date"),
        ("📍 Name Servers", "name_servers"),
        ("📋 Status", "status"),
        ("📧 Registrant Email", "registrant_email"),
        ("🏢 Organization", "registrant_organization"),
        ("🌍 Country", "registrant_country"),
        ("🏷️ DNSSEC", "dnssec"),
    ]

    found_any = False
    for label, key in fields:
        val = result.get(key)
        if val is None:
            # Try nested lookup
            for nested_key in ["registrant", "registryData", "administrativeContact", "technicalContact"]:
                nested = result.get(nested_key, {})
                if isinstance(nested, dict):
                    val = nested.get(key)
                    if val:
                        break
        if val:
            found_any = True
            if isinstance(val, list):
                val = "\n  ".join(str(v) for v in val)
            lines.append(f"{label}: {escape_html(str(val))}")

    if not found_any:
        await msg.edit_text(
            "📋 WHOIS data returned but no readable fields found.\n"
            "Domain may have privacy protection enabled.",
            reply_markup=_nav_keyboard(),
        )
        return

    # Add action buttons for the domain
    domain_lower = domain.lower()
    action_keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 Open Domain", url=f"http://{domain_lower}"),
            InlineKeyboardButton("📊 VirusTotal", url=f"https://www.virustotal.com/gui/domain/{domain_lower}"),
        ],
        [
            InlineKeyboardButton("🔍 DNS Lookup", url=f"https://dnsdumpster.com"),
            InlineKeyboardButton("🔗 Shodan", url=f"https://www.shodan.io/host/{domain_lower}"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="whois:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="whois:back_main"),
        ],
    ])

    await msg.edit_text("\n".join(lines), reply_markup=action_keyboard)


async def handle_whois_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the WHOIS module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "help":
        help_text = (
            "📖 <b>How WHOIS Works</b>\n\n"
            "WHOIS is a query and response protocol that stores registered users "
            "or assignees of an Internet resource, such as a domain name or an IP address block.\n\n"
            "<b>Information includes:</b>\n"
            "• Domain registrar and registration dates\n"
            "• Domain expiration date\n"
            "• Name servers handling the domain\n"
            "• Contact information of the registrant\n"
            "• Domain status codes (e.g., clientDeleteProhibited)\n\n"
            "<b>Privacy:</b> Many registrars offer WHOIS privacy services that "
            "replace personal details with proxy information."
        )
        await query.edit_message_text(
            help_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔧 Common Uses", callback_data="whois:uses"),
                    InlineKeyboardButton("← Back", callback_data="whois:menu"),
                ],
            ]),
        )

    elif action == "uses":
        uses_text = (
            "🔧 <b>Common Uses</b>\n\n"
            "• <b>Threat Intel:</b> Identify recently registered malicious domains\n"
            "• <b>Asset Discovery:</b> Find domains owned by an organization\n"
            "• <b>Brand Protection:</b> Detect domain squatting or typosquatting\n"
            "• <b>Expiration Tracking:</b> Monitor when domains expire\n"
            "• <b>Infrastructure Mapping:</b> Identify shared registrars/hosting\n"
            "• <b>Phishing Investigation:</b> Check registration age & patterns\n\n"
            f"{italic('Tip: Combine with /dns, /subdomain, and /urlscan for full reconnaissance.')}"
        )
        await query.edit_message_text(
            uses_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 How WHOIS Works", callback_data="whois:help"),
                    InlineKeyboardButton("← Back", callback_data="whois:menu"),
                ],
            ]),
        )

    elif action == "example":
        await query.edit_message_text(
            "🌍 <b>Try It Out</b>\n\n"
            "Type a domain name to perform a WHOIS lookup:\n\n"
            f"{code('/whois google.com')}\n"
            f"{code('/whois github.com')}\n"
            f"{code('/whois example.com')}\n\n"
            f"{italic('Just type any domain name after /whois')}",
            reply_markup=_help_keyboard(),
        )

    elif action == "menu":
        await query.edit_message_text(
            "📋 <b>WHOIS Lookup</b>\n\n"
            "Retrieve domain registration details.\n\n"
            f"Usage: {code('/whois example.com')}\n\n"
            "<b>What you get:</b>\n"
            "• 📝 Registrar info\n"
            "• 📅 Creation / Expiry dates\n"
            "• 📍 Name servers\n"
            "• 📋 Domain status\n"
            "• 🏢 Registrant details",
            reply_markup=_help_keyboard(),
        )

    elif action == "back_osint":
        from handlers.start import cmd_menu_callback
        query.data = "menu:osint"
        await cmd_menu_callback(update, context)
        return

    elif action == "back_main":
        from handlers.start import cmd_menu_callback
        query.data = "menu:main"
        await cmd_menu_callback(update, context)
        return

    else:
        await query.edit_message_reply_markup(reply_markup=None)


def _parse_pythonwhois(data: dict) -> dict:
    """Convert pythonwhois output to a standard format."""
    result = {}
    if "registrant" in data:
        reg = data["registrant"]
        if isinstance(reg, dict):
            result["registrant_organization"] = reg.get("organization", {}).get("raw")
            result["registrant_country"] = reg.get("country", {}).get("raw")

    if "dates" in data:
        dates = data["dates"]
        result["creation_date"] = dates.get("created")
        result["updated_date"] = dates.get("updated")
        result["expiration_date"] = dates.get("expires")

    if "nameservers" in data:
        ns = data["nameservers"]
        if isinstance(ns, dict):
            result["name_servers"] = list(ns.get("raw", []))

    if "registrar" in data:
        result["registrar"] = data["registrar"].get("raw")

    if "status" in data:
        result["status"] = data["status"].get("raw", [])

    return result
