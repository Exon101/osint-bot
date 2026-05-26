"""
Breach Data Lookup Handler
Check email addresses against known data breaches using HaveIBeenPwned API.
"""

import hashlib
import aiohttp

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_email
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard for breach lookup."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 About Breaches", callback_data="breach:about"),
            InlineKeyboardButton("🛡️ Stay Safe", callback_data="breach:Safety"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="breach:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="breach:back_main"),
        ],
    ])


async def cmd_breach(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /breach <email> — check for data breaches."""
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('🔥 Breach Data Lookup')}\n\n"
            f"Check if an email has been exposed in data breaches.\n\n"
            f"Usage: {code('/breach <email>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🔥 Search across 600+ known breaches\n"
            f"  📊 Breach details and compromised data types\n"
            f"  🕐 Timeline of exposures\n"
            f"  🔔 Notable breach information\n\n"
            f"Example: {code('/breach user@example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_email = sanitize_input(args[0], max_length=254).lower()

    if not validate_email(raw_email):
        await update.message.reply_text(
            f"❌ {bold('Invalid email format.')}\n\n"
            f"Please provide a valid email address.",
            parse_mode=ParseMode.HTML,
        )
        return

    email = raw_email
    processing_msg = await update.message.reply_text(
        f"🔍 Checking {code(email)} for breach data …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        breach_data = await _check_breaches(email)
        paste_data = await _check_pastes(email)
        result_text = _format_breach_report(email, breach_data, paste_data)

        hibp_url = f"https://haveibeenpwned.com/account/{email}"
        password_url = f"https://haveibeenpwned.com/Passwords"

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔥 View on HIBP", url=hibp_url),
                InlineKeyboardButton("🔐 Check Passwords", url=password_url),
            ],
            [
                InlineKeyboardButton("🛡️ 1Password Audit", url="https://security.1password.com/"),
                InlineKeyboardButton("🛡️ Firefox Monitor", url="https://monitor.firefox.com/"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="breach:back_osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="breach:back_main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "breach", email, "success")

    except Exception as exc:
        logger.error("Breach lookup failed for %s: %s", email, exc)
        await processing_msg.edit_text(
            f"❌ Breach check failed for {code(email)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "breach", email, f"error: {exc}")


async def handle_breach_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the breach module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>About Data Breaches</b>\n\n"
            "A data breach occurs when sensitive, protected, or confidential "
            "data is copied, transmitted, viewed, stolen, or used by an "
            "unauthorized person.\n\n"
            "<b>What gets leaked:</b>\n"
            "• 📧 Email addresses\n"
            "• 🔑 Passwords (hashed or plaintext)\n"
            "• 🏠 Home addresses\n"
            "• 📱 Phone numbers\n"
            "• 💳 Credit card numbers\n"
            "• 🔒 Security questions and answers\n"
            "• 📋 Personal documents\n\n"
            "<b>Key Statistics:</b>\n"
            "• Over 12 billion accounts have been breached\n"
            "• Average cost of a data breach: $4.45 million\n"
            "• 80% of breaches involve compromised credentials\n\n"
            f"{italic('Data sourced from HaveIBeenPwned.com — the most comprehensive breach database.')}"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🛡️ Stay Safe", callback_data="breach:Safety"),
                    InlineKeyboardButton("← Back", callback_data="breach:menu"),
                ],
            ]),
        )

    elif action == "Safety":
        safety_text = (
            "🛡️ <b>How to Stay Safe After a Breach</b>\n\n"
            "1️⃣ <b>Change your password immediately</b>\n"
            "  Use a unique, strong password for every account. "
            "  Use a password manager like Bitwarden or 1Password.\n\n"
            "2️⃣ <b>Enable Two-Factor Authentication (2FA)</b>\n"
            "  Add an extra layer of security to your accounts.\n"
            "  Prefer authenticator apps over SMS.\n\n"
            "3️⃣ <b>Check for credential stuffing</b>\n"
            "  If your password was leaked, attackers may try it on other sites.\n"
            "  Use unique passwords everywhere.\n\n"
            "4️⃣ <b>Monitor your accounts</b>\n"
            "  Watch for suspicious activity on breached accounts.\n"
            "  Set up breach notifications via HIBP.\n\n"
            "5️⃣ <b>Freeze your credit</b>\n"
            "  If financial data was leaked, consider freezing your credit report.\n\n"
            "6️⃣ <b>Be alert for phishing</b>\n"
            "  After a breach, attackers may send targeted phishing emails."
        )
        await query.edit_message_text(
            safety_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 About Breaches", callback_data="breach:about"),
                    InlineKeyboardButton("← Back", callback_data="breach:menu"),
                ],
            ]),
        )

    elif action == "menu":
        await query.edit_message_text(
            f"{bold('🔥 Breach Data Lookup')}\n\n"
            f"Check if an email has been exposed in data breaches.\n\n"
            f"Usage: {code('/breach <email>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🔥 Search across 600+ known breaches\n"
            f"  📊 Breach details and compromised data types\n"
            f"  🕐 Timeline of exposures\n\n"
            f"Example: {code('/breach user@example.com')}",
            parse_mode=ParseMode.HTML,
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


# ── Breach Check Engine ─────────────────────────────────────────────────────────

async def _check_breaches(email: str) -> list:
    """Check HIBP API for breaches associated with the email."""
    try:
        from config import config
        hibp_key = getattr(config, "HIBP_API_KEY", None)

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "User-Agent": "OSINT-Bot",
            "Accept": "application/json",
        }
        if hibp_key:
            headers["hibp-api-key"] = hibp_key

        params = {"truncateResponse": "false"}

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers, params=params,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data if isinstance(data, list) else []
                elif resp.status == 404:
                    return []
                elif resp.status == 429:
                    return [{"_rate_limited": True, "Name": "Rate limited", "Description": "Too many requests. Try again later."}]
                else:
                    return []
    except Exception as e:
        logger.warning("HIBP breach check failed: %s", e)
        return []


async def _check_pastes(email: str) -> list:
    """Check HIBP API for pastes containing the email."""
    try:
        from config import config
        hibp_key = getattr(config, "HIBP_API_KEY", None)

        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {
            "User-Agent": "OSINT-Bot",
            "Accept": "application/json",
        }
        if hibp_key:
            headers["hibp-api-key"] = hibp_key

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data if isinstance(data, list) else []
                elif resp.status == 404:
                    return []
                else:
                    return []
    except Exception as e:
        logger.warning("HIBP paste check failed: %s", e)
        return []


# ── Report Formatter ────────────────────────────────────────────────────────────

def _format_breach_report(email: str, breaches: list, pastes: list) -> str:
    """Build breach data report."""
    lines = [
        f"{bold('🔥 Breach Data Report')}",
        f"{'━' * 30}",
        "",
        f"📌 {bold('Target:')} {code(email)}",
    ]

    if breaches and not (len(breaches) == 1 and breaches[0].get("_rate_limited")):
        # Sort breaches by date (newest first)
        sorted_breaches = sorted(
            breaches,
            key=lambda b: b.get("BreachDate", "0000"),
            reverse=True,
        )

        lines.append(f"⚠️ {bold(f'Found in {len(sorted_breaches)} breach(es)!')}")

        for breach in sorted_breaches[:15]:  # Limit to 15
            name = breach.get("Name", "Unknown")
            domain = breach.get("Domain", "")
            date = breach.get("BreachDate", "")
            description = breach.get("Description", "")[:120]
            data_classes = breach.get("DataClasses", [])
            is_verified = breach.get("IsVerified", False)
            is_sensitive = breach.get("IsSensitive", False)
            is_spam_list = breach.get("IsSpamList", False)
            logo_url = breach.get("LogoPath", "")

            lines.append("")
            status = "✅ Verified" if is_verified else "❓ Unverified"
            if is_sensitive:
                status += " | 🔒 Sensitive"
            if is_spam_list:
                status += " | 📬 Spam List"

            lines.append(f"  {bold(f'💀 {name}')}")
            lines.append(f"  🌐 {escape_html(domain)}")
            lines.append(f"  📅 Breach Date: {escape_html(date)}")
            lines.append(f"  📋 Status: {status}")
            if data_classes:
                data_str = ", ".join(str(d) for d in data_classes[:8])
                lines.append(f"  📦 Compromised: {escape_html(data_str)}")
            if description:
                lines.append(f"  📝 {escape_html(description)}")

        if len(sorted_breaches) > 15:
            lines.append(f"\n  ... and {len(sorted_breaches) - 15} more breach(es)")

    elif breaches and breaches[0].get("_rate_limited"):
        lines.append("")
        lines.append(f"  ⚠️ {bold('Rate Limited')}")
        lines.append(f"  {italic('HIBP API rate limit reached. Try again in a few minutes.')}")
        lines.append(
            f"  👉 {link('Check manually on HIBP', f'https://haveibeenpwned.com/account/{email}')}"
        )
    else:
        lines.append("")
        lines.append(f"  ✅ {bold('No breaches found!')}")
        lines.append(
            "  " + italic("This email was not found in any known data breaches. "
                         "This is good news, but remember to use unique passwords and 2FA.")
        )

    # Paste info
    if pastes:
        lines.append("")
        lines.append(f"📋 {bold(f'Found in {len(pastes)} paste(s):')}")
        for paste in pastes[:5]:
            source = paste.get("Source", "Unknown")
            title = paste.get("Title", "No title")
            date = paste.get("Date", "")
            lines.append(
                f"  • {escape_html(source)} — {escape_html(title[:50])}"
                f" ({escape_html(date[:10])})"
            )

    # Recommendations
    lines.append("")
    lines.append(f"{'━' * 30}")
    if breaches and not (len(breaches) == 1 and breaches[0].get("_rate_limited")):
        lines.append(f"🛡️ {bold('Recommended Actions:')}")
        lines.append(f"  1. Change your password on breached services immediately")
        lines.append(f"  2. If you reuse passwords, change them on ALL accounts")
        lines.append(f"  3. Enable 2FA on all important accounts")
        lines.append(f"  4. Monitor for suspicious emails and login attempts")
    else:
        lines.append(f"💡 {italic('Stay safe: use unique passwords, enable 2FA, and monitor your accounts.')}")

    lines.append(f"\n📡 Source: HaveIBeenPwned.com")

    return "\n".join(lines)
