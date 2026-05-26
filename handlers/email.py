"""
Email OSINT Handler
Email validation, deliverability check via Hunter.io, disposable domain detection,
and breach history awareness using HaveIBeenPwned (educational).
"""

import re

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_email
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html

from api_clients.hunter_client import HunterClient

# Client singleton
hunter_client = HunterClient()

# ── Known Disposable / Temporary Email Domains ───────────────────────────────────
# Curated list of common disposable email providers.
# These domains offer throwaway email addresses that are unsuitable for
# professional or identity-trusted communication.
DISPOSABLE_DOMAINS: set[str] = {
    # Major disposable providers
    "guerrillamail.com", "guerrillamailblock.com", "sharklasers.com",
    "guerrillamailinfo.com", "grr.la", "dispostable.com", "mailinator.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "jetable.org", "mailcatch.com",
    "tempmail.com", "temp-mail.org", "throwaway.email", "trashmail.com",
    "mailexpire.com", "mintemail.com", "incognitomail.org", "maildrop.cc",
    "mailnesia.com", "mytemp.email", "receiveee.com", "tempinbox.com",
    "tempmailaddress.com", "fakeinbox.com", "trashymail.com", "tempail.com",
    "discard.email", "mailnull.com", "tempmailo.com", "harakirimail.com",
    "saynotospams.com", "maileater.com", "bugmenot.com", "filzmail.com",
    "mailshell.com", "mailzilla.org", "binkmail.com", "bobmail.info",
    "chammy.info", "devnullmail.com", "dfgh.net", "digitalsanctuary.com",
    "e4ward.com", "emailigo.de", "emailsensei.com", "emailtemporario.com.br",
    "fammix.com", "gishpuppy.com", "guerrillamail.biz", "hotpop.com",
    "koszmail.pl", "luckymail.org", "msa.minsmail.com", "nada.email",
    "objectmail.com", "proxymail.eu", "rcpt.at", "reallymymail.com",
    "recode.me", "regbypass.com", "rmqkr.net", "royal.net", "s0ny.net",
    "safersignup.de", "safetypost.de", "saynotospams.com", "schafmail.de",
    "selfdestructingmail.com", "sendspamhere.com", "sharklasers.com",
    "spamavert.com", "spambox.us", "spamfree24.org", "spamgourmet.com",
    "spamherelots.com", "spamhole.com", "spaminator.de", "spammotel.com",
    "spamthisplease.com", "supergreatmail.com", "tempmaildemo.com",
    "trash-mail.com", "trash2009.com", "trashymail.com", "tyldd.com",
    "uggsrock.com", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "willselfdestruct.com", "wuzupmail.net", "yopmail.com", "zoemail.org",
    # 10minutemail family
    "10minutemail.com", "10minutemail.net", "disposableemailaddresses.emailmiser.com",
    # Guerrilla mail alt domains
    "spam4.me", "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "spam4.me",
    # temp-mail.io family
    "tempail.com", "temp-mail.io", "temp-mail.org",
    # Additional popular services
    "ThrowAwayMail.com", "tmail.ws", "mailforspam.com", "safetymail.info",
    "instantemailaddress.com", "emaillime.com", "emailisvalid.com",
    "getnmail.com", "mailnow.com", "mustbedestroyed.com", "spambog.com",
    "emailigo.de", "trashymail.com", "wegwerfmail.de", "trashmail.me",
    "mytrashmail.com", "mailcatch.com", "inboxkitten.com",
    "tempmail.ninja", "burnermail.io", "guerrillamailblock.com",
}


def _is_disposable_domain(email: str) -> tuple[bool, str]:
    """
    Check if the email's domain is a known disposable / temporary email provider.

    Args:
        email: The full email address to check.

    Returns:
        Tuple of (is_disposable: bool, domain: str).
    """
    domain = email.lower().split("@")[-1].strip()
    # Also check subdomains by extracting just the last two parts
    domain_parts = domain.split(".")
    base_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

    is_disposable = (
        domain in DISPOSABLE_DOMAINS
        or base_domain in DISPOSABLE_DOMAINS
        or any(domain.endswith(f".{d}") for d in DISPOSABLE_DOMAINS if "." not in d)
    )
    return is_disposable, domain


def _extract_email_domain(email: str) -> str:
    """Extract and return the domain portion of an email address."""
    return email.lower().split("@")[-1].strip() if "@" in email else ""


def _classify_email_format(email: str) -> dict:
    """
    Perform a detailed analysis of the email address format.

    Checks:
    - Local part length and characters
    - Domain validity
    - Common business patterns (first.last, flast, etc.)

    Args:
        email: The email address to analyze.

    Returns:
        Dictionary with format analysis results.
    """
    local_part, domain = email.lower().rsplit("@", 1)

    analysis: dict = {
        "local_part": local_part,
        "domain": domain,
        "local_length": len(local_part),
        "has_plus_tag": "+" in local_part,
        "has_dots": "." in local_part,
        "has_numbers": any(c.isdigit() for c in local_part),
        "has_special_chars": bool(re.search(r'[^a-z0-9._%+\-]', local_part)),
    }

    # Detect common corporate email patterns
    name_pattern = "unknown"
    cleaned = local_part.split("+")[0]  # Strip plus addressing tags

    if "." in cleaned and not any(c.isdigit() for c in cleaned.replace(".", "")):
        parts = cleaned.split(".")
        if len(parts) == 2:
            name_pattern = "first.last"
        elif len(parts) == 3:
            name_pattern = "first.middle.last"
    elif "_" in cleaned and not any(c.isdigit() for c in cleaned.replace("_", "")):
        parts = cleaned.split("_")
        if len(parts) == 2:
            name_pattern = "first_last"
    elif re.match(r'^[a-z]{1,2}[a-z]{2,}$', cleaned):
        name_pattern = "possible initials"
    elif not any(c.isdigit() for c in cleaned) and len(cleaned) < 20:
        name_pattern = "possible single name"

    analysis["name_pattern"] = name_pattern

    return analysis


async def cmd_email(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /email <address>.
    Validates the email, checks deliverability via Hunter.io, detects disposable
    domains, and provides breach awareness information.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    # ── Parse arguments ─────────────────────────────────────────────────────
    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('ℹ️ Usage:')} {code('/email <address>')}\n\n"
            f"Gather OSINT data and breach info for an email address.\n\n"
            f"Example: {code('/email user@example.com')}\n\n"
            f"{bold('Features:')}\n"
            f"  ✅ Format validation\n"
            f"  ✅ Disposable domain detection\n"
            f"  ✅ Deliverability check (Hunter.io)\n"
            f"  ✅ Breach awareness (HaveIBeenPwned)",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_email = sanitize_input(args[0], max_length=254).lower()

    # ── Validate email format ───────────────────────────────────────────────
    if not validate_email(raw_email):
        await update.message.reply_text(
            f"❌ {bold('Invalid email format.')}\n\n"
            f"Please provide a valid email address.\n"
            f"Example: {code('/email user@example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    email = raw_email
    processing_msg = await update.message.reply_text(
        f"🔍 Investigating {code(email)} …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        # ── Run local checks ────────────────────────────────────────────────
        is_disposable, domain = _is_disposable_domain(email)
        format_analysis = _classify_email_format(email)

        # ── Query Hunter.io (if key available) ──────────────────────────────
        hunter_data = None
        if config.HUNTER_API_KEY:
            try:
                hunter_data = await hunter_client.email_verifier(email)
                if "error" in hunter_data:
                    hunter_data = None
                    logger.warning("Hunter.io returned error for %s", email)
            except Exception as exc:
                logger.warning("Hunter.io lookup failed for %s: %s", email, exc)
                hunter_data = None

        # ── Build the report ────────────────────────────────────────────────
        result_text = _format_email_report(
            email=email,
            is_disposable=is_disposable,
            domain=domain,
            format_analysis=format_analysis,
            hunter_data=hunter_data,
        )

        # ── Build keyboard ──────────────────────────────────────────────────
        hibp_url = f"https://haveibeenpwned.com/account/{email}"
        vt_url = f"https://www.virustotal.com/gui/search/{email}"

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔥 HaveIBeenPwned", url=hibp_url),
                InlineKeyboardButton("🛡️ VirusTotal Email", url=vt_url),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="email:back"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "email", query=email, result="success")

    except Exception as exc:
        logger.error("Email lookup failed for %s: %s", email, exc)
        await processing_msg.edit_text(
            f"❌ Email lookup failed for {code(email)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "email", query=email, result=f"error: {exc}")


async def handle_email_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the email lookup module."""
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


# ── Report Formatter ────────────────────────────────────────────────────────────

def _format_email_report(
    email: str,
    is_disposable: bool,
    domain: str,
    format_analysis: dict,
    hunter_data: dict | None,
) -> str:
    """
    Build a comprehensive email OSINT report.

    Args:
        email: The email address that was queried.
        is_disposable: Whether the domain is a known disposable provider.
        domain: The extracted domain name.
        format_analysis: Dictionary with local part analysis.
        hunter_data: Hunter.io verification response (or None).

    Returns:
        Formatted HTML string for the Telegram message.
    """
    lines = [
        f"{bold('📧 Email OSINT Report')}",
        f"{'━' * 30}",
        "",
        f"📌 {bold('Target:')} {code(email)}",
        f"🌐 {bold('Domain:')} {code(domain)}",
    ]

    # ── Format Validation ───────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold('✅ Format Validation')}")
    lines.append(f"  ✅ Syntax: {bold('Valid')}")
    lines.append(f"  📏 Local part length: {format_analysis['local_length']} characters")

    # Plus addressing (sub-addressing)
    if format_analysis["has_plus_tag"]:
        lines.append(f"  ➕ Sub-addressing: {bold('Detected')} (+ tag present)")
    else:
        lines.append(f"  ➕ Sub-addressing: Not detected")

    # Name pattern detection
    pattern = format_analysis.get("name_pattern", "unknown")
    if pattern != "unknown":
        pattern_label = pattern.replace("_", " ").title()
        lines.append(f"  👤 Likely pattern: {escape_html(pattern_label)}")

    # Character analysis
    char_types = []
    if format_analysis["has_dots"]:
        char_types.append("dots")
    if format_analysis["has_numbers"]:
        char_types.append("numbers")
    if format_analysis["has_special_chars"]:
        char_types.append("special chars")
    if char_types:
        lines.append(f"  🔤 Contains: {escape_html(', '.join(char_types))}")

    # ── Disposable Domain Check ─────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold('🚫 Disposable Domain Check')}")
    if is_disposable:
        lines.append(f"  ⚠️ {bold('WARNING: Disposable domain detected!')}")
        lines.append(
            "  " + italic(f"The domain {code(domain)} is a known temporary/disposable "
                         f"email provider. Email addresses from this domain are "
                         f"typically short-lived and not tied to real identities.")
        )
    else:
        lines.append(f"  ✅ {bold('Not disposable')} — Domain appears legitimate")

    # ── Hunter.io Verification ──────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold('📬 Deliverability (Hunter.io)')}")

    if hunter_data:
        result_data = hunter_data.get("data", {})
        email_result = result_data.get("result", "")
        score = result_data.get("score", 0)
        regexp = result_data.get("regexp", False)
        smtp_server = result_data.get("smtp_server", "")
        accept_all = result_data.get("accept_all", False)

        # Map Hunter.io result values to human-readable status
        result_map = {
            "deliverable": ("✅ Deliverable", "The mailbox exists and can receive mail."),
            "risky": ("🟡 Risky", "The mailbox exists but there are delivery risks."),
            "undeliverable": ("❌ Undeliverable", "The mailbox does not exist."),
            "unknown": ("❓ Unknown", "Could not verify deliverability."),
            "accept_all": ("🟡 Accept-All", "The server accepts all emails (may not verify)."),
        }

        status_emoji, status_desc = result_map.get(
            email_result,
            (f"❓ {escape_html(email_result)}", ""),
        )

        lines.append(f"  {status_emoji}")
        if status_desc:
            lines.append(f"  📝 {italic(status_desc)}")

        # Score bar
        if score is not None:
            score_clamped = max(0, min(100, int(score)))
            if score_clamped >= 80:
                score_emoji = "🟢"
            elif score_clamped >= 50:
                score_emoji = "🟡"
            else:
                score_emoji = "🔴"

            bar_filled = int(score_clamped / 100 * 15)
            bar = "█" * bar_filled + "░" * (15 - bar_filled)
            lines.append(f"  {score_emoji} Score: {bold(f'{score_clamped}/100')} [{bar}]")

        # SMTP details
        if smtp_server:
            lines.append(f"  📡 SMTP Server: {escape_html(smtp_server)}")

        if accept_all:
            lines.append(f"  ⚠️ Accept-All: {bold('Yes')} (may accept undeliverable mail)")

        # Regex validation
        if regexp:
            lines.append(f"  🔤 Syntax (Hunter): ✅ Valid")

        # Additional Hunter.io data
        sources = result_data.get("sources", [])
        if sources:
            lines.append(f"  📋 Found on {bold(str(len(sources)))} page(s)")

    else:
        hibp_note = link("haveibeenpwned.com", "https://haveibeenpwned.com")
        lines.append(f"  {italic('No Hunter.io API key configured.')}")
        lines.append(
            f"  {italic(f'Basic checks performed. For deliverability, visit {hibp_note}.')}"
        )

    # ── HaveIBeenPwned Awareness ────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold('🔥 Breach Awareness')}")

    hibp_link = link(
        f"Check {email} on HaveIBeenPwned",
        f"https://haveibeenpwned.com/account/{email}",
    )
    lines.append(f"  {hibp_link}")
    lines.append(
        "  " + italic("HaveIBeenPwned tracks data breaches. "
                     "Tap the link above to check manually.")
    )
    lines.append("")
    lines.append(
        "  💡 " + italic("Note: HIBP anonymous API requires k-anonymity via SHA-1 "
                        "password range queries. For email breach checks, "
                        "use their website or the paid API.")
    )

    # ── Footer ──────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 30}")
    lines.append(f"📡 Sources: Local analysis + Hunter.io + HaveIBeenPwned")
    lines.append(italic("Only use this information for authorized investigations."))

    return "\n".join(lines)
