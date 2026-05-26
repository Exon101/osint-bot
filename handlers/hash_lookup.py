"""
Hash Lookup Handler
Queries VirusTotal for file hash intelligence.
Supports MD5, SHA-1, SHA-256, and SHA-512 detection ratios, file metadata,
and related threat information.
"""

from datetime import datetime, timezone

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_hash
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html

from api_clients.virustotal_client import VirusTotalClient

# Client singleton
virustotal_client = VirusTotalClient()


async def cmd_hash_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /malware <hash>.
    Look up a file hash on VirusTotal and present the detection report.
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
            f"{bold('ℹ️ Usage:')} {code('/malware <hash>')}\n\n"
            f"Check a file hash against VirusTotal.\n\n"
            f"{bold('Supported formats:')}\n"
            f"  • MD5     — 32 hex characters\n"
            f"  • SHA-1   — 40 hex characters\n"
            f"  • SHA-256 — 64 hex characters\n"
            f"  • SHA-512 — 128 hex characters\n\n"
            f"Example: {code('/malware a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_hash = sanitize_input(args[0], max_length=128)

    # ── Validate hash format ────────────────────────────────────────────────
    hash_type = validate_hash(raw_hash)
    if not hash_type:
        await update.message.reply_text(
            f"❌ {bold('Invalid hash format.')}\n\n"
            f"Please provide a valid file hash in one of these formats:\n"
            f"  • MD5     — 32 hex characters\n"
            f"  • SHA-1   — 40 hex characters\n"
            f"  • SHA-256 — 64 hex characters\n"
            f"  • SHA-512 — 128 hex characters\n\n"
            f"Example: {code('/malware a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')}",
            parse_mode=ParseMode.HTML,
        )
        return

    file_hash = raw_hash.strip().lower()
    hash_preview = file_hash[:16] + ("…" if len(file_hash) > 16 else "")
    processing_msg = await update.message.reply_text(
        f"🔍 Scanning {code(hash_preview)} ({hash_type}) on VirusTotal …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    # ── Check for API key ───────────────────────────────────────────────────
    if not config.VIRUSTOTAL_API_KEY:
        logger.warning("Hash lookup attempted without VirusTotal API key by user %s", user_id)
        register_link = link("VirusTotal registration page", "https://www.virustotal.com/gui/join-us")
        await processing_msg.edit_text(
            f"{bold('❌ VirusTotal API Key Not Configured')}\n\n"
            f"VirusTotal requires a free API key to perform hash lookups.\n\n"
            f"{bold('How to get a free key:')}\n"
            f"  1. Visit the {register_link}\n"
            f"  2. Create a free account\n"
            f"  3. Navigate to {link('API Settings', 'https://www.virustotal.com/gui/my-apikey')}\n"
            f"  4. Copy your API key and set the {code('VIRUSTOTAL_API_KEY')} environment variable\n\n"
            f"{italic('Free tier: 500 requests/day')}\n\n"
            f"Hash: {code(file_hash)} ({hash_type})",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        log_query(user_id, "malware", query=file_hash, result="error: no_api_key")
        return

    # ── Query VirusTotal ────────────────────────────────────────────────────
    try:
        vt_data = await virustotal_client.lookup_file(file_hash)

        if "error" in vt_data:
            error_msg = vt_data["error"]
            # Special handling for hash not found
            if "not found" in error_msg.lower():
                result_text = _format_hash_not_found(file_hash, hash_type)
            else:
                result_text = (
                    f"❌ {bold('VirusTotal Error')}\n\n"
                    f"Unable to look up {code(hash_preview)}.\n\n"
                    f"Error: {escape_html(error_msg)}"
                )
                log_query(user_id, "malware", query=file_hash, result=f"error: {error_msg}")
        else:
            result_text = _format_hash_report(file_hash, hash_type, vt_data)
            log_query(user_id, "malware", query=file_hash, result="success")

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "🌐 Open in VirusTotal",
                    url=f"https://www.virustotal.com/gui/file/{file_hash}",
                ),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="hash:back"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

    except Exception as exc:
        logger.error("Hash lookup failed for %s: %s", file_hash, exc)
        await processing_msg.edit_text(
            f"❌ Hash lookup failed for {code(hash_preview)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "malware", query=file_hash, result=f"error: {exc}")


async def handle_hash_lookup_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the hash lookup module."""
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

    # Default: remove inline buttons
    await query.edit_message_reply_markup(reply_markup=None)


# ── Report Formatters ───────────────────────────────────────────────────────────

def _format_hash_report(file_hash: str, hash_type: str, vt_data: dict) -> str:
    """
    Build a comprehensive VirusTotal file hash analysis report.

    Args:
        file_hash: The file hash that was queried.
        hash_type: Detected hash type (MD5/SHA-1/SHA-256/SHA-512).
        vt_data: Raw JSON response from the VirusTotal API.

    Returns:
        Formatted HTML string for the Telegram message.
    """
    data = vt_data.get("data", {})
    attrs = data.get("attributes", {})

    # ── Last Analysis Date ──────────────────────────────────────────────────
    last_analysis_ts = attrs.get("last_analysis_date", 0)
    if last_analysis_ts:
        last_analysis_dt = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
        last_analysis = last_analysis_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        last_analysis = "Never"

    # First submission date
    first_seen_ts = attrs.get("first_submission_date", 0)
    if first_seen_ts:
        first_seen_dt = datetime.fromtimestamp(first_seen_ts, tz=timezone.utc)
        first_seen = first_seen_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        first_seen = "Unknown"

    # ── Detection Stats ─────────────────────────────────────────────────────
    stats = attrs.get("last_analysis_stats", {})
    harmless = stats.get("harmless", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    timeout_count = stats.get("timeout", 0)
    undetected = stats.get("undetected", 0)
    type_unsupported = stats.get("type-unsupported", 0)
    total_engines = (
        harmless + malicious + suspicious + timeout_count
        + undetected + type_unsupported
    )

    # Verdict with emoji
    if malicious > 0:
        verdict_emoji = "🔴"
        verdict_label = f"{malicious}/{total_engines} malicious"
    elif suspicious > 0:
        verdict_emoji = "🟠"
        verdict_label = f"{suspicious}/{total_engines} suspicious"
    else:
        verdict_emoji = "🟢"
        verdict_label = f"{total_engines}/{total_engines} clean"

    # ── File Information ────────────────────────────────────────────────────
    # Meaningful names (file names associated with this hash)
    names = attrs.get("names", [])
    meaningful_names = [n for n in names if n and not n.startswith("~")][:8]

    # File type / description
    type_description = attrs.get("type_description", "Unknown")
    type_tag = attrs.get("type_tag", "")

    # File size
    size = attrs.get("size", 0)
    size_str = _format_file_size(size) if size else "Unknown"

    # ── Reputation & Community ───────────────────────────────────────────────
    reputation = attrs.get("reputation", 0)
    total_votes = attrs.get("total_votes", {})
    community_malicious = total_votes.get("malicious", 0)
    community_harmless = total_votes.get("harmless", 0)

    # ── Popular Threat Tags ──────────────────────────────────────────────────
    popular_threat_names = []
    for _, tag_data in attrs.get("popular_threat_classification", {}).get(
        "suggested_threat_label", ""
    ).items():
        if isinstance(tag_data, str) and tag_data:
            popular_threat_names.append(tag_data)

    # Also get the overall suggested label
    suggested_label = attrs.get("popular_threat_classification", {}).get(
        "suggested_threat_label", ""
    )

    # ── Build Report ────────────────────────────────────────────────────────
    lines = [
        f"{bold('🦠 Malware Analysis Report')}",
        f"{'━' * 34}",
        "",
        f"📌 {bold('Hash:')} {code(file_hash)}",
        f"🏷️ {bold('Type:')} {hash_type}",
    ]

    # Verdict
    lines.append("")
    lines.append(f"{bold('📊 Detection Verdict')}")
    lines.append(f"  {verdict_emoji} {bold(verdict_label)}")

    if malicious > 0:
        lines.append(f"  ⚠️ {bold(str(malicious))} engine(s) detected this file as malicious")
    elif suspicious > 0:
        lines.append(f"  ⚠️ {bold(str(suspicious))} engine(s) flagged this file as suspicious")

    # Stats breakdown
    lines.append("")
    lines.append(f"{bold('📈 Engine Breakdown')}")
    if total_engines > 0:
        if malicious > 0:
            bar_len = min(int(malicious / total_engines * 15), 15)
            lines.append(f"  🔴 Malicious:   {malicious:>3}  {'█' * bar_len}")
        if suspicious > 0:
            bar_len = min(int(suspicious / total_engines * 15), 15)
            lines.append(f"  🟠 Suspicious:  {suspicious:>3}  {'█' * bar_len}")
        if harmless > 0:
            bar_len = min(int(harmless / total_engines * 15), 15)
            lines.append(f"  🟢 Harmless:    {harmless:>3}  {'█' * bar_len}")
        if undetected > 0:
            bar_len = min(int(undetected / total_engines * 15), 15)
            lines.append(f"  ⬜ Undetected:  {undetected:>3}  {'█' * bar_len}")
        if timeout_count > 0:
            lines.append(f"  ⏱️ Timeout:     {timeout_count:>3}")
        if type_unsupported > 0:
            lines.append(f"  ❓ Unsupported: {type_unsupported:>3}")

    # File information
    lines.append("")
    lines.append(f"{bold('📄 File Information')}")
    lines.append(f"  📦 Type: {escape_html(type_description or 'Unknown')}")
    if type_tag:
        lines.append(f"  🏷️ Tag: {escape_html(type_tag)}")
    lines.append(f"  📏 Size: {escape_html(str(size_str))}")
    lines.append(f"  📅 First Seen: {escape_html(first_seen)}")
    lines.append(f"  📅 Last Analysis: {escape_html(last_analysis)}")

    # File names
    if meaningful_names:
        lines.append("")
        lines.append(f"{bold('📝 Detected File Names')} ({len(meaningful_names)} shown)")
        for name in meaningful_names[:6]:
            # Truncate very long names
            display_name = name if len(name) <= 50 else name[:47] + "…"
            lines.append(f"  • {code(escape_html(display_name))}")
        if len(meaningful_names) > 6:
            lines.append(f"  … and {len(meaningful_names) - 6} more")

    # Reputation & Community
    lines.append("")
    lines.append(f"{bold('👥 Community & Reputation')}")
    lines.append(f"  📈 Reputation Score: {bold(str(reputation))}")
    lines.append(
        f"  👍 {community_harmless} harmless  /  👎 {community_malicious} malicious"
    )

    # Threat classification
    if suggested_label:
        lines.append("")
        lines.append(f"{bold('⚠️ Threat Classification')}")
        lines.append(f"  🏷️ {escape_html(str(suggested_label))}")

    # Additional tags from the attributes
    tags = attrs.get("tags", [])
    if tags:
        lines.append(f"  🏷️ Tags: {escape_html(', '.join(tags[:8]))}")

    # ── Footer ──────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 34}")
    lines.append(f"📡 Source: VirusTotal ({total_engines} engines)")
    lines.append(italic("Only use this information for authorized security analysis."))

    return "\n".join(lines)


def _format_hash_not_found(file_hash: str, hash_type: str) -> str:
    """Format the response when a hash is not found in VirusTotal."""

    lines = [
        f"{bold('🦠 Malware Analysis Result')}",
        f"{'━' * 34}",
        "",
        f"📌 {bold('Hash:')} {code(file_hash)}",
        f"🏷️ {bold('Type:')} {hash_type}",
        "",
        f"{bold('ℹ️ Result:')} This hash was {bold('not found')} in VirusTotal's database.\n",
        f"{italic('This could mean:')}",
        f"  • The file is too new and hasn't been submitted yet\n"
        f"  • The file is rare and hasn't been widely distributed\n"
        f"  • The hash was entered incorrectly\n\n"
        f"{italic('Tip: You can submit the file directly to VirusTotal for analysis.')}",
    ]

    return "\n".join(lines)


def _format_file_size(size_bytes: int) -> str:
    """
    Convert file size in bytes to a human-readable string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Human-readable size string (e.g., "2.3 MB").
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
