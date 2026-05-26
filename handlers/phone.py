"""
Phone Number Lookup Handler
Validates phone numbers in E.164 format and queries the numverify.com API
for carrier, country, and line type information. Gracefully handles API
unavailability with informative fallback responses.
"""

import re
import aiohttp

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


# ── E.164 Phone Number Validation ────────────────────────────────────────────────
# E.164 format: +[country code][subscriber number], max 15 digits total
E164_PATTERN = re.compile(r'^\+?[1-9]\d{6,14}$')


def validate_phone_number(raw: str) -> tuple[bool, str]:
    """
    Validate and normalize a phone number to E.164 format.

    Accepts various input formats:
    - International: +14155552671, +44 20 7946 0958
    - With dashes: +1-415-555-2671
    - With parens: +1 (415) 555-2671
    - With spaces: +44 20 7946 0958
    - Without plus: 14155552671

    Args:
        raw: The raw phone number string from user input.

    Returns:
        Tuple of (is_valid: bool, normalized_number: str).
        The normalized number always includes a leading '+' prefix.
    """
    if not raw:
        return False, ""

    # Strip all non-digit characters (except leading +)
    cleaned = raw.strip()
    has_plus = cleaned.startswith("+")
    digits = re.sub(r'[^\d]', '', cleaned)

    if not digits:
        return False, ""

    # Remove leading zero (common in national formats)
    if digits.startswith("0") and not has_plus:
        digits = digits[1:]

    # Validate digit count: 7-15 digits after country code
    if not (7 <= len(digits) <= 15):
        return False, ""

    # First digit must be 1-9 (country code cannot start with 0)
    if digits[0] not in "123456789":
        return False, ""

    # Reconstruct E.164 format
    normalized = f"+{digits}"

    # Final E.164 regex check
    if not E164_PATTERN.match(normalized):
        return False, ""

    return True, normalized


def _parse_country_code(number: str) -> str:
    """
    Extract the country calling code from an E.164 number.

    Args:
        number: E.164 formatted phone number (e.g., +14155552671).

    Returns:
        Country code string (e.g., "1", "44").
    """
    digits = number.lstrip("+")
    # Common country code lengths: 1, 2, or 3 digits
    # Try longest match first for accuracy
    for length in [3, 2, 1]:
        if len(digits) >= length:
            candidate = digits[:length]
            if candidate[0] in "123456789":
                return candidate
    return digits[0]


# ── Country Code Reference ───────────────────────────────────────────────────────
# Brief lookup for common country codes (supplement to API data).
COUNTRY_CODES: dict[str, str] = {
    "1": "US/CA", "7": "Russia", "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "33": "France", "34": "Spain",
    "39": "Italy", "44": "UK", "49": "Germany", "55": "Brazil",
    "61": "Australia", "62": "Indonesia", "65": "Singapore", "66": "Thailand",
    "81": "Japan", "82": "South Korea", "86": "China", "90": "Turkey",
    "91": "India", "92": "Pakistan", "94": "Sri Lanka", "994": "Azerbaijan",
}


# ── numverify.com API Client ─────────────────────────────────────────────────────
NUMVERIFY_BASE_URL = "https://phonevalidation.abstractapi.com/v1"

# Alternative free endpoint: apilayer.net/numverify
NUMVERIFY_API_URL = "https://apilayer.net/api/validate"


async def _query_numverify(number: str) -> dict | None:
    """
    Query the numverify.com API for phone number information.

    Uses the ACCESS_KEY from config if available, otherwise attempts
    a basic free request (limited results without API key).

    Args:
        number: E.164 formatted phone number.

    Returns:
        API response dict or None on failure.
    """
    # Check for configured numverify API key
    api_key = getattr(config, "NUMVERIFY_API_KEY", None)

    params = {"number": number}
    if api_key:
        params["access_key"] = api_key

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                NUMVERIFY_API_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # numverify returns {"valid": true, ...} or {"success": false, ...}
                    if data.get("success", True):
                        return {"source": "numverify", **data}
                    return {"source": "numverify", "error": data.get("error", {}).get("info", "API error")}
                return {"source": "numverify", "error": f"HTTP {resp.status}"}
    except aiohttp.ClientError as exc:
        logger.warning("numverify API request failed: %s", exc)
        return None
    except Exception as exc:
        logger.warning("numverify API unexpected error: %s", exc)
        return None


async def _query_abstract_api(number: str) -> dict | None:
    """
    Query AbstractAPI phone validation as a fallback.
    Uses PHONEVALIDATION_API_KEY from config if available.

    Args:
        number: E.164 formatted phone number.

    Returns:
        API response dict or None on failure.
    """
    api_key = getattr(config, "PHONEVALIDATION_API_KEY", None)
    if not api_key:
        return None

    try:
        params = {"api_key": api_key, "phone": number}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                NUMVERIFY_BASE_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"source": "abstractapi", **data}
                return None
    except Exception as exc:
        logger.warning("AbstractAPI phone validation failed: %s", exc)
        return None


# ── Command Handler ──────────────────────────────────────────────────────────────

async def cmd_phone(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /phone <number>.
    Validates the phone number format and queries external APIs for
    carrier, country, and line type details.
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
            f"{bold('ℹ️ Usage:')} {code('/phone <number>')}\n\n"
            f"Look up carrier, country, and line type for a phone number.\n\n"
            f"{bold('Accepted formats:')}\n"
            f"  • E.164: {code('+14155552671')}\n"
            f"  • Dashed: {code('+1-415-555-2671')}\n"
            f"  • Spaced: {code('+44 20 7946 0958')}\n"
            f"  • Plain: {code('14155552671')}\n\n"
            f"Example: {code('/phone +14155552671')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_number = sanitize_input(" ".join(args), max_length=30)

    # ── Validate phone number format ────────────────────────────────────────
    is_valid, normalized = validate_phone_number(raw_number)
    if not is_valid:
        await update.message.reply_text(
            f"❌ {bold('Invalid phone number format.')}\n\n"
            f"Please provide a valid phone number in E.164 format.\n\n"
            f"{bold('Examples:')}\n"
            f"  {code('/phone +14155552671')} (US)\n"
            f"  {code('/phone +442079460958')} (UK)\n"
            f"  {code('/phone +8613800138000')} (China)\n\n"
            f"{italic('Number must be 7-15 digits, optionally prefixed with +')}",
            parse_mode=ParseMode.HTML,
        )
        return

    processing_msg = await update.message.reply_text(
        f"🔍 Looking up {code(normalized)} …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    # ── Query APIs ──────────────────────────────────────────────────────────
    try:
        # Try numverify first
        api_data = await _query_numverify(normalized)

        # Fallback to AbstractAPI if numverify failed
        if api_data is None or "error" in api_data:
            abstract_data = await _query_abstract_api(normalized)
            if abstract_data and "error" not in abstract_data:
                api_data = abstract_data

        # Build report
        result_text = _format_phone_report(normalized, api_data)

        # Build keyboard
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="phone:back"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "phone", query=normalized, result="success")

    except Exception as exc:
        logger.error("Phone lookup failed for %s: %s", normalized, exc)
        await processing_msg.edit_text(
            f"❌ Phone lookup failed for {code(normalized)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "phone", query=normalized, result=f"error: {exc}")


async def handle_phone_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the phone lookup module."""
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


# ── Report Formatter ─────────────────────────────────────────────────────────────

def _format_phone_report(number: str, api_data: dict | None) -> str:
    """
    Build a formatted phone number intelligence report.

    Args:
        number: E.164 formatted phone number.
        api_data: API response dict or None (API unavailable).

    Returns:
        Formatted HTML string for the Telegram message.
    """
    country_code = _parse_country_code(number)
    local_number = number[len(country_code) + 1:]  # +1 for the '+'

    lines = [
        f"{bold('📞 Phone Number Intelligence')}",
        f"{'━' * 34}",
        "",
        f"📌 {bold('Number:')} {code(number)}",
        f"🔢 {bold('Country Code:')} +{country_code}",
        f"📱 {bold('Local Number:')} {escape_html(local_number)}",
    ]

    # ── API Results ─────────────────────────────────────────────────────────
    if api_data and "error" not in api_data:
        source = api_data.get("source", "unknown")

        if source == "numverify":
            lines.extend(_parse_numverify_data(api_data))
        elif source == "abstractapi":
            lines.extend(_parse_abstract_data(api_data))
        else:
            lines.extend(_parse_generic_data(api_data))

    else:
        # Graceful fallback when API is unavailable
        lines.extend(_format_fallback_report(number, country_code, api_data))

    # ── Footer ──────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 34}")

    if api_data and "error" not in api_data:
        lines.append(f"📡 Source: {escape_html(api_data.get('source', 'API'))}")
    else:
        lines.append(f"📡 Source: Local analysis (API unavailable)")

    lines.append(italic("Only use this information for authorized investigations."))

    return "\n".join(lines)


def _parse_numverify_data(data: dict) -> list[str]:
    """Parse numverify.com API response into report lines."""

    lines = []

    # Validity
    valid = data.get("valid", False)
    lines.append("")
    lines.append(f"{bold('📋 Validation & Location')}")

    if valid:
        lines.append(f"  ✅ Status: {bold('Valid number')}")
    else:
        lines.append(f"  ❌ Status: {bold('Invalid number')}")

    # Country information
    country_name = data.get("country_name", "")
    country_code_iso = data.get("country_code", "")
    location = data.get("location", "")
    calling_code = data.get("country_calling_code", "")

    if country_name:
        lines.append(f"  🌍 Country: {escape_html(country_name)}")
    if country_code_iso:
        lines.append(f"  🏳️ ISO Code: {escape_html(str(country_code_iso).upper())}")
    if calling_code:
        lines.append(f"  📞 Calling Code: {escape_html(str(calling_code))}")
    if location:
        lines.append(f"  📍 Location: {escape_html(location)}")

    # Carrier information
    carrier = data.get("carrier", "")
    line_type = data.get("line_type", "")

    if carrier or line_type:
        lines.append("")
        lines.append(f"{bold('📡 Network Details')}")
        if carrier:
            lines.append(f"  🏢 Carrier: {escape_html(carrier)}")
        if line_type:
            lines.append(f"  📱 Line Type: {escape_html(line_type.title())}")

    # Number format details
    international_fmt = data.get("international_format", "")
    national_fmt = data.get("national_format", "")

    if international_fmt or national_fmt:
        lines.append("")
        lines.append(f"{bold('📝 Number Formats')}")
        if international_fmt:
            lines.append(f"  🌐 International: {code(escape_html(international_fmt))}")
        if national_fmt:
            lines.append(f"  🏠 National: {code(escape_html(national_fmt))}")

    return lines


def _parse_abstract_data(data: dict) -> list[str]:
    """Parse AbstractAPI phone validation response into report lines."""

    lines = []
    phone_data = data.get("phone", {})

    lines.append("")
    lines.append(f"{bold('📋 Validation & Location')}")

    # Validity
    is_valid = phone_data.get("is_valid", False)
    if is_valid:
        lines.append(f"  ✅ Status: {bold('Valid number')}")
    else:
        lines.append(f"  ❌ Status: {bold('Invalid number')}")

    # Country
    country = phone_data.get("country", {})
    country_name = country.get("name", "")
    country_code_iso = country.get("iso2", "")
    if country_name:
        lines.append(f"  🌍 Country: {escape_html(country_name)}")
    if country_code_iso:
        lines.append(f"  🏳️ ISO Code: {escape_html(country_code_iso.upper())}")

    # Location
    location = phone_data.get("location", "")
    if location:
        lines.append(f"  📍 Location: {escape_html(location)}")

    # Carrier
    carrier = phone_data.get("carrier", "")
    if carrier:
        lines.append("")
        lines.append(f"{bold('📡 Network Details')}")
        lines.append(f"  🏢 Carrier: {escape_html(carrier)}")

    # Line type
    line_type = phone_data.get("type", "")
    if line_type:
        lines.append(f"  📱 Line Type: {escape_html(line_type.title())}")

    # Format details
    formats = phone_data.get("formats", {})
    if formats:
        international_fmt = formats.get("international", "")
        national_fmt = formats.get("national", "")
        if international_fmt or national_fmt:
            lines.append("")
            lines.append(f"{bold('📝 Number Formats')}")
            if international_fmt:
                lines.append(f"  🌐 International: {code(escape_html(international_fmt))}")
            if national_fmt:
                lines.append(f"  🏠 National: {code(escape_html(national_fmt))}")

    return lines


def _parse_generic_data(data: dict) -> list[str]:
    """Parse generic API response fields into report lines."""

    lines = []
    lines.append("")
    lines.append(f"{bold('📋 Available Information')}")

    # Display all non-empty fields we recognize
    field_map = {
        "valid": ("✅ Valid", lambda v: "Yes" if v else "No"),
        "country_name": ("🌍 Country", lambda v: v),
        "country_code": ("🏳️ ISO Code", lambda v: str(v).upper()),
        "location": ("📍 Location", lambda v: v),
        "carrier": ("🏢 Carrier", lambda v: v),
        "line_type": ("📱 Line Type", lambda v: str(v).title()),
        "international_format": ("🌐 International", lambda v: code(v)),
        "national_format": ("🏠 National", lambda v: code(v)),
    }

    for field, (label, formatter) in field_map.items():
        value = data.get(field)
        if value is not None and value != "":
            lines.append(f"  {label}: {escape_html(str(formatter(value)))}")

    return lines


def _format_fallback_report(
    number: str,
    country_code: str,
    api_data: dict | None,
) -> list[str]:
    """
    Generate an informative fallback report when APIs are unavailable.

    Uses local country code reference and format analysis to provide
    useful information even without API access.

    Args:
        number: E.164 formatted phone number.
        country_code: Extracted country calling code.
        api_data: API response (may contain error info).

    Returns:
        List of formatted report lines.
    """
    lines = []

    # Country code lookup
    country_guess = COUNTRY_CODES.get(country_code, "Unknown")

    lines.append("")
    lines.append(f"{bold('📋 Basic Analysis')} (API unavailable)")

    if api_data and "error" in api_data:
        lines.append(f"  ⚠️ API Error: {escape_html(str(api_data['error']))}")

    lines.append(f"  ✅ Format: {bold('Valid E.164')}")
    lines.append(f"  🌍 Likely Country: {escape_html(country_guess)}")
    lines.append(f"  🔢 Country Code: +{country_code}")

    # Digit count analysis
    digits = number.lstrip("+")
    lines.append(f"  📏 Total Digits: {len(digits)}")

    # Tip for getting full data
    lines.append("")
    lines.append(f"{bold('💡 Full Lookup')}")

    api_docs = link(
        "numverify.com API docs",
        "https://numverify.com/documentation",
    )
    lines.append(
        f"  {italic(f'For carrier and line type details, configure a free API key: {api_docs}')}"
    )
    lines.append(
        f"  {italic('Set the NUMVERIFY_API_KEY environment variable to enable full lookups.')}"
    )
    lines.append("")
    lines.append(f"  {italic('Free tier: 250 requests/month')}")

    return lines
