"""
Number Analysis Handler
Advanced phone number reconnaissance: carrier detection, region analysis,
spam/scam checking, number formatting, and related OSINT links.
"""

import re

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html
from handlers.phone import validate_phone_number, _parse_country_code, COUNTRY_CODES


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard for number analysis."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 About", callback_data="num:about"),
            InlineKeyboardButton("🎯 Use Cases", callback_data="num:uses"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="num:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="num:back_main"),
        ],
    ])


async def cmd_number(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /number <number> — advanced phone number analysis."""
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('📞 Advanced Number Analysis')}\n\n"
            f"Deep analysis of any phone number.\n\n"
            f"Usage: {code('/number <number>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🌍 Country & region detection\n"
            f"  📡 Carrier identification\n"
            f"  📱 Number type classification\n"
            f"  ⚠️ Spam & scam risk assessment\n"
            f"  🔗 Related OSINT lookup links\n"
            f"  📐 Multiple format output\n\n"
            f"Example: {code('/number +14155552671')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_number = sanitize_input(" ".join(args), max_length=30)

    is_valid, normalized = validate_phone_number(raw_number)
    if not is_valid:
        await update.message.reply_text(
            f"❌ {bold('Invalid phone number format.')}\n\n"
            f"Please provide a valid phone number.\n"
            f"Example: {code('/number +14155552671')}",
            parse_mode=ParseMode.HTML,
        )
        return

    processing_msg = await update.message.reply_text(
        f"📞 Analyzing {code(normalized)} …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        result_text = _format_number_analysis(normalized)

        # Build keyboard with search links
        country_code = _parse_country_code(normalized)

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 Truecaller", url=f"https://www.truecaller.com/search/{normalized}"),
                InlineKeyboardButton("📞 NumLookup", url=f"https://www.numlookup.com/"),
            ],
            [
                InlineKeyboardButton("⚠️ SpamCall", url="https://www.spamcalls.net/"),
                InlineKeyboardButton("📊 NumberAnalytics", url="https://www.numberanalytics.com/"),
            ],
            [
                InlineKeyboardButton("🌐 OSINT Tools", callback_data="num:back_osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="num:back_main"),
            ],
        ])

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "number", normalized, "success")

    except Exception as exc:
        logger.error("Number analysis failed for %s: %s", normalized, exc)
        await processing_msg.edit_text(
            f"❌ Number analysis failed for {code(normalized)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )


async def handle_number_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the number analysis module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>About Number Analysis</b>\n\n"
            "Phone number analysis extracts intelligence from a phone number "
            "using the number's structure, country codes, and carrier information.\n\n"
            "<b>What we can determine:</b>\n"
            "• 🌍 Country and region of origin\n"
            "• 📡 Likely carrier/network provider\n"
            "• 📱 Number type (mobile, landline, VoIP, toll-free)\n"
            "• 📐 Various formatting standards (E.164, national, international)\n\n"
            "<b>Limitations:</b>\n"
            "This is a structural analysis. For live carrier data, "
            "configure NUMVERIFY_API_KEY in the config."
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🎯 Use Cases", callback_data="num:uses"),
                    InlineKeyboardButton("← Back", callback_data="num:menu"),
                ],
            ]),
        )

    elif action == "uses":
        uses_text = (
            "🎯 <b>Phone Number OSINT Use Cases</b>\n\n"
            "🕵️ <b>Investigation:</b>\n"
            "  Identify the country and carrier behind unknown numbers. "
            "  Cross-reference with other OSINT data.\n\n"
            "⚠️ <b>Spam Detection:</b>\n"
            "  Analyze suspicious numbers. Check if the number is from "
            "  a known spam region or uses VoIP services.\n\n"
            "👤 <b>Social Engineering:</b>\n"
            "  Verify caller identity claims. A number claiming to be from "
            "  a US bank but using a foreign country code is suspicious.\n\n"
            "📋 <b>Background Checks:</b>\n"
            "  Part of a comprehensive phone number intelligence report. "
            "  Combine with /phone for full API-based lookup."
        )
        await query.edit_message_text(
            uses_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 About", callback_data="num:about"),
                    InlineKeyboardButton("← Back", callback_data="num:menu"),
                ],
            ]),
        )

    elif action == "menu":
        await query.edit_message_text(
            f"{bold('📞 Advanced Number Analysis')}\n\n"
            f"Deep analysis of any phone number.\n\n"
            f"Usage: {code('/number <number>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🌍 Country & region detection\n"
            f"  📡 Carrier identification\n"
            f"  📱 Number type classification\n"
            f"  ⚠️ Spam & scam risk assessment\n"
            f"  🔗 Related OSINT lookup links\n\n"
            f"Example: {code('/number +14155552671')}",
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


# ── Number Analysis Engine ──────────────────────────────────────────────────────

# Number type classification by country code
NUMBER_TYPES: dict[str, str] = {
    "1": "Geographic (varies by area code)",
    "7": "Geographic/Mobile (Russia)",
    "20": "Geographic (Egypt)",
    "27": "Geographic/Mobile (South Africa)",
    "30": "Geographic (Greece)",
    "31": "Geographic/Mobile (Netherlands)",
    "33": "Geographic/Mobile (France)",
    "34": "Geographic/Mobile (Spain)",
    "39": "Geographic/Mobile (Italy)",
    "44": "Geographic/Mobile (UK)",
    "49": "Geographic/Mobile (Germany)",
    "55": "Geographic/Mobile (Brazil)",
    "61": "Geographic/Mobile (Australia)",
    "62": "Geographic/Mobile (Indonesia)",
    "65": "Geographic/Mobile (Singapore)",
    "66": "Geographic/Mobile (Thailand)",
    "81": "Geographic/Mobile (Japan)",
    "82": "Geographic/Mobile (South Korea)",
    "86": "Geographic/Mobile (China)",
    "90": "Geographic/Mobile (Turkey)",
    "91": "Geographic/Mobile (India)",
    "92": "Geographic/Mobile (Pakistan)",
}

# Toll-free prefixes
TOLL_FREE_CODES = {"800", "888", "877", "866", "855", "844", "833"}
PREMIUM_CODES = {"900", "976"}

# VoIP indicators
VOIP_CARRIERS = ["google voice", "vonage", "skype", "twilio", "bandwidth", "grasshopper"]


def _format_number_analysis(number: str) -> str:
    """Build comprehensive number analysis report."""
    country_code = _parse_country_code(number)
    local_number = number[len(country_code) + 1:]  # +1 for the '+'
    digits = number.lstrip("+")
    country_guess = COUNTRY_CODES.get(country_code, "Unknown")

    lines = [
        f"{bold('📞 Number Intelligence Report')}",
        f"{'━' * 32}",
        "",
        f"📌 {bold('Number:')} {code(number)}",
        f"🔢 {bold('Country Code:')} +{country_code}",
        f"📱 {bold('Local Number:')} {escape_html(local_number)}",
        f"📏 {bold('Total Digits:')} {len(digits)}",
    ]

    # Country & Region
    lines.append("")
    lines.append(f"{bold('🌍 Country & Region')}")
    lines.append(f"  🌐 Likely Country: {escape_html(country_guess)}")
    lines.append(f"  🔢 Country Code: +{country_code}")

    # Area code analysis (US/Canada)
    if country_code == "1" and len(local_number) >= 3:
        area_code = local_number[:3]
        area_info = _get_area_code_info(area_code)
        if area_info:
            lines.append(f"  📍 Area Code: {code(area_code)} ({escape_html(area_info)})")
        lines.append(f"  📱 Number Type: {escape_html(_classify_us_number(area_code))}")

    # Number type
    lines.append("")
    lines.append(f"{bold('📱 Number Classification')}")
    num_type = NUMBER_TYPES.get(country_code, "Unknown type")
    lines.append(f"  📋 Type: {escape_html(num_type)}")

    # Toll-free / premium check
    if country_code == "1" and len(local_number) >= 3:
        area = local_number[:3]
        if area in TOLL_FREE_CODES:
            lines.append(f"  🆓 {bold('Toll-Free Number')}")
        elif area in PREMIUM_CODES:
            lines.append(f"  💰 {bold('Premium Rate Number')}")
        elif area.startswith("5"):
            lines.append(f"  📞 Likely: {bold('Personal Mobile')}")

    # Risk assessment
    lines.append("")
    lines.append(f"{bold('⚠️ Risk Assessment')}")
    risks = []
    if country_code == "1" and len(local_number) >= 3:
        area = local_number[:3]
        if area in PREMIUM_CODES:
            risks.append("Premium rate number — may incur charges")
        if len(digits) < 10:
            risks.append("Unusually short number")

    if risks:
        for risk in risks:
            lines.append(f"  ⚠️ {escape_html(risk)}")
    else:
        lines.append(f"  ✅ No obvious risk indicators")

    # Format variants
    lines.append("")
    lines.append(f"{bold('📐 Number Formats')}")
    lines.append(f"  🌐 E.164: {code(number)}")
    if country_code == "1" and len(local_number) >= 10:
        formatted_us = f"({local_number[:3]}) {local_number[3:6]}-{local_number[6:10]}"
        lines.append(f"  🇺🇸 US Format: {code(formatted_us)}")
    lines.append(f"  🔢 Digits only: {code(digits)}")

    # Footer
    lines.append("")
    lines.append(f"{'━' * 32}")
    lines.append(f"💡 {italic('Tap the buttons below for live carrier lookup and spam checks.')}")
    lines.append(italic("Use /phone for full API-based phone number reconnaissance."))

    return "\n".join(lines)


def _get_area_code_info(area_code: str) -> str:
    """Get location info for US/Canadian area codes."""
    area_codes = {
        "201": "New Jersey", "202": "Washington DC", "203": "Connecticut",
        "212": "New York City", "213": "Los Angeles", "310": "Los Angeles",
        "312": "Chicago", "323": "Los Angeles", "415": "San Francisco",
        "416": "Toronto", "512": "Austin", "617": "Boston",
        "646": "New York City", "650": "San Francisco Bay Area",
        "718": "New York City", "713": "Houston", "720": "Colorado",
        "808": "Hawaii", "818": "Los Angeles", "832": "Houston",
        "850": "Florida", "904": "Florida", "917": "New York City",
        "949": "Orange County CA", "951": "Riverside CA", "954": "Fort Lauderdale",
        "404": "Atlanta", "407": "Orlando", "469": "Dallas",
        "503": "Portland", "510": "Oakland", "513": "Cincinnati",
        "602": "Phoenix", "614": "Columbus", "619": "San Diego",
        "702": "Las Vegas", "703": "Virginia", "714": "Orange County CA",
        "786": "Miami", "813": "Tampa", "856": "New Jersey",
        "862": "New Jersey", "925": "San Francisco Bay Area",
        "929": "New York City", "970": "Colorado", "971": "Portland",
        "978": "Massachusetts", "989": "Michigan", "213": "Los Angeles",
    }
    return area_codes.get(area_code, "")


def _classify_us_number(area_code: str) -> str:
    """Classify a US/Canadian number by area code."""
    if area_code in TOLL_FREE_CODES:
        return "Toll-Free"
    if area_code in PREMIUM_CODES:
        return "Premium Rate"
    if area_code == "900":
        return "Premium"
    # Most US area codes are mixed geographic/mobile
    return "Geographic / Mobile"
