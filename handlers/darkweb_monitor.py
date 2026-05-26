"""
Dark Web / Breach Monitor Handler for Telegram OSINT Bot.

Provides breach lookup using known public breach data and optional HIBP integration.
Commands:
    /darkweb <email>           — Check if email appeared in known breaches
    /darkweb breach <name>     — Get info about a specific known breach
"""

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_email, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html
import aiohttp
import asyncio
from typing import Optional

# ---------------------------------------------------------------------------
# Known major breaches (publicly documented information for educational use)
# ---------------------------------------------------------------------------

KNOWN_BREACHES: dict[str, dict] = {
    "linkedin": {
        "name": "LinkedIn",
        "date": "2012-06-05",
        "records": 164_000_000,
        "description": (
            "In 2012, LinkedIn suffered a data breach that exposed 164 million email addresses and passwords. "
            "The data was initially sold on a dark web marketplace and later redistributed freely."
        ),
        "data_types": [
            "Email addresses",
            "Passwords (unsalted SHA-1 hashes)",
        ],
        "source": "https://www.bleepingcomputer.com/news/security/linkedin-confirms-2016-data-breach-of-164m-passwords/",
    },
    "facebook": {
        "name": "Facebook",
        "date": "2021-04-03",
        "records": 533_000_000,
        "description": (
            "In April 2021, a database of 533 million Facebook users was published on a hacking forum. "
            "The data was scraped using Facebook's contact importer feature prior to a 2019 policy change."
        ),
        "data_types": [
            "Full names",
            "Email addresses",
            "Phone numbers",
            "Locations",
            "Birth dates",
            "Biographical info",
        ],
        "source": "https://about.fb.com/news/2021/04/addressing-scraped-data/",
    },
    "adobe": {
        "name": "Adobe",
        "date": "2013-10-04",
        "records": 153_000_000,
        "description": (
            "In October 2013, Adobe Systems suffered a breach exposing 153 million customer records, "
            "including encrypted passwords, payment card information, and internal source code."
        ),
        "data_types": [
            "Email addresses",
            "Encrypted passwords (3DES-ECB)",
            "Credit/debit card numbers",
            "Customer names",
            "Source code",
        ],
        "source": "https://krebsonsecurity.com/2013/10/adobe-source-code-leak-includes-passwords/",
    },
    "yahoo": {
        "name": "Yahoo",
        "date": "2016-12-14",
        "records": 3_000_000_000,
        "description": (
            "Yahoo disclosed two massive breaches. The 2013 breach (disclosed 2016) affected all 3 billion accounts. "
            "The 2014 breach affected 500 million accounts. This is one of the largest known data breaches."
        ),
        "data_types": [
            "Email addresses",
            "Passwords (hashed, some unhashed)",
            "Security questions & answers",
            "Phone numbers",
            "Dates of birth",
        ],
        "source": "https://www.reuters.com/article/us-yahoo-cyber/yahoo-revises-estimate-of-2013-breach-to-3-billion-accounts-idUSKCN1C72OZ",
    },
    "equifax": {
        "name": "Equifax",
        "date": "2017-09-07",
        "records": 147_000_000,
        "description": (
            "Equifax, one of the largest credit bureaus, suffered a breach exposing the personal data of "
            "147 million people due to an unpatched Apache Struts vulnerability (CVE-2017-5638)."
        ),
        "data_types": [
            "Full names",
            "Social Security numbers",
            "Birth dates",
            "Addresses",
            "Driver's license numbers",
            "Credit card numbers (209K)",
        ],
        "source": "https://www.equifaxsecurity2017.com/",
    },
    "marriott": {
        "name": "Marriott / Starwood",
        "date": "2018-11-30",
        "records": 500_000_000,
        "description": (
            "Marriott International disclosed that its Starwood reservation database was compromised, "
            "exposing data of up to 500 million guests. The breach went undetected since 2014."
        ),
        "data_types": [
            "Names",
            "Passport numbers",
            "Email addresses",
            "Phone numbers",
            "Arrival/departure dates",
            "Loyalty account info",
        ],
        "source": "https://www.marriott.com/notice/faq-cn.isp",
    },
    "collection1": {
        "name": "Collection #1",
        "date": "2019-01-17",
        "records": 773_000_000,
        "description": (
            "Collection #1 was a massive data breach compilation containing 773 million unique email addresses "
            "and 21 million unique passwords. It was offered for sale on a hacking forum."
        ),
        "data_types": [
            "Email addresses",
            "Plain-text passwords",
        ],
        "source": "https://www.troyhunt.com/the-773-million-record-collection-1-data-reach/",
    },
    "twitter": {
        "name": "Twitter / X",
        "date": "2022-07-21",
        "records": 5_400_000,
        "description": (
            "A vulnerability in Twitter's API allowed threat actors to enumerate email addresses associated "
            "with Twitter accounts, exposing data of approximately 5.4 million users."
        ),
        "data_types": [
            "Email addresses",
            "Twitter handles",
            "Phone numbers",
        ],
        "source": "https://www.hackerone.com/reports/1607750",
    },
    "twitch": {
        "name": "Twitch",
        "date": "2021-10-06",
        "records": 125_000,
        "description": (
            "An anonymous hacker leaked the entire Twitch source code, creator payout records, and encrypted "
            "passwords. The breach was claimed to be motivated by the platform's toxic community."
        ),
        "data_types": [
            "Source code",
            "Creator earnings data",
            "Encrypted passwords",
            "Internal tools",
        ],
        "source": "https://blog.twitch.tv/en/2021/10/15/update-on-recent-security-incident/",
    },
    "dropbox": {
        "name": "Dropbox",
        "date": "2016-08-31",
        "records": 68_000_000,
        "description": (
            "Dropbox confirmed a 2012 breach that exposed 68 million user credentials. "
            "The data included email addresses and hashed passwords (some bcrypt, some salted SHA-1)."
        ),
        "data_types": [
            "Email addresses",
            "Hashed passwords",
        ],
        "source": "https://blog.dropbox.com/topics/company/2016/keeping-our-users-safe/",
    },
    "canva": {
        "name": "Canva",
        "date": "2019-05-24",
        "records": 137_000_000,
        "description": (
            "Canva suffered a breach that exposed 137 million user accounts. The attacker (GnosticPlayers) "
            "stole email addresses, usernames, names, cities, and passwords (bcrypt hashed)."
        ),
        "data_types": [
            "Email addresses",
            "Usernames",
            "Real names",
            "Cities",
            "Passwords (bcrypt hashes)",
            "OAuth tokens (partial)",
        ],
        "source": "https://www.canva.com/help/scammed-on-canva/",
    },
    "optus": {
        "name": "Optus (Australia)",
        "date": "2022-09-22",
        "records": 9_800_000,
        "description": (
            "Australian telecom Optus suffered a massive breach exposing personal data of 9.8 million "
            "customers, including passport and driver's license numbers."
        ),
        "data_types": [
            "Names",
            "Dates of birth",
            "Phone numbers",
            "Email addresses",
            "Addresses",
            "Passport numbers",
            "Driver's license numbers",
        ],
        "source": "https://www.optus.com.au/about/media-centre/media-releases",
    },
    "rockyou": {
        "name": "RockYou",
        "date": "2009-12-04",
        "records": 32_000_000,
        "description": (
            "The RockYou breach in 2009 exposed 32 million plaintext passwords stored without encryption. "
            "This breach is historically significant and its password list is widely used in security research."
        ),
        "data_types": [
            "Email addresses",
            "Plain-text passwords (unencrypted!)",
        ],
        "source": "https://www.wired.com/2009/12/rockyou-hack/",
    },
    "samsung": {
        "name": "Samsung",
        "date": "2022-03-04",
        "records": 200_000_000,
        "description": (
            "A threat actor known as 'Lapsus$' claimed to have stolen 190GB of proprietary Samsung source code "
            "and internal data from Samsung's internal servers."
        ),
        "data_types": [
            "Source code (Galaxy devices)",
            "Biometric unlock algorithms",
            "Bootloader source code",
            "Internal tools",
        ],
        "source": "https://www.bleepingcomputer.com/news/security/lapsus-hacker-group-leaks-190gb-of-samsung-source-code/",
    },
}

def _generate_aliases(name: str) -> list[str]:
    """Generate common search aliases for a breach name."""
    parts = name.lower().split()
    aliases: list[str] = []
    if len(parts) >= 2:
        aliases.append(" ".join(parts[:2]))  # first two words
    if len(parts) >= 1:
        aliases.append(parts[0])  # first word only
    return aliases


# Flatten for search: include breach names keyed by various aliases
_BREACH_LOOKUP: dict[str, str] = {}
for key, breach in KNOWN_BREACHES.items():
    _BREACH_LOOKUP[key] = key
    name_lower = breach["name"].lower().replace(" ", "").replace("/", "")
    _BREACH_LOOKUP[name_lower] = key
    _BREACH_LOOKUP[breach["name"].lower()] = key
    # Add common aliases
    for alias in _generate_aliases(breach["name"]):
        _BREACH_LOOKUP[alias] = key


# ---------------------------------------------------------------------------
# HIBP (Have I Been Pwned) integration (optional — requires API key)
# ---------------------------------------------------------------------------

HIBP_API_KEY = getattr(config, "HIBP_API_KEY", None)


async def _check_hibp(email: str) -> Optional[list[dict]]:
    """
    Check HIBP API for breaches associated with an email.
    Requires an API key set in config.HIBP_API_KEY.
    """
    if not HIBP_API_KEY:
        return None

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Bot/1.0",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return []  # not found in any breach
                elif resp.status == 429:
                    logger.warning("HIBP rate limit hit")
                    return None
                else:
                    logger.warning("HIBP returned status %s", resp.status)
                    return None
    except Exception as exc:
        logger.error("HIBP check error: %s", exc)
        return None


def _format_hibp_breach(b: dict) -> str:
    """Format a single HIBP breach entry."""
    name = b.get("name", "Unknown")
    breach_date = b.get("breachDate", "")
    desc = b.get("description", "")
    pwn_count = b.get("pwnCount", 0)
    data_classes = b.get("dataClasses", [])
    is_verified = b.get("isVerified", False)
    is_sensitive = b.get("isSensitive", False)
    domain = b.get("domain", "")

    lines: list[str] = []
    lines.append(f"{bold(f'⚠️  {name}')}")
    if breach_date:
        lines.append(f"  {bold('Date:')}  {breach_date}")
    lines.append(f"  {bold('Records:')}  {pwn_count:,}")
    if domain:
        lines.append(f"  {bold('Domain:')}  {domain}")
    if data_classes:
        lines.append(f"  {bold('Data compromised:')}  {', '.join(data_classes)}")
    verified_mark = "✅" if is_verified else "❌"
    sensitive_mark = "🔒" if is_sensitive else "🔓"
    lines.append(f"  Verified: {verified_mark}   Sensitive: {sensitive_mark}")
    if desc:
        short_desc = (desc[:300] + "…") if len(desc) > 300 else desc
        lines.append(f"\n  {italic(escape_html(short_desc))}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

async def cmd_darkweb(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /darkweb command — breach check or info about specific breaches."""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    args = context.args or []
    user_text = " ".join(args) if args else ""

    if not user_text:
        await update.message.reply_text(
            f"{bold('🌑 Dark Web Breach Monitor')}\n\n"
            "Usage:\n"
            f"  {code('/darkweb user@example.com')}  — Check email against breaches\n"
            f"  {code('/darkweb breach linkedin')}    — Info about a known breach\n"
            f"  {code('/darkweb breach list')}        — List all tracked breaches\n\n"
            f"{italic('Educational tool — uses publicly documented breach data.')}",
            parse_mode=ParseMode.HTML,
        )
        return

    # Rate limit
    if not check_rate_limit(user_id, "darkweb"):
        await update.message.reply_text(
            "⏳ Rate limit reached. Please wait before making another request.",
            parse_mode=ParseMode.HTML,
        )
        return

    user_text = sanitize_input(user_text)

    # Sub-command: breach info
    if user_text.lower().startswith("breach "):
        breach_query = user_text[7:].strip().lower()

        if breach_query == "list":
            await _show_breach_list(update)
            return

        if not breach_query:
            await update.message.reply_text(
                "Please specify a breach name.\n"
                f"Use {code('/darkweb breach list')} to see available breaches.",
                parse_mode=ParseMode.HTML,
            )
            return

        log_query(user_id, "darkweb_breach", breach_query)
        increment_usage(user_id)

        breach_key = _BREACH_LOOKUP.get(breach_query)
        if breach_key:
            breach = KNOWN_BREACHES[breach_key]
            message = _format_known_breach(breach)
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔗 Read more", url=breach.get("source", ""))],
            ])
            await update.message.reply_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=keyboard,
            )
        else:
            # Fuzzy match: partial search
            matches = [k for k in _BREACH_LOOKUP if breach_query in k]
            if matches:
                matched_key = _BREACH_LOOKUP[matches[0]]
                breach = KNOWN_BREACHES[matched_key]
                message = _format_known_breach(breach)
                keyboard = InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔗 Read more", url=breach.get("source", ""))],
                ])
                await update.message.reply_text(
                    f"{italic('Closest match found:')}\n\n{message}",
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                    reply_markup=keyboard,
                )
            else:
                await update.message.reply_text(
                    f"{bold('❌ Breach not found')}\n\n"
                    f"No known breach matching {code(breach_query)}.\n"
                    f"Use {code('/darkweb breach list')} to see available breaches.",
                    parse_mode=ParseMode.HTML,
                )
        return

    # Sub-command: email check
    email = user_text.strip()

    if not validate_email(email):
        await update.message.reply_text(
            f"{bold('❌ Invalid email address')}\n\n"
            "Please provide a valid email address.\n"
            f"Example: {code('/darkweb user@example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    log_query(user_id, "darkweb_email", email)
    increment_usage(user_id)

    await update.message.reply_text(
        f"🌑 Checking breach databases for {code(email)}…\n"
        f"{italic('This may take a moment.')}",
        parse_mode=ParseMode.HTML,
    )

    # Try HIBP first if API key is available
    hibp_results = await _check_hibp(email)

    if hibp_results is not None:
        # HIBP returned data (could be empty list = not found)
        if hibp_results:
            lines: list[str] = []
            lines.append(f"{bold('🚨 Breach Results for')} {code(email)}\n")
            lines.append(f"{italic(f'Found in {len(hibp_results)} known breach(es). Data via HaveIBeenPwned.')}\n")
            for b in hibp_results[:8]:
                lines.append(_format_hibp_breach(b))
                lines.append("")

            if len(hibp_results) > 8:
                lines.append(f"{italic(f'… and {len(hibp_results) - 8} more breaches.')}\n")

            lines.append(_educational_disclaimer())

            buttons: list[list[InlineKeyboardButton]] = [
                [InlineKeyboardButton("🔗 Check on HIBP", url=f"https://haveibeenpwned.com/account/{email}")],
            ]
            await update.message.reply_text(
                "\n".join(lines),
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=InlineKeyboardMarkup(buttons),
            )
        else:
            await update.message.reply_text(
                f"{bold('✅ Good news!')}\n\n"
                f"{code(email)} was {bold('not found')} in any known breaches.\n\n"
                f"Note: This only checks publicly disclosed breaches. "
                f"Always practice good security hygiene.",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔗 Check on HIBP", url=f"https://haveibeenpwned.com/account/{email}")],
                ]),
            )
    else:
        # No HIBP API key — use local educational data
        domain = email.split("@")[-1].lower() if "@" in email else ""
        domain_breaches = [
            b for key, b in KNOWN_BREACHES.items()
            if domain and domain in b["name"].lower()
        ]

        lines: list[str] = []
        lines.append(f"{bold('🌑 Breach Check for')} {code(email)}\n")

        if domain_breaches:
            lines.append(
                f"{italic('The domain associated with this email has known breaches:')}\n"
            )
            for b in domain_breaches:
                lines.append(f"  ⚠️  {bold(b['name'])} ({b['date']}) — {b['records']:,} records")
            lines.append(
                "\n" + italic("⚠️ This does NOT mean this specific email was in these breaches. "
                             "The entire database was compromised — individual inclusion cannot be confirmed locally.") + "\n"
            )
        else:
            lines.append(
                f"{italic('No direct match found in local breach database.')}\n"
            )

        lines.append(_educational_disclaimer())

        buttons: list[list[InlineKeyboardButton]] = [
            [
                InlineKeyboardButton("🔗 Check on HIBP", url=f"https://haveibeenpwned.com/account/{email}"),
                InlineKeyboardButton("🔗 Have I Been Zowned", url=f"https://zowned.org/?q={email}"),
            ],
        ]
        await update.message.reply_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup(buttons),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_known_breach(breach: dict) -> str:
    """Format a known breach entry for display."""
    lines: list[str] = []
    lines.append(f"{bold('⚠️  ' + breach['name'])}\n")
    lines.append(f"{bold('📅 Breach Date:')}  {breach['date']}")
    lines.append(f"{bold('📊 Records Affected:')}  {breach['records']:,}")
    lines.append(f"\n{bold('Description:')}\n{escape_html(breach['description'])}")
    lines.append(f"\n{bold('Data Compromised:')}")
    for dt in breach["data_types"]:
        lines.append(f"  • {dt}")
    lines.append(f"\n{bold('Source:')}  {link(breach.get('source', '#'), breach.get('source', 'N/A'))}")
    return "\n".join(lines)


async def _show_breach_list(update: Update) -> None:
    """Display a paginated list of all known breaches."""
    lines: list[str] = []
    lines.append(f"{bold('📋 Tracked Breaches')}\n")
    lines.append(f"{italic('Major publicly disclosed data breaches for educational reference.')}\n")

    buttons: list[list[InlineKeyboardButton]] = []
    for key, breach in KNOWN_BREACHES.items():
        records = breach["records"]
        records_str = f"{records / 1_000_000:.0f}M" if records >= 1_000_000 else f"{records / 1_000:.0f}K"
        lines.append(f"  ⚠️  {bold(breach['name'])}  —  {records_str} records ({breach['date']})")
        buttons.append([InlineKeyboardButton(
            f"📖 {breach['name']}",
            callback_data=f"darkweb:breach:{key}",
        )])

    lines.append(f"\n{italic('Tap a breach name below for full details.')}")
    lines.append(_educational_disclaimer())

    await update.message.reply_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup(buttons),
    )


def _educational_disclaimer() -> str:
    """Return the standard educational disclaimer."""
    return (
        "\n─── ⚖️ Educational Disclaimer ───\n"
        "This tool is for educational and awareness purposes only. "
        "Breach data shown is sourced from publicly documented incidents. "
        "Do not use this information for malicious purposes. "
        "Always follow responsible disclosure practices."
    )


# ---------------------------------------------------------------------------
# Callback query handler
# ---------------------------------------------------------------------------

async def handle_darkweb_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from darkweb results."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith("darkweb:"):
        return

    parts = data.split(":")
    if len(parts) < 3:
        return

    sub = parts[1]

    if sub == "breach":
        breach_key = parts[2]
        breach = KNOWN_BREACHES.get(breach_key)
        if breach:
            message = _format_known_breach(breach)
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔗 Read more", url=breach.get("source", ""))],
            ])
            await query.edit_message_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=keyboard,
            )
    elif sub == "page":
        page = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        # Placeholder for pagination logic if needed
        await query.edit_message_reply_markup(reply_markup=None)
