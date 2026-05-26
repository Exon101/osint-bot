"""
Start & Menu Handler
Welcome message, help listing, user stats, and inline keyboard menu routing.
"""

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


# ── Welcome Message ────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send the welcome message with a top-level category menu."""
    user = update.effective_user
    user_id = user.id

    # Ensure user exists in database
    from database import create_user
    create_user(user_id, username=user.username, first_name=user.first_name)
    increment_usage(user_id)
    log_query(user_id, "start")

    welcome_text = (
        f"{bold('🔍 OSINT Investigation Bot')}\n\n"
        f"Welcome, {escape_html(user.first_name or user.username or 'Agent')}!\n\n"
        f"{italic('A comprehensive Open Source Intelligence toolkit for Telegram.')}\n\n"
        f"Choose a category below to get started, or use {code('/help')} "
        f"to see all {bold('30+ commands')} available.\n\n"
        f"⚠️ {italic('For educational and authorized use only.')}"
    )

    keyboard = _build_main_menu_keyboard()
    await update.message.reply_text(
        text=welcome_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


# ── Help Command ───────────────────────────────────────────────────────────────

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """List all available commands grouped by category."""
    user_id = update.effective_user.id
    increment_usage(user_id)
    log_query(user_id, "help")

    help_text = (
        f"{bold('📖 OSINT Bot — Command Reference')}\n"
        f"{'━' * 34}\n\n"

        f"{bold('🔍 OSINT Investigation Tools')}\n"
        f"  {code('/ip <address>')} — Geo-location, ISP & abuse intel\n"
        f"  {code('/domain <name>')} — DNS records, WHOIS & VirusTotal\n"
        f"  {code('/user <name>')} — Username across 30+ platforms\n"
        f"  {code('/social <name>')} — Social media detailed lookup\n"
        f"  {code('/malware <hash>')} — File hash lookup on VirusTotal\n"
        f"  {code('/email <addr>')} — Email OSINT & validation\n"
        f"  {code('/emailrecon <addr>')} — Deep email reconnaissance\n"
        f"  {code('/breach <addr>')} — Data breach checker (HIBP)\n"
        f"  {code('/phone <num>')} — Phone number reconnaissance\n"
        f"  {code('/number <num>')} — Advanced number analysis\n"
        f"  {code('/dork <query>')} — Google dork generator\n\n"

        f"{bold('🖼️ Image & Photo Intelligence')}\n"
        f"  {code('/reverse')} — Reverse image search (send photo)\n"
        f"  {code('/face')} — Face detection & analysis\n"
        f"  {code('/meta')} — EXIF metadata extractor (send photo)\n\n"

        f"{bold('🛡️ Advanced Security')}\n"
        f"  {code('/vuln <cve>')} — CVE vulnerability details (NVD)\n"
        f"  {code('/nuclei scan <url>')} — Nuclei template vuln scanner\n"
        f"  {code('/darkweb <term>')} — Dark web breach monitor\n"
        f"  {code('/news [topic]')} — Cybersecurity news feed\n"
        f"  {code('/github <repo>')} — GitHub repo info & tracking\n\n"

        f"{bold('🧩 CTF & Developer Tools')}\n"
        f"  {code('/password [len]')} — Secure password generator\n"
        f"  {code('/run <code>')} — Execute Python code safely\n"
        f"  {code('/encode <text>')} — Base64 encode / decode\n\n"

        f"{bold('🌐 Network Reconnaissance')}\n"
        f"  {code('/subdomain <domain>')} — Subdomain enumeration\n"
        f"  {code('/dns <domain>')} — Full DNS record lookup\n"
        f"  {code('/whois <domain>')} — WHOIS registration data\n"
        f"  {code('/port <host> <port>')} — Port scan / probe\n\n"

        f"{bold('🔧 Utilities')}\n"
        f"  {code('/urlscan <url>')} — URL safety scanner\n"
        f"  {code('/qr <text>')} — Generate QR codes\n"
        f"  {code('/proxy')} — Proxy manager (tap buttons to control)\n"
        f"  {code('/proxy add <url>')} — Add a proxy\n"
        f"  {code('/stats')} — Your usage statistics\n"
        f"  {code('/menu')} — Show interactive menu\n"
    )

    await update.message.reply_text(
        text=help_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


# ── Stats Command ──────────────────────────────────────────────────────────────

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display the current user's query statistics."""
    user = update.effective_user
    user_id = user.id
    increment_usage(user_id)
    log_query(user_id, "stats")

    from database import get_user_stats

    stats = get_user_stats(user_id)

    if not stats or stats.get("total_queries", 0) == 0:
        text = (
            f"{bold('📊 Your Statistics')}\n\n"
            f"No queries recorded yet. Start investigating!\n\n"
            f"Try {code('/ip 8.8.8.8')} to begin."
        )
    else:
        total = stats.get("total_queries", 0)
        last_active = stats.get("last_active", "Unknown")
        top_commands = stats.get("top_commands", [])

        # Build top commands list
        cmd_lines = ""
        if top_commands:
            for entry in top_commands:
                cmd_name = entry.get("command", "?")
                cnt = entry.get("cnt", 0)
                cmd_lines += f"  • {code(cmd_name)} — {cnt} queries\n"
        else:
            cmd_lines = "  No data yet.\n"

        text = (
            f"{bold('📊 Your Statistics')}\n"
            f"{'━' * 24}\n\n"
            f"👤 User: {escape_html(user.username or user.first_name or str(user_id))}\n"
            f"🔢 Total Queries: {bold(str(total))}\n"
            f"🕐 Last Active: {escape_html(str(last_active)[:19])}\n\n"
            f"{bold('Top Commands:')}\n{cmd_lines}"
        )

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main")],
    ])

    await update.message.reply_text(
        text=text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
    )


# ── Menu Callback Router ───────────────────────────────────────────────────────

async def cmd_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Route inline keyboard callbacks that start with 'menu:'.
    Builds and sends the appropriate sub-menu or returns to main menu.
    """
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    callback_data = query.data  # e.g. "menu:osint"

    # Parse the menu category
    parts = callback_data.split(":", 1)
    category = parts[1] if len(parts) > 1 else "main"

    log_query(user_id, "menu_callback", query_data=callback_data)

    if category == "main":
        keyboard = _build_main_menu_keyboard()
        text = (
            f"{bold('🔍 OSINT Investigation Bot')}\n\n"
            f"Select a category to explore commands:"
        )
    elif category == "osint":
        keyboard, text = _build_submenu_keyboard(
            title="🔍 OSINT Investigation Tools",
            buttons=[
                ("🌐 IP Lookup", "menu:cmd_ip"),
                ("🌐 Domain Recon", "menu:cmd_domain"),
                ("👤 Username Search (30+)", "menu:cmd_user"),
                ("🔍 Social Media Lookup", "menu:cmd_social"),
                ("🦠 Malware Hash", "menu:cmd_malware"),
                ("📧 Email OSINT", "menu:cmd_email"),
                ("📧 Email Recon (Deep)", "menu:cmd_emailrecon"),
                ("🔥 Breach Checker", "menu:cmd_breach"),
                ("📞 Phone Lookup", "menu:cmd_phone"),
                ("📞 Number Analysis", "menu:cmd_number"),
                ("🔎 Google Dorks", "menu:cmd_dork"),
            ],
            back_to="main",
        )
    elif category == "security":
        keyboard, text = _build_submenu_keyboard(
            title="🛡️ Advanced Security",
            buttons=[
                ("🔒 CVE Lookup", "menu:cmd_vuln"),
                ("☢️ Nuclei Scanner", "menu:cmd_nuclei"),
                ("🕸️ Dark Web Monitor", "menu:cmd_darkweb"),
                ("📰 Cyber News", "menu:cmd_news"),
                ("🐙 GitHub Tracker", "menu:cmd_github"),
            ],
            back_to="main",
        )
    elif category == "image":
        keyboard, text = _build_submenu_keyboard(
            title="🖼️ Image & Photo Intelligence",
            buttons=[
                ("🔍 Reverse Image Search", "menu:cmd_reverse"),
                ("👤 Face Detection", "menu:cmd_face"),
                ("📋 EXIF Metadata", "menu:cmd_meta"),
            ],
            back_to="main",
        )
    elif category == "ctf":
        keyboard, text = _build_submenu_keyboard(
            title="🧩 CTF & Developer Tools",
            buttons=[
                ("🔑 Password Gen", "menu:cmd_password"),
                ("💻 Code Runner", "menu:cmd_run"),
                ("🔁 Base64 Encode/Decode", "menu:cmd_encode"),
            ],
            back_to="main",
        )
    elif category == "network":
        keyboard, text = _build_submenu_keyboard(
            title="🌐 Network Reconnaissance",
            buttons=[
                ("🔍 Subdomain Enum", "menu:cmd_subdomain"),
                ("📡 DNS Lookup", "menu:cmd_dns"),
                ("📋 WHOIS Lookup", "menu:cmd_whois"),
                ("🚪 Port Scanner", "menu:cmd_port"),
            ],
            back_to="main",
        )
    elif category == "utilities":
        keyboard, text = _build_submenu_keyboard(
            title="🔧 Utilities",
            buttons=[
                ("🔗 URL Scanner", "menu:cmd_urlscan"),
                ("📱 QR Generator", "menu:cmd_qr"),
                ("🔀 Proxy Manager", "menu:cmd_proxy"),
                ("📊 Your Stats", "menu:cmd_stats"),
            ],
            back_to="main",
        )
    # ── Command shortcut buttons (menu:cmd_xxx) ──
    elif category.startswith("cmd_"):
        cmd_map = {
            "cmd_ip": "/ip <address> — Look up geolocation, ISP, abuse score and open ports for an IP address.",
            "cmd_domain": "/domain <name> — Retrieve DNS records, WHOIS info, and VirusTotal report for a domain.",
            "cmd_user": "/user <name> — Check if a username exists across 30+ platforms (GitHub, Reddit, X, Instagram, TikTok, YouTube, Facebook, LinkedIn, Steam, and more).",
            "cmd_social": "/social <name> — Detailed social media profile lookup with bio, stats, and linked accounts across 25 platforms.",
            "cmd_emailrecon": "/emailrecon <addr> — Deep email reconnaissance: Gravatar profile, MX records, social profile discovery, ClearBit enrichment.",
            "cmd_breach": "/breach <addr> — Check if an email appeared in data breaches via HaveIBeenPwned API.",
            "cmd_number": "/number <num> — Advanced phone number analysis: carrier, region, spam risk, and OSINT links.",
            "cmd_reverse": "/reverse — Send a photo and get reverse image search links (Google Lens, Yandex, TinEye, Bing, SauceNAO).",
            "cmd_face": "/face — Send a photo for face detection, image analysis, and links to face search engines.",
            "cmd_malware": "/malware <hash> — Search VirusTotal for a file hash (MD5, SHA-1, SHA-256).",
            "cmd_email": "/email <addr> — Gather OSINT data and breach history for an email address.",
            "cmd_phone": "/phone <num> — Perform phone number reconnaissance.",
            "cmd_dork": "/dork <query> — Generate Google dork search strings for advanced OSINT.",
            "cmd_meta": "/meta <url> — Extract metadata from a webpage or file URL.",
            "cmd_nuclei": "/nuclei — Open Nuclei scanner menu. Use /nuclei scan <url> to run a template-based vulnerability scan (ProjectDiscovery). /nuclei templates <keyword> to search templates. /nuclei status <id> to check scan results.",
            "cmd_vuln": "/vuln <cve> — Get vulnerability details from the NVD database.",
            "cmd_darkweb": "/darkweb <term> — Monitor the dark web for data breaches mentioning your query.",
            "cmd_news": "/news [topic] — Get the latest cybersecurity news feed.",
            "cmd_github": "/github <repo> — View repo info or track GitHub repositories.",
            "cmd_password": "/password [len] — Generate a cryptographically secure random password.",
            "cmd_run": "/run <code> — Execute Python code in a sandboxed environment.",
            "cmd_encode": "/encode <text> — Encode or decode Base64, URL-encoded, and hex strings.",
            "cmd_subdomain": "/subdomain <domain> — Enumerate subdomains for a target domain.",
            "cmd_dns": "/dns <domain> — Full DNS record lookup (A, AAAA, MX, NS, TXT, CNAME).",
            "cmd_whois": "/whois <domain> — Retrieve WHOIS registration data.",
            "cmd_port": "/port <host> <port> — Scan or probe a specific port on a host.",
            "cmd_urlscan": "/urlscan <url> — Check a URL for safety and malicious content.",
            "cmd_qr": "/qr <text> — Generate a QR code from any text or URL.",
            "cmd_proxy": "/proxy — Open proxy manager. Tap buttons to enable/disable, test, remove. Use /proxy add <url> to add a proxy (HTTP/HTTPS/SOCKS4/SOCKS5).",
            "cmd_stats": "/stats — View your personal usage statistics.",
        }
        cmd_hint = cmd_map.get(category, "Unknown command.")
        # Determine back button based on command category
        back_map = {
            "cmd_reverse": "menu:image", "cmd_face": "menu:image", "cmd_meta": "menu:image",
            "cmd_social": "menu:osint", "cmd_emailrecon": "menu:osint",
            "cmd_breach": "menu:osint", "cmd_number": "menu:osint",
            "cmd_nuclei": "menu:security",
        }
        back_to = back_map.get(category, "menu:osint")
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("⬅️ Back", callback_data=back_to)],
        ])
        text = f"{bold('💡 Command Hint')}\n\n{code(cmd_hint)}\n\n{italic('Copy and use the command above!')}"
    else:
        keyboard = _build_main_menu_keyboard()
        text = f"{bold('🔍 OSINT Bot')}\n\nUnknown menu option. Please try again:"

    await query.edit_message_text(
        text=text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
    )


# ── Keyboard Builders ──────────────────────────────────────────────────────────

def _build_main_menu_keyboard() -> InlineKeyboardMarkup:
    """Build the top-level 5-category inline menu."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
            InlineKeyboardButton("🛡️ Security", callback_data="menu:security"),
        ],
        [
            InlineKeyboardButton("🧩 CTF Tools", callback_data="menu:ctf"),
            InlineKeyboardButton("🌐 Network Recon", callback_data="menu:network"),
        ],
        [InlineKeyboardButton("🔧 Utilities", callback_data="menu:utilities")],
    ])


def _build_submenu_keyboard(
    title: str,
    buttons: list,
    back_to: str = "main",
) -> tuple:
    """
    Build a sub-menu keyboard from a list of (label, callback_data) tuples.

    Args:
        title: The header text shown above the keyboard.
        buttons: List of (label, callback_data) pairs.
        back_to: Callback data for the back button.

    Returns:
        Tuple of (InlineKeyboardMarkup, formatted text string).
    """
    rows = [[InlineKeyboardButton(label, callback_data=cb)] for label, cb in buttons]
    # Add a "Back to Main Menu" button at the bottom
    rows.append([InlineKeyboardButton("⬅️ Back to Menu", callback_data=f"menu:{back_to}")])

    keyboard = InlineKeyboardMarkup(rows)
    text = f"{title}\n{'━' * 28}\n\nSelect a command to see usage instructions:"
    return keyboard, text
