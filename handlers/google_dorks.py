"""
Google Dork Generator Handler
Generates advanced Google dork queries for OSINT reconnaissance.
Produces categorized, clickable search queries covering information disclosure,
admin panels, file exposure, login pages, sensitive data, and database files.
Includes an educational disclaimer about ethical use.
"""

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


# ── Dork Category Definitions ────────────────────────────────────────────────────
# Each category contains a list of dork templates.
# Templates use {target} as a placeholder for the domain or query term.

DORK_CATEGORIES: dict[str, dict] = {
    "information_disclosure": {
        "name": "🔍 Information Disclosure",
        "emoji": "🔍",
        "description": "Find publicly exposed documents, config files, and metadata.",
        "dorks": [
            {"label": "Directory Listings", "template": "site:{target} intitle:\"index of\""},
            {"label": "Directory Listings (parent)", "template": "site:{target} intitle:\"index of\" \"parent directory\""},
            {"label": "Server Status", "template": "site:{target} intitle:\"apache\" \"server at\""},
            {"label": "PHP Info", "template": "site:{target} inurl:phpinfo.php"},
            {"label": "Test Pages", "template": "site:{target} inurl:test intitle:\"test page\""},
            {"label": "Config Files", "template": "site:{target} ext:conf | ext:cfg | ext:ini"},
            {"label": "Log Files", "template": "site:{target} ext:log"},
            {"label": "Backup Files", "template": "site:{target} ext:bak | ext:old | ext:backup"},
            {"label": "Environment Files", "template": "site:{target} inurl:.env"},
            {"label": "DS_Store Files", "template": "site:{target} inurl:.DS_Store"},
            {"label": "Git Exposed", "template": "site:{target} inurl:\".git\""},
            {"label": "SVN Exposed", "template": "site:{target} inurl:\".svn\""},
            {"label": "Error Messages", "template": "site:{target} intitle:\"error\" \"sql syntax\""},
            {"label": "WordPress Readme", "template": "site:{target} inurl:readme.html"},
        ],
    },
    "admin_panels": {
        "name": "🔐 Admin Panels",
        "emoji": "🔐",
        "description": "Discover administrative interfaces and login portals.",
        "dorks": [
            {"label": "Admin Login", "template": "site:{target} inurl:admin"},
            {"label": "WP Admin", "template": "site:{target} inurl:wp-admin"},
            {"label": "Administrator", "template": "site:{target} intitle:\"admin\" inurl:login"},
            {"label": "cPanel", "template": "site:{target} inurl:cpanel"},
            {"label": "phpMyAdmin", "template": "site:{target} inurl:phpmyadmin"},
            {"label": "Server Admin", "template": "site:{target} intitle:\"index of\" \"/admin\""},
            {"label": "Manager Login", "template": "site:{target} inurl:manager | inurl:admin.php"},
            {"label": "User Login", "template": "site:{target} intitle:\"login\" inurl:admin"},
            {"label": "Control Panel", "template": "site:{target} intitle:\"control panel\""},
            {"label": "Webmin", "template": "site:{target} inurl:webmin"},
            {"label": "Plesk Panel", "template": "site:{target} intitle:\"plesk\""},
        ],
    },
    "file_exposure": {
        "name": "📂 File Exposure",
        "emoji": "📂",
        "description": "Find exposed documents, spreadsheets, presentations, and data files.",
        "dorks": [
            {"label": "PDF Documents", "template": "site:{target} filetype:pdf"},
            {"label": "Word Docs", "template": "site:{target} filetype:doc | filetype:docx"},
            {"label": "Excel Sheets", "template": "site:{target} filetype:xls | filetype:xlsx"},
            {"label": "PowerPoint", "template": "site:{target} filetype:ppt | filetype:pptx"},
            {"label": "Text Files", "template": "site:{target} filetype:txt"},
            {"label": "CSV Data", "template": "site:{target} filetype:csv"},
            {"label": "JSON Files", "template": "site:{target} filetype:json"},
            {"label": "XML Files", "template": "site:{target} filetype:xml"},
            {"label": "SQL Dumps", "template": "site:{target} filetype:sql"},
            {"label": "ZIP Archives", "template": "site:{target} filetype:zip"},
        ],
    },
    "login_pages": {
        "name": "🔑 Login Pages",
        "emoji": "🔑",
        "description": "Locate authentication endpoints and user portals.",
        "dorks": [
            {"label": "Login Forms", "template": "site:{target} inurl:login"},
            {"label": "Sign-In Pages", "template": "site:{target} intitle:\"sign in\" | intitle:\"sign-in\""},
            {"label": "WP Login", "template": "site:{target} inurl:wp-login.php"},
            {"label": "User Portal", "template": "site:{target} inurl:user intitle:\"login\""},
            {"label": "Auth Pages", "template": "site:{target} inurl:auth"},
            {"label": "OAuth Pages", "template": "site:{target} inurl:oauth | inurl:authorize"},
            {"label": "Register Pages", "template": "site:{target} inurl:register intitle:\"register\""},
            {"label": "Forgot Password", "template": "site:{target} intitle:\"forgot password\""},
        ],
    },
    "sensitive_data": {
        "name": "⚠️ Sensitive Data",
        "emoji": "⚠️",
        "description": "Discover potentially exposed sensitive information.",
        "dorks": [
            {"label": "Email Addresses", "template": "site:{target} intext:\"@{target}\""},
            {"label": "API Keys", "template": "site:{target} intext:\"api_key\" | intext:\"apikey\""},
            {"label": "Passwords in Code", "template": "site:{target} intext:\"password\" filetype:log"},
            {"label": "Database Strings", "template": "site:{target} intext:\"mysql\" filetype:conf"},
            {"label": "Secrets", "template": "site:{target} intext:\"secret_key\" | intext:\"token\""},
            {"label": "Internal IPs", "template": "site:{target} intext:\"192.168.\" | intext:\"10.0.\""},
            {"label": "SSH Keys", "template": "site:{target} intext:\"BEGIN RSA PRIVATE KEY\""},
            {"label": "AWS Keys", "template": "site:{target} intext:\"AKIA\" (access key)"},
            {"label": "Database Connection", "template": "site:{target} intext:\"connectionString\""},
            {"label": "Private Docs", "template": "site:{target} intitle:\"private\" filetype:pdf"},
        ],
    },
    "database_files": {
        "name": "🗄️ Database Files",
        "emoji": "🗄️",
        "description": "Find exposed database files and data dumps.",
        "dorks": [
            {"label": "SQL Dumps", "template": "site:{target} filetype:sql"},
            {"label": "DB Dumps", "template": "site:{target} filetype:sql | filetype:mdb | filetype:db"},
            {"label": "SQLite Files", "template": "site:{target} filetype:db | filetype:sqlite"},
            {"label": "Access Database", "template": "site:{target} filetype:mdb"},
            {"label": "MySQL Dump", "template": "site:{target} filetype:sql intext:\"INSERT INTO\""},
            {"label": "CSV Database", "template": "site:{target} filetype:csv intext:\"password\""},
        ],
    },
}

# Total dork count across all categories
TOTAL_DORKS = sum(len(cat["dorks"]) for cat in DORK_CATEGORIES.values())

# ── Helper Functions ─────────────────────────────────────────────────────────────

def _build_google_search_url(query: str) -> str:
    """
    Build a Google search URL from a dork query string.

    Args:
        query: The full dork query (e.g., 'site:example.com inurl:admin').

    Returns:
        URL-encoded Google search URL.
    """
    from urllib.parse import quote_plus
    return f"https://www.google.com/search?q={quote_plus(query)}"


def _normalize_target(raw_input: str) -> str:
    """
    Normalize user input into a clean target for dork queries.

    - If input looks like a domain, strips protocol and path.
    - Otherwise, passes through as a general search term.

    Args:
        raw_input: Raw user input string.

    Returns:
        Cleaned target string suitable for dork templates.
    """
    target = raw_input.strip().lower()

    # Strip common protocol/path artifacts for domain-like inputs
    for prefix in ["https://", "http://", "www."]:
        if target.startswith(prefix):
            target = target[len(prefix):]

    # Strip trailing slashes and paths
    if "/" in target:
        target = target.split("/")[0]

    return target


def _build_dork_keyboard(
    target: str,
    category_key: str | None = None,
) -> InlineKeyboardMarkup:
    """
    Build an inline keyboard with clickable Google dork search buttons.

    Args:
        target: The domain or query term to substitute into dork templates.
        category_key: If provided, show dorks for a specific category only.
                     If None, show category navigation buttons.

    Returns:
        InlineKeyboardMarkup with dork buttons.
    """
    rows = []

    if category_key and category_key in DORK_CATEGORIES:
        # Show dorks for the specific category
        category = DORK_CATEGORIES[category_key]

        for dork in category["dorks"]:
            query = dork["template"].format(target=target)
            url = _build_google_search_url(query)

            # Truncate button label if too long
            label = dork["label"]
            if len(label) > 35:
                label = label[:32] + "..."

            rows.append([
                InlineKeyboardButton(
                    f"🔎 {label}",
                    url=url,
                )
            ])

        # Add back button and navigation
        nav_row = [
            InlineKeyboardButton("⬅️ All Categories", callback_data="dork:categories"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
        ]
        rows.append(nav_row)

    else:
        # Show category navigation buttons
        for cat_key, cat_data in DORK_CATEGORIES.items():
            dork_count = len(cat_data["dorks"])
            rows.append([
                InlineKeyboardButton(
                    f"{cat_data['name']} ({dork_count})",
                    callback_data=f"dork:cat:{cat_key}",
                )
            ])

        # Special dork types as standalone buttons
        rows.append([
            InlineKeyboardButton(
                "🔗 Related Sites",
                callback_data="dork:special:related",
            ),
            InlineKeyboardButton(
                "💾 Cached Versions",
                callback_data="dork:special:cache",
            ),
        ])

        rows.append([
            InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
        ])

    return InlineKeyboardMarkup(rows)


def _build_special_dork_keyboard(target: str, special_type: str) -> InlineKeyboardMarkup:
    """
    Build keyboard for special dork types (related:, cache:, etc.).

    Args:
        target: The domain or query term.
        special_type: The special dork type key.

    Returns:
        InlineKeyboardMarkup with special dork buttons.
    """
    rows = []

    if special_type == "related":
        query = f"related:{target}"
        url = _build_google_search_url(query)
        rows.append([
            InlineKeyboardButton("🔎 Search Related Sites", url=url),
        ])
        # Additional related queries
        query2 = f"link:{target}"
        url2 = _build_google_search_url(query2)
        rows.append([
            InlineKeyboardButton("🔗 Pages Linking to Site", url=url2),
        ])
    elif special_type == "cache":
        query = f"cache:{target}"
        url = _build_google_search_url(query)
        rows.append([
            InlineKeyboardButton("💾 View Cached Page", url=url),
        ])

    # Back navigation
    rows.append([
        InlineKeyboardButton("⬅️ All Categories", callback_data="dork:categories"),
        InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
    ])

    return InlineKeyboardMarkup(rows)


# ── Command Handler ──────────────────────────────────────────────────────────────

async def cmd_dork(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /dork <domain> or /dork <query>.
    Generate categorized Google dork queries with clickable search buttons.
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
            f"{bold('ℹ️ Usage:')} {code('/dork <domain>')}\n\n"
            f"Generate Google dork queries for OSINT reconnaissance.\n\n"
            f"Example: {code('/dork example.com')}\n\n"
            f"{bold('Dork Categories ({len(DORK_CATEGORIES)}):')}\n"
            + "".join(
                f"  {cat['name']} ({len(cat['dorks'])})\n"
                for cat in DORK_CATEGORIES.values()
            )
            + f"\n{bold('Special:')} related:, cache:, link:\n\n"
            f"💡 {italic('Enter a domain to generate targeted dork queries.')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_target = sanitize_input(" ".join(args), max_length=253)
    target = _normalize_target(raw_target)

    if not target:
        await update.message.reply_text(
            f"❌ {bold('Invalid target.')}\n\n"
            f"Please provide a domain or search term.\n"
            f"Example: {code('/dork example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Store target in user context for callback navigation ────────────────
    if not hasattr(context, "user_data") or context.user_data is None:
        context.user_data = {}
    context.user_data["dork_target"] = target

    increment_usage(user_id)

    # ── Build the response ──────────────────────────────────────────────────
    is_domain = validate_domain(target)
    target_label = code(target) if is_domain else italic(escape_html(target))

    # Determine display label
    if is_domain:
        target_description = f"Domain: {target_label}"
    else:
        target_description = f"Query: {target_label}"

    # Category summary
    cat_summary_lines = []
    for cat_key, cat_data in DORK_CATEGORIES.items():
        cat_summary_lines.append(
            f"  {cat_data['name']} — {len(cat_data['dorks'])} dorks"
        )

    educational_note = (
        f"\n{bold('⚠️ Ethical Use Disclaimer')}\n"
        f"{italic('Google dorks are powerful search operators. Use them responsibly:')}\n"
        f"  ✅ {italic('Authorized security testing')}\n"
        f"  ✅ {italic('Researching your own domains')}\n"
        f"  ✅ {italic('Educational purposes')}\n"
        f"  ❌ {italic('Unauthorized access or reconnaissance')}\n"
        f"  ❌ {italic('Targeting systems without permission')}\n\n"
        f"💡 {italic('Select a category below to see clickable search queries.')}"
    )

    result_text = (
        f"{bold('🔎 Google Dork Generator')}\n"
        f"{'━' * 32}\n\n"
        f"📌 {bold('Target:')} {target_description}\n"
        f"📊 {bold('Total Dorks:')} {TOTAL_DORKS} across {len(DORK_CATEGORIES)} categories\n\n"
        f"{bold('📂 Categories:')}\n"
        + "\n".join(cat_summary_lines)
        + educational_note
    )

    keyboard = _build_dork_keyboard(target)

    await update.message.reply_text(
        text=result_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )

    log_query(user_id, "dork", query=target, result="success")


async def handle_dork_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle inline button callbacks from the Google dork generator.

    Callback data formats:
    - "dork:categories"          — Return to category list
    - "dork:cat:<category_key>"   — Show dorks for a specific category
    - "dork:special:<type>"       — Show special dork types (related, cache)
    - "dork:back"                 — Return to OSINT menu
    """
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    # Retrieve target from user context
    target = ""
    if context.user_data:
        target = context.user_data.get("dork_target", "")

    if not target:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    if action == "back":
        from handlers.start import cmd_menu_callback
        query.data = "menu:osint"
        await cmd_menu_callback(update, context)
        return

    if action == "categories":
        # Re-show the category list with the same target
        is_domain = validate_domain(target)
        target_label = code(target) if is_domain else italic(escape_html(target))
        target_description = f"Domain: {target_label}" if is_domain else f"Query: {target_label}"

        educational_note = (
            f"\n{bold('⚠️ Ethical Use Disclaimer')}\n"
            f"{italic('Select a category below to see clickable search queries.')}"
        )

        cat_summary_lines = []
        for cat_key, cat_data in DORK_CATEGORIES.items():
            cat_summary_lines.append(
                f"  {cat_data['name']} — {len(cat_data['dorks'])} dorks"
            )

        text = (
            f"{bold('🔎 Google Dork Generator')}\n"
            f"{'━' * 32}\n\n"
            f"📌 {bold('Target:')} {target_description}\n"
            f"📊 {bold('Total Dorks:')} {TOTAL_DORKS}\n\n"
            f"{bold('📂 Categories:')}\n"
            + "\n".join(cat_summary_lines)
            + educational_note
        )

        keyboard = _build_dork_keyboard(target)
        await query.edit_message_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    if action == "cat":
        # Show dorks for a specific category
        category_key = parts[2] if len(parts) > 2 else ""
        if category_key not in DORK_CATEGORIES:
            await query.edit_message_reply_markup(reply_markup=None)
            return

        category = DORK_CATEGORIES[category_key]
        is_domain = validate_domain(target)
        target_label = code(target) if is_domain else italic(escape_html(target))
        target_description = f"Domain: {target_label}" if is_domain else f"Query: {target_label}"

        # Build a preview of dorks in text (first 5)
        dork_previews = []
        for i, dork in enumerate(category["dorks"][:5]):
            query_str = dork["template"].format(target=target)
            dork_previews.append(f"  {code(escape_html(query_str))}")

        remaining = len(category["dorks"]) - 5
        preview_note = ""
        if remaining > 0:
            preview_note = f"\n  … and {remaining} more (see buttons below)"

        text = (
            f"{category['name']}\n"
            f"{'━' * 32}\n\n"
            f"📌 {bold('Target:')} {target_description}\n"
            f"📝 {bold('Description:')} {italic(category['description'])}\n"
            f"📊 {bold('Dorks:')} {len(category['dorks'])}\n\n"
            f"{bold('📋 Sample Queries:')}\n"
            + "\n".join(dork_previews)
            + preview_note
            + f"\n\n"
            f"💡 {italic('Tap a button below to search directly on Google.')}"
        )

        keyboard = _build_dork_keyboard(target, category_key=category_key)

        await query.edit_message_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    if action == "special":
        special_type = parts[2] if len(parts) > 2 else ""
        is_domain = validate_domain(target)
        target_label = code(target) if is_domain else italic(escape_html(target))
        target_description = f"Domain: {target_label}" if is_domain else f"Query: {target_label}"

        if special_type == "related":
            text = (
                f"{bold('🔗 Related Sites & Backlinks')}\n"
                f"{'━' * 32}\n\n"
                f"📌 {bold('Target:')} {target_description}\n\n"
                f"{bold('Special Operators:')}\n"
                f"  • {code(f'related:{target}')} — Google's similar sites\n"
                f"  • {code(f'link:{target}')} — Pages that link to this site\n\n"
                f"💡 {italic('Tap a button below to search.')}"
            )
        elif special_type == "cache":
            text = (
                f"{bold('💾 Cached Versions')}\n"
                f"{'━' * 32}\n\n"
                f"📌 {bold('Target:')} {target_description}\n\n"
                f"{bold('Special Operators:')}\n"
                f"  • {code(f'cache:{target}')} — Google's cached version\n\n"
                f"💡 {italic('Tap a button below to view the cached page.')}"
            )
        else:
            await query.edit_message_reply_markup(reply_markup=None)
            return

        keyboard = _build_special_dork_keyboard(target, special_type)

        await query.edit_message_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    # Default: remove inline buttons
    await query.edit_message_reply_markup(reply_markup=None)
