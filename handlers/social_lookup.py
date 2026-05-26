"""
Social Media Lookup Handler
Performs detailed profile lookup on social media platforms.
Takes a username and gathers public profile information,
avatar, bio, stats, and related accounts.
"""

import asyncio
import re
import aiohttp

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


# ── Social Media Platform Definitions ───────────────────────────────────────────
# Each entry: name, emoji, profile URL template, API/scrape URL, check method
SOCIAL_PLATFORMS: list[dict] = [
    {
        "name": "Facebook",
        "emoji": "📘",
        "profile_url": "https://facebook.com/{username}",
        "check_url": "https://www.facebook.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Instagram",
        "emoji": "📸",
        "profile_url": "https://instagram.com/{username}/",
        "check_url": "https://www.instagram.com/{username}/",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "X (Twitter)",
        "emoji": "🐦",
        "profile_url": "https://x.com/{username}",
        "check_url": "https://twitter.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "TikTok",
        "emoji": "🎵",
        "profile_url": "https://tiktok.com/@{username}",
        "check_url": "https://www.tiktok.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "LinkedIn",
        "emoji": "💼",
        "profile_url": "https://linkedin.com/in/{username}",
        "check_url": "https://www.linkedin.com/in/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "YouTube",
        "emoji": "▶️",
        "profile_url": "https://youtube.com/@{username}",
        "check_url": "https://www.youtube.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Reddit",
        "emoji": "🤖",
        "profile_url": "https://reddit.com/user/{username}",
        "check_url": "https://www.reddit.com/user/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Pinterest",
        "emoji": "📌",
        "profile_url": "https://pinterest.com/{username}/",
        "check_url": "https://www.pinterest.com/{username}/",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Twitch",
        "emoji": "🟣",
        "profile_url": "https://twitch.tv/{username}",
        "check_url": "https://www.twitch.tv/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Discord",
        "emoji": "💬",
        "profile_url": "https://discord.com/users/{username}",
        "check_url": "https://discord.com/api/v10/users/{username}",
        "detect": "status_200",
        "method": "GET",
    },
    {
        "name": "GitHub",
        "emoji": "🐙",
        "profile_url": "https://github.com/{username}",
        "check_url": "https://api.github.com/users/{username}",
        "detect": "status_200",
        "method": "GET",
        "parse": "github",
    },
    {
        "name": "Steam",
        "emoji": "🎮",
        "profile_url": "https://steamcommunity.com/id/{username}",
        "check_url": "https://steamcommunity.com/id/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Snapchat",
        "emoji": "👻",
        "profile_url": "https://snapchat.com/add/{username}",
        "check_url": "https://www.snapchat.com/add/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Telegram",
        "emoji": "✈️",
        "profile_url": "https://t.me/{username}",
        "check_url": "https://t.me/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Medium",
        "emoji": "📝",
        "profile_url": "https://medium.com/@{username}",
        "check_url": "https://medium.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "DevTo",
        "emoji": "💻",
        "profile_url": "https://dev.to/{username}",
        "check_url": "https://dev.to/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Keybase",
        "emoji": "🔑",
        "profile_url": "https://keybase.io/{username}",
        "check_url": "https://keybase.io/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Mastodon",
        "emoji": "🐘",
        "profile_url": "https://mastodon.social/@{username}",
        "check_url": "https://mastodon.social/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "SoundCloud",
        "emoji": "🔊",
        "profile_url": "https://soundcloud.com/{username}",
        "check_url": "https://soundcloud.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Spotify",
        "emoji": "🟢",
        "profile_url": "https://open.spotify.com/user/{username}",
        "check_url": "https://open.spotify.com/user/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Threads",
        "emoji": "🧵",
        "profile_url": "https://threads.net/@{username}",
        "check_url": "https://www.threads.net/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Flickr",
        "emoji": "📷",
        "profile_url": "https://flickr.com/people/{username}",
        "check_url": "https://www.flickr.com/people/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Vimeo",
        "emoji": "🎬",
        "profile_url": "https://vimeo.com/{username}",
        "check_url": "https://vimeo.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "About.me",
        "emoji": "👤",
        "profile_url": "https://{username}.about.me",
        "check_url": "https://{username}.about.me",
        "detect": "status_not_404",
        "method": "HEAD",
    },
    {
        "name": "Gravatar",
        "emoji": "🖼️",
        "profile_url": "https://gravatar.com/{username}",
        "check_url": "https://en.gravatar.com/profile/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
    },
]


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard for social lookup."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 How It Works", callback_data="social:about"),
            InlineKeyboardButton("🎯 Use Cases", callback_data="social:uses"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="social:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="social:back_main"),
        ],
    ])


async def cmd_social(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /social <username> — lookup across social media platforms."""
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    args = context.args
    if not args:
        platform_list = " • ".join(
            f"{p['emoji']} {p['name']}" for p in SOCIAL_PLATFORMS[:12]
        )
        await update.message.reply_text(
            f"{bold('🔍 Social Media Lookup')}\n\n"
            f"Search for a username across {bold(str(len(SOCIAL_PLATFORMS)))} social platforms.\n\n"
            f"Usage: {code('/social <username>')}\n\n"
            f"{bold('Platforms:')}\n"
            f"{platform_list}\n"
            f"  • ...and {len(SOCIAL_PLATFORMS) - 12} more\n\n"
            f"Example: {code('/social johndoe')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_username = sanitize_input(args[0], max_length=39)

    # Validate username format
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,37}[a-zA-Z0-9]$', raw_username) and \
       not re.match(r'^[a-zA-Z0-9]{1,39}$', raw_username):
        await update.message.reply_text(
            f"❌ {bold('Invalid username format.')}\n\n"
            f"Usernames should be 1-39 characters containing only letters, "
            f"numbers, hyphens, underscores, and periods.",
            parse_mode=ParseMode.HTML,
        )
        return

    username = raw_username
    processing_msg = await update.message.reply_text(
        f"🔍 Searching for {code(username)} across {bold(str(len(SOCIAL_PLATFORMS)))} platforms …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        results = await _check_all_platforms(username)
        result_text = _format_social_report(username, results)
        github_data = results.get("github_data")

        # Build keyboard with profile links
        found_links = []
        for platform, found in results.get("platforms", []):
            if found:
                profile_url = platform["profile_url"].format(username=username)
                found_links.append(
                    InlineKeyboardButton(
                        f"{platform['emoji']} {platform['name']}",
                        url=profile_url,
                    )
                )

        button_rows = []
        for i in range(0, len(found_links), 2):
            row = found_links[i:i + 2]
            button_rows.append(row)

        button_rows.append([
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
        ])

        keyboard = InlineKeyboardMarkup(button_rows) if button_rows else None

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "social", username, "success")

    except Exception as exc:
        logger.error("Social lookup failed for %s: %s", username, exc)
        await processing_msg.edit_text(
            f"❌ Social lookup failed for {code(username)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "social", username, f"error: {exc}")


async def handle_social_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the social lookup module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>How Social Media Lookup Works</b>\n\n"
            "This tool checks if a username exists across "
            f"{bold(str(len(SOCIAL_PLATFORMS)))} social media platforms simultaneously.\n\n"
            "<b>How it works:</b>\n"
            "• Sends HTTP requests to each platform's profile page\n"
            "• Analyzes the response to determine if the profile exists\n"
            "• A 404 response means the profile doesn't exist\n"
            "• Any other response (200, 301, 302) likely means found\n\n"
            "<b>For GitHub specifically:</b>\n"
            "• Uses the GitHub API to fetch profile details\n"
            "• Shows bio, public repos, followers, and more\n\n"
            f"{italic('Note: Some platforms use rate limiting or CAPTCHAs, which may cause false negatives.')}"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🎯 Use Cases", callback_data="social:uses"),
                    InlineKeyboardButton("← Back", callback_data="social:menu"),
                ],
            ]),
        )

    elif action == "uses":
        uses_text = (
            "🎯 <b>Common Use Cases</b>\n\n"
            "🕵️ <b>OSINT Investigations:</b>\n"
            "  Map a target's digital footprint across platforms. "
            "Find linked accounts to build a comprehensive profile.\n\n"
            "💼 <b>Background Checks:</b>\n"
            "  Verify a person's identity by cross-referencing their "
            "claimed social media presence.\n\n"
            "🔒 <b>Social Engineering Defense:</b>\n"
            "  Check if your own username is being impersonated.\n"
            "  Find accounts that might be pretending to be you.\n\n"
            "⚠️ <b>Fraud Detection:</b>\n"
            "  Scammers often reuse the same username across platforms. "
            "  Finding multiple accounts with the same name can indicate fraud.\n\n"
            "👤 <b>Digital Footprint Audit:</b>\n"
            "  See how visible you are online. Understand what information "
            "  is publicly available about you."
        )
        await query.edit_message_text(
            uses_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 How It Works", callback_data="social:about"),
                    InlineKeyboardButton("← Back", callback_data="social:menu"),
                ],
            ]),
        )

    elif action == "menu":
        platform_list = " • ".join(
            f"{p['emoji']} {p['name']}" for p in SOCIAL_PLATFORMS[:8]
        )
        await query.edit_message_text(
            f"{bold('🔍 Social Media Lookup')}\n\n"
            f"Search for a username across {bold(str(len(SOCIAL_PLATFORMS)))} social platforms.\n\n"
            f"Usage: {code('/social <username>')}\n\n"
            f"{bold('Platforms:')} {platform_list} + more\n\n"
            f"Example: {code('/social johndoe')}",
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


# ── Platform Check Engine ──────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


async def _check_single_platform(
    platform: dict,
    username: str,
    session: aiohttp.ClientSession,
) -> tuple[dict, bool]:
    """Check a single platform for the given username."""
    url = platform["check_url"].format(username=username)
    method = platform.get("method", "HEAD").upper()
    detect = platform.get("detect", "status_not_404")

    try:
        if method == "GET":
            async with session.get(
                url, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
            ) as response:
                status = response.status
                extra = None
                if platform.get("parse") == "github" and status == 200:
                    try:
                        extra = await response.json()
                    except Exception:
                        pass
        else:
            async with session.head(
                url, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
            ) as response:
                status = response.status
                extra = None

        if detect == "status_200":
            found = status == 200
        else:
            found = status != 404

        return platform, found, extra

    except asyncio.TimeoutError:
        return platform, False, None
    except aiohttp.ClientError:
        return platform, False, None
    except Exception:
        return platform, False, None


async def _check_all_platforms(username: str) -> dict:
    """Check all platforms concurrently."""
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _check_single_platform(platform, username, session)
            for platform in SOCIAL_PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    platform_results = []
    github_data = None

    for result in results:
        if isinstance(result, Exception):
            continue
        platform, found, extra = result
        platform_results.append((platform, found))
        if platform.get("parse") == "github" and extra:
            github_data = extra

    platform_results.sort(key=lambda x: (0 if x[1] else 1, x[0]["name"]))

    return {
        "platforms": platform_results,
        "github_data": github_data,
    }


# ── Report Formatter ───────────────────────────────────────────────────────────

def _format_social_report(username: str, results: dict) -> str:
    """Build formatted social media lookup report."""
    platforms = results.get("platforms", [])
    github_data = results.get("github_data")

    found = [(p, f) for p, f in platforms if f]
    not_found = [(p, f) for p, f in platforms if not f]

    lines = [
        f"{bold('🔍 Social Media Lookup Report')}",
        f"{'━' * 32}",
        "",
        f"📌 {bold('Target:')} {code(username)}",
        f"📊 {bold('Platforms Checked:')} {len(platforms)}",
    ]

    # GitHub detailed info
    if github_data:
        lines.append("")
        lines.append(f"{bold('🐙 GitHub Profile Details')}")
        if github_data.get("name"):
            lines.append(f"  👤 Name: {escape_html(github_data['name'])}")
        if github_data.get("bio"):
            lines.append(f"  📝 Bio: {escape_html(github_data['bio'][:150])}")
        if github_data.get("location"):
            lines.append(f"  📍 Location: {escape_html(github_data['location'])}")
        if github_data.get("company"):
            lines.append(f"  🏢 Company: {escape_html(github_data['company'])}")
        if github_data.get("blog"):
            lines.append(f"  🔗 Website: {escape_html(github_data['blog'])}")
        lines.append(f"  📦 Public Repos: {bold(str(github_data.get('public_repos', 0)))}")
        lines.append(f"  👥 Followers: {bold(str(github_data.get('followers', 0)))}")
        lines.append(f"  🤝 Following: {bold(str(github_data.get('following', 0)))}")
        if github_data.get("created_at"):
            lines.append(f"  📅 Joined: {escape_html(github_data['created_at'][:10])}")
        if github_data.get("twitter_username"):
            lines.append(f"  🐦 Twitter: @{escape_html(github_data['twitter_username'])}")

    # Found platforms
    lines.append("")
    if found:
        lines.append(f"{bold(f'✅ Found on {len(found)} platform(s):')}")
        for platform, _ in found:
            profile_url = platform["profile_url"].format(username=username)
            platform_link = link(f"{platform['emoji']} {platform['name']}", profile_url)
            lines.append(f"  • {platform_link}")
    else:
        lines.append(f"{bold('❌ Not found on any platform.')}")
        lines.append(italic("Username not found on any checked platform."))

    # Not found
    lines.append("")
    if not_found:
        lines.append(f"{bold(f'🚫 Not found on {len(not_found)} platform(s):')}")
        not_found_names = ", ".join(f"{p['emoji']}" for p, _ in not_found)
        lines.append(f"  {not_found_names}")

    # Footer
    lines.append("")
    lines.append(f"{'━' * 32}")
    lines.append(italic("Tap platform buttons below to visit profiles."))
    lines.append(italic("Results may not be 100% accurate due to rate limits and anti-bot measures."))

    return "\n".join(lines)
