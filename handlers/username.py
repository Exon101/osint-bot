"""
Username Enumeration Handler
Checks if a given username exists across multiple social platforms
using asynchronous HTTP HEAD requests.
"""

import asyncio
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


# ── Platform Definitions ───────────────────────────────────────────────────────
# Each entry: (display_name, emoji, url_template, detection_logic)
# url_template uses {username} as a placeholder.
# detection: "status_200" (found on 200) or "status_not_404" (found if NOT 404).

PLATFORMS: list[dict] = [
    {
        "name": "GitHub",
        "emoji": "🐙",
        "url": "https://github.com/{username}",
        "detect": "status_not_404",
        "method": "GET",
        "profile_link": "https://github.com/{username}",
    },
    {
        "name": "Reddit",
        "emoji": "🤖",
        "url": "https://www.reddit.com/user/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.reddit.com/user/{username}",
    },
    {
        "name": "X (Twitter)",
        "emoji": "🐦",
        "url": "https://x.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://x.com/{username}",
    },
    {
        "name": "Instagram",
        "emoji": "📸",
        "url": "https://www.instagram.com/{username}/",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.instagram.com/{username}/",
    },
    {
        "name": "TikTok",
        "emoji": "🎵",
        "url": "https://www.tiktok.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.tiktok.com/@{username}",
    },
    {
        "name": "YouTube",
        "emoji": "▶️",
        "url": "https://www.youtube.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.youtube.com/@{username}",
    },
    {
        "name": "Facebook",
        "emoji": "📘",
        "url": "https://www.facebook.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.facebook.com/{username}",
    },
    {
        "name": "LinkedIn",
        "emoji": "💼",
        "url": "https://www.linkedin.com/in/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.linkedin.com/in/{username}",
    },
    {
        "name": "Pinterest",
        "emoji": "📌",
        "url": "https://www.pinterest.com/{username}/",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.pinterest.com/{username}/",
    },
    {
        "name": "Twitch",
        "emoji": "🟣",
        "url": "https://www.twitch.tv/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.twitch.tv/{username}",
    },
    {
        "name": "Medium",
        "emoji": "📝",
        "url": "https://medium.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://medium.com/@{username}",
    },
    {
        "name": "Keybase",
        "emoji": "🔑",
        "url": "https://keybase.io/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://keybase.io/{username}",
    },
    {
        "name": "DevTo",
        "emoji": "💻",
        "url": "https://dev.to/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://dev.to/{username}",
    },
    {
        "name": "Steam",
        "emoji": "🎮",
        "url": "https://steamcommunity.com/id/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://steamcommunity.com/id/{username}",
    },
    {
        "name": "Snapchat",
        "emoji": "👻",
        "url": "https://www.snapchat.com/add/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.snapchat.com/add/{username}",
    },
    {
        "name": "Telegram",
        "emoji": "✈️",
        "url": "https://t.me/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://t.me/{username}",
    },
    {
        "name": "SoundCloud",
        "emoji": "🔊",
        "url": "https://soundcloud.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://soundcloud.com/{username}",
    },
    {
        "name": "Spotify",
        "emoji": "🟢",
        "url": "https://open.spotify.com/user/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://open.spotify.com/user/{username}",
    },
    {
        "name": "Threads",
        "emoji": "🧵",
        "url": "https://www.threads.net/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.threads.net/@{username}",
    },
    {
        "name": "Flickr",
        "emoji": "📷",
        "url": "https://www.flickr.com/people/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.flickr.com/people/{username}",
    },
    {
        "name": "Vimeo",
        "emoji": "🎬",
        "url": "https://vimeo.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://vimeo.com/{username}",
    },
    {
        "name": "Mastodon",
        "emoji": "🐘",
        "url": "https://mastodon.social/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://mastodon.social/@{username}",
    },
    {
        "name": "About.me",
        "emoji": "👤",
        "url": "https://{username}.about.me",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://{username}.about.me",
    },
    {
        "name": "Gravatar",
        "emoji": "🖼️",
        "url": "https://en.gravatar.com/profile/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://gravatar.com/{username}",
    },
    {
        "name": "Patreon",
        "emoji": "🎨",
        "url": "https://www.patreon.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.patreon.com/{username}",
    },
    {
        "name": "Tumblr",
        "emoji": "📝",
        "url": "https://{username}.tumblr.com",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://{username}.tumblr.com",
    },
    {
        "name": "DeviantArt",
        "emoji": "🎨",
        "url": "https://www.deviantart.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://www.deviantart.com/{username}",
    },
    {
        "name": "HackerNews",
        "emoji": "📰",
        "url": "https://news.ycombinator.com/user?id={username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://news.ycombinator.com/user?id={username}",
    },
    {
        "name": "Replit",
        "emoji": "⚡",
        "url": "https://replit.com/@{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://replit.com/@{username}",
    },
    {
        "name": "GitLab",
        "emoji": "🦊",
        "url": "https://gitlab.com/{username}",
        "detect": "status_not_404",
        "method": "HEAD",
        "profile_link": "https://gitlab.com/{username}",
    },
]


async def cmd_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /user <username> and /username <username>.
    Checks existence of the username across all configured platforms.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    # Parse arguments
    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('ℹ️ Usage:')} {code('/user <username>')}\n\n"
            f"Example: {code('/user johndoe')}\n\n"
            f"Checks if the username exists across:\n"
            f"GitHub, Reddit, Twitter, Instagram, TikTok, YouTube, Medium, Keybase, DevTo",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_username = sanitize_input(args[0], max_length=39)

    # Basic username validation: alphanumeric, underscores, hyphens
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,37}[a-zA-Z0-9]$', raw_username) and \
       not re.match(r'^[a-zA-Z0-9]{1,39}$', raw_username):
        await update.message.reply_text(
            f"❌ {bold('Invalid username format.')}\n\n"
            f"Usernames should be 1-39 characters and contain only letters, "
            f"numbers, hyphens, underscores, and periods.",
            parse_mode=ParseMode.HTML,
        )
        return

    username = raw_username
    processing_msg = await update.message.reply_text(
        f"🔍 Searching for {code(username)} across {bold(str(len(PLATFORMS)))} platforms …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        # Run all checks concurrently
        results = await _check_all_platforms(username)
        result_text = _format_username_report(username, results)

        # Build keyboard with links to found profiles
        found_links = []
        for platform, found in results:
            if found:
                profile_url = platform["profile_link"].format(username=username)
                found_links.append(
                    InlineKeyboardButton(
                        f"{platform['emoji']} {platform['name']}",
                        url=profile_url,
                    )
                )

        # Arrange buttons in rows of 2
        button_rows = []
        for i in range(0, len(found_links), 2):
            row = found_links[i:i + 2]
            button_rows.append(row)

        # Add navigation buttons
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

        log_query(user_id, "username", query=username, result="success")

    except Exception as exc:
        logger.error("Username lookup failed for %s: %s", username, exc)
        await processing_msg.edit_text(
            f"❌ Username lookup failed for {code(username)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "username", query=username, result=f"error: {exc}")


async def handle_username_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the username lookup module."""
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


# ── Platform Check Engine ──────────────────────────────────────────────────────

async def _check_single_platform(
    platform: dict,
    username: str,
    session: aiohttp.ClientSession,
) -> tuple[dict, bool]:
    """
    Check a single platform for the given username.

    Returns:
        Tuple of (platform dict, found: bool).

    Detection strategies:
    - "status_not_404": Username exists if we get any response other than 404.
      This is more reliable as many platforms redirect existing users (301/302).
    - "status_200": Username exists only on an explicit 200 OK.
    """
    url = platform["url"].format(username=username)
    method = platform.get("method", "HEAD").upper()
    detect = platform.get("detect", "status_not_404")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        if method == "GET":
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as response:
                status = response.status
        else:
            async with session.head(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as response:
                status = response.status

        if detect == "status_200":
            found = status == 200
        else:
            # status_not_404: treat redirects and 200 as "found"
            found = status != 404

        return platform, found

    except asyncio.TimeoutError:
        return platform, False
    except aiohttp.ClientError:
        return platform, False
    except Exception:
        return platform, False


async def _check_all_platforms(username: str) -> list[tuple[dict, bool]]:
    """
    Check all platforms concurrently for the given username.

    Returns:
        List of (platform_dict, found_bool) tuples, sorted with found results first.
    """
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _check_single_platform(platform, username, session)
            for platform in PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    clean_results = []
    for result in results:
        if isinstance(result, Exception):
            continue
        clean_results.append(result)

    # Sort: found platforms first, then not found
    clean_results.sort(key=lambda x: (0 if x[1] else 1, x[0]["name"]))

    return clean_results


# ── Report Formatter ───────────────────────────────────────────────────────────

def _format_username_report(
    username: str,
    results: list[tuple[dict, bool]],
) -> str:
    """Build a formatted username enumeration report."""

    found = [(p, f) for p, f in results if f]
    not_found = [(p, f) for p, f in results if not f]

    lines = [
        f"{bold('👤 Username Enumeration Report')}",
        f"{'━' * 32}",
        "",
        f"📌 {bold('Target:')} {code(username)}",
        f"🔍 {bold(f'Platforms Checked:')} {len(results)}",
    ]

    # ── Found Platforms ────────────────────────────────────────────────────
    lines.append("")
    if found:
        lines.append(f"{bold(f'✅ Found on {len(found)} platform(s):')}")
        for platform, _ in found:
            profile_url = platform["profile_link"].format(username=username)
            platform_link = link(f"{platform['emoji']} {platform['name']}", profile_url)
            lines.append(f"  • {platform_link}")
    else:
        lines.append(f"{bold('❌ Not found on any platform.')}")
        lines.append(italic("The username does not appear to be registered on any of the checked platforms."))

    # ── Not Found Platforms ────────────────────────────────────────────────
    lines.append("")
    if not_found:
        lines.append(f"{bold(f'🚫 Not found on {len(not_found)} platform(s):')}")
        for platform, _ in not_found:
            lines.append(f"  {platform['emoji']} {platform['name']}")

    # ── Footer ─────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'━' * 32}")

    if found:
        lines.append(f"💡 {italic('Tap the platform buttons below to visit profiles.')}")
    else:
        lines.append(
            "💡 " + italic("Note: Some platforms may block automated checks. "
                           "Manual verification is recommended.")
        )
    lines.append(italic("Results may not be 100% accurate due to rate limits and anti-bot measures."))

    return "\n".join(lines)
