"""
Hacker News / Cybersecurity News Handler for Telegram OSINT Bot.

Aggregates headlines from multiple RSS/Atom feeds using manual XML parsing.
Commands:
    /news           — Fetch latest cybersecurity headlines (all categories)
    /news threats   — Filter by category: threats, malware, privacy, vulns, all
"""

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html
import aiohttp
import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Feed sources
# ---------------------------------------------------------------------------

FEED_SOURCES: list[dict] = [
    {
        "id": "hackernews",
        "name": "Hacker News",
        "url": "https://hnrss.org/newest?points=50",
        "category": "all",
        "icon": "🔶",
        "type": "rss",
    },
    {
        "id": "thehackernews",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "all",
        "icon": "🔴",
        "type": "rss",
    },
    {
        "id": "krebsonsecurity",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "all",
        "icon": "🟡",
        "type": "rss",
    },
]

# Category keyword matching (simple fuzzy filter)
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "threats": [
        "apt", "threat", "attack", "campaign", "nation-state", "espionage",
        "phishing", "ransomware", "apt group", "hacking group", "cyberattack",
        "spear-phishing", "supply chain", "dprk", "china", "russia", "iran",
        "apt2", "apt3", "lazarus", "fancy bear", "cozy bear",
    ],
    "malware": [
        "malware", "trojan", "rat", "backdoor", "worm", "rootkit",
        "botnet", "cryptominer", "info-stealer", "infostealer", "wiper",
        "virus", "spyware", "adware", "keylogger", "payload", "exploit kit",
    ],
    "privacy": [
        "privacy", "surveillance", "data breach", "data leak", "gdpr",
        "encryption", "vpn", "tracking", "fingerprint", "metadata",
        "zero-knowledge", "e2ee", "anonymity", "tor", "signal", "whatsapp",
    ],
    "vulns": [
        "vulnerability", "cve-", "exploit", "patch", "zero-day", "0-day",
        "rce", "lfi", "rfi", "xss", "sql injection", "ssrf", "deserialization",
        "buffer overflow", "privilege escalation", "authentication bypass",
    ],
}

VALID_CATEGORIES = ["all", "threats", "malware", "privacy", "vulns"]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FeedItem:
    """Represents a single news item from a feed."""
    title: str = ""
    link: str = ""
    source: str = ""
    source_icon: str = "📰"
    published: str = ""
    description: str = ""
    category: str = "all"
    category_tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# RSS XML parser (no feedparser — manual regex-based parsing)
# ---------------------------------------------------------------------------

async def _fetch_feed(session: aiohttp.ClientSession, url: str, timeout: int = 15) -> Optional[str]:
    """Fetch raw XML/HTML content from a feed URL."""
    headers = {
        "User-Agent": "OSINT-Bot/1.0 (Telegram; +https://t.me/osintbot)",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, text/html",
    }
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                return await resp.text()
            else:
                logger.warning("Feed fetch failed: %s returned %s", url, resp.status)
                return None
    except asyncio.TimeoutError:
        logger.warning("Feed fetch timeout: %s", url)
        return None
    except Exception as exc:
        logger.error("Feed fetch error for %s: %s", url, exc)
        return None


def _decode_html_entities(text: str) -> str:
    """Decode common HTML entities in XML content."""
    entities = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&#39;": "'",
        "&#x27;": "'",
        "&nbsp;": " ",
    }
    for entity, char in entities.items():
        text = text.replace(entity, char)
    # Handle numeric entities like &#8217; etc.
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)
    text = re.sub(r"&#[xX]([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), text)
    return text


def _strip_tags(html: str) -> str:
    """Remove HTML/XML tags from a string."""
    clean = re.sub(r"<[^>]+>", "", html)
    return _decode_html_entities(clean).strip()


def _parse_rss_items(xml_text: str) -> list[dict]:
    """
    Parse RSS 2.0 items from raw XML text using regex.
    Handles both <item> and <entry> (Atom) tags.
    """
    items: list[dict] = []

    # Try RSS <item> first
    item_blocks = re.findall(r"<item>(.*?)</item>", xml_text, re.DOTALL | re.IGNORECASE)

    # Fallback to Atom <entry>
    if not item_blocks:
        item_blocks = re.findall(r"<entry>(.*?)</entry>", xml_text, re.DOTALL | re.IGNORECASE)

    if not item_blocks:
        return items

    for block in item_blocks:
        item: dict = {}

        # Title — try both <title> and <title>...</title>
        # Some feeds have CDATA
        title_match = re.search(
            r"<title[^>]*><!\[CDATA\[(.*?)\]\]></title>|<title[^>]*>(.*?)</title>",
            block, re.DOTALL | re.IGNORECASE,
        )
        if title_match:
            item["title"] = _strip_tags(title_match.group(1) or title_match.group(2) or "")
        else:
            item["title"] = "Untitled"

        # Link
        link_match = re.search(
            r"<link[^>]*>(.*?)</link>|<link[^>]*href=[\"'](.*?)[\"']",
            block, re.DOTALL | re.IGNORECASE,
        )
        if link_match:
            item["link"] = _strip_tags(link_match.group(1) or link_match.group(2) or "").strip()
        else:
            item["link"] = ""

        # Description / Summary
        desc_match = re.search(
            r"<(?:description|summary|content)[^>]*><!\[CDATA\[(.*?)\]\]></(?:description|summary|content)>"
            r"|<(?:description|summary|content)[^>]*>(.*?)</(?:description|summary|content)>",
            block, re.DOTALL | re.IGNORECASE,
        )
        if desc_match:
            item["description"] = _strip_tags(desc_match.group(1) or desc_match.group(2) or "")
        else:
            item["description"] = ""

        # Published date
        pub_match = re.search(
            r"<(?:pubDate|published|updated|dc:date)[^>]*>(.*?)</(?:pubDate|published|updated|dc:date)>",
            block, re.DOTALL | re.IGNORECASE,
        )
        if pub_match:
            date_str = _strip_tags(pub_match.group(1))
            # Clean up date format — keep it reasonable
            date_str = re.sub(r"\s+", " ", date_str).strip()
            # Truncate to keep message short
            item["published"] = date_str[:50]
        else:
            item["published"] = ""

        items.append(item)

    return items


def _categorize_item(title: str, description: str) -> list[str]:
    """Categorize a news item based on keywords in title and description."""
    combined = (title + " " + description).lower()
    matched: list[str] = []
    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in combined:
                matched.append(cat)
                break
    return matched if matched else ["all"]


async def _fetch_all_feeds(category: str = "all") -> list[FeedItem]:
    """Fetch and parse all feed sources, optionally filtering by category."""
    all_items: list[FeedItem] = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for source in FEED_SOURCES:
            tasks.append(_fetch_feed(session, source["url"]))

        results = await asyncio.gather(*tasks, return_exceptions=True)

    for idx, result in enumerate(results):
        source = FEED_SOURCES[idx]

        if isinstance(result, Exception) or result is None:
            logger.warning("Failed to fetch feed: %s", source["name"])
            continue

        items = _parse_rss_items(result)

        for item in items[:10]:  # Cap per source
            cats = _categorize_item(item["title"], item["description"])

            if category != "all" and category not in cats:
                continue

            feed_item = FeedItem(
                title=_strip_tags(item.get("title", "")).strip(),
                link=item.get("link", ""),
                source=source["name"],
                source_icon=source["icon"],
                published=item.get("published", ""),
                description=_strip_tags(item.get("description", ""))[:200],
                category=", ".join(cats) if cats != ["all"] else "general",
                category_tags=cats,
            )
            all_items.append(feed_item)

    return all_items


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _format_news_items(items: list[FeedItem], category: str = "all") -> str:
    """Format news items into a Telegram-friendly message."""
    cat_label = category.upper() if category != "all" else "ALL"
    lines: list[str] = []
    lines.append(f"{bold(f'📰 Cybersecurity News — {cat_label}')}\n")

    if not items:
        lines.append(f"{italic('No headlines found for this category. Try /news all')}")
        return "\n".join(lines)

    for i, item in enumerate(items, 1):
        source_tag = f"{item.source_icon} {item.source}"
        cat_tag = f"[{item.category}]" if item.category != "general" else ""

        title_display = escape_html(item.title[:120])
        if len(item.title) > 120:
            title_display += "…"

        lines.append(f"{bold(f'{i}.')} {title_display}")
        if cat_tag:
            lines.append(f"   {source_tag}  {italic(cat_tag)}")
        else:
            lines.append(f"   {source_tag}")

    lines.append(f"\n{italic(f'Showing {len(items)} headlines from {len(set(i.source for i in items))} sources.')}")
    return "\n".join(lines)


def _build_category_keyboard(current_category: str) -> InlineKeyboardMarkup:
    """Build inline keyboard for category filtering."""
    buttons: list[list[InlineKeyboardButton]] = []

    # Category row
    cat_buttons = []
    for cat in VALID_CATEGORIES:
        label = cat.upper()
        if cat == current_category:
            label = f"✅ {label}"
        cat_buttons.append(InlineKeyboardButton(
            text=label,
            callback_data=f"news:category:{cat}",
        ))
    buttons.append(cat_buttons)

    return InlineKeyboardMarkup(buttons)


def _build_article_keyboard(items: list[FeedItem]) -> InlineKeyboardMarkup:
    """Build inline keyboard with links to articles."""
    buttons: list[list[InlineKeyboardButton]] = []

    for item in items[:6]:
        if item.link:
            # Truncate button label
            label = item.title[:60] + "…" if len(item.title) > 60 else item.title
            buttons.append([InlineKeyboardButton(
                text=f"🔗 {label}",
                url=item.link,
            )])

    # Add refresh and category buttons
    buttons.append([
        InlineKeyboardButton("🔄 Refresh", callback_data="news:refresh"),
        InlineKeyboardButton("📋 Categories", callback_data="news:categories"),
    ])

    return InlineKeyboardMarkup(buttons)


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

async def cmd_news(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /news command — fetch and display cybersecurity headlines."""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Parse category argument
    category = "all"
    if context.args:
        raw_cat = sanitize_input(" ".join(context.args)).strip().lower()
        if raw_cat in VALID_CATEGORIES:
            category = raw_cat
        elif raw_cat in ("list", "help"):
            await update.message.reply_text(
                f"{bold('📰 News Categories')}\n\n"
                "Available categories:\n"
                f"  {code('/news all')}      — All headlines\n"
                f"  {code('/news threats')}  — APTs, campaigns, attacks\n"
                f"  {code('/news malware')}  — Malware, trojans, botnets\n"
                f"  {code('/news privacy')}  — Privacy, surveillance, encryption\n"
                f"  {code('/news vulns')}    — Vulnerabilities, CVEs, exploits\n\n"
                f"Sources: Hacker News, The Hacker News, Krebs on Security",
                parse_mode=ParseMode.HTML,
            )
            return
        else:
            await update.message.reply_text(
                f"Unknown category: {code(raw_cat)}\n"
                f"Valid categories: {', '.join(code(c) for c in VALID_CATEGORIES)}",
                parse_mode=ParseMode.HTML,
            )
            return

    # Rate limit
    if not check_rate_limit(user_id, "news"):
        await update.message.reply_text(
            "⏳ Rate limit reached. Please wait before making another request.",
            parse_mode=ParseMode.HTML,
        )
        return

    log_query(user_id, "news", category)
    increment_usage(user_id)

    await update.message.reply_text(
        f"📰 Fetching latest {category.upper()} headlines…",
        parse_mode=ParseMode.HTML,
    )

    items = await _fetch_all_feeds(category)

    if not items:
        await update.message.reply_text(
            f"{bold('❌ No headlines found')}\n\n"
            f"Could not fetch news at this time. The feeds may be temporarily unavailable.\n"
            f"Please try again in a moment.",
            parse_mode=ParseMode.HTML,
        )
        return

    # Sort by source for readability, cap total items
    items = items[:8]

    message = _format_news_items(items, category)
    keyboard = _build_article_keyboard(items)

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )


# ---------------------------------------------------------------------------
# Callback query handler
# ---------------------------------------------------------------------------

async def handle_news_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from news results."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith("news:"):
        return

    parts = data.split(":")
    if len(parts) < 2:
        return

    sub = parts[1]
    user_id = query.from_user.id

    if sub == "category":
        category = parts[2] if len(parts) > 2 else "all"
        await query.answer(f"Loading {category.upper()} headlines…")

        if not check_rate_limit(user_id, "news"):
            await query.answer("⏳ Rate limit reached.", show_alert=True)
            return

        log_query(user_id, "news_callback", category)
        increment_usage(user_id)

        items = await _fetch_all_feeds(category)
        items = items[:8]

        if not items:
            message = f"{bold('❌ No headlines found')}\n\nNo items match the '{category}' category."
            await query.edit_message_text(
                message,
                parse_mode=ParseMode.HTML,
                reply_markup=_build_category_keyboard(category),
            )
            return

        message = _format_news_items(items, category)
        keyboard = _build_article_keyboard(items)

        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )

    elif sub == "refresh":
        category = "all"
        await query.answer("Refreshing headlines…")

        if not check_rate_limit(user_id, "news"):
            await query.answer("⏳ Rate limit reached.", show_alert=True)
            return

        increment_usage(user_id)

        items = await _fetch_all_feeds(category)
        items = items[:8]

        if not items:
            message = f"{bold('❌ No headlines found')}\n\nFeeds may be temporarily unavailable."
            await query.edit_message_text(
                message,
                parse_mode=ParseMode.HTML,
                reply_markup=_build_category_keyboard(category),
            )
            return

        message = _format_news_items(items, category)
        keyboard = _build_article_keyboard(items)

        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )

    elif sub == "categories":
        category = "all"
        cat_lines: list[str] = []
        cat_lines.append(f"{bold('📰 News Categories')}\n")
        for cat in VALID_CATEGORIES:
            label = cat.upper()
            description = {
                "all": "All headlines from all sources",
                "threats": "APTs, campaigns, state-sponsored attacks",
                "malware": "Malware, trojans, botnets, info-stealers",
                "privacy": "Privacy, surveillance, encryption",
                "vulns": "Vulnerabilities, CVEs, zero-days, exploits",
            }.get(cat, "")
            cat_lines.append(f"  {bold(label)}  —  {italic(description)}")

        cat_lines.append(f"\n{italic('Sources: Hacker News, The Hacker News, Krebs on Security')}")

        buttons: list[list[InlineKeyboardButton]] = []
        row = []
        for cat in VALID_CATEGORIES:
            row.append(InlineKeyboardButton(
                text=cat.upper(),
                callback_data=f"news:category:{cat}",
            ))
            if len(row) == 3:
                buttons.append(row)
                row = []
        if row:
            buttons.append(row)
        buttons.append([InlineKeyboardButton("🔙 Back to News", callback_data="news:refresh")])

        await query.edit_message_text(
            "\n".join(cat_lines),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
