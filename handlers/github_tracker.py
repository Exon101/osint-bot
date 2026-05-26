"""
GitHub Tracker Handler for Telegram OSINT Bot.

Provides repository information, security scanning, and trending repos.
Commands:
    /github owner/repo      — Show repo info, releases, security
    /github trending        — Show trending security repos
    /github scan owner/repo — Scan for sensitive files (.env, credentials, etc.)
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
from typing import Optional
from datetime import datetime

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN = getattr(config, "GITHUB_TOKEN", None) or ""


def _gh_headers() -> dict[str, str]:
    """Return headers for GitHub API requests."""
    headers = {
        "User-Agent": "OSINT-Bot/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def _format_number(n: Optional[int]) -> str:
    """Format large numbers with K/M suffix."""
    if n is None:
        return "N/A"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _format_date(date_str: Optional[str]) -> str:
    """Format ISO date string to a readable format."""
    if not date_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, AttributeError):
        return date_str[:10]


# ---------------------------------------------------------------------------
# Sensitive file patterns for /github scan
# ---------------------------------------------------------------------------

SENSITIVE_FILE_PATTERNS: list[dict] = [
    {"pattern": r"\.env$", "name": ".env file", "severity": "CRITICAL", "emoji": "🔴"},
    {"pattern": r"credentials\.json$", "name": "credentials.json", "severity": "CRITICAL", "emoji": "🔴"},
    {"pattern": r"aws_credentials", "name": "AWS credentials", "severity": "CRITICAL", "emoji": "🔴"},
    {"pattern": r"id_rsa$", "name": "RSA private key", "severity": "CRITICAL", "emoji": "🔴"},
    {"pattern": r"id_ed25519$", "name": "Ed25519 private key", "severity": "CRITICAL", "emoji": "🔴"},
    {"pattern": r"\.pem$", "name": "PEM certificate/key", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"\.key$", "name": "Private key file", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"secret_key", "name": "Secret key reference", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"database\.yml$", "name": "Database config", "severity": "MEDIUM", "emoji": "🟡"},
    {"pattern": r"wp-config\.php$", "name": "WordPress config", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"application\.properties$", "name": "Java app properties", "severity": "MEDIUM", "emoji": "🟡"},
    {"pattern": r"\.htpasswd$", "name": "Apache password file", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"settings\.py$", "name": "Django settings", "severity": "MEDIUM", "emoji": "🟡"},
    {"pattern": r"firebase.*\.json$", "name": "Firebase config", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"travis\.yml$|\.travis\.yml$", "name": "Travis CI config", "severity": "LOW", "emoji": "🟢"},
    {"pattern": r"\.npmrc$", "name": "NPM config", "severity": "LOW", "emoji": "🟢"},
    {"pattern": r"docker-compose.*\.yml$", "name": "Docker compose", "severity": "LOW", "emoji": "🟢"},
    {"pattern": r"netrc", "name": "netrc credentials", "severity": "HIGH", "emoji": "🟠"},
    {"pattern": r"\.gitlab-ci\.yml$", "name": "GitLab CI config", "severity": "LOW", "emoji": "🟢"},
    {"pattern": r"mongo.*\.(js|py|yml)$", "name": "MongoDB connection string", "severity": "HIGH", "emoji": "🟠"},
]

# Trending search queries for security repos
TRENDING_QUERIES: list[str] = [
    "topic:security topic:tools stars:>1000 pushed:>2024-01-01",
    "topic:cve scanner stars:>500 pushed:>2024-01-01",
    "topic:vulnerability assessment stars:>500 pushed:>2024-01-01",
    "topic:osint tool stars:>200 pushed:>2024-01-01",
    "topic:reverse-engineering stars:>500 pushed:>2024-01-01",
]


# ---------------------------------------------------------------------------
# GitHub API calls
# ---------------------------------------------------------------------------

async def _get_repo_info(session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[dict]:
    """Fetch repository info from GitHub API."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    try:
        async with session.get(url, headers=_gh_headers(), timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.json()
            elif resp.status == 404:
                logger.info("Repo not found: %s/%s", owner, repo)
            elif resp.status == 403:
                logger.warning("GitHub API rate limit hit")
            else:
                logger.warning("GitHub API returned %s for %s/%s", resp.status, owner, repo)
    except Exception as exc:
        logger.error("GitHub repo info error: %s", exc)
    return None


async def _get_latest_release(session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[dict]:
    """Fetch the latest release from GitHub API."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/releases/latest"
    try:
        async with session.get(url, headers=_gh_headers(), timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception as exc:
        logger.error("GitHub release fetch error: %s", exc)
    return None


async def _get_readme(session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[str]:
    """Fetch repository README content."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/readme"
    try:
        async with session.get(url, headers={**_gh_headers(), "Accept": "application/vnd.github.v3.raw"}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception as exc:
        logger.debug("README fetch error: %s", exc)
    return None


async def _search_repos(session: aiohttp.ClientSession, query: str, per_page: int = 5) -> Optional[list[dict]]:
    """Search GitHub repositories."""
    url = f"{GITHUB_API_BASE}/search/repositories?q={query}&sort=stars&order=desc&per_page={per_page}"
    try:
        async with session.get(url, headers=_gh_headers(), timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("items", [])
            elif resp.status == 403:
                logger.warning("GitHub search API rate limit hit")
            else:
                logger.warning("GitHub search returned %s", resp.status)
    except Exception as exc:
        logger.error("GitHub search error: %s", exc)
    return None


async def _search_code(session: aiohttp.ClientSession, owner: str, repo: str, filename_pattern: str) -> Optional[list[dict]]:
    """Search for files in a repository matching a pattern."""
    query = f"{filename_pattern} repo:{owner}/{repo}"
    url = f"{GITHUB_API_BASE}/search/code?q={query}&per_page=3"
    try:
        async with session.get(url, headers=_gh_headers(), timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("items", [])
            elif resp.status == 422:
                # Search qualifier error
                return []
            elif resp.status == 403:
                logger.warning("GitHub code search rate limit hit")
                return None
            else:
                return []
    except Exception as exc:
        logger.error("GitHub code search error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _format_repo_info(repo_data: dict, release: Optional[dict] = None) -> str:
    """Format repository information for display."""
    full_name = repo_data.get("full_name", "Unknown")
    description = repo_data.get("description") or "No description"
    html_url = repo_data.get("html_url", "")

    stars = repo_data.get("stargazers_count", 0)
    forks = repo_data.get("forks_count", 0)
    open_issues = repo_data.get("open_issues_count", 0)
    watchers = repo_data.get("watchers_count", 0)
    language = repo_data.get("language", "Unknown")
    license_info = repo_data.get("license")
    license_name = license_info.get("spdx_id", "N/A") if license_info else "N/A"
    default_branch = repo_data.get("default_branch", "main")
    created = _format_date(repo_data.get("created_at"))
    updated = _format_date(repo_data.get("updated_at"))
    pushed = _format_date(repo_data.get("pushed_at"))
    is_archived = repo_data.get("archived", False)
    is_fork = repo_data.get("fork", False)
    size_kb = repo_data.get("size", 0)
    topics = repo_data.get("topics", [])

    lines: list[str] = []
    lines.append(f"{bold(f'📦 {full_name}')}\n")

    if description:
        desc_display = description[:300] + "…" if len(description) > 300 else description
        lines.append(escape_html(desc_display))
        lines.append("")

    # Stats row
    lines.append(
        f"⭐ {_format_number(stars)}   "
        f"🍴 {_format_number(forks)}   "
        f"👁 {_format_number(watchers)}   "
        f"🐛 {open_issues}"
    )
    lines.append(f"💻 {language}   📜 {license_name}")
    lines.append(f"🌿 Branch: {code(default_branch)}")

    if is_archived:
        lines.append("⚠️ Archived repository")
    if is_fork:
        parent = repo_data.get("parent", {})
        lines.append(f"🔀 Fork of {code(parent.get('full_name', 'unknown'))}")

    lines.append(f"\n📅 Created: {created}   Updated: {updated}   Pushed: {pushed}")
    lines.append(f"📦 Size: {size_kb} KB")

    if topics:
        lines.append(f"\n🏷 Topics: {', '.join(code(t) for t in topics[:10])}")

    # Latest release
    if release:
        tag = release.get("tag_name", "Unknown")
        release_name = release.get("name", "")
        release_date = _format_date(release.get("published_at"))
        prerelease = release.get("prerelease", False)
        release_url = release.get("html_url", "")

        lines.append(f"\n{bold('🚀 Latest Release:')}")
        label = f"{tag}" + (f" — {release_name}" if release_name else "")
        if prerelease:
            label += " (pre-release)"
        lines.append(f"  {bold(label)}")
        lines.append(f"  📅 {release_date}")
        if release_url:
            lines.append(f"  🔗 {link(release_url, 'Release Notes')}")

    return "\n".join(lines)


def _build_repo_keyboard(owner: str, repo: str) -> InlineKeyboardMarkup:
    """Build inline keyboard for repo actions."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 Open in Browser", url=f"https://github.com/{owner}/{repo}"),
            InlineKeyboardButton("📦 Releases", url=f"https://github.com/{owner}/{repo}/releases"),
        ],
        [
            InlineKeyboardButton("🐛 Issues", url=f"https://github.com/{owner}/{repo}/issues"),
            InlineKeyboardButton("📜 README", url=f"https://github.com/{owner}/{repo}#readme"),
        ],
        [
            InlineKeyboardButton("🔍 Security", url=f"https://github.com/{owner}/{repo}/security"),
            InlineKeyboardButton("📊 Insights", url=f"https://github.com/{owner}/{repo}/pulse"),
        ],
    ])


def _format_trending(repos: list[dict]) -> str:
    """Format trending repos list."""
    lines: list[str] = []
    lines.append(f"{bold('🔥 Trending Security Repos')}\n")
    lines.append(f"{italic('Popular security-related repositories on GitHub')}\n")

    buttons: list[list[InlineKeyboardButton]] = []

    for i, repo in enumerate(repos[:8], 1):
        full_name = repo.get("full_name", "Unknown")
        description = repo.get("description") or "No description"
        stars = repo.get("stargazers_count", 0)
        language = repo.get("language", "")
        updated = _format_date(repo.get("updated_at", ""))

        short_desc = (description[:100] + "…") if len(description) > 100 else description
        lines.append(f"{bold(f'{i}.')} {code(full_name)}  ⭐{_format_number(stars)}")
        if language:
            lines.append(f"   💻 {language}  •  {escape_html(short_desc)}")
        else:
            lines.append(f"   {escape_html(short_desc)}")
        lines.append(f"   📅 Updated: {updated}")
        lines.append("")

        owner, repo_name = full_name.split("/", 1) if "/" in full_name else (full_name, "")
        buttons.append([InlineKeyboardButton(
            f"📦 {full_name}",
            callback_data=f"github:repo:{owner}/{repo_name}",
        )])

    return "\n".join(lines), InlineKeyboardMarkup(buttons)


def _format_scan_results(findings: list[dict], owner: str, repo: str) -> str:
    """Format security scan results."""
    lines: list[str] = []
    lines.append(f"{bold(f'🔐 Security Scan: {owner}/{repo}')}\n")

    if not findings:
        lines.append(f"✅ {bold('No sensitive files detected')}\n")
        lines.append(italic("The repository was scanned for common sensitive file patterns."))
        lines.append(italic("Note: This is a surface-level scan and does not guarantee the absence of all secrets."))
        return "\n".join(lines)

    # Group by severity
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]

    lines.append(f"{bold(f'⚠️  Found {len(findings)} potential sensitive file(s)')}\n")

    if critical:
        lines.append(f"{bold('🔴 CRITICAL')} ({len(critical)})")
        for f in critical:
            lines.append(f"  • {f['name']} — {f.get('path', '')}")
        lines.append("")

    if high:
        lines.append(f"{bold('🟠 HIGH')} ({len(high)})")
        for f in high:
            lines.append(f"  • {f['name']} — {f.get('path', '')}")
        lines.append("")

    if medium:
        lines.append(f"{bold('🟡 MEDIUM')} ({len(medium)})")
        for f in medium:
            lines.append(f"  • {f['name']} — {f.get('path', '')}")
        lines.append("")

    if low:
        lines.append(f"{bold('🟢 LOW')} ({len(low)})")
        for f in low:
            lines.append(f"  • {f['name']} — {f.get('path', '')}")
        lines.append("")

    lines.append("─── ⚖️ Disclaimer ───")
    lines.append(italic("This scan uses GitHub Code Search API to find files matching known sensitive patterns."))
    lines.append(italic("Results may include false positives. Always verify manually."))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_repo_arg(text: str) -> Optional[tuple[str, str]]:
    """Parse owner/repo from text, returning (owner, repo) or None."""
    text = text.strip()
    if "/" not in text:
        return None

    # Handle URLs like https://github.com/owner/repo
    url_match = re.search(r"github\.com/([^/]+)/([^/\s?]+)", text)
    if url_match:
        return url_match.group(1), url_match.group(2)

    # Handle owner/repo format
    parts = text.split("/")
    if len(parts) >= 2:
        return parts[0].strip(), parts[1].strip()

    return None


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

async def cmd_github(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /github command — repo info, trending, or security scan."""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    args = context.args or []

    if not args:
        await update.message.reply_text(
            f"{bold('📦 GitHub Tracker')}\n\n"
            "Usage:\n"
            f"  {code('/github owner/repo')}      — Show repo info\n"
            f"  {code('/github trending')}         — Trending security repos\n"
            f"  {code('/github scan owner/repo')}   — Scan for sensitive files\n\n"
            f"{italic('Supports both owner/repo and full GitHub URLs.')}",
            parse_mode=ParseMode.HTML,
        )
        return

    # Rate limit
    if not check_rate_limit(user_id, "github"):
        await update.message.reply_text(
            "⏳ Rate limit reached. Please wait before making another request.",
            parse_mode=ParseMode.HTML,
        )
        return

    sub_cmd = args[0].lower().strip()
    rest = " ".join(args[1:]) if len(args) > 1 else ""

    # --- /github trending ---
    if sub_cmd == "trending":
        await _handle_trending(update, context, user_id)
        return

    # --- /github scan owner/repo ---
    if sub_cmd == "scan":
        repo_arg = sanitize_input(rest) if rest else ""
        if not repo_arg:
            await update.message.reply_text(
                f"Please specify a repository.\n"
                f"Example: {code('/github scan owner/repo')}",
                parse_mode=ParseMode.HTML,
            )
            return

        parsed = _parse_repo_arg(repo_arg)
        if not parsed:
            await update.message.reply_text(
                f"{bold('❌ Invalid repository format')}\n\n"
                f"Use {code('owner/repo')} or a full GitHub URL.",
                parse_mode=ParseMode.HTML,
            )
            return

        await _handle_scan(update, context, user_id, parsed[0], parsed[1])
        return

    # --- /github owner/repo (default) ---
    repo_arg = sanitize_input(" ".join(args))
    parsed = _parse_repo_arg(repo_arg)

    if not parsed:
        await update.message.reply_text(
            f"{bold('❌ Invalid repository format')}\n\n"
            f"Use {code('owner/repo')} or a full GitHub URL.\n"
            f"Example: {code('/github python/cpython')}",
            parse_mode=ParseMode.HTML,
        )
        return

    await _handle_repo_info(update, context, user_id, parsed[0], parsed[1])


async def _handle_repo_info(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    owner: str,
    repo: str,
) -> None:
    """Fetch and display repository information."""
    await update.message.reply_text(
        f"📦 Fetching info for {code(f'{owner}/{repo}')}…",
        parse_mode=ParseMode.HTML,
    )

    log_query(user_id, "github", f"{owner}/{repo}")
    increment_usage(user_id)

    async with aiohttp.ClientSession() as session:
        repo_task = _get_repo_info(session, owner, repo)
        release_task = _get_latest_release(session, owner, repo)

        results = await asyncio.gather(repo_task, release_task)
        repo_data, release_data = results

    if not repo_data:
        await update.message.reply_text(
            f"{bold('❌ Repository not found')}\n\n"
            f"Could not find {code(f'{owner}/{repo}')} on GitHub.\n\n"
            "Possible reasons:\n"
            "  • The repository name is incorrect\n"
            "  • The repository is private\n"
            "  • GitHub API rate limit was hit\n\n"
            f"Check manually: {link(f'https://github.com/{owner}/{repo}', 'GitHub')}",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    message = _format_repo_info(repo_data, release_data)
    keyboard = _build_repo_keyboard(owner, repo)

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )


async def _handle_trending(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
) -> None:
    """Fetch and display trending security repositories."""
    await update.message.reply_text(
        "🔥 Searching for trending security repos…",
        parse_mode=ParseMode.HTML,
    )

    log_query(user_id, "github_trending", "")
    increment_usage(user_id)

    all_repos: list[dict] = []
    seen: set[str] = set()

    async with aiohttp.ClientSession() as session:
        tasks = [_search_repos(session, q, per_page=5) for q in TRENDING_QUERIES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception) or result is None:
            continue
        for repo in result:
            full_name = repo.get("full_name", "")
            if full_name and full_name not in seen:
                seen.add(full_name)
                all_repos.append(repo)

    if not all_repos:
        await update.message.reply_text(
            f"{bold('❌ Could not fetch trending repos')}\n\n"
            "GitHub API rate limit may have been reached. Try again later.\n\n"
            "Manual links:\n"
            f"  • {link('https://github.com/trending?since=weekly&spoken_language_code=', 'GitHub Trending')}\n"
            f"  • {link('https://github.com/topics/security', 'Security Topic')}",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        return

    # Sort by stars
    all_repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)
    all_repos = all_repos[:8]

    message, keyboard = _format_trending(all_repos)

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )


async def _handle_scan(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
    owner: str,
    repo: str,
) -> None:
    """Scan a repository for sensitive files."""
    await update.message.reply_text(
        f"🔐 Scanning {code(f'{owner}/{repo}')} for sensitive files…\n"
        f"{italic('Checking {len(SENSITIVE_FILE_PATTERNS)} patterns via GitHub Code Search.')}",
        parse_mode=ParseMode.HTML,
    )

    log_query(user_id, "github_scan", f"{owner}/{repo}")
    increment_usage(user_id)

    findings: list[dict] = []

    async with aiohttp.ClientSession() as session:
        # First verify the repo exists
        repo_data = await _get_repo_info(session, owner, repo)
        if not repo_data:
            await update.message.reply_text(
                f"{bold('❌ Repository not found')}\n"
                f"Could not find {code(f'{owner}/{repo}')}.",
                parse_mode=ParseMode.HTML,
            )
            return

        # Search for sensitive files (respect rate limits — batch slowly)
        for pattern_info in SENSITIVE_FILE_PATTERNS:
            result = await _search_code(session, owner, repo, pattern_info["pattern"])
            if result is None:
                # Rate limited — stop scanning
                logger.warning("GitHub code search rate limited during scan of %s/%s", owner, repo)
                break
            if result:
                for item in result:
                    path = item.get("path", "")
                    # Deduplicate by path
                    if not any(f.get("path") == path for f in findings):
                        findings.append({
                            "name": pattern_info["name"],
                            "severity": pattern_info["severity"],
                            "emoji": pattern_info["emoji"],
                            "path": path,
                        })

    message = _format_scan_results(findings, owner, repo)

    buttons: list[list[InlineKeyboardButton]] = [
        [
            InlineKeyboardButton("🌐 Repository", url=f"https://github.com/{owner}/{repo}"),
            InlineKeyboardButton("🔍 GitHub Search", url=f"https://github.com/search?q=repo%3A{owner}%2F{repo}+.env&type=code"),
        ],
        [
            InlineKeyboardButton("📦 Full Info", callback_data=f"github:repo:{owner}/{repo}"),
        ],
    ]

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup(buttons),
    )


# ---------------------------------------------------------------------------
# Callback query handler
# ---------------------------------------------------------------------------

async def handle_github_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from GitHub results."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith("github:"):
        return

    parts = data.split(":")
    if len(parts) < 3:
        return

    sub = parts[1]
    user_id = query.from_user.id

    if sub == "repo":
        repo_ref = parts[2]
        owner, repo = repo_ref.split("/", 1) if "/" in repo_ref else (repo_ref, "")

        await query.answer(f"Loading {owner}/{repo}…")

        if not check_rate_limit(user_id, "github"):
            await query.answer("⏳ Rate limit reached.", show_alert=True)
            return

        log_query(user_id, "github_callback", f"{owner}/{repo}")
        increment_usage(user_id)

        async with aiohttp.ClientSession() as session:
            repo_task = _get_repo_info(session, owner, repo)
            release_task = _get_latest_release(session, owner, repo)
            results = await asyncio.gather(repo_task, release_task)
            repo_data, release_data = results

        if not repo_data:
            await query.edit_message_text(
                f"{bold('❌ Repository not found')}\n"
                f"Could not find {code(f'{owner}/{repo}')}.",
                parse_mode=ParseMode.HTML,
            )
            return

        message = _format_repo_info(repo_data, release_data)
        keyboard = _build_repo_keyboard(owner, repo)

        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )

    elif sub == "trending":
        await query.answer("Loading trending repos…")

        if not check_rate_limit(user_id, "github"):
            await query.answer("⏳ Rate limit reached.", show_alert=True)
            return

        increment_usage(user_id)

        all_repos: list[dict] = []
        seen: set[str] = set()

        async with aiohttp.ClientSession() as session:
            tasks = [_search_repos(session, q, per_page=5) for q in TRENDING_QUERIES]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            for repo in result:
                full_name = repo.get("full_name", "")
                if full_name and full_name not in seen:
                    seen.add(full_name)
                    all_repos.append(repo)

        if all_repos:
            all_repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)
            all_repos = all_repos[:8]
            message, keyboard = _format_trending(all_repos)
            await query.edit_message_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=keyboard,
            )
        else:
            await query.edit_message_text(
                f"{bold('❌ Could not fetch trending repos')}\n"
                "GitHub API rate limit may have been reached.",
                parse_mode=ParseMode.HTML,
            )
