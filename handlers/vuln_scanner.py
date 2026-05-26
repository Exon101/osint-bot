"""
Vulnerability Scanner Handler for Telegram OSINT Bot.

Provides CVE lookup via NVD API with MITRE fallback.
Commands:
    /vuln CVE-2024-3400        — Look up a specific CVE
    /vuln apache struts         — Keyword search via NVD
"""

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_cve
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html
import aiohttp
import asyncio
import re
from typing import Optional

# ---------------------------------------------------------------------------
# NVD API helpers
# ---------------------------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_API_BASE = "https://cveawg.mitre.org/api/cve"

NVD_API_KEY = getattr(config, "NVD_API_KEY", None) or ""


def _nvd_headers() -> dict[str, str]:
    """Return headers for NVD requests (API key optional)."""
    headers = {"User-Agent": "OSINT-Bot/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _severity_color(score: Optional[float]) -> str:
    """Return severity label with coloured emoji."""
    if score is None:
        return "UNKNOWN ⚪"
    if score >= 9.0:
        return f"CRITICAL 🔴  {score}"
    elif score >= 7.0:
        return f"HIGH 🟠  {score}"
    elif score >= 4.0:
        return f"MEDIUM 🟡  {score}"
    elif score > 0:
        return f"LOW 🟢  {score}"
    else:
        return "NONE ⚪  0.0"


def _extract_cvss(metrics: dict) -> Optional[float]:
    """Try to pull the best CVSS v3.1/v3/v2 base score from metrics."""
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        bucket = metrics.get(version)
        if bucket and isinstance(bucket, list) and len(bucket) > 0:
            cvss_data = bucket[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return float(score)
    return None


def _format_cve_detail(cve: dict) -> str:
    """Format a single CVE entry into a readable Telegram message."""
    cve_id = cve.get("id", "Unknown")
    descriptions = cve.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break

    metrics = cve.get("metrics", {})
    cvss_score = _extract_cvss(metrics)

    severity = _severity_color(cvss_score)

    # Affected products / configurations
    configurations = cve.get("configurations", [])
    affected: list[str] = []
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for cpematch in node.get("cpeMatch", []):
                criteria = cpematch.get("criteria", "")
                if criteria:
                    # Simplify long CPE URIs
                    short = criteria.split(":")[-1] if ":" in criteria else criteria
                    affected.append(short)
    affected_unique = list(dict.fromkeys(affected))[:8]  # deduplicate & cap

    # References
    refs = cve.get("references", [])[:5]

    # Build message
    lines: list[str] = []
    lines.append(f"{bold('🔍 CVE Details')}\n")
    lines.append(f"{bold('ID:')}  {code(cve_id)}")
    lines.append(f"{bold('Severity:')}  {severity}")
    if desc_text:
        # Truncate very long descriptions
        display_desc = desc_text[:500] + "…" if len(desc_text) > 500 else desc_text
        lines.append(f"\n{bold('Description:')}\n{escape_html(display_desc)}")

    if affected_unique:
        lines.append(f"\n{bold('Affected Products:')}")
        for prod in affected_unique:
            lines.append(f"  • {code(prod)}")

    if refs:
        lines.append(f"\n{bold('References:')}")
        for ref in refs[:5]:
            url = ref.get("url", "")
            tag = ref.get("tags", [""])[0] if ref.get("tags") else ""
            label = tag.upper() if tag else "Link"
            lines.append(f"  • [{label}]({url})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

async def _lookup_cve_nvd(cve_id: str) -> Optional[dict]:
    """Lookup a single CVE via the NVD API."""
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=_nvd_headers(), timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        return vulnerabilities[0].get("cve")
                elif resp.status == 403:
                    logger.warning("NVD rate-limit hit (403)")
                else:
                    logger.warning("NVD returned status %s for %s", resp.status, cve_id)
    except Exception as exc:
        logger.error("NVD lookup error for %s: %s", cve_id, exc)
    return None


async def _lookup_cve_mitre(cve_id: str) -> Optional[dict]:
    """Fallback: lookup a single CVE via MITRE free API."""
    url = f"{MITRE_API_BASE}/{cve_id}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 200:
                    return await resp.json()
    except Exception as exc:
        logger.error("MITRE lookup error for %s: %s", cve_id, exc)
    return None


def _format_mitre_cve(cve: dict) -> str:
    """Format CVE data returned by the MITRE API."""
    cve_id = cve.get("cveMetadata", {}).get("cveId", "Unknown")
    containers = cve.get("containers", {}).get("cna", {})
    descriptions = containers.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break

    affected = containers.get("affected", [])
    affected_list: list[str] = []
    for a in affected[:8]:
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        affected_list.append(f"{vendor} {product}".strip())

    metrics = containers.get("metrics", [])
    cvss_score: Optional[float] = None
    for m in metrics:
        for ver in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if ver in m:
                cvss_data = m[ver].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                if cvss_score is not None:
                    cvss_score = float(cvss_score)
                    break

    severity = _severity_color(cvss_score)
    refs = containers.get("references", [])[:5]

    lines: list[str] = []
    lines.append(f"{bold('🔍 CVE Details')}  {italic('(via MITRE)')}\n")
    lines.append(f"{bold('ID:')}  {code(cve_id)}")
    lines.append(f"{bold('Severity:')}  {severity}")
    if desc_text:
        display_desc = desc_text[:500] + "…" if len(desc_text) > 500 else desc_text
        lines.append(f"\n{bold('Description:')}\n{escape_html(display_desc)}")
    if affected_list:
        lines.append(f"\n{bold('Affected Products:')}")
        for prod in affected_list:
            lines.append(f"  • {code(prod)}")
    if refs:
        lines.append(f"\n{bold('References:')}")
        for ref in refs[:5]:
            url = ref.get("url", "")
            lines.append(f"  • {link(url, 'Link')}")

    return "\n".join(lines)


async def _search_cve_keyword(keyword: str) -> Optional[list[dict]]:
    """Search NVD by keyword and return top results."""
    url = f"{NVD_API_BASE}?keywordSearch={keyword}&resultsPerPage=5"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=_nvd_headers(), timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [v.get("cve") for v in data.get("vulnerabilities", [])]
    except Exception as exc:
        logger.error("NVD keyword search error: %s", exc)
    return None


def _format_search_results(results: list[dict], keyword: str) -> str:
    """Format multiple CVE results from a keyword search."""
    lines: list[str] = []
    lines.append(f"{bold('🔎 CVE Search Results')}\n")
    lines.append(f"{italic(f'Showing up to 5 results for: {code(keyword)}')}\n")

    buttons: list[list[InlineKeyboardButton]] = []

    for cve in results:
        cve_id = cve.get("id", "Unknown")
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_score = _extract_cvss(metrics)
        severity = _severity_color(cvss_score)

        short_desc = (desc_text[:120] + "…") if len(desc_text) > 120 else desc_text
        lines.append(f"{code(cve_id)}  —  {severity}")
        lines.append(f"  {escape_html(short_desc)}\n")

        buttons.append([InlineKeyboardButton(f"Details: {cve_id}", callback_data=f"vuln:{cve_id}")])

    lines.append(f"\n{italic('Click a CVE above for full details, or search on NVD directly:')}")
    lines.append(link(f"https://nvd.nist.gov/vuln/search/results?query={keyword}", "NVD Search"))

    return "\n".join(lines), InlineKeyboardMarkup(buttons)


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /vuln command — CVE lookup or keyword search."""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    user_text = " ".join(context.args) if context.args else ""

    if not user_text:
        await update.message.reply_text(
            f"{bold('🔍 Vulnerability Scanner')}\n\n"
            "Usage:\n"
            f"  {code('/vuln CVE-2024-3400')}  — Look up a specific CVE\n"
            f"  {code('/vuln apache struts')}   — Keyword search\n\n"
            f"{italic('Data source: NVD (MITRE fallback)')}",
            parse_mode=ParseMode.HTML,
        )
        return

    # Rate limit
    if not check_rate_limit(user_id, "vuln"):
        await update.message.reply_text(
            "⏳ Rate limit reached. Please wait before making another request.",
            parse_mode=ParseMode.HTML,
        )
        return

    user_text = sanitize_input(user_text)

    await update.message.reply_text(
        f"🔍 Scanning vulnerability databases…",
        parse_mode=ParseMode.HTML,
    )

    # Determine if this is a CVE ID or a keyword search
    if validate_cve(user_text):
        cve_id = user_text.upper()

        log_query(user_id, "vuln", cve_id)
        increment_usage(user_id)

        # Try NVD first
        cve_data = await _lookup_cve_nvd(cve_id)

        if cve_data:
            message = _format_cve_detail(cve_data)
        else:
            # Fallback to MITRE
            await update.message.reply_text(
                f"NVD rate-limit hit. Trying MITRE fallback…",
                parse_mode=ParseMode.HTML,
            )
            mitre_data = await _lookup_cve_mitre(cve_id)
            if mitre_data:
                message = _format_mitre_cve(mitre_data)
            else:
                message = (
                    f"{bold('❌ No results found')}\n\n"
                    f"Could not find {code(cve_id)} in NVD or MITRE.\n\n"
                    "Suggestions:\n"
                    f"  • {link('https://nvd.nist.gov/vuln/detail/' + cve_id, 'Check NVD directly')}\n"
                    f"  • {link('https://www.cvedetails.com/cve/' + cve_id, 'Check CVE Details')}\n"
                    f"  • Verify the CVE ID is correct\n"
                    f"  • The CVE may be reserved but not yet published"
                )

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                InlineKeyboardButton("MITRE", url=f"https://www.cve.org/CVERecord?id={cve_id}"),
                InlineKeyboardButton("Exploit DB", url=f"https://www.exploit-db.com/search?q={cve_id}"),
            ]
        ])
        await update.message.reply_text(
            message,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )

    else:
        # Keyword search
        keyword = user_text

        log_query(user_id, "vuln_search", keyword)
        increment_usage(user_id)

        results = await _search_cve_keyword(keyword)

        if results:
            message, keyboard = _format_search_results(results, keyword)
            await update.message.reply_text(
                message,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=keyboard,
            )
        else:
            await update.message.reply_text(
                f"{bold('❌ No results found')}\n\n"
                f"No CVEs found for {code(keyword)}.\n\n"
                "Suggestions:\n"
                f"  • Try different keywords\n"
                f"  • {link('https://nvd.nist.gov/vuln/search/results?query=' + keyword, 'Search NVD directly')}\n"
                f"  • Use a specific CVE ID with {code('/vuln CVE-YYYY-NNNNN')}",
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )


# ---------------------------------------------------------------------------
# Callback query handler
# ---------------------------------------------------------------------------

async def handle_vuln_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from vulnerability results."""
    query = update.callback_query
    await query.answer()

    data = query.data
    if not data.startswith("vuln:"):
        return

    cve_id = data.split(":", 1)[1]
    user_id = query.from_user.id

    await query.edit_message_reply_markup(reply_markup=None)
    await query.message.reply_text(
        f"🔍 Fetching details for {code(cve_id)}…",
        parse_mode=ParseMode.HTML,
    )

    cve_data = await _lookup_cve_nvd(cve_id)

    if cve_data:
        message = _format_cve_detail(cve_data)
    else:
        mitre_data = await _lookup_cve_mitre(cve_id)
        if mitre_data:
            message = _format_mitre_cve(mitre_data)
        else:
            message = (
                f"{bold('❌ Could not fetch details')}\n\n"
                f"Try checking directly:\n"
                f"  • {link('https://nvd.nist.gov/vuln/detail/' + cve_id, 'NVD')}\n"
                f"  • {link('https://www.cve.org/CVERecord?id=' + cve_id, 'MITRE')}"
            )

    log_query(user_id, "vuln_callback", cve_id)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
            InlineKeyboardButton("MITRE", url=f"https://www.cve.org/CVERecord?id={cve_id}"),
            InlineKeyboardButton("Exploit DB", url=f"https://www.exploit-db.com/search?q={cve_id}"),
        ]
    ])
    await query.message.reply_text(
        message,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )
