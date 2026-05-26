"""
Nuclei Vulnerability Scanner Handler
Integrates ProjectDiscovery Nuclei via Cloud API for template-based vulnerability scanning.

Commands:
    /nuclei                         — Show inline button menu
    /nuclei scan <target>           — Run a quick scan on a target
    /nuclei scan <target> critical  — Scan with severity filter
    /nuclei templates [query]       — Search/browse Nuclei templates
    /nuclei status <scan_id>       — Check scan status and results
    /nuclei list                    — List recent scans
    /nuclei cancel <scan_id>       — Cancel a running scan

Callback prefixes: nuclei:
"""

import asyncio
from typing import Optional, Dict, Any
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_url, validate_domain
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html
from api_clients.nuclei_client import NucleiClient

# ── Severity colour mapping ──────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🟢 LOW",
    "info": "🔵 INFO",
}

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info", "all")


def _sev_tag(sev: str) -> str:
    sev_lower = sev.lower()
    return SEVERITY_COLORS.get(sev_lower, f"⚪ {sev.upper()}")


def _format_finding(finding: Dict[str, Any], index: int) -> str:
    """Format a single Nuclei scan finding into Telegram-friendly text."""
    lines: list[str] = []
    lines.append(f"<b>#{index + 1}</b>  {_sev_tag(finding.get('severity', 'info'))}")

    template_id = finding.get("template-id", finding.get("template_id", ""))
    if template_id:
        lines.append(f"  Template: <code>{escape_html(template_id)}</code>")

    name = finding.get("name", finding.get("info", {}).get("name", ""))
    if name:
        lines.append(f"  Name: {escape_html(name)}")

    # Extract matched-at or url
    matched = (
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("url", "")
        or finding.get("host", "")
    )
    if matched:
        lines.append(f"  Matched: <code>{escape_html(matched)}</code>")

    # Extract type
    ftype = finding.get("type", finding.get("info", {}).get("classification", {}).get("cwe-type", ""))
    if ftype:
        lines.append(f"  Type: <code>{escape_html(ftype)}</code>")

    # CVE reference
    cve = finding.get("cve", "")
    if not cve:
        refs = finding.get("references", finding.get("info", {}).get("reference", []))
        for ref in refs:
            if isinstance(ref, str) and "CVE-" in ref.upper():
                cve = ref.split("CVE-")[-1].strip("/").split("/")[0]
                cve = f"CVE-{cve}"
                break
    if cve:
        lines.append(f"  CVE: <code>{escape_html(cve)}</code>")

    # Extract and show extract lines
    extracted = finding.get("extracted-results", finding.get("extracted_results", []))
    if extracted and isinstance(extracted, list):
        for ext in extracted[:3]:
            ext_str = str(ext).replace("<", "&lt;").replace(">", "&gt;")
            if len(ext_str) > 200:
                ext_str = ext_str[:200] + "..."
            lines.append(f"  Extract: <code>{ext_str}</code>")

    # CURL command if present
    curl = finding.get("curl-command", "")
    if curl and len(curl) < 300:
        lines.append(f"  CURL: <code>{escape_html(curl[:200])}</code>")

    # Description
    desc = finding.get("description", finding.get("info", {}).get("description", ""))
    if desc:
        desc_clean = desc[:200] + "..." if len(desc) > 200 else desc
        lines.append(f"  Desc: {escape_html(desc_clean)}")

    return "\n".join(lines)


def _format_scan_results(results_data: Dict[str, Any]) -> tuple:
    """
    Format scan results into a message and optional inline keyboard.
    Returns (message_text, InlineKeyboardMarkup or None).
    """
    data = results_data.get("data", {})
    findings = data if isinstance(data, list) else data.get("findings", data.get("results", []))

    if not findings or not isinstance(findings, list):
        return "✅ <b>Scan completed</b>\n\nNo vulnerabilities found. The target appears clean!", None

    # Count by severity
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines: list[str] = []
    lines.append(f"<b>☢️ Nuclei Scan Results</b>\n")
    lines.append(f"Found <b>{len(findings)}</b> issue(s):\n")

    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            lines.append(f"  {_sev_tag(sev)}: <b>{sev_counts[sev]}</b>")

    lines.append("\n" + "━" * 20 + "\n")

    # Show first 5 findings in detail
    for i, finding in enumerate(findings[:5]):
        lines.append(_format_finding(finding, i))
        lines.append("")

    if len(findings) > 5:
        lines.append(f"  ... and <b>{len(findings) - 5}</b> more findings")

    # Build reference buttons
    buttons: list = []
    target_url = ""
    if findings and isinstance(findings, list):
        target_url = findings[0].get("matched-at", findings[0].get("host", ""))
        if target_url:
            buttons.append([
                InlineKeyboardButton("🌐 Target", url=target_url),
                InlineKeyboardButton("📋 Nuclei Templates", url="https://templates.nuclei.sh"),
            ])

    return "\n".join(lines), InlineKeyboardMarkup(buttons) if buttons else None


# ── Command handler ──────────────────────────────────────────────────

async def cmd_nuclei(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /nuclei command with subcommands."""
    user_id = update.effective_user.id
    args = context.args or []

    if not check_rate_limit(user_id, "nuclei"):
        await update.message.reply_text("⏳ Rate limit reached. Please wait.")
        return

    # ── No args: show interactive menu ──
    if not args:
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("⚡ Quick Scan", callback_data="nuclei:scan_prompt"),
                InlineKeyboardButton("🔍 Search Templates", callback_data="nuclei:template_prompt"),
            ],
            [
                InlineKeyboardButton("📊 Scan Status", callback_data="nuclei:status_prompt"),
                InlineKeyboardButton("📋 Recent Scans", callback_data="nuclei:list_scans"),
            ],
            [
                InlineKeyboardButton("🛑 Cancel Scan", callback_data="nuclei:cancel_prompt"),
                InlineKeyboardButton("ℹ️ About", callback_data="nuclei:about"),
            ],
        ])

        # Check if API key is configured
        from config import config
        has_key = bool(getattr(config, "NUCLEI_API_KEY", None))

        status_badge = "✅ API Key Configured" if has_key else "⚠️ No API Key"
        key_hint = (
            "\n\n<b>Setup:</b>\n"
            f"  <code>NUCLEI_API_KEY=your_key</code>\n\n"
            "Get your key at: https://cloud.projectdiscovery.io"
            if not has_key else ""
        )

        await update.message.reply_text(
            f"<b>☢️ Nuclei Vulnerability Scanner</b>\n\n"
            f"Template-based vulnerability scanning powered by ProjectDiscovery.\n\n"
            f"{status_badge}{key_hint}\n\n"
            f"Select an action:",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )
        return

    subcommand = args[0].lower()

    # ── /nuclei scan <target> [severity] ──
    if subcommand == "scan":
        await _handle_scan_command(update, context, user_id, args[1:])
        return

    # ── /nuclei templates [query] ──
    if subcommand in ("templates", "tpl"):
        await _handle_templates_command(update, context, user_id, args[1:])
        return

    # ── /nuclei status <scan_id> ──
    if subcommand == "status":
        await _handle_status_command(update, context, user_id, args[1:])
        return

    # ── /nuclei list ──
    if subcommand == "list":
        await _handle_list_command(update, context, user_id)
        return

    # ── /nuclei cancel <scan_id> ──
    if subcommand == "cancel":
        await _handle_cancel_command(update, context, user_id, args[1:])
        return

    # Unknown subcommand
    await update.message.reply_text(
        f"<b>Unknown subcommand:</b> <code>{escape_html(subcommand)}</code>\n\n"
        f"Use <code>/nuclei</code> to see available actions.",
        parse_mode=ParseMode.HTML,
    )


# ── Scan Command ─────────────────────────────────────────────────────

async def _handle_scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                user_id: int, args: list) -> None:
    """Handle /nuclei scan <target> [severity]."""
    if not args:
        await update.message.reply_text(
            f"{bold('☢️ Nuclei Scan')}\n\n"
            f"Usage:\n"
            f"  {code('/nuclei scan https://example.com')}\n"
            f"  {code('/nuclei scan example.com critical')}\n\n"
            f"Severity filters: {code('critical')}, {code('high')}, "
            f"{code('medium')}, {code('low')}, {code('info')}\n\n"
            f"⚠️ Only scan targets you have authorization to test!",
            parse_mode=ParseMode.HTML,
        )
        return

    from config import config
    api_key = getattr(config, "NUCLEI_API_KEY", None)
    if not api_key:
        await update.message.reply_text(
            "⚠️ <b>Nuclei API key not configured.</b>\n\n"
            "Set the <code>NUCLEI_API_KEY</code> environment variable.\n"
            "Get your key: https://cloud.projectdiscovery.io",
            parse_mode=ParseMode.HTML,
        )
        return

    target = sanitize_input(args[0])
    if not target:
        await update.message.reply_text("❌ Invalid target.")
        return

    # Ensure target has a scheme for URL targets
    if validate_domain(target) and not target.startswith("http"):
        target = f"https://{target}"
    elif not validate_url(target) and not validate_domain(target):
        await update.message.reply_text("❌ Invalid target. Use a URL or domain name.")
        return

    # Parse optional severity
    severity = None
    if len(args) > 1 and args[1].lower() in VALID_SEVERITIES:
        severity = args[1].lower()

    log_query(user_id, "nuclei_scan", target)
    increment_usage(user_id)

    status_msg = await update.message.reply_text(
        f"☢️ <b>Starting Nuclei scan…</b>\n\n"
        f"Target: <code>{escape_html(target)}</code>\n"
        f"Severity: <code>{severity or 'all'}</code>\n\n"
        f"⏳ Scanning (this may take 30-120 seconds)…",
        parse_mode=ParseMode.HTML,
    )

    client = NucleiClient(api_key)

    # Start the scan
    scan_kwargs: Dict[str, Any] = {"target": target}
    if severity and severity != "all":
        scan_kwargs["severity"] = severity

    result = await client.start_scan(**scan_kwargs)

    if not result.get("ok"):
        error = result.get("error", "Unknown error")
        await status_msg.edit_text(
            f"❌ <b>Scan failed</b>\n\n"
            f"<code>{escape_html(str(error))}</code>\n\n"
            f"Check your API key and try again.",
            parse_mode=ParseMode.HTML,
        )
        return

    scan_data = result.get("data", {})
    scan_id = scan_data.get("scan_id") or scan_data.get("id")

    if not scan_id:
        # If the response already contains results (quick scan)
        if scan_data.get("findings") or scan_data.get("results"):
            formatted, kb = _format_scan_results(result)
            await status_msg.edit_text(
                formatted,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=kb,
            )
            return

        await status_msg.edit_text("❌ Scan started but no scan ID returned.")
        return

    # Poll for results
    await status_msg.edit_text(
        f"☢️ <b>Scanning…</b>\n\n"
        f"Scan ID: <code>{escape_html(scan_id)}</code>\n"
        f"Target: <code>{escape_html(target)}</code>\n\n"
        f"⏳ Waiting for results (may take up to 120s)…",
        parse_mode=ParseMode.HTML,
    )

    completed = False
    for attempt in range(24):
        await asyncio.sleep(5)
        poll = await client.get_scan_status(scan_id)
        if not poll.get("ok"):
            continue

        poll_data = poll.get("data", {})
        state = poll_data.get("status", "")

        # Update progress message
        progress = poll_data.get("progress", "")
        scanned = poll_data.get("templates_scanned", "")
        update_text = (
            f"☢️ <b>Scanning…</b>\n\n"
            f"Scan ID: <code>{escape_html(scan_id)}</code>\n"
            f"Status: <code>{escape_html(state)}</code>"
        )
        if progress:
            update_text += f"\nProgress: {escape_html(str(progress))}"
        if scanned:
            update_text += f"\nTemplates: {escape_html(str(scanned))}"
        update_text += f"\n⏱️ {(attempt + 1) * 5}s elapsed"

        try:
            await status_msg.edit_text(update_text, parse_mode=ParseMode.HTML)
        except Exception:
            pass  # Ignore edit conflicts

        if state in ("completed", "done", "finished"):
            completed = True
            break
        elif state in ("failed", "error", "cancelled"):
            error_msg = poll_data.get("error", state)
            await status_msg.edit_text(
                f"❌ <b>Scan {state}</b>\n\n"
                f"<code>{escape_html(str(error_msg))}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

    if not completed:
        # Timeout — give user the scan ID to check later
        await status_msg.edit_text(
            f"⏳ <b>Scan still running</b>\n\n"
            f"Scan ID: <code>{escape_html(scan_id)}</code>\n"
            f"Target: <code>{escape_html(target)}</code>\n\n"
            f"The scan is taking longer than expected.\n"
            f"Use the buttons below to check results later:",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📊 Check Status", callback_data=f"nuclei:status:{scan_id}"),
                    InlineKeyboardButton("📋 Get Results", callback_data=f"nuclei:results:{scan_id}"),
                ],
            ]),
        )
        return

    # Fetch results
    results = await client.get_scan_results(scan_id)
    formatted, kb = _format_scan_results(results)

    kb_rows = [[
        InlineKeyboardButton("📊 Scan Info", callback_data=f"nuclei:status:{scan_id}"),
    ]]
    if kb and kb.inline_keyboard:
        kb_rows.extend(kb.inline_keyboard)
    kb_rows.append([InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")])

    await status_msg.edit_text(
        formatted,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup(kb_rows),
    )


# ── Templates Command ───────────────────────────────────────────────

async def _handle_templates_command(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                     user_id: int, args: list) -> None:
    """Handle /nuclei templates [query]."""
    from config import config
    api_key = getattr(config, "NUCLEI_API_KEY", None)

    client = NucleiClient(api_key)

    if not args:
        # List default templates
        msg = await update.message.reply_text(
            "🔍 <b>Fetching Nuclei templates…</b>", parse_mode=ParseMode.HTML
        )
        result = await client.list_templates(limit=25)

        if not result.get("ok"):
            await msg.edit_text(
                f"❌ <code>{escape_html(result.get('error', 'Failed to fetch templates'))}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        data = result.get("data", {})
        templates = data if isinstance(data, list) else data.get("templates", [])

        if not templates:
            await msg.edit_text(
                "No templates found. Try searching with a keyword:\n"
                f"  <code>/nuclei templates xss</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        lines: list[str] = ["<b>📋 Nuclei Templates</b>\n"]

        # Group by severity
        sev_groups: Dict[str, list] = {}
        for tpl in templates:
            sev = tpl.get("severity", "info").lower()
            if sev not in sev_groups:
                sev_groups[sev] = []
            sev_groups[sev].append(tpl)

        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in sev_groups:
                tpls = sev_groups[sev][:5]
                lines.append(f"\n{_sev_tag(sev)} ({len(sev_groups[sev])} total):")
                for tpl in tpls:
                    tpl_id = tpl.get("id", tpl.get("template-id", "?"))
                    tpl_name = tpl.get("name", tpl.get("info", {}).get("name", "Unknown"))
                    lines.append(f"  • <code>{escape_html(str(tpl_id))}</code> — {escape_html(str(tpl_name)[:60])}")

        lines.append(f"\n{italic('Search: /nuclei templates <keyword>')}")
        lines.append(link("https://templates.nuclei.sh", "Browse all templates online"))

        await msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        return

    # Search templates
    query = sanitize_input(" ".join(args))
    msg = await update.message.reply_text(
        f"🔍 <b>Searching templates for:</b> <code>{escape_html(query)}</code>",
        parse_mode=ParseMode.HTML,
    )

    result = await client.search_templates(query, limit=15)

    if not result.get("ok"):
        await msg.edit_text(
            f"❌ <code>{escape_html(result.get('error', 'Search failed'))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    data = result.get("data", {})
    templates = data if isinstance(data, list) else data.get("templates", [])

    if not templates:
        await msg.edit_text(
            f"❌ No templates found for <code>{escape_html(query)}</code>\n\n"
            f"Try: xss, sqli, rce, lfi, ssrf, wordpress, apache, nginx",
            parse_mode=ParseMode.HTML,
        )
        return

    lines: list[str] = [
        f"<b>🔍 Template Search:</b> <code>{escape_html(query)}</code>",
        f"Found <b>{len(templates)}</b> template(s)\n",
    ]

    for i, tpl in enumerate(templates[:10]):
        tpl_id = tpl.get("id", tpl.get("template-id", "?"))
        tpl_name = tpl.get("name", tpl.get("info", {}).get("name", "Unknown"))
        sev = tpl.get("severity", "info").lower()
        tags = tpl.get("tags", tpl.get("info", {}).get("tags", []))
        tag_str = ", ".join(str(t) for t in tags[:3]) if tags else ""

        lines.append(f"<b>#{i+1}</b> {_sev_tag(sev)}")
        lines.append(f"  <code>{escape_html(str(tpl_id))}</code>")
        lines.append(f"  {escape_html(str(tpl_name)[:80])}")
        if tag_str:
            lines.append(f"  Tags: {escape_html(tag_str)}")
        lines.append("")

    await msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    log_query(user_id, "nuclei_templates", query)
    increment_usage(user_id)


# ── Status Command ──────────────────────────────────────────────────

async def _handle_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                  user_id: int, args: list) -> None:
    """Handle /nuclei status <scan_id>."""
    if not args:
        await update.message.reply_text(
            f"{bold('📊 Scan Status')}\n\n"
            f"Usage: {code('/nuclei status <scan_id>')}\n\n"
            f"Use {code('/nuclei list')} to see your recent scans.",
            parse_mode=ParseMode.HTML,
        )
        return

    from config import config
    api_key = getattr(config, "NUCLEI_API_KEY", None)
    scan_id = sanitize_input(args[0])

    msg = await update.message.reply_text(
        f"📊 <b>Fetching scan status…</b>", parse_mode=ParseMode.HTML
    )

    client = NucleiClient(api_key)
    result = await client.get_scan_status(scan_id)

    if not result.get("ok"):
        await msg.edit_text(
            f"❌ <code>{escape_html(result.get('error', 'Failed to fetch status'))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    data = result.get("data", {})
    state = data.get("status", "unknown")
    target = data.get("target", "")
    progress = data.get("progress", "")
    templates_scanned = data.get("templates_scanned", 0)
    findings_count = data.get("findings_count", data.get("vulnerabilities_count", "?"))
    started = data.get("created_at", data.get("started_at", ""))

    lines: list[str] = [
        f"<b>📊 Scan Status</b>\n",
        f"  Scan ID: <code>{escape_html(scan_id)}</code>",
        f"  Target: <code>{escape_html(target)}</code>",
        f"  Status: <code>{escape_html(str(state))}</code>",
        f"  Templates Scanned: <code>{escape_html(str(templates_scanned))}</code>",
        f"  Findings: <code>{escape_html(str(findings_count))}</code>",
    ]
    if progress:
        lines.append(f"  Progress: {escape_html(str(progress))}")
    if started:
        lines.append(f"  Started: {escape_html(str(started)[:19])}")

    buttons = []
    if state in ("completed", "done", "finished"):
        buttons.append([InlineKeyboardButton("📋 View Results", callback_data=f"nuclei:results:{scan_id}")])
        buttons.append([InlineKeyboardButton("🛑 New Scan", callback_data="nuclei:scan_prompt")])

    buttons.append([InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")])

    await msg.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(buttons),
    )

    log_query(user_id, "nuclei_status", scan_id)


# ── List Scans Command ──────────────────────────────────────────────

async def _handle_list_command(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                user_id: int) -> None:
    """Handle /nuclei list."""
    from config import config
    api_key = getattr(config, "NUCLEI_API_KEY", None)

    msg = await update.message.reply_text(
        "📋 <b>Fetching recent scans…</b>", parse_mode=ParseMode.HTML
    )

    client = NucleiClient(api_key)
    result = await client.list_scans(limit=10)

    if not result.get("ok"):
        await msg.edit_text(
            f"❌ <code>{escape_html(result.get('error', 'Failed to list scans'))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    data = result.get("data", {})
    scans = data if isinstance(data, list) else data.get("scans", [])

    if not scans:
        await msg.edit_text(
            "📋 <b>No recent scans found.</b>\n\n"
            f"Start a scan: {code('/nuclei scan https://example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    lines: list[str] = ["<b>📋 Recent Scans</b>\n"]
    buttons: list = []

    for scan in scans[:8]:
        scan_id = scan.get("id", scan.get("scan_id", "?"))
        target = scan.get("target", "Unknown")
        state = scan.get("status", "unknown")
        findings = scan.get("findings_count", scan.get("vulnerabilities_count", "?"))

        state_emoji = "✅" if state in ("completed", "done") else "⏳" if state == "running" else "❌"
        lines.append(
            f"{state_emoji} <code>{escape_html(str(scan_id))}</code> — {escape_html(str(target)[:40])}"
        )
        lines.append(f"   Status: {state} | Findings: {findings}\n")

        short_id = str(scan_id)[:16]
        buttons.append([
            InlineKeyboardButton(
                f"📊 {escape_html(str(target)[:25])}",
                callback_data=f"nuclei:status:{scan_id}",
            ),
        ])

    buttons.append([InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")])

    await msg.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(buttons),
    )

    log_query(user_id, "nuclei_list")
    increment_usage(user_id)


# ── Cancel Command ──────────────────────────────────────────────────

async def _handle_cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                  user_id: int, args: list) -> None:
    """Handle /nuclei cancel <scan_id>."""
    if not args:
        await update.message.reply_text(
            f"{bold('🛑 Cancel Scan')}\n\n"
            f"Usage: {code('/nuclei cancel <scan_id>')}\n\n"
            f"Use {code('/nuclei list')} to find scan IDs.",
            parse_mode=ParseMode.HTML,
        )
        return

    from config import config
    api_key = getattr(config, "NUCLEI_API_KEY", None)
    scan_id = sanitize_input(args[0])

    client = NucleiClient(api_key)
    result = await client.cancel_scan(scan_id)

    if result.get("ok"):
        await update.message.reply_text(
            f"🛑 <b>Scan cancelled</b>\n\n"
            f"Scan ID: <code>{escape_html(scan_id)}</code>",
            parse_mode=ParseMode.HTML,
        )
    else:
        await update.message.reply_text(
            f"❌ <code>{escape_html(result.get('error', 'Failed to cancel'))}</code>",
            parse_mode=ParseMode.HTML,
        )

    log_query(user_id, "nuclei_cancel", scan_id)


# ── Callback Query Handler ──────────────────────────────────────────

async def handle_nuclei_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks for Nuclei module."""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id

    data = query.data
    if not data.startswith("nuclei:"):
        return

    parts = data.split(":", 2)
    action = parts[1] if len(parts) > 1 else ""
    param = parts[2] if len(parts) > 2 else ""

    # ── Menu ──
    if action == "menu":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("⚡ Quick Scan", callback_data="nuclei:scan_prompt"),
                InlineKeyboardButton("🔍 Search Templates", callback_data="nuclei:template_prompt"),
            ],
            [
                InlineKeyboardButton("📊 Scan Status", callback_data="nuclei:status_prompt"),
                InlineKeyboardButton("📋 Recent Scans", callback_data="nuclei:list_scans"),
            ],
            [InlineKeyboardButton("↩️ Main Menu", callback_data="menu:security")],
        ])
        await query.edit_message_text(
            "<b>☢️ Nuclei Scanner</b>\n\nSelect an action:",
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        return

    # ── Scan prompt ──
    if action == "scan_prompt":
        await query.edit_message_text(
            f"{bold('☢️ Start Scan')}\n\n"
            f"Send the command:\n"
            f"  {code('/nuclei scan https://example.com')}\n"
            f"  {code('/nuclei scan example.com critical')}\n\n"
            f"Severity filters: critical, high, medium, low, info\n\n"
            f"⚠️ Only scan authorized targets!",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:menu")],
            ]),
        )
        return

    # ── Template prompt ──
    if action == "template_prompt":
        await query.edit_message_text(
            f"{bold('🔍 Search Templates')}\n\n"
            f"Send the command:\n"
            f"  {code('/nuclei templates')} — List popular templates\n"
            f"  {code('/nuclei templates xss')} — Search by keyword\n\n"
            f"Popular searches: xss, sqli, rce, lfi, ssrf, exposed-panels,\n"
            f"misconfiguration, token, wordpress, apache, nginx",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔥 XSS", callback_data="nuclei:tpl:xss"),
                    InlineKeyboardButton("💉 SQLi", callback_data="nuclei:tpl:sqli"),
                    InlineKeyboardButton("💀 RCE", callback_data="nuclei:tpl:rce"),
                ],
                [
                    InlineKeyboardButton("📂 LFI", callback_data="nuclei:tpl:lfi"),
                    InlineKeyboardButton("🔗 SSRF", callback_data="nuclei:tpl:ssrf"),
                    InlineKeyboardButton("⚙️ Exposed Panels", callback_data="nuclei:tpl:exposed-panels"),
                ],
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:menu")],
            ]),
        )
        return

    # ── Quick template search from button ──
    if action == "tpl":
        from config import config
        api_key = getattr(config, "NUCLEI_API_KEY", None)
        client = NucleiClient(api_key)

        await query.edit_message_text(
            f"🔍 <b>Searching templates for:</b> <code>{escape_html(param)}</code>",
            parse_mode=ParseMode.HTML,
        )
        result = await client.search_templates(param, limit=10)

        if not result.get("ok"):
            await query.edit_message_text(
                f"❌ <code>{escape_html(result.get('error', 'Search failed'))}</code>\n\n"
                f"Ensure your NUCLEI_API_KEY is configured.",
                parse_mode=ParseMode.HTML,
            )
            return

        data = result.get("data", {})
        templates = data if isinstance(data, list) else data.get("templates", [])

        if not templates:
            await query.edit_message_text(
                f"❌ No templates found for <code>{escape_html(param)}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        lines: list[str] = [f"<b>🔍 Templates:</b> <code>{escape_html(param)}</code> ({len(templates)} found)\n"]

        for i, tpl in enumerate(templates[:8]):
            tpl_id = tpl.get("id", tpl.get("template-id", "?"))
            tpl_name = tpl.get("name", tpl.get("info", {}).get("name", "Unknown"))
            sev = tpl.get("severity", "info").lower()
            lines.append(f"{_sev_tag(sev)} — <code>{escape_html(str(tpl_id))}</code>")
            lines.append(f"  {escape_html(str(tpl_name)[:80])}\n")

        await query.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:template_prompt")],
            ]),
        )
        return

    # ── Status prompt ──
    if action == "status_prompt":
        await query.edit_message_text(
            f"{bold('📊 Check Scan Status')}\n\n"
            f"Send the command:\n"
            f"  {code('/nuclei status <scan_id>')}\n\n"
            f"Or use {code('/nuclei list')} to find your scan IDs.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📋 List Scans", callback_data="nuclei:list_scans")],
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:menu")],
            ]),
        )
        return

    # ── Fetch status by scan_id ──
    if action == "status" and param:
        from config import config
        api_key = getattr(config, "NUCLEI_API_KEY", None)
        client = NucleiClient(api_key)

        await query.edit_message_text("📊 <b>Fetching status…</b>", parse_mode=ParseMode.HTML)
        result = await client.get_scan_status(param)

        if not result.get("ok"):
            await query.edit_message_text(
                f"❌ <code>{escape_html(result.get('error', 'Failed'))}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        data = result.get("data", {})
        state = data.get("status", "unknown")
        target = data.get("target", "")
        findings_count = data.get("findings_count", data.get("vulnerabilities_count", "?"))

        lines: list[str] = [
            f"<b>📊 Scan Status</b>\n",
            f"  ID: <code>{escape_html(param)}</code>",
            f"  Target: <code>{escape_html(target)}</code>",
            f"  Status: <code>{escape_html(str(state))}</code>",
            f"  Findings: <code>{escape_html(str(findings_count))}</code>",
        ]

        buttons = [[InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")]]
        if state in ("completed", "done", "finished"):
            buttons.insert(0, [InlineKeyboardButton("📋 View Results", callback_data=f"nuclei:results:{param}")])

        await query.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return

    # ── Fetch results by scan_id ──
    if action == "results" and param:
        from config import config
        api_key = getattr(config, "NUCLEI_API_KEY", None)
        client = NucleiClient(api_key)

        await query.edit_message_text("📋 <b>Fetching results…</b>", parse_mode=ParseMode.HTML)
        results = await client.get_scan_results(param)

        formatted, kb = _format_scan_results(results)

        kb_rows = [[InlineKeyboardButton("📊 Status", callback_data=f"nuclei:status:{param}")]]
        if kb and kb.inline_keyboard:
            kb_rows.extend(kb.inline_keyboard)
        kb_rows.append([InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")])

        await query.edit_message_text(
            formatted,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup(kb_rows),
        )
        return

    # ── Cancel prompt ──
    if action == "cancel_prompt":
        await query.edit_message_text(
            f"{bold('🛑 Cancel Scan')}\n\n"
            f"Send the command:\n"
            f"  {code('/nuclei cancel <scan_id>')}\n\n"
            f"Use {code('/nuclei list')} to find scan IDs.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📋 List Scans", callback_data="nuclei:list_scans")],
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:menu")],
            ]),
        )
        return

    # ── About ──
    if action == "about":
        await query.edit_message_text(
            f"{bold('☢️ About Nuclei Integration')}\n\n"
            f"Nuclei is a fast, template-based vulnerability scanner by "
            f"{link('ProjectDiscovery', 'https://github.com/projectdiscovery/nuclei')}.\n\n"
            f"{bold('Features:')}\n"
            f"  • 8,000+ community templates\n"
            f"  • HTTP, DNS, TCP, SSL scanning\n"
            f"  • CVE detection & exposure checking\n"
            f"  • Custom template support\n\n"
            f"{bold('Powered by:')}\n"
            f"  • {link('PDCP Cloud API', 'https://cloud.projectdiscovery.io')}\n"
            f"  • {link('Nuclei Templates', 'https://templates.nuclei.sh')}\n\n"
            f"{italic('⚠️ For authorized security testing only.')}",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⚡ Start Scan", callback_data="nuclei:scan_prompt")],
                [InlineKeyboardButton("↩️ Back", callback_data="nuclei:menu")],
            ]),
        )
        return

    # ── List scans from button ──
    if action == "list_scans":
        from config import config
        api_key = getattr(config, "NUCLEI_API_KEY", None)
        client = NucleiClient(api_key)

        await query.edit_message_text("📋 <b>Fetching scans…</b>", parse_mode=ParseMode.HTML)
        result = await client.list_scans(limit=10)

        if not result.get("ok"):
            await query.edit_message_text(
                f"❌ <code>{escape_html(result.get('error', 'Failed'))}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        data = result.get("data", {})
        scans = data if isinstance(data, list) else data.get("scans", [])

        if not scans:
            await query.edit_message_text(
                "📋 <b>No recent scans.</b>\n\n"
                f"Start one: {code('/nuclei scan https://example.com')}",
                parse_mode=ParseMode.HTML,
            )
            return

        lines: list[str] = ["<b>📋 Recent Scans</b>\n"]
        buttons: list = []

        for scan in scans[:8]:
            scan_id = scan.get("id", scan.get("scan_id", "?"))
            target = scan.get("target", "Unknown")[:35]
            state = scan.get("status", "unknown")
            findings = scan.get("findings_count", scan.get("vulnerabilities_count", "?"))
            emoji = "✅" if state in ("completed", "done") else "⏳" if state == "running" else "❌"

            lines.append(f"{emoji} <code>{escape_html(str(scan_id))}</code> — {escape_html(str(target))}")
            buttons.append([
                InlineKeyboardButton(f"{emoji} {escape_html(str(target))}", callback_data=f"nuclei:status:{scan_id}"),
            ])

        buttons.append([InlineKeyboardButton("↩️ Nuclei Menu", callback_data="nuclei:menu")])

        await query.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return

    # Fallback
    await query.edit_message_text(
        "Unknown action. Use /nuclei to start.",
        parse_mode=ParseMode.HTML,
    )
