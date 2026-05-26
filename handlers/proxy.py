"""
Proxy Management Handler for Telegram OSINT Bot.

Simple button-driven interface — no complex sub-commands needed.

Commands:
    /proxy              — Show proxy status and management menu
    /proxy add <url>    — Add a proxy (only text command — you need to type a URL)

Everything else (enable/disable, test, remove, clear, rotation) is done via inline buttons.
"""

import asyncio

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit, is_admin
from utils.logger import logger
from utils.formatters import bold, code, italic, escape_html
from utils.proxy_manager import proxy_manager, RotationMode


# ── Shared: Build the main menu keyboard ─────────────────────────────────────────

def _menu_keyboard() -> InlineKeyboardMarkup:
    """Build the clean 2-row proxy menu."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔌 On / Off", callback_data="proxy:toggle"),
            InlineKeyboardButton("📋 My Proxies", callback_data="proxy:list"),
        ],
        [
            InlineKeyboardButton("🧪 Test All", callback_data="proxy:test_all"),
            InlineKeyboardButton("🗑️ Clear All", callback_data="proxy:clear"),
        ],
    ])


def _back_keyboard() -> InlineKeyboardMarkup:
    """Single 'Back' button row."""
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⬅️ Back", callback_data="proxy:menu")],
    ])


def _menu_text() -> str:
    """Build the menu status text."""
    stats = proxy_manager.get_stats()
    on = stats["enabled"]
    icon = "🟢" if on else "🔴"

    text = (
        f"{bold('🔀 Proxy Manager')}\n\n"
        f"Status: {icon} {bold('ON' if on else 'OFF')}\n"
        f"Mode: {code(stats['rotation_mode'])}\n"
    )

    if stats["total_proxies"] > 0:
        text += f"Pool: {stats['total_proxies']} proxies "
        if stats["healthy_proxies"] > 0:
            text += f"({stats['healthy_proxies']} healthy)\n"
        else:
            text += "\n"
    else:
        text += "Pool: empty\n"

    text += (
        f"\n{italic('Add proxy: ')}{code('/proxy add <url>')}\n"
        f"{italic('Supports: HTTP, HTTPS, SOCKS4, SOCKS5')}"
    )
    return text


# ── Main Command ─────────────────────────────────────────────────────────────────

async def cmd_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /proxy and /proxy add."""
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment."
        )
        return

    # Restrict proxy management to admins only
    if not is_admin(user_id):
        await update.message.reply_text(
            "🔒 Proxy management is restricted to administrators only."
        )
        return

    args = context.args or []

    # /proxy add <url> — the ONLY text sub-command (you need to type a URL)
    if args and args[0].lower() in ("add", "set"):
        await _add_proxy_from_text(update, args[1:])
        return

    # Any other args → ignore and show menu
    if args:
        # Treat first arg as a raw URL shortcut: /proxy http://... or /proxy socks5://...
        raw = args[0].strip()
        if raw.startswith(("http://", "https://", "socks4://", "socks5://")):
            await _add_proxy_from_text(update, args)
            return
        # else just show the menu

    # /proxy → show menu
    increment_usage(user_id)
    log_query(user_id, "proxy_menu")
    await update.message.reply_text(
        text=_menu_text(),
        reply_markup=_menu_keyboard(),
        parse_mode=ParseMode.HTML,
    )


async def _add_proxy_from_text(update: Update, args: list) -> None:
    """Add a proxy from the text command."""
    user_id = update.effective_user.id

    if not args:
        await update.message.reply_text(
            f"ℹ️ {bold('Add a Proxy')}\n\n"
            f"{code('/proxy add <url>')}\n\n"
            f"{bold('Examples:')}\n"
            f"  {code('/proxy add http://host:port')}\n"
            f"  {code('/proxy add http://user:pass@host:port')}\n"
            f"  {code('/proxy add socks5://host:port')}\n"
            f"  {code('/proxy add 127.0.0.1:9050')}\n\n"
            f"{italic('Supports: HTTP, HTTPS, SOCKS4, SOCKS5')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_url = sanitize_input(args[0], max_length=256)
    label = sanitize_input(" ".join(args[1:]), max_length=64) if len(args) > 1 else ""

    if not raw_url:
        await update.message.reply_text(
            f"❌ {bold('Invalid proxy URL.')}",
            parse_mode=ParseMode.HTML,
        )
        return

    entry = proxy_manager.add_proxy(raw_url, label=label)
    increment_usage(user_id)
    log_query(user_id, "proxy_add", query=entry.url)

    masked = proxy_manager._mask_credentials(entry.url)
    label_str = f" ({escape_html(label)})" if label else ""

    await update.message.reply_text(
        f"✅ {bold('Proxy Added')}{label_str}\n"
        f"🔗 {code(masked)}\n"
        f"🏷️ {entry.proxy_type.value.upper()}",
        parse_mode=ParseMode.HTML,
    )


# ── Callback Handler ────────────────────────────────────────────────────────────

async def handle_proxy_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle ALL proxy inline button taps."""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id

    parts = query.data.split(":")
    if len(parts) < 2:
        return

    action = parts[1]

    # ── Main menu ────────────────────────────────────────────
    if action == "menu":
        await query.edit_message_text(
            text=_menu_text(),
            reply_markup=_menu_keyboard(),
            parse_mode=ParseMode.HTML,
        )

    # ── Toggle proxy on/off ──────────────────────────────────
    elif action == "toggle":
        if proxy_manager.pool_size == 0 and not proxy_manager.enabled:
            await query.answer("Add a proxy first!", show_alert=True)
            return
        proxy_manager.enabled = not proxy_manager.enabled
        increment_usage(user_id)
        log_query(user_id, "proxy_toggle")
        await query.edit_message_text(
            text=_menu_text(),
            reply_markup=_menu_keyboard(),
            parse_mode=ParseMode.HTML,
        )

    # ── List all proxies ────────────────────────────────────
    elif action == "list":
        increment_usage(user_id)
        log_query(user_id, "proxy_list")
        proxies = proxy_manager.pool

        if not proxies:
            await query.edit_message_text(
                f"📋 {bold('Proxy Pool')}\n\n"
                f"{italic('Empty — add one with ')}{code('/proxy add <url>')}",
                reply_markup=_back_keyboard(),
                parse_mode=ParseMode.HTML,
            )
            return

        lines = [f"📋 {bold('Your Proxies')} ({len(proxies)})\n"]

        for p in proxies:
            if not p.enabled:
                icon = "⚫"
            elif not p.last_tested:
                icon = "⚪"
            elif p.is_healthy:
                icon = "🟢"
            elif p.success_rate >= 0.1:
                icon = "🟡"
            else:
                icon = "🔴"

            rate = f"{p.success_rate * 100:.0f}%" if p.last_tested else "—"
            label = f" {escape_html(p.label)}" if p.label else ""
            lines.append(f"{icon} #{p.id}{label} [{p.proxy_type.value}] {rate}")

        # Build buttons: one row per proxy with Test + Remove
        buttons: list[list[InlineKeyboardButton]] = []
        for p in proxies:
            lbl = (p.label or f"#{p.id}")[:25]
            buttons.append([
                InlineKeyboardButton(f"🧪 {lbl}", callback_data=f"proxy:test:{p.id}"),
                InlineKeyboardButton("🗑️", callback_data=f"proxy:remove:{p.id}"),
            ])

        # Rotation picker at bottom
        current = proxy_manager.rotation_mode.value
        rot_btns = []
        for mode in ("sequential", "random", "failover"):
            mark = "✅ " if mode == current else ""
            rot_btns.append(InlineKeyboardButton(
                f"{mark}{mode.capitalize()}",
                callback_data=f"proxy:mode:{mode}",
            ))
        buttons.append(rot_btns)
        buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="proxy:menu")])

        await query.edit_message_text(
            text="\n".join(lines),
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode=ParseMode.HTML,
        )

    # ── Set rotation mode ───────────────────────────────────
    elif action == "mode":
        if len(parts) < 3:
            return
        mode_str = parts[2]
        valid = {m.value: m for m in RotationMode}
        if mode_str in valid:
            proxy_manager.rotation_mode = valid[mode_str]
            log_query(user_id, "proxy_mode", query=mode_str)
        # Refresh the list view
        increment_usage(user_id)
        proxies = proxy_manager.pool
        if proxies:
            lines = [f"📋 {bold('Your Proxies')} ({len(proxies)})\n"]
            for p in proxies:
                if not p.enabled:
                    icon = "⚫"
                elif not p.last_tested:
                    icon = "⚪"
                elif p.is_healthy:
                    icon = "🟢"
                elif p.success_rate >= 0.1:
                    icon = "🟡"
                else:
                    icon = "🔴"
                rate = f"{p.success_rate * 100:.0f}%" if p.last_tested else "—"
                label = f" {escape_html(p.label)}" if p.label else ""
                lines.append(f"{icon} #{p.id}{label} [{p.proxy_type.value}] {rate}")

            buttons: list[list[InlineKeyboardButton]] = []
            for p in proxies:
                lbl = (p.label or f"#{p.id}")[:25]
                buttons.append([
                    InlineKeyboardButton(f"🧪 {lbl}", callback_data=f"proxy:test:{p.id}"),
                    InlineKeyboardButton("🗑️", callback_data=f"proxy:remove:{p.id}"),
                ])
            current = proxy_manager.rotation_mode.value
            rot_btns = []
            for mode in ("sequential", "random", "failover"):
                mark = "✅ " if mode == current else ""
                rot_btns.append(InlineKeyboardButton(
                    f"{mark}{mode.capitalize()}",
                    callback_data=f"proxy:mode:{mode}",
                ))
            buttons.append(rot_btns)
            buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="proxy:menu")])

            await query.edit_message_text(
                text="\n".join(lines),
                reply_markup=InlineKeyboardMarkup(buttons),
                parse_mode=ParseMode.HTML,
            )

    # ── Test all proxies ─────────────────────────────────────
    elif action == "test_all":
        if proxy_manager.pool_size == 0:
            await query.answer("No proxies to test!", show_alert=True)
            return

        await query.edit_message_text(
            f"🧪 Testing {proxy_manager.pool_size} proxy(ies) …",
            parse_mode=ParseMode.HTML,
        )

        increment_usage(user_id)
        log_query(user_id, "proxy_test_all")
        results = await proxy_manager.test_all()

        working = sum(1 for r in results if r.get("working"))
        failed = len(results) - working

        lines = [f"🧪 {bold('Test Results')}\n"]
        for r in results:
            pid = r.get("proxy_id", "?")
            if r.get("working"):
                ip = r.get("ip", "?")
                t = r.get("response_time", 0)
                lines.append(f"  ✅ #{pid} — {t}s IP: {code(ip)}")
            else:
                err = escape_html(r.get("error", "Unknown")[:40])
                lines.append(f"  ❌ #{pid} — {err}")

        lines.append(f"\n{bold(f'{working} working, {failed} failed')}")

        await query.edit_message_text(
            text="\n".join(lines),
            reply_markup=_back_keyboard(),
            parse_mode=ParseMode.HTML,
        )

    # ── Test single proxy ───────────────────────────────────
    elif action == "test":
        if len(parts) < 3:
            return
        proxy_id = int(parts[2])
        proxy = proxy_manager.get_proxy(proxy_id)
        if not proxy:
            await query.answer("Not found!", show_alert=True)
            return

        await query.edit_message_text(
            f"🧪 Testing #{proxy_id} …",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "proxy_test", query=str(proxy_id))
        result = await proxy_manager.test_proxy(proxy)

        if result["working"]:
            text = (
                f"✅ #{proxy_id} {bold('Working!')}\n"
                f"⏱️ {result['response_time']}s\n"
                f"🌐 IP: {code(result.get('ip', '?'))}"
            )
        else:
            text = (
                f"❌ #{proxy_id} {bold('Failed')}\n"
                f"{escape_html(result.get('error', 'Unknown')[:60])}"
            )

        await query.edit_message_text(
            text=text,
            reply_markup=_back_keyboard(),
            parse_mode=ParseMode.HTML,
        )

    # ── Remove proxy (confirm) ──────────────────────────────
    elif action == "remove":
        if len(parts) < 3:
            return
        proxy_id = int(parts[2])
        proxy = proxy_manager.get_proxy(proxy_id)
        if not proxy:
            await query.answer("Not found!", show_alert=True)
            return

        masked = proxy_manager._mask_credentials(proxy.url)
        await query.edit_message_text(
            text=(
                f"⚠️ {bold('Remove this proxy?')}\n\n"
                f"#{proxy_id} {code(masked)}\n"
                f"{italic('This cannot be undone.')}"
            ),
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✅ Remove", callback_data=f"proxy:do_remove:{proxy_id}"),
                    InlineKeyboardButton("❌ Cancel", callback_data="proxy:list"),
                ],
            ]),
            parse_mode=ParseMode.HTML,
        )

    # ── Confirm removal ─────────────────────────────────────
    elif action == "do_remove":
        if len(parts) < 3:
            return
        proxy_id = int(parts[2])
        proxy_manager.remove_proxy(proxy_id)
        log_query(user_id, "proxy_remove", query=str(proxy_id))

        await query.edit_message_text(
            text=f"🗑️ {bold(f'Proxy #{proxy_id} removed.')}\n\n"
                 f"Pool: {proxy_manager.pool_size} remaining",
            reply_markup=_back_keyboard(),
            parse_mode=ParseMode.HTML,
        )

    # ── Clear all proxies (confirm) ─────────────────────────
    elif action == "clear":
        if proxy_manager.pool_size == 0:
            await query.answer("Already empty!", show_alert=True)
            return

        await query.edit_message_text(
            text=(
                f"⚠️ {bold('Clear all proxies?')}\n\n"
                f"You have {proxy_manager.pool_size} proxy(ies).\n"
                f"{italic('This cannot be undone.')}"
            ),
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✅ Clear All", callback_data="proxy:do_clear"),
                    InlineKeyboardButton("❌ Cancel", callback_data="proxy:menu"),
                ],
            ]),
            parse_mode=ParseMode.HTML,
        )

    elif action == "do_clear":
        count = proxy_manager.clear_pool()
        log_query(user_id, "proxy_clear")

        await query.edit_message_text(
            text=f"🗑️ {bold('All proxies cleared.')}\n\n"
                 f"Removed {count} proxy(ies).\n\n"
                 f"Add new with {code('/proxy add <url>')}",
            reply_markup=_back_keyboard(),
            parse_mode=ParseMode.HTML,
        )
