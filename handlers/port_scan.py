"""
Port Scanner Handler
Uses Shodan InternetDB (free) + socket-based probing.
"""

import asyncio
import logging
import socket
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.validators import sanitize_input, validate_domain, validate_ip
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, escape_html
import aiohttp
from api_clients.shodan_client import ShodanClient

# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5672: "AMQP",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    11211: "Memcached", 6443: "Kubernetes API",
}

shodan = ShodanClient()


async def cmd_port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    if not context.args:
        buttons = [
            [InlineKeyboardButton("⚡ Quick Scan (Top 20)", callback_data="port:help:quick"),
             InlineKeyboardButton("🔍 Full Scan (Top 30)", callback_data="port:help:full")]
        ]
        await update.message.reply_text(
            "🔌 <b>Port Scanner</b>\n\n"
            "Usage: <code>/port example.com</code>\n"
            "       <code>/port 8.8.8.8</code>\n\n"
            "Scans commonly known ports using:\n"
            "• Shodan InternetDB (instant)\n"
            "• Socket probing (live check)\n\n"
            "⚠️ Only scan targets you have authorization for!",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        return

    target = sanitize_input(context.args[0].lower().strip())
    target = re.sub(r'^https?://', '', target).split('/')[0]
    scan_mode = "quick"

    if len(context.args) > 1 and context.args[1].lower() in ("full", "all"):
        scan_mode = "full"

    msg = await update.message.reply_text(f"🔌 Scanning ports on <b>{escape_html(target)}</b>...")

    # Resolve domain to IP
    ip = target
    if validate_domain(target):
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            await msg.edit_text(f"❌ Could not resolve <b>{escape_html(target)}</b>")
            return

    elif not validate_ip(target):
        await msg.edit_text("❌ Invalid IP or domain.")
        return

    ports_to_scan = list(COMMON_PORTS.keys())
    if scan_mode == "quick":
        ports_to_scan = sorted(ports_to_scan)[:20]

    # Step 1: Shodan InternetDB
    shodan_data = None
    try:
        shodan_data = await shodan.internet_db(ip)
    except Exception:
        pass

    # Step 2: Socket probing (concurrent)
    probe_results = await _probe_ports(ip, ports_to_scan)

    # Merge results
    all_open = set()
    shodan_ports = []

    if shodan_data and not isinstance(shodan_data, dict) or shodan_data.get("error"):
        shodan_data = {}

    if isinstance(shodan_data, dict) and "ports" in shodan_data:
        shodan_ports = shodan_data.get("ports", [])
        all_open.update(shodan_ports)

    for port in probe_results:
        if probe_results[port]:
            all_open.add(port)

    increment_usage(user_id)
    log_query(user_id, "port", f"{target}({ip})", f"open_{len(all_open)}")

    # Format output
    lines = [f"🔌 <b>Port Scan Results — {escape_html(target)}</b>"]
    lines.append(f"📍 IP: <code>{ip}</code>")
    lines.append(f"🔓 <b>Open Ports: {len(all_open)}</b>\n")

    if shodan_data and isinstance(shodan_data, dict):
        if shodan_data.get("vulns"):
            vulns = shodan_data["vulns"]
            lines.append(f"⚠️ <b>Vulnerabilities ({len(vulns)})</b>:")
            for v in vulns[:15]:
                lines.append(f"  • <code>{v}</code>")
            if len(vulns) > 15:
                lines.append(f"  ... and {len(vulns) - 15} more")
            lines.append("")

        if shodan_data.get("hostnames"):
            lines.append(f"🌐 Hostnames: {', '.join(shodan_data['hostnames'][:5])}")
            lines.append("")

        if shodan_data.get("cpes"):
            lines.append(f"🏷️ CPEs: {len(shodan_data['cpes'])} identified")
            lines.append("")

    if all_open:
        lines.append("<b>Port Details:</b>")
        for port in sorted(all_open):
            service = COMMON_PORTS.get(port, "Unknown")
            source = []
            if port in probe_results and probe_results[port]:
                source.append("probed")
            if port in shodan_ports:
                source.append("shodan")
            lines.append(f"  • <code>{port:>5}</code>  {service:20s}  [{', '.join(source)}]")
    else:
        lines.append("✅ No open ports detected among scanned targets.")

    lines.append(f"\n⚠️ Scanned {len(ports_to_scan)} ports | "
                 f"Shodan: {'✅' if shodan_ports else '❌'} | Probed: ✅")

    await msg.edit_text("\n".join(lines))


async def _probe_ports(ip: str, ports: list[int], timeout: float = 2.0) -> dict:
    """Concurrently probe ports using asyncio."""
    results = {}

    async def check_port(port: int):
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port, True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return port, False

    tasks = [check_port(p) for p in ports]
    done = await asyncio.gather(*tasks, return_exceptions=True)
    for item in done:
        if isinstance(item, Exception):
            continue
        port, is_open = item
        results[port] = is_open

    return results


async def handle_port_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data.split(":")
    if data[1] == "help":
        mode = data[2]
        mode_text = "Quick (top 20 ports)" if mode == "quick" else "Full (top 30 ports)"
        await query.edit_message_text(
            f"🔌 <b>Port Scan Mode: {mode_text}</b>\n\n"
            "Usage:\n"
            f"  <code>/port domain.com</code> — Quick scan\n"
            f"  <code>/port domain.com full</code> — Full scan\n\n"
            "Common ports include: SSH(22), HTTP(80), HTTPS(443), "
            "FTP(21), SMTP(25), DNS(53), MySQL(3306), "
            "PostgreSQL(5432), Redis(6379), MongoDB(27017)\n\n"
            "⚠️ Only scan targets you have permission to test."
        )
