"""
Email Reconnaissance Handler
Advanced email OSINT: Gravatar, ClearBit, social profile discovery,
email reputation, and breach awareness.
"""

import re
import hashlib
import aiohttp

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from database import increment_usage, log_query
from utils.validators import sanitize_input, validate_email
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, link, escape_html


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard for email recon."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 How It Works", callback_data="erecon:about"),
            InlineKeyboardButton("🎯 Techniques", callback_data="erecon:techniques"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="erecon:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="erecon:back_main"),
        ],
    ])


async def cmd_emailrecon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /emailrecon <address> — advanced email OSINT."""
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    args = context.args
    if not args:
        await update.message.reply_text(
            f"{bold('📧 Advanced Email Reconnaissance')}\n\n"
            f"Gather deep OSINT data from an email address.\n\n"
            f"Usage: {code('/emailrecon <address>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🖼️ Gravatar profile lookup\n"
            f"  🌐 ClearBit company enrichment\n"
            f"  👤 Social profile discovery\n"
            f"  📬 Email format analysis\n"
            f"  🔥 Breach history awareness\n"
            f"  📡 Email server fingerprinting\n\n"
            f"Example: {code('/emailrecon user@example.com')}",
            parse_mode=ParseMode.HTML,
        )
        return

    raw_email = sanitize_input(args[0], max_length=254).lower()

    if not validate_email(raw_email):
        await update.message.reply_text(
            f"❌ {bold('Invalid email format.')}\n\n"
            f"Please provide a valid email address.",
            parse_mode=ParseMode.HTML,
        )
        return

    email = raw_email
    processing_msg = await update.message.reply_text(
        f"🔍 Investigating {code(email)} …",
        parse_mode=ParseMode.HTML,
    )

    increment_usage(user_id)

    try:
        results = await _run_email_recon(email)
        result_text = _format_email_recon_report(email, results)

        # Build keyboard
        gravatar_url = f"https://www.gravatar.com/avatar/{hashlib.md5(email.strip().encode()).hexdigest()}"
        hibp_url = f"https://haveibeenpwned.com/account/{email}"
        vt_url = f"https://www.virustotal.com/gui/search/{email}"

        rows = []
        if results.get("gravatar_profile"):
            rows.append([
                InlineKeyboardButton("🖼️ View Gravatar", url=gravatar_url),
                InlineKeyboardButton("🔥 HIBP Breaches", url=hibp_url),
            ])
        else:
            rows.append([
                InlineKeyboardButton("🔥 HIBP Breaches", url=hibp_url),
                InlineKeyboardButton("🛡️ VirusTotal", url=vt_url),
            ])

        if results.get("social_profiles"):
            for profile in results["social_profiles"][:4]:
                rows.append([
                    InlineKeyboardButton(
                        f"{profile['emoji']} {profile['name']}",
                        url=profile["url"],
                    )
                ])

        rows.append([
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="erecon:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="erecon:back_main"),
        ])

        keyboard = InlineKeyboardMarkup(rows)

        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

        log_query(user_id, "email_recon", email, "success")

    except Exception as exc:
        logger.error("Email recon failed for %s: %s", email, exc)
        await processing_msg.edit_text(
            f"❌ Email recon failed for {code(email)}.\n\n"
            f"Error: {escape_html(str(exc))}",
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "email_recon", email, f"error: {exc}")


async def handle_emailrecon_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the email recon module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>How Email Reconnaissance Works</b>\n\n"
            "Email reconnaissance is a multi-layered OSINT technique that "
            "extracts maximum information from an email address.\n\n"
            "<b>Data Sources:</b>\n"
            "🖼️ <b>Gravatar:</b> Many people link a profile photo to their "
            "email via Gravatar. This can reveal their photo, name, bio, "
            "and social media links.\n\n"
            "🌐 <b>ClearBit:</b> Enriches email with company data, job title, "
            "and social profiles when a company email is used.\n\n"
            "📡 <b>MX Records:</b> The mail server configuration reveals the "
            "email provider and organizational infrastructure.\n\n"
            "🔥 <b>HIBP:</b> Checks if the email appeared in known data breaches.\n\n"
            f"{italic('Note: Basic checks run without API keys. Configure API keys for full results.')}"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🎯 Techniques", callback_data="erecon:techniques"),
                    InlineKeyboardButton("← Back", callback_data="erecon:menu"),
                ],
            ]),
        )

    elif action == "techniques":
        techniques_text = (
            "🎯 <b>OSINT Email Techniques</b>\n\n"
            "🔍 <b>Email Format Discovery:</b>\n"
            "  Analyze the email pattern (first.last@, flast@, etc.) to guess "
            "  other email addresses at the same company.\n\n"
            "🖼️ <b>Gravatar Mining:</b>\n"
            "  Hash the email with MD5 and check gravatar.com. Even without "
            "  a profile, a default image confirms the email is registered.\n\n"
            "🌐 <b>Domain Recon:</b>\n"
            "  Check the email domain for SPF, DKIM, and DMARC records to "
            "  understand the organization's email security posture.\n\n"
            "📧 <b>Breach Correlation:</b>\n"
            "  Cross-reference breach data with the email to find passwords, "
            "  and understand the scope of compromised accounts.\n\n"
            "🔗 <b>Social Mapping:</b>\n"
            "  Use the email to find connected accounts on social media, "
            "  forums, and other platforms where it was used to sign up."
        )
        await query.edit_message_text(
            techniques_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 How It Works", callback_data="erecon:about"),
                    InlineKeyboardButton("← Back", callback_data="erecon:menu"),
                ],
            ]),
        )

    elif action == "menu":
        await query.edit_message_text(
            f"{bold('📧 Advanced Email Reconnaissance')}\n\n"
            f"Gather deep OSINT data from an email address.\n\n"
            f"Usage: {code('/emailrecon <address>')}\n\n"
            f"{bold('Features:')}\n"
            f"  🖼️ Gravatar profile lookup\n"
            f"  🌐 ClearBit company enrichment\n"
            f"  👤 Social profile discovery\n"
            f"  📬 Email format analysis\n"
            f"  🔥 Breach history awareness\n"
            f"  📡 Email server fingerprinting\n\n"
            f"Example: {code('/emailrecon user@example.com')}",
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


# ── Recon Engine ────────────────────────────────────────────────────────────────

async def _run_email_recon(email: str) -> dict:
    """Run all email reconnaissance checks concurrently."""
    domain = email.split("@")[-1].strip()
    email_hash = hashlib.md5(email.strip().encode()).hexdigest()

    results = {
        "email": email,
        "domain": domain,
        "md5_hash": email_hash,
        "gravatar_profile": None,
        "gravatar_exists": False,
        "clearbit_data": None,
        "social_profiles": [],
        "mx_records": [],
        "spf_record": None,
        "domain_info": {},
    }

    tasks = [
        _check_gravatar(email, email_hash),
        _check_clearbit(email),
        _check_mx_records(domain),
        _discover_social_profiles(email),
    ]

    task_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in task_results:
        if isinstance(result, Exception):
            continue
        if isinstance(result, dict):
            if "gravatar_profile" in result:
                results["gravatar_profile"] = result["gravatar_profile"]
                results["gravatar_exists"] = result.get("gravatar_exists", False)
            if "clearbit_data" in result:
                results["clearbit_data"] = result["clearbit_data"]
            if "social_profiles" in result:
                results["social_profiles"] = result["social_profiles"]
            if "mx_records" in result:
                results["mx_records"] = result["mx_records"]

    return results


async def _check_gravatar(email: str, email_hash: str) -> dict:
    """Check Gravatar for profile info."""
    try:
        url = f"https://en.gravatar.com/{email_hash}.json"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "OSINT-Bot/1.0"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"gravatar_profile": data.get("entry", [{}])[0], "gravatar_exists": True}
                else:
                    return {"gravatar_profile": None, "gravatar_exists": False}
    except Exception:
        return {"gravatar_profile": None, "gravatar_exists": False}


async def _check_clearbit(email: str) -> dict:
    """Check ClearBit for person/company enrichment."""
    try:
        from config import config
        # ClearBit requires an API key
        clearbit_key = getattr(config, "CLEARBIT_API_KEY", None)
        if not clearbit_key:
            return {"clearbit_data": None}

        url = f"https://person.clearbit.com/v2/people/find?email={email}"
        headers = {"Authorization": f"Bearer {clearbit_key}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"clearbit_data": data}
                return {"clearbit_data": None}
    except Exception:
        return {"clearbit_data": None}


async def _check_mx_records(domain: str) -> dict:
    """Check MX records for the email domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted(
            [(str(r.exchange).rstrip("."), r.preference) for r in answers],
            key=lambda x: x[1],
        )
        return {"mx_records": mx_records}
    except Exception:
        return {"mx_records": []}


async def _discover_social_profiles(email: str) -> dict:
    """Discover social profiles associated with the email."""
    profiles = []

    # Check Gravatar profile links
    email_hash = hashlib.md5(email.strip().encode()).hexdigest()
    try:
        url = f"https://en.gravatar.com/{email_hash}.json"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "OSINT-Bot/1.0"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entry = data.get("entry", [{}])[0]
                    accounts = entry.get("accounts", {})

                    social_map = {
                        "github": ("🐙", "GitHub"),
                        "twitter": ("🐦", "X / Twitter"),
                        "linkedin": ("💼", "LinkedIn"),
                        "facebook": ("📘", "Facebook"),
                        "instagram": ("📸", "Instagram"),
                        "youtube": ("▶️", "YouTube"),
                        "reddit": ("🤖", "Reddit"),
                        "tiktok": ("🎵", "TikTok"),
                        "twitch": ("🟣", "Twitch"),
                        "mastodon": ("🐘", "Mastodon"),
                        "keybase": ("🔑", "Keybase"),
                        "aboutme": ("👤", "About.me"),
                    }

                    for platform_key, (emoji, name) in social_map.items():
                        account = accounts.get(platform_key)
                        if account and isinstance(account, dict) and account.get("url"):
                            profiles.append({
                                "emoji": emoji,
                                "name": name,
                                "url": account["url"],
                                "username": account.get("username", ""),
                            })
    except Exception:
        pass

    return {"social_profiles": profiles}


# ── Report Formatter ────────────────────────────────────────────────────────────

def _format_email_recon_report(email: str, results: dict) -> str:
    """Build comprehensive email recon report."""
    domain = results["domain"]
    email_hash = results["md5_hash"]
    gravatar = results["gravatar_profile"]
    clearbit = results["clearbit_data"]
    social_profiles = results["social_profiles"]
    mx_records = results["mx_records"]

    lines = [
        f"{bold('📧 Email Reconnaissance Report')}",
        f"{'━' * 32}",
        "",
        f"📌 {bold('Target:')} {code(email)}",
        f"🌐 {bold('Domain:')} {code(domain)}",
        f"🔑 {bold('MD5:')} <code>{email_hash}</code>",
    ]

    # Gravatar section
    lines.append("")
    lines.append(f"{bold('🖼️ Gravatar Profile')}")

    if gravatar:
        display_name = gravatar.get("displayName", "")
        if display_name:
            lines.append(f"  👤 Name: {escape_html(display_name)}")
        about = gravatar.get("aboutMe", "")
        if about:
            lines.append(f"  📝 Bio: {escape_html(about[:200])}")
        location = gravatar.get("currentLocation", "")
        if location:
            lines.append(f"  📍 Location: {escape_html(location)}")
        profile_url = gravatar.get("profileUrl", "")
        if profile_url:
            lines.append(f"  🔗 Profile: {link(escape_html(profile_url), profile_url)}")

        # Photos
        photos = gravatar.get("photos", [])
        if photos:
            preferred = [p for p in photos if p.get("preferred")]
            img = preferred[0] if preferred else photos[0]
            lines.append(f"  🖼️ Avatar: {link('View Gravatar', img.get('value', ''))}")

        if social_profiles:
            lines.append(f"  🔗 Social Accounts: {bold(str(len(social_profiles)))} linked")
            for profile in social_profiles:
                username_str = f" (@{profile['username']})" if profile.get('username') else ""
                lines.append(
                    f"    • {profile['emoji']} {profile['name']}{escape_html(username_str)}"
                )
    else:
        lines.append(f"  ❌ No Gravatar profile found")
        lines.append(f"  {italic('This email is not linked to a Gravatar account.')}")

    # MX Records
    lines.append("")
    lines.append(f"{bold('📡 Email Infrastructure')}")

    if mx_records:
        lines.append(f"  📬 MX Records ({bold(str(len(mx_records)))}):")
        for mx_host, priority in mx_records:
            # Identify provider
            provider = _identify_email_provider(mx_host)
            provider_str = f" ({provider})" if provider else ""
            lines.append(f"    • {escape_html(mx_host)} [priority {priority}]{provider_str}")
    else:
        lines.append(f"  ⚠️ No MX records found (may not receive email)")

    # ClearBit enrichment
    if clearbit:
        lines.append("")
        lines.append(f"{bold('🌐 ClearBit Enrichment')}")
        if clearbit.get("fullName"):
            lines.append(f"  👤 Full Name: {escape_html(clearbit['fullName'])}")
        if clearbit.get("title"):
            lines.append(f"  💼 Title: {escape_html(clearbit['title'])}")
        if clearbit.get("linkedin", {}).get("handle"):
            lines.append(f"  💼 LinkedIn: @{escape_html(clearbit['linkedin']['handle'])}")
        if clearbit.get("email"):
            lines.append(f"  📧 Email: {code(escape_html(clearbit['email']))}")

    # Email pattern analysis
    lines.append("")
    lines.append(f"{bold('📬 Email Pattern Analysis')}")
    local_part = email.split("@")[0]
    pattern = _detect_email_pattern(local_part)
    lines.append(f"  🔤 Pattern: {bold(pattern)}")
    lines.append(f"  📏 Local part: {len(local_part)} characters")

    # Breach awareness
    lines.append("")
    lines.append(f"{bold('🔥 Breach Awareness')}")
    hibp_link = link(
        f"Check {email} on HIBP",
        f"https://haveibeenpwned.com/account/{email}",
    )
    lines.append(f"  {hibp_link}")
    lines.append(
        f"  {italic('Tap to check if this email appeared in known data breaches.')}"
    )

    # Footer
    lines.append("")
    lines.append(f"{'━' * 32}")
    lines.append(f"📡 Sources: Gravatar + DNS MX + ClearBit + HIBP")
    lines.append(italic("Only use this information for authorized investigations."))

    return "\n".join(lines)


def _detect_email_pattern(local_part: str) -> str:
    """Detect the email naming pattern."""
    cleaned = local_part.split("+")[0]

    if "." in cleaned and not any(c.isdigit() for c in cleaned.replace(".", "")):
        parts = cleaned.split(".")
        if len(parts) == 2:
            return "first.last"
        elif len(parts) == 3:
            return "first.middle.last"
    elif "_" in cleaned and not any(c.isdigit() for c in cleaned.replace("_", "")):
        parts = cleaned.split("_")
        if len(parts) == 2:
            return "first_last"
    elif cleaned.isdigit():
        return "numeric"
    elif re.match(r'^[a-z]{1,2}[a-z]{2,}$', cleaned):
        return "possible initials"
    elif any(c.isdigit() for c in cleaned):
        return "mixed alphanumeric"

    return "custom"


def _identify_email_provider(mx_host: str) -> str:
    """Identify the email provider from MX record."""
    mx_lower = mx_host.lower()
    providers = {
        "google": "Google Workspace",
        "googlemail": "Gmail",
        "outlook": "Microsoft 365",
        "office365": "Microsoft 365",
        "microsoft": "Microsoft",
        "yahoo": "Yahoo Mail",
        "amazonses": "Amazon SES",
        "sendgrid": "SendGrid",
        "mailgun": "Mailgun",
        "zoho": "Zoho Mail",
        "protonmail": "ProtonMail",
        "tutanota": "Tutanota",
        "icloud": "iCloud",
        "apple": "Apple Mail",
        "mimecast": "Mimecast",
        "proofpoint": "Proofpoint",
        "rackspace": "Rackspace Email",
        "fastmail": "Fastmail",
        "godaddy": "GoDaddy",
        "hostinger": "Hostinger",
        "cloudflare": "Cloudflare Email",
    }

    for key, name in providers.items():
        if key in mx_lower:
            return name

    return ""


# Need asyncio import
import asyncio
