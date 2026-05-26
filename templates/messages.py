"""
Message Templates — Centralized message strings.
"""

MAIN_MENU_TEXT = (
    "🕵️‍♂️ <b>OSINT Investigation Bot</b>\n\n"
    "Select a category to explore tools:"
)

HELP_TEXT = """🔍 <b>OSINT Bot — Command Reference</b>

<b>🔎 OSINT Investigation</b>
  /ip — IP geolocation & abuse check
  /domain — Domain analysis & DNS
  /user — Username search across platforms
  /malware — File hash scan (VirusTotal)
  /email — Email validation & breach check
  /phone — Phone number lookup
  /dork — Google dork generator
  /meta — EXIF metadata (send image)

<b>🛡️ Advanced Security</b>
  /vuln — CVE vulnerability scanner
  /darkweb — Breach monitor
  /news — Cybersecurity news feed
  /github — GitHub repo tracker

<b>🛠️ CTF & Developer Tools</b>
  /password — Secure password generator
  /run — Sandboxed code executor
  /encode — Hash & encoding tool

<b>🌐 Network Reconnaissance</b>
  /subdomain — Subdomain enumeration
  /dns — DNS record lookup
  /whois — WHOIS domain lookup
  /port — Port scanner

<b>🔗 URL & QR Tools</b>
  /urlscan — URL safety analyzer
  /qr — QR code generate/decode

<b>📋 General</b>
  /help — Show this message
  /stats — Your usage statistics
  /menu — Main menu"""
