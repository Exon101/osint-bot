"""
Hash & Encode Tool Handler
Compute hashes (MD5, SHA-1, SHA-256, SHA-512), encode/decode Base64, Hex, and URL,
and auto-identify unknown hash types by length.

All operations use Python stdlib: hashlib, base64, binascii, urllib.parse.
"""

import base64
import binascii
import hashlib
import re
import urllib.parse

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from config import config
from database import increment_usage, log_query
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger
from utils.formatters import bold, code, italic, escape_html


# ── Constants ────────────────────────────────────────────────────────────────────

# Canonical hash algorithm names
HASH_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# Display metadata for each hash type
HASH_META = {
    "md5": {
        "label": "MD5",
        "emoji": "🟡",
        "length": 32,
        "bits": 128,
        "note": "Not collision-resistant — use for checksums only",
    },
    "sha1": {
        "label": "SHA-1",
        "emoji": "🟠",
        "length": 40,
        "bits": 160,
        "note": "Deprecated — vulnerable to collision attacks",
    },
    "sha256": {
        "label": "SHA-256",
        "emoji": "🟢",
        "length": 64,
        "bits": 256,
        "note": "Recommended — widely used, secure",
    },
    "sha512": {
        "label": "SHA-512",
        "emoji": "🔵",
        "length": 128,
        "bits": 512,
        "note": "Strong — good for high-security applications",
    },
}


# ── Hash Functions ───────────────────────────────────────────────────────────────

def _compute_hash(text: str, algorithm: str) -> str:
    """
    Compute a hash of the given text using the specified algorithm.

    Args:
        text: Input string to hash.
        algorithm: One of 'md5', 'sha1', 'sha256', 'sha512'.

    Returns:
        Hex-encoded hash digest string.
    """
    hasher = HASH_ALGORITHMS.get(algorithm)
    if not hasher:
        return "unsupported"
    return hasher(text.encode("utf-8")).hexdigest()


def _compute_all_hashes(text: str) -> dict[str, str]:
    """Compute all supported hash algorithms for a given text."""
    return {algo: _compute_hash(text, algo) for algo in HASH_ALGORITHMS}


# ── Encode / Decode Functions ────────────────────────────────────────────────────

def _encode_base64(text: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _decode_base64(encoded: str) -> str | None:
    """
    Decode a Base64 string. Returns None if input is invalid.

    Handles both standard Base64 and URL-safe Base64.
    """
    # Strip whitespace
    encoded = encoded.strip()
    if not encoded:
        return None
    try:
        # Try standard Base64 first
        decoded_bytes = base64.b64decode(encoded, validate=True)
        return decoded_bytes.decode("utf-8")
    except Exception:
        try:
            # Try URL-safe Base64
            padded = encoded + "=" * (-len(encoded) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            return decoded_bytes.decode("utf-8")
        except Exception:
            return None


def _encode_hex(text: str) -> str:
    """Encode text to hexadecimal."""
    return text.encode("utf-8").hex()


def _decode_hex(hex_str: str) -> str | None:
    """Decode a hexadecimal string. Returns None if input is invalid."""
    hex_str = hex_str.strip().lower()
    # Remove optional 0x prefix
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    # Remove optional spaces (e.g. "48 65 6c 6c 6f")
    hex_str = hex_str.replace(" ", "")
    if not hex_str:
        return None
    if len(hex_str) % 2 != 0:
        return None
    try:
        decoded_bytes = bytes.fromhex(hex_str)
        return decoded_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _encode_url(text: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(text, safe="")


def _decode_url(encoded: str) -> str:
    """URL-decode a string."""
    return urllib.parse.unquote(encoded)


# ── Hash Identification ──────────────────────────────────────────────────────────

def _identify_hash_type(hash_str: str) -> list[dict]:
    """
    Attempt to identify the type of a hash string based on length and character set.

    Args:
        hash_str: The hash string to identify.

    Returns:
        List of possible hash type dicts, sorted by confidence.
    """
    hash_str = hash_str.strip().lower()
    hash_len = len(hash_str)

    results = []

    # Check hex-only (most hashes are hex)
    is_hex = bool(re.fullmatch(r"[0-9a-f]+", hash_str))

    candidates = []

    if is_hex:
        for algo, meta in HASH_META.items():
            if hash_len == meta["length"]:
                candidates.append({
                    "algorithm": algo,
                    "label": meta["label"],
                    "emoji": meta["emoji"],
                    "length": meta["length"],
                    "bits": meta["bits"],
                    "confidence": "high",
                    "note": meta["note"],
                })

    # Check Base64 patterns
    # Base64: 22-24 chars for 16 bytes (MD5-equivalent), etc.
    # We look for alphanumeric + /+ = characters
    is_b64 = bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", hash_str))
    if is_b64 and len(hash_str) >= 4:
        candidates.append({
            "algorithm": "base64",
            "label": "Base64",
            "emoji": "🔤",
            "length": len(hash_str),
            "bits": len(hash_str) * 6,  # approximate bits
            "confidence": "medium",
            "note": "Base64 encoded data (use /encode b64 decode <input> to decode)",
        })

    # Check URL-encoded pattern (%XX)
    if re.search(r"%[0-9a-fA-F]{2}", hash_str):
        candidates.append({
            "algorithm": "url_encoded",
            "label": "URL Encoded",
            "emoji": "🔗",
            "length": len(hash_str),
            "bits": 0,
            "confidence": "high",
            "note": "Contains URL-encoded characters",
        })

    # Check for numeric patterns (possible CRC32 or simple hash)
    if hash_str.isdigit() and len(hash_str) <= 10:
        candidates.append({
            "algorithm": "numeric",
            "label": "Numeric Hash",
            "emoji": "🔢",
            "length": len(hash_str),
            "bits": 0,
            "confidence": "low",
            "note": "Could be CRC32, Adler32, or simple numeric hash",
        })

    # Heuristic: if it's a hex string that doesn't match standard hash lengths
    if is_hex and hash_len not in {32, 40, 64, 128}:
        candidates.append({
            "algorithm": "hex",
            "label": "Hex String",
            "emoji": "🔤",
            "length": hash_len,
            "bits": hash_len * 4,
            "confidence": "medium",
            "note": f"Hex string ({hash_len * 4} bits) — unknown algorithm",
        })

    # If it's hex and matches multiple lengths, report all
    return candidates


# ── Response Formatters ──────────────────────────────────────────────────────────

def _format_all_hashes(text: str, hashes: dict[str, str]) -> str:
    """Format the complete hash report for all algorithms."""
    input_preview = escape_html(text[:80]) + ("…" if len(text) > 80 else "")

    lines = [
        f"{bold('🔤 Hash & Encode Results')}",
        f"{'━' * 34}",
        "",
        f"📝 {bold('Input:')} {code(input_preview)}",
        f"📏 {bold('Length:')} {len(text)} characters",
        "",
        f"{bold('🔐 Hash Digests:')}",
    ]

    for algo, digest in hashes.items():
        meta = HASH_META[algo]
        lines.append(
            f"  {meta['emoji']} {bold(meta['label'])} ({meta['bits']}-bit)"
        )
        lines.append(f"     {code(digest)}")

    return "\n".join(lines)


def _format_single_hash(
    algorithm: str,
    text: str,
    digest: str,
) -> str:
    """Format a single hash result."""
    meta = HASH_META.get(algorithm, {"label": algorithm.upper(), "emoji": "🔤", "bits": 0, "note": ""})
    input_preview = escape_html(text[:80]) + ("…" if len(text) > 80 else "")
    _hash_title = f"{meta['emoji']} {meta['label']} Hash"

    lines = [
        bold(_hash_title),
        f"{'━' * 34}",
        "",
        f"📝 {bold('Input:')} {code(input_preview)}",
        f"📐 {bold('Algorithm:')} {meta['label']} ({meta['bits']}-bit)",
        f"📏 {bold('Digest:')}",
        f"  {code(digest)}",
        f"📏 {bold('Digest Length:')} {len(digest)} hex characters",
    ]

    if meta.get("note"):
        lines.append("")
        lines.append(f"💡 {italic(meta['note'])}")

    return "\n".join(lines)


def _format_encode_result(
    operation: str,
    algorithm: str,
    input_text: str,
    output_text: str,
) -> str:
    """Format an encode/decode result."""
    input_preview = escape_html(input_text[:80]) + ("…" if len(input_text) > 80 else "")
    output_preview = escape_html(output_text[:80]) + ("…" if len(output_text) > 80 else "")

    op_icon = "🟢" if "encode" in operation.lower() else "🔵"

    lines = [
        f"{op_icon} {bold(operation + ' — ' + algorithm)}",
        f"{'━' * 34}",
        "",
        f"📝 {bold('Input:')} {code(input_preview)}",
        f"📤 {bold('Output:')} {code(output_preview)}",
        f"📏 {bold('Output Length:')} {len(output_text)} characters",
    ]

    return "\n".join(lines)


def _format_decode_error(algorithm: str, input_text: str) -> str:
    """Format a decode error message."""
    input_preview = escape_html(input_text[:60]) + ("…" if len(input_text) > 60 else "")

    lines = [
        f"❌ {bold(f'{algorithm} Decode Failed')}",
        f"{'━' * 30}",
        "",
        f"📝 {bold('Input:')} {code(input_preview)}",
        "",
        f"The input is not valid {algorithm} encoded data.\n",
    ]

    # Add hints based on algorithm
    if algorithm == "Base64":
        lines.append(f"💡 {italic('Tip: Base64 uses A-Z, a-z, 0-9, +, /, and = for padding.')}")
    elif algorithm == "Hex":
        lines.append(f"💡 {italic('Tip: Hex uses 0-9 and a-f. Each byte = 2 hex chars.')}")
    elif algorithm == "URL":
        lines.append(f"💡 {italic('Tip: URL-encoded strings contain %XX patterns.')}")

    return "\n".join(lines)


def _format_identify_results(hash_str: str, candidates: list[dict]) -> str:
    """Format hash identification results."""
    hash_preview = escape_html(hash_str[:60]) + ("…" if len(hash_str) > 60 else "")

    lines = [
        f"{bold('🔍 Hash Identification')}",
        f"{'━' * 34}",
        "",
        f"📝 {bold('Input:')} {code(hash_preview)}",
        f"📏 {bold('Length:')} {len(hash_str)} characters",
        f"🔤 {bold('Charset:')} "
        f"{'Hex (0-9, a-f)' if re.fullmatch(r'[0-9a-f]+', hash_str.strip(), re.IGNORECASE) else 'Mixed'}",
    ]

    if not candidates:
        lines.append("")
        lines.append("❓ Could not identify the hash type.")
        lines.append(f"💡 {italic('Tip: Try providing a known hash format (MD5, SHA, etc.)')}")
    else:
        lines.append("")
        lines.append(f"{bold('Possible Matches')} ({len(candidates)} found):\n")

        for candidate in candidates:
            conf_icon = {"high": "✅", "medium": "🟡", "low": "⚪"}.get(
                candidate["confidence"], "⚪"
            )
            lines.append(
                f"  {conf_icon} {candidate['emoji']} {bold(candidate['label'])} "
                f"— {italic(candidate['confidence'])}"
            )
            if candidate.get("bits"):
                lines.append(f"     {candidate['bits']}-bit")
            if candidate.get("note"):
                lines.append(f"     {italic(candidate['note'])}")
            lines.append("")

    return "\n".join(lines)


def _format_full_encode_table(text: str) -> str:
    """
    Format a comprehensive table showing all encode/hash formats for the given text.
    """
    input_preview = escape_html(text[:80]) + ("…" if len(text) > 80 else "")

    # Compute all values
    hashes = _compute_all_hashes(text)
    b64 = _encode_base64(text)
    hex_enc = _encode_hex(text)
    url_enc = _encode_url(text)

    lines = [
        f"{bold('🔤 Complete Encode & Hash Table')}",
        f"{'━' * 38}",
        "",
        f"📝 {bold('Input:')} {code(input_preview)}",
        "",
        f"{bold('┌─────────────────────────────────────')}",
        f"{bold('│ 🔐 Hash Digests')}",
        f"{bold('└─────────────────────────────────────')}",
    ]

    for algo in HASH_ALGORITHMS:
        meta = HASH_META[algo]
        lines.append(
            f"  {meta['emoji']} {bold(meta['label']):<8} "
            f"│ {code(hashes[algo])}"
        )

    lines.append("")
    lines.append(f"{bold('┌─────────────────────────────────────')}")
    lines.append(f"{bold('│ 🔄 Encodings')}")
    lines.append(f"{bold('└─────────────────────────────────────')}")

    lines.append(f"  🔤 {bold('Base64')}  │ {code(escape_html(b64))}")
    lines.append(f"  🔤 {bold('Hex')}     │ {code(escape_html(hex_enc))}")
    lines.append(f"  🔗 {bold('URL')}     │ {code(escape_html(url_enc))}")

    lines.append("")
    lines.append(f"💡 {italic('Use specific commands for decode:')}")
    lines.append(f"  • {code('/encode b64 decode <input>')}")
    lines.append(f"  • {code('/encode hex decode <input>')}")
    lines.append(f"  • {code('/encode url decode <input>')}")

    return "\n".join(lines)


def _format_usage_help() -> str:
    """Format the usage help text for /encode."""
    lines = [
        f"{bold('🔤 Hash & Encode Tool')}",
        f"{'━' * 34}",
        "",
        f"{bold('Hash a string with all algorithms:')}",
        f"  {code('/encode <text>')}",
        "",
        f"{bold('Compute a specific hash:')}",
        f"  {code('/encode md5 <text>')}",
        f"  {code('/encode sha1 <text>')}",
        f"  {code('/encode sha256 <text>')}",
        f"  {code('/encode sha512 <text>')}",
        "",
        f"{bold('Encode / Decode:')}",
        f"  {code('/encode b64 <text>')}",
        f"  {code('/encode b64 decode <encoded_text>')}",
        f"  {code('/encode hex <text>')}",
        f"  {code('/encode hex decode <hex_string>')}",
        f"  {code('/encode url <text>')}",
        f"  {code('/encode url decode <url_encoded_text>')}",
        "",
        f"{bold('Identify a hash type:')}",
        f"  {code('/encode identify <hash_string>')}",
        "",
        f"⚠️ {italic('Supports: MD5, SHA-1, SHA-256, SHA-512, Base64, Hex, URL encoding.')}",
    ]
    return "\n".join(lines)


# ── Command Parser ───────────────────────────────────────────────────────────────

def _parse_encode_command(args: list[str] | None) -> tuple[str, str, str]:
    """
    Parse /encode command arguments.

    Formats:
        /encode <text>                    → ("all", text, "encode")
        /encode md5 <text>                → ("md5", text, "hash")
        /encode sha256 <text>             → ("sha256", text, "hash")
        /encode b64 <text>                → ("b64", text, "encode")
        /encode b64 decode <text>         → ("b64", text, "decode")
        /encode hex <text>                → ("hex", text, "encode")
        /encode hex decode <text>         → ("hex", text, "decode")
        /encode url <text>                → ("url", text, "encode")
        /encode url decode <text>         → ("url", text, "decode")
        /encode identify <hash>           → ("identify", hash, "")

    Returns:
        Tuple of (action, value, sub_action).
        action: one of 'all', 'md5', 'sha1', 'sha256', 'sha512', 'b64', 'hex', 'url', 'identify'
        value: the text to process
        sub_action: 'encode', 'decode', 'hash', or ''
    """
    if not args:
        return "help", "", ""

    first = args[0].lower()

    # Identify subcommand
    if first == "identify":
        value = " ".join(args[1:]).strip()
        if not value:
            return "identify_help", "", ""
        return "identify", value, ""

    # Decode subcommand: /encode b64|hex|url decode <text>
    if first in ("b64", "hex", "url") and len(args) >= 3 and args[1].lower() == "decode":
        value = " ".join(args[2:]).strip()
        if not value:
            return f"{first}_decode_help", "", ""
        return first, value, "decode"

    # Encode/hash subcommand: /encode md5|sha1|sha256|sha512|b64|hex|url <text>
    if first in HASH_ALGORITHMS:
        value = " ".join(args[1:]).strip()
        if not value:
            return "hash_help", first, "hash"
        return first, value, "hash"

    if first in ("b64", "hex", "url"):
        value = " ".join(args[1:]).strip()
        if not value:
            return f"{first}_help", "", ""
        return first, value, "encode"

    # Default: hash everything
    value = " ".join(args).strip()
    if not value:
        return "help", "", ""
    return "all", value, "encode"


# ── Keyboard Builders ────────────────────────────────────────────────────────────

def _build_hash_keyboard() -> InlineKeyboardMarkup:
    """Build the inline keyboard for hash tool options."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔐 MD5", callback_data="hash:action:md5"),
            InlineKeyboardButton("🔐 SHA-1", callback_data="hash:action:sha1"),
            InlineKeyboardButton("🟢 SHA-256", callback_data="hash:action:sha256"),
        ],
        [
            InlineKeyboardButton("🔵 SHA-512", callback_data="hash:action:sha512"),
        ],
        [
            InlineKeyboardButton("🔤 Base64 Enc", callback_data="hash:action:b64"),
            InlineKeyboardButton("🔤 Base64 Dec", callback_data="hash:action:b64_decode"),
            InlineKeyboardButton("🔤 Hex Enc", callback_data="hash:action:hex"),
        ],
        [
            InlineKeyboardButton("🔤 Hex Dec", callback_data="hash:action:hex_decode"),
            InlineKeyboardButton("🔗 URL Enc", callback_data="hash:action:url"),
            InlineKeyboardButton("🔗 URL Dec", callback_data="hash:action:url_decode"),
        ],
        [
            InlineKeyboardButton("🔍 Identify Hash", callback_data="hash:action:identify"),
        ],
        [
            InlineKeyboardButton("⬅️ Back to Menu", callback_data="menu:ctf"),
        ],
    ])


# ── Command Handler ──────────────────────────────────────────────────────────────

async def cmd_encode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /encode [algorithm] [decode] <text>.
    Compute hashes, encode/decode strings, or identify hash types.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    increment_usage(user_id)

    # Parse arguments
    action, value, sub_action = _parse_encode_command(context.args)

    # ── Help / no arguments ─────────────────────────────────────────────────
    if action == "help" or action == "hash_help" or action == "identify_help":
        text = _format_usage_help()
        keyboard = _build_hash_keyboard()
        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode", query="usage_help")
        return

    if action in ("b64_help", "hex_help"):
        algo_label = action.replace("_help", "").upper()
        text = (
            f"❌ {bold(f'Missing input text')}\n\n"
            f"Usage: {code(f'/encode {algo_label.lower()} <text>')}\n\n"
            f"Example: {code(f'/encode {algo_label.lower()} Hello World')}"
        )
        await update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        return

    if action in ("b64_decode_help", "hex_decode_help", "url_decode_help"):
        algo_label = action.replace("_decode_help", "").upper()
        text = (
            f"❌ {bold(f'Missing encoded text')}\n\n"
            f"Usage: {code(f'/encode {algo_label.lower()} decode <text>')}\n\n"
            f"Example: {code(f'/encode {algo_label.lower()} decode SGVsbG8=')}"
        )
        await update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        return

    # Sanitize input value
    value = sanitize_input(value, max_length=4096)

    # ── All hashes (no specific algorithm) ───────────────────────────────────
    if action == "all":
        hashes = _compute_all_hashes(value)
        text = _format_full_encode_table(value)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode_all", query=f"input_len={len(value)}")
        return

    # ── Single hash ──────────────────────────────────────────────────────────
    if action in HASH_ALGORITHMS and sub_action == "hash":
        digest = _compute_hash(value, action)
        text = _format_single_hash(action, value, digest)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, f"encode_{action}", query=f"input_len={len(value)}")
        return

    # ── Base64 encode ───────────────────────────────────────────────────────
    if action == "b64" and sub_action == "encode":
        encoded = _encode_base64(value)
        text = _format_encode_result("Encode", "Base64", value, encoded)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode_b64_enc", query=f"input_len={len(value)}")
        return

    # ── Base64 decode ───────────────────────────────────────────────────────
    if action == "b64" and sub_action == "decode":
        decoded = _decode_base64(value)
        if decoded is not None:
            text = _format_encode_result("Decode", "Base64", value, decoded)
        else:
            text = _format_decode_error("Base64", value)

        keyboard = _build_hash_keyboard()
        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(
            user_id,
            "encode_b64_dec",
            query=f"input_len={len(value)}",
            result="success" if decoded is not None else "failed",
        )
        return

    # ── Hex encode ──────────────────────────────────────────────────────────
    if action == "hex" and sub_action == "encode":
        encoded = _encode_hex(value)
        text = _format_encode_result("Encode", "Hex", value, encoded)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode_hex_enc", query=f"input_len={len(value)}")
        return

    # ── Hex decode ──────────────────────────────────────────────────────────
    if action == "hex" and sub_action == "decode":
        decoded = _decode_hex(value)
        if decoded is not None:
            text = _format_encode_result("Decode", "Hex", value, decoded)
        else:
            text = _format_decode_error("Hex", value)

        keyboard = _build_hash_keyboard()
        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(
            user_id,
            "encode_hex_dec",
            query=f"input_len={len(value)}",
            result="success" if decoded is not None else "failed",
        )
        return

    # ── URL encode ───────────────────────────────────────────────────────────
    if action == "url" and sub_action == "encode":
        encoded = _encode_url(value)
        text = _format_encode_result("Encode", "URL", value, encoded)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode_url_enc", query=f"input_len={len(value)}")
        return

    # ── URL decode ───────────────────────────────────────────────────────────
    if action == "url" and sub_action == "decode":
        decoded = _decode_url(value)
        text = _format_encode_result("Decode", "URL", value, decoded)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "encode_url_dec", query=f"input_len={len(value)}")
        return

    # ── Hash identification ──────────────────────────────────────────────────
    if action == "identify":
        candidates = _identify_hash_type(value)
        text = _format_identify_results(value, candidates)
        keyboard = _build_hash_keyboard()

        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(
            user_id,
            "encode_identify",
            query=f"input_len={len(value)}",
            result=f"{len(candidates)} candidates",
        )
        return

    # ── Fallback ─────────────────────────────────────────────────────────────
    text = _format_usage_help()
    keyboard = _build_hash_keyboard()
    await update.message.reply_text(
        text=text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
    )


# ── Callback Handler ─────────────────────────────────────────────────────────────

async def handle_hash_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle inline keyboard callbacks from the hash tool.
    Callback data format: hash:action:<action>
    """
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id

    if not check_rate_limit(user_id):
        await query.answer("⏳ Rate limit exceeded. Please wait.", show_alert=True)
        return

    parts = query.data.split(":")
    if len(parts) < 3 or parts[0] != "hash":
        return

    action = parts[2]

    # Build a hint response showing how to use the selected feature
    hints = {
        "md5": (
            f"{bold('🔐 MD5 Hash')}\n\n"
            f"Compute an MD5 hash:\n"
            f"  {code('/encode md5 <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode md5 hello')}\n"
            f"  → 5d41402abc4b2a76b9719d911017c592"
        ),
        "sha1": (
            f"{bold('🔐 SHA-1 Hash')}\n\n"
            f"Compute a SHA-1 hash:\n"
            f"  {code('/encode sha1 <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode sha1 hello')}\n"
            f"  → aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        ),
        "sha256": (
            f"{bold('🟢 SHA-256 Hash')}\n\n"
            f"Compute a SHA-256 hash:\n"
            f"  {code('/encode sha256 <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode sha256 hello')}\n"
            f"  → 2cf24dba5fb0a30e…"
        ),
        "sha512": (
            f"{bold('🔵 SHA-512 Hash')}\n\n"
            f"Compute a SHA-512 hash:\n"
            f"  {code('/encode sha512 <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode sha512 hello')}"
        ),
        "b64": (
            f"{bold('🔤 Base64 Encode')}\n\n"
            f"Encode text to Base64:\n"
            f"  {code('/encode b64 <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode b64 Hello World')}\n"
            f"  → SGVsbG8gV29ybGQ="
        ),
        "b64_decode": (
            f"{bold('🔤 Base64 Decode')}\n\n"
            f"Decode Base64 text:\n"
            f"  {code('/encode b64 decode <encoded>')}\n\n"
            f"Example:\n"
            f"  {code('/encode b64 decode SGVsbG8=')}\n"
            f"  → Hello"
        ),
        "hex": (
            f"{bold('🔤 Hex Encode')}\n\n"
            f"Encode text to hexadecimal:\n"
            f"  {code('/encode hex <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode hex hello')}\n"
            f"  → 68656c6c6f"
        ),
        "hex_decode": (
            f"{bold('🔤 Hex Decode')}\n\n"
            f"Decode hexadecimal:\n"
            f"  {code('/encode hex decode <hex>')}\n\n"
            f"Example:\n"
            f"  {code('/encode hex decode 68656c6c6f')}\n"
            f"  → hello"
        ),
        "url": (
            f"{bold('🔗 URL Encode')}\n\n"
            f"URL-encode text:\n"
            f"  {code('/encode url <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode url hello world')}\n"
            f"  → hello%20world"
        ),
        "url_decode": (
            f"{bold('🔗 URL Decode')}\n\n"
            f"Decode URL-encoded text:\n"
            f"  {code('/encode url decode <text>')}\n\n"
            f"Example:\n"
            f"  {code('/encode url decode hello%20world')}\n"
            f"  → hello world"
        ),
        "identify": (
            f"{bold('🔍 Hash Identification')}\n\n"
            f"Identify an unknown hash type:\n"
            f"  {code('/encode identify <hash>')}\n\n"
            f"Supports identification of:\n"
            f"  • MD5 (32 hex chars)\n"
            f"  • SHA-1 (40 hex chars)\n"
            f"  • SHA-256 (64 hex chars)\n"
            f"  • SHA-512 (128 hex chars)\n"
            f"  • Base64 encoded strings\n"
            f"  • URL-encoded strings\n"
            f"  • Numeric hashes\n"
        ),
    }

    text = hints.get(action, _format_usage_help())
    keyboard = _build_hash_keyboard()

    increment_usage(user_id)
    log_query(user_id, "encode_callback", query=action)

    try:
        await query.edit_message_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.warning("Failed to update hash callback message: %s", exc)
