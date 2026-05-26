"""
Password Generator Handler
Cryptographically secure password generation with multiple modes:
Random, XKCD, Passphrase, PIN, and Hex.

IMPORTANT: Generated passwords are NEVER logged to the database.
"""

import math
import secrets

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

DEFAULT_LENGTH = 16
MIN_LENGTH = 4
MAX_LENGTH = 128

CHARSET_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHARSET_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
CHARSET_DIGITS = "0123456789"
CHARSET_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
CHARSET_HEX = "0123456789abcdef"

# XKCD common-word list (100 words) — used for memorable passwords
XKCD_WORDLIST = [
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "garden", "harbor",
    "island", "jungle", "knight", "lantern", "marble", "nebula", "orange", "phoenix",
    "quartz", "raven", "silver", "thunder", "umbrella", "velvet", "walnut", "xenon",
    "yellow", "zeppelin", "anchor", "bridge", "castle", "desert", "ember", "frozen",
    "galaxy", "hazard", "ivory", "jigsaw", "karma", "lemon", "mystic", "noble",
    "ocean", "pirate", "quest", "rocket", "shadow", "titan", "unique", "voyage",
    "wonder", "crystal", "dawn", "echo", "flame", "ghost", "horizon", "infinity",
    "jade", "kinetic", "legend", "magnet", "neutron", "omega", "prism", "quantum",
    "ripple", "stellar", "twilight", "utopia", "vertex", "whisper", "zenith",
    "alpha", "breeze", "coral", "drift", "frost", "griffin", "halo", "jolt",
    "keynote", "lunar", "matrix", "neon", "orbit", "pulse", "rust", "solar",
    "trident", "ultra", "viper", "wave", "axiom", "blaze", "cipher", "delta",
]

PASSPHRASE_SEPARATORS = ["-", "_", ".", "~", "/"]


# ── Entropy Calculation ──────────────────────────────────────────────────────────

def _calculate_entropy(pool_size: int, length: int) -> float:
    """
    Calculate entropy in bits: log2(pool_size^length).

    Args:
        pool_size: Number of possible characters / words.
        length: Length of the password / passphrase.

    Returns:
        Entropy in bits (float).
    """
    if pool_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)


def _entropy_strength(entropy_bits: float) -> tuple[str, str]:
    """
    Classify password strength based on entropy.

    Returns:
        Tuple of (label, emoji).
    """
    if entropy_bits < 28:
        return "Very Weak", "🔴"
    elif entropy_bits < 36:
        return "Weak", "🟠"
    elif entropy_bits < 60:
        return "Moderate", "🟡"
    elif entropy_bits < 80:
        return "Strong", "🟢"
    elif entropy_bits < 100:
        return "Very Strong", "🔵"
    else:
        return "Excellent", "💜"


# ── Password Generators ──────────────────────────────────────────────────────────

def _generate_random(length: int) -> tuple[str, str, float]:
    """
    Generate a random password mixing uppercase, lowercase, digits, and symbols.
    Guarantees at least one character from each category.

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    if length < 4:
        length = 4

    # Ensure at least one of each category
    password_chars = [
        secrets.choice(CHARSET_UPPERCASE),
        secrets.choice(CHARSET_LOWERCASE),
        secrets.choice(CHARSET_DIGITS),
        secrets.choice(CHARSET_SYMBOLS),
    ]

    full_charset = CHARSET_UPPERCASE + CHARSET_LOWERCASE + CHARSET_DIGITS + CHARSET_SYMBOLS

    for _ in range(length - 4):
        password_chars.append(secrets.choice(full_charset))

    # Shuffle to randomize positions of guaranteed characters
    secrets.SystemRandom().shuffle(password_chars)
    password = "".join(password_chars)

    pool_size = len(full_charset)
    entropy = _calculate_entropy(pool_size, length)

    return password, f"Random ({length} chars, {pool_size}-char pool)", entropy


def _generate_xkcd(word_count: int | None = None) -> tuple[str, str, float]:
    """
    Generate an XKCD-style password: 4-6 random common words separated by spaces.

    Args:
        word_count: Number of words (default: 4, range: 4-6).

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    if word_count is None:
        word_count = secrets.choice([4, 5, 6])
    word_count = max(4, min(6, word_count))

    words = [secrets.choice(XKCD_WORDLIST) for _ in range(word_count)]
    password = " ".join(words)

    entropy = _calculate_entropy(len(XKCD_WORDLIST), word_count)
    description = f"XKCD ({word_count} words from {len(XKCD_WORDLIST)}-word list)"

    return password, description, entropy


def _generate_passphrase(word_count: int | None = None) -> tuple[str, str, float]:
    """
    Generate a passphrase similar to XKCD but with random separators.

    Args:
        word_count: Number of words (default: 4, range: 4-6).

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    if word_count is None:
        word_count = secrets.choice([4, 5, 6])
    word_count = max(4, min(6, word_count))

    words = [secrets.choice(XKCD_WORDLIST) for _ in range(word_count)]
    separator = secrets.choice(PASSPHRASE_SEPARATORS)
    password = separator.join(words)

    entropy = _calculate_entropy(len(XKCD_WORDLIST), word_count)
    description = f"Passphrase ({word_count} words, sep: '{separator}')"

    return password, description, entropy


def _generate_pin(length: int) -> tuple[str, str, float]:
    """
    Generate a numeric-only PIN.

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    if length < 4:
        length = 4

    password = "".join(secrets.choice(CHARSET_DIGITS) for _ in range(length))
    entropy = _calculate_entropy(len(CHARSET_DIGITS), length)
    description = f"PIN ({length} digits)"

    return password, description, entropy


def _generate_hex(length: int) -> tuple[str, str, float]:
    """
    Generate a hexadecimal string.

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    if length < 4:
        length = 4

    password = "".join(secrets.choice(CHARSET_HEX) for _ in range(length))
    entropy = _calculate_entropy(len(CHARSET_HEX), length)
    description = f"Hex ({length} chars)"

    return password, description, entropy


# ── Mode Router ──────────────────────────────────────────────────────────────────

def _generate_password(mode: str, length: int = DEFAULT_LENGTH) -> tuple[str, str, float]:
    """
    Route to the appropriate generator based on mode.

    Args:
        mode: One of 'random', 'xkcd', 'passphrase', 'pin', 'hex'.
        length: Desired length (applies to random/pin/hex modes).

    Returns:
        Tuple of (password, description, entropy_bits).
    """
    generators = {
        "random": lambda: _generate_random(length),
        "xkcd": lambda: _generate_xkcd(),
        "passphrase": lambda: _generate_passphrase(),
        "pin": lambda: _generate_pin(length),
        "hex": lambda: _generate_hex(length),
    }
    gen = generators.get(mode, generators["random"])
    return gen()


# ── Keyboard Builders ────────────────────────────────────────────────────────────

def _build_password_keyboard(mode: str, length: int) -> InlineKeyboardMarkup:
    """Build the inline keyboard for password generation options."""
    mode_labels = {
        "random": "🎲 Random",
        "xkcd": "📖 XKCD",
        "passphrase": "🔐 Passphrase",
        "pin": "🔢 PIN",
        "hex": "🔤 Hex",
    }

    # Mode buttons — highlight current mode
    mode_buttons = []
    row = []
    for m in ["random", "xkcd", "passphrase", "pin", "hex"]:
        prefix = "✅ " if m == mode else ""
        row.append(InlineKeyboardButton(
            f"{prefix}{mode_labels[m]}",
            callback_data=f"pw:mode:{m}:{length}",
        ))
        if len(row) == 3:
            mode_buttons.append(row)
            row = []
    if row:
        mode_buttons.append(row)

    # Length adjustment buttons
    length_buttons = [
        InlineKeyboardButton("➖ 4", callback_data=f"pw:len:{mode}:{max(MIN_LENGTH, length - 4)}"),
        InlineKeyboardButton(
            f"📏 Length: {length}",
            callback_data=f"pw:nop",  # no-op, just display
        ),
        InlineKeyboardButton("➕ 4", callback_data=f"pw:len:{mode}:{min(MAX_LENGTH, length + 4)}"),
    ]

    quick_lengths = [
        InlineKeyboardButton("8", callback_data=f"pw:len:{mode}:8"),
        InlineKeyboardButton("16", callback_data=f"pw:len:{mode}:16"),
        InlineKeyboardButton("24", callback_data=f"pw:len:{mode}:24"),
        InlineKeyboardButton("32", callback_data=f"pw:len:{mode}:32"),
        InlineKeyboardButton("64", callback_data=f"pw:len:{mode}:64"),
    ]

    # Regenerate button
    regen_button = [
        InlineKeyboardButton("🔄 Regenerate", callback_data=f"pw:regen:{mode}:{length}"),
    ]

    # Back button
    back_button = [
        InlineKeyboardButton("⬅️ Back to Menu", callback_data="menu:ctf"),
    ]

    return InlineKeyboardMarkup([
        *mode_buttons,
        length_buttons,
        quick_lengths,
        regen_button,
        back_button,
    ])


def _build_initial_keyboard(length: int) -> InlineKeyboardMarkup:
    """Build the initial keyboard when /password is called without specifying a mode."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🎲 Random", callback_data=f"pw:mode:random:{length}"),
            InlineKeyboardButton("📖 XKCD", callback_data=f"pw:mode:xkcd:{length}"),
            InlineKeyboardButton("🔐 Passphrase", callback_data=f"pw:mode:passphrase:{length}"),
        ],
        [
            InlineKeyboardButton("🔢 PIN", callback_data=f"pw:mode:pin:{length}"),
            InlineKeyboardButton("🔤 Hex", callback_data=f"pw:mode:hex:{length}"),
        ],
        [
            InlineKeyboardButton("⬅️ Back to Menu", callback_data="menu:ctf"),
        ],
    ])


# ── Response Formatters ──────────────────────────────────────────────────────────

def _format_password_response(password: str, description: str, entropy: float) -> str:
    """
    Format the password response message.

    IMPORTANT: The password itself is only shown to the user and is NEVER logged.
    """
    strength_label, strength_emoji = _entropy_strength(entropy)
    entropy_display = f"{entropy:.1f}"

    # Estimate crack time (assuming 10 billion guesses/sec)
    combinations = 2 ** entropy
    seconds_to_crack = combinations / 10_000_000_000
    crack_time = _format_crack_time(seconds_to_crack)

    text = (
        f"{bold('🔑 Generated Password')}\n"
        f"{'━' * 30}\n\n"
        f"{code(escape_html(password))}\n\n"
        f"{bold('📊 Statistics')}\n"
        f"  📐 Type: {escape_html(description)}\n"
        f"  📏 Length: {bold(str(len(password)))} characters\n"
        f"  🔢 Entropy: {bold(f'{entropy_display} bits')}\n"
        f"  {strength_emoji} Strength: {bold(strength_label)}\n"
        f"  ⏱️ Est. crack time: {bold(escape_html(crack_time))}\n\n"
        f"💡 {italic('Tap the password above to copy it.')}\n"
        f"⚠️ {italic('This password was generated client-side and is NOT logged.')}"
    )
    return text


def _format_crack_time(seconds: float) -> str:
    """Convert seconds to a human-readable crack-time estimate."""
    if seconds < 0.001:
        return "Instant"
    elif seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 86400 * 365:
        return f"{seconds / 86400:.0f} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.0f} years"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{seconds / (86400 * 365 * 1000):.0f} thousand years"
    elif seconds < 86400 * 365 * 1_000_000_000:
        return f"{seconds / (86400 * 365 * 1_000_000):.0f} million years"
    elif seconds < 86400 * 365 * 1_000_000_000_000:
        return f"{seconds / (86400 * 365 * 1_000_000_000):.0f} billion years"
    else:
        return "∞ (practically uncrackable)"


# ── Command Handler ──────────────────────────────────────────────────────────────

async def cmd_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /password [length].
    Shows the initial mode-selection keyboard, or generates with a default mode
    if a length is provided.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    # Check feature flag
    if not config.ENABLE_PASSWORD_GEN:
        await update.message.reply_text(
            f"🔒 {bold('Feature Disabled')}\n\n"
            "The password generator is currently disabled by the administrator.",
            parse_mode=ParseMode.HTML,
        )
        return

    increment_usage(user_id)
    # NOTE: We intentionally do NOT pass the password to log_query

    # Parse optional length argument
    length = DEFAULT_LENGTH
    if context.args:
        try:
            parsed = int(sanitize_input(context.args[0], max_length=3))
            length = max(MIN_LENGTH, min(MAX_LENGTH, parsed))
        except (ValueError, TypeError):
            pass

    # Show mode selection keyboard
    help_text = (
        f"{bold('🔑 Password Generator')}\n"
        f"{'━' * 30}\n\n"
        f"Select a password mode below:\n\n"
        f"  🎲 {bold('Random')} — Mixed characters (default {length} chars)\n"
        f"  📖 {bold('XKCD')} — 4-6 common words (like correct horse battery staple)\n"
        f"  🔐 {bold('Passphrase')} — Words with separators\n"
        f"  🔢 {bold('PIN')} — Numeric only\n"
        f"  🔤 {bold('Hex')} — Hexadecimal\n\n"
        f"⚠️ {italic('Passwords are generated with cryptographic randomness and are NEVER stored or logged.')}"
    )

    keyboard = _build_initial_keyboard(length)

    await update.message.reply_text(
        text=help_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
    )

    # Log the command but NOT any generated password
    log_query(user_id, "password", query=f"mode_select,length={length}")


# ── Callback Handler ─────────────────────────────────────────────────────────────

async def handle_password_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle inline keyboard callbacks from the password generator.
    Callback data format: pw:<action>:<mode>:<length>
    """
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id

    if not check_rate_limit(user_id):
        await query.answer("⏳ Rate limit exceeded. Please wait.", show_alert=True)
        return

    parts = query.data.split(":")
    if len(parts) < 2 or parts[0] != "pw":
        return

    action = parts[1]

    # No-op button (length display)
    if action == "nop":
        return

    # Parse mode and length from callback data
    mode = parts[2] if len(parts) > 2 else "random"
    length = DEFAULT_LENGTH

    try:
        length = int(parts[3]) if len(parts) > 3 else DEFAULT_LENGTH
        length = max(MIN_LENGTH, min(MAX_LENGTH, length))
    except (ValueError, IndexError):
        length = DEFAULT_LENGTH

    # Validate mode
    valid_modes = {"random", "xkcd", "passphrase", "pin", "hex"}
    if mode not in valid_modes:
        mode = "random"

    # Handle different actions
    if action == "mode":
        # User selected a mode — generate password
        pass
    elif action == "regen":
        # Regenerate with same mode and length
        pass
    elif action == "len":
        # User changed length — regenerate with same mode
        pass
    else:
        return

    # Generate the password
    password, description, entropy = _generate_password(mode, length)

    # Build response
    text = _format_password_response(password, description, entropy)
    keyboard = _build_password_keyboard(mode, length)

    increment_usage(user_id)

    # Log the event WITHOUT the password
    log_query(
        user_id,
        "password_generate",
        query=f"mode={mode},length={length},entropy={entropy:.1f}",
    )
    # IMPORTANT: password is intentionally NOT logged

    try:
        await query.edit_message_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        # If message content didn't change, just update the keyboard
        try:
            await query.edit_message_reply_markup(reply_markup=keyboard)
        except Exception as exc:
            logger.warning("Failed to update password message: %s", exc)
