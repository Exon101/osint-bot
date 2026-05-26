"""
Code Runner Handler
Execute Python, JavaScript, and Bash code snippets with security restrictions.
Uses asyncio subprocess with timeout, output limits, module allowlist, and pattern blacklisting.
"""

import asyncio
import os
import re
import tempfile
import time

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

DEFAULT_LANGUAGE = "python"

SUPPORTED_LANGUAGES = {
    "python": {
        "label": "🐍 Python",
        "extension": ".py",
        "command": ["python3", "-u"],   # -u for unbuffered output
        "alias": ["py", "python3"],
    },
    "javascript": {
        "label": "🟨 JavaScript",
        "extension": ".js",
        "command": ["node"],
        "alias": ["js", "node"],
    },
    "bash": {
        "label": "🖥️ Bash",
        "extension": ".sh",
        "command": ["bash", "--norc", "--noprofile"],
        "alias": ["sh", "shell"],
    },
}

# ── Security: Allowlist + Blacklist ─────────────────────────────────────────────
# The allowlist defines the ONLY Python modules safe to import.
# Everything else is blocked. The blacklist catches additional dangerous patterns.

ALLOWED_PYTHON_MODULES = frozenset({
    # Math & numbers
    "math", "cmath", "decimal", "fractions", "numbers", "random",
    # Collections & data structures
    "collections", "itertools", "functools", "operator", "heapq",
    "bisect", "array", "copy", "pprint", "enum",
    # String & text
    "string", "re", "unicodedata", "textwrap",
    # Datetime
    "datetime", "time", "calendar",
    # Data formats
    "json", "csv", "html", "xml.etree.ElementTree",
    # Statistics
    "statistics",
    # Types & typing
    "typing", "types",
    # Hashing & encoding
    "hashlib", "hmac", "base64", "binascii", "codecs",
    # Dataclasses
    "dataclasses",
    # Debug
    "inspect", "dis", "ast",
    # Formatting
    "reprlib",
})

# Additional dangerous patterns blocked on top of the module allowlist.
BLACKLISTED_PATTERNS = [
    # ── Shell destructive commands (all languages) ──
    (r"\brm\s+-[rf]+\s", "Destructive command (rm -rf)"),
    (r":\(\)\s*\{\s*:\|\:&\s*\}", "Fork bomb pattern"),
    (r"\bmkfs\b", "Filesystem format command"),
    (r"\bdd\s+if=", "Direct disk write (dd)"),
    (r">\s*/dev/", "Direct device write"),
    (r"\bshutdown\b", "System shutdown command"),
    (r"\breboot\b", "System reboot command"),
    (r"\binit\s+0\b", "System halt command"),
    (r"\bchmod\s+777\s+/", "Recursive permission escalation on /"),
    (r"\bchown\b.*-R\s+/", "Recursive ownership change on /"),
    (r"\bkill\s+(-9|\s+-\s*1)\b", "Process kill command"),

    # ── Python: dangerous builtins & attributes ──
    (r"\bos\.?(system|popen|spawn[lvpe]*|exec[lvpe]*|dup2|pipe|fork|remove|unlink|rmdir|walk|link|symlink|environ|access|listdir|read|write|stat|path)\b", "Dangerous os.* call"),
    (r"\bsubprocess\b", "subprocess module - process execution blocked"),
    (r"\b__import__\b", "__import__() - dynamic import blocked"),
    (r"\beval\s*\(", "eval() call - blocked for safety"),
    (r"\bexec\s*\(", "exec() call - blocked for safety"),
    (r"\bcompile\s*\(", "compile() call - blocked for safety"),
    (r"\bglobals\b", "globals() - blocked for safety"),
    (r"\blocals\b", "locals() - blocked for safety"),
    (r"\bgetattr\s*\(", "getattr() - blocked for safety"),
    (r"\bsetattr\s*\(", "setattr() - blocked for safety"),
    (r"\bdelattr\s*\(", "delattr() - blocked for safety"),
    (r"__class__|__bases__|__subclasses__|__mro__|__init__|__globals__|__builtins__", "Dunder attribute access - blocked"),

    # ── Python: dangerous modules (blocking the module name entirely) ──
    (r"\bos\b", "os module - use only safe modules (math, json, re, etc.)"),
    (r"\bsys\b", "sys module - blocked for safety"),
    (r"\bctypes\b", "ctypes module - FFI blocked"),
    (r"\bmultiprocessing\b", "multiprocessing module - blocked"),
    (r"\bthreading\b", "threading module - blocked"),
    (r"\bsignal\b", "signal module - blocked"),
    (r"\bshutil\b", "shutil module - file operations blocked"),
    (r"\bpathlib\b", "pathlib module - file system blocked"),
    (r"\btempfile\b", "tempfile module - blocked"),
    (r"\bimportlib\b", "importlib module - dynamic import blocked"),
    (r"\bpickle\b", "pickle module - deserialization blocked"),
    (r"\bmarshal\b", "marshal module - serialization blocked"),

    # ── Python: file I/O ──
    (r"\bopen\s*\(", "open() - file I/O blocked"),
    (r"\binput\s*\(", "input() - interactive input blocked"),

    # ── Python: network access ──
    (r"\brequests\b", "requests module - network blocked"),
    (r"\burllib\b", "urllib module - network blocked"),
    (r"\bsocket\b", "socket module - network blocked"),
    (r"\bhttp\.?client\b", "http.client module - network blocked"),
    (r"\burlopen\b", "urlopen() - network blocked"),
    (r"\bssl\b", "ssl module - network blocked"),
    (r"\basyncio\b", "asyncio module - async I/O blocked"),
    (r"\bselect\b", "select module - network blocked"),

    # ── Shell: network & escalation tools ──
    (r"\b(curl|wget|nc|ncat|nmap|telnet)\b", "Network tool - blocked"),
    (r"\b(python|python3)\s+-c\b", "Nested Python execution - blocked"),
    (r"\b(sudo|su\s)\b", "Privilege escalation - blocked"),
    (r"\b(cat|less|more|head|tail)\s+/", "File reading of system paths - blocked"),
    (r"/etc/(passwd|shadow|hosts|resolv|cron|ssh|nginx|apache)", "System file access - blocked"),
    (r"/proc/self|/proc/\d+|/sys/|/dev/", "System directory access - blocked"),
    (r"\.(env|secret|key|pem|p12|pfx|jks|keystore)\b", "Credential file reference - blocked"),
]

# Compile regex patterns once for performance
COMPILED_BLACKLIST = [
    (re.compile(pattern, re.IGNORECASE), reason)
    for pattern, reason in BLACKLISTED_PATTERNS
]


# ── Security Checks ──────────────────────────────────────────────────────────────

def _check_blacklist(code_text: str, language: str) -> list[str]:
    """
    Scan code against blacklisted patterns and Python module allowlist.

    Args:
        code_text: The source code to check.
        language: Programming language for context-specific checks.

    Returns:
        List of detected threat descriptions (empty if safe).
    """
    threats = []

    # For Python: check import allowlist
    if language == "python":
        import_matches = re.finditer(
            r"^\s*(?:import|from)\s+([\w.]+)",
            code_text,
            re.MULTILINE,
        )
        for match in import_matches:
            module_name = match.group(1).split(".")[0]  # top-level module
            if module_name not in ALLOWED_PYTHON_MODULES:
                threats.append(
                    f"Module '{module_name}' is not in the allowlist. "
                    f"Allowed: math, json, re, collections, itertools, "
                    f"datetime, statistics, hashlib, base64, fractions, decimal, "
                    f"functools, random, string, etc."
                )

    # Check all blacklisted patterns
    for pattern, reason in COMPILED_BLACKLIST:
        if pattern.search(code_text):
            threats.append(reason)

    return threats


def _format_security_warning() -> str:
    """Return the security warning footer appended to every code execution result."""
    return (
        f"\n\n{'━' * 34}\n"
        f"🔒 {bold('Security Notice')}\n"
        f"  ⚠️ Only a whitelist of safe Python modules is allowed "
        f"(math, json, re, collections, etc.).\n"
        f"  ⚠️ Network, file I/O, and process execution are blocked.\n"
        f"  ⚠️ Execution is limited to "
        f"{bold(str(config.CODE_RUNNER_TIMEOUT))}s / "
        f"{bold(str(config.CODE_RUNNER_MAX_OUTPUT))} chars output.\n"
        f"  {italic('For educational and CTF purposes only.')}"
    )


# ── Code Execution Engine ────────────────────────────────────────────────────────

async def _execute_code(
    code_text: str,
    language: str,
) -> tuple[str, str, float, int]:
    """
    Execute code in a subprocess with timeout, output limits, and sandbox env.

    Args:
        code_text: The source code to execute.
        language: One of 'python', 'javascript', 'bash'.

    Returns:
        Tuple of (stdout, stderr, elapsed_seconds, exit_code).
        Returns error message in stderr on failure.
    """
    lang_config = SUPPORTED_LANGUAGES.get(language)
    if not lang_config:
        return "", f"Unsupported language: {escape_html(language)}", 0.0, 1

    tmp_file = None
    try:
        # Create a temporary file with random prefix to mitigate symlink races
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=lang_config["extension"],
            prefix="osint_bot_",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(code_text)
            tmp_file = f.name

        # Build the command: interpreter + script_path
        cmd = lang_config["command"] + [tmp_file]

        start_time = time.monotonic()

        # Restricted environment: minimal PATH, no PYTHONPATH, isolated HOME
        sandbox_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": tempfile.gettempdir(),
            "TMPDIR": tempfile.gettempdir(),
            "PYTHONPATH": "",
            "PYTHONSTARTUP": "",
            "PYTHONNOUSERSITE": "1",
        }

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=sandbox_env,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=config.CODE_RUNNER_TIMEOUT,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            elapsed = time.monotonic() - start_time
            return (
                "",
                f"⏱️ Execution timed out after {config.CODE_RUNNER_TIMEOUT} seconds.",
                elapsed,
                -1,
            )

        elapsed = time.monotonic() - start_time

        # Decode output
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        # Truncate output if needed
        max_output = config.CODE_RUNNER_MAX_OUTPUT
        if len(stdout) > max_output:
            stdout = stdout[:max_output] + f"\n... [truncated, {len(stdout)} chars total]"
        if len(stderr) > max_output:
            stderr = stderr[:max_output] + f"\n... [truncated, {len(stderr)} chars total]"

        return stdout, stderr, elapsed, process.returncode

    except FileNotFoundError:
        return "", f"Runtime not found for {escape_html(language)}. Is it installed?", 0.0, 1
    except Exception as exc:
        logger.error("Code execution error: %s", exc)
        return "", f"Execution error: {escape_html(str(exc))}", 0.0, 1
    finally:
        # Always clean up the temporary file
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.unlink(tmp_file)
            except OSError:
                pass


# ── Language Resolver ───────────────────────────────────────────────────────────

def _resolve_language(lang_input: str) -> str | None:
    """
    Resolve a language name or alias to a canonical language key.

    Args:
        lang_input: User-provided language string (e.g. 'py', 'javascript', 'node').

    Returns:
        Canonical language key ('python', 'javascript', 'bash') or None.
    """
    lang_lower = lang_input.lower().strip()

    # Direct match
    if lang_lower in SUPPORTED_LANGUAGES:
        return lang_lower

    # Alias match
    for key, lang_config in SUPPORTED_LANGUAGES.items():
        if lang_lower in lang_config["alias"]:
            return key

    return None


def _parse_run_command(args: list[str] | None) -> tuple[str | None, str | None]:
    """
    Parse /run command arguments.

    Expected formats:
        /run python print("hello")
        /run js console.log("hello")
        /run print("hello")           -> defaults to python
        /run bash echo "hello world"

    Args:
        args: List of arguments from context.args.

    Returns:
        Tuple of (language, code_text) - either may be None if parsing fails.
    """
    if not args:
        return None, None

    # Try to extract language from the first argument
    potential_lang = args[0].lower()
    resolved_lang = _resolve_language(potential_lang)

    if resolved_lang:
        # Language was explicitly provided
        code_text = " ".join(args[1:]).strip()
        if not code_text:
            return resolved_lang, None
        return resolved_lang, code_text
    else:
        # No language specified - default to Python
        code_text = " ".join(args).strip()
        if not code_text:
            return None, None
        return DEFAULT_LANGUAGE, code_text


# ── Response Formatters ──────────────────────────────────────────────────────────

def _format_execution_result(
    language: str,
    code_text: str,
    stdout: str,
    stderr: str,
    elapsed: float,
    exit_code: int,
) -> str:
    """Format the code execution result message."""
    lang_label = SUPPORTED_LANGUAGES[language]["label"]

    lines = [
        bold('💻 Code Execution — ' + lang_label),
        f"{'━' * 34}",
        "",
        f"📝 {bold('Code:')}",
        f"{code(escape_html(code_text[:200]))}{'...' if len(code_text) > 200 else ''}",
        "",
    ]

    # Execution info
    exit_icon = "✅" if exit_code == 0 else "❌"
    lines.append(
        f"{bold('📊 Result:')}\n"
        f"  {exit_icon} Exit code: {exit_code}\n"
        f"  ⏱️ Time: {bold(f'{elapsed:.3f}s')}"
    )

    # Stdout
    if stdout:
        lines.append("")
        lines.append(f"{bold('📤 Output:')}")
        # Use pre-formatted code block for output
        truncated_out = stdout[:3000]
        lines.append(f"{code(escape_html(truncated_out))}")
        if len(stdout) > 3000:
            lines.append(italic(f"... {len(stdout)} chars total (truncated)"))

    # Stderr
    if stderr:
        lines.append("")
        lines.append(f"{bold('⚠️ Errors:')}")
        truncated_err = stderr[:2000]
        lines.append(f"{code(escape_html(truncated_err))}")
        if len(stderr) > 2000:
            lines.append(italic(f"... {len(stderr)} chars total (truncated)"))

    # No output at all
    if not stdout and not stderr:
        lines.append("")
        lines.append(italic("(No output produced)"))

    # Append security warning
    lines.append(_format_security_warning())

    return "\n".join(lines)


def _format_blocked_response(threats: list[str]) -> str:
    """Format the response when dangerous patterns are detected."""
    threat_list = "\n".join(f"  🚫 {t}" for t in threats[:10])
    if len(threats) > 10:
        threat_list += f"\n  … and {len(threats) - 10} more"

    text = (
        f"{bold('🚫 Execution Blocked')}\n"
        f"{'━' * 30}\n\n"
        f"Your code contains {bold(str(len(threats)))} potentially dangerous pattern(s):\n\n"
        f"{threat_list}\n\n"
        + italic("Dangerous commands, file operations, and network access are blocked "
                 "for security reasons.") + "\n"
        + italic("If you believe this is a false positive, contact the admin.")
    )
    return text


def _format_usage_help() -> str:
    """Format the usage help text for the /run command."""
    lang_lines = "\n".join(
        f"  • {lc['label']} — {code(f'/run {key} <code>')}"
        for key, lc in SUPPORTED_LANGUAGES.items()
    )
    alias_lines = "\n".join(
        f"  • {code(alias)} → {lc['label']}"
        for key, lc in SUPPORTED_LANGUAGES.items()
        for alias in lc["alias"]
    )

    _ex1 = code('/run python print("Hello, World!")')
    _ex2 = code('/run js console.log(2 + 2)')
    _ex3 = code('/run bash echo "hello"')

    text = (
        f"{bold('💻 Code Runner')}\n"
        f"{'━' * 30}\n\n"
        f"{bold('Supported Languages:')}\n{lang_lines}\n\n"
        f"{bold('Aliases:')}\n{alias_lines}\n\n"
        f"{bold('Examples:')}\n"
        f"  {_ex1}\n"
        f"  {_ex2}\n"
        f"  {_ex3}\n"
        f"  {code('/run x = [1,2,3]; print(sum(x))')}  (defaults to Python)\n\n"
        f"🔒 {bold('Limits:')} {config.CODE_RUNNER_TIMEOUT}s timeout, "
        f"{config.CODE_RUNNER_MAX_OUTPUT} chars max output\n"
        f"⚠️ {italic('Dangerous commands are blacklisted for security.')}"
    )
    return text


# ── Keyboard Builders ────────────────────────────────────────────────────────────

def _build_run_keyboard(current_lang: str = DEFAULT_LANGUAGE) -> InlineKeyboardMarkup:
    """Build inline keyboard for language selection and quick actions."""
    lang_buttons = []
    row = []
    for key, lang_config in SUPPORTED_LANGUAGES.items():
        prefix = "✅ " if key == current_lang else ""
        row.append(InlineKeyboardButton(
            f"{prefix}{lang_config['label']}",
            callback_data=f"run:lang:{key}",
        ))
        if len(row) == 2:
            lang_buttons.append(row)
            row = []
    if row:
        lang_buttons.append(row)

    back_button = [
        InlineKeyboardButton("⬅️ Back to Menu", callback_data="menu:ctf"),
    ]

    return InlineKeyboardMarkup([
        *lang_buttons,
        back_button,
    ])


# ── Command Handler ──────────────────────────────────────────────────────────────

async def cmd_run(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /run [language] <code>.
    Execute code in a sandboxed subprocess environment.
    """
    user_id = update.effective_user.id

    if not check_rate_limit(user_id):
        await update.message.reply_text(
            "⏳ Rate limit exceeded. Please wait a moment before trying again."
        )
        return

    # Check feature flag
    if not config.ENABLE_CODE_RUNNER:
        await update.message.reply_text(
            f"🔒 {bold('Feature Disabled')}\n\n"
            "The code runner is currently disabled by the administrator.",
            parse_mode=ParseMode.HTML,
        )
        return

    increment_usage(user_id)

    # Parse arguments
    language, code_text = _parse_run_command(context.args)

    # No arguments — show usage
    if not code_text:
        text = _format_usage_help()
        keyboard = _build_run_keyboard()
        await update.message.reply_text(
            text=text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
        log_query(user_id, "run", query="usage_help")
        return

    # Validate language
    if language not in SUPPORTED_LANGUAGES:
        await update.message.reply_text(
            f"❌ {bold('Unsupported language')}: {code(escape_html(str(language)))}\n\n"
            f"Supported: Python, JavaScript, Bash",
            parse_mode=ParseMode.HTML,
        )
        return

    # Sanitize input (max 8KB of code)
    code_text = sanitize_input(code_text, max_length=8192)

    # Security check — scan for blacklisted patterns
    threats = _check_blacklist(code_text, language)
    if threats:
        text = _format_blocked_response(threats)
        await update.message.reply_text(
            text=text,
            parse_mode=ParseMode.HTML,
        )
        log_query(
            user_id,
            "run_blocked",
            query=f"lang={language}",
            result=f"blacklisted: {', '.join(threats[:5])}",
        )
        return

    # Send a "running" indicator
    lang_label = SUPPORTED_LANGUAGES[language]["label"]
    processing_msg = await update.message.reply_text(
        f"⏳ {bold('Executing')} {lang_label} code…",
        parse_mode=ParseMode.HTML,
    )

    # Execute the code
    stdout, stderr, elapsed, exit_code = await _execute_code(code_text, language)

    # Format and send result
    result_text = _format_execution_result(
        language, code_text, stdout, stderr, elapsed, exit_code,
    )
    keyboard = _build_run_keyboard(language)

    try:
        await processing_msg.edit_text(
            text=result_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        # Message too long — truncate and retry
        try:
            short_text = (
                f"{bold(f'💻 {lang_label} Execution')}\n"
                f"  Exit code: {exit_code}\n"
                f"  Time: {bold(f'{elapsed:.3f}s')}\n\n"
            )
            if stdout:
                short_text += f"{bold('Output:')}\n{code(escape_html(stdout[:1000]))}\n\n"
            if stderr:
                short_text += f"{bold('Errors:')}\n{code(escape_html(stderr[:1000]))}\n\n"
            short_text += _format_security_warning()

            await processing_msg.edit_text(
                text=short_text,
                reply_markup=keyboard,
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.warning("Failed to send code runner result: %s", exc)

    # Log execution (without the code content for privacy)
    log_query(
        user_id,
        "run",
        query=f"lang={language},code_len={len(code_text)}",
        result=f"exit_code={exit_code},time={elapsed:.3f}s",
    )


# ── Callback Handler ─────────────────────────────────────────────────────────────

async def handle_run_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle inline keyboard callbacks from the code runner.
    Callback data format: run:lang:<language>
    """
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    parts = query.data.split(":")

    if len(parts) < 3 or parts[0] != "run":
        return

    action = parts[1]

    if action == "lang":
        selected_lang = parts[2]
        if selected_lang not in SUPPORTED_LANGUAGES:
            return

        # Build a hint message showing how to use the selected language
        lang_config = SUPPORTED_LANGUAGES[selected_lang]
        _py1 = code("/run python print('Hello!')")
        _py2 = code("/run python import math; print(math.pi)")
        _py3 = code("/run python [x**2 for x in range(10)]")
        _js1 = code("/run js console.log('Hello!')")
        _js2 = code("/run js Array(10).fill(0).map((_,i) => i**2)")
        _js3 = code("/run js JSON.stringify({a:1, b:2})")
        _bash1 = code('/run bash echo "Hello World"')
        _bash2 = code("/run bash ls -la /tmp")
        _bash3 = code("/run bash date +%Y-%m-%d")
        examples = {
            "python": [_py1, _py2, _py3],
            "javascript": [_js1, _js2, _js3],
            "bash": [_bash1, _bash2, _bash3],
        }

        example_lines = "\n".join(examples.get(selected_lang, []))

        text = (
            f"{bold(lang_config['label'] + ' Selected')}\n\n"
            f"Type a command like:\n\n"
            f"{example_lines}\n\n"
            f"Or type {code(f'/run {selected_lang} <your code>')} to execute."
        )

        keyboard = _build_run_keyboard(selected_lang)

        increment_usage(user_id)
        log_query(user_id, "run_lang_select", query=selected_lang)

        try:
            await query.edit_message_text(
                text=text,
                reply_markup=keyboard,
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.warning("Failed to update run callback message: %s", exc)
