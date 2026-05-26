"""
Telegram HTML Formatting Helpers
"""

from telegram.constants import ParseMode


def bold(text: str) -> str:
    return f"<b>{text}</b>"


def italic(text: str) -> str:
    return f"<i>{text}</i>"


def code(text: str) -> str:
    return f"<code>{text}</code>"


def pre(text: str) -> str:
    return f"<pre>{text}</pre>"


def link(label: str, url: str) -> str:
    return f'<a href="{url}">{label}</a>'


def escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
