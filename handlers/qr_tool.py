"""
QR Code Generator & Decoder Handler
Uses qrserver.com free API (no key needed).
"""

import logging
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.validators import sanitize_input
from utils.rate_limiter import check_rate_limit
from utils.logger import logger, log_query
from utils.formatters import bold, code, escape_html
import aiohttp

QR_GENERATE_URL = "https://api.qrserver.com/v1/create-qr-code/"
QR_READ_URL = "https://api.qrserver.com/v1/read-qr-code/"


async def cmd_qr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded.")
        return

    if not context.args:
        buttons = [
            [InlineKeyboardButton("📤 Generate QR", callback_data="qr:gen"),
             InlineKeyboardButton("📥 Decode QR", callback_data="qr:dec")]
        ]
        await update.message.reply_text(
            "📱 <b>QR Code Tool</b>\n\n"
            "Usage:\n"
            "  <code>/qr generate Hello World</code> — Create QR code\n"
            "  <code>/qr gen https://example.com</code> — Short form\n"
            "  <code>/qr size 300 gen Hello</code> — Custom size\n\n"
            "📥 Send me an image with QR code to decode it!\n\n"
            "Powered by qrserver.com (free API)",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        return

    # Parse arguments: [size] [color] generate/gen <text>
    args = list(context.args)
    size = 300
    color = "000000"
    bg_color = "FFFFFF"

    # Parse options
    while args:
        if args[0] == "size" and len(args) > 1:
            try:
                size = max(100, min(1000, int(args[1])))
                args = args[2:]
                continue
            except ValueError:
                args = args[1:]
        elif args[0] == "color" and len(args) > 1:
            color = args[1].lstrip("#")
            args = args[2:]
            continue
        elif args[0] == "bg" and len(args) > 1:
            bg_color = args[1].lstrip("#")
            args = args[2:]
            continue
        elif args[0].lower() in ("generate", "gen"):
            args = args[1:]
            break
        else:
            break

    text = sanitize_input(" ".join(args))
    if not text:
        await update.message.reply_text("❌ Please provide text to encode.")
        return

    await _generate_qr(update, text, size=size, color=color, bg_color=bg_color)


async def _generate_qr(update: Update, text: str, size: int = 300,
                       color: str = "000000", bg_color: str = "FFFFFF") -> None:
    user_id = update.effective_user.id
    msg = await update.message.reply_text("📱 Generating QR code...")

    try:
        params = {
            "size": f"{size}x{size}",
            "data": text,
            "color": color,
            "bgcolor": bg_color,
            "format": "png",
            "margin": 10,
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(QR_GENERATE_URL, params=params,
                                   timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    img_bytes = await resp.read()

                    caption = (
                        f"📱 <b>QR Code Generated</b>\n\n"
                        f"📝 Content: <code>{escape_html(text[:200])}</code>\n"
                        f"📐 Size: {size}x{size}px\n"
                        f"🔢 Chars: {len(text)}"
                    )

                    await update.message.reply_photo(
                        photo=img_bytes,
                        caption=caption
                    )
                    await msg.delete()
                    log_query(user_id, "qr_generate", text[:100], "success")
                else:
                    await msg.edit_text(f"❌ QR generation failed: HTTP {resp.status}")
                    log_query(user_id, "qr_generate", text[:100], "failure")

    except Exception as e:
        logger.error(f"QR generation error: {e}")
        await msg.edit_text(f"❌ Error: {str(e)[:200]}")


async def _decode_qr(update: Update, photo) -> None:
    """Decode QR code from a sent photo."""
    user_id = update.effective_user.id
    msg = await update.message.reply_text("📱 Decoding QR code...")

    try:
        file = await photo.get_file()
        img_bytes = await file.download_as_bytearray()

        form = aiohttp.FormData()
        form.add_field("file", bytes(img_bytes), filename="qr.png",
                       content_type="image/png")

        async with aiohttp.ClientSession() as session:
            async with session.post(QR_READ_URL, data=form,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("Results", [])
                    if results and results[0].get("Symbol", [{}])[0].get("Data"):
                        decoded = results[0]["Symbol"][0]["Data"]
                        text = (
                            f"📱 <b>QR Code Decoded</b>\n\n"
                            f"📝 Content:\n<code>{escape_html(decoded)}</code>\n\n"
                            f"📏 Length: {len(decoded)} characters"
                        )
                        # Check if it's a URL
                        if decoded.startswith(("http://", "https://")):
                            buttons = [[InlineKeyboardButton("🔗 Open Link", url=decoded)]]
                            await msg.edit_text(text, reply_markup=InlineKeyboardMarkup(buttons))
                        else:
                            await msg.edit_text(text)
                        log_query(user_id, "qr_decode", decoded[:100], "success")
                    else:
                        await msg.edit_text("❌ No QR code found in image.")
                        log_query(user_id, "qr_decode", "none", "failure")
                else:
                    await msg.edit_text(f"❌ Decode failed: HTTP {resp.status}")

    except Exception as e:
        logger.error(f"QR decode error: {e}")
        await msg.edit_text(f"❌ Error: {str(e)[:200]}")


async def handle_qr_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data.split(":")
    action = data[1] if len(data) > 1 else ""

    if action == "gen":
        await query.edit_message_text(
            "📤 <b>Generate QR Code</b>\n\n"
            "Usage:\n"
            "  <code>/qr Hello World</code>\n"
            "  <code>/qr gen https://example.com</code>\n\n"
            "Options:\n"
            "  <code>/qr size 400 gen Text</code> — Custom size\n"
            "  <code>/qr color FF0000 gen Text</code> — Red QR\n"
            "  <code>/qr bg FFFFFF color 000000 gen Text</code>"
        )
    elif action == "dec":
        await query.edit_message_text(
            "📥 <b>Decode QR Code</b>\n\n"
            "Send me any image containing a QR code\n"
            "and I'll decode it for you!"
        )
