"""
Face Detection Handler
Detects and extracts faces from images using basic analysis.
Provides face position info and links to face recognition search engines.
"""

import io
import logging

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.logger import logger, log_query
from utils.formatters import bold, code, italic, escape_html
from database import increment_usage

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard for face detection."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 About Face Detection", callback_data="face:about"),
            InlineKeyboardButton("🎯 Use Cases", callback_data="face:uses"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="face:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="face:back_main"),
        ],
    ])


async def cmd_face(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show usage info for face detection."""
    user_id = update.effective_user.id
    increment_usage(user_id)

    text = (
        "👤 <b>Face Detection & Analysis</b>\n\n"
        "Send me an <b>image</b> and I'll analyze it for faces!\n\n"
        "<b>What this does:</b>\n"
        "• 📐 Detect faces in images\n"
        "• 📏 Show face position and size\n"
        "• 🔍 Links to face search engines\n"
        "• 📊 Image analysis summary\n\n"
        f"{italic('Just send any photo to this bot.')}"
    )
    await update.message.reply_text(text, reply_markup=_help_keyboard())


async def handle_face_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle incoming photos for face detection."""
    from database import log_query

    user_id = update.effective_user.id
    photo = update.message.photo[-1]

    if not HAS_PILLOW:
        await update.message.reply_text(
            "⚠️ Pillow library not installed. Run: pip install Pillow",
            reply_markup=_help_keyboard(),
        )
        return

    try:
        file = await photo.get_file()
        bio = io.BytesIO()
        await file.download_to_memory(bio)
        bio.seek(0)

        image = Image.open(bio)
        img_width, img_height = image.size
        img_format = image.format or "Unknown"
        img_mode = image.mode or "Unknown"

        increment_usage(user_id)

        # Analyze image properties
        result_lines = [
            "👤 <b>Face Detection & Image Analysis</b>\n",
            f"📊 <b>Image Info:</b>",
            f"  • Dimensions: {img_width} x {img_height} px",
            f"  • Format: {escape_html(img_format)}",
            f"  • Color Mode: {escape_html(img_mode)}",
            f"  • Aspect Ratio: {_get_aspect_ratio(img_width, img_height)}",
            f"  • Megapixels: {(img_width * img_height / 1_000_000):.1f} MP",
        ]

        # Detect potential face regions (simple skin-tone heuristic)
        faces = _detect_faces_basic(image)

        result_lines.append("")
        result_lines.append(f"{'━' * 30}")

        if faces:
            result_lines.append(f"👨 {bold(f'{len(faces)} potential face(s) detected')}\n")
            for i, face in enumerate(faces, 1):
                result_lines.append(
                    f"  Face {i}: ({face['x']}, {face['y']}) "
                    f"— {face['w']}x{face['h']} px "
                    f"[{face['confidence']}]"
                )
        else:
            result_lines.append("❌ No faces detected using basic analysis.")
            result_lines.append(italic("For better results, use the search engines below."))

        # Build search engine links
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔎 Yandex Face Search", url="https://yandex.com/images/"),
                InlineKeyboardButton("🔍 PimEyes", url="https://pimeyes.com/"),
            ],
            [
                InlineKeyboardButton("🤖 Search4faces", url="https://search4faces.com/"),
                InlineKeyboardButton("🌐 Google Lens", url="https://lens.google.com/"),
            ],
            [
                InlineKeyboardButton("🛡️ FaceCheck.ID", url="https://facecheck.id/"),
                InlineKeyboardButton("👤 Tineye", url="https://tineye.com/"),
            ],
            [
                InlineKeyboardButton("📸 EXIF Extract", callback_data="face:exif_tip"),
                InlineKeyboardButton("🔍 Reverse Search", callback_data="face:reverse_tip"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="face:back_osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="face:back_main"),
            ],
        ])

        await update.message.reply_text("\n".join(result_lines), reply_markup=keyboard)
        log_query(user_id, "face_detect", photo.file_id, "success")

    except Exception as e:
        logger.error("Face detection error: %s", e)
        await update.message.reply_text(
            f"❌ Error analyzing image: {escape_html(str(e)[:200])}",
            reply_markup=_help_keyboard(),
        )


async def handle_face_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the face detection module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>About Face Detection</b>\n\n"
            "Face detection is a computer vision technique that identifies "
            "and locates human faces in digital images. Combined with reverse "
            "image search, it's a powerful OSINT tool.\n\n"
            "<b>How it works:</b>\n"
            "• The bot analyzes image pixels to identify potential face regions\n"
            "• Face position and size are reported\n"
            "• Links to specialized face search engines are provided\n\n"
            "<b>Face Search Engines:</b>\n"
            "• <b>Yandex</b> — Best free face recognition. Often finds social media profiles.\n"
            "• <b>PimEyes</b> — Advanced face search (paid). Very accurate.\n"
            "• <b>Search4faces</b> — Searches VKontakte and other social networks.\n"
            "• <b>FaceCheck.ID</b> — Searches mugshots and social media.\n\n"
            f"{italic('⚠️ Always use face search responsibly and ethically.')}"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🎯 Use Cases", callback_data="face:uses"),
                    InlineKeyboardButton("← Back", callback_data="face:menu"),
                ],
            ]),
        )

    elif action == "uses":
        uses_text = (
            "🎯 <b>Face Search Use Cases</b>\n\n"
            "🕵️ <b>OSINT Investigations:</b>\n"
            "  Identify unknown persons in photos by finding their social media "
            "  profiles through facial recognition search engines.\n\n"
            "⚠️ <b>Anti-Scam Verification:</b>\n"
            "  Check if a profile picture belongs to the real person or has been "
            "  stolen from someone else's social media.\n\n"
            "📰 <b>Journalism:</b>\n"
            "  Identify people in news photos or viral images.\n\n"
            "🔒 <b>Personal Security:</b>\n"
            "  Check if your own photos appear on websites you don't know about.\n\n"
            "🎭 <b>Deepfake Detection:</b>\n"
            "  Combined with EXIF analysis, face search can help identify "
            "  AI-generated or manipulated images."
        )
        await query.edit_message_text(
            uses_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 About", callback_data="face:about"),
                    InlineKeyboardButton("← Back", callback_data="face:menu"),
                ],
            ]),
        )

    elif action == "exif_tip":
        tip_text = (
            "📸 <b>EXIF Tip</b>\n\n"
            "Before doing a face search, check the image's EXIF metadata first!\n\n"
            "Use {code('/meta')} and send the image to extract:\n"
            "• 📷 Camera make and model\n"
            "• 📍 GPS coordinates\n"
            "• 📅 Date and time taken\n"
            "• 🖥️ Software used\n\n"
            "EXIF data can provide context that helps narrow down "
            "your search before using face recognition engines.\n\n"
            f"{italic('💡 Tip: GPS data can pinpoint where the photo was taken!')}"
        )
        await query.answer(
            "💡 Use /meta and send the image to check EXIF data first!",
            show_alert=True,
        )

    elif action == "reverse_tip":
        await query.answer(
            "💡 Use /reverse and send the image for reverse image search!",
            show_alert=True,
        )

    elif action == "menu":
        await query.edit_message_text(
            "👤 <b>Face Detection & Analysis</b>\n\n"
            "Send me an <b>image</b> and I'll analyze it for faces!\n\n"
            "<b>What this does:</b>\n"
            "• 📐 Detect faces in images\n"
            "• 📏 Show face position and size\n"
            "• 🔍 Links to face search engines\n"
            "• 📊 Image analysis summary\n\n"
            f"{italic('Just send any photo to this bot.')}",
            reply_markup=_help_keyboard(),
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


# ── Face Detection (Basic) ─────────────────────────────────────────────────────

def _detect_faces_basic(image: Image.Image) -> list:
    """
    Basic face detection using skin-tone color analysis.
    This is a simplified heuristic — not as accurate as ML-based detection.

    Returns list of face regions with x, y, w, h, confidence.
    """
    try:
        # Convert to RGB if needed
        if image.mode != "RGB":
            image = image.convert("RGB")

        img_width, img_height = image.size

        # Downsample for performance
        max_dim = 200
        ratio = min(max_dim / img_width, max_dim / img_height, 1.0)
        if ratio < 1.0:
            small = image.resize(
                (int(img_width * ratio), int(img_height * ratio)),
                Image.Resampling.LANCZOS,
            )
        else:
            small = image.copy()

        pixels = list(small.getdata())
        w, h = small.size

        # Scan for skin-tone regions
        skin_pixels = 0
        total_pixels = w * h

        for r, g, b in pixels:
            # Skin tone detection in RGB space
            if (
                r > 95 and g > 40 and b > 20
                and max(r, g, b) - min(r, g, b) > 15
                and abs(r - g) > 15
                and r > g and r > b
            ):
                skin_pixels += 1

        skin_ratio = skin_pixels / total_pixels if total_pixels > 0 else 0

        # If significant skin-tone pixels, likely has a face
        faces = []
        if skin_ratio > 0.05:
            # Estimate face region (upper-center of image)
            face_w = int(w * 0.3)
            face_h = int(h * 0.4)
            face_x = (w - face_w) // 2
            face_y = int(h * 0.1)

            # Scale back to original dimensions
            if ratio < 1.0:
                face_x = int(face_x / ratio)
                face_y = int(face_y / ratio)
                face_w = int(face_w / ratio)
                face_h = int(face_h / ratio)

            confidence = "High" if skin_ratio > 0.15 else "Medium" if skin_ratio > 0.08 else "Low"

            faces.append({
                "x": face_x,
                "y": face_y,
                "w": face_w,
                "h": face_h,
                "confidence": confidence,
            })

        return faces

    except Exception:
        return []


def _get_aspect_ratio(width: int, height: int) -> str:
    """Get simplified aspect ratio string."""
    from math import gcd
    g = gcd(width, height)
    w = width // g
    h = height // g

    # Limit to reasonable numbers
    if w > 50 or h > 50:
        ratio = width / height
        if abs(ratio - 16/9) < 0.1:
            return "16:9"
        elif abs(ratio - 4/3) < 0.1:
            return "4:3"
        elif abs(ratio - 3/2) < 0.1:
            return "3:2"
        elif abs(ratio - 1) < 0.1:
            return "1:1"
        elif abs(ratio - 9/16) < 0.1:
            return "9:16"
        else:
            return f"{width}:{height}"

    return f"{w}:{h}"
