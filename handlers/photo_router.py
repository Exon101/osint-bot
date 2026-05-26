"""
Photo Router Handler
Intercepts all incoming photos and presents a menu for the user to choose
which analysis to perform: EXIF extraction, reverse search, or face detection.
"""

import io
import hashlib
import logging

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, MessageHandler, filters
from utils.logger import logger
from utils.formatters import bold, italic

from database import increment_usage, log_query


async def handle_photo_router(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Intercept all incoming photos and present an analysis menu.
    Stores the photo file_id and basic info in user_data for routing.
    """
    user_id = update.effective_user.id
    photo = update.message.photo[-1]  # Highest resolution

    try:
        file = await photo.get_file()
        bio = io.BytesIO()
        await file.download_to_memory(bio)
        image_bytes = bio.read()
        bio.close()

        if not image_bytes or len(image_bytes) < 100:
            await update.message.reply_text("❌ Image is too small or corrupted.")
            return

        img_hash = hashlib.md5(image_bytes).hexdigest()[:12]
        img_size_kb = len(image_bytes) / 1024

        # Store image data in user_data for later use
        context.user_data["photo_bytes"] = image_bytes
        context.user_data["photo_hash"] = img_hash
        context.user_data["photo_size_kb"] = img_size_kb

        increment_usage(user_id)

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📋 EXIF Metadata", callback_data="photo:exif"),
                InlineKeyboardButton("🔍 Reverse Search", callback_data="photo:reverse"),
            ],
            [
                InlineKeyboardButton("👤 Face Detection", callback_data="photo:face"),
                InlineKeyboardButton("🧪 Run All", callback_data="photo:all"),
            ],
        ])

        text = (
            f"📷 <b>Photo Received</b>\n\n"
            f"📊 Size: {img_size_kb:.1f} KB\n"
            f"🔑 Hash: <code>{img_hash}</code>\n\n"
            f"{bold('Choose an analysis:')}\n"
            f"  📋 EXIF Metadata — Extract camera, GPS, date info\n"
            f"  🔍 Reverse Search — Find where this image appears online\n"
            f"  👤 Face Detection — Detect faces and find face search links\n"
            f"  🧪 Run All — Perform all analyses at once"
        )

        await update.message.reply_text(text, reply_markup=keyboard)
        log_query(user_id, "photo_received", img_hash, "success")

    except Exception as e:
        logger.error("Photo router error: %s", e)
        await update.message.reply_text(f"❌ Error processing image.")


async def handle_photo_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Route photo analysis choice to the appropriate handler."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]
    photo_bytes = context.user_data.get("photo_bytes")
    photo_hash = context.user_data.get("photo_hash", "")

    if not photo_bytes:
        await query.edit_message_text("❌ Photo data expired. Please send the image again.")
        return

    user_id = query.from_user.id

    if action == "exif":
        await query.edit_message_text("📋 Extracting EXIF metadata …")
        await _run_exif_analysis(update, context, photo_bytes, photo_hash)

    elif action == "reverse":
        await query.edit_message_text("🔍 Preparing reverse image search …")
        await _run_reverse_search(update, context, photo_hash)

    elif action == "face":
        await query.edit_message_text("👤 Detecting faces …")
        await _run_face_detection(update, context, photo_bytes, photo_hash)

    elif action == "all":
        await query.edit_message_text("🧪 Running all analyses …")
        # Run EXIF
        exif_text = await _get_exif_text(photo_bytes)
        # Run face detection
        face_text = await _get_face_text(photo_bytes)
        # Provide reverse search links
        reverse_text = _get_reverse_links_text(photo_hash)

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🌐 Google Lens", url="https://lens.google.com/"),
                InlineKeyboardButton("🔎 Yandex", url="https://yandex.com/images/"),
            ],
            [
                InlineKeyboardButton("🔍 TinEye", url="https://tineye.com/"),
                InlineKeyboardButton("🎨 SauceNAO", url="https://saucenao.com/"),
            ],
            [
                InlineKeyboardButton("🤖 PimEyes", url="https://pimeyes.com/"),
                InlineKeyboardButton("🔍 FaceCheck", url="https://facecheck.id/"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        result = (
            f"🧪 <b>All Analyses</b>\n"
            f"🔑 Hash: <code>{photo_hash}</code>\n\n"
            f"{exif_text}\n"
            f"{face_text}\n"
            f"{reverse_text}"
        )

        await query.edit_message_text(result, reply_markup=keyboard)

    else:
        await query.edit_message_reply_markup(reply_markup=None)


async def _run_exif_analysis(update, context, photo_bytes, photo_hash):
    """Run EXIF analysis and update the message."""
    try:
        import exifread

        bio = io.BytesIO(photo_bytes)
        bio.seek(0)
        tags = exifread.process_file(bio, details=False, stop_tag="UNDEF")
        bio.close()

        if not tags:
            await update.callback_query.edit_message_text(
                "🔍 No EXIF metadata found in this image.\n\n"
                "This could mean:\n"
                "• Metadata was stripped\n"
                "• Image was created programmatically\n"
                "• Screenshot or screen capture\n\n"
                f"{italic('Try Reverse Search or Face Detection instead!')}"
            )
            return

        result_lines = [f"📋 <b>EXIF Metadata</b>  🔑 <code>{photo_hash}</code>\n"]

        interesting_tags = {
            "Image Make": "📷 Make",
            "Image Model": "📷 Model",
            "Image DateTime": "📅 Date Taken",
            "EXIF DateTimeOriginal": "📅 Original Date",
            "Image Software": "🖥️ Software",
            "Image ImageWidth": "📐 Width",
            "Image ImageLength": "📐 Height",
            "Image Orientation": "🔄 Orientation",
            "EXIF ISOSpeedRatings": "📸 ISO",
            "EXIF FocalLength": "🔭 Focal Length",
            "EXIF FNumber": "📷 F-Stop",
            "EXIF ExposureTime": "⏱️ Exposure",
        }

        gps_coords = {}
        for tag, value in tags.items():
            tag_short = tag.split(" ")[-1] if " " in tag else tag
            if "GPS" in tag:
                gps_coords[tag_short] = str(value)
            else:
                for key, label in interesting_tags.items():
                    if tag_short in key and tag_short == key.split(" ")[-1]:
                        val_str = str(value)[:100]
                        result_lines.append(f"  {label}: {escape_html_val(val_str)}")
                        break

        # GPS info
        if gps_coords:
            lat = gps_coords.get("GPSLatitude", "")
            lon = gps_coords.get("GPSLongitude", "")
            if lat and lon:
                result_lines.append(f"\n  📍 <b>GPS</b>: {lat}, {lon}")
                try:
                    from handlers.metadata import _dms_to_decimal
                    lat_d, lon_d = _dms_to_decimal(gps_coords)
                    result_lines.append(
                        f"  🗺️ <a href='https://maps.google.com/?q={lat_d},{lon_d}'>"
                        f"View on Google Maps</a>"
                    )
                except Exception:
                    pass

        result_lines.append(f"\n📊 Total tags: {len(tags)}")

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 Reverse Search", callback_data="photo:reverse"),
                InlineKeyboardButton("👤 Face Detection", callback_data="photo:face"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await update.callback_query.edit_message_text(
            "\n".join(result_lines),
            reply_markup=keyboard,
        )

    except ImportError:
        await update.callback_query.edit_message_text(
            "⚠️ EXIF library not installed. Run: pip install exifread"
        )
    except Exception as e:
        logger.error("EXIF error: %s", e)
        await update.callback_query.edit_message_text(
            f"❌ Error extracting EXIF: {escape_html_val(str(e)[:200])}"
        )


async def _run_reverse_search(update, context, photo_hash):
    """Show reverse image search links."""
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 Google Lens", url="https://lens.google.com/"),
            InlineKeyboardButton("🔎 Yandex Images", url="https://yandex.com/images/"),
        ],
        [
            InlineKeyboardButton("🔍 TinEye", url="https://tineye.com/"),
            InlineKeyboardButton("🖼️ Bing Visual", url="https://www.bing.com/visualsearch"),
        ],
        [
            InlineKeyboardButton("🎨 SauceNAO", url="https://saucenao.com/"),
            InlineKeyboardButton("🤖 ASCII2D", url="https://ascii2d.net/"),
        ],
        [
            InlineKeyboardButton("📋 EXIF Metadata", callback_data="photo:exif"),
            InlineKeyboardButton("👤 Face Detection", callback_data="photo:face"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
        ],
    ])

    text = (
        f"🔍 <b>Reverse Image Search</b>\n"
        f"🔑 Hash: <code>{photo_hash}</code>\n\n"
        f"{bold('Tap a button below to search:')}\n\n"
        f"💡 {italic('Tip: Upload the image to each service to perform the search.')}"
    )

    await update.callback_query.edit_message_text(text, reply_markup=keyboard)


async def _run_face_detection(update, context, photo_bytes, photo_hash):
    """Run face detection and show results."""
    try:
        from PIL import Image
        from handlers.face_detect import _detect_faces_basic, _get_aspect_ratio

        image = Image.open(io.BytesIO(photo_bytes))
        img_width, img_height = image.size

        result_lines = [
            f"👤 <b>Face Detection</b>  🔑 <code>{photo_hash}</code>\n",
            f"📐 Dimensions: {img_width} x {img_height} px",
            f"📏 Aspect Ratio: {_get_aspect_ratio(img_width, img_height)}",
        ]

        faces = _detect_faces_basic(image)

        result_lines.append("")
        if faces:
            result_lines.append(f"👨 {bold(f'{len(faces)} potential face(s) detected')}\n")
            for i, face in enumerate(faces, 1):
                result_lines.append(
                    f"  Face {i}: ({face['x']}, {face['y']}) "
                    f"— {face['w']}x{face['h']} px [{face['confidence']}]"
                )
        else:
            result_lines.append("❌ No faces detected using basic analysis.")
            result_lines.append(italic("For better results, use face search engines below."))

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔎 Yandex Face Search", url="https://yandex.com/images/"),
                InlineKeyboardButton("🤖 PimEyes", url="https://pimeyes.com/"),
            ],
            [
                InlineKeyboardButton("🔍 Search4faces", url="https://search4faces.com/"),
                InlineKeyboardButton("🛡️ FaceCheck.ID", url="https://facecheck.id/"),
            ],
            [
                InlineKeyboardButton("📋 EXIF Metadata", callback_data="photo:exif"),
                InlineKeyboardButton("🔍 Reverse Search", callback_data="photo:reverse"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="menu:osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="menu:main"),
            ],
        ])

        await update.callback_query.edit_message_text(
            "\n".join(result_lines),
            reply_markup=keyboard,
        )

    except ImportError:
        await update.callback_query.edit_message_text(
            "⚠️ Pillow library not installed. Run: pip install Pillow"
        )
    except Exception as e:
        logger.error("Face detection error: %s", e)
        await update.callback_query.edit_message_text(
            f"❌ Error detecting faces: {escape_html_val(str(e)[:200])}"
        )


# ── Helper functions ─────────────────────────────────────────────────────────────

async def _get_exif_text(photo_bytes) -> str:
    """Get EXIF text for 'all' mode."""
    try:
        import exifread
        bio = io.BytesIO(photo_bytes)
        bio.seek(0)
        tags = exifread.process_file(bio, details=False, stop_tag="UNDEF")
        bio.close()

        if not tags:
            return "📋 <b>EXIF:</b> No metadata found"

        lines = ["📋 <b>EXIF Metadata:</b>"]
        count = 0
        for tag, value in tags.items():
            tag_short = tag.split(" ")[-1] if " " in tag else tag
            if tag_short in ("JPEGThumbnail", "TIFFThumbnail"):
                continue
            if "GPS" in tag:
                continue
            val_str = str(value)[:80]
            lines.append(f"  • {escape_html_val(tag_short)}: {escape_html_val(val_str)}")
            count += 1
            if count >= 8:
                lines.append(f"  … and {len(tags) - 8} more tags")
                break
        return "\n".join(lines)
    except Exception:
        return "📋 <b>EXIF:</b> Error extracting metadata"


async def _get_face_text(photo_bytes) -> str:
    """Get face detection text for 'all' mode."""
    try:
        from PIL import Image
        from handlers.face_detect import _detect_faces_basic
        image = Image.open(io.BytesIO(photo_bytes))
        faces = _detect_faces_basic(image)
        if faces:
            return f"👤 <b>Face Detection:</b> {len(faces)} face(s) detected"
        return "👤 <b>Face Detection:</b> No faces detected"
    except Exception:
        return "👤 <b>Face Detection:</b> Analysis unavailable (Pillow needed)"


def _get_reverse_links_text(photo_hash) -> str:
    """Get reverse search links for 'all' mode."""
    return (
        "🔍 <b>Reverse Search:</b>\n"
        "  • 🌐 Google Lens\n"
        "  • 🔎 Yandex Images\n"
        "  • 🔍 TinEye\n"
        "  • 🎨 SauceNAO\n"
        "  • 🤖 PimEyes\n"
        "  • 🛡️ FaceCheck.ID\n\n"
        "👆 Tap the buttons below to search."
    )


def escape_html_val(value) -> str:
    """Simple HTML escape."""
    s = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s[:200]
