"""
Metadata Extractor Handler
Extract EXIF data from images sent to the bot.
"""

import io
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, MessageHandler, filters, CallbackQueryHandler
from utils.logger import logger
from utils.formatters import bold, code, italic, escape_html

try:
    import exifread
    HAS_EXIFREAD = True
except ImportError:
    HAS_EXIFREAD = False


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard shown when /meta is used without args."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 What is EXIF?", callback_data="meta:about"),
            InlineKeyboardButton("🔒 Privacy Risks", callback_data="meta:privacy"),
        ],
        [
            InlineKeyboardButton("🛠️ Strip Metadata", callback_data="meta:strip"),
            InlineKeyboardButton("📱 Supported Formats", callback_data="meta:formats"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="meta:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="meta:back_main"),
        ],
    ])


def _nav_keyboard() -> InlineKeyboardMarkup:
    """Build navigation keyboard for metadata results."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🗺️ Google Maps", callback_data="meta:map"),
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="meta:back_osint"),
        ],
        [
            InlineKeyboardButton("🌐 Main Menu", callback_data="meta:back_main"),
        ],
    ])


async def cmd_metadata(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Metadata extraction is handled via photo messages — just show usage."""
    text = (
        "📷 <b>Metadata Extractor</b>\n\n"
        "Send me an <b>image</b> and I'll extract its EXIF metadata!\n\n"
        "<b>What can be extracted:</b>\n"
        "• 📷 Camera make & model\n"
        "• 📍 GPS coordinates\n"
        "• 📅 Date taken\n"
        "• 🖥️ Software used\n"
        "• 📐 Image dimensions\n"
        "• 🔄 Orientation\n\n"
        f"{italic('Just send any photo to this bot.')}"
    )
    await update.message.reply_text(text, reply_markup=_help_keyboard())


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Extract EXIF metadata from received photos."""
    if not HAS_EXIFREAD:
        await update.message.reply_text(
            "⚠️ EXIF library not installed. Run: pip install exifread",
            reply_markup=_nav_keyboard(),
        )
        return

    from database import log_query

    user_id = update.effective_user.id
    photo = update.message.photo[-1]  # Get highest resolution

    try:
        file = await photo.get_file()
        bio = io.BytesIO()
        await file.download_to_memory(bio)
        bio.seek(0)

        tags = exifread.process_file(bio, details=False, stop_tag="UNDEF")

        if not tags:
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔒 Why No Data?", callback_data="meta:no_exif"),
                ],
                [
                    InlineKeyboardButton("🔍 OSINT Tools", callback_data="meta:back_osint"),
                    InlineKeyboardButton("🌐 Main Menu", callback_data="meta:back_main"),
                ],
            ])
            await update.message.reply_text(
                "🔍 No EXIF metadata found in this image.\n\n"
                "This could mean:\n"
                "• Metadata was stripped\n"
                "• Image was created programmatically\n"
                "• Screenshot or screen capture",
                reply_markup=keyboard,
            )
            log_query(user_id, "metadata", photo.file_id, "no_exif")
            return

        # Categorize tags
        camera_info = {}
        gps_info = {}
        image_info = {}
        other_info = {}

        interesting_tags = {
            "Image Make": "Make",
            "Image Model": "Model",
            "Image DateTime": "Date Taken",
            "EXIF DateTimeOriginal": "Date Original",
            "EXIF DateTimeDigitized": "Date Digitized",
            "Image Software": "Software",
            "Image Artist": "Artist",
            "GPS GPSLatitude": "Latitude",
            "GPS GPSLongitude": "Longitude",
            "GPS GPSAltitude": "Altitude",
            "Image ImageWidth": "Width",
            "Image ImageLength": "Height",
            "Image Orientation": "Orientation",
            "EXIF ExposureTime": "Exposure",
            "EXIF FNumber": "F-Stop",
            "EXIF ISOSpeedRatings": "ISO",
            "EXIF FocalLength": "Focal Length",
            "EXIF Flash": "Flash",
        }

        result_lines = ["📷 <b>EXIF Metadata</b>\n"]

        # Group tags
        gps_coords = {}
        has_gps = False
        for tag, value in tags.items():
            tag_short = tag.split(" ")[-1] if " " in tag else tag

            if "GPS" in tag:
                gps_coords[tag_short] = str(value)
            elif any(tag_short == k.split(" ")[-1] for k in interesting_tags if tag_short in k):
                if "GPS" in tag:
                    continue
                result_lines.append(f"  • <b>{tag_short}</b>: {escape(value)}")
            elif tag_short in ("JPEGThumbnail", "TIFFThumbnail"):
                continue

        # Add GPS link if coordinates found
        if gps_coords:
            lat = gps_coords.get("GPSLatitude", "")
            lon = gps_coords.get("GPSLongitude", "")
            if lat and lon:
                has_gps = True
                result_lines.append(f"\n  📍 <b>GPS</b>: {lat}, {lon}")
                # Convert DMS to decimal if possible
                try:
                    lat_d, lon_d = _dms_to_decimal(gps_coords)
                    # Store for callback use
                    context.user_data["meta_gps"] = (lat_d, lon_d)
                    result_lines.append(
                        f"  🗺️ <a href='https://maps.google.com/?q={lat_d},{lon_d}'>"
                        f"View on Google Maps</a>"
                    )
                except Exception:
                    pass

        if len(result_lines) <= 1:
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔍 OSINT Tools", callback_data="meta:back_osint"),
                    InlineKeyboardButton("🌐 Main Menu", callback_data="meta:back_main"),
                ],
            ])
            await update.message.reply_text("🔍 No interesting metadata found.", reply_markup=keyboard)
            return

        result_lines.append(f"\n📊 <b>Total tags</b>: {len(tags)}")

        # Build keyboard with optional GPS button
        nav_buttons = [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="meta:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="meta:back_main"),
        ]
        if has_gps and "meta_gps" in context.user_data:
            nav_buttons.insert(0, InlineKeyboardButton(
                "🗺️ Open in Maps", callback_data="meta:map"
            ))

        keyboard = InlineKeyboardMarkup([nav_buttons])

        msg = "\n".join(result_lines)
        await update.message.reply_text(msg, reply_markup=keyboard)
        log_query(user_id, "metadata", photo.file_id, "success")

    except Exception as e:
        logger.error("Metadata extraction error: %s", e)
        await update.message.reply_text(
            f"❌ Error extracting metadata: {escape_html(str(e)[:200])}",
            reply_markup=_nav_keyboard(),
        )
        log_query(user_id, "metadata", "error", "failure")


async def handle_metadata_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the metadata module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>What is EXIF?</b>\n\n"
            "EXIF (Exchangeable Image File Format) is a standard that specifies "
            "the formats for images, sounds, and ancillary tags used by digital "
            "cameras (including smartphones). These tags contain metadata about "
            "the image and the device that captured it.\n\n"
            "<b>Common EXIF data includes:</b>\n"
            "• 📷 Camera make and model\n"
            "• 📍 GPS coordinates (latitude/longitude)\n"
            "• 📅 Date and time the photo was taken\n"
            "• 🖥️ Software used to edit the image\n"
            "• 📐 Image dimensions and resolution\n"
            "• 📸 Camera settings (ISO, aperture, shutter speed)\n"
            "• 🎨 Color space and compression info\n\n"
            f"{italic('EXIF data is embedded inside the image file itself — it travels with the image wherever it goes.')}"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔒 Privacy Risks", callback_data="meta:privacy"),
                    InlineKeyboardButton("← Back", callback_data="meta:menu"),
                ],
            ]),
        )

    elif action == "privacy":
        privacy_text = (
            "🔒 <b>Privacy Risks</b>\n\n"
            "Photos you share online can reveal sensitive information:\n\n"
            "📍 <b>Location Tracking:</b> GPS coordinates can show exactly "
            "where a photo was taken — your home, workplace, or school.\n\n"
            "📷 <b>Device Fingerprinting:</b> Camera model + software can "
            "link photos across platforms to the same device.\n\n"
            "📅 <b>Timeline Analysis:</b> Date/time stamps help build a "
            "chronological profile of your activities.\n\n"
            "👤 <b>Identity Exposure:</b> Artist/author fields may contain "
            "your real name or username.\n\n"
            "<b>How to protect yourself:</b>\n"
            "• Disable camera geotagging in phone settings\n"
            "• Use apps that strip EXIF before sharing\n"
            "• Send images as documents instead of photos\n"
            "• Use secure messaging apps that auto-strip metadata"
        )
        await query.edit_message_text(
            privacy_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🛠️ Strip Metadata", callback_data="meta:strip"),
                    InlineKeyboardButton("← Back", callback_data="meta:menu"),
                ],
            ]),
        )

    elif action == "strip":
        strip_text = (
            "🛠️ <b>How to Strip Metadata</b>\n\n"
            "<b>On Desktop:</b>\n"
            "• <b>ExifTool</b> (CLI): <code>exiftool -all= photo.jpg</code>\n"
            "• <b>ImageMagick</b>: <code>mogrify -strip photo.jpg</code>\n"
            "• <b>mat2</b>: <code>mat2 photo.jpg</code>\n"
            "• <b>Photoshop/GIMP</b>: Export for Web (strips EXIF)\n\n"
            "<b>On Mobile:</b>\n"
            "• <b>Android</b>: Use \"Scrambled Exif\" or \"Photo Metadata\"\n"
            "• <b>iOS</b>: Use \"Metapho\" or \"EXIF Cleaner\"\n\n"
            "<b>Telegram Tip:</b>\n"
            "Send images as files/documents instead of photos — "
            "Telegram strips EXIF from photos but not from files.\n\n"
            f"{italic('⚠️ Always strip metadata before sharing images publicly.')}"
        )
        await query.edit_message_text(
            strip_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📱 Formats", callback_data="meta:formats"),
                    InlineKeyboardButton("← Back", callback_data="meta:menu"),
                ],
            ]),
        )

    elif action == "formats":
        formats_text = (
            "📱 <b>Supported Image Formats</b>\n\n"
            "<b>Full EXIF Support:</b>\n"
            "• JPEG / JPG — Most common, rich metadata\n"
            "• TIFF — High-quality format, extensive EXIF\n"
            "• HEIC / HEIF — Apple's modern format\n"
            "• DNG — Adobe Digital Negative (RAW)\n"
            "• WEBP — Growing support for EXIF\n\n"
            "<b>Limited/No EXIF:</b>\n"
            "• PNG — Minimal metadata (no EXIF standard)\n"
            "• GIF — No EXIF support\n"
            "• BMP — No EXIF support\n"
            "• SVG — XML-based, no EXIF\n\n"
            "<b>RAW Camera Formats:</b>\n"
            "• CR2 (Canon), NEF (Nikon), ARW (Sony)\n"
            "• ORF (Olympus), RAF (Fujifilm)\n"
            "• These contain extensive camera data\n\n"
            f"{italic('JPEG is the most common format for OSINT metadata analysis.')}"
        )
        await query.edit_message_text(
            formats_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 What is EXIF?", callback_data="meta:about"),
                    InlineKeyboardButton("← Back", callback_data="meta:menu"),
                ],
            ]),
        )

    elif action == "no_exif":
        no_exif_text = (
            "🔍 <b>No EXIF Data Found</b>\n\n"
            "If the bot can't find EXIF metadata, it usually means:\n\n"
            "🧹 <b>Metadata was stripped:</b>\n"
            "Many social media platforms (Twitter, Facebook, Instagram) "
            "automatically remove EXIF data when you upload images.\n\n"
            "🖥️ <b>Screenshot:</b>\n"
            "Screenshots typically don't inherit EXIF data from the "
            "original image.\n\n"
            "📱 <b>Privacy-focused apps:</b>\n"
            "Signal, WhatsApp, and other secure messengers strip GPS "
            "and camera info from images.\n\n"
            "🎨 <b>Edited image:</b>\n"
            "Image editors often strip or modify EXIF data during export.\n\n"
            "📸 <b>Programmatic creation:</b>\n"
            "Images generated by AI or created with code typically "
            "don't have EXIF data."
        )
        await query.edit_message_text(
            no_exif_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔒 Privacy Risks", callback_data="meta:privacy"),
                    InlineKeyboardButton("← Back", callback_data="meta:menu"),
                ],
            ]),
        )

    elif action == "map":
        """Open GPS location in Google Maps."""
        gps = context.user_data.get("meta_gps")
        if gps:
            lat, lon = gps
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🗺️ Open in Google Maps", url=f"https://maps.google.com/?q={lat},{lon}"),
                    InlineKeyboardButton("🌍 OpenStreetMap", url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"),
                ],
                [
                    InlineKeyboardButton("← Back to Metadata", callback_data="meta:menu"),
                ],
            ])
            await query.edit_message_reply_markup(reply_markup=keyboard)
        else:
            await query.answer("No GPS data available.", show_alert=True)

    elif action == "menu":
        await query.edit_message_text(
            "📷 <b>Metadata Extractor</b>\n\n"
            "Send me an <b>image</b> and I'll extract its EXIF metadata!\n\n"
            "<b>What can be extracted:</b>\n"
            "• 📷 Camera make & model\n"
            "• 📍 GPS coordinates\n"
            "• 📅 Date taken\n"
            "• 🖥️ Software used\n"
            "• 📐 Image dimensions\n"
            "• 🔄 Orientation\n\n"
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


def escape(value) -> str:
    """Simple HTML escape for EXIF values."""
    s = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s[:200]


def _dms_to_decimal(gps_coords: dict) -> tuple:
    """Convert GPS DMS coordinates to decimal."""
    def parse_dms(val):
        parts = str(val).replace("[", "").replace("]", "").replace("deg", "").strip().split(",")
        if len(parts) == 3:
            d, m, s = float(parts[0]), float(parts[1]), float(parts[2])
            return d + m / 60 + s / 3600
        return float(val)

    lat = parse_dms(gps_coords.get("GPSLatitude", "0"))
    lat_ref = str(gps_coords.get("GPSLatitudeRef", "N"))
    if lat_ref == "S":
        lat = -lat

    lon = parse_dms(gps_coords.get("GPSLongitude", "0"))
    lon_ref = str(gps_coords.get("GPSLongitudeRef", "E"))
    if lon_ref == "W":
        lon = -lon

    return lat, lon
