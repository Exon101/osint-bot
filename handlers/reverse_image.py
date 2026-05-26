"""
Reverse Image Search Handler
Accepts an image from the user and generates reverse image search links
for multiple engines (Google Lens, Yandex, TinEye, Bing Visual, SauceNAO).
"""

import io
import logging
import base64
import hashlib

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from utils.logger import logger, log_query
from utils.formatters import bold, code, italic, escape_html
from database import increment_usage


def _help_keyboard() -> InlineKeyboardMarkup:
    """Build help keyboard shown when /reverse is used without an image."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📖 How It Works", callback_data="rev:about"),
            InlineKeyboardButton("🔍 Search Engines", callback_data="rev:engines"),
        ],
        [
            InlineKeyboardButton("💡 Tips & Tricks", callback_data="rev:tips"),
        ],
        [
            InlineKeyboardButton("🔍 OSINT Tools", callback_data="rev:back_osint"),
            InlineKeyboardButton("🌐 Main Menu", callback_data="rev:back_main"),
        ],
    ])


async def cmd_reverse(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show usage info for reverse image search."""
    user_id = update.effective_user.id
    increment_usage(user_id)

    text = (
        "🔍 <b>Reverse Image Search</b>\n\n"
        "Send me an <b>image</b> and I'll generate reverse search links!\n\n"
        "<b>Supported engines:</b>\n"
        "• 🌐 Google Lens\n"
        "• 🔎 Yandex Images\n"
        "• 🔍 TinEye\n"
        "• 🖼️ Bing Visual Search\n"
        "• 🎨 SauceNAO (Anime/Art)\n"
        "• 🤖 ASCII2D (Japanese)\n"
        "• 📷 Reddit Image Search\n\n"
        f"{italic('Just send any photo to this bot.')}"
    )
    await update.message.reply_text(text, reply_markup=_help_keyboard())


async def handle_reverse_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle incoming photos for reverse image search."""
    from database import log_query

    user_id = update.effective_user.id
    photo = update.message.photo[-1]  # Highest resolution

    try:
        file = await photo.get_file()
        bio = io.BytesIO()
        await file.download_to_memory(bio)
        image_bytes = bio.read()
        bio.close()

        if not image_bytes or len(image_bytes) < 100:
            await update.message.reply_text(
                "❌ Image is too small or corrupted.",
                reply_markup=_help_keyboard(),
            )
            return

        # Generate image hash for reference
        img_hash = hashlib.md5(image_bytes).hexdigest()[:12]
        img_size_kb = len(image_bytes) / 1024

        # Build reverse search URLs

        # Google Lens (via upload or camera search)
        google_url = "https://lens.google.com/upload?ep=ccm&s=&st="

        # Yandex reverse image
        yandex_url = "https://yandex.com/images/search?rpt=imageview&url="

        # TinEye
        tineye_url = "https://tineye.com/search/?url="

        # Bing Visual Search
        bing_url = "https://www.bing.com/images/search?q=imgref&first=1&iss=sbiupload"

        # SauceNAO (anime/art)
        saucenao_url = "https://saucenao.com/search.php"

        # ASCII2D
        ascii2d_url = "https://ascii2d.net/search/url/"

        # Reddit image reverse search
        reddit_url = "https://redditimage.com/"

        # Karma Decay (reddit repost detection)
        karma_url = "https://karmadecay.com/"

        increment_usage(user_id)

        result_lines = [
            "🔍 <b>Reverse Image Search</b>\n",
            f"📊 <b>Image Info:</b>",
            f"  • Size: {img_size_kb:.1f} KB",
            f"  • Hash: <code>{img_hash}</code>",
            "",
            f"{'━' * 30}",
            "",
            "<b>🔎 Tap a button below to search:</b>",
        ]

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🌐 Google Lens", callback_data="rev:google"),
                InlineKeyboardButton("🔎 Yandex Images", callback_data="rev:yandex"),
            ],
            [
                InlineKeyboardButton("🔍 TinEye", callback_data="rev:tineye"),
                InlineKeyboardButton("🖼️ Bing Visual", callback_data="rev:bing"),
            ],
            [
                InlineKeyboardButton("🎨 SauceNAO", callback_data="rev:saucenao"),
                InlineKeyboardButton("🤖 ASCII2D", callback_data="rev:ascii2d"),
            ],
            [
                InlineKeyboardButton("📷 Reddit Search", callback_data="rev:reddit"),
                InlineKeyboardButton("🔄 Karma Decay", callback_data="rev:karma"),
            ],
            [
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="rev:back_osint"),
                InlineKeyboardButton("🌐 Main Menu", callback_data="rev:back_main"),
            ],
        ])

        msg_text = "\n".join(result_lines)
        await update.message.reply_text(msg_text, reply_markup=keyboard)
        log_query(user_id, "reverse_image", img_hash, "success")

    except Exception as e:
        logger.error("Reverse image search error: %s", e)
        await update.message.reply_text(
            f"❌ Error processing image: {escape_html(str(e)[:200])}",
            reply_markup=_help_keyboard(),
        )


async def handle_reverse_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button callbacks from the reverse image module."""
    query = update.callback_query
    await query.answer()

    parts = query.data.split(":", 2)
    if len(parts) < 2:
        await query.edit_message_reply_markup(reply_markup=None)
        return

    action = parts[1]

    if action == "about":
        about_text = (
            "📖 <b>How Reverse Image Search Works</b>\n\n"
            "Reverse image search finds where an image appears online, "
            "similar images, and the original source. This is a core "
            "OSINT technique.\n\n"
            "<b>Common Use Cases:</b>\n"
            "• 🕵️ <b>Verify image authenticity</b> — Check if a photo is real or fake\n"
            "• 👤 <b>Identify people</b> — Find social media profiles from photos\n"
            "• 📍 <b>Find image location</b> — Discover where a photo was taken\n"
            "• 🔄 <b>Find higher resolution</b> — Locate the original quality version\n"
            "• 📰 <b>Check for manipulation</b> — Detect edited or Photoshopped images\n"
            "• 🎨 <b>Find image source</b> — Credit the original creator\n"
            "• ⚠️ <b>Expose scams</b> — Verify profile pictures aren't stolen"
        )
        await query.edit_message_text(
            about_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔍 Search Engines", callback_data="rev:engines"),
                    InlineKeyboardButton("← Back", callback_data="rev:menu"),
                ],
            ]),
        )

    elif action == "engines":
        engines_text = (
            "🔍 <b>Search Engines Compared</b>\n\n"
            "🌐 <b>Google Lens</b>\n"
            "  Best all-rounder. Excellent for objects, text in images, "
            "similar images, and products.\n\n"
            "🔎 <b>Yandex Images</b>\n"
            "  Best for face recognition. Often finds social media profiles "
            "that Google misses. Essential for people OSINT.\n\n"
            "🔍 <b>TinEye</b>\n"
            "  Best for finding exact copies and derivatives. Shows "
            "oldest/newest appearances. Great for tracking image spread.\n\n"
            "🖼️ <b>Bing Visual Search</b>\n"
            "  Good for products, landmarks, and objects.\n\n"
            "🎨 <b>SauceNAO</b>\n"
            "  Best for anime, manga, and artwork. Massive database of "
            "Pixiv, DeviantArt, and other art sites.\n\n"
            "🤖 <b>ASCII2D</b>\n"
            "  Japanese image search engine. Good for finding the source "
            "of manga, anime, and doujinshi artwork."
        )
        await query.edit_message_text(
            engines_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("💡 Tips", callback_data="rev:tips"),
                    InlineKeyboardButton("← Back", callback_data="rev:menu"),
                ],
            ]),
        )

    elif action == "tips":
        tips_text = (
            "💡 <b>Reverse Search Tips</b>\n\n"
            "🎯 <b>For Face Identification:</b>\n"
            "  1. Use Yandex first (best face recognition)\n"
            "  2. Then try Google Lens\n"
            "  3. Crop the face and search again\n\n"
            "🔍 <b>For Location Detection:</b>\n"
            "  1. Check EXIF metadata first (/meta)\n"
            "  2. Use Google Lens for landmark identification\n"
            "  3. Search for distinctive signs or buildings\n\n"
            "📱 <b>For Profile Pictures:</b>\n"
            "  1. Search the full image first\n"
            "  2. Crop to just the face and search\n"
            "  3. Try TinEye to find oldest appearance\n"
            "  4. Check if image appears on scam warning sites\n\n"
            "🖼️ <b>For Artwork:</b>\n"
            "  1. SauceNAO is best for anime/manga art\n"
            "  2. ASCII2D for Japanese sources\n"
            "  3. TinEye for tracking where art has been reposted"
        )
        await query.edit_message_text(
            tips_text,
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 How It Works", callback_data="rev:about"),
                    InlineKeyboardButton("← Back", callback_data="rev:menu"),
                ],
            ]),
        )

    elif action == "google":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🌐 Open Google Lens", url="https://lens.google.com/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open Google Lens and upload your image there.", show_alert=True)

    elif action == "yandex":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔎 Open Yandex Images", url="https://yandex.com/images/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open Yandex Images and use the camera icon to upload.", show_alert=True)

    elif action == "tineye":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 Open TinEye", url="https://tineye.com/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open TinEye and upload your image.", show_alert=True)

    elif action == "bing":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🖼️ Open Bing Visual Search", url="https://www.bing.com/visualsearch"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open Bing Visual Search and upload your image.", show_alert=True)

    elif action == "saucenao":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🎨 Open SauceNAO", url="https://saucenao.com/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open SauceNAO and upload your image.", show_alert=True)

    elif action == "ascii2d":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🤖 Open ASCII2D", url="https://ascii2d.net/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)
        await query.answer("👆 Open ASCII2D and upload your image.", show_alert=True)

    elif action == "reddit":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📷 Open Reddit Image Search", url="https://redditimage.com/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)

    elif action == "karma":
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔄 Open Karma Decay", url="https://karmadecay.com/"),
            ],
            [
                InlineKeyboardButton("← Back to Results", callback_data="rev:menu"),
            ],
        ])
        await query.edit_message_reply_markup(reply_markup=keyboard)

    elif action == "menu":
        await query.edit_message_text(
            "🔍 <b>Reverse Image Search</b>\n\n"
            "Send me an <b>image</b> and I'll generate reverse search links!\n\n"
            "<b>Supported engines:</b>\n"
            "• 🌐 Google Lens\n"
            "• 🔎 Yandex Images\n"
            "• 🔍 TinEye\n"
            "• 🖼️ Bing Visual Search\n"
            "• 🎨 SauceNAO (Anime/Art)\n"
            "• 🤖 ASCII2D (Japanese)\n\n"
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
