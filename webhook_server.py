#!/usr/bin/env python3
"""
================================================
  OSINT Bot — Webhook Server (for HF Spaces)
================================================
HuggingFace Spaces blocks outbound connections to Telegram API.
This module uses a reverse proxy to route requests through the HF
Spaces public URL.

Architecture:
  User → Telegram → HF Space webhook → webhook_server → Telegram API
"""

import asyncio
import json
import logging
import os
import ssl
from typing import Optional

import httpx
from aiohttp import web

logger = logging.getLogger("osint_bot")


def get_telegram_api_url() -> str:
    """Return a custom Telegram API base URL if TELEGRAM_API_URL is set."""
    return os.getenv("TELEGRAM_API_URL", "https://api.telegram.org")


def _safe_token_url(api_url: str, token: str, method: str) -> str:
    """Build a bot API URL with the token colon percent-encoded.

    httpx interprets the colon in bot tokens as a port separator.
    Encoding it as %3A avoids the error; the proxy worker decodes
    it back before forwarding to Telegram.
    """
    return f"{api_url}/bot{token.replace(':', '%3A')}/{method}"


async def forward_to_telegram(
    method: str,
    payload: dict,
    client: httpx.AsyncClient,
) -> dict:
    """Forward a Bot API method call to Telegram (optionally via proxy)."""
    token = os.environ["TELEGRAM_TOKEN"]
    api_url = get_telegram_api_url()

    url = _safe_token_url(api_url, token, method)
    try:
        resp = await client.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.error("Telegram API call %s failed: %s", method, exc)
        return {"ok": False, "description": str(exc)}


async def handle_webhook(request: web.Request) -> web.Response:
    """Receive an Update from Telegram and process it."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False}, status=400)

    # Get the shared app instance
    app = request.app["telegram_app"]
    update = app.update_queue.put_nowait

    # Deserialize into an Update object and feed it to the Application
    from telegram import Update
    from telegram.ext._application import ApplicationHandlerStop

    tg_update = Update.de_json(data, app.bot)
    if tg_update:
        await app.update_queue.put(tg_update)

    return web.json_response({"ok": True})


async def handle_health(request: web.Request) -> web.Response:
    """Health-check endpoint (used by HF Spaces and Docker HEALTHCHECK)."""
    return web.json_response({"status": "ok"})


async def on_startup(app: web.Application) -> None:
    """Set the Telegram webhook after the HTTP server is ready."""
    logger.info("Webhook HTTP server starting up...")

    # Give the event loop a moment to bind the port
    await asyncio.sleep(2)

    token = os.environ.get("TELEGRAM_TOKEN", "")
    space_host = os.getenv("HF_SPACE_HOST", "")  # e.g. gamingextra-osint-bot.hf.space
    space_port = int(os.getenv("SPACE_PORT", os.getenv("PORT", "7860")))

    if not space_host:
        logger.warning(
            "HF_SPACE_HOST not set — skipping webhook registration. "
            "If running locally, use polling mode (python main.py) instead."
        )
        return

    webhook_url = f"https://{space_host}/webhook/{token}"
    api_url = get_telegram_api_url()
    set_url = _safe_token_url(api_url, token, "setWebhook")

    logger.info("Registering webhook: %s", webhook_url)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                set_url,
                json={
                    "url": webhook_url,
                    "allowed_updates": ["message", "callback_query", "edited_channel_post"],
                    "drop_pending_updates": True,
                },
                timeout=30,
            )
            result = resp.json()
            if result.get("ok"):
                logger.info("Webhook registered successfully!")
            else:
                logger.error("Failed to register webhook: %s", result.get("description"))
        except Exception as exc:
            logger.error("Webhook registration error: %s", exc)


def run_webhook_server(application) -> None:
    """Build and run the aiohttp webhook server, then start the bot.

    This replaces ``application.run_polling()`` for environments like
    HuggingFace Spaces that block outbound connections to Telegram.
    """
    port = int(os.getenv("SPACE_PORT", os.getenv("PORT", "7860")))
    host = "0.0.0.0"

    # Store the Application on the aiohttp app so the webhook handler can
    # feed updates into it
    web_app = web.Application()
    web_app["telegram_app"] = application

    web_app.router.add_post("/webhook/{token}", handle_webhook)
    web_app.router.add_get("/health", handle_health)
    web_app.router.add_get("/", handle_health)

    web_app.on_startup.append(on_startup)

    logger.info("Starting webhook server on %s:%d", host, port)

    # Start the bot's internal processing (JobQueue, etc.)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run():
        async with application:
            await application.initialize()
            await application.start()
            # Let python-telegram-bot process updates in the background
            update_task = asyncio.create_task(
                _process_updates(application)
            )
            # Start the aiohttp server (this blocks)
            runner = web.AppRunner(web_app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()
            logger.info("Webhook server is live on port %d", port)
            # Keep running forever
            try:
                await asyncio.Future()  # block indefinitely
            except asyncio.CancelledError:
                pass
            update_task.cancel()
            await application.stop()
            await application.shutdown()

    loop.run_until_complete(_run())


async def _process_updates(application):
    """Continuously pull updates from the queue and dispatch them."""
    from telegram.ext._extbot import ExtBot

    while True:
        try:
            update = await application.update_queue.get()
            await application.process_update(update)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Error processing update: %s", exc)
