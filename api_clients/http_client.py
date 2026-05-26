"""
Generic HTTP client with proxy support.
All outgoing requests from the bot go through this module
to ensure proxy routing is consistently applied.
"""

import aiohttp

from utils.proxy_manager import proxy_manager

# Maximum response size (1MB) to prevent memory exhaustion
MAX_RESPONSE_SIZE = 1 * 1024 * 1024


async def fetch_json(url: str, headers: dict = None, timeout: int = 15, **kwargs) -> dict:
    """Fetch JSON from any URL, using proxy if enabled."""
    proxy_url = proxy_manager.get_proxy_url()
    proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

    try:
        if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
            connector = proxy_manager.create_connector()
            async with aiohttp.ClientSession(
                connector=connector or aiohttp.TCPConnector(limit=10),
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as session:
                async with session.get(url, headers=headers or {}, **kwargs) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return data
                    return {"error": f"HTTP {resp.status}"}
        elif proxy_url:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, headers=headers or {}, proxy=proxy_url, **kwargs) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return data
                    return {"error": f"HTTP {resp.status}"}
        else:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, headers=headers or {}, **kwargs) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return data
                    return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}


async def fetch_text(url: str, headers: dict = None, timeout: int = 15, **kwargs) -> dict:
    """Fetch text from any URL, using proxy if enabled. Enforces response size limit."""
    proxy_url = proxy_manager.get_proxy_url()
    proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

    try:
        if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
            connector = proxy_manager.create_connector()
            async with aiohttp.ClientSession(
                connector=connector or aiohttp.TCPConnector(limit=10),
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as session:
                async with session.get(url, headers=headers or {}, **kwargs) as resp:
                    if resp.status == 200:
                        text = await _read_limited(resp)
                        return {"text": text}
                    return {"error": f"HTTP {resp.status}"}
        elif proxy_url:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, headers=headers or {}, proxy=proxy_url, **kwargs) as resp:
                    if resp.status == 200:
                        text = await _read_limited(resp)
                        return {"text": text}
                    return {"error": f"HTTP {resp.status}"}
        else:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, headers=headers or {}, **kwargs) as resp:
                    if resp.status == 200:
                        text = await _read_limited(resp)
                        return {"text": text}
                    return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}


async def _read_limited(resp) -> str:
    """Read response body with a size limit to prevent memory exhaustion."""
    chunks = []
    total = 0
    async for chunk in resp.content.iter_chunked(8192):
        total += len(chunk)
        if total > MAX_RESPONSE_SIZE:
            raise ValueError(f"Response exceeds {MAX_RESPONSE_SIZE} bytes limit")
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


async def request(method: str, url: str, headers: dict = None,
                  params: dict = None, json: dict = None,
                  timeout: int = 15, **kwargs) -> dict:
    """
    Make any HTTP request, routing through proxy if enabled.

    Returns:
        {"ok": True, "status": 200, "data": ...} or {"ok": False, "error": "..."}
    """
    return await proxy_manager.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=json,
        timeout=timeout,
        **kwargs,
    )
