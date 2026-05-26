"""
IPInfo API Client — https://ipinfo.io
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class IPInfoClient:
    BASE_URL = "https://ipinfo.io"

    def __init__(self, api_key=None):
        self.api_key = api_key or config.IPINFO_API_KEY
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    async def lookup(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}/json"
        proxy_url = proxy_manager.get_proxy_url()
        proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

        try:
            if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
                connector = proxy_manager.create_connector()
                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=10),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as session:
                    async with session.get(url, headers=self.headers) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"IPInfo HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as session:
                    async with session.get(url, headers=self.headers, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"IPInfo HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"IPInfo HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}
