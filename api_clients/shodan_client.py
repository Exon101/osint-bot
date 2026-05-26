"""
Shodan API Client — https://api.shodan.io
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class ShodanClient:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key=None):
        self.api_key = api_key or config.SHODAN_API_KEY

    async def _request(self, url: str, timeout: int = 15) -> dict:
        """Internal proxied request helper."""
        proxy_url = proxy_manager.get_proxy_url()
        proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

        try:
            if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
                connector = proxy_manager.create_connector()
                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=10),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"Shodan HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"Shodan HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"Shodan HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}

    async def host(self, ip: str) -> dict:
        if not self.api_key:
            return {"error": "Shodan API key not configured"}
        url = f"{self.BASE_URL}/shodan/host/{ip}?key={self.api_key}"
        return await self._request(url)

    async def internet_db(self, ip: str) -> dict:
        """Free Shodan InternetDB — no API key needed."""
        url = f"https://internetdb.shodan.io/{ip}"
        return await self._request(url, timeout=10)
