"""
Hunter.io Email API Client
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class HunterClient:
    BASE_URL = "https://api.hunter.io/v2"

    def __init__(self, api_key=None):
        self.api_key = api_key or config.HUNTER_API_KEY

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
                        return {"error": f"Hunter.io HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"Hunter.io HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"Hunter.io HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}

    async def domain_search(self, domain: str) -> dict:
        if not self.api_key:
            return {"error": "Hunter.io API key not configured"}
        url = f"{self.BASE_URL}/domain-search?domain={domain}&api_key={self.api_key}"
        return await self._request(url)

    async def email_verifier(self, email: str) -> dict:
        if not self.api_key:
            return {"error": "Hunter.io API key not configured"}
        url = f"{self.BASE_URL}/email-verifier?email={email}&api_key={self.api_key}"
        return await self._request(url)
